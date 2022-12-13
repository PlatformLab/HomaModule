/* Copyright (c) 2019-2022 Stanford University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* This file defines the kernel call interface for the Homa
 * transport protocol.
 */

#ifndef _HOMA_H
#define _HOMA_H

#include <linux/types.h>
#ifndef __KERNEL__
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

/* Homa's protocol number within the IP protocol space (this is not an
 * officially allocated slot).
 */
#define IPPROTO_HOMA 0xFD

/**
 * define HOMA_MAX_MESSAGE_LENGTH - Maximum bytes of payload in a Homa
 * request or response message.
 */
#define HOMA_MAX_MESSAGE_LENGTH 1000000

/**
 * define HOMA_BPAGE_SIZE - Number of bytes in pages used for receive
 * buffers. Must be power of two.
 */
#define HOMA_BPAGE_SHIFT 16
#define HOMA_BPAGE_SIZE (1 << HOMA_BPAGE_SHIFT)

/**
 * define HOMA_MAX_BPAGES: The largest number of bpages that will be required
 * to store an incoming message.
 */
#define HOMA_MAX_BPAGES ((HOMA_MAX_MESSAGE_LENGTH + HOMA_BPAGE_SIZE - 1) \
		>> HOMA_BPAGE_SHIFT)

/**
 * define HOMA_MIN_DEFAULT_PORT - The 16-bit port space is divided into
 * two nonoverlapping regions. Ports 1-32767 are reserved exclusively
 * for well-defined server ports. The remaining ports are used for client
 * ports; these are allocated automatically by Homa. Port 0 is reserved.
 */
#define HOMA_MIN_DEFAULT_PORT 0x8000

/**
 * Holds either an IPv4 or IPv6 address (smaller and easier to use than
 * sockaddr_storage).
 */
typedef union sockaddr_in_union {
	struct sockaddr sa;
	struct sockaddr_in in4;
	struct sockaddr_in6 in6;
} sockaddr_in_union;

/**
 * struct homa_sendmsg_args - Provides information needed by Homa's
 * sendmsg; passed to sendmsg using the msg_control field.
 */
struct homa_sendmsg_args {
	/**
	 * @id: (in/out) An initial value of 0 means a new request is
	 * being sent; nonzero means the message is a reply to the given
	 * id. If the message is a request, then the value is modified to
	 * hold the id of the new RPC.
	 */
	uint64_t id;

	/**
	 * @completion_cookie: (in) Used only for request messages; will be
	 * returned by recvmsg when the RPC completes. Typically used to
	 * locate app-specific info about the RPC.
	 */
	uint64_t completion_cookie;
};
#if !defined(__cplusplus)
_Static_assert(sizeof(struct homa_sendmsg_args) >= 16,
		"homa_sendmsg_args shrunk");
_Static_assert(sizeof(struct homa_sendmsg_args) <= 16,
		"homa_sendmsg_args grew");
#endif

/**
 * struct homa_recvmsg_args - Provides information needed by Homa's
 * recvmsg; passed to recvmsg using the msg_control field.
 */
struct homa_recvmsg_args {

	/**
	 * @id: (in/out) Initially specifies the id of the desired RPC, or 0
	 * if any RPC is OK; returns the actual id received.
	 */
	uint64_t id;

	/**
	 * @completion_cookie: (out) If the incoming message is a response,
	 * this will return the completion cookie specified when the
	 * request was sent. For requests this will always be zero.
	 */
	uint64_t completion_cookie;

	/**
	 * @flags: (in) OR-ed combination of bits that control the operation.
	 * See below for values.
	 */
	int flags;

	/**
	 * @num_bpages: (in/out) Number of valid entries in @bpage_offsets.
	 * Passes in bpages from previous messages that can now be
	 * recycled; returns bpages from the new message.
	 */
	uint32_t num_bpages;

	uint32_t _pad[2];

	/**
	 * @bpage_offsets: (in/out) Each entry is an offset into the buffer
     * region for the socket pool. When returned from recvmsg, the
     * offsets indicate where fragments of the new message are stored. All
     * entries but the last refer to full buffer pages (HOMA_BPAGE_SIZE bytes)
     * and are bpage-aligned. The last entry may refer to a bpage fragment and
     * is not necessarily aligned. The application now owns these bpages and
     * must eventually return them to Homa, using bpage_offsets in a future
     * recvmsg invocation.
	 */
	uint32_t bpage_offsets[HOMA_MAX_BPAGES];
};
#if !defined(__cplusplus)
_Static_assert(sizeof(struct homa_recvmsg_args) >= 96,
		"homa_recvmsg_args shrunk");
_Static_assert(sizeof(struct homa_recvmsg_args) <= 96,
		"homa_recvmsg_args grew");
#endif

/* Flag bits for homa_recvmsg_args.flags (see man page for documentation):
 */
#define HOMA_RECVMSG_REQUEST       0x01
#define HOMA_RECVMSG_RESPONSE      0x02
#define HOMA_RECVMSG_NONBLOCKING   0x04
#define HOMA_RECVMSG_VALID_FLAGS   0x07

/**
 * struct homa_abort_args - Structure that passes arguments and results
 * between user space and the HOMAIOCABORT ioctl.
 */
struct homa_abort_args {
	/** @id: Id of RPC to abort, or zero to abort all RPCs on socket. */
	uint64_t id;

	/**
	 * @error: Zero means destroy and free RPCs; nonzero means complete
	 * them with this error (recvmsg will return the RPCs).
	 */
	int error;

	int _pad1;
	uint64_t _pad2[2];
};
#if !defined(__cplusplus)
_Static_assert(sizeof(struct homa_abort_args) >= 32, "homa_abort_args shrunk");
_Static_assert(sizeof(struct homa_abort_args) <= 32, "homa_abort_args grew");
#endif

/** define SO_HOMA_SET_BUF: setsockopt option for specifying buffer region. */
#define SO_HOMA_SET_BUF 10

/** struct homa_set_buf - setsockopt argument for SO_HOMA_SET_BUF. */
struct homa_set_buf_args {
	/** @start: First byte of buffer region. */
	void *start;

	/** @length: Total number of bytes available at @start. */
	size_t length;
};

/**
 * Meanings of the bits in Homa's flag word, which can be set using
 * "sysctl /net/homa/flags".
 */

/**
 * Disable the output throttling mechanism: always send all packets
 * immediately.
 */
#define HOMA_FLAG_DONT_THROTTLE   2

/**
 * I/O control calls on Homa sockets. These are mapped into the
 * SIOCPROTOPRIVATE range of 0x89e0 through 0x89ef.
 */

#define HOMAIOCREPLY  _IOWR(0x89, 0xe2, struct homa_reply_args)
#define HOMAIOCABORT  _IOWR(0x89, 0xe3, struct homa_abort_args)
#define HOMAIOCFREEZE _IO(0x89, 0xef)

extern int     homa_abortp(int fd, struct homa_abort_args *args);

extern int     homa_send(int sockfd, const void *message_buf,
		size_t length, const sockaddr_in_union *dest_addr,
		uint64_t *id, uint64_t completion_cookie);
extern int     homa_sendv(int sockfd, const struct iovec *iov,
		int iovcnt, const sockaddr_in_union *dest_addr,
		uint64_t *id, uint64_t completion_cookie);
extern ssize_t homa_reply(int sockfd, const void *message_buf,
		size_t length, const sockaddr_in_union *dest_addr,
		uint64_t id);
extern ssize_t homa_replyv(int sockfd, const struct iovec *iov,
		int iovcnt, const sockaddr_in_union *dest_addr,
		uint64_t id);
extern int     homa_abort(int sockfd, uint64_t id, int error);

#ifdef __cplusplus
}
#endif

#endif /* _HOMA_H */
