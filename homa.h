/* SPDX-License-Identifier: BSD-2-Clause */

/* This file defines the kernel call interface for the Homa
 * transport protocol.
 */

#ifndef _UAPI_LINUX_HOMA_H
#define _UAPI_LINUX_HOMA_H

#include <linux/types.h>
#ifndef __KERNEL__
#include <netinet/in.h>
#include <sys/socket.h>
#endif

/* IANA-assigned Internet Protocol number for Homa. */
#define IPPROTO_HOMA 146

/**
 * define HOMA_MAX_MESSAGE_LENGTH - Maximum bytes of payload in a Homa
 * request or response message.
 */
#define HOMA_MAX_MESSAGE_LENGTH 1000000

/**
 * define HOMA_BPAGE_SIZE - Number of bytes in pages used for receive
 * buffers. Must be power of two.
 */
#define HOMA_BPAGE_SIZE (1 << HOMA_BPAGE_SHIFT)
#define HOMA_BPAGE_SHIFT 16

/**
 * define HOMA_MAX_BPAGES - The largest number of bpages that will be required
 * to store an incoming message.
 */
#define HOMA_MAX_BPAGES ((HOMA_MAX_MESSAGE_LENGTH + HOMA_BPAGE_SIZE - 1) \
		>> HOMA_BPAGE_SHIFT)

/**
 * define HOMA_MIN_DEFAULT_PORT - The 16 bit port space is divided into
 * two nonoverlapping regions. Ports 1-32767 are reserved exclusively
 * for well-defined server ports. The remaining ports are used for client
 * ports; these are allocated automatically by Homa. Port 0 is reserved.
 */
#define HOMA_MIN_DEFAULT_PORT 0x8000

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
	__u64 id;

	/**
	 * @completion_cookie: (in) Used only for request messages; will be
	 * returned by recvmsg when the RPC completes. Typically used to
	 * locate app-specific info about the RPC.
	 */
	__u64 completion_cookie;
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
	__u64 id;

	/**
	 * @completion_cookie: (out) If the incoming message is a response,
	 * this will return the completion cookie specified when the
	 * request was sent. For requests this will always be zero.
	 */
	__u64 completion_cookie;

	/**
	 * @flags: (in) OR-ed combination of bits that control the operation.
	 * See below for values.
	 */
	__u32 flags;

	/**
	 * @num_bpages: (in/out) Number of valid entries in @bpage_offsets.
	 * Passes in bpages from previous messages that can now be
	 * recycled; returns bpages from the new message.
	 */
	__u32 num_bpages;

	/**
	 * @bpage_offsets: (in/out) Each entry is an offset into the buffer
	 * region for the socket pool. When returned from recvmsg, the
	 * offsets indicate where fragments of the new message are stored. All
	 * entries but the last refer to full buffer pages (HOMA_BPAGE_SIZE
	 * bytes) and are bpage-aligned. The last entry may refer to a bpage
	 * fragment and is not necessarily aligned. The application now owns
	 * these bpages and must eventually return them to Homa, using
	 * bpage_offsets in a future recvmsg invocation.
	 */
	__u32 bpage_offsets[HOMA_MAX_BPAGES];
};

#if !defined(__cplusplus)
_Static_assert(sizeof(struct homa_recvmsg_args) >= 88,
	       "homa_recvmsg_args shrunk");
_Static_assert(sizeof(struct homa_recvmsg_args) <= 88,
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
	__u64 id;

	/**
	 * @error: Zero means destroy and free RPCs; nonzero means complete
	 * them with this error (recvmsg will return the RPCs).
	 */
	int error;

	int _pad1;
	__u64 _pad2[2];
};

#if !defined(__cplusplus)
_Static_assert(sizeof(struct homa_abort_args) >= 32, "homa_abort_args shrunk");
_Static_assert(sizeof(struct homa_abort_args) <= 32, "homa_abort_args grew");
#endif

/** define SO_HOMA_RCVBUF: setsockopt option for specifying buffer region. */
#define SO_HOMA_RCVBUF 10

/** struct homa_rcvbuf_args - setsockopt argument for SO_HOMA_RCVBUF. */
struct homa_rcvbuf_args {
	/** @start: First byte of buffer region. */
	void *start;

	/** @length: Total number of bytes available at @start. */
	size_t length;
};

/* Meanings of the bits in Homa's flag word, which can be set using
 * "sysctl /net/homa/flags".
 */

/**
 * define HOMA_FLAG_DONT_THROTTLE - disable the output throttling mechanism
 * (always send all packets immediately).
 */
#define HOMA_FLAG_DONT_THROTTLE   2

/**
 * I/O control calls on Homa sockets. These are mapped into the
 * SIOCPROTOPRIVATE range of 0x89e0 through 0x89ef.
 */

#define HOMAIOCABORT  _IOWR(0x89, 0xe3, struct homa_abort_args)
#define HOMAIOCFREEZE _IO(0x89, 0xef)

#ifndef __STRIP__ /* See strip.py */
int     homa_abort(int sockfd, __u64 id, int error);
int     homa_send(int sockfd, const void *message_buf,
		  size_t length, const struct sockaddr *dest_addr,
		  __u32 addrlen,  __u64 *id, __u64 completion_cookie);
int     homa_sendv(int sockfd, const struct iovec *iov,
		   int iovcnt, const struct sockaddr *dest_addr,
		   __u32 addrlen,  __u64 *id, __u64 completion_cookie);
ssize_t homa_reply(int sockfd, const void *message_buf,
		   size_t length, const struct sockaddr *dest_addr,
		   __u32 addrlen,  __u64 id);
ssize_t homa_replyv(int sockfd, const struct iovec *iov,
		    int iovcnt, const struct sockaddr *dest_addr,
		    __u32 addrlen,  __u64 id);
#endif /* See strip.py */

#endif /* _UAPI_LINUX_HOMA_H */
