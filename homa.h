/* Copyright (c) 2019-2021 Stanford University
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
 * define HOMA_MIN_DEFAULT_PORT - The 16-bit port space is divided into
 * two nonoverlapping regions. Ports 1-32767 are reserved exclusively
 * for well-defined server ports. The remaining ports are used for client
 * ports; these are allocated automatically by Homa. Port 0 is reserved.
 */
#define HOMA_MIN_DEFAULT_PORT 0x8000

/**
 * This is smaller and easier to use than sockaddr_storage.
 */
typedef union sockaddr_in_union {
        struct sockaddr sa;
        struct sockaddr_in in4;
        struct sockaddr_in6 in6;
} sockaddr_in_union;

/**
 * define homa_send_args - Structure that passes arguments and results
 * betweeen homa_send and the HOMAIOCSEND ioctl.
 */
struct homa_send_args {
        // Exactly one of message_buf and iovec will be non-null.
        void *message_buf;
        const struct iovec *iovec;

        // The number of bytes at *request, or the number of elements at *iovec.
        size_t length;
        sockaddr_in_union dest_addr;
        int flags;
        __u64 completion_cookie;
        __u64 id;

        __u64 _pad[7];
};
#if !defined(__cplusplus)
_Static_assert(sizeof(struct homa_send_args) >= 128, "homa_send_args shrunk");
_Static_assert(sizeof(struct homa_send_args) <= 128, "homa_send_args grew");
#endif

/**
 * define homa_recv_args - Structure that passes arguments and results
 * betweeen homa_recv and the HOMAIOCRECV ioctl.
 *
 * Ideally this should have the exact same layout as homa_reply_args.
 * Therefore new members should be added at the end of the padding,
 * not at the beginning.
 */
struct homa_recv_args {
        // Exactly one of message_buf and iovec will be non-null.
        void *message_buf;
        const struct iovec *iovec;

        // Initially holds length of @buf or @iovec; modified to return total
        // message length.
        size_t length;
        sockaddr_in_union source_addr;
        int flags;
        __u64 completion_cookie;
        __u64 id;

        __u64 _pad[7];
};
#if !defined(__cplusplus)
_Static_assert(sizeof(struct homa_recv_args) >= 128, "homa_recv_args shrunk");
_Static_assert(sizeof(struct homa_recv_args) <= 128, "homa_recv_args grew");
#endif

/* Flag bits for homa_recv (see man page for documentation):
 */
#define HOMA_RECV_REQUEST       0x01
#define HOMA_RECV_RESPONSE      0x02
#define HOMA_RECV_NONBLOCKING   0x04
#define HOMA_RECV_PARTIAL       0x08

/**
 * define homa_reply_args - Structure that passes arguments and results
 * betweeen homa_reply and the HOMAIOCREPLY ioctl.
 *
 * Ideally this should have the exact same layout as homa_recv_args.
 * Therefore new members should be added at the beginning of the padding,
 * not at the end.
 */
struct homa_reply_args {
        // Exactly one of message_buf and iovec will be non-null.
        void *message_buf;
        const struct iovec *iovec;

        // The number of bytes at *response, or the number of elements at *iovec.
        size_t length;
        sockaddr_in_union dest_addr;
        int flags;
        __u64 completion_cookie;
        __u64 id;

        __u64 _pad[7];
};
#if !defined(__cplusplus)
_Static_assert(sizeof(struct homa_reply_args) >= 128, "homa_reply_args shrunk");
_Static_assert(sizeof(struct homa_reply_args) <= 128, "homa_reply_args grew");
#endif

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

#define HOMAIOCSEND   _IOWR(0x89, 0xe0, struct homa_send_args)
#define HOMAIOCRECV   _IOWR(0x89, 0xe1, struct homa_recv_args)
#define HOMAIOCREPLY  _IOWR(0x89, 0xe2, struct homa_reply_args)
#define HOMAIOCABORT  _IO(0x89, 0xe3)
#define HOMAIOCCANCEL _IO(0x89, 0xe4)
#define HOMAIOCFREEZE _IO(0x89, 0xef)

extern ssize_t homa_recv(int fd, struct homa_recv_args *args);

extern ssize_t homa_reply(int fd, struct homa_reply_args *args);

extern ssize_t homa_send(int fd, struct homa_send_args *args);

extern int     homa_abort(int sockfd, uint64_t id);

extern int     homa_cancel(int sockfd, uint64_t id);

extern int     homa_send_helper(int sockfd, const void *request, size_t reqlen,
                    const sockaddr_in_union *dest_addr, uint64_t *id,
                    uint64_t completion_cookie);
extern int     homa_sendv_helper(int sockfd, const struct iovec *iov,
                    int iovcnt, const sockaddr_in_union *dest_addr,
                    uint64_t *id, uint64_t completion_cookie);
extern ssize_t homa_recv_helper(int sockfd, void *buf, size_t len, int flags,
                    sockaddr_in_union *src_addr, uint64_t *id,
                    size_t *msglen, uint64_t *completion_cookie_p);
extern ssize_t homa_recvv_helper(int sockfd, const struct iovec *iov,
                    int iovcnt, int flags, sockaddr_in_union *src_addr,
                    uint64_t *id, size_t *msglen,
                    uint64_t *completion_cookie_p);
extern ssize_t homa_reply_helper(int sockfd, const void *response,
                    size_t resplen, const sockaddr_in_union *dest_addr,
                    uint64_t id);
extern ssize_t homa_replyv_helper(int sockfd, const struct iovec *iov,
                    int iovcnt, const sockaddr_in_union *dest_addr,
                    uint64_t id);

#ifdef __cplusplus
}
#endif

#endif /* _HOMA_H */
