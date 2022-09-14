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
 * I/O control calls on Homa sockets. These particular values were
 * chosen somewhat randomly, and probably need to be reconsidered to
 * make sure they don't conflict with anything else.
 */

#define HOMAIOCSEND   1003101
#define HOMAIOCRECV   1003102
#define HOMAIOCREPLY  1003103
#define HOMAIOCABORT  1003104
#define HOMAIOCFREEZE 1003105

extern int     homa_send(int sockfd, const void *request, size_t reqlen,
                    const struct sockaddr *dest_addr, size_t addrlen,
                    uint64_t *id, uint64_t completion_cookie);
extern int     homa_sendv(int sockfd, const struct iovec *iov, int iovcnt,
                    const struct sockaddr *dest_addr, size_t addrlen,
                    uint64_t *id, uint64_t completion_cookie);
extern ssize_t homa_recv(int sockfd, void *buf, size_t len, int flags,
                    struct sockaddr *src_addr, size_t *addrlen,
                    uint64_t *id, size_t *msglen, uint64_t *completion_cookie);
extern ssize_t homa_recvv(int sockfd, const struct iovec *iov, int iovcnt,
                    int flags, struct sockaddr *src_addr, size_t *addrlen,
                    uint64_t *id, size_t *msglen, uint64_t *completion_cookie);
extern ssize_t homa_reply(int sockfd, const void *response, size_t resplen,
                    const struct sockaddr *dest_addr, size_t addrlen,
                    uint64_t id);
extern ssize_t homa_replyv(int sockfd, const struct iovec *iov, int iovcnt,
                    const struct sockaddr *dest_addr, size_t addrlen,
                    uint64_t id);
extern int     homa_abort(int sockfd, uint64_t id, int error);

/**
 * define homa_args_send_ipv4 - Structure that passes arguments and results
 * betweeen homa_send and the HOMAIOCSEND ioctl. Assumes IPV4 addresses.
 */
struct homa_args_send_ipv4 {
        // Exactly one of request and iovec will be non-null.
        void *request;
        const struct iovec *iovec;

        // The number of bytes at *request, or the number of elements at *iovec.
        size_t length;
        struct sockaddr_in dest_addr;
        __u64 id;
        __u64 completion_cookie;
};

/**
 * define homa_args_recv_ipv4 - Structure that passes arguments and results
 * betweeen homa_recv and the HOMAIOCRECV ioctl. Assumes IPV4 addresses.
 */
struct homa_args_recv_ipv4 {
        // Exactly one of buf and iovec will be non-null.
        void *buf;
        const struct iovec *iovec;

        // Initially holds length of @buf or @iovec; modified to return total
        // message length.
        size_t len;
        struct sockaddr_in source_addr;
        int flags;
        __u64 requestedId;
        __u64 actualId;
        __u64 completion_cookie;
};

/* Flag bits for homa_recv (see man page for documentation):
 */
#define HOMA_RECV_REQUEST       0x01
#define HOMA_RECV_RESPONSE      0x02
#define HOMA_RECV_NONBLOCKING   0x04
#define HOMA_RECV_PARTIAL       0x08

/**
 * define homa_args_reply_ipv4 - Structure that passes arguments and results
 * betweeen homa_reply and the HOMAIOCREPLY ioctl. Assumes IPV4 addresses.
 */
struct homa_args_reply_ipv4 {
        // Exactly one of response and iovec will be non-null.
        void *response;
        const struct iovec *iovec;

        // The number of bytes at *response, or the number of elements at *iovec.
        size_t length;
        struct sockaddr_in dest_addr;
        __u64 id;
};

/**
 * define homa_args_abort_ipv4 - Structure that passes arguments and results
 * betweeen homa_abort and the HOMAIOCABORT ioctl.
 */
struct homa_args_abort_ipv4 {
        uint64_t id;
	int error;
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

#ifdef __cplusplus
}
#endif

#endif /* _HOMA_H */
