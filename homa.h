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
#define IPPROTO_HOMA 140

/**
 * define HOMA_MAX_MESSAGE_LENGTH - Maximum bytes of payload in a Homa
 * request or response message.
 */
#define HOMA_MAX_MESSAGE_LENGTH 1000000

/**
 * define HOMA_MIN_CLIENT_PORT - The 16-bit port space is divided into
 * two nonoverlapping regions. Ports 1-32767 are reserved exclusively
 * for well-defined server ports. The remaining ports are used for client
 * ports; these are allocated automatically by Homa. Port 0 is reserved.
 */
#define HOMA_MIN_CLIENT_PORT 0x8000

/**
 * I/O control calls on Homa sockets. These particular values were
 * chosen somewhat randomly, and probably need to be reconsidered to
 * make sure they don't conflict with anything else.
 */

#define HOMAIOCSEND   1003101
#define HOMAIOCRECV   1003102
#define HOMAIOCINVOKE 1003103
#define HOMAIOCREPLY  1003104
#define HOMAIOCABORT  1003105

extern int     homa_send(int sockfd, const void *request, size_t reqlen,
			const struct sockaddr *dest_addr, size_t addrlen,
			uint64_t *id);
extern ssize_t homa_recv(int sockfd, void *buf, size_t len, int flags,
			uint64_t *id, struct sockaddr *src_addr, size_t addrlen);
extern ssize_t homa_invoke(int sockfd, const void *request, size_t reqlen,
			const struct sockaddr *dest_addr, size_t addrlen,
			void *response, size_t resplen);
extern ssize_t homa_reply(int sockfd, const void *response, size_t resplen,
			const struct sockaddr *dest_addr, size_t addrlen,
			uint64_t id);
extern int     homa_abort(int sockfd, uint64_t id);

/**
 * define homa_args_send_ipv4 - Structure that passes arguments and results
 * betweeen homa_send and the HOMAIOCSEND ioctl. Assumes IPV4 addresses.
 */
struct homa_args_send_ipv4 {
	void *request;
	size_t reqlen;
	struct sockaddr_in dest_addr;
	__u64 id;
};

/**
 * define homa_args_recv_ipv4 - Structure that passes arguments and results
 * betweeen homa_recv and the HOMAIOCRECV ioctl. Assumes IPV4 addresses.
 */
struct homa_args_recv_ipv4 {
	void *buf;
	size_t len;
	struct sockaddr_in source_addr;
	int flags;
	__u64 id;
};

/* Flag bits for homa_recv (see man page for documentation): 
 */
#define HOMA_RECV_REQUEST       0x01
#define HOMA_RECV_RESPONSE      0x02
#define HOMA_RECV_NONBLOCKING   0x04

/**
 * define homa_args_invoke_ipv4 - Structure that passes arguments and results
 * betweeen homa_invoke and the HOMAIOCINVOKE ioctl. Assumes IPV4 addresses.
 */
struct homa_args_invoke_ipv4 {
	void *request;
	size_t reqlen;
	struct sockaddr_in dest_addr;
	void *response;
	size_t resplen;
};

/**
 * define homa_args_reply_ipv4 - Structure that passes arguments and results
 * betweeen homa_reply and the HOMAIOCREPLY ioctl. Assumes IPV4 addresses.
 */
struct homa_args_reply_ipv4 {
	void *response;
	size_t resplen;
	struct sockaddr_in dest_addr;
	__u64 id;
};

/**
 * Meanings of the bits in Homa's flag word, which can be set using
 * "sysctl /net/homa/flags".
 */

/**
 * The next invocation of the Homa timer will log info about active RPCs,
 * then clear this flag; used to see if RPCs are getting "stuck" and not
 * progressing or aborting.
 */
#define HOMA_FLAG_LOG_ACTIVE_RPCS 1

/**
 * Disable the output throttling mechanism: always send all packets
 * immediately.
 */
#define HOMA_FLAG_DONT_THROTTLE   2

#ifdef __cplusplus
}
#endif

#endif /* _HOMA_H */