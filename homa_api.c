/* This file contains functions that implement the Homa API visible to
 * applications. It's intended to be part of the user-level run-time library.
 */

#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include "homa.h"

/**
 * homa_invoke() - Send a request message and wait for the response.
 * @sockfd:     File descriptor for the socket on which to send the message.
 * @request:    First byte of buffer containing the request message.
 * @reqlen:     Number of bytes at @request.
 * @dest_addr:  Address of server to which the request should be sent.
 * @addrlen:    Size of @dest_addr in bytes.
 * @response:    First byte of buffer containing the request message.
 * @resplen:     Number of bytes at @request.
 * 
 * Return:      The total size of the incoming message. This may be larger
 *              than len, in which case the last bytes of the incoming message
 *              were discarded. A negative value indicates an error. 
 */
size_t homa_invoke(int sockfd, const void *request, size_t reqlen,
		const struct sockaddr *dest_addr, size_t addrlen,
		void *response, size_t resplen)
{
	struct homa_args_invoke_ipv4 args;
	int result;
	
	if (dest_addr->sa_family != AF_INET) {
		errno = EAFNOSUPPORT;
		return -EAFNOSUPPORT;
	}
	args.request = (void *) request;
	args.reqlen = reqlen;
	args.dest_addr = *((struct sockaddr_in *) dest_addr);
	args.response = response;
	args.resplen = resplen;
	result = ioctl(sockfd, HOMAIOCSEND, &args);
	return result;
}

/**
 * homa_recv() - Wait for an incoming message (either request or response)
 * and return it.
 * @sockfd:     File descriptor for the socket on which to receive the message.
 * @buf:        First byte of buffer for the incoming message.
 * @len:        Number of bytes available at @request.
 * @src_addr:   The sender's address will be returned here.
 * @addrlen:    Space available at @src_addr, in bytes.
 * @id:         A unique identifier for the RPC associated with the message
 *              will be returned here.
 * 
 * Return:      The total size of the incoming message. This may be larger
 *              than len, in which case the last bytes of the incoming message
 *              were discarded. A negative value indicates an error. 
 */
size_t homa_recv(int sockfd, void *buf, size_t len, struct sockaddr *src_addr,
		size_t addrlen, uint64_t *id)
{
	struct homa_args_recv_ipv4 args;
	int result;
	
	if (addrlen < sizeof(struct sockaddr_in)) {
		errno = EINVAL;
		return -EINVAL;
	}
	args.buf = (void *) buf;
	args.len = len;
	result = ioctl(sockfd, HOMAIOCRECV, &args);
	*((struct sockaddr_in *) src_addr) = args.source_addr;
	*id = args.id;
	return result;
}

/**
 * homa_reply() - Send a response message for an RPC previously received
 * with a call to homa_recv.
 * @sockfd:     File descriptor for the socket on which to send the message.
 * @response:   First byte of buffer containing the response message.
 * @resplen:    Number of bytes at @response.
 * @dest_addr:  Address of the RPC's client (returned by homa_recv when
 *              the message was received).
 * @addrlen:    Size of @dest_addr in bytes.
 * @id:         Unique identifier for the request, as returned by homa_recv 
 *              when the request was received.
 * 
 * @dest_addr and @id must correspond to a previously-received request
 * for which no reply has yet been sent; if there is no such active request,
 * then this function does nothing.
 * 
 * Return:      0 means the response has been accepted for delivery. A
 *              negative value indicates an error. 
 */
size_t homa_reply(int sockfd, const void *response, size_t resplen,
		const struct sockaddr *dest_addr, size_t addrlen,
		uint64_t id)
{
	struct homa_args_reply_ipv4 args;
	
	if (dest_addr->sa_family != AF_INET) {
		errno = EAFNOSUPPORT;
		return -EAFNOSUPPORT;
	}
	args.response = (void *) response;
	args.resplen = resplen;
	args.dest_addr = *((struct sockaddr_in *) dest_addr);
	args.id = id;
	return ioctl(sockfd, HOMAIOCREPLY, &args);
}

/**
 * homa_send() - Send a request message to initiate an RPC.
 * @sockfd:     File descriptor for the socket on which to send the message.
 * @request:    First byte of buffer containing the request message.
 * @reqlen:     Number of bytes at @request.
 * @dest_addr:  Address of server to which the request should be sent.
 * @addrlen:    Size of @dest_addr in bytes.
 * @id:         A unique identifier for the request will be returned here;
 *              this can be used later to find the response for this request.
 * 
 * Return:      0 means the request has been accepted for delivery. A
 *              negative value indicates an error. 
 */
int homa_send(int sockfd, const void *request, size_t reqlen,
		const struct sockaddr *dest_addr, size_t addrlen,
		uint64_t *id)
{
	struct homa_args_send_ipv4 args;
	int result;
	
	if (dest_addr->sa_family != AF_INET) {
		errno = EAFNOSUPPORT;
		return -EAFNOSUPPORT;
	}
	args.request = (void *) request;
	args.reqlen = reqlen;
	args.dest_addr = *((struct sockaddr_in *) dest_addr);
	args.id = 0;
	result = ioctl(sockfd, HOMAIOCSEND, &args);
	*id = args.id;
	return result;
}