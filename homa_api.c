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

/* This file contains functions that implement the Homa API visible to
 * applications. It is intended to be part of the user-level run-time library.
 */

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#ifndef NDEBUG
#include <stdlib.h>
#endif
#include <sys/ioctl.h>
#include <sys/types.h>

#include "homa.h"

/**
 * homa_abort() - Remove all state associated with an outgoing RPC.
 * @sockfd:     File descriptor for the socket associated with the RPC.
 * @id:         Unique identifier for the RPC to abort (return value
 *              from previous call to homa_send). Should be a client
 *              RPC.
 *
 * Return:      If an error occurred, -1 is returned and errno is set
 *              appropriately. Otherwise zero is returned.
 */
int homa_abort(int sockfd, uint64_t id)
{
	return ioctl(sockfd, HOMAIOCABORT, (void *) id);
}

/**
 * homa_cancel() - Attempt to cancel outgoing RPC(s), while continuing
 *              to deliver their completions to homa_recv().
 * @sockfd:     File descriptor for the socket associated with the RPC.
 * @id:         Unique identifier for the RPC to abort (return value
 *              from previous call to homa_send). Should be a client
 *              RPC. If set to -1 cancels all pending client RPCs.
 *
 * Return:      If an error occurred, -1 is returned and errno is set
 *              appropriately. Otherwise zero is returned. An errno value of
 *              EALREADY is set if the specified RPC was already finished.
 */
int homa_cancel(int sockfd, uint64_t id)
{
	return ioctl(sockfd, HOMAIOCCANCEL, (void *) id);
}

ssize_t homa_recv(int sockfd, struct homa_recv_args *args) {
	return ioctl(sockfd, HOMAIOCRECV, args);
}

ssize_t homa_reply(int sockfd, struct homa_reply_args *args) {
	return ioctl(sockfd, HOMAIOCREPLY, args);
}

ssize_t homa_send(int sockfd, struct homa_send_args *args) {
	return ioctl(sockfd, HOMAIOCSEND, args);
}

/**
 * homa_recv_helper() - Wait for an incoming message (either request or
 * response) and return it.
 * @sockfd:     File descriptor for the socket on which to receive the message.
 * @buf:        First byte of buffer for the incoming message.
 * @length:     Number of bytes available at @request.
 * @flags:      An ORed combination of bits such as HOMA_RECV_REQUEST and
 *              HOMA_RECV_NONBLOCKING
 * @src_addr:   If @id is non-null, specifies the desired source for an
 *              RPC. Also used to return the sender's IP address.
 * @id:         Points to a unique RPC identifier, which is used both as
 *              an input and an output parameter. If the value is initially
 *              nonzero, then a message matching this id and @src_addr
 *              may be returned. This word is also used to return the actual
 *              id for the incoming message.
 * @msglen:     If non-null, the total length of the message will be returned
 *              here.
 * @completion_cookie:
 *              Pointer to value to be delivered upon RPC completion set via
 *              homa_send() or homa_sendv().
 *
 * Return:      The number of bytes of data returned at @buf. If an error
 *              occurred, -1 is returned and errno is set appropriately.
 */
ssize_t homa_recv_helper(int sockfd, void *buf, size_t length, int flags,
	        sockaddr_in_union *src_addr, uint64_t *id, size_t *msglen,
		uint64_t *completion_cookie)
{
	struct homa_recv_args args = {};
	int result;

	args.message_buf = buf;
	args.iovec = NULL;
	args.length = length;
	args.source_addr = *src_addr;
	args.flags = flags;
	args.id = *id;
	result = homa_recv(sockfd, &args);
	*src_addr = args.source_addr;
	*id = args.id;
	if (msglen) {
		*msglen = args.length;
	}
	if (completion_cookie) {
		*completion_cookie = args.completion_cookie;
	} else if (args.completion_cookie) {
		fprintf(stderr, "Lost completion_cookie 0x%"PRIx64"\n",
				(uint64_t)args.completion_cookie);
#ifndef NDEBUG
		abort();
#endif
	}
	return result;
}

/**
 * homa_recvv_helper() - Similar to homa_recv_helper except the message data can
 * be scattered across multiple target buffers.
 * @sockfd:     File descriptor for the socket on which to receive the message.
 * @iov:        Pointer to array that describes the chunks of the response
 *              message.
 * @iovcnt:     Number of elements in @iov.
 * @flags:      An ORed combination of bits such as HOMA_RECV_REQUEST and
 *              HOMA_RECV_NONBLOCKING
 * @src_addr:   If @id is non-null, specifies the desired source for an
 *              RPC. Also used to return the sender's IP address.
 * @id:         Points to a unique RPC identifier, which is used both as
 *              an input and an output parameter. If the value is initially
 *              nonzero, then a message matching this id and @src_addr
 *              may be returned. This word is also used to return the actual
 *              id for the incoming message.
 * @msglen:     If non-null, the total length of the message will be returned
 *              here.
 * @completion_cookie:
 *              Pointer to value to be delivered upon RPC completion set via
 *              homa_send() or homa_sendv().
 *
 * Return:      The number of bytes of data returned at @buf. If an error
 *              occurred, -1 is returned and errno is set appropriately.
 */
ssize_t homa_recvv_helper(int sockfd, const struct iovec *iov, int iovcnt, int flags,
	        sockaddr_in_union *src_addr, uint64_t *id, size_t *msglen,
		uint64_t *completion_cookie)
{
	struct homa_recv_args args = {};
	int result;

	args.message_buf = NULL;
	args.iovec = iov;
	args.length = iovcnt;
	args.source_addr = *src_addr;
	args.flags = flags;
	args.id = *id;
	result = homa_recv(sockfd, &args);
	*src_addr = args.source_addr;
	*id = args.id;
	if (msglen) {
		*msglen = args.length;
	}
	if (completion_cookie) {
		*completion_cookie = args.completion_cookie;
	} else if (args.completion_cookie) {
		fprintf(stderr, "Lost completion_cookie 0x%"PRIx64"\n",
				(uint64_t)args.completion_cookie);
#ifndef NDEBUG
		abort();
#endif
	}
	return result;
}

/**
 * homa_reply_helper() - Send a response message for an RPC previously received
 * with a call to homa_recv.
 * @sockfd:     File descriptor for the socket on which to send the message.
 * @response:   First byte of buffer containing the response message.
 * @resplen:    Number of bytes at @response.
 * @dest_addr:  Address of the RPC's client (returned by homa_recv when
 *              the message was received).
 * @id:         Unique identifier for the request, as returned by homa_recv
 *              when the request was received.
 *
 * @dest_addr and @id must correspond to a previously-received request
 * for which no reply has yet been sent; if there is no such active request,
 * then this function does nothing.
 *
 * Return:      0 means the response has been accepted for delivery. If an
 *              error occurred, -1 is returned and errno is set appropriately.
 */
ssize_t homa_reply_helper(int sockfd, const void *response, size_t resplen,
		const sockaddr_in_union *dest_addr, uint64_t id)
{
	struct homa_reply_args args = {};
	args.message_buf = (void *) response;
	args.iovec = NULL;
		args.length = resplen;
	args.dest_addr = *dest_addr;
	args.id = id;
	return homa_reply(sockfd, &args);
}

/**
 * homa_replyv_helper() - Similar to homa_reply_helper, except the response
 * message can be divided among several chunks of memory.
 * @sockfd:     File descriptor for the socket on which to send the message.
 * @iov:        Pointer to array that describes the chunks of the response
 *              message.
 * @iovcnt:     Number of elements in @iov.
 * @dest_addr:  Address of the RPC's client (returned by homa_recv when
 *              the message was received).
 * @id:         Unique identifier for the request, as returned by homa_recv
 *              when the request was received.
 *
 * @dest_addr and @id must correspond to a previously-received request
 * for which no reply has yet been sent; if there is no such active request,
 * then this function does nothing.
 *
 * Return:      0 means the response has been accepted for delivery. If an
 *              error occurred, -1 is returned and errno is set appropriately.
 */
ssize_t homa_replyv_helper(int sockfd, const struct iovec *iov, int iovcnt,
		const sockaddr_in_union *dest_addr, uint64_t id)
{
	struct homa_reply_args args = {};
	args.message_buf = NULL;
	args.iovec = iov;
	args.length = iovcnt;
	args.dest_addr = *dest_addr;
	args.id = id;
	return homa_reply(sockfd, &args);
}

/**
 * homa_send_helper() - Send a request message to initiate an RPC.
 * @sockfd:     File descriptor for the socket on which to send the message.
 * @request:    First byte of buffer containing the request message.
 * @reqlen:     Number of bytes at @request.
 * @dest_addr:  Address of server to which the request should be sent.
 * @id:         A unique identifier for the request will be returned here;
 *              this can be used later to find the response for this request.
 * @completion_cookie:
 *              value to be delivered upon RPC completion.
 *
 * Return:      0 means the request has been accepted for delivery. If an
 *              error occurred, -1 is returned and errno is set appropriately.
 */
int homa_send_helper(int sockfd, const void *request, size_t reqlen,
		const sockaddr_in_union *dest_addr, uint64_t *id,
		uint64_t completion_cookie)
{
	struct homa_send_args args = {};
	int result;
	args.message_buf = (void *) request;
	args.iovec = NULL;
	args.length = reqlen;
	args.dest_addr = *dest_addr;
	args.id = 0;
	args.completion_cookie = completion_cookie;
	result = homa_send(sockfd, &args);
	if ((result >= 0) && (id != NULL))
		*id = args.id;
	return result;
}

/**
 * homa_sendv_helper() - Same as homa_send, except that the request message can
 * be divided among multiple disjoint chunks of memory.
 * @sockfd:     File descriptor for the socket on which to send the message.
 * @iov:        Pointer to array that describes the chunks of the request
 *              message.
 * @iovcnt:     Number of elements in @iov.
 * @dest_addr:  Address of server to which the request should be sent.
 * @id:         A unique identifier for the request will be returned here;
 *              this can be used later to find the response for this request.
 * @completion_cookie:
 *              value to be delivered upon RPC completion.
 *
 * Return:      0 means the request has been accepted for delivery. If an
 *              error occurred, -1 is returned and errno is set appropriately.
 */
int homa_sendv_helper(int sockfd, const struct iovec *iov, int iovcnt,
		const sockaddr_in_union *dest_addr, uint64_t *id,
		uint64_t completion_cookie)
{
	struct homa_send_args args = {};
	int result;
	args.message_buf = NULL;
	args.iovec = iov;
	args.length = iovcnt;
	args.dest_addr = *dest_addr;
	args.id = 0;
	args.completion_cookie = completion_cookie;
	result = homa_send(sockfd, &args);
	if ((result >= 0) && (id != NULL))
		*id = args.id;
	return result;
}
