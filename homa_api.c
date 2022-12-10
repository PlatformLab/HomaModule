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
 * homa_replyp() - Send a response message for an RPC.
 * @sockfd:     File descriptor for the socket on which to receive.
 * @args:       Structure that contains parameters for this operation;
 *              results are also returned in this struct.
 * Return:      0 means the response has been accepted for delivery. If an
 *              error occurred, -1 is returned and errno is set appropriately.
 */
ssize_t homa_replyp(int sockfd, struct homa_reply_args *args) {
	return ioctl(sockfd, HOMAIOCREPLY, args);
}

/**
 * homa_sendp() - Send the request message for a new RPC.
 * @sockfd:     File descriptor for the socket on which to send the message.
 * @args:       Structure that contains parameters for this operation;
 *              results are also returned in this struct.
 * Return:      0 means the request has been accepted for delivery. If an
 *              error occurred, -1 is returned and errno is set appropriately.
 */
ssize_t homa_sendp(int sockfd, struct homa_send_args *args) {
	return ioctl(sockfd, HOMAIOCSEND, args);
}

/**
 * homa_abortp() - Terminate the execution of an RPC.
 * @sockfd:     File descriptor for the socket associated with the RPC.
 * @args:       Structure that contains parameters for this operation.
 */
int homa_abortp(int sockfd, struct homa_abort_args *args) {
	return ioctl(sockfd, HOMAIOCABORT, args);
}

/**
 * homa_reply() - Send a response message for an RPC previously received
 * with a call to recvmsg.
 * @sockfd:     File descriptor for the socket on which to send the message.
 * @response:   First byte of buffer containing the response message.
 * @resplen:    Number of bytes at @response.
 * @dest_addr:  Address of the RPC's client (returned by recvmsg when
 *              the message was received).
 * @id:         Unique identifier for the request, as returned by recvmsg
 *              when the request was received.
 *
 * @dest_addr and @id must correspond to a previously-received request
 * for which no reply has yet been sent; if there is no such active request,
 * then this function does nothing.
 *
 * Return:      0 means the response has been accepted for delivery. If an
 *              error occurred, -1 is returned and errno is set appropriately.
 */
ssize_t homa_reply(int sockfd, const void *message_buf, size_t length,
		const sockaddr_in_union *dest_addr, uint64_t id)
{
	struct homa_reply_args args = {};
	args.message_buf = (void *) message_buf;
	args.iovec = NULL;
	args.length = length;
	args.dest_addr = *dest_addr;
	args.id = id;
	return homa_replyp(sockfd, &args);
}

/**
 * homa_replyv() - Similar to homa_reply, except the response
 * message can be divided among several chunks of memory.
 * @sockfd:     File descriptor for the socket on which to send the message.
 * @iov:        Pointer to array that describes the chunks of the response
 *              message.
 * @iovcnt:     Number of elements in @iov.
 * @dest_addr:  Address of the RPC's client (returned by recvmsg when
 *              the message was received).
 * @id:         Unique identifier for the request, as returned by recvmsg
 *              when the request was received.
 *
 * @dest_addr and @id must correspond to a previously-received request
 * for which no reply has yet been sent; if there is no such active request,
 * then this function does nothing.
 *
 * Return:      0 means the response has been accepted for delivery. If an
 *              error occurred, -1 is returned and errno is set appropriately.
 */
ssize_t homa_replyv(int sockfd, const struct iovec *iov, int iovcnt,
		const sockaddr_in_union *dest_addr, uint64_t id)
{
	struct homa_reply_args args = {};
	args.message_buf = NULL;
	args.iovec = iov;
	args.length = iovcnt;
	args.dest_addr = *dest_addr;
	args.id = id;
	return homa_replyp(sockfd, &args);
}

/**
 * homa_send() - Send a request message to initiate an RPC.
 * @sockfd:            File descriptor for the socket on which to send the
 *                     message.
 * @message_buf:       First byte of buffer containing the request message.
 * @length:            Number of bytes at @message_buf.
 * @dest_addr:         Address of server to which the request should be sent.
 * @id:                A unique identifier for the request will be returned
 *                     here; this can be used later to find the response for
 *                     this request.
 * @completion_cookie: Value to be returned by recvmsg when RPC completes.
 *
 * Return:      0 means the request has been accepted for delivery. If an
 *              error occurred, -1 is returned and errno is set appropriately.
 */
int homa_send(int sockfd, const void *message_buf, size_t length,
		const sockaddr_in_union *dest_addr, uint64_t *id,
		uint64_t completion_cookie)
{
	struct homa_send_args args = {};
	int result;
	args.message_buf = (void *) message_buf;
	args.iovec = NULL;
	args.length = length;
	args.dest_addr = *dest_addr;
	args.id = 0;
	args.completion_cookie = completion_cookie;
	result = homa_sendp(sockfd, &args);
	if ((result >= 0) && (id != NULL))
		*id = args.id;
	return result;
}

/**
 * homa_sendv() - Same as homa_send, except that the request message can
 * be divided among multiple disjoint chunks of memory.
 * @sockfd:            File descriptor for the socket on which to send the
 *                     message.
 * @iov:               Pointer to array that describes the chunks of the request
 *                     message.
 * @iovcnt:            Number of elements in @iov.
 * @dest_addr:         Address of server to which the request should be sent.
 * @id:                A unique identifier for the request will be returned
 *                     here; this can be used later to find the response for
 *                     this request.
 * @completion_cookie: Value to be returned by recvmsg when RPC completes.
 *
 * Return:      0 means the request has been accepted for delivery. If an
 *              error occurred, -1 is returned and errno is set appropriately.
 */
int homa_sendv(int sockfd, const struct iovec *iov, int iovcnt,
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
	result = homa_sendp(sockfd, &args);
	if ((result >= 0) && (id != NULL))
		*id = args.id;
	return result;
}

/**
 * homa_abort() - Terminate the execution of an RPC.
 * @sockfd:     File descriptor for the socket associated with the RPC.
 * @id:         Unique identifier for a client RPC to abort (return value
 *              from previous call to homa_send). 0 means abort all client
 *              RPCs on this socket.
 * @error:      0 means that the aborted RPCs should be destroyed
 *              immediately (they will never be returned by recvmsg).
 *              Nonzero means that the RPCs should be moved to the
 *              completed state; recvmsg will return an error for these
 *              RPCs, with @error as the errno value.
 *
 * Return:      If an error occurred, -1 is returned and errno is set
 *              appropriately. Otherwise zero is returned.
 */
int homa_abort(int sockfd, uint64_t id, int error)
{
	struct homa_abort_args args = {id, error};
	return ioctl(sockfd, HOMAIOCABORT, &args);
}
