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
 * homa_recv() - Wait for an incoming message (either request or response)
 * and return it.
 * See the man page for documentation of this API.
 */
ssize_t homa_recv(int sockfd, void *buf, size_t len, int flags,
	        struct sockaddr *src_addr, size_t *addrlen, uint64_t *id,
		size_t *msglen, uint64_t *completion_cookie)
{
	struct homa_args_recv_ipv4 args = {};
	int result;

	if (*addrlen < sizeof(struct sockaddr_in)) {
		errno = EINVAL;
		return -EINVAL;
	}
	args.buf = (void *) buf;
	args.iovec = NULL;
	args.len = len;
	args.source_addr = *((struct sockaddr_in *) src_addr);
	args.flags = flags;
	args.requestedId = *id;
	args.actualId = 0;
	result = ioctl(sockfd, HOMAIOCRECV, &args);
	*((struct sockaddr_in *) src_addr) = args.source_addr;
	*addrlen = sizeof(struct sockaddr_in);
	*id = args.actualId;
	if (msglen)
		*msglen = args.len;
	if (completion_cookie)
		*completion_cookie = args.completion_cookie;
	return result;
}

/**
 * homa_recvv() - Similar to homa_recv except the message data can be
 * scattered across multiple target buffers.
 * See the man page for documentation of this API.
 */
ssize_t homa_recvv(int sockfd, const struct iovec *iov, int iovcnt, int flags,
	        struct sockaddr *src_addr, size_t *addrlen, uint64_t *id,
		size_t *msglen, uint64_t *completion_cookie)
{
	struct homa_args_recv_ipv4 args = {};
	int result;

	if (*addrlen < sizeof(struct sockaddr_in)) {
		errno = EINVAL;
		return -EINVAL;
	}
	args.buf = NULL;
	args.iovec = iov;
	args.len = iovcnt;
	args.source_addr = *((struct sockaddr_in *) src_addr);
	args.flags = flags;
	args.requestedId = *id;
	args.actualId = 0;
	result = ioctl(sockfd, HOMAIOCRECV, &args);
	*((struct sockaddr_in *) src_addr) = args.source_addr;
	*addrlen = sizeof(struct sockaddr_in);
	*id = args.actualId;
	if (msglen)
		*msglen = args.len;
	if (completion_cookie)
		*completion_cookie = args.completion_cookie;
	return result;
}

/**
 * homa_reply() - Send a response message for an RPC previously received
 * with a call to homa_recv.
 * See the man page for documentation of this API.
 */
ssize_t homa_reply(int sockfd, const void *response, size_t resplen,
		const struct sockaddr *dest_addr, size_t addrlen,
		uint64_t id)
{
	struct homa_args_reply_ipv4 args = {};

	if (dest_addr->sa_family != AF_INET) {
		errno = EAFNOSUPPORT;
		return -EAFNOSUPPORT;
	}
	args.response = (void *) response;
	args.iovec = NULL;
		args.length = resplen;
	args.dest_addr = *((struct sockaddr_in *) dest_addr);
	args.id = id;
	return ioctl(sockfd, HOMAIOCREPLY, &args);
}

/**
 * homa_replyv() - Similar to homa_reply, except the response message can
 * be divided among several chunks of memory.
 * See the man page for documentation of this API.
 */
ssize_t homa_replyv(int sockfd, const struct iovec *iov, int iovcnt,
		const struct sockaddr *dest_addr, size_t addrlen,
		uint64_t id)
{
	struct homa_args_reply_ipv4 args = {};

	if (dest_addr->sa_family != AF_INET) {
		errno = EAFNOSUPPORT;
		return -EAFNOSUPPORT;
	}
	args.response = NULL;
	args.iovec = iov;
	args.length = iovcnt;
	args.dest_addr = *((struct sockaddr_in *) dest_addr);
	args.id = id;
	return ioctl(sockfd, HOMAIOCREPLY, &args);
}

/**
 * homa_send() - Send a request message to initiate an RPC.
 * See the man page for documentation of this API.
 */
int homa_send(int sockfd, const void *request, size_t reqlen,
		const struct sockaddr *dest_addr, size_t addrlen,
		uint64_t *id, uint64_t completion_cookie)
{
	struct homa_args_send_ipv4 args = {};
	int result;

	if (dest_addr->sa_family != AF_INET) {
		errno = EAFNOSUPPORT;
		return -EAFNOSUPPORT;
	}
	args.request = (void *) request;
	args.iovec = NULL;
	args.length = reqlen;
	args.dest_addr = *((struct sockaddr_in *) dest_addr);
	args.id = 0;
	args.completion_cookie = completion_cookie;
	result = ioctl(sockfd, HOMAIOCSEND, &args);
	if ((result >= 0) && (id != NULL))
		*id = args.id;
	return result;
}

/**
 * homa_sendv() - Same as homa_send, except that the request message can
 * be divided among multiple disjoint chunks of memory.
 * See the man page for documentation of this API.
 */
int homa_sendv(int sockfd, const struct iovec *iov, int iovcnt,
		const struct sockaddr *dest_addr, size_t addrlen,
		uint64_t *id, uint64_t completion_cookie)
{
	struct homa_args_send_ipv4 args = {};
	int result;

	if (dest_addr->sa_family != AF_INET) {
		errno = EAFNOSUPPORT;
		return -EAFNOSUPPORT;
	}
	args.request = NULL;
	args.iovec = iov;
	args.length = iovcnt;
	args.dest_addr = *((struct sockaddr_in *) dest_addr);
	args.id = 0;
	args.completion_cookie = completion_cookie;
	result = ioctl(sockfd, HOMAIOCSEND, &args);
	if ((result >= 0) && (id != NULL))
		*id = args.id;
	return result;
}

/**
 * homa_abort() - Terminate the execution of an RPC.
 * See the man page for documentation of this API.
 */
int homa_abort(int sockfd, uint64_t id, int error)
{
	struct homa_args_abort_ipv4 args = {id, error};
	return ioctl(sockfd, HOMAIOCABORT, &args);
}
