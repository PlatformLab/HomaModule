/* Copyright (c) 2026 Homa Developers
 * SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+
 */

/* This file implements a simple single-threaded Homa client that
 * issues a series of RPCs of varying lengths:
 *
 * Usage:
 * demo_client1 server port
 */

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "homa.h"

/**
 * checksum() - Compute the 32-bit checksum of an incoming message.
 * @recv_args:     Contains information about the fragments of
 *                 an incoming Homa message.
 * @length:        Total length of the message; must be a multiple of 4.
 * @region:        Base address of the buffer region.
 */
uint32_t checksum(struct homa_recvmsg_args *recv_args, int length,
		  char *buf_region)
{
	uint32_t sum = 0;
	int bytes_left = length;

	for (uint32_t i = 0; i < recv_args->num_bpages; i++) {
		uint32_t *buf = reinterpret_cast<uint32_t *>(
				buf_region + recv_args->bpage_offsets[i]);
		size_t bp_bytes = bytes_left;
		if (bp_bytes > HOMA_BPAGE_SIZE)
			bp_bytes = HOMA_BPAGE_SIZE;
		bytes_left -= bp_bytes;

		while (bp_bytes >= sizeof(uint32_t)) {
			sum += *buf;
			buf++;
			bp_bytes -= 4;
		}
	}
	return sum;
}

/**
 * homa_client() - Send a series of requests to a given server, waiting
 * for each response.
 * @fd:          File descriptor for socket to use for requests.
 * @buf_region:  Base address of the region of memory that will be used for
 *               receive buffers on fd.
 * @daddr:       Where to send requests.
 */
void homa_client(int fd, char *buf_region, struct sockaddr_in *daddr)
{
	int cookie = 100;
	int req_lengths[] = {100, 1000, 10000, 50000, 100000,
			     HOMA_MAX_MESSAGE_LENGTH};

	/* Prepare the request "message". */
	char request[HOMA_MAX_MESSAGE_LENGTH];
	for (int i = 0; i < HOMA_MAX_MESSAGE_LENGTH; i += 4) {
		int *p = reinterpret_cast<int *>(request + i);
		*p = i;
	}

	/* Initialize parameter blocks for recvmsg. By reusing the same
	 * parameter block without reinitizlization, each receive
	 * automatically returns to Homa the buffers from the previous
	 * receive.
	 */
	struct homa_recvmsg_args recv_args;
	memset(&recv_args, 0, sizeof(recv_args));

	struct msghdr recv_hdr;
	recv_hdr.msg_name = NULL;
	recv_hdr.msg_namelen = 0;
	recv_hdr.msg_iov = NULL;
	recv_hdr.msg_iovlen = 0;
	recv_hdr.msg_control = &recv_args;
	recv_hdr.msg_controllen = sizeof(recv_args);
	recv_hdr.msg_flags = 0;

	/* Each iteration through the following loop sends one request
	 * and waits for its response.
	 */
	for (size_t i = 0; i < sizeof(req_lengths)/sizeof(*req_lengths); i++) {
		/* Initialize the Homa-specific parameter block for the
		 * request message.
		 */
		struct homa_sendmsg_args send_args;
		memset(&send_args, 0, sizeof(send_args));
		send_args.completion_cookie = cookie;
		cookie++;
		send_args.flags = HOMA_SENDMSG_PRIVATE;

		/* Initialize the parameter block for sendmsg. */
		struct iovec vec;
		vec.iov_base = request;
		vec.iov_len = req_lengths[i];

		struct msghdr send_hdr;
		send_hdr.msg_name = (struct sockaddr *)daddr;
		send_hdr.msg_namelen = sizeof(*daddr);
		send_hdr.msg_iov = &vec;
		send_hdr.msg_iovlen = 1;
		send_hdr.msg_control = &send_args;
		send_hdr.msg_controllen = 0;   /* See Homa man page. */
		send_hdr.msg_flags = 0;

		/* Send the request. */
		int status = sendmsg(fd, &send_hdr, 0);
		if (status < 0) {
			fprintf(stderr, "sendmsg for request failed: %s\n",
				strerror(errno));
			return;
		}
		printf("Sent request for RPC id %llu with %lu bytes\n",
		       send_args.id, vec.iov_len);

		/* Receive the response. */
		recv_args.id = send_args.id;
		recv_hdr.msg_controllen = sizeof(recv_args);
		int resp_length = recvmsg(fd, &recv_hdr, 0);
		if (resp_length < 0) {
			fprintf(stderr, "recvmsg failed: %s\n",
				strerror(errno));
			return;
		}

		/* Print info about the response. */
		printf("Received response with %d bytes, id %llu, %d frags, "
		       "cookie %lld, checksum 0x%x\n", resp_length,
		       recv_args.id, recv_args.num_bpages,
		       recv_args.completion_cookie,
		       checksum(&recv_args, resp_length, buf_region));
	}
}

int main(int argc, char** argv)
{
	struct sockaddr_in daddr;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s server_addr port\n", argv[0]);
		exit(1);
	}

	/* Lookup the server address. */
	struct addrinfo *matching_addresses;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	int status = getaddrinfo(argv[1], argv[2], &hints, &matching_addresses);
	if (status != 0) {
		fprintf(stderr, "Couldn't look up address for %s: %s\n",
			argv[1], gai_strerror(status));
		exit(1);
	}
	daddr = *(sockaddr_in *)matching_addresses->ai_addr;

	/* Open client socket. */
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
	if (fd < 0) {
		fprintf(stderr, "Couldn't open Homa socket: %s\n",
			strerror(errno));
		exit(1);
	}

	// Set up receive buffer region.
	char *buf_region = (char *) mmap(NULL, 1000*HOMA_BPAGE_SIZE,
				   PROT_READ|PROT_WRITE,
				   MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
	if (buf_region == MAP_FAILED) {
		fprintf(stderr, "Couldn't mmap buffer region: %s\n",
			strerror(errno));
		exit(1);
	}
	struct homa_rcvbuf_args rcvbuf_args;
	rcvbuf_args.start = (uintptr_t)buf_region;
	rcvbuf_args.length = 1000*HOMA_BPAGE_SIZE;
	status = setsockopt(fd, IPPROTO_HOMA, SO_HOMA_RCVBUF, &rcvbuf_args,
				sizeof(rcvbuf_args));
	if (status < 0) {
		fprintf(stderr, "Error in setsockopt(SO_HOMA_RCVBUF): %s\n",
			strerror(errno));
		exit(1);
	}

	homa_client(fd, buf_region, &daddr);
}