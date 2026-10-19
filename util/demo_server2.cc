/* Copyright (c) 2026 Homa Developers
 * SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+
 */

/* This file implements a multi-threaded Homa server that listens on
 * port 4000 and echos back its requests.
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

#include <thread>

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
 * homa_server() - Handle requests arriving on a given socket. Each request
 * is handled by printing a checksum of the message, then echoing the message
 * back to the client. This function does not return.
 * @fd:          File descriptor for socket to receive requests from.
 * @buf_region:  Base address of the region of memory provided to Homa for
 *               receive buffers for fd.
 * @thread_id:   Numeric identifier for this thread.
 */
void homa_server(int fd, char *buf_region, int thread_id)
{
	struct sockaddr_in saddr;

	/* Initialize parameter blocks for recvmsg. */
	struct homa_recvmsg_args recv_args;
	memset(&recv_args, 0, sizeof(recv_args));

	struct msghdr recv_hdr;
	recv_hdr.msg_name = &saddr;
	recv_hdr.msg_namelen = sizeof(saddr);
	recv_hdr.msg_iov = NULL;
	recv_hdr.msg_iovlen = 0;
	recv_hdr.msg_control = &recv_args;
	recv_hdr.msg_controllen = sizeof(recv_args);
	recv_hdr.msg_flags = 0;

	/* Each iteration through the following loop processes one request. */
	while (1) {
		/* Note: by reusing recv_args for successive calls to
		 * recvmsg we automatically return to Homa the buffers
		 * left in recv_args by the previous call to recvmsg.
		 */
		recv_args.id = 0;
		recv_hdr.msg_controllen = sizeof(recv_args);
		int length = recvmsg(fd, &recv_hdr, 0);
		if (length < 0) {
			fprintf(stderr, "recvmsg failed: %s\n",
				strerror(errno));
			continue;
		}

		/* Print info about the request. */
		char host[NI_MAXHOST];
		char port[NI_MAXSERV];
		int status = getnameinfo((struct sockaddr *)&saddr,
					  sizeof(saddr), host, sizeof(host),
                    			  port, sizeof(port),
                    			  NI_NUMERICHOST | NI_NUMERICSERV);
		if (status != 0)
			fprintf(stderr, "getnameinfo failed: %s\n",
				gai_strerror(status));
		else
			printf("Thread %d received id %llu from %s:%s with %d bytes, "
			       "checksum 0x%x\n", thread_id, recv_args.id,
			       host, port, length,
			       checksum(&recv_args, length, buf_region));

		/* Echo the request message back as response. First set up
		 * the iovecs for the message.
		 */
		int num_vecs = 0;
		int bytes_left = length;
		struct iovec vecs[HOMA_MAX_BPAGES];
		while (bytes_left > 0) {
			vecs[num_vecs].iov_len = (bytes_left > HOMA_BPAGE_SIZE)
					? HOMA_BPAGE_SIZE : bytes_left;
			vecs[num_vecs].iov_base = buf_region +
					recv_args.bpage_offsets[num_vecs];
			bytes_left -= vecs[num_vecs].iov_len;
			num_vecs++;
		}

		/* Initialize the Homa-specific parameter block. */
		struct homa_sendmsg_args resp_args;
		memset(&resp_args, 0, sizeof(resp_args));
		resp_args.id = recv_args.id;

		/* Initialize the parameter block for sendmsg. */
		struct msghdr resp_hdr;
		resp_hdr.msg_name = (struct sockaddr *)&saddr;
		resp_hdr.msg_namelen = sizeof(saddr);
		resp_hdr.msg_iov = vecs;
		resp_hdr.msg_iovlen = num_vecs;
		resp_hdr.msg_control = &resp_args;
		resp_hdr.msg_controllen = 0;   /* See Homa man page. */
		resp_hdr.msg_flags = 0;

		/* Send the response. */
		status = sendmsg(fd, &resp_hdr, 0);
		if (status < 0) {
			fprintf(stderr, "sendmsg for reply failed: %s\n",
				strerror(errno));
		}
	}
}

int main(int argc, char** argv)
{
	struct sockaddr_in addr;

	/* Open server socket, set up port binding. */
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
	if (fd < 0) {
		fprintf(stderr, "Couldn't open Homa socket: %s\n",
			strerror(errno));
		exit(1);
	}

	int port = 4000;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		fprintf(stderr, "Couldn't bind socket to Homa port %d: %s\n",
			port, strerror(errno));
		exit(1);
	}
	printf("Successfully bound to Homa port %d\n", port);

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
	int status = setsockopt(fd, IPPROTO_HOMA, SO_HOMA_RCVBUF, &rcvbuf_args,
				sizeof(rcvbuf_args));
	if (status < 0) {
		fprintf(stderr, "Error in setsockopt(SO_HOMA_RCVBUF): %s\n",
			strerror(errno));
		exit(1);
	}

	for (int i = 0; i < 5; i++) {
		std::thread thread(homa_server, fd, buf_region, i);
		thread.detach();
	}
	homa_server(fd, buf_region, 4);
}