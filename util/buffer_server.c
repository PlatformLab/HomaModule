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

/* This is a test program used together with buffer_client.c to learn about
 * how TCP handles buffer exhaustion. This program opens accepts connections
 * on a given port, but it never reads any incoming data, so buffers will
 * pile up in the kernel.
 *
 * Usage:
 * buffer_server port
 */

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "homa.h"

int main(int argc, char** argv) {
	int fd, port;
	int optval = 1;
	sockaddr_in_union bindAddress;

	if (argc < 2) {
		printf("Usage: %s port\n", argv[0]);
		exit(1);
	}
	port = strtol(argv[1], NULL, 10);
	if (port == 0) {
		printf("Bad port number %s; must be integer\n",
				argv[1]);
		exit(1);
	}

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("Couldn't create socket: %s\n", strerror(errno));
		exit(1);
	}
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval,
                           sizeof(optval)) != 0) {
		printf("Couldn't set SO_REUSEADDR: %s\n", strerror(errno));
		exit(1);
	}
	bindAddress.in4.sin_family = AF_INET;
	bindAddress.in4.sin_port = htons(port);
	bindAddress.in4.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(fd, &bindAddress.sa, sizeof(bindAddress.in4))
	    != 0) {
		printf("Couldn't bind to port %d\n: %s\n", port, strerror(errno));
		exit(1);
	}
	if (listen(fd, 1000000) != 0) {
		printf("Listen failed on socket: %s\n", strerror(errno));
		exit(1);
	}

	while (1) {
		int peerFd;
		peerFd = accept(fd, NULL, NULL);
		if (peerFd < 0) {
			printf("Accept failed: %s\n", strerror(errno));
		} else {
			printf("Accepted connection on fd %d\n", peerFd);
		}
	}
	exit(0);
}

