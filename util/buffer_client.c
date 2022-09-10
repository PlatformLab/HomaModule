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

/* This is a test program used together with buffer_server.c to learn about
 * how TCP handles buffer exhaustion. This program opens an infinite series
 * of sockets to a single port and writes as much data to each socket as
 * if can before the socket backs up (it assumes that the server application
 * is not reading any of the data). Once each socket backs up, it goes on
 * to the next socket.
 *
 * Usage:
 * buffer_client hostName port
 */

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(int argc, char** argv) {
	int fd, status, port;
	struct addrinfo *result;
	struct addrinfo hints;
	char *host;
#define BUFFER_SIZE 4096
	char buffer[BUFFER_SIZE];
	int bytesSent;

	if (argc < 3) {
		printf("Usage: %s hostName port\n", argv[0]);
		exit(1);
	}
	host = argv[1];
	port = strtol(argv[2], NULL, 10);
	if (port == 0) {
		printf("Bad port number %s; must be integer\n",
				argv[2]);
		exit(1);
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	status = getaddrinfo(host, argv[2], &hints, &result);
	if (status != 0) {
		printf("Couldn't look up address for %s: %s\n",
				host, gai_strerror(status));
		exit(1);
	}

	while (1) {
		fd = socket(PF_INET, SOCK_STREAM, 0);
		if (fd < 0) {
			printf("Couldn't create socket: %s\n", strerror(errno));
			exit(1);
		}
		status = connect(fd, result->ai_addr, result->ai_addrlen);
		if (status < 0) {
		    close(fd);
		    fd = -1;
		    printf("Couldn't connect to %s:%d: %s\n", host, port,
				strerror(errno));
		    sleep(5);
		    continue;
		}

		bytesSent = 0;
		while (1) {
			status = send(fd, buffer, BUFFER_SIZE,
				MSG_NOSIGNAL|MSG_DONTWAIT);
			if (status > 0) {
				bytesSent += status;
				continue;
			}
			if (status == 0) {
				printf("Fd %d got 0 status after sending %d bytes\n",
						fd, bytesSent);
			} else if (errno == EAGAIN) {
				printf("Fd %d blocked after sending %d bytes\n",
						fd, bytesSent);
			} else {
				printf("Fd %d failed after sending %d "
						"bytes: %s (%d)\n",
						fd, bytesSent, strerror(errno),
						errno);
			}
			break;
		}
	}
	exit(0);
}

