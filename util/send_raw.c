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

/* This is a test program that will send a packet to a given
 * IP protocol, with given contents.
 *
 * Usage: send_raw hostName contents [protocol]
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
	int fd, status;
	struct addrinfo *result;
	struct addrinfo hints;
	char *message;
	char *host;
	int protocol;
	sockaddr_in_union *addr;
	uint8_t *bytes;

	if (argc < 3) {
		printf("Usage: %s hostName contents [protocol]\n", argv[0]);
		exit(1);
	}
	host = argv[1];
	message = argv[2];
	if (argc >= 4) {
		protocol = strtol(argv[3], NULL, 10);
		if (protocol == 0) {
			printf("Bad protocol number %s; must be integer\n",
					argv[3]);
			exit(1);
		}
	} else {
		protocol = IPPROTO_HOMA;
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	status = getaddrinfo(host, "80", &hints, &result);
	if (status != 0) {
		printf("Couldn't look up address for %s: %s\n",
				host, gai_strerror(status));
		exit(1);
	}
	addr = (sockaddr_in_union*) result->ai_addr;
	bytes = (uint8_t *) &addr->in4.sin_addr;
	printf("Destination address: %x (%d.%d.%d.%d)\n", addr->in4.sin_addr.s_addr,
		bytes[0], bytes[1], bytes[2], bytes[3]);

	fd = socket(AF_INET, SOCK_RAW, protocol);
	if (fd < 0) {
		printf("Couldn't open raw socket: %s\n", strerror(errno));
		exit(1);
	}

	status = sendto(fd, message, strlen(message), 0, result->ai_addr,
			result->ai_addrlen);
	if (status < 0) {
		printf("Error in sendto: %s\n", strerror(errno));
	} else {
		printf("Sendto succeeded\n");
	}
	exit(0);
}

