// This is a test program that opens a Homa socket and responds to
// requests.
//
// Usage: homaServer port

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "homa.h"

// Homa's protocol number within the IP protocol space.
#define IPPROTO_HOMA 140

/**
 * printAddress() - Generate a human-readable description of an inet address.
 * @addr:    The address to print
 * @buffer:  Where to store the human readable description.
 * @size:    Number of bytes available in buffer.
 * Return:   The address of the human-readable string (buffer).
 */
char *printAddress(struct sockaddr_in *addr, char *buffer, int size)
{
	if (addr->sin_family != AF_INET) {
		snprintf(buffer, size, "Unknown family %d", addr->sin_family);
		return buffer;
	}
	uint8_t *ipaddr = (uint8_t *) &addr->sin_addr;
	snprintf(buffer, size, "%u.%u.%u.%u:%u", ipaddr[0], ipaddr[1],
		ipaddr[2], ipaddr[3], ntohs(addr->sin_port));
	return buffer;
}

int main(int argc, char** argv) {
	int fd;
	int port;
	struct sockaddr_in addr_in;
	int message[100000];
	char sourceAddress[1000];
	struct sockaddr_in source;
	int length;
	
	if (argc < 2) {
		printf("Usage: %s port\n", argv[0]);
		exit(1);
	}
	port = strtol(argv[1], NULL, 10);
	if (port == 0) {
		printf("Bad port number %s; must be positive integer\n",
				argv[1]);
		exit(1);
	}
	
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
	if (fd < 0) {
		printf("Couldn't open Homa socket: %s\n", strerror(errno));
		exit(1);
	}
	
	memset(&addr_in, 0, sizeof(addr_in));
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *) &addr_in, sizeof(addr_in)) != 0) {
		printf("Couldn't bind socket to Homa port %d: %s\n", port,
				strerror(errno));
		exit(1);
	}
	printf("Successfully bound to Homa port %d\n", port);
	while (1) {
		uint64_t id;
		length = homa_recv(fd, message, sizeof(message),
			(struct sockaddr *) &source, sizeof(source), &id);
		if (length > 0) {
			int seed = message[0];
			int limit = (length + sizeof(int) - 1)/sizeof(int);
			int i;
			printf("Received message from %s with %d bytes, "
				"seed %d, id %lu\n",
				printAddress(&source, sourceAddress,
				sizeof(sourceAddress)),length, seed, id);
			for (i = 0; i < limit; i++) {
				if (message[i] != seed + i) {
					printf("Bad value at index %d in "
						"message; expected %d, got %d\n",
						i, seed+i, message[i]);
					break;
				}
			}
		} else {
			printf("Recvmsg failed: %s\n", strerror(errno));
		}
		// sleep(1);
	}
}
