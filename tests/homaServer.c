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

// Homa's protocol number within the IP protocol space.
#define IPPROTO_HOMA 140

int main(int argc, char** argv) {
	int fd;
	int port;
	struct sockaddr_in addr_in;
	
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
		sleep(1000);
	}
}
