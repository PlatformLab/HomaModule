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
	struct msghdr msg;
	struct iovec iovec;
	int message[100000];
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
		iovec.iov_base = message;
		iovec.iov_len = sizeof(message);
		msg.msg_name = &source;
		msg.msg_namelen = sizeof(source);
		msg.msg_iov = &iovec;
		msg.msg_iovlen = 1;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;
		length = recvmsg(fd, &msg, 0);
		if (length > 0) {
			int seed = message[0];
			int limit = (length + sizeof(int) - 1)/sizeof(int);
			int i;
			printf ("Received message with %d bytes, seed %d\n",
				length, seed);
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
		sleep(1);
	}
}
