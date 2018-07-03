// This is a test program to exercise Homa from the sender side.
//
// Usage:
// homaSend hostName message

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

// Homa's protocol number within the IP protocol space.
#define IPPROTO_HOMA 140

int main(int argc, char** argv) {
	int fd, status;
	struct addrinfo *result;
	struct addrinfo hints;
	char *host;
//	char *sockType;
//	struct addrinfo  *rp;
//	int count;
	char *message;
	
	if (argc < 3) {
		printf("Usage: %s hostName message\n", argv[0]);
		exit(1);
	}
	host = argv[1];
	message = argv[2];
	
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	status = getaddrinfo(host, "80", &hints, &result);
	if (status != 0) {
		printf("Couldn't look up address for %s: %s\n",
				host, gai_strerror(status));
		exit(1);
	}
//	count = 0;
//	for (rp = result; rp != NULL; rp = rp->ai_next) {
//		if (rp->ai_socktype == SOCK_DGRAM) {
//			sockType = "SOCK_DGRAM";
//		} else if (rp->ai_socktype == SOCK_STREAM) {
//			sockType = "SOCK_STREAM";
//		} else {
//			sockType = "OTHER";
//		}
//		printf("canonname: %s, flags: %d, family: %d, socktype %s, "
//				"protocol: %d, addrlen: %d\n",
//				rp->ai_canonname, rp->ai_flags,
//				rp->ai_family, sockType,
//				rp->ai_protocol, rp->ai_addrlen);
//		count++;
//	}
//	printf("Getaddrinfo returned %d addresses\n", count);
	
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
	if (fd < 0) {
		printf("Couldn't open socket: %s\n", strerror(errno));
		exit(1);
	}
	
	status = sendto(fd, message, strlen(message), 0, result->ai_addr,
			result->ai_addrlen);
	if (status < 0) {
		printf("Error in sendto: %s\n", strerror(errno));
	}
	exit(0);
}

