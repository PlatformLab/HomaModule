// This file contains a collection of tests for the Linux implementation
// of Homa
//
// Usage:
// homaTest host:port [options] op op ...
//
// host:port gives the location of a server to invoke
// Each op specifies a particular test to perform

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <thread>

#include "homa.h"

/**
 * get_int() - Parse an integer from a string, and exit if the parse fails.
 * @s:      String to parse.
 * @msg:    Error message to print (with a single %s specifier) on errors.
 * Return:  The integer value corresponding to @s.
 */
int get_int(const char *s, const char *msg)
{
	int value;
	value = strtol(s, NULL, 10);
	if (value == 0) {
		printf(msg, s);
		exit(1);
	}
	return value;
}

/**
 * close_fd() - Helper method for "close" test: sleeps a while, then closes
 * an fd
 * @fd:   Open file descriptor to close.
 */
void close_fd(int fd)
{
	sleep(1);
	int result = close(fd);
	if (result >= 0) {
		printf("Closed fd %d\n", fd);
	} else {
		printf("Close failed: %s\n", strerror(errno));
	}
}

/**
 * print_help() - Print out usage information for this program.
 * @name:   Name of the program (argv[0])
 */
void print_help(const char *name)
{
	printf("Usage: %s host:port [options] op op ...\n\n"
		"host:port describes a server to communicate with, and each op\n"
		"selects a particular test to run (see the code for available\n"
		"tests). The following options are supported:\n\n"
		"--length     Size of messages, in bytes (default: 100)\n"
		"--seed       Used to compute message contents (default: 0)\n",
		name);
}

int main(int argc, char** argv) {
	int fd, status, port, nextArg;
        unsigned int i;
	struct addrinfo *result;
	struct sockaddr_in *addr_in;
	struct addrinfo hints;
	char *host, *port_name;
	int seed = 0;
#define MAX_MESSAGE_LENGTH 100000
#define INTS_IN_BUFFER ((MAX_MESSAGE_LENGTH + sizeof(int) - 1)/sizeof(int))
	int buffer[INTS_IN_BUFFER];
	int length = 100;
	
	if ((argc >= 2) && (strcmp(argv[1], "--help") == 0)) {
		print_help(argv[0]);
		exit(0);
	}
	
	if (argc < 3) {
		printf("Usage: %s host:port [options] op op ...\n", argv[0]);
		exit(1);
	}
	host = argv[1];
	port_name = strchr(argv[1], ':');
	if (port_name == NULL) {
		printf("Bad server spec %s: must be 'host:port'\n", argv[1]);
		exit(1);
	}
	*port_name = 0;
	port_name++;
	port = get_int(port_name,
			"Bad port number %s; must be positive integer\n");
	for (nextArg = 2; (nextArg < argc) && (*argv[nextArg] == '-');
			nextArg += 1) {
		if (strcmp(argv[nextArg], "--help") == 0) {
			print_help(argv[0]);
			exit(0);
		} else if (strcmp(argv[nextArg], "--length") == 0) {
			if (nextArg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[nextArg]);
				exit(1);
			}
			nextArg++;
			length = get_int(argv[nextArg],
				"Bad message length %s; must be positive "
				"integer\n");
			if (length > MAX_MESSAGE_LENGTH) {
				length = MAX_MESSAGE_LENGTH;
				printf("Reducing message length to %d", length);
			}
		} else if (strcmp(argv[nextArg], "--seed") == 0) {
			if (nextArg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[nextArg]);
				exit(1);
			}
			nextArg++;
			seed = get_int(argv[nextArg],
				"Bad seed %s; must be positive integer\n");
		} else {
			printf("Unknown option %s; type '%s -help' for help\n",
				argv[nextArg], argv[0]);
			exit(1);
		}
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
	addr_in = (struct sockaddr_in *) result->ai_addr;
	addr_in->sin_port = htons(port);
	for (i = 0; i < INTS_IN_BUFFER; i++) {
		buffer[i] = seed + i;
	}
	
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
	if (fd < 0) {
		printf("Couldn't open Homa socket: %s\n", strerror(errno));
		exit(1);
	}
	
	for ( ; nextArg < argc; nextArg++) {
		if (strcmp(argv[nextArg], "close") == 0) {
			/* Test what happens if a socket is closed while a
			 * thread is waiting on it. */
			int result, fd2;
			struct msghdr msg;
			struct iovec iovec;
			int message[100000];
			struct sockaddr_in source;
			
			iovec.iov_base = message;
			iovec.iov_len = sizeof(message);
			msg.msg_name = &source;
			msg.msg_namelen = sizeof(source);
			msg.msg_iov = &iovec;
			msg.msg_iovlen = 1;
			msg.msg_control = NULL;
			msg.msg_controllen = 0;
			msg.msg_flags = 0;
			
			fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
			if (fd2 < 0) {
				printf("Couldn't open Homa socket: %s\n",
					strerror(errno));
				exit(1);
			}
			std::thread thread(close_fd, fd2);
			result = recvmsg(fd2, &msg, 0);
			if (result > 0) {
				printf("Received %d bytes\n", result);
			} else {
				printf("Error in recvmsg: %s\n",
					strerror(errno));
			}
		} else if (strcmp(argv[nextArg], "send") == 0) {
			uint64_t id;
			/* Send a single message to the server. */
			status = homa_send(fd, buffer, length, result->ai_addr,
					result->ai_addrlen, &id);
			if (status < 0) {
				printf("Error in homa_send: %s\n",
					strerror(errno));
			} else {
				printf("Homa_send succeeded, id %lu\n", id);
			}
		} else if (strcmp(argv[nextArg], "udpclose") == 0) {
			/* Test what happens if a UDP socket is closed while a
			 * thread is waiting on it. */
			struct sockaddr_in address;
			char buffer[1000];
			
			int fd2 = socket(AF_INET, SOCK_DGRAM, 0);
			if (fd2 < 0) {
				printf("Couldn't open UDP socket: %s\n",
					strerror(errno));
				exit(1);
			}
			address.sin_family = AF_INET;
			address.sin_addr.s_addr = htonl(INADDR_ANY);
			address.sin_port = 0;
			int result = bind(fd2,
				reinterpret_cast<struct sockaddr*>(&address),
				sizeof(address));
			if (result < 0) {
				printf("Couldn't bind UDP socket: %s\n",
					strerror(errno));
				exit(1);
			}
			std::thread thread(close_fd, fd2);
			result = read(fd2, buffer, sizeof(buffer));
			if (result >= 0) {
				printf("UDP read returned %d bytes\n", result);
			} else {
				printf("UDP read returned error: %s\n",
					strerror(errno));
			}
		} else {
			printf("Unknown operation '%s'\n", argv[nextArg]);
			exit(1);
		}
	}
	exit(0);
}

