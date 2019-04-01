// This file implements a simple benchmark that measures the round-trip
// latency for short messages sent over TCP.
//
// Usage:
// tcp_ping host port (for the client side)
// tcp_ping port (for the server side)
//
// host and port give the location of the server

#include <errno.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "test_utils.h"

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

void run_server(int port)
{
	int listen_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (listen_fd == -1) {
		printf("Couldn't open server socket: %s\n", strerror(errno));
		exit(1);
	}
	int option_value = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &option_value,
			sizeof(option_value)) != 0) {
		printf("Couldn't set SO_REUSEADDR on listen socket: %s",
			strerror(errno));
		exit(1);
	}
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(listen_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr))
			== -1) {
		printf("Couldn't bind to port %d: %s\n", port, strerror(errno));
		exit(1);
	}
	while (1) {
		if (listen(listen_fd, 1000) == -1) {
			printf("Couldn't listen on socket: %s", strerror(errno));
			exit(1);
		}
		int stream = accept(listen_fd, NULL, NULL);
		if (stream < 0) {
			printf("Couldn't accept incoming connection: %s",
				strerror(errno));
			exit(1);
		}
		int flag = 1;
		setsockopt(stream, IPPROTO_TCP, TCP_NODELAY, &flag,
				sizeof(flag));
		while (1) {
			char buffer[10000];
			int num_bytes = read(stream, buffer, sizeof(buffer));
			if (num_bytes == 0)
				break;
			if (num_bytes < 0)  {
				printf("Read error on socket: %s",
						strerror(errno));
				exit(1);
			}
			if (write(stream, buffer, num_bytes) != num_bytes) {
				printf("Socket write failed: %s\n", strerror(errno));
				exit(1);
			}
		}
	}
}

void ping(int stream)
{
	char buffer[10000];
	if (write(stream, buffer, 100) != 100) {
		printf("Socket write failed: %s\n", strerror(errno));
		exit(1);
	}
	int num_bytes = read(stream, buffer, sizeof(buffer));
	if (num_bytes > 0)
		return;
	if (num_bytes < 0) {
		printf("Socket read failed: %s\n", strerror(errno));
		exit(1);
	}
	printf("Server closed socket\n");
	exit(1);
}

void run_client(char *server_name, int port)
{
	struct addrinfo hints;
	struct addrinfo *matching_addresses;
	struct sockaddr *dest;
	int status, i;
	
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	status = getaddrinfo(server_name, "80", &hints, &matching_addresses);
	if (status != 0) {
		printf("Couldn't look up address for %s: %s\n",
				server_name, gai_strerror(status));
		exit(1);
	}
	dest = matching_addresses->ai_addr;
	((struct sockaddr_in *) dest)->sin_port = htons(port);
	
	int stream = socket(PF_INET, SOCK_STREAM, 0);
	if (stream == -1) {
		printf("Couldn't open client socket: %s\n", strerror(errno));
		exit(1);
	}
	if (connect(stream, dest, sizeof(struct sockaddr_in)) == -1) {
		printf("Couldn't connect to %s:%d: %s\n", server_name, port,
				strerror(errno));
		exit(1);
	}
	int flag = 1;
	setsockopt(stream, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	
	/* Warm up. */
	for (i = 0; i < 10; i++)
		ping(stream);
	
#define COUNT 100000
	uint64_t times[COUNT+1];
	for (i = 0; i < COUNT; i++) {
		times[i] = rdtsc();
		ping(stream);
	}
	times[COUNT] = rdtsc();
	
	for (i = 0; i < COUNT; i++) {
		times[i] = times[i+1] - times[i];
	}
	print_dist(times, COUNT);
	return;
}

int main(int argc, char** argv)
{
	char *port_name;
	int port;
	
	if ((argc != 2) && (argc != 3)) {
		printf("Usage: %s [host] port\n", argv[0]);
		exit(1);
	}
	
	port_name = argv[argc-1];
	port = get_int(port_name,
			"Bad port number %s; must be positive integer\n");
	if (argc == 2)
		run_server(port);
	else
		run_client(argv[1], port);
	
	exit(0);
}