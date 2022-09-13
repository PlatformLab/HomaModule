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

/* This is a test program that acts as a server for testing either
 * Homa or TCP; it simply accepts request packets of arbitrary length
 * and responds with packets whose length is determined by the request.
 * The program runs forever; use control-C to kill it.
 *
 * Usage:
 * server [options]
 *
 * Type "server --help" for documenation on the options.
 */

#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <thread>

#include "homa.h"
#include "test_utils.h"

/* Log events to standard output. */
bool verbose = false;

/* Port number on which to listen (both for Homa and TCP); if multiple
 * Homa ports are in use, they will be consecutive numbers starting with
 * this. */
int port = 4000;

/* True that a specific format is expected for incoming messages, and we
 * should check that incoming messages conform to it.
 */
bool validate = false;

/**
 * homa_server() - Opens a Homa socket and handles all requests arriving on
 * that socket.
 * @port:   Port number to use for the Homa socket.
 */
void homa_server(int port)
{
	int fd;
	struct sockaddr_in addr_in;
	int message[1000000];
	struct sockaddr_in source;
	size_t source_length;
	int length;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
	if (fd < 0) {
		printf("Couldn't open Homa socket: %s\n", strerror(errno));
		return;
	}

	memset(&addr_in, 0, sizeof(addr_in));
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *) &addr_in, sizeof(addr_in)) != 0) {
		printf("Couldn't bind socket to Homa port %d: %s\n", port,
				strerror(errno));
		return;
	}
	if (verbose)
		printf("Successfully bound to Homa port %d\n", port);
	while (1) {
		uint64_t id = 0;
		int seed;
		int result;

		source_length = sizeof(source);
		length = homa_recv(fd, message, sizeof(message),
			HOMA_RECV_REQUEST, (struct sockaddr *) &source,
			&source_length, &id, NULL, NULL);
		if (length < 0) {
			printf("homa_recv failed: %s\n", strerror(errno));
			continue;
		}
		if (validate) {
			seed = check_buffer(&message[2],
				length - 2*sizeof32(int));
			if (verbose)
				printf("Received message from %s with %d bytes, "
					"id %lu, seed %d, response length %d\n",
					print_address(&source), length, id,
					seed, message[1]);
		} else
			if (verbose)
				printf("Received message from %s with "
					"%d bytes, id %lu, response length %d\n",
					print_address(&source), length, id,
					message[1]);

		/* Second word of the message indicates how large a
		 * response to send.
		 */
		result = homa_reply(fd, message, message[1],
			(struct sockaddr *) &source, source_length, id);
		if (result < 0) {
			printf("Homa_reply failed: %s\n", strerror(errno));
		}
	}
}

/**
 * print_help() - Print out usage information for this program.
 * @name:   Name of the program (argv[0])
 */
void print_help(const char *name)
{
	printf("Usage: %s [options]\n\n"
		"The following options are supported:\n\n"
		"--help       Print this message and exit\n"
		"--port       (First) port number to use (default: 4000)\n"
		"--num_ports  Number of Homa ports to open (default: 1)\n"
		"--validate   Validate contents of incoming messages (default: false\n"
		"--verbose    Log events as they happen (default: false)\n",
		name);
}

/**
 * tcp_connection() - Handles messages arriving on a given socket.
 * @fd:           File descriptor for the socket over which messages
 *                will arrive.
 * @client_addr:  Information about the client (for messages).
 */
void tcp_connection(int fd, struct sockaddr_in source)
{
	int flag = 1;
	char buffer[1000000];
	int cur_length = 0;
	bool streaming = false;

	int *int_buffer = reinterpret_cast<int*>(buffer);
	if (verbose)
		printf("New TCP socket from %s\n", print_address(&source));
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	while (1) {
		int result = read(fd, buffer + cur_length,
				sizeof(buffer) - cur_length);
		if (result < 0) {
			if (errno == ECONNRESET)
				break;
			printf("Read error on socket: %s", strerror(errno));
			exit(1);
		}
		if (result == 0)
			break;

		/* The connection can be used in two modes. If the first
		 * word received is -1, then the connection is in streaming
		 * mode: we just read bytes and throw them away. If the
		 * first word isn't -1, then it's in message mode: we read
		 * full messages and respond to them.
		 */
		if (streaming)
			continue;
		if (int_buffer[0] < 0) {
			streaming = true;
			continue;
		}
		cur_length += result;

		/* First word of request contains expected length in bytes. */
		if ((cur_length >= 2*sizeof32(int))
				&& (cur_length >= int_buffer[0])) {
			if (cur_length != int_buffer[0])
				printf("Received %d bytes but buffer[0] = %d, "
					"buffer[1] = %d\n",
					cur_length, int_buffer[0],
					int_buffer[1]);
			if (validate) {
				int seed = check_buffer(&int_buffer[2],
					int_buffer[0] - 2*sizeof32(int));
				if (verbose)
					printf("Received message from %s with "
						"%d bytes, seed %d\n",
						print_address(&source),
						int_buffer[0], seed);
			} else if (verbose)
				printf("Received message from %s with %d "
					"bytes\n",
					print_address(&source), int_buffer[0]);
			cur_length = 0;
			if (int_buffer[1] <= 0)
				continue;
			if (write(fd, buffer, int_buffer[1]) != int_buffer[1]) {
				printf("Socket write failed: %s\n",
						strerror(errno));
				exit(1);
			};
		}
	}
	if (verbose)
		printf("Closing TCP socket from %s\n", print_address(&source));
	close(fd);
}

/**
 * tcp_server() - Opens a TCP socket, accepts connections on that socket
 * (one thread per connection) and processes messages on those connections.
 * @port:  Port number on which to listen.
 */
void tcp_server(int port)
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
		struct sockaddr_in client_addr;
		socklen_t addr_len = sizeof(client_addr);
		if (listen(listen_fd, 1000) == -1) {
			printf("Couldn't listen on socket: %s", strerror(errno));
			exit(1);
		}
		int stream = accept(listen_fd,
				reinterpret_cast<sockaddr *>(&client_addr),
				&addr_len);
		if (stream < 0) {
			printf("Couldn't accept incoming connection: %s",
				strerror(errno));
			exit(1);
		}
		std::thread thread(tcp_connection, stream, client_addr);
		thread.detach();
	}
}

int main(int argc, char** argv) {
	int next_arg;
	int num_ports = 1;

	if ((argc >= 2) && (strcmp(argv[1], "--help") == 0)) {
		print_help(argv[0]);
		exit(0);
	}

	for (next_arg = 1; next_arg < argc; next_arg++) {
		if (strcmp(argv[next_arg], "--help") == 0) {
			print_help(argv[0]);
			exit(0);
		} else if (strcmp(argv[next_arg], "--port") == 0) {
			if (next_arg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[next_arg]);
				exit(1);
			}
			next_arg++;
			port = get_int(argv[next_arg],
					"Bad port %s; must be positive integer\n");
		} else if (strcmp(argv[next_arg], "--num_ports") == 0) {
			if (next_arg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[next_arg]);
				exit(1);
			}
			next_arg++;
			num_ports = get_int(argv[next_arg],
				"Bad num_ports %s; must be positive integer\n");
		} else if (strcmp(argv[next_arg], "--validate") == 0) {
			validate = true;
		} else if (strcmp(argv[next_arg], "--verbose") == 0) {
			verbose = true;
		} else {
			printf("Unknown option %s; type '%s --help' for help\n",
				argv[next_arg], argv[0]);
			exit(1);
		}
	}

	for (int i = 0; i < num_ports; i++) {
		std::thread thread(homa_server, port+i);
		thread.detach();
	}

	tcp_server(port);
}
