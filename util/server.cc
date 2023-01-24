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
 * It's typically used along with homa_test, which implements the client
 * side.  The program runs forever; use control-C to kill it.
 *
 * Usage:
 * server [options]
 *
 * Type "server --help" for documentation on the options.
 */

#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

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

/* Either AF_INET or AF_INET6: indicates whether to use IPv6 instead of IPv4. */
int inet_family = AF_INET;

/**
 * homa_server() - Opens a Homa socket and handles all requests arriving on
 * that socket.
 * @port:   Port number to use for the Homa socket.
 */
void homa_server(int port)
{
	int fd;
	sockaddr_in_union addr;
	sockaddr_in_union source;
	int length;
	struct homa_recvmsg_args recv_args;
	struct msghdr hdr;
	struct homa_set_buf_args arg;
	char *buf_region;
	struct iovec vecs[HOMA_MAX_BPAGES];
	int num_vecs;

	fd = socket(inet_family, SOCK_DGRAM, IPPROTO_HOMA);
	if (fd < 0) {
		printf("Couldn't open Homa socket: %s\n", strerror(errno));
		return;
	}
	memset(&addr, 0, sizeof(addr));
	addr.in4.sin_family = inet_family;
	addr.in4.sin_port = htons(port);
	if (bind(fd, &addr.sa, sizeof(addr)) != 0) {
		printf("Couldn't bind socket to Homa port %d: %s\n", port,
				strerror(errno));
		return;
	}
	if (verbose)
		printf("Successfully bound to Homa port %d\n", port);

	// Set up buffer region.
	buf_region = (char *) mmap(NULL, 1000*HOMA_BPAGE_SIZE,
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
	if (buf_region == MAP_FAILED) {
		printf("Couldn't mmap buffer region: %s\n", strerror(errno));
		return;
	}
	arg.start = buf_region;
	arg.length = 1000*HOMA_BPAGE_SIZE;
	int status = setsockopt(fd, IPPROTO_HOMA, SO_HOMA_SET_BUF, &arg,
			sizeof(arg));
	if (status < 0) {
		printf("Error in setsockopt(SO_HOMA_SET_BUF): %s\n",
				strerror(errno));
		return;
	}

	memset(&recv_args, 0, sizeof(recv_args));
	hdr.msg_name = &source;
	hdr.msg_namelen = sizeof32(source);
	hdr.msg_iov = NULL;
	hdr.msg_iovlen = 0;
	hdr.msg_control = &recv_args;
	hdr.msg_controllen = sizeof(recv_args);
	hdr.msg_flags = 0;
	while (1) {
		int seed;
		int result;

		recv_args.id = 0;
		recv_args.flags = HOMA_RECVMSG_REQUEST;
		length = recvmsg(fd, &hdr, 0);
		if (length < 0) {
			printf("recvmsg failed: %s\n", strerror(errno));
			continue;
		}
		int resp_length = ((int *) (buf_region + recv_args.bpage_offsets[0]))[1];
		if (validate) {
			seed = check_message(&recv_args, buf_region, length,
					2*sizeof32(int));
			if (verbose)
				printf("Received message from %s with %d bytes, "
					"id %lu, seed %d, response length %d\n",
					print_address(&source), length,
					recv_args.id, seed, resp_length);
		} else
			if (verbose)
				printf("Received message from %s with "
					"%d bytes, id %lu, response length %d\n",
					print_address(&source), length,
					recv_args.id, resp_length);

		/* Second word of the message indicates how large a
		 * response to send.
		 */
		num_vecs = 0;
		while (resp_length > 0) {
			vecs[num_vecs].iov_len = (resp_length > HOMA_BPAGE_SIZE)
					? HOMA_BPAGE_SIZE : resp_length;
			vecs[num_vecs].iov_base = buf_region
					+ recv_args.bpage_offsets[num_vecs];
			resp_length -= vecs[num_vecs].iov_len;
			num_vecs++;
		}
		result = homa_replyv(fd, vecs, num_vecs, &source, recv_args.id);
		if (result < 0) {
			printf("homa_reply failed: %s\n", strerror(errno));
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
		"--ipv6       Use IPv6 instead of IPv4 (default: IPv4)\n"
		"--num_ports  Number of Homa ports to open (default: 1)\n"
		"--port       (First) port number to use (default: 4000)\n"
		"--validate   Validate contents of incoming messages (default: false)\n"
		"--verbose    Log events as they happen (default: false)\n",
		name);
}

/**
 * tcp_connection() - Handles messages arriving on a given socket.
 * @fd:           File descriptor for the socket over which messages
 *                will arrive.
 * @client_addr:  Information about the client (for messages).
 */
void tcp_connection(int fd, sockaddr_in_union source)
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
	int listen_fd = socket(inet_family, SOCK_STREAM, 0);
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
	sockaddr_in_union addr;
	memset(&addr, 0, sizeof(addr));
	addr.in4.sin_family = inet_family;
	addr.in4.sin_port = htons(port);
	if (bind(listen_fd, &addr.sa, sizeof(addr)) == -1) {
		printf("Couldn't bind to port %d: %s\n", port, strerror(errno));
		exit(1);
	}
	while (1) {
		sockaddr_in_union client_addr;
		socklen_t addr_len = sizeof(client_addr);
		if (listen(listen_fd, 1000) == -1) {
			printf("Couldn't listen on socket: %s", strerror(errno));
			exit(1);
		}
		int stream = accept(listen_fd, &client_addr.sa,	&addr_len);
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
		} else if (strcmp(argv[next_arg], "--ipv6") == 0) {
			inet_family = AF_INET6;
		} else if (strcmp(argv[next_arg], "--num_ports") == 0) {
			if (next_arg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[next_arg]);
				exit(1);
			}
			next_arg++;
			num_ports = get_int(argv[next_arg],
				"Bad num_ports %s; must be positive integer\n");
		} else if (strcmp(argv[next_arg], "--port") == 0) {
			if (next_arg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[next_arg]);
				exit(1);
			}
			next_arg++;
			port = get_int(argv[next_arg],
					"Bad port %s; must be positive integer\n");
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
