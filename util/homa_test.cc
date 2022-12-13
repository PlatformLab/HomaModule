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

// This file contains a collection of tests for the Linux implementation
// of Homa; it's typically used together with homa_server.
//
// Usage:
// homaTest host:port [options] op op ...
//
// host:port gives the location of a server to invoke
// Each op specifies a particular test to perform

#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <thread>

#include "homa.h"
#include "test_utils.h"

/* Determines message size in bytes for tests. */
int length = 100;

/* How many iterations to perform for the test. */
int count = 1000;

/* Used to generate "somewhat random but predictable" contents for buffers. */
int seed = 12345;

/* Buffer space used for receiving messages. */
char *buf_region;

/* Control blocks for receiving messages. */
struct homa_recvmsg_control recv_control;
struct msghdr recv_hdr;

/* Address of message sender. */
sockaddr_in_union source_addr;

/**
 * close_fd() - Helper method for "close" test: sleeps a while, then closes
 * an fd
 * @fd:   Open file descriptor to close.
 */
void close_fd(int fd)
{
	sleep(1);
	if (close(fd) >= 0) {
		printf("Closed fd %d\n", fd);
	} else {
		printf("Close failed on fd %d: %s\n", fd, strerror(errno));
	}
}

/**
 * send_fd() - Helper method for "poll" test: sleeps a while, then sends
 * a request to a socket.
 * @fd:      File descriptor for a Homa socket; used to send the message.
 * @addr:    Where to send the message.
 * @request: Request message to send.
 */
void send_fd(int fd, const sockaddr_in_union *addr, char *request)
{
	uint64_t id;
	int status;

	sleep(1);
	status = homa_send(fd, request, length, addr, &id, 0);
	if (status < 0) {
		printf("Error in homa_send: %s\n",
			strerror(errno));
	} else {
		printf("Homa_send succeeded, id %lu\n", id);
	}
}

/**
 * shutdown_fd() - Helper method for "close" test: sleeps a while, then shuts
 * down an fd
 * @fd:   Open file descriptor to shut down.
 */
void shutdown_fd(int fd)
{
	sleep(1);
	if (shutdown(fd, 0) >= 0) {
		printf("Shutdown fd %d\n", fd);
	} else {
		printf("Shutdown failed on fd %d: %s\n", fd, strerror(errno));
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
		"--count      Number of times to repeat a test (default: 1000)\n"
		"--length     Size of messages, in bytes (default: 100)\n"
		"--seed       Used to compute message contents (default: 12345)\n",
		name);
}

/**
 * test_close() - Close a Homa socket while a thread is waiting on it.
 * Note: this will hang the thread. To abort the thread, must invoke
 * shutdown before close.
 */
void test_close()
{
	int result, fd;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
	if (fd < 0) {
		printf("Couldn't open Homa socket: %s\n",
			strerror(errno));
		exit(1);
	}
	std::thread thread(close_fd, fd);
	recv_control.id = 0;
	recv_control.flags = HOMA_RECVMSG_RESPONSE;
	result = recvmsg(fd, &recv_hdr, 0);
	if (result > 0) {
		printf("Received %d bytes\n", result);
	} else {
		printf("Error in recvmsg: %s\n",
			strerror(errno));
	}
}

/**
 * test_fill_memory() - Send requests to a server, but never read responses;
 * eventually, this will cause memory to fill up.
 * @fd:       Homa socket.
 * @dest:     Where to send the request
 * @request:  Request message.
 */
void test_fill_memory(int fd, const sockaddr_in_union *dest, char *request)
{
	uint64_t id;
	int status;
	int completed = 0;
	size_t total = 0;
#define PRINT_INTERVAL 1000
	ssize_t received;
	uint64_t start = rdtsc();

	for (int i = 1; i <= count; i++) {
		status = homa_send(fd, request, length, dest, &id, 0);
		if (status < 0) {
			printf("Error in homa_send: %s\n",
				strerror(errno));
			sleep(1);
		}
		total += length;
		if ((i % PRINT_INTERVAL) == 0) {
			printf("%lu MB sent (%d RPCs)\n", total/1000000, i);
		}
	}
	total = 0;
	for (int i = 1; i <= count; i++) {
		recv_control.id = 0;
		recv_control.flags = HOMA_RECVMSG_RESPONSE;
		received = recvmsg(fd, &recv_hdr, 0);
		if (received < 0) {
			printf("Error in recvmsg for id %lu: %s\n",
				id, strerror(errno));
		} else {
			total += received;
			completed++;
		}
		if ((i % PRINT_INTERVAL) == 0) {
			printf("%lu MB received (%d RPCs)\n", total/1000000, i);
		}
	}
	uint64_t end = rdtsc();
	double tput = total;
	tput = tput / to_seconds(end-start);
	double timePer = to_seconds(end-start) / completed;
	printf("%d/%d RPCs succeeded, average goodput %.1f MB/sec (%.1f us/RPC)\n",
		completed, count, tput*1e-06, timePer*1e06);
}

/**
 * test_invoke() - Send a request and wait for response.
 * @fd:       Homa socket.
 * @dest:     Where to send the request
 * @request:  Request message.
 */
void test_invoke(int fd, const sockaddr_in_union *dest, char *request)
{
	uint64_t id;
	int status;
	ssize_t resp_length;

	status = homa_send(fd, request, length, dest, &id, 0);
	if (status < 0) {
		printf("Error in homa_send: %s\n", strerror(errno));
		return;
	} else {
		printf("Homa_send succeeded, id %lu\n", id);
	}
	recv_control.id = 0;
	recv_control.flags = HOMA_RECVMSG_RESPONSE;
	resp_length = recvmsg(fd, &recv_hdr, 0);
	if (resp_length < 0) {
		printf("Error in recvmsg: %s\n", strerror(errno));
		return;
	}
	int seed = check_message(&recv_control, buf_region, resp_length,
			2*sizeof32(int));
	printf("Received message from %s with %lu bytes, "
			"seed %d, id %lu\n",
			print_address(&source_addr), resp_length, seed,
			recv_control.id);
}

/**
 * test_ioctl() - Measure round-trip time for an ioctl kernel call that
 * does nothing but return an error.
 * @fd:       Homa socket.
 * @count:    Number of reads to issue.
 */
void test_ioctl(int fd, int count)
{
	char buffer[100];
	int status;
	uint64_t start;
	uint64_t times[count];

	for (int i = -10; i < count; i++) {
		start = rdtsc();
		status = ioctl(fd, 123456, buffer);
		if ((status >= 0) || (errno != EINVAL)) {
			printf("Unexpected return from ioctl: result %d, "
					"errno %s\n",
					status, strerror(errno));
			return;
		}
		if (i >= 0)
			times[i] = rdtsc() - start;
	}
	print_dist(times, count);
}

/**
 * test_poll() - Receive a message using the poll interface.
 * @fd:       Homa socket.
 * @request:  Request message.
 */
void test_poll(int fd, char *request)
{
	int result;
	struct pollfd poll_info = {
		.fd =     fd,
		.events = POLLIN,
		.revents = 0
	};
	sockaddr_in_union addr;
	addr.in4.sin_family = AF_INET;
	addr.in4.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.in4.sin_port = htons(500);

	if (bind(fd, &addr.sa, sizeof(addr)) != 0) {
		printf("Couldn't bind socket to Homa port %d: %s\n",
				ntohl(addr.in4.sin_port), strerror(errno));
		return;
	}

	std::thread thread(send_fd, fd, &addr, request);
	thread.detach();

	result = poll(&poll_info, 1, -1);
	if (result > 0) {
		printf("Poll succeeded with mask 0x%x\n", poll_info.revents);
	} else {
		printf("Poll failed: %s\n", strerror(errno));
		return;
	}

	recv_control.id = 0;
	recv_control.flags = HOMA_RECVMSG_REQUEST;
	result = recvmsg(fd, &recv_hdr, 0);
	if (result < 0)
		printf("Error in recvmsg: %s\n", strerror(errno));
	else
		printf("rcvmsg returned %d bytes from port %d\n",
				result, ntohs(source_addr.in4.sin_port));
}

/**
 * test_read() - Measure round-trip time for a read kernel call that
 * does nothing but return an error.
 * @fd:       Homa socket.
 * @count:    Number of reads to issue.
 */
void test_read(int fd, int count)
{
	char buffer[100];
	int status;
	uint64_t start;
	uint64_t times[count];

	for (int i = -10; i < count; i++) {
		start = rdtsc();
		status = read(fd, buffer, sizeof(buffer));
		if ((status >= 0) || (errno != EINVAL)) {
			printf("Unexpected return from read: result %d, "
					"errno %s\n",
					status, strerror(errno));
			return;
		}
		if (i >= 0)
			times[i] = rdtsc() - start;
	}
	print_dist(times, count);
}

/**
 * test_rtt() - Measure round-trip time for an RPC.
 * @fd:       Homa socket.
 * @dest:     Where to send requests.
 * @request:  Request message.
 */
void test_rtt(int fd, const sockaddr_in_union *dest, char *request)
{
	int status;
	ssize_t resp_length;
	uint64_t start;
	uint64_t *times = new uint64_t[count];

	for (int i = -10; i < count; i++) {
		start = rdtsc();
		status = homa_send(fd, request, length, dest, NULL, 0);
		if (status < 0) {
			printf("Error in homa_send: %s\n",
					strerror(errno));
			return;
		}
		recv_control.id = 0;
		recv_control.flags = HOMA_RECVMSG_RESPONSE;
		resp_length = recvmsg(fd, &recv_hdr, 0);
		if (i >= 0)
			times[i] = rdtsc() - start;
		if (resp_length < 0) {
			printf("Error in recvmsg: %s\n", strerror(errno));
			return;
		}
		if (resp_length != length)
			printf("Expected %d bytes in response, received %ld\n",
					length, resp_length);
	}
	print_dist(times, count);
	printf("Bandwidth at median: %.1f MB/sec\n",
			2.0*((double) length)/(to_seconds(times[count/2])*1e06));
	delete times;
}

/**
 * test_send() - Send a request; don't wait for response.
 * @fd:       Homa socket.
 * @dest:     Where to send the request
 * @request:  Request message.
 */
void test_send(int fd, const sockaddr_in_union *dest, char *request)
{
	uint64_t id;
	int status;

	status = homa_send(fd, request, length, dest, &id, 0);
	if (status < 0) {
		printf("Error in homa_send: %s\n",
			strerror(errno));
	} else {
		printf("Homa_send succeeded, id %lu\n", id);
	}
}

/**
 * test_set_buf() - Invoke homa_set_buf on a Homa socket.
 * @fd:       Homa socket.
 */
void test_set_buf(int fd)
{
	int status;
	char *region = (char *) mmap(NULL, 64*HOMA_BPAGE_SIZE,
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
	struct homa_set_buf_args arg;

	if (region == MAP_FAILED) {
		printf("Couldn't mmap buffer region: %s\n", strerror(errno));
		return;
	}

	arg.start = region;
	arg.length = 64*HOMA_BPAGE_SIZE;
	status = setsockopt(fd, IPPROTO_HOMA, SO_HOMA_SET_BUF, &arg,
			sizeof(arg));
	if (status < 0)
		printf("Error in setsockopt(SO_HOMA_SET_BUF): %s\n",
				strerror(errno));
}

/**
 * test_shutdown() - Shutdown a Homa socket while a thread is waiting on it.
 * @fd:   Homa socket
 */
void test_shutdown(int fd)
{
	int result;

	std::thread thread(shutdown_fd, fd);
	thread.detach();
	recv_control.id = 0;
	recv_control.flags = HOMA_RECVMSG_RESPONSE;
	result = recvmsg(fd, &recv_hdr, 0);
	if (result > 0) {
		printf("Received %d bytes\n", result);
	} else {
		printf("Error in recvmsg: %s\n",
			strerror(errno));
	}

	/* Make sure that future reads also fail. */
	recv_control.id = 0;
	recv_control.flags = HOMA_RECVMSG_RESPONSE;
	result = recvmsg(fd, &recv_hdr, 0);
	if (result < 0) {
		printf("Second recvmsg call also failed: %s\n",
			strerror(errno));
	} else {
		printf("Second recvmsg call succeeded: %d bytes\n", result);
	}
}

/**
 * test_stream() - measure Homa's throughput in streaming mode by
 * maintaining --count outstanding RPCs at any given time, each with --length
 * bytes of data. Data flows only in one direction
 * @fd:       Homa socket
 * @dest:     Where to send requests
 */
void test_stream(int fd, const sockaddr_in_union *dest)
{
#define MAX_RPCS 100
	int *buffers[MAX_RPCS];
	ssize_t resp_length;
	uint64_t id, end_cycles;
	uint64_t start_cycles = 0;
	uint64_t end_time;
	int status, i;
	int64_t bytes_sent = 0;
	int64_t start_bytes = 0;
	double rate;

	end_time = rdtsc() + (uint64_t) (5*get_cycles_per_sec());

	if (count > MAX_RPCS) {
		printf("Count too large; reducing from %d to %d\n", count,
				MAX_RPCS);
		count = MAX_RPCS;
	}
	for (i = 0; i < count; i++) {
		buffers[i] = (int *) malloc(length);
		buffers[i][0] = length;
		buffers[i][1] = 12;
		seed_buffer(buffers[i]+2, length - 2*sizeof32(int), 1000*i);
	}
	for (i = 0; i < count; i++) {
		status = homa_send(fd, buffers[i], length, dest, &id, 0);
		if (status < 0) {
			printf("Error in homa_send: %s\n", strerror(errno));
			return;
		}
	}

	/* Each iteration through the following the loop waits for a
	 * response to an outstanding request, then initiates a new
	 * request.
	 */
	while (1){
		int *response;

		recv_control.id = 0;
		recv_control.flags = HOMA_RECVMSG_RESPONSE;
		resp_length = recvmsg(fd, &recv_hdr, 0);
		if (resp_length < 0) {
			printf("Error in recvmsg: %s\n",
					strerror(errno));
			return;
		}
		if (resp_length != 12)
			printf("Expected 12 bytes in response, received %ld\n",
					resp_length);
		response = (int *) (buf_region + recv_control.bpage_offsets[0]);
		status = homa_send(fd, buffers[(response[2]/1000) %count],
				length, dest, &id, 0);
		if (status < 0) {
			printf("Error in homa_send: %s\n", strerror(errno));
			return;
		}
		bytes_sent += length;
		if (rdtsc() > end_time)
			break;

		/* Don't start timing until we've sent a few bytes to warm
		 * everything up.
		 */
		if ((start_bytes == 0) && (bytes_sent > 1000000)) {
			start_bytes = bytes_sent;
			start_cycles = rdtsc();
		}
	}
	end_cycles = rdtsc();
	rate = ((double) bytes_sent - start_bytes)/ to_seconds(
			end_cycles - start_cycles);
	printf("Homa throughput using %d concurrent %d byte messages: "
			"%.2f GB/sec\n", count, length, rate*1e-09);

	for (i = 0; i < count; i++)
		free(buffers[i]);
}

/**
 * tcp_ping() - Send a request on a TCP socket and wait for the
 * corresponding response.
 * @fd:       File descriptor corresponding to a TCP connection.
 * @request:  Buffer containing the request message.
 * @length:   Length of the request message.
 */
void tcp_ping(int fd, void *request, int length)
{
	char response[1000000];
	int response_length;
	int *int_response = reinterpret_cast<int*>(response);
	if (write(fd, request, length) != length) {
		printf("Socket write failed: %s\n", strerror(errno));
		exit(1);
	}
	response_length = 0;
	while (true) {
		int num_bytes = read(fd, response + response_length,
				sizeof(response) - response_length);
		if (num_bytes <= 0) {
			if (num_bytes == 0)
				printf("Server closed socket\n");
			else
				printf("Socket read failed: %s\n",
						strerror(errno));
			exit(1);
		}
		response_length += num_bytes;
		if (response_length < 2*sizeof32(int))
			continue;
		if (response_length < int_response[1])
			continue;
		if (response_length != int_response[1])
			printf("Expected %d bytes in response, got %d\n",
					int_response[1], response_length);
		if (response_length >= sizeof32(response)) {
			printf("Overflowed receive buffer: response_length %d,"
					"buffer[0] %d\n", response_length,
					int_response[0]);
		}
		break;
	}
}

/**
 * test_tcp() - Measure round-trip time for an RPC sent via a TCP socket.
 * @server_name:  Name of the server machine.
 * @port:         Server port to connect to.
 */
void test_tcp(char *server_name, int port)
{
	struct addrinfo hints;
	struct addrinfo *matching_addresses;
	struct sockaddr *dest;
	int status, i;
	int buffer[250000];

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
	buffer[0] = length;
	buffer[1] = length;
	seed_buffer(&buffer[2], sizeof32(buffer) - 2*sizeof32(int), seed);
	for (i = 0; i < 10; i++)
		tcp_ping(stream, buffer, length);

	uint64_t times[count+1];
	for (i = 0; i < count; i++) {
		times[i] = rdtsc();
		tcp_ping(stream, buffer, length);
	}
	times[count] = rdtsc();

	for (i = 0; i < count; i++) {
		times[i] = times[i+1] - times[i];
	}
	print_dist(times, count);
	printf("Bandwidth at median: %.1f MB/sec\n",
			2.0*((double) length)/(to_seconds(times[count/2])*1e06));
	return;
}

/**
 * test_tcpstream() - Measure throughput of a TCP socket using --length as
 * the size of the buffer for each write system call.
 * @server_name:  Name of the server machine.
 * @port:         Server port to connect to.
 */
void test_tcpstream(char *server_name, int port)
{
	struct addrinfo hints;
	struct addrinfo *matching_addresses;
	struct sockaddr *dest;
	int status;
	int buffer[1000000];
	int64_t bytes_sent = 0;
	int64_t start_bytes = 0;
	uint64_t start_cycles = 0;
	double elapsed, rate;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	status = getaddrinfo(server_name, "80", &hints, &matching_addresses);
	if (status != 0) {
		printf("Couldn't look up address for %s: %s\n",
				server_name, gai_strerror(status));
		return;
	}
	dest = matching_addresses->ai_addr;
	((struct sockaddr_in *) dest)->sin_port = htons(port);

	int fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		printf("Couldn't open client socket: %s\n", strerror(errno));
		return;
	}
	if (connect(fd, dest, sizeof(struct sockaddr_in)) == -1) {
		printf("Couldn't connect to %s:%d: %s\n", server_name, port,
				strerror(errno));
		return;
	}
	int flag = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	buffer[0] = -1;

	while (1) {
		if (write(fd, buffer, length) != length) {
			printf("Socket write failed: %s\n", strerror(errno));
			return;
		}
		bytes_sent += length;
		if (bytes_sent > 1010000000)
			break;

		/* Don't start timing until we've sent a few bytes to warm
		 * everything up.
		 */
		if ((start_bytes == 0) && (bytes_sent > 10000000)) {
			start_bytes = bytes_sent;
			start_cycles = rdtsc();
		}

	}
	elapsed = to_seconds(rdtsc() - start_cycles);
	rate = ((double) bytes_sent - start_bytes) / elapsed;
	printf("TCP throughput using %d byte buffers: %.2f GB/sec\n",
			length, rate*1e-09);
}
/**
 * test_tmp() - Placeholder for temporary tests used for debugging, etc.
 * @fd:     Fd for Homa socket.
 * @count:  --count commdand-line argument.
 */
void test_tmp(int fd, int count)
{
	struct msghdr h;
	char addr[20];
	struct homa_recvmsg_control control;
	struct iovec vecs[2];
	char buffer1[10], buffer2[20];

	vecs[0].iov_base = buffer1;
	vecs[0].iov_len = sizeof(buffer1);
	vecs[1].iov_base = buffer2;
	vecs[1].iov_len = sizeof(buffer2);

	strcpy(addr, "Input sockaddr");

	h.msg_name = &addr;
	h.msg_namelen = sizeof(addr);
	h.msg_iov = vecs;
	h.msg_iovlen = 2;
	h.msg_control = &control;
	h.msg_controllen = sizeof(control);

	memset(&control, 0, sizeof(control));
	control.flags = HOMA_RECVMSG_REQUEST | HOMA_RECVMSG_REQUEST
			| HOMA_RECVMSG_NONBLOCKING;

	int result = recvmsg(fd, &h, 0);
	printf("recvmsg returned %d, addr %p, namelen %d, control %p, "
			"addr_out %s, errno %d\n",
			result, &addr, sizeof32(addr), &control, addr, errno);
	return;
}

/**
 * test_udpclose() - Close a UDP socket while a thread is waiting on it.
 */
void test_udpclose()
{
	/* Test what happens if a UDP socket is closed while a
	 * thread is waiting on it. */
	sockaddr_in_union address;
	char buffer[1000];

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		printf("Couldn't open UDP socket: %s\n",
			strerror(errno));
		exit(1);
	}
	address.in4.sin_family = AF_INET;
	address.in4.sin_addr.s_addr = htonl(INADDR_ANY);
	address.in4.sin_port = 0;
	int result = bind(fd,
		&address.sa,
		sizeof(address));
	if (result < 0) {
		printf("Couldn't bind UDP socket: %s\n",
			strerror(errno));
		exit(1);
	}
	std::thread thread(close_fd, fd);
	thread.detach();
	result = read(fd, buffer, sizeof(buffer));
	if (result >= 0) {
		printf("UDP read returned %d bytes\n", result);
	} else {
		printf("UDP read returned error: %s\n",
			strerror(errno));
	}
}

int main(int argc, char** argv)
{
	int fd, status, port, nextArg;
	struct addrinfo *matching_addresses;
	sockaddr_in_union dest;
	struct addrinfo hints;
	char *host, *port_name;
	char buffer[HOMA_MAX_MESSAGE_LENGTH];

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
		} else if (strcmp(argv[nextArg], "--count") == 0) {
			if (nextArg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[nextArg]);
				exit(1);
			}
			nextArg++;
			count = get_int(argv[nextArg],
					"Bad count %s; must be positive integer\n");
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
			if (length > HOMA_MAX_MESSAGE_LENGTH) {
				length = HOMA_MAX_MESSAGE_LENGTH;
				printf("Reducing message length to %d\n", length);
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
			printf("Unknown option %s; type '%s --help' for help\n",
				argv[nextArg], argv[0]);
			exit(1);
		}
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	status = getaddrinfo(host, "80", &hints, &matching_addresses);
	if (status != 0) {
		printf("Couldn't look up address for %s: %s\n",
				host, gai_strerror(status));
		exit(1);
	}
	dest.in4 = *(struct sockaddr_in*)matching_addresses->ai_addr;
	dest.in4.sin_port = htons(port);
	int *ibuf = reinterpret_cast<int *>(buffer);
	ibuf[0] = ibuf[1] = length;
	seed_buffer(&ibuf[2], sizeof32(buffer) - 2*sizeof32(int), seed);

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
	if (fd < 0) {
		printf("Couldn't open Homa socket: %s\n", strerror(errno));
	}

	// Set up buffer region.
	buf_region = (char *) mmap(NULL, 1000*HOMA_BPAGE_SIZE,
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
	if (buf_region == MAP_FAILED) {
		printf("Couldn't mmap buffer region: %s\n", strerror(errno));
		exit(1);
	}
	struct homa_set_buf_args arg;
	arg.start = buf_region;
	arg.length = 1000*HOMA_BPAGE_SIZE;
	status = setsockopt(fd, IPPROTO_HOMA, SO_HOMA_SET_BUF, &arg,
			sizeof(arg));
	if (status < 0) {
		printf("Error in setsockopt(SO_HOMA_SET_BUF): %s\n",
				strerror(errno));
		exit(1);
	}
	recv_control.id = 0;
	recv_control.flags = 0;
	recv_control.num_bpages = 0;
	recv_hdr.msg_name = &source_addr;
	recv_hdr.msg_namelen = sizeof32(source_addr);
	recv_hdr.msg_iov = NULL;
	recv_hdr.msg_iovlen = 0;
	recv_hdr.msg_control = &recv_control;
	recv_hdr.msg_controllen = sizeof(recv_control);
	recv_hdr.msg_flags = 0;

	for ( ; nextArg < argc; nextArg++) {
		if (strcmp(argv[nextArg], "close") == 0) {
			test_close();
		} else if (strcmp(argv[nextArg], "fill_memory") == 0) {
			test_fill_memory(fd, &dest, buffer);
		} else if (strcmp(argv[nextArg], "invoke") == 0) {
			test_invoke(fd, &dest, buffer);
		} else if (strcmp(argv[nextArg], "ioctl") == 0) {
			test_ioctl(fd, count);
		} else if (strcmp(argv[nextArg], "poll") == 0) {
			test_poll(fd, buffer);
		} else if (strcmp(argv[nextArg], "send") == 0) {
			test_send(fd, &dest, buffer);
		} else if (strcmp(argv[nextArg], "read") == 0) {
			test_read(fd, count);
		} else if (strcmp(argv[nextArg], "rtt") == 0) {
			test_rtt(fd, &dest, buffer);
		} else if (strcmp(argv[nextArg], "shutdown") == 0) {
			test_shutdown(fd);
		} else if (strcmp(argv[nextArg], "set_buf") == 0) {
			test_set_buf(fd);
		} else if (strcmp(argv[nextArg], "stream") == 0) {
			test_stream(fd, &dest);
		} else if (strcmp(argv[nextArg], "tcp") == 0) {
			test_tcp(host, port);
		} else if (strcmp(argv[nextArg], "tcpstream") == 0) {
			test_tcpstream(host, port);
		} else if (strcmp(argv[nextArg], "tmp") == 0) {
			test_tmp(fd, count);
		} else if (strcmp(argv[nextArg], "udpclose") == 0) {
			test_udpclose();
		} else {
			printf("Unknown operation '%s'\n", argv[nextArg]);
			exit(1);
		}
	}
	close(fd);
	exit(0);
}

