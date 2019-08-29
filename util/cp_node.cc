// This file contains a program that runs on one node, as part of
// the cluster_perf test.

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
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <thread>
#include <vector>

#include "homa.h"
#include "test_utils.h"

/* Command-line parameter values: */

int client_threads = 1;
const char *dist_file = "foo.bar";
bool is_server = false;
int id = -1;
int max_requests = 50;
double net_util = 0.8;
const char *protocol = "homa";
int server_threads = 1;
int server_nodes = 1000;

/**
 * struct tcp_connection - Manages state information for one incoming TCP
 * connection.
 */
struct tcp_connection {
	/** @fd: file descriptor used to read/write connection. */
	int fd;
	
	/** @client_addr: address of connecting client. */
	struct sockaddr_in client_addr;
	
	/**
	 * @bytes_received: nonzero means we have read part of an incoming
	 * request; the value indicates how many bytes have been received
	 * so far.
	 */
	int bytes_received;
	
	/**
	 * @size: total number of bytes in current partially-received
	 * request. Meaningless if @bytes_received is 0. If @bytes_received
	 * is < sizeof(int), then only the first @bytes_received bytes of
	 * this integer value have been filled in.
	 */
	int size;
};

/**
 * @tcp_connections: holds information about all open TCP connections.
 * Entries are dynamically allocated.
 */
std::vector<struct tcp_connection *> tcp_connections;

/**
 * print_help() - Print out usage information for this program.
 * @name:   Name of the program (argv[0])
 */
void print_help(const char *name)
{
	printf("Usage: %s [options]\n\n"
		"The following options are supported:\n\n"
		"--client_threads      Number of request invocation threads to run on this\n"
		"                      node (default: %d)\n"
		"--dist_file           Name of file containing request size distribution\n"
		"                      (default: %s)\n"
		"--help                Print this message\n"
		"--is_server           Instantiate server threads on this node\n"
		"--max_requests        Maximum number of outstanding requests from each client\n"
		"                      thread (default: %d)\n"
		"--net_util            Target network utilization, including headers and packet\n"
		"                      gaps (default: %.2f)\n"
		"--protocol            Transport protocol to use for requests: homa or tcp\n"
		"                      (default: %s)\n"
		"--server_nodes        Number of nodes running server threads (default: %d)\n"
		"--server_threads      Number of server threads/ports on each server node\n"
		"                      (default: %d)\n",
		name, client_threads, dist_file, max_requests, net_util,
		protocol, server_nodes, server_threads);
}

/**
 * float_arg() - Parse a floating--point command-line argument from a string;
 * print an error message and exit if there is a problem.
 * @value:  String value of argument (from argv array).
 * @name:   Name of argument (for use in error messages).
 * Return:  The floating-poing value corresponding to @value.
 */
double float_arg(const char *value, const char *name)
{
	double result;
	char *end;
	if ((value == NULL) || (value[0] == 0)) {
		printf("No value provided for %s\n", name);
		exit(1);
	}
	result = strtod(value, &end);
	if (*end != 0) {
		printf("Bad value '%s' for %s; must be integer\n",
			value, name);
		exit(1);
	}
	return result;
}

/**
 * int_arg() - Parse an integer command-line argument from a string; print
 * an error message and exit if there is a problem.
 * @value:  String value of argument (from argv array).
 * @name:   Name of argument (for use in error messages).
 * Return:  The integer value corresponding to @value.
 */
int int_arg(const char *value, const char *name)
{
	int result;
	char *end;
	if ((value == NULL) || (value[0] == 0)) {
		printf("No value provided for %s\n", name);
		exit(1);
	}
	result = strtol(value, &end, 0);
	if (*end != 0) {
		printf("Bad value '%s' for %s; must be integer\n",
			value, name);
		exit(1);
	}
	return result;
}

/**
 * homa_server() - Opens a Homa socket and handles all requests arriving on
 * that socket. Normally invoked as top-level method in a thread.
 * @port:   Port number to use for the Homa socket.
 */
void homa_server(int port)
{
	int fd;
	struct sockaddr_in addr_in;
	int message[1000000];
	struct sockaddr_in source;
	int length;
	
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
		uint64_t id = 0;
		int result;
		
		length = homa_recv(fd, message, sizeof(message),
			HOMA_RECV_REQUEST, &id, (struct sockaddr *) &source,
			sizeof(source));
		if (length < 0) {
			printf("homa_recv failed: %s\n", strerror(errno));
			continue;
		}

		/* Second word of the message indicates how large a
		 * response to send.
		 */
		result = homa_reply(fd, message, length,
			(struct sockaddr *) &source, sizeof(source), id);
		if (result < 0) {
			printf("Homa_reply failed: %s\n", strerror(errno));
		}
	}
}

/**
 * tcp_accept() - Accepts a new incoming TCP connection and
 * initialize state for that connection.
 * @listen_fd:  File descriptor for the listen socket.
 * @epoll_fd:   Used to arrange for epolling on the new connection.
 */
void tcp_accept(int listen_fd, int epoll_fd)
{
	struct tcp_connection *connection = new tcp_connection();
	socklen_t addr_len = sizeof(connection->client_addr);
	connection->fd = accept(listen_fd,
			reinterpret_cast<sockaddr *>(&connection->client_addr),
			&addr_len);
	if (connection->fd < 0) {
		printf("Couldn't accept incoming TCP connection: %s",
			strerror(errno));
		exit(1);
	}
	connection->bytes_received = 0;
	tcp_connections.reserve(connection->fd + 1);
	tcp_connections[connection->fd] = connection;
	printf("Accepted TCP connection from %s on fd %d\n",
			 print_address(&connection->client_addr),
			 connection->fd);
	
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = connection->fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, connection->fd, &ev) < 0) {
		printf("Couldn't add new TCP connection to epoll: %s\n",
				strerror(errno));
		exit(1);
	}
}

/**
 * tcp_read() - Reads available data from a TCP connection; once an entire
 * request has been read, sends an appropriate response.
 * @fd:        File descriptor for connection; tcp_connections must hold
 *             state information for this descriptor.
 */
void tcp_read(int fd)
{
	char buffer[100000];
	struct tcp_connection *connection = tcp_connections[fd];
	char *next = buffer;
	
	int count = read(fd, buffer, sizeof(buffer));
	
	if ((count == 0) || ((count < 0) && (errno == ECONNRESET))) {
		/* Connection was closed by the client. */
		if (close(fd) < 0) {
			printf("Error closing TCP connection: %s\n",
					strerror(errno));
			exit(1);
		}
		printf("TCP connection from %s closed (fd %d)\n",
				print_address(&connection->client_addr), fd);
		delete tcp_connections[fd];
		tcp_connections[fd] = NULL;
		return;
	}
	
	if (count < 0) {
		printf("Error reading from TCP connection: %s\n",
				strerror(errno));
		exit(1);
	}
	
	/*
	 * Process incoming bytes (could contains parts of multiple requests).
	 * The first 4 bytes of each request give its length.
	 */
	while (count > 0) {
		/* First, fill in the length word with incoming data (there's
		 * no guarantee that a single read will return all of the bytes
		 * of the size word).
		 */
		int length_bytes = sizeof32(int) - connection->bytes_received;
		if (length_bytes > 0) {
			if (count < length_bytes)
				length_bytes = count;
			char *size_p = reinterpret_cast<char *>(&connection->size);
			memcpy(size_p + connection->bytes_received, next,
					length_bytes);
			connection->bytes_received += length_bytes;
			next += length_bytes;
			count -= length_bytes;
			continue;
		}
		
		/* At this point we know the request length, so read until
		 * we've got a full request.
		 */
		if (count < (connection->size - connection->bytes_received)) {
			connection->bytes_received += count;
			break;
		}
		
		/* We now have a full request; send the response. */
		count -= (connection->size - connection->bytes_received);
		next += (connection->size - connection->bytes_received);
		int *int_buffer = reinterpret_cast<int *>(buffer);
		int_buffer[0] = int_buffer[1] = connection->size;
		for (int bytes_left = connection->size; bytes_left > 0; ) {
			int this_size = bytes_left;
			if (this_size > sizeof32(buffer))
				this_size = sizeof32(buffer);
			if (write(fd, buffer, this_size) < 0) {
				printf("Error writing TCP connection: %s\n",
						strerror(errno));
				exit(1);
			}
			bytes_left -= this_size;
		}
		connection->bytes_received = 0;
	}
}

/**
 * tcp_server() - Opens a TCP socket, accepts connections on that socket
 * and processes messages on those connections.
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
	if (listen(listen_fd, 1000) == -1) {
		printf("Couldn't listen on socket: %s", strerror(errno));
		exit(1);
	}
	
	int epoll_fd = epoll_create(10);
	if (epoll_fd < 0) {
		printf("Couldn't create epoll instance: %s\n", strerror(errno));
		exit(1);
	}
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = listen_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
		printf("Couldn't add listen socket to epoll: %s\n",
				strerror(errno));
		exit(1);
	}
	
	/* Each iteration through this loop processes a batch of epoll events. */
	while (1) {
#define MAX_EVENTS 10
		struct epoll_event events[MAX_EVENTS];
		int num_events;
		
		num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
		if (num_events < 0) {
			printf("epoll_wait failed: %s\n", strerror(errno));
			exit(1);
		}
		for (int i = 0; i < num_events; i++) {
			int fd = events[i].data.fd;
			if (fd == listen_fd)
				tcp_accept(fd, epoll_fd);
			else
				tcp_read(fd);
		}
	}
}

int main(int argc, char** argv)
{
	int next_arg, i;
	
	for (next_arg = 1; (next_arg < argc); next_arg += 1) {
		if (strcmp(argv[next_arg], "--help") == 0) {
			print_help(argv[0]);
			exit(0);
		} else if (strcmp(argv[next_arg], "--client_threads") == 0) {
			client_threads = int_arg(argv[next_arg+1],
					argv[next_arg]);
			next_arg++;
		} else if (strcmp(argv[next_arg], "--dist_file") == 0) {
			next_arg++;
			dist_file = argv[next_arg];
			if (dist_file == NULL) {
				printf("No value provided for --dist_file\n");
				exit(1);
			}
		} else if (strcmp(argv[next_arg], "--is_server") == 0) {
			is_server = true;
		} else if (strcmp(argv[next_arg], "--max_requests") == 0) {
			max_requests = int_arg(argv[next_arg+1],
					argv[next_arg]);
			next_arg++;
		} else if (strcmp(argv[next_arg], "--net_util") == 0) {
			net_util = float_arg(argv[next_arg+1],
					argv[next_arg]);
			next_arg++;
		} else if (strcmp(argv[next_arg], "--protocol") == 0) {
			next_arg++;
			protocol = argv[next_arg];
			if (protocol == NULL) {
				printf("No value provided for --protocol\n");
				exit(1);
			}
		} else if (strcmp(argv[next_arg], "--server_nodes") == 0) {
			server_nodes = int_arg(argv[next_arg+1],
					argv[next_arg]);
			next_arg++;
		} else if (strcmp(argv[next_arg], "--server_threads") == 0) {
			server_threads = int_arg(argv[next_arg+1],
					argv[next_arg]);
			next_arg++;
		} else {
			printf("Unknown option %s; type '%s --help' for help\n",
				argv[next_arg], argv[0]);
			exit(1);
		}
	}
	if ((strcmp(protocol, "homa") != 0) && (strcmp(protocol, "tcp") != 0)) {
		printf("Unknown protocol '%s': must be homa or tcp\n", protocol);
		exit(1);
	}
	
	/* Spawn server threads. */
	if (is_server) {
		if (strcmp(protocol, "homa") == 0) {
			for (i = 0; i < server_threads; i++) {
				std::thread thread(homa_server, 4000+i);
				thread.detach();
			}
		} else {
			for (i = 0; i < server_threads; i++) {
				std::thread thread(tcp_server, 4000+i);
				thread.detach();
			}
		}
	}
	sleep(1000);
	exit(0);
}

