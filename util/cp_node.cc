/* Copyright (c) 2019-2020 Stanford University
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

/* This file contains a program that runs on one node, as part of
 * the cluster_perf test.
 */

#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>

#include <algorithm>
#include <atomic>
#include <functional>
#include <iostream>
#include <mutex>
#include <optional>
#include <random>
#include <thread>
#include <vector>

#include "dist.h"
#include "homa.h"
#include "test_utils.h"

using std::string;

/* Command-line parameter values (note: changes to default values must
 * also be reflected in client and server constructors): */
uint32_t client_max = 1;
int client_ports = 0;
int first_port = 4000;
int first_server = 1;
bool is_server = false;
int id = -1;
uint32_t server_max = 1;
double net_bw = 0.0;
bool tcp_trunc = true;
int port_receivers = 1;
int port_threads = 1;
const char *protocol;
int server_nodes = 1;
int server_ports = 1;
bool verbose = false;
const char *workload = "100";

/** @rand_gen: random number generator. */
std::mt19937 rand_gen(
		std::chrono::system_clock::now().time_since_epoch().count());

/**
 * @server_addrs: Internet addresses for each of the server threads available
 * to receive a Homa RPC.
 */
std::vector<struct sockaddr_in> server_addrs;

/**
 * @last_stats_time: time (in rdtsc cycles) when we last printed
 * staticsics. Zero means that none of the statistics below are valid.
 */
uint64_t last_stats_time;

/**
 * @last_client_rpcs: total number of client RPCS completed by this
 * application as of the last time we printed statistics.
 */
uint64_t last_client_rpcs;

/**
 * @last_client_data: total amount of data in client RPCS completed by this
 * application as of the last time we printed statistics.
 */
uint64_t last_client_data;

/**
 * @last_total_elapsed: total amount of elapsed time for all client RPCs
 * issued by this application (in units of rdtsc cycles), as of the last
 * time we printed statistics.
 */
uint64_t last_total_rtt;

/**
 * @last_lag: total lag across all clients (measured in rdtsc cycles)
 * as of the last time we printed statistics.
 */
uint64_t last_lag;

/**
 * @last_server_rpcs: total number of server RPCS handled by this
 * application as of the last time we printed statistics.
 */
uint64_t last_server_rpcs;

/**
 * @last_server_data: total amount of data in server RPCS handled by this
 * application as of the last time we printed statistics.
 */
uint64_t last_server_data;

/**
 * @last_per_server_rpcs: server->requests for each individual server,
 * as of the last time we printed statistics.
 */
std::vector<uint64_t> last_per_server_rpcs;

/** @log_file: where log messages get printed. */
FILE* log_file = stdout;

enum Msg_Type {NORMAL, VERBOSE};

/** @log_level: only print log messages if they have a level <= this value. */
Msg_Type log_level = NORMAL;

extern void log(Msg_Type type, const char *format, ...)
	__attribute__((format(printf, 2, 3)));

/**
 * @cmd_lock: held whenever a command is executing.  Used to ensure that
 * operations such as statistics printing don't run when commands such
 * as "stop" are changing the client or server structure.
 */
std::mutex cmd_lock;

/**
 * print_help() - Print out usage information for this program.
 * @name:   Name of the program (argv[0])
 */
void print_help(const char *name)
{
	printf("Usage: cp_node [command]\n\n"
		"If there are command-line options, they constitute a single command\n"
		"to execute, after which cp_node will print statistics every second.\n\n"
		"If there are no command-line options, then cp_node enters a loop reading\n"
		"lines from standard input and executing them as commands. The following\n"
		"commands are supported, each followed by a list of options supported\n"
		"by that command:\n\n"
		"client [options]      Start one or more client threads\n"
		"    --first-port      Lowest port number to use for each server (default: %d)\n"
		"    --first-server    Id of first server node (default: %d, meaning node-%d)\n"
		"    --id              Id of this node; a value of I >= 0 means requests will\n"
		"                      not be sent to node-I (default: -1)\n"
		"    --net-bw          Target network utilization, including only message data,\n"
		"                      GB/s; 0 means send continuously (default: %.1f)\n"
		"    --no-trunc        For TCP, allow messages longer than Homa's limit"
		"    --protocol        Transport protocol to use: homa or tcp (default: %s)\n"
		"    --server-max      Maximum number of outstanding requests from a single\n"
		"                      client port to a single server port (default: %d)\n"
		"    --server-nodes    Number of nodes running server threads (default: %d)\n"
		"    --server-ports    Number of server ports on each server node\n"
		"                      (default: %d)\n"
		"    --port-max        Maximum number of outstanding requests from a single\n"
		"                      client port (across all servers) (default: %d)\n"
		"    --ports           Number of ports on which to send requests (one"
		"                      sending thread per port (default: %d)\n"
		"    --port_receivers  Number of threads to listen for responses on each\n"
		"                      port (default: %d)\n"
		"    --workload        Name of distribution for request lengths (e.g., 'w1')\n"
		"                      or integer for fixed length (default: %s)\n\n"
		"dump_times file       Log RTT times (and lengths) to file\n\n"
		"exit                  Exit the application\n\n"
		"log [options] [msg]   Configure logging as determined by the options. If\n"
		"                      there is an \"option\" that doesn't start with \"--\",\n"
		"                      then it and all of the remaining words are printed to\n"
		"                      the log as a message.\n"
		"    --file            Name of log file to use for future messages (\"-\"\n"
		"                      means use standard output)\n"
		"    --level           Log level: either normal or verbose\n\n"
		"server [options]      Start serving requests on one or more ports\n"
		"    --first-port      Lowest port number to use (default: %d)\n"
		"    --protocol        Transport protocol to use: homa or tcp (default: %s)\n"
		"    --port-threads    Number of server threads to service each port\n"
		"                      (Homa only, default: %d)\n"
		"    --ports           Number of ports to listen on (default: %d)\n\n"
		"stop [options]        Stop existing client and/or server threads; each\n"
		"                      option must be either 'clients' or 'servers'\n",
		first_port, first_server, first_server, net_bw, protocol,
		server_max, server_nodes, server_ports, client_max,
		client_ports, port_receivers, workload,
		first_port, protocol, port_threads, server_ports);
}

/**
 * log() - Print a message to the current log file
 * @type:   Kind of message (NORMAL or VERBOSE); used to control degree of
 *          log verbosity
 * @format: printf-style format string, followed by printf-style arguments.
 */
void log(Msg_Type type, const char *format, ...)
{
	char buffer[1000];
	struct timespec now;
	va_list args;

	if (type > log_level)
		return;
	va_start(args, format);
	clock_gettime(CLOCK_REALTIME, &now);

	vsnprintf(buffer, sizeof(buffer), format, args);
	fprintf(log_file, "%010lu.%09lu %s", now.tv_sec, now.tv_nsec, buffer);
}

/**
 * parse_float() - Parse an floating-point value from an argument word.
 * @words:  Words of a command being parsed.
 * @i:      Index within words of a word expected to contain a floating-
 *          point value (may be outside the range of words, in which case an
 *          error message is printed).
 * @value:  The value corresponding to @words[i] is stored here,
 *          if the function completes successfully.
 * @option: Name of option being parsed (for use in error messages).
 * Return:  Nonzero means success, zero means an error occurred (and a
 *          message was printed).
 */
int parse_float(std::vector<string> &words, unsigned i, double *value,
		const char *option)
{
	double num;
	char *end;
	
	if (i >= words.size()) {
		printf("No value provided for %s\n", option);
		return 0;
	}
	num = strtod(words[i].c_str(), &end);
	if (*end != 0) {
		printf("Bad value '%s' for %s; must be floating-point "
				"number\n", words[i].c_str(), option);
		return 0;
	}
	*value = num;
	return 1;
}

/**
 * parse_int() - Parse an integer value from an argument word.
 * @words:  Words of a command being parsed.
 * @i:      Index within words of a word expected to contain an integer
 *          value (may be outside the range of words, in which case an
 *          error message is printed).
 * @value:  The integer value corresponding to @words[i] is stored here,
 *          if the function completes successfully.
 * @option: Name of option being parsed (for use in error messages).
 * Return:  Nonzero means success, zero means an error occurred (and a
 *          message was printed).
 */
int parse_int(std::vector<string> &words, unsigned i, int *value,
		const char *option)
{
	int num;
	char *end;
	
	if (i >= words.size()) {
		printf("No value provided for %s\n", option);
		return 0;
	}
	num = strtol(words[i].c_str(), &end, 0);
	if (*end != 0) {
		printf("Bad value '%s' for %s; must be integer\n",
				words[i].c_str(), option);
		return 0;
	}
	*value = num;
	return 1;
}

/**
 * struct message_header - The first few bytes of each message (request or
 * response) have the structure defined here. The client initially specifies
 * this information in the request, and the server returns the information
 * in the response.
 */
struct message_header {
	/**
	 * @length: total number of bytes in the message, including this
	 * header.
	 */
	int length;
	
	/**
	 * @start_time: the time when the client initiated the request.
	 * This is the low-order 32 bits of a rdtsc value.
	 */
	uint32_t start_time;
	
	/**
	 * @server_id: the index in @server_addrs (on the client) of
	 * the server for this request.
	 */
	int server_id;
};

/**
 * send_message() - Writes a message to a file descriptor in the
 * standard form (size, timestamp, then arbitrary ignored padding).
 * @fd:         File descriptor on which to write the message.
 * @header:     Transmitted as the first bytes of the message.
 *              If the size isn't at least as large as the header.
 *              we'll round it up.
 * 
 * Return:   Zero for success; anything else means there was an error
 *           (check errno for details).
 */
int send_message(int fd, message_header *header)
{
	char buffer[100000];
	if (header->length < sizeof32(*header))
		header->length = sizeof32(*header);
	*(reinterpret_cast<message_header *>(buffer)) = *header;
	for (int bytes_left = header->length; bytes_left > 0; ) {
		int this_size = bytes_left;
		if (this_size > sizeof32(buffer))
			this_size = sizeof32(buffer);
		if (send(fd, buffer, this_size, MSG_NOSIGNAL) < 0)
			return -1;
		bytes_left -= this_size;
	}
	return 0;
}


/**
 * init_server_addrs() - Set up the server_addrs table (addresses of the
 * server/port combinations that clients will communicate with), based on
 * current configuration parameters. Any previous contents of the table
 * are discarded
 */
void init_server_addrs(void)
{
	server_addrs.clear();
	for (int node = first_server; node < first_server + server_nodes;
			node++) {
		char host[100];
		struct addrinfo hints;
		struct addrinfo *matching_addresses;
		struct sockaddr_in *dest;

		if (node == id)
			continue;
		snprintf(host, sizeof(host), "node-%d", node);
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;
		int status = getaddrinfo(host, NULL, &hints,
				&matching_addresses);
		if (status != 0) {
			log(NORMAL, "FATAL: couldn't look up address "
					"for %s: %s\n",
					host, gai_strerror(status));
			exit(1);
		}
		dest = reinterpret_cast<struct sockaddr_in *>
				(matching_addresses->ai_addr);
		for (int thread = 0; thread < server_ports; thread++) {
			dest->sin_port = htons(first_port + thread);
			server_addrs.push_back(*dest);
		}
	}
}

/**
 * struct tcp_message - Handles the reading of TCP messages; a message
 * may arrive in several chunks spaced out in time; this class keeps track
 * of the current state.
 */
class tcp_message {
    public:
	tcp_message(int fd, int port, struct sockaddr_in peer);
	int read(std::function<void (message_header *header)> func);
	
	/** @fd: File descriptor to use for reading data. */
	int fd;
	
	/**
	 * @port: Local port used to read this message (for error
	 * messages).
	 */
	int port;
	
	/**
	 * @per: Address of the machine we're reading from; used for
	 * messages.
	 */
	struct sockaddr_in peer;
	
	/**
	 * @bytes_received: nonzero means we have read part of an incoming
	 * request; the value indicates how many bytes have been received
	 * so far.
	 */
	int bytes_received;
	
	/**
	 * @header: will eventually hold the first bytes of the message.
	 * If @bytes_received is less than the size of this value, then
	 * it has not yet been fully read.
	 */
	message_header header;
	
	/**
	 * @error_message: holds human-readable error information after
	 * an error.
	 */
	char error_message[200];
} __attribute__((packed));

/**
 * tcp_message:: tcp_message() - Constructor for tcp_message objects.
 * @fd:        File descriptor from which to read data.
 * @peer:      Address of the machine we're reading from; used for messages.
 */
tcp_message::tcp_message(int fd, int port, struct sockaddr_in peer)
	: fd(fd)
        , port(port)
	, peer(peer)
	, bytes_received(0)
        , header()
{
}

/**
 * tcp_message::read() - Reads more data from a TCP connection and calls
 * a function to handle complete messages, if any.
 * @func:      Function to call when there is a complete message; the arguments
 *             to the function contain the total length of the message, plus
 *             a pointer to the standard header from the message. Func
 *             may be called multiple times in a single indication of this
 *             method.
 * Return:     Zero means success; nonzero means the socket was closed
 *             by the peer, or there was an error; a human-readable message
 *	       will be left in @error_message.
 */
int tcp_message::read(std::function<void (message_header *header)> func)
{
	char buffer[100000];
	char *next = buffer;
	
	int count = ::read(fd, buffer, sizeof(buffer));
	if ((count == 0) || ((count < 0) && (errno == ECONNRESET))) {
		/* Connection was closed by the client. */
		snprintf(error_message, sizeof(error_message),
				"TCP connection on port %d closed by peer %s",
				port, print_address(&peer));
		return 1;
	}
	if (count < 0) {
		snprintf(error_message, sizeof(error_message),
				"Error reading from TCP connection on "
				"port %d to %s: %s", port,
				print_address(&peer), strerror(errno));
		return 1;
	}
	
	/*
	 * Process incoming bytes (could contains parts of multiple requests).
	 * The first 4 bytes of each request give its length.
	 */
	while (count > 0) {
		/* First, fill in the message header with incoming data
		 * (there's no guarantee that a single read will return
		 * all of the bytes needed for these).
		 */
		int header_bytes = sizeof32(message_header) - bytes_received;
		if (header_bytes > 0) {
			if (count < header_bytes)
				header_bytes = count;
			char *dst = reinterpret_cast<char *>(&header);
			memcpy(dst + bytes_received, next, header_bytes);
			bytes_received += header_bytes;
			next += header_bytes;
			count -= header_bytes;
			if (bytes_received < sizeof32(message_header))
				break;
		}
		
		/* At this point we know the request length, so read until
		 * we've got a full request.
		 */
		int needed = header.length - bytes_received;
		if (count < needed) {
			bytes_received += count;
			break;
		}
		
		/* We now have a full request. */
		count -= needed;
		next += needed;
		func(&header);
		bytes_received = 0;
	}
	return 0;
}

/**
 * class server_metrics - Keeps statistics for a single server thread
 * (i.e. all the requests arriving via one Homa port or one TCP listen
 * socket).
 */
class server_metrics {
    public:
	/** @requests: Total number of requests handled so far. */
	uint64_t requests;
	
	/**
	 * @data: Total number of bytes of data in requests handled
	 * so far.
	 */
	uint64_t data;
	
	server_metrics() :requests(0), data(0) {}
};

/** @metrics: keeps track of metrics for all servers (whether Homa or TCP). */
std::vector<server_metrics *> metrics;

/**
 * class homa_server - Holds information about a single Homa server
 * thread, which handles requests on a given port. There may be more
 * than one thread on the same port.
 */
class homa_server {
    public:
	homa_server(int port);
	~homa_server();
	void server(void);
	
	/** @fd: File descriptor for Homa socket. */
	int fd;
	
	/** @metrics: Performance statistics. */
	server_metrics metrics;
	
	/** @thread: Background thread that services requests. */
	std::thread thread;
};

/** @homa_servers: keeps track of all existing Homa clients. */
std::vector<homa_server *> homa_servers;

/**
 * homa_server::homa_server() - Constructor for homa_server objects.
 * @fd:  File descriptor for Homa socket to use for receiving
 *       requests.
 */
homa_server::homa_server(int fd)
	: fd(fd)
        , metrics()
	, thread(&homa_server::server, this)
{
}

/**
 * homa_server::~homa_server() - Destructor for homa_servers; terminates
 * the background thread.
 */
homa_server::~homa_server()
{
	shutdown(fd, SHUT_RDWR);
	close(fd);
	thread.join();
}

/**
 * homa_server::server() - Handles incoming requests arriving on a Homa
 * socket. Normally invoked as top-level method in a thread.
 */
void homa_server::server(void)
{
	int message[1000000];
	struct sockaddr_in source;
	int length;
	while (1) {
		uint64_t id = 0;
		int result;
		
		while (1) {
			length = homa_recv(fd, message, sizeof(message),
				HOMA_RECV_REQUEST, &id,
				(struct sockaddr *) &source, sizeof(source));
			if (length >= 0)
				break;
			if ((errno == EBADF) || (errno == ESHUTDOWN))
				return;
			else if ((errno != EINTR) && (errno != EAGAIN))
				log(NORMAL, "homa_recv failed: %s\n",
						strerror(errno));
		}

		result = homa_reply(fd, message, length,
			(struct sockaddr *) &source, sizeof(source), id);
		if (result < 0) {
			log(NORMAL, "FATAL: homa_reply failed: %s\n",
					strerror(errno));
			exit(1);
		}
		metrics.requests++;
		metrics.data += length;
	}
}

/**
 * class tcp_server - Holds information about a single TCP server,
 * which consists of a thread that handles requests on a given port.
 */
class tcp_server {
    public:
	tcp_server(int port);
	~tcp_server();
	void accept(int epoll_fd);
	void read(int fd);
	void server(void);
	
	/** @port: Port on which we listen for connections. */
	int port;
	
	/** @listen_fd: File descriptor for the listen socket. */
	int listen_fd;
	
	/** @epoll_fd: File descriptor used for epolling. */
	int epoll_fd;
	
	/**
	 * @connections: Entry i contains information for a client
	 * connection on fd i.
	 */
	std::vector<tcp_message *> connections;
	
	/** @metrics: Performance statistics. */
	server_metrics metrics;
	
	/**
	 * @thread: Background thread that both accepts connections and
	 * services requests on them.
	 */
	std::optional<std::thread> thread;
	
	/** @stop: True means that background threads should exit. */
	bool stop;
};

/** @tcp_servers: keeps track of all existing Homa clients. */
std::vector<tcp_server *> tcp_servers;

/**
 * tcp_server::tcp_server() - Constructor for tcp_server objects.
 * @port:  Port number on which this server should listen for incoming
 *         requests.
 */
tcp_server::tcp_server(int port)
	: port(port)
	, listen_fd(-1)
	, epoll_fd(-1)
        , connections()
        , metrics()
        , thread()
        , stop(false)
{
	listen_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (listen_fd == -1) {
		log(NORMAL, "FATAL: couldn't open server socket: %s\n",
				strerror(errno));
		exit(1);
	}
	int option_value = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &option_value,
			sizeof(option_value)) != 0) {
		log(NORMAL, "FATAL: couldn't set SO_REUSEADDR on listen "
				"socket: %s",
				strerror(errno));
		exit(1);
	}
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(listen_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr))
			== -1) {
		log(NORMAL, "FATAL: couldn't bind to port %d: %s\n", port,
				strerror(errno));
		exit(1);
	}
	if (listen(listen_fd, 1000) == -1) {
		log(NORMAL, "FATAL: couldn't listen on socket: %s",
				strerror(errno));
		exit(1);
	}
	
	epoll_fd = epoll_create(10);
	if (epoll_fd < 0) {
		log(NORMAL, "FATAL: couldn't create epoll instance for "
				"TCP server: %s\n",
				strerror(errno));
		exit(1);
	}
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = listen_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
		log(NORMAL, "FATAL: couldn't add listen socket to epoll: %s\n",
				strerror(errno));
		exit(1);
	}
	
	thread.emplace(&tcp_server::server, this);
}

/**
 * tcp_server::~tcp_server() - Destructor for TCP servers. Terminates the
 * server's background thread.
 */
tcp_server::~tcp_server()
{
	int fds[2];
	
	stop = true;
	
	/* In order to wake up the background thread, open a file that is
	 * readable and add it to the epoll set.
	 */
	if (pipe2(fds, 0) < 0) {
		log(NORMAL, "FATAL: couldn't create pipe to shutdown TCP "
				"server: %s\n", strerror(errno));
		exit(1);
	}
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = fds[0];
	epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fds[0], &ev);
	if (write(fds[1], "xxxx", 4) < 0) {
		log(NORMAL, "FATAL: couldn't write to TCP shutdown pipe: %s\n",
				strerror(errno));
		exit(1);
	}
	
	thread->join();
	close(listen_fd);
	close(epoll_fd);
	close(fds[0]);
	close(fds[1]);
	for (unsigned i = 0; i < connections.size(); i++) {
		if (connections[i] != NULL) {
			if (close(i) < 0)
				log(NORMAL, "Error closing TCP connection to "
						"%s: %s\n",
						print_address(
						&connections[i]->peer),
						strerror(errno));
			delete connections[i];
			connections[i] = NULL;
		}
	}
}

/**
 * tcp_server::server() - Handles incoming TCP requests on a listen socket
 * and all of the connections accepted via that socket. Normally invoked as
 * top-level method in a thread
 */
void tcp_server::server()
{
	
	/* Each iteration through this loop processes a batch of epoll events. */
	while (1) {
#define MAX_EVENTS 20
		struct epoll_event events[MAX_EVENTS];
		int num_events;
		
		while (1) {
			num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
			if (stop)
				return;
			if (num_events >= 0)
				break;
			if ((errno == EAGAIN) || (errno == EINTR))
				continue;
			log(NORMAL, "FATAL: epoll_wait failed: %s\n",
					strerror(errno));
			exit(1);
		}
		for (int i = 0; i < num_events; i++) {
			int fd = events[i].data.fd;
			if (fd == listen_fd)
				accept(epoll_fd);
			else
				read(fd);
		}
	}
}

/**
 * tcp_server::accept() - Accepts a new incoming TCP connection and
 * initializes state for that connection.
 * @epoll_fd:   Used to arrange for epolling on the new connection.
 */
void tcp_server::accept(int epoll_fd)
{
	int fd;
	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(client_addr);
	
	fd = ::accept(listen_fd, reinterpret_cast<sockaddr *>(&client_addr),
			&addr_len);
	if (fd < 0) {
		log(NORMAL, "FATAL: couldn't accept incoming TCP connection: "
				"%s\n", strerror(errno));
		exit(1);
	}
	log(NORMAL, "tcp_server on port %d accepted connection from %s, fd %d\n",
			port, print_address(&client_addr), fd);
	int flag = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	tcp_message *message = new tcp_message(fd, port, client_addr);
	while (connections.size() <= static_cast<unsigned>(fd))
		connections.push_back(NULL);
	connections[fd] = message;
	
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		log(NORMAL, "FATAL: couldn't add new TCP connection to epoll: "
				"%s\n", strerror(errno));
		exit(1);
	}
}

/**
 * tcp_server::read() - Reads available data from a TCP connection; once an
 * entire request has been read, sends an appropriate response.
 * @fd:        File descriptor for connection; connections must hold
 *             state information for this descriptor.
 */
void tcp_server::read(int fd)
{
	int error = connections[fd]->read([this, fd](message_header *header) {
		metrics.requests++;
		metrics.data += header->length;
		if (send_message(fd, header) != 0) {
			if ((errno != EPIPE) && (errno != ECONNRESET)) {
				log(NORMAL, "FATAL: error sending TCP reply "
						"to %s: %s\n",
						print_address(&connections[fd]->peer),
						strerror(errno));
				exit(1);
			}
		};
	});
	if (error) {
		log(NORMAL, "%s\n", connections[fd]->error_message);
		if (close(fd) < 0) {
			log(NORMAL, "Error closing TCP connection to %s: %s\n",
					print_address(&connections[fd]->peer),
					strerror(errno));
		}
		delete connections[fd];
		connections[fd] = NULL;
	}
}

/**
 * class client - Holds information that is common to both Homa clients
 * and TCP clients. 
 */
class client {
    public:
	/**
	 * @id: unique identifier for this client (index starting at
	 * 0 for the first client.
	 */
	int id;
	    
	/**
	 * @receivers_running: number of receiving threads that have
	 * initialized and are ready to receive responses.
	 */
	std::atomic<size_t> receivers_running;
	
	/**
	 * @request_servers: a randomly chosen collection of indexes into
	 * server_addrs; used to select the server for each outgoing request.
	 */
	std::vector<int16_t> request_servers;

	/**
	 * @next_server: index into request_servers of the server to use for
	 * the next outgoing RPC.
	 */
	uint32_t next_server;
	
	/**
	 * @request_lengths: a randomly chosen collection of lengths to
	 * use for outgoing RPCs. Precomputed to save time during the
	 * actual measurements, and based on a given distribution.
	 * Note: lengths are always at least 4 (this is needed in order
	 * to include a 32-bit timestamp in the request).
	 */
	std::vector<int> request_lengths;

	/**
	 * @cnext_length: index into request_lengths of the length to use for
	 * the next outgoing RPC.
	 */
	uint32_t next_length;
	
	/**
	 * @request_intervals: a randomly chosen collection of inter-request
	 * intervals, measured in rdtsc cycles. Precomputed to save time
	 * during the actual measurements, and chosen to achieve a given
	 * network utilization, assuming a given distribution of request
	 * lengths.
	 */
	std::vector<int> request_intervals;

	/**
	 * @next_interval: index into request_intervals of the value to use
	 * for the next outgoing RPC.
	 */
	std::atomic<uint32_t> next_interval;
	
	/**
	 * @actual_lengths: a circular buffer that holds the actual payload
	 * sizes used for the most recent RPCs.
	 */
	std::vector<int> actual_lengths;
	
	/**
	 * @actual_rtts: a circular buffer that holds the actual round trip
	 * times (measured in rdtsc cycles) for the most recent RPCs. Entries
	 * in this array correspond to those in @actual_lengths.
	 */
	std::vector<uint32_t> actual_rtts;

	/**
	 * define NUM_CLENT_STATS: number of records in actual_lengths
	 * and actual_rtts.
	 */
#define NUM_CLIENT_STATS 500000
	
	/** @requests: total number of RPCs issued so far for each server. */
	std::vector<uint64_t> requests;
	
	/** @responses: total number of responses received so far from
	 * each server. Dynamically allocated (as of 3/2020, can't use
	 * vector with std::atomic).
	 */
	std::atomic<uint64_t> *responses;
	
	/** @num_servers: Number of entries in @responses. */
	size_t num_servers;
	
	/**
	 * @total_requests: total number of RPCs issued so far across all
	 * servers.
	 */
	uint64_t total_requests;
	
	/**
	 * @total_responses: total number of responses received so far from all
	 * servers.
	 */
	std::atomic<uint64_t> total_responses;
	
	/**
	 * @response_data: total number of bytes of data in responses
	 * received so far.
	 */
	std::atomic<uint64_t> response_data;
	
	/**
	 * @total_rtt: sum of round-trip times (in rdtsc cycles) for
	 * all responses received so far.
	 */
	std::atomic<uint64_t> total_rtt;
	
	/**
	 * @lag: time in rdtsc cycles by which we are running behind
	 * because server_max or client_max was exceeded (i.e., the
	 * request we just sent should have been sent @lag cycles ago).
	 */
	uint64_t lag;
	
	client(int id);
	virtual ~client();
	void record(int length, uint32_t rtt, int server_id);
};

/** @clients: keeps track of all existing clients. */
std::vector<client *> clients;
	
/**
 * client::client() - Constructor for client objects.
 *
 * @id: Unique identifier for this client (index starting at 0?)
 */
client::client(int id)
	: id(id)
	, receivers_running(0)
	, request_servers()
	, next_server(0)
	, request_lengths()
	, next_length(0)
	, request_intervals()
	, next_interval(0)
	, actual_lengths(NUM_CLIENT_STATS, 0)
	, actual_rtts(NUM_CLIENT_STATS, 0)
	, requests()
	, responses()
        , num_servers(server_addrs.size())
	, total_requests(0)
	, total_responses(0)
	, response_data(0)
        , total_rtt(0)
        , lag(0)
{
	/* Precompute information about the requests this client will
	 * generate. Pick a different prime number for the size of each
	 * vector, so that they will wrap at different times, giving
	 * different combinations of values over time.
	 */
#define NUM_SERVERS 4729
#define NUM_LENGTHS 7207
#define NUM_INTERVALS 8783
	std::uniform_int_distribution<int> server_dist(0,
			static_cast<int>(num_servers - 1));
	for (int i = 0; i < NUM_SERVERS; i++) {
		int server = server_dist(rand_gen);
		request_servers.push_back(server);
	}
	if (!dist_sample(workload, &rand_gen, NUM_LENGTHS, &request_lengths)) {
		printf("FATAL: invalid workload '%s'\n", workload);
		exit(1);
	}
	if (net_bw == 0.0)
		request_intervals.push_back(0);
	else {
		double lambda = 1e09*net_bw/(dist_mean(workload,
				HOMA_MAX_MESSAGE_LENGTH)*client_ports);
		double cycles_per_second = get_cycles_per_sec();
		std::exponential_distribution<double> interval_dist(lambda);
		for (int i = 0; i < NUM_INTERVALS; i++) {
			double seconds = interval_dist(rand_gen);
			int cycles = int(seconds*cycles_per_second);
			request_intervals.push_back(cycles);
		}
	}
	requests.resize(server_addrs.size());
	responses = new std::atomic<uint64_t>[num_servers];
	for (size_t i = 0; i < num_servers; i++)
		responses[i] = 0;
	double avg_length = 0;
	for (size_t i = 0; i < request_lengths.size(); i++)
		avg_length += request_lengths[i];
	avg_length /= NUM_LENGTHS;
	uint64_t interval_sum = 0;
	for (size_t i = 0; i < request_intervals.size(); i++)
		interval_sum += request_intervals[i];
	double rate = ((double) NUM_INTERVALS)/to_seconds(interval_sum);
	log(NORMAL, "Average message length %.1f KB (expected %.1fKB), "
			"rate %.2f K/sec, expected BW %.1f MB/sec\n",
			avg_length*1e-3, dist_mean(workload,
			HOMA_MAX_MESSAGE_LENGTH)*1e-3, rate*1e-3,
			avg_length*rate*1e-6);
}

/**
 * Destructor for clients.
 */
client::~client()
{
	delete[] responses;
}

/**
 * record() - Records statistics about a particular request.
 * @length:     Size of the request and response messages for the request,
 *              in bytes.
 * @rtt:        Total round-trip time to complete the request, in rdtsc cycles.
 * @server_id:  Index of the server for this request in @server_addrs.
 */
void client::record(int length, uint32_t rtt, int server_id)
{
	int slot = total_responses.fetch_add(1) % NUM_CLIENT_STATS;
	responses[server_id]++;
	response_data += length;
	total_rtt += rtt;
	actual_lengths[slot] = length;
	actual_rtts[slot] = rtt;
}

/**
 * class homa_client - Holds information about a single Homa client,
 * which consists of one thread issuing requests and one thread receiving
 * responses. 
 */
class homa_client : public client {
    public:
	homa_client(int id);
	virtual ~homa_client();
	void receiver(void);
	void sender(void);
	void wait_response(uint64_t id);
	
	/** @fd: file descriptor for Homa socket. */
	int fd;
	
	/** @stop: true means threads should exit ASAP. */
	bool stop;
	
	/** @receiver: threads that receive responses. */
	std::vector<std::thread> receiving_threads;
	
	/**
	 * @sender: thread that sends requests (may also receive
	 * responses if port_receivers is 0).
	 */
	std::optional<std::thread> sending_thread;
};

/**
 * homa_client::homa_client() - Constructor for homa_client objects.
 *
 * @id: Unique identifier for this client (index starting at 0?)
 */
homa_client::homa_client(int id)
	: client(id)
	, fd(-1)
        , stop(false)
        , receiving_threads()
        , sending_thread()
{
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
	if (fd < 0) {
		log(NORMAL, "Couldn't open Homa socket: %s\n", strerror(errno));
	}
	
	for (int i = 0; i < port_receivers; i++) {
		receiving_threads.emplace_back(&homa_client::receiver, this);
	}
	while (receivers_running < receiving_threads.size()) {
		/* Wait for the receivers to begin execution before
		 * starting the sender; otherwise the initial RPCs
		 * may appear to take a long time.
		 */
	}
	sending_thread.emplace(&homa_client::sender, this);
}

/**
 * homa_client::~homa_client() - Destructor for homa_client objects;
 * will terminate threads created for this client.
 */
homa_client::~homa_client()
{
	stop = true;
	shutdown(fd, SHUT_RDWR);
	close(fd);
	if (sending_thread)
		sending_thread->join();
	for (std::thread &thread: receiving_threads)
		thread.join();
}

/**
 * homa_client::weight_response() - Wait for a response to arrive and
 * update statistics.
 * @id   Id of a specific RPC to wait for, or 0 for "any response".
 */
void homa_client::wait_response(uint64_t id)
{
	char response[1000000];
	message_header *header = reinterpret_cast<message_header *>(response);
	struct sockaddr_in server_addr;
	
	id = 0;
	int length;
	do {
		length = homa_recv(fd, response, sizeof(response),
				HOMA_RECV_RESPONSE, &id,
				(struct sockaddr *) &server_addr,
				sizeof(server_addr));
	} while ((length < 0) && ((errno == EAGAIN) || (errno == EINTR)));
	if (length < 0) {
		if (stop)
			return;
		log(NORMAL, "FATAL: error in homa_recv: %s (id %lu, server %s\n",
				strerror(errno), id,
				print_address(&server_addr));
		exit(1);
	}
	uint32_t end_time = rdtsc() & 0xffffffff;
	record(length, end_time - header->start_time, header->server_id);
}

/**
 * homa_client::sender() - Invoked as the top-level method in a thread;
 * invokes a pseudo-random stream of RPCs continuously.
 */
void homa_client::sender()
{
	char request[1000000];
	message_header *header = reinterpret_cast<message_header *>(request);
	uint64_t next_start = rdtsc();
	
	while (1) {
		uint64_t now;
		uint64_t id;
		int server;
		
		/* Wait until (a) we have reached the next start time
		 * and (b) there aren't too many requests outstanding.
		 */
		while (1) {
			if (stop)
				return;
			now = rdtsc();
			if (now < next_start)
				continue;
			if ((total_requests - total_responses) < client_max)
				break;
		}
		
		server = request_servers[next_server];
		next_server++;
		if (next_server >= request_servers.size())
			next_server = 0;
		if ((requests[server] - responses[server]) >= server_max) {
			/* This server is overloaded, so skip it (don't
			 * let one slow server stop the whole benchmark).
			 */ 
			continue;
		}
		
		header->length = request_lengths[next_length];
		if (header->length > HOMA_MAX_MESSAGE_LENGTH)
			header->length = HOMA_MAX_MESSAGE_LENGTH;
		if (header->length < sizeof32(*header))
			header->length = sizeof32(*header);
		header->start_time = now & 0xffffffff;
		header->server_id = server;
		int status = homa_send(fd, request, header->length,
			reinterpret_cast<struct sockaddr *>(
			&server_addrs[server]),
			sizeof(server_addrs[0]), &id);
		if (stop)
			return;
		if (status < 0) {
			if (stop)
				return;
			log(NORMAL, "FATAL: error in homa_send: %s (request "
					"length %d)\n", strerror(errno),
					header->length);
			exit(1);
		}
		requests[server]++;
		total_requests++;
		next_length++;
		if (next_length >= request_lengths.size())
			next_length = 0;
		lag = now - next_start;
		next_start = next_start + request_intervals[next_interval];
		next_interval++;
		if (next_interval >= request_intervals.size())
			next_interval = 0;
		
		if (receivers_running == 0) {
			/* There isn't a separate receiver thread; wait for
			 * the response here. */
			wait_response(id);
		}
	}
}

/**
 * homa_client::receiver() - Invoked as the top-level method in a thread
 * that waits for RPC responses and then logs statistics about them.
 */
void homa_client::receiver(void)
{	
	receivers_running++;
	while (!stop)
		wait_response(0);
}

/**
 * class tcp_client - Holds information about a single TCP client,
 * which consists of one thread issuing requests and one thread receiving
 * responses. 
 */
class tcp_client : public client {
    public:
	tcp_client(int id);
	virtual ~tcp_client();
	void receiver(void);
	void sender(void);
	
	/** 
	 * @messages: One entry for each server in server_addrs; used to
	 * receive responses from that server.
	 */
	std::vector<tcp_message> messages;
	
	/**
	 * @epoll_fd: File descriptor used by @receiving_thread to
	 * wait for incoming messages.
	 */
	int epoll_fd;
	
	/** @stop:  True means background threads should exit. */
	bool stop;
	
	/** @receiver: threads that receive responses. */
	std::vector<std::thread> receiving_threads;
	
	/**
	 * @sender: thread that sends requests (may also receive
	 * responses if port_receivers is 0).
	 */
	std::optional<std::thread> sending_thread;
};

/**
 * tcp_client::tcp_client() - Constructor for tcp_client objects.
 *
 * @id: Unique identifier for this client (index starting at 0?)
 */
tcp_client::tcp_client(int id)
	: client(id)
	, messages()
        , epoll_fd(-1)
        , stop(false)
        , receiving_threads()
        , sending_thread()
{
	if (port_receivers != 1) {
		log(NORMAL, "FATAL: --port-receivers is %d, but TCP only "
				"supports 1", port_receivers);
		exit(1);
	}
	for (uint32_t i = 0; i < server_addrs.size(); i++) {
		int fd = socket(PF_INET, SOCK_STREAM, 0);
		if (fd == -1) {
			log(NORMAL, "FATAL: couldn't open TCP client "
					"socket: %s\n",
					strerror(errno));
			exit(1);
		}
		if (connect(fd, reinterpret_cast<struct sockaddr *>(
				&server_addrs[i]),
				sizeof(server_addrs[i])) == -1) {
			log(NORMAL, "FATAL: client couldn't connect "
					"to %s: %s\n",
					print_address(&server_addrs[i]),
					strerror(errno));
			exit(1);
		}
		int flag = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
		struct sockaddr_in addr;
		socklen_t length = sizeof(addr);
		if (getsockname(fd, reinterpret_cast<struct sockaddr *>(&addr),
				&length)) {
			log(NORMAL, "FATAL: getsockname failed for TCP client: "
					"%s\n", strerror(errno));
			exit(1);
		}
		messages.emplace_back(fd, ntohs(addr.sin_port), server_addrs[i]);
	}
	
	epoll_fd = epoll_create(10);
	if (epoll_fd < 0) {
		log(NORMAL, "FATAL: tcp_client couldn't create epoll "
				"instance: %s\n", strerror(errno));
		exit(1);
	}
	struct epoll_event ev;
	for (uint32_t i = 0; i < messages.size(); i++) {
		ev.events = EPOLLIN;
		ev.data.u32 = i;
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, messages[i].fd,
				&ev) != 0) {
			log(NORMAL, "FATAL: tcp_client couldn't add TCP "
					"socket %d  to epoll: %s\n", i,
					strerror(errno));
			exit(1);
		}
	}
	
	receiving_threads.emplace_back(&tcp_client::receiver, this);
	while (receivers_running == 0) {
		/* Wait for the receiver to begin execution before
		 * starting the sender; otherwise the initial RPCs
		 * may appear to take a long time.
		 */
	}
	sending_thread.emplace(&tcp_client::sender, this);
}

/**
 * tcp_client::~tcp_client() - Destructor for tcp_client objects;
 * will terminate threads created for this client.
 */
tcp_client::~tcp_client()
{
	int fds[2];
	
	stop = true;
	
	/* In order to wake up the background thread, open a file that is
	 * readable and add it to the epoll set.
	 */
	if (pipe2(fds, 0) < 0) {
		log(NORMAL, "FATAL: couldn't create pipe to shutdown TCP "
				"server: %s\n", strerror(errno));
		exit(1);
	}
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = fds[0];
	epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fds[0], &ev);
	if (write(fds[1], "xxxx", 4) < 0) {
		log(NORMAL, "FATAL: couldn't write to TCP shutdown "
				"pipe: %s\n", strerror(errno));
		exit(1);
	}
	
	if (sending_thread)
		sending_thread->join();
	for (std::thread& thread: receiving_threads)
		thread.join();
	
	close(fds[0]);
	close(fds[1]);
	close(epoll_fd);
	for (tcp_message &message: messages)
		close(message.fd);
}

/**
 * tcp_client::sender() - Invoked as the top-level method in a thread;
 * invokes a pseudo-random stream of RPCs continuously.
 */
void tcp_client::sender()
{
	uint64_t next_start = rdtsc();
	message_header header;
	
	while (1) {
		uint64_t now;
		int server;
		
		/* Wait until (a) we have reached the next start time
		 * and (b) there aren't too many requests outstanding.
		 */
		while (1) {
			if (stop)
				return;
			now = rdtsc();
			if (now < next_start)
				continue;
			if ((total_requests - total_responses) < client_max)
				break;
		}
		
		server = request_servers[next_server];
		next_server++;
		if (next_server >= request_servers.size())
			next_server = 0;
		if (requests[server] >= (responses[server] + server_max)) {
			/* This server is overloaded, so skip it (don't
			 * let one slow server stop the whole benchmark).
			 */
			continue;
		}
		
		header.length = request_lengths[next_length];
		if ((header.length > HOMA_MAX_MESSAGE_LENGTH) && tcp_trunc)
			header.length = HOMA_MAX_MESSAGE_LENGTH;
		header.start_time = now & 0xffffffff;
		header.server_id = server;
		int status = send_message(messages[server].fd, &header);
		if (status != 0) {
			log(NORMAL, "FATAL: error in TCP socket write to %s: "
					"%s (client port %d)\n",
					print_address(&server_addrs[server]),
					strerror(errno), messages[server].port);
			exit(1);
		}
		if (verbose)
			log(NORMAL, "tcp_client %d sent request to server port "
					"%d, length %d\n",
					id, header.server_id,
					request_lengths[next_length]);
		requests[server]++;
		total_requests++;
		next_length++;
		if (next_length >= request_lengths.size())
			next_length = 0;
		lag = now - next_start;
		next_start += request_intervals[next_interval];
		next_interval++;
		if (next_interval >= request_intervals.size())
			next_interval = 0;
	}
}

/**
 * tcp_client::receiver() - Invoked as the top-level method in a thread
 * that waits for RPC responses and then logs statistics about them.
 */
void tcp_client::receiver(void)
{
	receivers_running++;
	
	/* Each iteration through this loop processes a batch of incoming
	 * responses
	 */
	while (1) {
#define MAX_EVENTS 20
		struct epoll_event events[MAX_EVENTS];
		int num_events;
		
		while (1) {
			num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
			if (stop)
				return;
			if (num_events > 0)
				break;
			if ((errno == EAGAIN) || (errno == EINTR))
				continue;
			log(NORMAL, "FATAL: epoll_wait failed in tcp_client: "
					"%s\n",
					strerror(errno));
			exit(1);
		}
		for (int i = 0; i < num_events; i++) {
			tcp_message *message = &messages[events[i].data.u32];
			int error = message->read([this](
					message_header *header) {
				uint32_t end_time = rdtsc() & 0xffffffff;
				record(header->length,
						end_time - header->start_time,
						header->server_id);
			});
			if (error) {
				log(NORMAL, "FATAL: %s (client)\n",
						message->error_message);
				exit(1);
			}
		}
	}
}

/**
 * server_stats() -  Prints recent statistics collected from all
 * servers.
 * @now:   Current time in rdtsc cycles (used to compute rates for
 *         statistics).
 */
void server_stats(uint64_t now)
{
	char details[10000];
	int offset = 0;
	int length;
	uint64_t server_rpcs = 0;
	uint64_t server_data = 0;
	details[0] = 0;
	for (uint32_t i = 0; i < metrics.size(); i++) {
		server_metrics *server = metrics[i];
		server_rpcs += server->requests;
		server_data += server->data;
		length = snprintf(details + offset, sizeof(details) - offset,
				"%s%lu", (offset != 0) ? " " : "",
				server->requests - last_per_server_rpcs[i]);
		offset += length;
		if (i > last_per_server_rpcs.size())
			printf("last_per_server_rpcs has %lu entries, needs %lu\n",
					last_per_server_rpcs.size(),
					metrics.size());
		last_per_server_rpcs[i] = server->requests;
	}
	if ((last_stats_time != 0) && (server_data != last_server_data)) {
		double elapsed = to_seconds(now - last_stats_time);
		double rpcs = (double) (server_rpcs - last_server_rpcs);
		double data = (double) (server_data - last_server_data);
		log(NORMAL, "Servers: %.2f Kops/sec, %.2f MB/sec, "
				"avg. length %.1f bytes\n",
				rpcs/(1000.0*elapsed), data/(1e06*elapsed),
				data/rpcs);
		log(NORMAL, "RPCs per server: %s\n", details);
	}
	last_server_rpcs = server_rpcs;
	last_server_data = server_data;
}

/**
 * client_stats() -  Prints recent statistics collected by all existing
 * clients (either TCP or Homa).
 * @now:       Current time in rdtsc cycles (used to compute rates for
 *             statistics).
 */
void client_stats(uint64_t now)
{
#define CDF_VALUES 100000
	uint64_t client_rpcs = 0;
	uint64_t client_data = 0;
	uint64_t total_rtt = 0;
	uint64_t lag = 0;
	uint64_t cdf_times[CDF_VALUES];
	int times_per_client;
	int cdf_index = 0;
	
	if (clients.size() == 0)
		return;
	
	times_per_client = CDF_VALUES/clients.size();
	if (times_per_client > NUM_CLIENT_STATS)
		times_per_client = NUM_CLIENT_STATS;
	for (client *client: clients) {
		for (size_t i = 0; i < client->num_servers; i++)
			client_rpcs += client->responses[i];
		client_data += client->response_data;
		total_rtt += client->total_rtt;
		lag += client->lag;
		for (int i = 1; i <= times_per_client; i++) {
			/* Collect the most recent RTTs from the client for
			 * computing a CDF.
			 */
			int src = (client->total_responses - i)
					% NUM_CLIENT_STATS;
			if (client->actual_rtts[src] == 0) {
				/* Client hasn't accumulated times_per_client
				 * entries yet; just use what it has. */
				break;
			}
			cdf_times[cdf_index] = client->actual_rtts[src];
			cdf_index++;
		}
	}
	std::sort(cdf_times, cdf_times + cdf_index);
	if ((last_stats_time != 0) && (client_data != last_client_data)) {
		double elapsed = to_seconds(now - last_stats_time);
		double rpcs = (double) (client_rpcs - last_client_rpcs);
		double data = (double) (client_data - last_client_data);
		log(NORMAL, "Clients: %.2f Kops/sec, %.2f MB/sec, RTT (us) "
				"P50 %.2f P99 %.2f P99.9 %.2f, avg. length "
				"%.1f bytes\n",
				rpcs/(1000.0*elapsed), data/(1e06*elapsed),
				to_seconds(cdf_times[cdf_index/2])*1e06,
				to_seconds(cdf_times[99*cdf_index/100])*1e06,
				to_seconds(cdf_times[999*cdf_index/1000])*1e06,
			        data/rpcs);
		double lag_fraction;
		if (lag > last_lag)
			lag_fraction = (to_seconds(lag - last_lag)/elapsed)
				/ clients.size();
		else
			lag_fraction = -(to_seconds(last_lag - lag)/elapsed)
				/ clients.size();
		if (lag_fraction >= .01)
			log(NORMAL, "Lag due to overload: %.1f%%\n",
					lag_fraction*100.0);
	}
	last_client_rpcs = client_rpcs;
	last_client_data = client_data;
	last_total_rtt = total_rtt;
	last_lag = lag;
}

/**
 * log_stats() - Enter an infinite loop printing statistics to the
 * log every second. This function never returns.
 */
void log_stats()
{
	while (1) {
		sleep(1);
		std::lock_guard<std::mutex> lock(cmd_lock);
		uint64_t now = rdtsc();
		server_stats(now);
		client_stats(now);

		last_stats_time = now;
	}
}

/**
 * client_cmd() - Parse the arguments for a "client" command and execute it.
 * @words:  Command arguments (including the command name as @words[0]).
 * 
 * Return:  Nonzero means success, zero means there was an error.
 */
int client_cmd(std::vector<string> &words)
{
	client_max = 1;
	client_ports = 1;
	first_port = 4000;
	first_server = 1;
	server_max = 1;
	net_bw = 0.0;
	port_receivers = 1;
	protocol = "homa";
	server_nodes = 1;
	tcp_trunc = true;
	workload = "100";
	for (unsigned i = 1; i < words.size(); i++) {
		const char *option = words[i].c_str();

		if (strcmp(option, "--first-port") == 0) {
			if (!parse_int(words, i+1, &first_port, option))
				return 0;
			i++;
		} else if (strcmp(option, "--first-server") == 0) {
			if (!parse_int(words, i+1, &first_server, option))
				return 0;
			i++;
		} else if (strcmp(option, "--id") == 0) {
			if (!parse_int(words, i+1, &id, option))
				return 0;
			i++;
		} else if (strcmp(option, "--net-bw") == 0) {
			if (!parse_float(words, i+1, &net_bw, option))
				return 0;
			i++;
		} else if (strcmp(option, "--no-trunc") == 0) {
			tcp_trunc = false;
		} else if (strcmp(option, "--ports") == 0) {
			if (!parse_int(words, i+1, &client_ports, option))
				return 0;
			i++;
		} else if (strcmp(option, "--port-max") == 0) {
			if (!parse_int(words, i+1, (int *) &client_max,
					option))
				return 0;
			i++;
		} else if (strcmp(option, "--port-receivers") == 0) {
			if (!parse_int(words, i+1, &port_receivers, option))
				return 0;
			i++;
		} else if (strcmp(option, "--protocol") == 0) {
			if ((i + 1) >= words.size()) {
				printf("No value provided for %s\n",
						option);
				return 0;
			}
			protocol = words[i+1].c_str();
			i++;
		} else if (strcmp(option, "--server-max") == 0) {
			if (!parse_int(words, i+1, (int *) &server_max,
					option))
				return 0;
			i++;
		} else if (strcmp(option, "--server-nodes") == 0) {
			if (!parse_int(words, i+1, &server_nodes, option))
				return 0;
			i++;
		} else if (strcmp(option, "--server-ports") == 0) {
			if (!parse_int(words, i+1, &server_ports, option))
				return 0;
			i++;
		} else if (strcmp(option, "--workload") == 0) {
			if ((i + 1) >= words.size()) {
				printf("No value provided for %s\n",
						option);
				return 0;
			}
			workload = words[i+1].c_str();
			i++;
		} else {
			printf("Unknown option '%s'\n", option);
			return 0;
		}
	}
	init_server_addrs();

	/* Create clients. */
	for (int i = 0; i < client_ports; i++) {
		if (strcmp(protocol, "homa") == 0)
			clients.push_back(new homa_client(i));
		else
			clients.push_back(new tcp_client(i));
	}
	last_stats_time = 0;
	return 1;
}

/**
 * dump_times_cmd() - Parse the arguments for a "dump_times" command and
 * execute it.
 * @words:  Command arguments (including the command name as @words[0]).
 * 
 * Return:  Nonzero means success, zero means there was an error.
 */
int dump_times_cmd(std::vector<string> &words)
{
	FILE *f;
	time_t now;
	char time_buffer[100];
	
	if (words.size() != 2) {
		printf("Wrong # args; must be 'dump_times file'\n");
		return 0;
	}
	f = fopen(words[1].c_str(), "w");
	if (f == NULL) {
		printf("Couldn't open file %s: %s\n", words[1].c_str(),
				strerror(errno));
		return 0;
	}
	
	time(&now);
	strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S",
			localtime(&now));
	fprintf(f, "# Round-trip times measured by cp_node at %s\n",
			time_buffer);
	fprintf(f, "# --protocol %s, --workload %s, --net-bw %.1f --threads %d,\n",
			protocol, workload, net_bw, client_ports);
	fprintf(f, "# --server-nodes %d --server-ports %d, --port-max %d, --server-max %d\n",
			server_nodes, server_ports, client_max, server_max);
	fprintf(f, "# Length   RTT (usec)\n");
	for (client *client: clients) {
		__u32 start = client->total_responses % NUM_CLIENT_STATS;
		__u32 i = start;
		while (1) {
			if (client->actual_rtts[i] != 0) {
				fprintf(f, "%8d %12.2f\n",
						client->actual_lengths[i],
						1e06*to_seconds(
						client->actual_rtts[i]));
				client->actual_rtts[i] = 0;
			}
			i++;
			if (i >= client->actual_rtts.size())
				i = 0;
			if (i == start)
				break;
		}
	}
	fclose(f);
	return 1;
}

/**
 * log_cmd() - Parse the arguments for a "log" command and execute it.
 * @words:  Command arguments (including the command name as @words[0]).
 * 
 * Return:  Nonzero means success, zero means there was an error.
 */
int log_cmd(std::vector<string> &words)
{
	for (unsigned i = 1; i < words.size(); i++) {
		const char *option = words[i].c_str();
		
		if (strncmp(option, "--", 2) != 0) {
			string message;
			for (unsigned j = i; j < words.size(); j++) {
				if (j != i)
					message.append(" ");
				message.append(words[j]);
			}
			message.append("\n");
			log(NORMAL, "%s", message.c_str());
			return 1;
		}

		if (strcmp(option, "--file") == 0) {
			FILE *f;
			if ((i + 1) >= words.size()) {
				printf("No value provided for %s\n",
						option);
				return 0;
			}
			const char *name = words[i+1].c_str();
			if (strcmp(name, "-") == 0)
				f = stdout;
			else {
				f = fopen(name, "w");
				if (f == NULL) {
					printf("Couldn't open %s: %s\n", name,
							strerror(errno));
					return 0;
				}
				setlinebuf(f);
			}
			if (log_file != stdout)
				fclose(log_file);
			log_file = f;
			i++;
		} else if (strcmp(option, "--level") == 0) {
			if ((i + 1) >= words.size()) {
				printf("No value provided for %s\n",
						option);
				return 0;
			}
			if (words[i+1].compare("normal") == 0)
				log_level = NORMAL;
			else if (words[i+1].compare("verbose") == 0)
				log_level = VERBOSE;
			else {
				printf("Unknown log level '%s'; must be "
						"normal or verbose\n",
						words[i+1].c_str());
				return 0;
			}
			log(NORMAL, "Log level is now %s\n",
					words[i+1].c_str());
			i++;
		} else {
			printf("Unknown option '%s'\n", option);
			return 0;
		}
	}
	return 1;
}

/**
 * server_cmd() - Parse the arguments for a "server" command and execute it.
 * @words:  Command arguments (including the command name as @words[0]).
 * 
 * Return:  Nonzero means success, zero means there was an error.
 */
int server_cmd(std::vector<string> &words)
{
	first_port = 4000;
        protocol = "homa";
	port_threads = 1;
	server_ports = 1;
	
	for (unsigned i = 1; i < words.size(); i++) {
		const char *option = words[i].c_str();

		if (strcmp(option, "--first-port") == 0) {
			if (!parse_int(words, i+1, &first_port, option))
				return 0;
			i++;
		} else if (strcmp(option, "--port-threads") == 0) {
			if (!parse_int(words, i+1, &port_threads, option))
				return 0;
			i++;
		} else if (strcmp(option, "--ports") == 0) {
			if (!parse_int(words, i+1, &server_ports, option))
				return 0;
			i++;
		} else if (strcmp(option, "--protocol") == 0) {
			if ((i + 1) >= words.size()) {
				printf("No value provided for %s\n",
						option);
				return 0;
			}
			protocol = words[i+1].c_str();
			i++;
		} else {
			printf("Unknown option '%s'\n", option);
			return 0;
		}
	}

	if (strcmp(protocol, "homa") == 0) {
		for (int i = 0; i < server_ports; i++) {
			struct sockaddr_in addr_in;
			int fd, j, port;

			fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
			if (fd < 0) {
				log(NORMAL, "FATAL: couldn't open Homa socket: "
						"%s\n",
						strerror(errno));
				exit(1);
			}

			port = first_port + i;
			memset(&addr_in, 0, sizeof(addr_in));
			addr_in.sin_family = AF_INET;
			addr_in.sin_port = htons(port);
			if (bind(fd, (struct sockaddr *) &addr_in,
					sizeof(addr_in)) != 0) {
				log(NORMAL, "FATAL: couldn't bind socket "
						"to Homa port %d: %s\n", port,
						strerror(errno));
				exit(1);
			}
			log(NORMAL, "Successfully bound to Homa port %d\n",
					port);
			for (j = 0; j < port_threads; j++) {
				homa_server *server = new homa_server(
						fd);
				homa_servers.push_back(server);
				metrics.push_back(&server->metrics);
			}
		}
	} else {
		for (int i = 0; i < server_ports; i++) {
			tcp_server *server = new tcp_server(
					first_port + i);
			tcp_servers.push_back(server);
			metrics.push_back(&server->metrics);
		}
	}
	last_per_server_rpcs.resize(server_ports*port_threads, 0);
	last_stats_time = 0;
	return 1;
}

/**
 * stop_cmd() - Parse the arguments for a "stop" command and execute it.
 * @words:  Command arguments (including the command name as @words[0]).
 * 
 * Return:  Nonzero means success, zero means there was an error.
 */
int stop_cmd(std::vector<string> &words)
{	
	for (unsigned i = 1; i < words.size(); i++) {
		const char *option = words[i].c_str();
		if (strcmp(option, "clients") == 0) {
			for (client *client: clients)
				delete client;
			clients.clear();
		} else if (strcmp(option, "servers") == 0) {
			for (homa_server *server: homa_servers)
				delete server;
			homa_servers.clear();
			for (tcp_server *server: tcp_servers)
				delete server;
			tcp_servers.clear();
			last_per_server_rpcs.clear();
			metrics.clear();
		} else {
			printf("Unknown option '%s'; must be clients or "
				"servers\n", option);
			return 0;
		}
	}
	return 1;
}

/**
 * exec_words() - Given a command that has been parsed into words,
 * execute the command corresponding to the words.
 * @words:  Each entry represents one word of the command, like argc/argv.
 * 
 * Return:  Nonzero means success, zero means there was an error. 
 */
int exec_words(std::vector<string> &words)
{
	std::lock_guard<std::mutex> lock(cmd_lock);
	if (words.size() == 0)
		return 1;
	if (words[0].compare("client") == 0) {
		return client_cmd(words);
	} else if (words[0].compare("dump_times") == 0) {
		return dump_times_cmd(words);
	} else if (words[0].compare("log") == 0) {
		return log_cmd(words);
	} else if (words[0].compare("exit") == 0) {
		if (log_file != stdout)
			log(NORMAL, "cp_node exiting (exit command)\n");
		exit(0);
	} else if (words[0].compare("server") == 0) {
		return server_cmd(words);
	} else if (words[0].compare("stop") == 0) {
		return stop_cmd(words);
	} else {
		printf("Unknown command '%s'\n", words[0].c_str());
		return 0;
	}
}

/**
 * exec_string() - Given a string, parse it into words and execute the
 * resulting command.
 * @cmd:  Command to execute.
 */
void exec_string(const char *cmd)
{
	const char *p = cmd;
	std::vector<string> words;
	
	if (log_file != stdout)
		log(NORMAL, "Command: %s\n", cmd);
	
	while (1) {
		int word_length = strcspn(p, " \t\n");
		if (word_length > 0)
			words.emplace_back(p, word_length);
		p += word_length;
		if (*p == 0)
			break;
		p++;
	}
	exec_words(words);
}

/**
 * error_handler() - This method is invoked after a terminal error such
 * as a segfault; it logs a backtrace and exits.
 * @signal    Signal number that caused this method to be invoked.
 * @info      Details about the cause of the signal; used to find the
 *            faulting address for segfaults.
 * @ucontext  CPU context at the time the signal occurred.
 */
void error_handler(int signal, siginfo_t* info, void* ucontext)
{
	ucontext_t* uc = static_cast<ucontext_t*>(ucontext);
	void* caller_address = reinterpret_cast<void*>(
			uc->uc_mcontext.gregs[REG_RIP]);

	log(NORMAL, "Signal %d (%s) at address %p from %p\n",
			signal, strsignal(signal), info->si_addr,
			caller_address);

	const int max_frames = 128;
	void* return_addresses[max_frames];
	int frames = backtrace(return_addresses, max_frames);

	// Overwrite sigaction with caller's address.
	return_addresses[1] = caller_address;

	char** symbols = backtrace_symbols(return_addresses, frames);
	if (symbols == NULL) {
		/* If the malloc failed we might be able to get the backtrace out
		 * to stderr still.
		 */
		log(NORMAL, "backtrace_symbols failed; trying "
				"backtrace_symbols_fd\n");
		backtrace_symbols_fd(return_addresses, frames, 2);
		return;
	}

	log(NORMAL, "Backtrace:\n");
	for (int i = 1; i < frames; ++i)
		log(NORMAL, "%s\n", symbols[i]);
	fflush(log_file);

	/* Use abort, rather than exit, to dump core/trap in gdb. */
	abort();
}

int main(int argc, char** argv)
{
	setlinebuf(stdout);
	signal(SIGPIPE, SIG_IGN);
	struct rlimit limits;
	if (getrlimit(RLIMIT_NOFILE, &limits) != 0) {
		log(NORMAL, "FATAL: couldn't read file descriptor limits: "
				"%s\n", strerror(errno));
		exit(1);
	}
	limits.rlim_cur = limits.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &limits) != 0) {
		log(NORMAL, "FATAL: couldn't increase file descriptor limit: "
				"%s\n", strerror(errno));
		exit(1);
	}
	struct sigaction action;
	action.sa_sigaction = error_handler;
	action.sa_flags = SA_RESTART | SA_SIGINFO;
	if (sigaction(SIGSEGV, &action, NULL) != 0)
		log(VERBOSE, "Couldn't set signal handler for SIGSEGV; "
				"continuing anyway\n");

	if ((argc >= 2) && (strcmp(argv[1], "--help") == 0)) {
		print_help(argv[0]);
		exit(0);
	}
	
	if (argc > 1) {
		std::vector<string> words;
		for (int i = 1; i < argc; i++)
			words.emplace_back(argv[i]);
		if (!exec_words(words))
			exit(1);
		
		/* Instead of going interactive, just print stats.
		 * every second.
		 */
		log_stats();
	}
	
	
	std::thread logger(log_stats);
	while (1) {
		string line;
		
		printf("%% ");
		fflush(stdout);
		if (!std::getline(std::cin, line)) {
			if (log_file != stdout)
				log(NORMAL, "cp_node exiting (EOF on stdin)\n");
			exit(0);
		}
		exec_string(line.c_str());
	}
}
