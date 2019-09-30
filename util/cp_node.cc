/* This file contains a program that runs on one node, as part of
 * the cluster_perf test.
 */

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

#include <algorithm>
#include <atomic>
#include <functional>
#include <random>
#include <thread>
#include <vector>

#include "dist.h"
#include "homa.h"
#include "test_utils.h"

/* Command-line parameter values (and default values): */
int client_threads = 0;
const char *dist_file = "foo.bar";
int first_port = 4000;
int first_server = 1;
bool is_server = false;
int id = -1;
uint32_t max_requests = 5;
double net_util = 0.8;
const char *protocol = "homa";
int server_threads = 1;
int server_nodes = 1;
const char *workload = "100";

/** @rand_gen: random number generator. */
std::mt19937 rand_gen(12345);

/**
 * @server_addrs: Internet addresses for each of the server threads available
 * to receive a Homa RPC.
 */
std::vector<struct sockaddr_in> server_addrs;

/**
 * @last_stats_time: time (in rdtsc cycles) when we last printed
 * staticsics.
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
		"--first_port          First port number to use on servers (default: %d)\n"
		"--first_server        Id of first server for clients to use (default: %d,\n"
		"                      meaning node-%d)\n"
		"--help                Print this message\n"
		"--is_server           Instantiate server threads on this node\n"
		"--max_requests        Maximum number of outstanding requests from a client\n"
		"                      to a single server thread (default: %d)\n"
		"--net_util            Target network utilization, including headers and packet\n"
		"                      gaps (default: %.2f)\n"
		"--protocol            Transport protocol to use for requests: homa or tcp\n"
		"                      (default: %s)\n"
		"--server_nodes        Number of nodes running server threads (default: %d)\n"
		"--server_threads      Number of server threads/ports on each server node\n"
		"                      (default: %d)\n"
		"--workload            Name of distribution for request lengths (e.g., 'w1')\n"
		"                      or integer for fixed length (default: %s)\n",
		name, client_threads, dist_file, first_port, first_server,
		first_server, max_requests, net_util, protocol, server_nodes,
		server_threads, workload);
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
 * struct message_header - The first few bytes of each message (request or
 * response) have the structure defined here. The client initially specifies
 * this information in the request, and the server returns the information
 * in the response.
 */
struct message_header {
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
 * @size:       Size of message to write (must be at least 8).
 * @header:     Transmitted as the first bytes of the message
 *              (after the size word).
 * 
 * Return:   Zero for success; anything else means there was an error
 *           (check errno for details).
 */
int send_message(int fd, int size, message_header *header)
{
	int buffer[100000/sizeof(uint32_t)];
	buffer[0] = size;
	*(reinterpret_cast<message_header *>(&buffer[1])) = *header;
	for (int bytes_left = size; bytes_left > 0; ) {
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
 * struct tcp_message - Handles the reading of TCP messages; a message
 * may arrive in several chunks spaced out in time; this class keeps track
 * of the current state.
 */
class tcp_message {
    public:
	tcp_message(int fd, struct sockaddr_in peer);
	int read(std::function<void (int size, message_header *header)> func);
	
	/** @fd: File descriptor to use for reading data. */
	int fd;
	
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
	 * @size: this variable and @timestamp will eventually hold the
	 * first 8 bytes of the message; if @bytes_received is less than
	 * 8, then these values have not yet been fully read. This variable
	 * gives the total message length in bytes (including the size).
	 */
	int size;
	
	/**
	 * @header: first bytes of the message, starting at byte 4; not valid
	 * unless @bytes_received >= 4+sizeof(message_header).
	 */
	message_header header;
} __attribute__((packed));

/**
 * tcp_message:: tcp_message() - Constructor for tcp_message objects.
 * @fd:        File descriptor from which to read data.
 * @peer:      Address of the machine we're reading from; used for messages.
 */
tcp_message::tcp_message(int fd, struct sockaddr_in peer)
	: fd(fd)
	, peer(peer)
	, bytes_received(0)
        , size(0)
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
 *             by the peer, or there was an error. Before returning, this
 *             method prints an error message.
 */
int tcp_message::read(std::function<void (int size, message_header *header)> func)
{
	char buffer[100000];
	char *next = buffer;
#define TCP_HDR_SIZE (sizeof32(int) + sizeof32(message_header))
	
	int count = ::read(fd, buffer, sizeof(buffer));
	if ((count == 0) || ((count < 0) && (errno == ECONNRESET))) {
		/* Connection was closed by the client. */
		return 1;
	}
	if (count < 0) {
		printf("Error reading from TCP connection: %s\n",
				strerror(errno));
		return 1;
	}
	
	/*
	 * Process incoming bytes (could contains parts of multiple requests).
	 * The first 4 bytes of each request give its length.
	 */
	while (count > 0) {
		/* First, fill in the size and message_header with incoming
		 * data (there's no guarantee that a single read will return
		 * all of the bytes needed for these).
		 */
		int header_bytes = TCP_HDR_SIZE - bytes_received;
		if (header_bytes > 0) {
			if (count < header_bytes)
				header_bytes = count;
			char *header = reinterpret_cast<char *>(&size);
			memcpy(header + bytes_received, next, header_bytes);
			bytes_received += header_bytes;
			next += header_bytes;
			count -= header_bytes;
			if (bytes_received < TCP_HDR_SIZE)
				break;
		}
		
		/* At this point we know the request length, so read until
		 * we've got a full request.
		 */
		int needed = size - bytes_received;
		if (count < needed) {
			bytes_received += count;
			break;
		}
		
		/* We now have a full request. */
		count -= needed;
		next += needed;
		func(size, &header);
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
 * class homa_server - Holds information about a single Homa server,
 * which consists of a thread that handles requests on a given port.
 */
class homa_server {
    public:
	homa_server(int port);
	void server(void);
	
	/** @fd: File descriptor for Homa socket. */
	int fd;
	
	/** @metrics: Performance statistics. */
	server_metrics metrics;
};

/** @homa_servers: keeps track of all existing Homa clients. */
std::vector<homa_server *> homa_servers;

/**
 * homa_server::homa_server() - Constructor for homa_server objects.
 * @port:  Port on which to receive requests
 */
homa_server::homa_server(int port)
	: fd(-1)
        , metrics()
{
	struct sockaddr_in addr_in;
	
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
	
	std::thread server(&homa_server::server, this);
	server.detach();
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
		
		length = homa_recv(fd, message, sizeof(message),
			HOMA_RECV_REQUEST, &id, (struct sockaddr *) &source,
			sizeof(source));
		if (length < 0) {
			printf("homa_recv failed: %s\n", strerror(errno));
			continue;
		}

		result = homa_reply(fd, message, length,
			(struct sockaddr *) &source, sizeof(source), id);
		if (result < 0) {
			printf("Homa_reply failed: %s\n", strerror(errno));
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
	void accept(int epoll_fd);
	void read(int fd);
	void server(void);
	
	/** @listen_fd: File descriptor for the listen socket. */
	int listen_fd;
	
	/**
	 * @connections: Entry i contains information for a client
	 * connection on fd i.
	 */
	std::vector<tcp_message *> connections;
	
	/** @metrics: Performance statistics. */
	server_metrics metrics;
};

/** @tcp_servers: keeps track of all existing Homa clients. */
std::vector<tcp_server *> tcp_servers;

/**
 * tcp_server::tcp_server() - Constructor for tcp_server objects.
 * @port:  Port number on which this server should listen for incoming
 *         requests.
 */
tcp_server::tcp_server(int port)
	: listen_fd(-1)
        , connections()
        , metrics()
{
	listen_fd = socket(PF_INET, SOCK_STREAM, 0);
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
	
	std::thread server(&tcp_server::server, this);
	server.detach();
}

/**
 * tcp_server::server() - Handles incoming TCP requests on a listen socket
 * and all of the connections accepted via that socket. Normally invoked as
 * top-level method in a thread
 */
void tcp_server::server()
{	
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
#define MAX_EVENTS 20
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
		printf("Couldn't accept incoming TCP connection: %s",
			strerror(errno));
		exit(1);
	}
	int flag = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	tcp_message *message = new tcp_message(fd, client_addr);
	connections.resize(fd + 1);
	connections[fd] = message;
	
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		printf("Couldn't add new TCP connection to epoll: %s\n",
				strerror(errno));
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
	int error = connections[fd]->read([this, fd](int size,
			message_header *header) {
		metrics.requests++;
		metrics.data += size;
		if (send_message(fd, size, header) != 0) {
			if ((errno != EPIPE) && (errno != ECONNRESET)) {
				printf("Error sending reply to %s: %s\n",
						print_address(&connections[fd]->peer),
						strerror(errno));
				exit(1);
			}
		};
	});
	if (error) {
		if (close(fd) < 0) {
			printf("Error closing TCP connection to %s: %s\n",
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
	 * @receiver_running: nonzero means the receiving thread has
	 * initialized and is ready to receive responses.
	 */
	std::atomic<int> receiver_running;
	
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
	 * @next_interval: index into request_lengths of the length to use for
	 * the next outgoing RPC.
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
	
	/**
	 * @next_result: index into both actual_lengths and actual_rtts
	 * where info about the next RPC completion will be stored.
	 */
	uint32_t next_result;
	
	/** @requests: total number of RPCs issued so far for each server. */
	std::vector<uint64_t> requests;
	
	/** @responses: total number of responses received so far. */
	std::vector<uint64_t> responses;
	
	/**
	 * @response_data: total number of bytes of data in responses
	 * received so far.
	 */
	uint64_t response_data;
	
	/**
	 * @total_rtt: sum of round-trip times (in rdtsc cycles) for
	 * all responses received so far.
	 */
	uint64_t total_rtt;
	
	client();
};

/** @clients: keeps track of all existing clients. */
std::vector<client *> clients;
	
/** client::client() - Constructor for client objects. */
client::client()
	: receiver_running(0)
	, request_servers()
	, next_server(0)
	, request_lengths()
	, next_length(0)
	, request_intervals()
	, next_interval(0)
	, actual_lengths(NUM_CLIENT_STATS, 0)
	, actual_rtts(NUM_CLIENT_STATS, 0)
	, next_result(0)
	, requests()
	, responses()
	, response_data(0)
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
			static_cast<int>(server_addrs.size() - 1));
	for (int i = 0; i < NUM_SERVERS; i++) {
		int server = server_dist(rand_gen);
		request_servers.push_back(server);
	}
	if (!dist_sample(workload, &rand_gen, NUM_LENGTHS, &request_lengths)) {
		printf("Invalid workload '%s'\n", workload);
		exit(1);
	}
	request_lengths.push_back(100);
	request_intervals.push_back(0);
	requests.resize(server_addrs.size());
	responses.resize(server_addrs.size());
}

/**
 * class homa_client - Holds information about a single Homa client,
 * which consists of one thread issuing requests and one thread receiving
 * responses. 
 */
class homa_client : public client {
    public:
	homa_client(void);
	void receiver(void);
	void sender(void);
	
	/** @fd: file descriptor for Homa socket. */
	int fd;
};

/** homa_client::homa_client() - Constructor for homa_client objects. */
homa_client::homa_client()
	: fd(-1)
{
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
	if (fd < 0) {
		printf("Couldn't open Homa socket: %s\n", strerror(errno));
	}
	
	std::thread receiver(&homa_client::receiver, this);
	while (!receiver_running) {
		/* Wait for the receiver to begin execution before
		 * starting the sender; otherwise the initial RPCs
		 * may appear to take a long time.
		 */
	}
	receiver.detach();
	std::thread sender(&homa_client::sender, this);
	sender.detach();
}

/**
 * homa_client::sender() - Invoked as the top-level method in a thread;
 * invokes a pseudo-random stream of RPCs continuously.
 */
void homa_client::sender()
{
	char request[1000000];
	message_header *header = reinterpret_cast<message_header *>(request);
	uint64_t next_start = 0;
	
	while (1) {
		uint64_t now;
		uint64_t id;
		int server;
		
		/* Wait until we have reached the next start time. */
		do {
			now = rdtsc();
		} while (now < next_start);
		
		server = request_servers[next_server];
		next_server++;
		if (next_server >= request_servers.size())
			next_server = 0;
		if ((requests[server] - responses[server]) >= max_requests) {
			/* This server is overloaded, so skip it (don't
			 * let one slow server stop the whole benchmark).
			 */
			continue;
		}
		
		header->start_time = now & 0xffffffff;
		header->server_id = server;
		int status = homa_send(fd, request, request_lengths[next_length],
			reinterpret_cast<struct sockaddr *>(
			&server_addrs[server]),
			sizeof(server_addrs[0]), &id);
		if (status < 0) {
			printf("Error in homa_client::sender: %s\n",
				strerror(errno));
			exit(1);
		}
		requests[server]++;
		next_length++;
		if (next_length >= request_lengths.size())
			next_length = 0;
		next_start = now + request_intervals[next_interval];
		next_interval++;
		if (next_interval >= request_intervals.size())
			next_interval = 0;
	}
}

/**
 * homa_client::receiver() - Invoked as the top-level method in a thread
 * that waits for RPC responses and then logs statistics about them.
 */
void homa_client::receiver(void)
{
	char response[1000000];
	message_header *header = reinterpret_cast<message_header *>(response);
	uint64_t id;
	struct sockaddr_in server_addr;
	
	receiver_running = 1;
	while (1) {
		id = 0;
		int length = homa_recv(fd, response, sizeof(response),
				HOMA_RECV_RESPONSE, &id,
				(struct sockaddr *) &server_addr,
				sizeof(server_addr));
		if (length < 0) {
			printf("Error in homa_recv: %s (id %lu, server %s)\n",
				strerror(errno), id,
				print_address(&server_addr));
			exit(1);
		}
		uint32_t elapsed = rdtsc() & 0xffffffff;
		elapsed -= header->start_time;
		responses[header->server_id]++;
		response_data += length;
		total_rtt += elapsed;
		actual_lengths[next_result] = length;
		actual_rtts[next_result] = elapsed;
		next_result++;
		if (next_result >= actual_lengths.size())
			next_result = 0;
	}
}

/**
 * class tcp_client - Holds information about a single TCP client,
 * which consists of one thread issuing requests and one thread receiving
 * responses. 
 */
class tcp_client : public client {
    public:
	tcp_client(void);
	void receiver(void);
	void sender(void);
	
	/** 
	 * @messages: one entry for each server in server_addrs; used to
	 * receive responses from that server.
	 */
	std::vector<tcp_message> messages;
};

/** tcp_client::tcp_client() - Constructor for tcp_client objects. */
tcp_client::tcp_client()
	: messages()
{
	for (uint32_t i = 0; i < server_addrs.size(); i++) {
		int fd = socket(PF_INET, SOCK_STREAM, 0);
		if (fd == -1) {
			printf("Couldn't open TCP socket: %s\n",
					strerror(errno));
			exit(1);
		}
		if (connect(fd, reinterpret_cast<struct sockaddr *>(
				&server_addrs[i]),
				sizeof(server_addrs[i])) == -1) {
			printf("Couldn't connect to %s:%d: %s\n",
					print_address(&server_addrs[i]),
					ntohs(server_addrs[i].sin_port),
					strerror(errno));
			exit(1);
		}
		int flag = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
		messages.emplace_back(fd, server_addrs[i]);
	}
	
	std::thread receiver(&tcp_client::receiver, this);
	while (!receiver_running) {
		/* Wait for the receiver to begin execution before
		 * starting the sender; otherwise the initial RPCs
		 * may appear to take a long time.
		 */
	}
	receiver.detach();
	std::thread sender(&tcp_client::sender, this);
	sender.detach();
}

/**
 * tcp_client::sender() - Invoked as the top-level method in a thread;
 * invokes a pseudo-random stream of RPCs continuously.
 */
void tcp_client::sender()
{
	uint64_t next_start = 0;
	message_header header;
	
	while (1) {
		uint64_t now;
		int server;
		
		/* Wait until we have reached the next start time. */
		do {
			now = rdtsc();
		} while (now < next_start);
		
		server = request_servers[next_server];
		next_server++;
		if (next_server >= request_servers.size())
			next_server = 0;
		if (requests[server] >= (responses[server] + max_requests)) {
			/* This server is overloaded, so skip it (don't
			 * let one slow server stop the whole benchmark).
			 */
			continue;
		}
		
		header.start_time = now & 0xffffffff;
		header.server_id = server;
		int status = send_message(messages[server].fd,
				request_lengths[next_length], &header);
		if (status != 0) {
			printf("Error in TCP socket write for %s: %s\n",
				print_address(&server_addrs[server]),
				strerror(errno));
			exit(1);
		}
		requests[server]++;
		next_length++;
		if (next_length >= request_lengths.size())
			next_length = 0;
		next_start = now + request_intervals[next_interval];
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
	int epoll_fd = epoll_create(10);
	if (epoll_fd < 0) {
		printf("tcp_client::receiver couldn't create epoll instance: "
				"%s\n", strerror(errno));
		exit(1);
	}
	struct epoll_event ev;
	for (uint32_t i = 0; i < messages.size(); i++) {
		ev.events = EPOLLIN;
		ev.data.u32 = i;
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, messages[i].fd,
				&ev) != 0) {
			printf("Couldn't add TCP socket %d to epoll: %s\n",
					i, strerror(errno));
			exit(1);
		}
	}
	receiver_running = 1;
	
	/* Each iteration through this loop processes a batch of incoming
	 * responses
	 */
	while (1) {
#define MAX_EVENTS 20
		struct epoll_event events[MAX_EVENTS];
		int num_events;
		
		while (1) {
			num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
			if (num_events > 0)
				break;
			if ((errno == EAGAIN) || (errno == EINTR))
				continue;
			printf("epoll_wait failed in tcp_client: %s\n",
					strerror(errno));
			exit(1);
		}
		for (int i = 0; i < num_events; i++) {
			tcp_message *message = &messages[events[i].data.u32];
			int error = message->read([this](int size,
					message_header *header) {
				uint32_t elapsed = rdtsc() & 0xffffffff;
				elapsed -= header->start_time;
				responses[header->server_id]++;
				response_data += size;
				total_rtt += elapsed;
				actual_lengths[next_result] = size;
				actual_rtts[next_result] = elapsed;
				next_result++;
				if (next_result >= actual_lengths.size())
					next_result = 0;
			});
			if (error) {
				printf("Connection with server closed.\n");
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
	for (uint32_t i = 0; i < metrics.size(); i++) {
		server_metrics *server = metrics[i];
		server_rpcs += server->requests;
		server_data += server->data;
		length = snprintf(details + offset, sizeof(details) - offset,
				"%s%lu", (offset != 0) ? " " : "",
				server->requests - last_per_server_rpcs[i]);
		offset += length;
		last_per_server_rpcs[i] = server->requests;
	}
	if ((last_stats_time != 0) && (server_data != last_server_data)) {
		double elapsed = to_seconds(now - last_stats_time);
		double rpcs = (double) (server_rpcs - last_server_rpcs);
		double data = (double) (server_data - last_server_data);
		printf("Servers: %.2f Kops/sec, %.2f MB/sec, "
				"avg. length %.1f bytes\n",
				rpcs/(1000.0*elapsed), data/(1e06*elapsed),
				data/rpcs);
		printf("RPCs per server: %s\n", details);
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
	uint64_t cdf_times[CDF_VALUES];
	int times_per_client;
	int cdf_index = 0;
	
	if (clients.size() == 0)
		return;
	
	times_per_client = CDF_VALUES/clients.size();
	if (times_per_client > NUM_CLIENT_STATS)
		times_per_client = NUM_CLIENT_STATS;
	for (client *client: clients) {
		for (int count: client->responses)
			client_rpcs += count;
		client_data += client->response_data;
		total_rtt += client->total_rtt;
		for (int i = 1; i <= times_per_client; i++) {
			/* Collect the most recent RTTs from the client for
			 * computing a CDF.
			 */
			int src = client->next_result - i;
			if (src < 0)
				src += NUM_CLIENT_STATS;
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
		printf("Clients: %.2f Kops/sec, %.2f MB/sec, RTT (us) "
				"P50 %.2f P99 %.2f P99.9 %.2f, avg. length "
				"%.1f bytes\n",
				rpcs/(1000.0*elapsed), data/(1e06*elapsed),
				to_seconds(cdf_times[cdf_index/2])*1e06,
				to_seconds(cdf_times[99*cdf_index/100])*1e06,
				to_seconds(cdf_times[999*cdf_index/1000])*1e06,
			        data/rpcs);
	}
	last_client_rpcs = client_rpcs;
	last_client_data = client_data;
	last_total_rtt = total_rtt;
}

int main(int argc, char** argv)
{
	int next_arg, i, homa_protocol;
	
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
		} else if (strcmp(argv[next_arg], "--first_port") == 0) {
			first_port = int_arg(argv[next_arg+1],
					argv[next_arg]);
			next_arg++;
		} else if (strcmp(argv[next_arg], "--first_server") == 0) {
			first_server = int_arg(argv[next_arg+1],
					argv[next_arg]);
			next_arg++;
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
		} else if (strcmp(argv[next_arg], "--workload") == 0) {
			workload = argv[next_arg+1];
			next_arg++;
		} else {
			printf("Unknown option %s; type '%s --help' for help\n",
				argv[next_arg], argv[0]);
			exit(1);
		}
	}
	if (strcmp(protocol, "homa") == 0)
		homa_protocol = 1;
	else if (strcmp(protocol, "tcp") == 0)
	        homa_protocol = 0;
	else {
		printf("Unknown protocol '%s': must be homa or tcp\n", protocol);
		exit(1);
	}
	
	/* Spawn server threads. */
	if (is_server) {
		if (homa_protocol) {
			for (i = 0; i < server_threads; i++) {
				homa_server *server = new homa_server(
						first_port + i);
				homa_servers.push_back(server);
				metrics.push_back(&server->metrics);
			}
		} else {
			for (i = 0; i < server_threads; i++) {
				tcp_server *server = new tcp_server(
						first_port + i);
				tcp_servers.push_back(server);
				metrics.push_back(&server->metrics);
			}
		}
		last_per_server_rpcs.resize(server_threads, 0);
	}
	
	/* Initialize server_addrs. */
	for (int node = 0; node < server_nodes; node++) {
		char host[100];
		struct addrinfo hints;
		struct addrinfo *matching_addresses;
		struct sockaddr_in *dest;

		snprintf(host, sizeof(host), "node-%d", node + first_server);
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;
		int status = getaddrinfo(host, NULL, &hints,
				&matching_addresses);
		if (status != 0) {
			printf("Couldn't look up address for %s: %s\n",
					host, gai_strerror(status));
			exit(1);
		}
		dest = reinterpret_cast<struct sockaddr_in *>
				(matching_addresses->ai_addr);
		for (int thread = 0; thread < server_threads; thread++) {
			dest->sin_port = htons(first_port + thread);
			server_addrs.push_back(*dest);
		}
	}
	
	/* Create clients. */
	for (i = 0; i < client_threads; i++) {
		if (homa_protocol)
			clients.push_back(new homa_client);
		else
			clients.push_back(new tcp_client);
	}
	
	/* Print a few statistics every second. */
	while (1) {
		sleep(1);
		uint64_t now = rdtsc();
		server_stats(now);
		client_stats(now);
		
		last_stats_time = now;
	}
	exit(0);
}

