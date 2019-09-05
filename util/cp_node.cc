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

#include <atomic>
#include <random>
#include <thread>
#include <vector>

#include "homa.h"
#include "test_utils.h"

/* Command-line parameter values: */
int client_threads = 1;
const char *dist_file = "foo.bar";
bool is_server = false;
int id = -1;
uint32_t max_requests = 50;
double net_util = 0.8;
const char *protocol = "homa";
int server_threads = 1;
int server_nodes = 1000;

/** @rand_gen: random number generator. */
std::mt19937 rand_gen(12345);

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
 * @server_addrs: Internet addresses for each of the server threads available
 * to receive a Homa RPC.
 */
std::vector<struct sockaddr_in> server_addrs;

/**
 * class homa_server - Holds information about a single Homa server,
 * which consists of a thread that handles requests on a given port.
 */
class homa_server {
    public:
	homa_server(int port);
	void server(void);
	
	/** @fd: file descriptor for Homa socket. */
	int fd;
	
	/** @requests: total number of requests handled so far. */
	uint64_t requests;
	
	/**
	 * @data: total number of bytes of data in requests handled
	 * so far.
	 */
	uint64_t data;
};

/** @homa_servers: keeps track of all existing Homa clients. */
std::vector<homa_server *> homa_servers;

/**
 * class homa_client - Holds information about a single Homa client,
 * which consists of one thread issuing requests and one thread receiving
 * responses. 
 */
class homa_client {
    public:
	homa_client(void);
	void receiver(void);
	void sender(void);
	
	/** @fd: file descriptor for Homa socket. */
	int fd;
	
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
	uint32_t next_interval;
	
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
	 * @next_result: index into both actual_lengths and actual_rtts
	 * where info about the next RPC completion will be stored.
	 */
	uint32_t next_result;
	
	/** @requests: total number of RPCs issued so far. */
	uint64_t requests;
	
	/** @responses: total number of responses received so far. */
	std::atomic<uint64_t> responses;
	
	/**
	 * @failures: total number of RPCs that resulted in errors
	 * in homa_recv, so they didn't complete.
	 **/
	std::atomic<uint64_t> failures;
	
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
};

/** @homa_clients: keeps track of all existing Homa clients. */
std::vector<homa_client *> homa_clients;

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
 * homa_server::homa_server() - Constructor for homa_server objects.
 * @port:  Port on which to receive requests
 */
homa_server::homa_server(int port)
	: fd(-1)
        , requests(0)
        , data(0)
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

		/* Second word of the message indicates how large a
		 * response to send.
		 */
		result = homa_reply(fd, message, length,
			(struct sockaddr *) &source, sizeof(source), id);
		if (result < 0) {
			printf("Homa_reply failed: %s\n", strerror(errno));
			exit(1);
		}
		requests++;
		data += length;
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

/** homa_client::homa_client() - Constructor for homa_client objects. */
homa_client::homa_client()
	: fd(-1)
        , request_servers()
        , next_server(0)
        , request_lengths()
        , next_length(0)
        , request_intervals()
	, next_interval(0)
        , actual_lengths(500000, 0)
        , actual_rtts(500000, 0)
        , next_result(0)
        , requests(0)
        , responses(0)
        , failures(0)
        , response_data(0)
{
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
	if (fd < 0) {
		printf("Couldn't open Homa socket: %s\n", strerror(errno));
	}
	
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
	request_servers.reserve(NUM_SERVERS);
	for (int i = 0; i < NUM_SERVERS; i++)
		request_servers.push_back(server_dist(rand_gen));
	request_lengths.push_back(100);
	request_intervals.push_back(0);
	
	std::thread sender(&homa_client::sender, this);
	sender.detach();
	std::thread receiver(&homa_client::receiver, this);
	receiver.detach();
}

/**
 * homa_client::sender() - Invoked as the top-level method in a thread;
 * invokes a pseudo-random stream of RPCs continuously.
 */
void homa_client::sender()
{
	uint32_t request[1000000/sizeof(uint32_t)];
	uint64_t next_start = 0;
	
	while (1) {
		uint64_t now;
		uint64_t id;
		
		/* Wait until (a) we have reached the next start time
		 * and (b) there aren't too many requests outstanding.
		 */
		while (1) {
			now = rdtsc();
			if (now < next_start)
				continue;
			if ((requests - responses - failures) < max_requests)
				break;
		}
		
		/* Store the low-order bits of the send timestamp in
		 * the request; it will be returned in the response and
		 * used by the receiver.
		 */
		request[0] = now & 0xffffffff;
		int status = homa_send(fd, request, request_lengths[next_length],
			reinterpret_cast<struct sockaddr *>(
			&server_addrs[request_servers[next_server]]),
			sizeof(server_addrs[0]), &id);
		if (status < 0) {
			printf("Error in homa_send: %s\n",
				strerror(errno));
			exit(1);
		}
		requests++;
		next_server++;
		if (next_server >= request_servers.size())
			next_server = 0;
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
	uint32_t response[1000000/sizeof(uint32_t)];
	uint64_t id;
	struct sockaddr_in server_addr;
	
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
			failures++;
			continue;
		}
		uint32_t elapsed = rdtsc() & 0xffffffff;
		elapsed -= response[0];
		responses++;
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
 * homa_server_stats() -  Prints recent statistics collected from Homa
 * servers.
 * @now:   Current time in rdtsc cycles (used to compute rates for
 *         statistics).
 */
void homa_server_stats(uint64_t now)
{
	char details[10000];
	int offset = 0;
	int length;
	uint64_t server_rpcs = 0;
	uint64_t server_data = 0;
	for (uint32_t i = 0; i < homa_servers.size(); i++) {
		homa_server *server = homa_servers[i];
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
		printf("Homa servers: %.2f Kops/sec, %.2f MB/sec, "
				"avg.length %.1f bytes\n",
				rpcs/(1000.0*elapsed), data/(1e06*elapsed),
				data/rpcs);
		printf("RPCs per server: %s\n", details);
	}
	last_server_rpcs = server_rpcs;
	last_server_data = server_data;
}

/**
 * homa_client_stats() -  Prints recent statistics collected from Homa
 * clients.
 * @now:   Current time in rdtsc cycles (used to compute rates for
 *         statistics).
 */
void homa_client_stats(uint64_t now)
{
	uint64_t client_rpcs = 0;
	uint64_t client_data = 0;
	uint64_t total_rtt = 0;
	for (homa_client *client: homa_clients) {
		client_rpcs += client->responses;
		client_data += client->response_data;
		total_rtt += client->total_rtt;
	}
	if ((last_stats_time != 0) && (client_data != last_client_data)) {
		double elapsed = to_seconds(now - last_stats_time);
		double rpcs = (double) (client_rpcs - last_client_rpcs);
		double data = (double) (client_data - last_client_data);
		double rtt =  to_seconds(total_rtt - last_total_rtt)
			/ rpcs;
		printf("Homa clients: %.2f Kops/sec, %.2f MB/sec, avg. RTT %.2f "
				"usec, avg.length %.1f bytes\n",
				rpcs/(1000.0*elapsed), data/(1e06*elapsed),
				rtt*1e06, data/rpcs);
	}
	last_client_rpcs = client_rpcs;
	last_client_data = client_data;
	last_total_rtt = total_rtt;
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
				homa_servers.push_back(new homa_server(4000+i));
			}
		} else {
			for (i = 0; i < server_threads; i++) {
				std::thread thread(tcp_server, 4000+i);
				thread.detach();
			}
		}
		last_per_server_rpcs.resize(server_threads, 0);
	}
	
	/* Initialize server_addrs. */
	for (int node = 1; node <= server_nodes; node++) {
		char host[100];
		struct addrinfo hints;
		struct addrinfo *matching_addresses;
		struct sockaddr_in *dest;

		snprintf(host, sizeof(host), "node-%d", node);
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
			dest->sin_port = htons(4000+thread);
			server_addrs.push_back(*dest);
		}
	}
	
	/* Create clients. */
	if (strcmp(protocol, "homa") == 0) {
		for (i = 0; i < client_threads; i++)
			homa_clients.push_back(new homa_client);
	}
	
	/* Print a few statistics every second. */
	while (1) {
		sleep(1);
		uint64_t now = rdtsc();
		homa_server_stats(now);
		homa_client_stats(now);
		
		last_stats_time = now;
	}
	exit(0);
}

