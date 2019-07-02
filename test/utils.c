/* This file various utility functions for unit testing; this file
 * is implemented entirely in C, and accesses Homa and kernel internals.
 */

#include "homa_impl.h"
#include "ccutils.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "mock.h"

/**
 * unit_client_rpc() - Create a homa_client_rpc and arrange for it to be
 * in a given state.
 * @hsk:           Socket that will receive the incoming RPC.
 * @state:         Desired state for the RPC: RPC_OUTGOING, etc.
 * @client_ip:     Client's IP address.
 * @server_ip:     Server's IP address.
 * @server_port:   Port number on the server.
 * @id:            Id for the RPC (0 means use default).
 * @req_length:    Amount of data in the request.
 * @resp_length:   Amount of data in the response.
 * 
 * Return:         The properly initialized homa_client_rpc, or NULL if
 *                 there was an error. If state is RPC_OUTGOING, then  ...
 */
struct homa_rpc *unit_client_rpc(struct homa_sock *hsk, int state,
		__be32 client_ip, __be32 server_ip, int server_port, int id,
	        int req_length, int resp_length)
{
	int bytes_received;
	struct sockaddr_in server_addr;
	
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = server_ip;
	server_addr.sin_port =  htons(server_port);
	struct homa_rpc *crpc = homa_rpc_new_client(hsk, &server_addr,
			req_length, NULL);
	if (!crpc)
		return NULL;
	if (id != 0)
		crpc->id = id;
	EXPECT_EQ(RPC_OUTGOING, crpc->state);
	if (state == RPC_OUTGOING)
		return crpc;
	crpc->msgout.next_offset = req_length;

	struct data_header h = {
		.common = {
			.sport = htons(server_port),
	                .dport = htons(hsk->client_port),
			.id = id,
			.type = DATA
		},
		.message_length = htonl(resp_length),
		.offset = 0,
		.unscheduled = htonl(10000),
		.cutoff_version = 0,
		.retransmit = 0
	};
	
	int this_size = (resp_length > HOMA_MAX_DATA_PER_PACKET)
			? HOMA_MAX_DATA_PER_PACKET : resp_length;
	homa_data_pkt(mock_skb_new(server_ip, &h.common, this_size, 0),
			crpc);
	if (crpc->state == state)
		return crpc;
	if (state == RPC_INCOMING)
		/* Can't get to RPC_INCOMING state for responses that
		 * fit in a single packet.
		 */
		goto error;
	for (bytes_received = HOMA_MAX_DATA_PER_PACKET;
			bytes_received < resp_length;
			bytes_received += HOMA_MAX_DATA_PER_PACKET) {
		this_size = resp_length - bytes_received;
		if (this_size >  HOMA_MAX_DATA_PER_PACKET)
			this_size = HOMA_MAX_DATA_PER_PACKET;
		h.offset = htonl(bytes_received);
		homa_data_pkt(mock_skb_new(server_ip, &h.common,
				this_size , 0), crpc);
	}
	EXPECT_EQ(RPC_READY, crpc->state);
	if (crpc->state == state)
		return crpc;
	
	/* The desired state doesn't exist. */
    error:
	homa_rpc_free(crpc);
	return NULL;
}

/**
 * unit_get_in_addr - Parse a string into an IPV4 host addresss
 * @s:          IPV4 host specification such as 192.168.0.1
 * 
 * Return:      The in_addr (in network order) corresponding to @s. IF
 *              s couldn't be parsed properly then 0 is returned.
 * 
 */
__be32 unit_get_in_addr(char *s)
{
	unsigned int a, b, c, d;
	if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
		return htonl((a<<24) + (b<<16) + (c<<8) + d);
	}
	return 0;
}

/**
 * unit_get_metrics() - Compile all of the metrics and return a pointer
 * to the result. Unit tests should use this method rather than just
 * checking homa_metrics[1] in order to ensure that homa_compile_metrics
 * will include the desired metric.
 * 
 * Result:      Compiled metrics from all cores.
 */
struct homa_metrics *unit_get_metrics(void)
{
	static struct homa_metrics compiled;
	
	homa_compile_metrics(&compiled);
	return &compiled;
}

/**
 * unit_list_length() - Return the number of entries in a list (not including
 * the list header.
 * @head:   Header for the list (or any entry in the list, for that matter).
 */
int unit_list_length(struct list_head *head)
{
	struct list_head *pos;
	int count = 0;
	list_for_each(pos, head) {
		count++;
	}
	return count;
}

/**
 * unit_log_grantables() - Append to the test log information about all of
 * the messages in homa->grantable_msgs.
 * @homa:     Homa's overall state.
 */
void unit_log_grantables(struct homa *homa)
{
	struct list_head *pos;
	struct homa_rpc *rpc;
	int count = 0;
	list_for_each(pos, &homa->grantable_rpcs) {
		count++;
		rpc = list_entry(pos, struct homa_rpc, grantable_links);
		unit_log_printf("; ", "%s %lu, remaining %d",
				rpc->is_client ? "response" : "request",
				(long unsigned int) rpc->id,
				rpc->msgin.bytes_remaining);
	}
	if (count != homa->num_grantable) {
		unit_log_printf("; ", "num_grantable error: should be %d, is %d",
			count, homa->num_grantable);
	}
}

/**
 * unit_log_message_out_packets() - Append to the test log a human-readable
 * description of the packets associated with a homa_message_out.
 * @message:     Message containing the packets.
 * @verbose:     If non-zero, use homa_print_packet for each packet;
 *               otherwise use homa_print_packet_short.
 * 
 * This function also checks to be sure that homa->num_grantable matches
 * the actual number of entries in the list, and generates additional
 * log output if it doesn't. 
 */
void unit_log_message_out_packets(struct homa_message_out *message, int verbose)
{
	struct sk_buff *skb;
	char buffer[200];
	
	for (skb = message->packets; skb != NULL; skb = *homa_next_skb(skb)) {
		if (verbose) {
			homa_print_packet(skb, buffer, sizeof(buffer));
		} else {
			homa_print_packet_short(skb, buffer, sizeof(buffer));
		}
		unit_log_printf("; ", "%s", buffer);
	}
}

/**
 * unit_log_skb_list() - Append to the test log a human-readable description
 * of a list of packet buffers.
 * @packets:     Header for list of sk_buffs to print.
 * @verbose:     If non-zero, use homa_print_packet for each packet;
 *               otherwise use homa_print_packet_short.
 */
void unit_log_skb_list(struct sk_buff_head *packets, int verbose)
{
	struct sk_buff *skb;
	char buffer[200];
	
	skb_queue_walk(packets, skb) {
		if (verbose) {
			homa_print_packet(skb, buffer, sizeof(buffer));
		} else {
			homa_print_packet_short(skb, buffer, sizeof(buffer));
		}
		unit_log_printf("; ", "%s", buffer);
	}
}

/**
 * unit_log_throttled() - Append to the test log information about all of
 * the messages in homa->throttle_rpcs.
 * @homa:     Homa's overall state.
 */
void unit_log_throttled(struct homa *homa)
{
	struct homa_rpc *rpc;
	list_for_each_entry_rcu(rpc, &homa->throttled_rpcs, throttled_links) {
		unit_log_printf("; ", "%s %lu, next_offset %d",
				rpc->is_client ? "request" : "response",
				(long unsigned int) rpc->id,
				rpc->msgout.next_offset);
	}
}

/**
 * unit_server_rpc() - Create a homa_server_rpc and arrange for it to be
 * in a given state.
 * @hsk:           Socket that will receive the incoming RPC.
 * @state:         Desired state for the RPC: RPC_INCOMING, etc.
 * @client_ip:     Client's IP address.
 * @server_ip:     Server's IP address.
 * @client_port:   Port number that the client used.
 * @id:            Id for the RPC.
 * @req_length:    Amount of data in the request.
 * @resp_length:   Amount of data in the response.
 * 
 * Return:         The properly initialized homa_server_rpc, or NULL if
 *                 there was an error. If state is RPC_INCOMING, then
 *                 one packet of data will have been received for the RPC;
 *                 otherwise the entire RPC will have been received. If
 *                 state is RPC_OUTGOING, no data will have been sent yet.
 */
struct homa_rpc *unit_server_rpc(struct homa_sock *hsk, int state,
		__be32 client_ip, __be32 server_ip, int client_port, int id,
	        int req_length, int resp_length)
{
	int bytes_received;
	struct data_header h = {
		.common = {
			.sport = htons(client_port),
	                .dport = htons(hsk->server_port),
			.id = id,
			.type = DATA
		},
		.message_length = htonl(req_length),
		.offset = 0,
		.unscheduled = htonl(10000),
		.cutoff_version = 0,
		.retransmit = 0
	};
	struct homa_rpc *srpc = homa_rpc_new_server(hsk, client_ip, &h);
	if (!srpc)
		return NULL;
	homa_data_pkt(mock_skb_new(client_ip, &h.common,
			(req_length > HOMA_MAX_DATA_PER_PACKET)
			? HOMA_MAX_DATA_PER_PACKET : req_length , 0),
			srpc);
	if (srpc->state == state)
		return srpc;
	if (state == RPC_INCOMING)
		/* Can't get to RPC_INCOMING state for messages that require
		 * only a single packet.
		 */
		goto error;
	for (bytes_received = HOMA_MAX_DATA_PER_PACKET;
			bytes_received < req_length;
			bytes_received += HOMA_MAX_DATA_PER_PACKET) {
		int this_size = req_length - bytes_received;
		if (this_size >  HOMA_MAX_DATA_PER_PACKET)
			this_size = HOMA_MAX_DATA_PER_PACKET;
		h.offset = htonl(bytes_received);
		homa_data_pkt(mock_skb_new(client_ip, &h.common,
				this_size , 0), srpc);
	}
	EXPECT_EQ(RPC_READY, srpc->state);
	if (srpc->state == state)
		return srpc;
	list_del_init(&srpc->ready_links);
	srpc->state = RPC_IN_SERVICE;
	if (srpc->state == state)
		return srpc;
	int err = homa_message_out_init(srpc, hsk->server_port, resp_length,
			NULL);
	EXPECT_EQ(0, err);
	srpc->state = RPC_OUTGOING;
	if (srpc->state == state)
		return srpc;
	
	/* The desired state doesn't exist. */
    error:
	homa_rpc_free(srpc);
	return NULL;
}

/**
 * unit_teardown() - This function should be invoked at the end of every test.
 * It performs various cleanup operations, and it also performs a set of
 * consistency checks, such as checking for memory leaks or lost sk_buffs.
 */
void unit_teardown(void)
{
	mock_teardown();
	unit_log_clear();
}