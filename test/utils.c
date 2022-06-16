/* Copyright (c) 2019-2021 Stanford University
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

/* This file various utility functions for unit testing; this file
 * is implemented entirely in C, and accesses Homa and kernel internals.
 */

#include "homa_impl.h"
#include "ccutils.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "mock.h"
#include "utils.h"

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
 *                 there was an error. If @state is RPC_OUTGOING, no data
 *                 will have been sent yet.  If @state is RPC_INCOMING, then
 *                 one packet of data will have been received for the RPC;
 *                 if @state is RPC_READY the entire RPC will have been
 *                 received. The RPC is not locked.
 */
struct homa_rpc *unit_client_rpc(struct homa_sock *hsk, int state,
		__be32 client_ip, __be32 server_ip, int server_port, int id,
	        int req_length, int resp_length)
{
	int bytes_received;
	struct sockaddr_in server_addr;
	int saved_id = atomic64_read(&hsk->homa->next_outgoing_id);
	
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = server_ip;
	server_addr.sin_port =  htons(server_port);
	if (id != 0)
		atomic64_set(&hsk->homa->next_outgoing_id, id);
	struct homa_rpc *crpc = homa_rpc_new_client(hsk, &server_addr,
			unit_iov_iter(NULL, req_length));
	homa_rpc_unlock(crpc);
	if (!crpc)
		return NULL;
	if (id != 0)
		atomic64_set(&hsk->homa->next_outgoing_id, saved_id);
	EXPECT_EQ(RPC_OUTGOING, crpc->state);
	if (state == RPC_OUTGOING)
		return crpc;
	crpc->msgout.next_packet = NULL;

	struct data_header h = {
		.common = {
			.sport = htons(server_port),
	                .dport = htons(hsk->port),
			.type = DATA,
			.sender_id = cpu_to_be64(id ^ 1)
		},
		.message_length = htonl(resp_length),
		.incoming = htonl(10000),
		.cutoff_version = 0,
		.retransmit = 0,
		.seg = {.offset = 0,
			.segment_length = htonl(UNIT_TEST_DATA_PER_PACKET),
		        .ack = {0, 0, 0}}
	};
	
	int this_size = (resp_length > UNIT_TEST_DATA_PER_PACKET)
			? UNIT_TEST_DATA_PER_PACKET : resp_length;
	h.seg.segment_length = htonl(this_size);
	homa_data_pkt(mock_skb_new(server_ip, &h.common, this_size, 0),
			crpc);
	if (crpc->state == state)
		return crpc;
	if (state == RPC_INCOMING)
		/* Can't get to RPC_INCOMING state for responses that
		 * fit in a single packet.
		 */
		goto error;
	for (bytes_received = UNIT_TEST_DATA_PER_PACKET;
			bytes_received < resp_length;
			bytes_received += UNIT_TEST_DATA_PER_PACKET) {
		this_size = resp_length - bytes_received;
		if (this_size >  UNIT_TEST_DATA_PER_PACKET)
			this_size = UNIT_TEST_DATA_PER_PACKET;
		h.seg.offset = htonl(bytes_received);
		h.seg.segment_length = htonl(this_size);
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
 * unit_log_active_ids() - Appended to the test log a list of the active
 * RPC ids for a given socket, in order.
 * @hsk:   Socket whose active RPC ids should be logged.
 */
void unit_log_active_ids(struct homa_sock *hsk)
{
	struct homa_rpc *rpc;
	list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links)
		unit_log_printf(" ", "%llu", rpc->id);
}

/**
 * unit_log_frag_list() - Append to the test log a human-readable description
 * of all of the packets on a given skb's frag_list.
 * @skb:         Packet whose frag_list is of interest.
 * @verbose:     If non-zero, use homa_print_packet for each packet;
 *               otherwise use homa_print_packet_short.
 */
void unit_log_frag_list(struct sk_buff *skb, int verbose)
{
	struct sk_buff *frag;
	char buffer[200];
	
	for (frag = skb_shinfo(skb)->frag_list; frag != NULL;
			frag = frag->next) {
		if (verbose) {
			homa_print_packet(frag, buffer, sizeof(buffer));
		} else {
			homa_print_packet_short(frag, buffer, sizeof(buffer));
		}
		unit_log_printf("; ", "%s", buffer);
	}
}

/**
 * unit_log_grantables() - Append to the test log information about all of
 * the messages in homa->grantable_msgs.
 * @homa:     Homa's overall state.
 */
void unit_log_grantables(struct homa *homa)
{
	struct homa_peer *peer;
	struct homa_rpc *rpc;
	int count = 0;
	list_for_each_entry(peer, &homa->grantable_peers, grantable_links) {
		count++;
		list_for_each_entry(rpc, &peer->grantable_rpcs,
				grantable_links) {
			unit_log_printf("; ", "%s from %s, id %lu, "
					"remaining %d",
					homa_is_client(rpc->id) ? "response"
					: "request",
					homa_print_ipv4_addr(peer->addr),
					(long unsigned int) rpc->id,
					rpc->msgin.bytes_remaining);
		}
	}
	if (count != homa->num_grantable_peers) {
		unit_log_printf("; ", "num_grantable_peers error: should "
				"be %d, is %d",
				count, homa->num_grantable_peers);
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
 * unit_log_filled_skbs() - Append to the test log a human-readable description
 * of a list of packet buffers created by homa_fill_packets.
 * @skb:         First in list of sk_buffs to print; the list is linked
 *               using homa_next_skb.
 * @verbose:     If non-zero, use homa_print_packet for each packet;
 *               otherwise use homa_print_packet_short.
 */
void unit_log_filled_skbs(struct sk_buff *skb, int verbose)
{
	char buffer[400];
	
	while (skb != NULL) {
		if (verbose) {
			homa_print_packet(skb, buffer, sizeof(buffer));
		} else {
			homa_print_packet_short(skb, buffer, sizeof(buffer));
		}
		unit_log_printf("; ", "%s", buffer);
		skb = *homa_next_skb(skb);
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
	int offset;
	list_for_each_entry_rcu(rpc, &homa->throttled_rpcs, throttled_links) {
		if (rpc->msgout.next_packet)
			offset = homa_data_offset(rpc->msgout.next_packet);
		else
			offset = rpc->msgout.length;
		unit_log_printf("; ", "%s %lu, next_offset %d",
				homa_is_client(rpc->id) ? "request"
				: "response",
				(long unsigned int) rpc->id, offset);
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
 *                 The RPC is not locked.
 */
struct homa_rpc *unit_server_rpc(struct homa_sock *hsk, int state,
		__be32 client_ip, __be32 server_ip, int client_port, int id,
	        int req_length, int resp_length)
{
	int bytes_received;
	struct data_header h = {
		.common = {
			.sport = htons(client_port),
	                .dport = htons(hsk->port),
			.type = DATA,
			.sender_id = cpu_to_be64(id ^ 1)
		},
		.message_length = htonl(req_length),
		.incoming = htonl(10000),
		.cutoff_version = 0,
		.retransmit = 0,
		.seg = {.offset = 0,
			.segment_length = htonl(UNIT_TEST_DATA_PER_PACKET),
		        .ack = {0, 0, 0}}
	};
	if (req_length < UNIT_TEST_DATA_PER_PACKET)
		h.seg.segment_length = htonl(req_length);
	struct homa_rpc *srpc = homa_rpc_new_server(hsk, client_ip, &h);
	homa_rpc_unlock(srpc);
	if (!srpc)
		return NULL;
	homa_data_pkt(mock_skb_new(client_ip, &h.common,
			(req_length > UNIT_TEST_DATA_PER_PACKET)
			? UNIT_TEST_DATA_PER_PACKET : req_length , 0),
			srpc);
	if (srpc->state == state)
		return srpc;
	if (state == RPC_INCOMING)
		/* Can't get to RPC_INCOMING state for messages that require
		 * only a single packet.
		 */
		goto error;
	for (bytes_received = UNIT_TEST_DATA_PER_PACKET;
			bytes_received < req_length;
			bytes_received += UNIT_TEST_DATA_PER_PACKET) {
		int this_size = req_length - bytes_received;
		if (this_size >  UNIT_TEST_DATA_PER_PACKET)
			this_size = UNIT_TEST_DATA_PER_PACKET;
		h.seg.offset = htonl(bytes_received);
		h.seg.segment_length = htonl(this_size);
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
	homa_message_out_init(srpc, hsk->port, homa_fill_packets(hsk,
			srpc->peer, unit_iov_iter((void *) 2000, resp_length)),
			resp_length);
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

/**
 * Return an iov_iter corresponding to the arguments.
 * @buffer:     First byte of data.
 * @length:     Number of bytes of data.
 * @direction:  WRITE means data will be copied out of the init, READ means
 *              data will be copied into it.
 */
struct iov_iter *unit_iov_iter(void *buffer, size_t length)
{
    
	static struct iovec iovec;
	static struct iov_iter iter;
	iovec.iov_base = buffer;
	iovec.iov_len = length;
	iov_iter_init(&iter, WRITE, &iovec, 1, length);
	return &iter;
}

/**
 * Returns a human-readable description of the fields in an ack.
 * @ack:  The ack to stringify. 
 */
char *unit_ack_string(struct homa_ack *ack)
{
	static char buffer[1000];
	snprintf(buffer, sizeof(buffer),
			"client_port %d, server_port %d, client_id %llu",
			ntohs(ack->client_port), ntohs(ack->server_port),
			be64_to_cpu(ack->client_id));
	return buffer;
}