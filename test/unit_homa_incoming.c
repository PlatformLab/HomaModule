/* Copyright (c) 2019-2021, Stanford University
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

#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

/* The following variable (and function) are used via mock_schedule_hook
 * to mark an RPC ready (but only if thread is sleeping).
 */
struct homa_rpc *hook_rpc = NULL;
struct homa_sock *hook_hsk = NULL;
int delete_count = 0;
void ready_hook(void)
{
	if (current->state == TASK_RUNNING)
		return;
	homa_rpc_ready(hook_rpc);
	unit_log_printf("; ",
			"%d in ready_requests, %d in ready_responses, "
			"%d in request_interests, %d in response_interests",
			unit_list_length(&hook_rpc->hsk->ready_requests),
			unit_list_length(&hook_rpc->hsk->ready_responses),
			unit_list_length(&hook_rpc->hsk->request_interests),
			unit_list_length(&hook_rpc->hsk->response_interests));
}

/* The following function is used by mock_schedule_hook to mark an
 * RPC ready even if a thread is polling.
 */
int poll_count = 0;
void poll_hook(void)
{
	if (poll_count <= 0)
		return;
	poll_count--;
	if (poll_count == 0)
		homa_rpc_ready(hook_rpc);
}

/* Used when testing the mechanism to abort polls because not at front
 * of waiting list.
 */
struct homa_interest *hook_interest;
struct list_head *hook_list_request;
struct list_head *hook_list_response;
int cycle_increment = 0;
struct homa_sock *shutdown_hsk;
void poll_hook2(void) {
	mock_cycles += cycle_increment;
	if (poll_count <= 0)
		return;
	poll_count--;
	if (poll_count == 0) {
		if (hook_list_request)
			list_add(&hook_interest->request_links,
					hook_list_request);
		if (hook_list_response)
			list_add(&hook_interest->response_links,
					hook_list_response);
		shutdown_hsk->shutdown = 1;
	}
	
}

int poll_hook3_count = 0;
void poll_hook3(void) {
	if (poll_hook3_count == 0) {
		/* First call (while polling): just increment clock enough
		 * to abort the polling loop.
		 */
		mock_cycles += 1000;
	} else if (poll_hook3_count == 1) {
		/* Second call (thread "sleeps"): do nothing. */
	} else if (poll_hook3_count == 2) {
		/* Third call (thread has looped back around and is
		 * polling again):mark RPC ready.
		 */
		homa_rpc_ready(hook_rpc);
	}
	poll_hook3_count++;
}

/* The following function is used via mock_schedule_hook to delete an RPC. */
void delete_hook(void)
{
	if (delete_count == 0) {
		void (*saved)(void) = mock_spin_lock_hook;
		mock_spin_lock_hook = NULL;
		homa_rpc_free(hook_rpc);
		mock_spin_lock_hook = saved;
	}
	delete_count--;
}

/* The following function is used via mock_schedule_hook to shutdown a socket. */
void shutdown_hook(void)
{
	homa_sock_shutdown(hook_hsk);
}

FIXTURE(homa_incoming) {
	__be32 client_ip;
	int client_port;
	__be32 server_ip;
	int server_port;
	__u64 client_id;
	__u64 server_id;
	struct sockaddr_in server_addr;
	struct sockaddr_in addr;
	struct homa homa;
	struct homa_sock hsk;
	struct data_header data;
	struct homa_interest interest;
};
FIXTURE_SETUP(homa_incoming)
{
	self->client_ip = unit_get_in_addr("196.168.0.1");
	self->client_port = 40000;
	self->server_ip = unit_get_in_addr("1.2.3.4");
	self->server_port = 99;
	self->client_id = 1234;
	self->server_id = 1235;
	self->server_addr.sin_family = AF_INET;
	self->server_addr.sin_addr.s_addr = self->server_ip;
	self->server_addr.sin_port =  htons(self->server_port);
	self->addr.sin_family = AF_INET;
	self->addr.sin_addr.s_addr = 0;
	self->addr.sin_port =  0;
	homa_init(&self->homa);
	self->homa.num_priorities = 1;
	self->homa.poll_cycles = 0;
	self->homa.flags |= HOMA_FLAG_DONT_THROTTLE;
	self->homa.pacer_fifo_fraction = 0;
	self->homa.grant_fifo_fraction = 0;
	self->homa.grant_threshold = self->homa.rtt_bytes;
	mock_sock_init(&self->hsk, &self->homa, 0);
	self->data = (struct data_header){.common = {
			.sport = htons(self->client_port),
	                .dport = htons(self->server_port),
			.type = DATA,
			.sender_id = cpu_to_be64(self->client_id),
			.generation = htons(1)},
			.message_length = htonl(10000),
			.incoming = htonl(10000), .cutoff_version = 0,
		        .retransmit = 0,
			.seg = {.offset = 0, .segment_length = htonl(1400)}};
	unit_log_clear();
	delete_count = 0;
}
FIXTURE_TEARDOWN(homa_incoming)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_incoming, homa_message_in_init)
{
	struct homa_message_in msgin;
	homa_message_in_init(&msgin, 127, 10000);
	EXPECT_EQ(127, msgin.incoming);
	homa_message_in_init(&msgin, 128, 10000);
	homa_message_in_init(&msgin, 130, 10000);
	homa_message_in_init(&msgin, 0xfff, 10000);
	homa_message_in_init(&msgin, 0x3000, 10000);
	homa_message_in_init(&msgin, 1000000, 10000);
	EXPECT_EQ(10000, msgin.incoming);
	homa_message_in_init(&msgin, 2000000, 10000);
	EXPECT_EQ(255, homa_cores[cpu_number]->metrics.small_msg_bytes[1]);
	EXPECT_EQ(130, homa_cores[cpu_number]->metrics.small_msg_bytes[2]);
	EXPECT_EQ(0xfff, homa_cores[cpu_number]->metrics.small_msg_bytes[63]);
	EXPECT_EQ(0x3000, homa_cores[cpu_number]->metrics.medium_msg_bytes[11]);
	EXPECT_EQ(0, homa_cores[cpu_number]->metrics.medium_msg_bytes[15]);
	EXPECT_EQ(3000000, homa_cores[cpu_number]->metrics.large_msg_bytes);
}

TEST_F(homa_incoming, homa_add_packet__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);
	homa_message_in_init(&crpc->msgin, 10000, 10000);
	unit_log_clear();
	self->data.seg.offset = htonl(1400);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	
	self->data.seg.offset = htonl(4200);
	self->data.seg.segment_length = htonl(800);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 800, 4200));
	
	self->data.seg.offset = 0;
	self->data.seg.segment_length = htonl(1400);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));
	unit_log_skb_list(&crpc->msgin.packets, 0);
	EXPECT_STREQ("DATA 1400@0; DATA 1400@1400; DATA 800@4200",
			unit_log_get());
	EXPECT_EQ(6400, crpc->msgin.bytes_remaining);
	
	unit_log_clear();
	self->data.seg.offset = htonl(2800);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 2800));
	unit_log_skb_list(&crpc->msgin.packets, 0);
	EXPECT_STREQ("DATA 1400@0; DATA 1400@1400; DATA 1400@2800; "
			"DATA 800@4200", unit_log_get());
}
TEST_F(homa_incoming, homa_add_packet__varying_sizes)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);
	homa_message_in_init(&crpc->msgin, 10000, 10000);
	unit_log_clear();
	self->data.seg.offset = 0;
	self->data.seg.segment_length = htonl(4000);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 4000, 0));
	
	self->data.seg.offset = htonl(4000);
	self->data.seg.segment_length = htonl(6000);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 6000, 4000));
	unit_log_skb_list(&crpc->msgin.packets, 0);
	EXPECT_STREQ("DATA 4000@0; DATA 6000@4000",
			unit_log_get());
	EXPECT_EQ(0, crpc->msgin.bytes_remaining);
}
TEST_F(homa_incoming, homa_add_packet__redundant_packet)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);
	homa_message_in_init(&crpc->msgin, 10000, 10000);
	unit_log_clear();
	self->data.seg.offset = htonl(1400);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	EXPECT_EQ(1, crpc->msgin.num_skbs);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	unit_log_skb_list(&crpc->msgin.packets, 0);
	EXPECT_STREQ("DATA 1400@1400", unit_log_get());
	EXPECT_EQ(1, crpc->msgin.num_skbs);
}
TEST_F(homa_incoming, homa_add_packet__overlapping_ranges)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);
	homa_message_in_init(&crpc->msgin, 10000, 10000);
	unit_log_clear();
	self->data.seg.offset = htonl(1400);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	self->data.seg.offset = htonl(2000);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 2000));
	unit_log_skb_list(&crpc->msgin.packets, 0);
	EXPECT_STREQ("DATA 1400@1400; DATA 1400@2000", unit_log_get());
	EXPECT_EQ(2, crpc->msgin.num_skbs);
	EXPECT_EQ(8000, crpc->msgin.bytes_remaining);
	
	unit_log_clear();
	self->data.seg.offset = htonl(1800);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1800));
	unit_log_skb_list(&crpc->msgin.packets, 0);
	EXPECT_STREQ("DATA 1400@1400; DATA 1400@2000", unit_log_get());
	EXPECT_EQ(2, crpc->msgin.num_skbs);
	EXPECT_EQ(8000, crpc->msgin.bytes_remaining);
}

TEST_F(homa_incoming, homa_message_in_copy_data__basics)
{
	int count;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 4000);
	EXPECT_NE(NULL, crpc);
	self->data.message_length = htonl(4000);
	self->data.seg.offset = htonl(1000);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 101000), crpc);
	self->data.seg.offset = htonl(1800);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 201800), crpc);
	self->data.seg.offset = htonl(3200);
	self->data.seg.segment_length = htonl(800);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			800, 303200), crpc);
	unit_log_clear();
	count = homa_message_in_copy_data(&crpc->msgin,
			unit_iov_iter((void *) 10000, 5000), 5000);
	EXPECT_STREQ("skb_copy_datagram_iter: 1400 bytes to 10000: 0-1399; "
		"skb_copy_datagram_iter: 1000 bytes to 11400: 101400-102399; "
		"skb_copy_datagram_iter: 800 bytes to 12400: 202400-203199; "
		"skb_copy_datagram_iter: 800 bytes to 13200: 303200-303999", 
		unit_log_get());
	EXPECT_EQ(4000, count);
}

TEST_F(homa_incoming, homa_message_in_copy_data__multiple_calls)
{
	int count;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 4000);
	EXPECT_NE(NULL, crpc);
	self->data.message_length = htonl(2400);
	self->data.seg.offset = htonl(1400);
	self->data.seg.segment_length = htonl(1000);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 100000), crpc);
	unit_log_clear();
	count = homa_message_in_copy_data(&crpc->msgin,
			unit_iov_iter((void *) 10000, 5000), 600);
	EXPECT_EQ(600, count);
	EXPECT_STREQ("skb_copy_datagram_iter: 600 bytes to 10000: 0-599",
			unit_log_get());
	
	unit_log_clear();
	count = homa_message_in_copy_data(&crpc->msgin,
			unit_iov_iter((void *) 10000, 5000), 1000);
	EXPECT_EQ(1000, count);
	EXPECT_STREQ("skb_copy_datagram_iter: 800 bytes to 10000: 600-1399; "
		"skb_copy_datagram_iter: 200 bytes to 10800: 100000-100199",
		unit_log_get());
	
	unit_log_clear();
	count = homa_message_in_copy_data(&crpc->msgin,
			unit_iov_iter((void *) 10000, 5000), 1000);
	EXPECT_EQ(800, count);
	EXPECT_STREQ("skb_copy_datagram_iter: 800 bytes to 10000: 100200-100999",
			unit_log_get());
}

TEST_F(homa_incoming, homa_get_resend_range__uninitialized_rpc)
{
	struct homa_message_in msgin;
	struct resend_header resend;
	
	msgin.total_length = -1;
	homa_get_resend_range(&msgin, &resend);
	EXPECT_EQ(0, resend.offset);
	EXPECT_EQ(100, ntohl(resend.length));
}
TEST_F(homa_incoming, homa_get_resend_range__empty_range)
{
	struct resend_header resend;
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 5000, 5000);
	
	homa_get_resend_range(&srpc->msgin, &resend);
	EXPECT_EQ(0, resend.offset);
	EXPECT_EQ(0, ntohl(resend.length));
}
TEST_F(homa_incoming, homa_get_resend_range__various_gaps)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);
	homa_message_in_init(&crpc->msgin, 10000, 10000);
	struct resend_header resend;
	
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	homa_get_resend_range(&crpc->msgin, &resend);
	EXPECT_EQ(1400, ntohl(resend.offset));
	EXPECT_EQ(8600, ntohl(resend.length));
	
	self->data.seg.offset = htonl(8600);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 8600));
	homa_get_resend_range(&crpc->msgin, &resend);
	EXPECT_EQ(1400, ntohl(resend.offset));
	EXPECT_EQ(7200, ntohl(resend.length));
	
	self->data.seg.offset = htonl(6000);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 6000));
	homa_get_resend_range(&crpc->msgin, &resend);
	EXPECT_EQ(1400, ntohl(resend.offset));
	EXPECT_EQ(4600, ntohl(resend.length));
	
	self->data.seg.offset = htonl(4600);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 4600));
	homa_get_resend_range(&crpc->msgin, &resend);
	EXPECT_EQ(1400, ntohl(resend.offset));
	EXPECT_EQ(3200, ntohl(resend.length));
}
TEST_F(homa_incoming, homa_get_resend_range__received_past_granted)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);
	homa_message_in_init(&crpc->msgin, 10000, 10000);
	struct resend_header resend;
	
	self->data.message_length = htonl(2500);
	self->data.seg.offset = htonl(0);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));
	self->data.seg.offset = htonl(1500);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));
	self->data.seg.offset = htonl(2900);
	self->data.seg.segment_length = htonl(1100);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1100, 0));
	crpc->msgin.incoming = 2000;
	homa_get_resend_range(&crpc->msgin, &resend);
	EXPECT_EQ(1400, ntohl(resend.offset));
	EXPECT_EQ(100, ntohl(resend.length));
}
TEST_F(homa_incoming, homa_get_resend_range__gap_at_beginning)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);
	homa_message_in_init(&crpc->msgin, 10000, 10000);
	struct resend_header resend;
	
	self->data.seg.offset = htonl(6200);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 6200));
	homa_get_resend_range(&crpc->msgin, &resend);
	EXPECT_EQ(0, ntohl(resend.offset));
	EXPECT_EQ(6200, ntohl(resend.length));
}

TEST_F(homa_incoming, homa_pkt_dispatch__new_server_rpc)
{
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), &self->hsk);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(1, mock_skb_count());
}
TEST_F(homa_incoming, homa_pkt_dispatch__existing_server_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 10000, 100);
	EXPECT_NE(NULL, srpc);
	EXPECT_EQ(8600, srpc->msgin.bytes_remaining);
	self->data.seg.offset = htonl(1400);
	self->data.common.sender_id = cpu_to_be64(self->client_id);
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0),&self->hsk);
	EXPECT_EQ(7200, srpc->msgin.bytes_remaining);
}
TEST_F(homa_incoming, homa_pkt_dispatch__cant_create_rpc)
{
	mock_kmalloc_errors = 1;
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), &self->hsk);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(0, mock_skb_count());
}
TEST_F(homa_incoming, homa_pkt_dispatch__non_data_packet_for_existing_server_rpc)
{
	struct resend_header resend = {.common = {
		.sport = htons(self->client_port),
		.dport = htons(self->server_port),
		.type = RESEND,
		.sender_id = cpu_to_be64(self->client_id),
	        .generation = htons(1)},
		.offset = 0,
		.length = 1000,
		.priority = 3};
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 10000, 100);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &resend.common, 0, 0),
			&self->hsk);
	EXPECT_STREQ("xmit BUSY", unit_log_get());
}
TEST_F(homa_incoming, homa_pkt_dispatch__unknown_client_rpc)
{
	struct resend_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(99991),
			.generation = htons(1),
			.type = RESEND},
		        .offset = htonl(11200),
			.length = htonl(1000),
			.priority = 3};
	mock_xmit_log_verbose = 1;
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.unknown_rpcs);
	EXPECT_STREQ("xmit UNKNOWN from 0.0.0.0:40000, dport 99, id 99990",
			unit_log_get());
}
TEST_F(homa_incoming, homa_pkt_dispatch__unknown_server_rpc)
{
	struct resend_header h = {{.sport = htons(self->client_port),
	                .dport = htons(self->server_port),
			.sender_id = cpu_to_be64(99990),
			.generation = htons(1),
			.type = RESEND},
		        .offset = htonl(11200),
			.length = htonl(1000),
			.priority = 3};
	mock_xmit_log_verbose = 1;
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.unknown_rpcs);
	EXPECT_STREQ("xmit UNKNOWN from 0.0.0.0:99, dport 40000, id 99991",
			unit_log_get());
}
TEST_F(homa_incoming, homa_pkt_dispatch__dont_send_unknowns_except_for_resends)
{
	struct grant_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(99991),
			.generation = htons(1),
			.type = GRANT},
		        .offset = htonl(11200),
			.priority = 3};
	mock_xmit_log_verbose = 1;
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.unknown_rpcs);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.unknown_rpcs);
}
TEST_F(homa_incoming, homa_pkt_dispatch__existing_client_rpc)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(10000, crpc->msgout.granted);
	unit_log_clear();
	
	struct grant_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(self->server_id),
			.generation = htons(1),
			.type = GRANT},
			.offset = htonl(11200),
			.priority = 3};
	homa_pkt_dispatch(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_EQ(11200, crpc->msgout.granted);
}
TEST_F(homa_incoming, homa_pkt_dispatch__cutoffs_for_unknown_client_rpc)
{
	struct homa_peer *peer;
	struct cutoffs_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(99991),
			.generation = htons(1),
			.type = CUTOFFS},
		        .unsched_cutoffs = {htonl(10), htonl(9), htonl(8),
			htonl(7), htonl(6), htonl(5), htonl(4),
			htonl(3)},
			.cutoff_version = 400};
	homa_pkt_dispatch(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->hsk);
	peer = homa_peer_find(&self->homa.peers, self->server_ip,
			&self->hsk.inet);
	ASSERT_FALSE(IS_ERR(peer));
	EXPECT_EQ(400, peer->cutoff_version);
	EXPECT_EQ(9, peer->unsched_cutoffs[1]);
	EXPECT_EQ(3, peer->unsched_cutoffs[7]);
}
TEST_F(homa_incoming, homa_pkt_dispatch__resend_for_unknown_server_rpc)
{
	struct resend_header h = {{.sport = htons(self->client_port),
	                .dport = htons(self->server_port),
			.sender_id = cpu_to_be64(99990),
			.generation = htons(1),
			.type = RESEND},
			.offset = 0, .length = 2000, .priority = 5};
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_STREQ("xmit UNKNOWN", unit_log_get());
}
TEST_F(homa_incoming, homa_pkt_dispatch__future_generation_for_client_rpc)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(10000, crpc->msgout.granted);
	unit_log_clear();
	
	struct grant_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(self->server_id),
			.generation = htons(2),
			.type = GRANT},
			.offset = htonl(11200), .priority = 3};
	homa_pkt_dispatch(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_EQ(10000, crpc->msgout.granted);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.stale_generations);
}
TEST_F(homa_incoming, homa_pkt_dispatch__past_generation_for_client_rpc)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(10000, crpc->msgout.granted);
	unit_log_clear();
	crpc->generation = 3;
	
	struct grant_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(self->server_id),
			.generation = htons(2),
			.type = GRANT}, .offset = htonl(11200),
			.priority = 3};
	homa_pkt_dispatch(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_EQ(10000, crpc->msgout.granted);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.stale_generations);
}
TEST_F(homa_incoming, homa_pkt_dispatch__future_generation_for_server_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 10000, 100);
	EXPECT_NE(NULL, srpc);
	EXPECT_EQ(8600, srpc->msgin.bytes_remaining);
	self->data.seg.offset = htonl(1400);
	self->data.common.generation = htons(4);
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0),&self->hsk);
	EXPECT_EQ(7200, srpc->msgin.bytes_remaining);
	EXPECT_EQ(4, srpc->generation);
	EXPECT_EQ(0, homa_cores[cpu_number]->metrics.stale_generations);
}
TEST_F(homa_incoming, homa_pkt_dispatch__reset_counters)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(10000, crpc->msgout.granted);
	unit_log_clear();
	crpc->silent_ticks = 5;
	crpc->peer->outstanding_resends = 2;
	
	struct grant_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(self->server_id),
			.generation = htons(1),
			.type = GRANT},
			.offset = htonl(11200), .priority = 3};
	homa_pkt_dispatch(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_EQ(0, crpc->silent_ticks);
	EXPECT_EQ(0, crpc->peer->outstanding_resends);
}
TEST_F(homa_incoming, homa_pkt_dispatch__forced_reap)
{
	struct homa_rpc *dead = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 20000);
	homa_rpc_free(dead);
	EXPECT_EQ(30, self->hsk.dead_skbs);
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 10000, 5000);
	EXPECT_NE(NULL, srpc);
	self->homa.dead_buffs_limit = 16;
	mock_cycles = ~0;
	
	/* First packet: below the threshold for reaps. */
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), &self->hsk);
	EXPECT_EQ(30, self->hsk.dead_skbs);
	EXPECT_EQ(0, homa_cores[cpu_number]->metrics.data_pkt_reap_cycles);
	
	/* Second packet: must reap. */
	self->homa.dead_buffs_limit = 15;
	self->homa.reap_limit = 10;
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), &self->hsk);
	EXPECT_EQ(20, self->hsk.dead_skbs);
	EXPECT_NE(0, homa_cores[cpu_number]->metrics.data_pkt_reap_cycles);
}
TEST_F(homa_incoming, homa_pkt_dispatch__unknown_type)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(10000, crpc->msgout.granted);
	unit_log_clear();
	
	struct common_header h = {.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(self->server_id),
			.generation = htons(1), .type = 99};
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &h, 0, 0), &self->hsk);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.unknown_packet_types);
}
TEST_F(homa_incoming, homa_pkt_dispatch__new_server_rpc_but_socket_shutdown)
{
	self->hsk.shutdown = 1;
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), &self->hsk);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	self->hsk.shutdown = 0;
}

TEST_F(homa_incoming, homa_data_pkt__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 1600);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	crpc->msgout.next_packet = NULL;
	self->data.message_length = htonl(1600);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 0), crpc);
	EXPECT_EQ(RPC_INCOMING, crpc->state);
	EXPECT_EQ(0, unit_list_length(&self->hsk.ready_responses));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(200, crpc->msgin.bytes_remaining);
	EXPECT_EQ(1, crpc->msgin.num_skbs);
	EXPECT_EQ(1600, crpc->msgin.incoming);
	
	unit_log_clear();
	self->data.seg.offset = htonl(1400);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			200, 1400), crpc);
	EXPECT_EQ(RPC_READY, crpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_responses));
	EXPECT_EQ(0, crpc->msgin.bytes_remaining);
	EXPECT_EQ(2, crpc->msgin.num_skbs);
}
TEST_F(homa_incoming, homa_data_pkt__wrong_rpc_state)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 1400, 5000);
	EXPECT_NE(NULL, srpc);
	homa_data_pkt(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), srpc);
	EXPECT_EQ(RPC_OUTGOING, srpc->state);
	EXPECT_EQ(5, mock_skb_count());
}
TEST_F(homa_incoming, homa_data_pkt__another_wrong_rpc_state)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 2000);
	EXPECT_NE(NULL, crpc);
	
	crpc->state = RPC_READY;
	self->data.message_length = htonl(2000);
	self->data.seg.offset = htonl(1400);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			600, 1400), crpc);
	EXPECT_EQ(600, crpc->msgin.bytes_remaining);
	crpc->state = RPC_INCOMING;
}
TEST_F(homa_incoming, homa_data_pkt__add_to_grantables)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100000, 1000);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_SUBSTR("id 1235", unit_log_get());
}
TEST_F(homa_incoming, homa_data_pkt__set_extra_incoming_for_short_message)
{
	atomic_set(&self->homa.extra_incoming, 1000);
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 6000, 1000);
	EXPECT_NE(NULL, srpc);
	EXPECT_EQ(4600, srpc->msgin.extra_incoming);
	EXPECT_EQ(5600, atomic_read(&self->homa.extra_incoming));
}
TEST_F(homa_incoming, homa_data_pkt__dont_set_extra_incoming_for_large_message)
{
	atomic_set(&self->homa.extra_incoming, 1000);
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100000, 1000);
	EXPECT_NE(NULL, srpc);
	EXPECT_EQ(0, srpc->msgin.extra_incoming);
	EXPECT_EQ(1000, atomic_read(&self->homa.extra_incoming));
}
TEST_F(homa_incoming, homa_data_pkt__dont_set_extra_incoming_for_one_pkt_message)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 1000);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	self->data.message_length = htonl(1000);
	self->data.incoming = htonl(1000);
	crpc->msgout.next_packet = NULL;
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 0), crpc);
	EXPECT_EQ(RPC_READY, crpc->state);
	EXPECT_EQ(1000, crpc->msgin.incoming);
	EXPECT_EQ(0, crpc->msgin.extra_incoming);
	EXPECT_EQ(0, atomic_read(&self->homa.extra_incoming));
}
TEST_F(homa_incoming, homa_data_pkt__short_server_rpc_ready)
{
	self->data.message_length = htonl(100);
	self->data.incoming = htonl(100);
	self->data.seg.segment_length = htonl(100);
	struct homa_rpc *srpc = homa_rpc_new_server(&self->hsk,
			self->client_ip, &self->data);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			100, 0), srpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_requests));
	homa_rpc_unlock(srpc);
}
TEST_F(homa_incoming, homa_data_pkt__long_server_rpc_ready)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 2000, 1000);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(0, unit_list_length(&self->hsk.ready_requests));
	self->data.message_length = htonl(2000);
	self->data.incoming = htonl(600);
	self->data.seg.offset = htonl(1400);
	self->data.seg.segment_length = htonl(600);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 1400), srpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_requests));
}
TEST_F(homa_incoming, homa_data_pkt__long_server_rpc_ready_but_socket_shutdown)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 2000, 1000);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(0, unit_list_length(&self->hsk.ready_requests));
	self->data.message_length = htonl(2000);
	self->data.incoming = htonl(600);
	self->data.seg.offset = htonl(1400);
	self->data.seg.segment_length = htonl(600);
	self->hsk.shutdown = 1;
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 1400), srpc);
	EXPECT_EQ(0, unit_list_length(&self->hsk.ready_requests));
	self->hsk.shutdown = 0;
}
TEST_F(homa_incoming, homa_data_pkt__remove_from_grantable_when_ready)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 11200, 1000);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(0, unit_list_length(&self->hsk.ready_requests));
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 196.168.0.1, id 1235, remaining 9800",
			unit_log_get());

	// Send all of the data packets except the last one.
	self->data.message_length = htonl(11200);
	self->data.incoming = 100000;
	for (int i = 1400; i < 9800; i += 1400) {
		self->data.seg.offset = htonl(i);
		homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
				1400, i), srpc);
	}
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 196.168.0.1, id 1235, remaining 1400",
			unit_log_get());
	
	// Send the last data packet.
	self->data.seg.offset = htonl(9800);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 1400), srpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_requests));
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_incoming, homa_data_pkt__socket_shutdown)
{
	self->data.message_length = htonl(100);
	self->data.incoming = htonl(100);
	self->data.seg.segment_length = htonl(100);
	struct homa_rpc *srpc = homa_rpc_new_server(&self->hsk,
			self->client_ip, &self->data);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	homa_rpc_lock(srpc);
	self->hsk.shutdown = 1;
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			100, 0), srpc);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(0, unit_list_length(&self->hsk.ready_requests));
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	homa_rpc_unlock(srpc);
	self->hsk.shutdown = 0;
}
TEST_F(homa_incoming, homa_data_pkt__send_cutoffs)
{
	self->homa.cutoff_version = 2;
	self->homa.unsched_cutoffs[0] = 19;
	self->homa.unsched_cutoffs[1] = 18;
	self->homa.unsched_cutoffs[2] = 17;
	self->homa.unsched_cutoffs[3] = 16;
	self->homa.unsched_cutoffs[4] = 15;
	self->homa.unsched_cutoffs[5] = 14;
	self->homa.unsched_cutoffs[6] = 13;
	self->homa.unsched_cutoffs[7] = 12;
	self->data.message_length = htonl(5000);
	mock_xmit_log_verbose = 1;
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), &self->hsk);
	EXPECT_SUBSTR("cutoffs 19 18 17 16 15 14 13 12, version 2",
			unit_log_get());
	
	/* Try again, but this time no comments should be sent because
	 * no time has elapsed since the last cutoffs were sent.
	 */
	unit_log_clear();
	self->homa.cutoff_version = 3;
	self->data.seg.offset = 1400;
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), &self->hsk);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_incoming, homa_data_pkt__cutoffs_up_to_date)
{
	self->homa.cutoff_version = 123;
	self->data.cutoff_version = htons(123);
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), &self->hsk);
	EXPECT_STREQ("", unit_log_get());
}

TEST_F(homa_incoming, homa_grant_pkt__basics)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 20000);
	EXPECT_NE(NULL, srpc);
	homa_xmit_data(srpc, false);
	unit_log_clear();
	
	struct grant_header h = {{.sport = htons(srpc->dport),
	                .dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->client_id),
			.generation = htons(1),
			.type = GRANT},
		        .offset = htonl(12600),
			.priority = 3};
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_EQ(12600, srpc->msgout.granted);
	EXPECT_STREQ("xmit DATA 1400@11200", unit_log_get());
	
	/* Don't let grant offset go backwards. */
	h.offset = htonl(10000);
	unit_log_clear();
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_EQ(12600, srpc->msgout.granted);
	EXPECT_STREQ("", unit_log_get());
	
	/* Wrong state. */
	h.offset = htonl(20000);
	srpc->state = RPC_INCOMING;
	unit_log_clear();
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_EQ(12600, srpc->msgout.granted);
	EXPECT_STREQ("", unit_log_get());
	
	/* Must restore old state to avoid potential crashes. */
	srpc->state = RPC_OUTGOING;
}
TEST_F(homa_incoming, homa_grant_pkt__grant_past_end_of_message)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	
	struct grant_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(self->server_id),
			.generation = htons(1),
			.type = GRANT},
		        .offset = htonl(25000),
			.priority = 3};
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_EQ(20000, crpc->msgout.granted);
}
TEST_F(homa_incoming, homa_grant_pkt__delete_server_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 20000);
	EXPECT_NE(NULL, srpc);
	EXPECT_FALSE(list_empty(&self->hsk.active_rpcs));

	struct grant_header h = {{.sport = htons(self->client_port),
	                .dport = htons(self->server_port),
			.sender_id = cpu_to_be64(self->client_id),
			.generation = htons(1),
			.type = GRANT},
		        .offset = htonl(25000),
			.priority = 3};
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_TRUE(list_empty(&self->hsk.active_rpcs));
}

TEST_F(homa_incoming, homa_resend_pkt__server_sends_busy)
{
	struct resend_header h = {{.sport = htons(self->client_port),
	                .dport = htons(self->server_port),
			.sender_id = cpu_to_be64(self->client_id),
			.generation = htons(1),
			.type = RESEND},
		        .offset = htonl(100),
			.length = htonl(200),
			.priority = 3};
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_READY,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 20000);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_STREQ("xmit BUSY", unit_log_get());
}
TEST_F(homa_incoming, homa_resend_pkt__client_not_outgoing)
{
	/* Important to respond to resends even if client thinks the
	 * server must already have received everything.
	 */
	struct resend_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(self->server_id),
			.generation = htons(1),
			.type = RESEND},
		        .offset = htonl(100),
			.length = htonl(200),
			.priority = 3};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 2000, 3000);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	
	homa_pkt_dispatch(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_STREQ("xmit DATA retrans 1400@0", unit_log_get());
}
TEST_F(homa_incoming, homa_resend_pkt__send_busy_instead_of_data)
{
	struct resend_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(self->server_id),
			.generation = htons(1),
			.type = RESEND},
		        .offset = htonl(100),
			.length = htonl(200),
			.priority = 3};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 2000, 100);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	
	homa_pkt_dispatch(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_STREQ("xmit BUSY", unit_log_get());
}
TEST_F(homa_incoming, homa_resend_pkt__client_send_data)
{
	struct resend_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(self->server_id),
			.generation = htons(1),
			.type = RESEND},
		        .offset = htonl(100),
			.length = htonl(200),
			.priority = 3};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 2000, 100);
	EXPECT_NE(NULL, crpc);
	homa_xmit_data(crpc, false);
	unit_log_clear();
	mock_clear_xmit_prios();
	
	homa_pkt_dispatch(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_STREQ("xmit DATA retrans 1400@0", unit_log_get());
	EXPECT_STREQ("3", mock_xmit_prios);
}
TEST_F(homa_incoming, homa_resend_pkt__server_send_data)
{
	struct resend_header h = {{.sport = htons(self->client_port),
	                .dport = htons(self->server_port),
			.sender_id = cpu_to_be64(self->client_id),
			.generation = htons(1),
			.type = RESEND},
		        .offset = htonl(100),
			.length = htonl(2000),
			.priority = 4};
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 20000);
	EXPECT_NE(NULL, srpc);
	homa_xmit_data(srpc, false);
	unit_log_clear();
	mock_clear_xmit_prios();
	
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_STREQ("xmit DATA retrans 1400@0; "
			"xmit DATA retrans 1400@1400", unit_log_get());
	EXPECT_STREQ("4 4", mock_xmit_prios);
}

TEST_F(homa_incoming, homa_unknown_pkt__basics)
{
	struct unknown_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(self->server_id),
			.generation = htons(1),
			.type = UNKNOWN}};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 2000, 2000);
	EXPECT_NE(NULL, crpc);
	homa_xmit_data(crpc, false);
	unit_log_clear();
	
	mock_xmit_log_verbose = 1;
	
	/* Nothing happens on first call. */
	homa_pkt_dispatch(mock_skb_new(self->server_ip, &h.common, 0, 0), 
			&self->hsk);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(2000, crpc->msgin.total_length);
	EXPECT_STREQ("INCOMING", homa_symbol_for_state(crpc));
	
	/* Second call causes restart. */
	homa_pkt_dispatch(mock_skb_new(self->server_ip, &h.common, 0, 0), 
			&self->hsk);
	EXPECT_STREQ("homa_remove_from_grantable invoked; "
			"xmit DATA from 0.0.0.0:32768, dport 99, id 1234, "
			"generation 2, message_length 2000, offset 0, "
			"data_length 1400, incoming 2000; "
			"xmit DATA from 0.0.0.0:32768, dport 99, id 1234, "
			"generation 2, message_length 2000, offset 1400, "
			"data_length 600, incoming 2000",
			unit_log_get());
	EXPECT_EQ(-1, crpc->msgin.total_length);
}
TEST_F(homa_incoming, homa_unknown_pkt__rpc_ready)
{
	struct unknown_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(self->server_id),
			.generation = htons(1),
			.type = UNKNOWN}};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 2000, 2000);
	EXPECT_NE(NULL, crpc);
	crpc->unknowns = 1;
	EXPECT_STREQ("READY", homa_symbol_for_state(crpc));
	unit_log_clear();
	
	homa_pkt_dispatch(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_STREQ("READY", homa_symbol_for_state(crpc));
}
TEST_F(homa_incoming, homa_unknown_pkt__generation_overflow)
{
	struct unknown_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(self->server_id),
			.generation = htons(~0),
			.type = UNKNOWN}};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 2000, 2000);
	EXPECT_NE(NULL, crpc);
	crpc->unknowns = 1;
	homa_xmit_data(crpc, true);
	unit_log_clear();
	
	mock_alloc_skb_errors = 1;
	h.common.generation = ~0;
	crpc->generation = ~0;
	homa_pkt_dispatch(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_STREQ("READY", homa_symbol_for_state(crpc));
	EXPECT_EQ(EOVERFLOW, -crpc->error);
}
TEST_F(homa_incoming, homa_unknown_pkt__error)
{
	struct unknown_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(self->server_id),
			.generation = htons(1),
			.type = UNKNOWN}};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 2000, 2000);
	EXPECT_NE(NULL, crpc);
	crpc->unknowns = 1;
	homa_xmit_data(crpc, true);
	unit_log_clear();
	
	mock_alloc_skb_errors = 1;
	homa_pkt_dispatch(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_STREQ("READY", homa_symbol_for_state(crpc));
	EXPECT_EQ(ENOMEM, -crpc->error);
}
TEST_F(homa_incoming, homa_unknown_pkt__free_server_rpc)
{
	struct unknown_header h = {{.sport = htons(self->client_port),
	                .dport = htons(self->server_port),
			.sender_id = cpu_to_be64(self->client_id),
			.generation = htons(1),
			.type = UNKNOWN}};
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 20000);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	
	homa_pkt_dispatch(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_STREQ("DEAD", homa_symbol_for_state(srpc));
}
	
TEST_F(homa_incoming, homa_cutoffs_pkt_basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(10000, crpc->msgout.granted);
	unit_log_clear();
	
	struct cutoffs_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(self->server_id),
			.generation = htons(1),
			.type = CUTOFFS},
		        .unsched_cutoffs = {htonl(10), htonl(9), htonl(8),
			htonl(7), htonl(6), htonl(5), htonl(4), htonl(3)},
			.cutoff_version = 400};
	homa_pkt_dispatch(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->hsk);
	EXPECT_EQ(400, crpc->peer->cutoff_version);
	EXPECT_EQ(9, crpc->peer->unsched_cutoffs[1]);
	EXPECT_EQ(3, crpc->peer->unsched_cutoffs[7]);
}
TEST_F(homa_incoming, homa_cutoffs__cant_find_peer)
{	
	struct homa_peer *peer;
	struct cutoffs_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.sender_id = cpu_to_be64(self->server_id),
			.generation = htons(1),
			.type = CUTOFFS},
		        .unsched_cutoffs = {htonl(10), htonl(9), htonl(8),
			htonl(7), htonl(6), htonl(5), htonl(4), htonl(3)},
			.cutoff_version = 400};
	struct sk_buff *skb = mock_skb_new(self->server_ip, &h.common, 0, 0);
	mock_kmalloc_errors = 1;
	homa_cutoffs_pkt(skb, &self->hsk);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.peer_kmalloc_errors);
	peer = homa_peer_find(&self->homa.peers, self->server_ip,
			&self->hsk.inet);
	ASSERT_FALSE(IS_ERR(peer));
	EXPECT_EQ(0, peer->cutoff_version);
}

TEST_F(homa_incoming, homa_check_grantable__not_ready_for_grant)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 5000, 100);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	
	srpc->msgin.total_length = 20000;
	srpc->msgin.bytes_remaining = 15000;
	srpc->msgin.incoming = 18000;
	homa_check_grantable(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	
	srpc->msgin.incoming = 20000;
	homa_check_grantable(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	
	srpc->msgin.incoming = 18000;
	srpc->msgin.bytes_remaining = 10000;
	homa_check_grantable(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 196.168.0.1, id 1235, remaining 10000",
			unit_log_get());
}
TEST_F(homa_incoming, homa_check_grantable__move_upward_in_peer_list)
{
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 100000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 3, 50000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 5, 120000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 7, 70000, 100);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 196.168.0.1, id 3, remaining 48600; "
			"request from 196.168.0.1, id 7, remaining 68600; "
			"request from 196.168.0.1, id 1, remaining 98600; "
			"request from 196.168.0.1, id 5, remaining 118600",
			unit_log_get());
	EXPECT_EQ(1, self->homa.num_grantable_peers);
}
TEST_F(homa_incoming, homa_check_grantable__adjust_order_in_peer_list)
{
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 3, 30000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 5, 40000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 7, 50000, 100);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 196.168.0.1, id 1, remaining 18600; "
			"request from 196.168.0.1, id 3, remaining 28600; "
			"request from 196.168.0.1, id 5, remaining 38600; "
			"request from 196.168.0.1, id 7, remaining 48600",
			unit_log_get());

	struct homa_rpc *srpc = homa_find_server_rpc(&self->hsk,
			self->client_ip, self->client_port, 5);
	EXPECT_NE(NULL, srpc);
	homa_rpc_unlock(srpc);
	srpc->msgin.bytes_remaining = 28600;
	homa_check_grantable(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 196.168.0.1, id 1, remaining 18600; "
			"request from 196.168.0.1, id 3, remaining 28600; "
			"request from 196.168.0.1, id 5, remaining 28600; "
			"request from 196.168.0.1, id 7, remaining 48600",
			unit_log_get());
	
	srpc->msgin.bytes_remaining = 28599;
	homa_check_grantable(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 196.168.0.1, id 1, remaining 18600; "
			"request from 196.168.0.1, id 5, remaining 28599; "
			"request from 196.168.0.1, id 3, remaining 28600; "
			"request from 196.168.0.1, id 7, remaining 48600",
			unit_log_get());

	srpc = homa_find_server_rpc(&self->hsk, self->client_ip,
			self->client_port, 7);
	EXPECT_NE(NULL, srpc);
	homa_rpc_unlock(srpc);;
	srpc->msgin.bytes_remaining = 1000;
	homa_check_grantable(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 196.168.0.1, id 7, remaining 1000; "
			"request from 196.168.0.1, id 1, remaining 18600; "
			"request from 196.168.0.1, id 5, remaining 28599; "
			"request from 196.168.0.1, id 3, remaining 28600",
			unit_log_get());
}
TEST_F(homa_incoming, homa_check_grantable__order_in_homa_list)
{
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 100000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 3, 50000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+2,
			self->server_ip, self->client_port, 5, 120000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+3,
			self->server_ip, self->client_port, 7, 70000, 100);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 197.168.0.1, id 3, remaining 48600; "
			"request from 199.168.0.1, id 7, remaining 68600; "
			"request from 196.168.0.1, id 1, remaining 98600; "
			"request from 198.168.0.1, id 5, remaining 118600",
			unit_log_get());
	EXPECT_EQ(4, self->homa.num_grantable_peers);
}
TEST_F(homa_incoming, homa_check_grantable__move_upward_in_homa_list)
{
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 3, 30000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+2,
			self->server_ip, self->client_port, 5, 40000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+3,
			self->server_ip, self->client_port, 7, 50000, 100);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 196.168.0.1, id 1, remaining 18600; "
			"request from 197.168.0.1, id 3, remaining 28600; "
			"request from 198.168.0.1, id 5, remaining 38600; "
			"request from 199.168.0.1, id 7, remaining 48600",
			unit_log_get());

	struct homa_rpc *srpc = homa_find_server_rpc(&self->hsk,
			self->client_ip+2, self->client_port, 5);
	EXPECT_NE(NULL, srpc);
	homa_rpc_unlock(srpc);
	srpc->msgin.bytes_remaining = 28600;
	homa_check_grantable(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 196.168.0.1, id 1, remaining 18600; "
			"request from 197.168.0.1, id 3, remaining 28600; "
			"request from 198.168.0.1, id 5, remaining 28600; "
			"request from 199.168.0.1, id 7, remaining 48600",
			unit_log_get());
	
	srpc->msgin.bytes_remaining = 28599;
	homa_check_grantable(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 196.168.0.1, id 1, remaining 18600; "
			"request from 198.168.0.1, id 5, remaining 28599; "
			"request from 197.168.0.1, id 3, remaining 28600; "
			"request from 199.168.0.1, id 7, remaining 48600",
			unit_log_get());

	srpc = homa_find_server_rpc(&self->hsk, self->client_ip+3,
			self->client_port, 7);
	EXPECT_NE(NULL, srpc);
	homa_rpc_unlock(srpc);;
	srpc->msgin.bytes_remaining = 1000;
	homa_check_grantable(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 199.168.0.1, id 7, remaining 1000; "
			"request from 196.168.0.1, id 1, remaining 18600; "
			"request from 198.168.0.1, id 5, remaining 28599; "
			"request from 197.168.0.1, id 3, remaining 28600",
			unit_log_get());
}

TEST_F(homa_incoming, homa_send_grants__max_incoming)
{
	struct homa_rpc *srpc1, *srpc2, *srpc3, *srpc4;
	srpc1 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	srpc2 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 3, 30000, 100);
	srpc3 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+2,
			self->server_ip, self->client_port, 5, 40000, 100);
	srpc4 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+3,
			self->server_ip, self->client_port, 7, 50000, 100);
	homa_send_grants(&self->homa);
	
	unit_log_clear();
	srpc1->msgin.incoming = 11400;        /* 10000 bytes incoming */
	srpc2->msgin.incoming = 1400;         /* 0 incoming */
	srpc3->msgin.incoming = 1400;         /* 0 incoming */
	srpc4->msgin.incoming = 1400;         /* 0 incoming */
	
	self->homa.max_incoming = 40000;
	self->homa.grant_increment = 10000;
	atomic_set(&self->homa.extra_incoming, 15000);
	unit_log_clear();
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 11400@2", unit_log_get());
	
	/* Try again (no new grants, since nothing has changed). */
	unit_log_clear();
	homa_send_grants(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	
	/* Now create enough headroom for all of the messages. */
	self->homa.max_incoming = 55000;
	unit_log_clear();
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 11400@1; xmit GRANT 11400@0", unit_log_get());
}
TEST_F(homa_incoming, homa_send_grants__grant_threshold)
{
	struct homa_rpc *srpc1, *srpc2, *srpc3, *srpc4;
	srpc1 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	srpc2 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 3, 30000, 100);
	srpc3 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+2,
			self->server_ip, self->client_port, 5, 40000, 100);
	srpc4 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+3,
			self->server_ip, self->client_port, 7, 50000, 100);
	homa_send_grants(&self->homa);
	
	unit_log_clear();
	srpc1->msgin.incoming = 11400;        /* 10000 bytes incoming */
	srpc2->msgin.incoming = 15400;        /* 14000 incoming */
	srpc3->msgin.incoming = 21400;        /* 20000 incoming */
	srpc4->msgin.incoming = 6400;         /* 5000 incoming */
	
	self->homa.max_incoming = 100000;
	self->homa.grant_increment = 12000;
	self->homa.grant_threshold = 15000;
	self->homa.rtt_bytes = 25000;
	unit_log_clear();
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 20000@3; "
			"xmit GRANT 27400@2; "
			"xmit GRANT 26400@0", unit_log_get());
}
TEST_F(homa_incoming, homa_send_grants__one_grant_per_peer)
{
	struct homa_rpc *srpc2, *srpc3, *srpc4;
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	srpc2 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 3, 30000, 100);
	srpc3 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 5, 40000, 100);
	srpc4 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 7, 50000, 100);
	srpc2->msgin.bytes_remaining -= 1000;
	srpc3->msgin.bytes_remaining -= 2000;
	srpc4->msgin.bytes_remaining -= 3000;
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 11400@1; xmit GRANT 14400@0", unit_log_get());
}
TEST_F(homa_incoming, homa_send_grants__choose_grant_offset)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			1, 40000, 100);
	
	self->homa.rtt_bytes = 10000;
	self->homa.grant_increment = 4000;
	
	/* No need for grant. */
	srpc->msgin.bytes_remaining = 35000;
	srpc->msgin.incoming = 16000;
	unit_log_clear();
	homa_send_grants(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	
	/* Normal grant needed. */
	srpc->msgin.bytes_remaining = 35000;
	srpc->msgin.incoming = 14000;
	unit_log_clear();
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 18000@0", unit_log_get());
	
	/* We're behind: need larger than normal grant. */
	srpc->msgin.bytes_remaining = 35000;
	srpc->msgin.incoming = 6000;
	unit_log_clear();
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 15000@0", unit_log_get());
	
	/* Smaller grant at end of message. */
	srpc->msgin.bytes_remaining = 3000;
	srpc->msgin.incoming = 38000;
	unit_log_clear();
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 40000@0", unit_log_get());
}
TEST_F(homa_incoming, homa_send_grants__choose_priority_level)
{
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 40000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 3, 30000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+2,
			self->server_ip, self->client_port, 5, 20000, 100);
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 11400@2; "
			"xmit GRANT 11400@1; "
			"xmit GRANT 11400@0", unit_log_get());

	struct homa_rpc *srpc = homa_find_server_rpc(&self->hsk,
			self->client_ip, self->client_port, 1);
	EXPECT_NE(NULL, srpc);
	homa_rpc_unlock(srpc);
	
	/* Share lowest priority level. */
	self->homa.max_sched_prio = 1;
	srpc->msgin.bytes_remaining -= 1400;
	unit_log_clear();
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 12800@0", unit_log_get());
}
TEST_F(homa_incoming, homa_send_grants__many_messages_of_same_size)
{
	self->homa.rtt_bytes = 10000;
	self->homa.max_incoming = 20000;
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	unit_log_clear();
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 11400@0", unit_log_get());
	unit_log_clear();
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 3, 20000, 100);
	unit_log_clear();
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 11400@0", unit_log_get());
	unit_log_clear();
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+2,
			self->server_ip, self->client_port, 5, 20000, 100);
	unit_log_clear();
	homa_send_grants(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	unit_log_clear();
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+3,
			self->server_ip, self->client_port, 7, 20000, 100);
	unit_log_clear();
	homa_send_grants(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_incoming, homa_send_grants__prevent_priorities_less_than_zero)
{
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 15000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 3, 30000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+2,
			self->server_ip, self->client_port, 5, 40000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 7, 50000, 100);
	
	/* Arrange for one message to become fully granted; it will be
	 * replaced in the list by another message from the same peer.
	 */
	struct homa_rpc *srpc = homa_find_server_rpc(&self->hsk,
			self->client_ip+1, self->client_port, 3);
	homa_rpc_unlock(srpc);
	srpc->msgin.incoming = 25000;
	srpc->msgin. bytes_remaining = 5000;
	
	self->homa.rtt_bytes = 10000;
	self->homa.max_incoming = 50000;
	unit_log_clear();
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 11400@2; xmit GRANT 30000@1; "
			"xmit GRANT 11400@0; xmit GRANT 11400@0",
			unit_log_get());
}
TEST_F(homa_incoming, homa_send_grants__remove_from_grantable)
{
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 15000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 3, 30000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+2,
			self->server_ip, self->client_port, 5, 40000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+3,
			self->server_ip, self->client_port, 7, 50000, 100);
	
	struct homa_rpc *srpc = homa_find_server_rpc(&self->hsk,
			self->client_ip, self->client_port, 1);
	homa_rpc_unlock(srpc);
	EXPECT_EQ(1, srpc->msgin.possibly_in_grant_queue);
	
	self->homa.rtt_bytes = 20000;
	self->homa.max_incoming = 20000;
	self->homa.grant_increment = 10000;
	unit_log_clear();
	homa_send_grants(&self->homa);
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 15000@3", unit_log_get());
	EXPECT_EQ(13600, atomic_read(&self->homa.extra_incoming));
	EXPECT_EQ(13600, srpc->msgin.extra_incoming);
	EXPECT_EQ(0, srpc->msgin.possibly_in_grant_queue);
}
TEST_F(homa_incoming, homa_send_grants__MAX_GRANTS_exceeded)
{
	mock_max_grants = 3;
	self->homa.rtt_bytes = 10000;
	self->homa.max_incoming = 100000;
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 32, 30000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+2,
			self->server_ip, self->client_port, 5, 40000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+3,
			self->server_ip, self->client_port, 7, 50000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+4,
			self->server_ip, self->client_port, 9, 60000, 100);

	struct homa_rpc *srpc = homa_find_server_rpc(&self->hsk,
			self->client_ip, self->client_port, 1);
	EXPECT_NE(NULL, srpc);
	homa_rpc_unlock(srpc);
	unit_log_clear();
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 11400@3; xmit GRANT 11400@2; "
			"xmit GRANT 11400@1", unit_log_get());
}
TEST_F(homa_incoming, homa_send_grants__grant_fifo)
{
	struct homa_rpc *srpc1, *srpc2;
	self->homa.rtt_bytes = 10000;
	self->homa.grant_increment = 5000;
	self->homa.max_sched_prio = 3;
	self->homa.grant_fifo_fraction = 100;
	self->homa.grant_nonfifo_left = 6000;
	self->homa.grant_nonfifo = 10000;
	self->homa.max_overcommit = 1;
	self->homa.max_incoming = 15000;
	mock_cycles = ~0;
	srpc1 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 30000, 100);
	EXPECT_NE(NULL, srpc1);
	EXPECT_EQ(10000, srpc1->msgin.incoming);
	srpc2 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 1, 20000, 100);
	EXPECT_NE(NULL, srpc2);
	srpc2->msgin.incoming = 9000;
	
	/* First call: not time for FIFO grants yet. */
	unit_log_clear();
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 14000@1", unit_log_get());
	EXPECT_EQ(14000, srpc2->msgin.incoming);
	EXPECT_EQ(1000, self->homa.grant_nonfifo_left);
	
	/* Second call: time for a FIFO grant. */
	unit_log_clear();
	srpc2->msgin.incoming = 5000;
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 15000@3; xmit GRANT 11400@1", unit_log_get());
	EXPECT_EQ(15000, srpc1->msgin.incoming);
	EXPECT_EQ(11400, srpc2->msgin.incoming);
	EXPECT_EQ(4600, self->homa.grant_nonfifo_left);
	
	/* Third call: time for a FIFO grant, but FIFO fraction is zero. */
	unit_log_clear();
	srpc1->msgin.incoming = 5000;
	srpc2->msgin.incoming = 5000;
	self->homa.grant_nonfifo_left = 1000;
	self->homa.grant_fifo_fraction = 0;
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 11400@1", unit_log_get());
	EXPECT_EQ(11400, srpc2->msgin.incoming);
	EXPECT_EQ(4600, self->homa.grant_nonfifo_left);
}
TEST_F(homa_incoming, homa_send_grants__dont_grant_fifo_no_inactive_rpcs)
{
	struct homa_rpc *srpc1, *srpc2;
	self->homa.rtt_bytes = 10000;
	self->homa.grant_increment = 5000;
	self->homa.max_sched_prio = 3;
	self->homa.grant_fifo_fraction = 100;
	self->homa.grant_nonfifo_left = 1000;
	self->homa.grant_nonfifo = 10000;
	self->homa.max_overcommit = 2;
	self->homa.max_incoming = 20000;
	mock_cycles = ~0;
	srpc1 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 30000, 100);
	EXPECT_NE(NULL, srpc1);
	srpc1->msgin.incoming = 10000;
	srpc2 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 1, 20000, 100);
	EXPECT_NE(NULL, srpc2);
	srpc2->msgin.incoming = 9000;

	unit_log_clear();
	homa_send_grants(&self->homa);
	EXPECT_STREQ("xmit GRANT 14000@1", unit_log_get());
	EXPECT_EQ(10000, srpc1->msgin.incoming);
	EXPECT_EQ(14000, srpc2->msgin.incoming);
	EXPECT_EQ(6000, self->homa.grant_nonfifo_left);
}
TEST_F(homa_incoming, homa_send_grants__grant_after_rpc_deleted)
{
	self->homa.rtt_bytes = 10000;
	self->homa.max_incoming = 20000;
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 3, 30000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+2,
			self->server_ip, self->client_port, 5, 40000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+3,
			self->server_ip, self->client_port, 7, 50000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+4,
			self->server_ip, self->client_port, 9, 60000, 100);

	struct homa_rpc *srpc = homa_find_server_rpc(&self->hsk,
			self->client_ip, self->client_port, 1);
	EXPECT_NE(NULL, srpc);
	homa_rpc_unlock(srpc);
	homa_send_grants(&self->homa);
	unit_log_clear();
	homa_rpc_free(srpc);
	EXPECT_STREQ("homa_remove_from_grantable invoked; xmit GRANT 11400@2",
			unit_log_get());
}

TEST_F(homa_incoming, homa_grant_fifo__basics)
{
	struct homa_rpc *srpc;
	self->homa.rtt_bytes = 10000;
	self->homa.grant_increment = 5000;
	self->homa.max_sched_prio = 2;
	mock_cycles = ~0;
	srpc = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 40000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 3, 30000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 5, 20000, 100);
	EXPECT_NE(NULL, srpc);
	EXPECT_EQ(10000, srpc->msgin.incoming);
	
	unit_log_clear();
	homa_grant_fifo(&self->homa);
	EXPECT_STREQ("xmit GRANT 15000@2", unit_log_get());
	EXPECT_EQ(15000, srpc->msgin.incoming);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.fifo_grants);
	EXPECT_EQ(0, homa_cores[cpu_number]->metrics.fifo_grants_no_incoming);
}
TEST_F(homa_incoming, homa_grant_fifo__pity_grant_still_active)
{
	struct homa_rpc *srpc1, *srpc2;
	self->homa.rtt_bytes = 10000;
	self->homa.grant_increment = 5000;
	self->homa.max_sched_prio = 2;
	mock_cycles = ~0;
	srpc1 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 40000, 100);
	srpc2 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 3, 30000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 5, 20000, 100);
	EXPECT_NE(NULL, srpc1);
	EXPECT_NE(NULL, srpc2);
	srpc1->msgin.incoming = 16400;
	
	unit_log_clear();
	homa_grant_fifo(&self->homa);
	EXPECT_STREQ("xmit GRANT 15000@2", unit_log_get());
	EXPECT_EQ(16400, srpc1->msgin.incoming);
	EXPECT_EQ(15000, srpc2->msgin.incoming);
}
TEST_F(homa_incoming, homa_grant_fifo__no_good_candidates)
{
	struct homa_rpc *srpc1;
	self->homa.rtt_bytes = 10000;
	self->homa.grant_increment = 5000;
	self->homa.max_sched_prio = 2;
	mock_cycles = ~0;
	srpc1 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 40000, 100);
	EXPECT_NE(NULL, srpc1);
	srpc1->msgin.incoming = 16400;
	
	unit_log_clear();
	homa_grant_fifo(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(16400, srpc1->msgin.incoming);
}
TEST_F(homa_incoming, homa_grant_fifo__increment_fifo_grants_no_incoming)
{
	struct homa_rpc *srpc1;
	self->homa.rtt_bytes = 10000;
	self->homa.grant_increment = 5000;
	self->homa.max_sched_prio = 2;
	mock_cycles = ~0;
	srpc1 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 40000, 100);
	EXPECT_NE(NULL, srpc1);
	srpc1->msgin.incoming = 1400;
	
	unit_log_clear();
	homa_grant_fifo(&self->homa);
	EXPECT_STREQ("xmit GRANT 6400@2", unit_log_get());
	EXPECT_EQ(6400, srpc1->msgin.incoming);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.fifo_grants_no_incoming);
}
TEST_F(homa_incoming, homa_grant_fifo__remove_from_grantable)
{
	struct homa_rpc *srpc1;
	self->homa.rtt_bytes = 10000;
	self->homa.grant_increment = 5000;
	self->homa.max_sched_prio = 2;
	mock_cycles = ~0;
	srpc1 = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 15000, 100);
	EXPECT_NE(NULL, srpc1);
	
	unit_log_clear();
	homa_grant_fifo(&self->homa);
	EXPECT_STREQ("xmit GRANT 15000@2", unit_log_get());
	EXPECT_EQ(15000, srpc1->msgin.incoming);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}

TEST_F(homa_incoming, homa_remove_grantable_locked__basics)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			1, 20000, 100);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 196.168.0.1, id 1, remaining 18600",
			unit_log_get());
	
	/* First time: on the list. */
	homa_remove_grantable_locked(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, self->homa.num_grantable_peers);
	
	/* Second time: not on the list. */
	homa_remove_grantable_locked(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, self->homa.num_grantable_peers);
};
TEST_F(homa_incoming, homa_remove_grantable_locked__not_head_of_peer_list)
{
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			3, 50000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 5, 30000, 100);
	EXPECT_NE(NULL, srpc);
	homa_remove_grantable_locked(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 196.168.0.1, id 1, remaining 18600; "
			"request from 197.168.0.1, id 5, remaining 28600",
			unit_log_get());
	EXPECT_EQ(2, self->homa.num_grantable_peers);
}
TEST_F(homa_incoming, homa_remove_grantable_locked__remove_peer_from_homa_list)
{
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip+1, self->server_ip, self->client_port,
			3, 30000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+2,
			self->server_ip, self->client_port, 5, 40000, 100);
	EXPECT_NE(NULL, srpc);
	homa_remove_grantable_locked(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 196.168.0.1, id 1, remaining 18600; "
			"request from 198.168.0.1, id 5, remaining 38600",
			unit_log_get());
	EXPECT_EQ(2, self->homa.num_grantable_peers);
}
TEST_F(homa_incoming, homa_remove_grantable_locked__peer_moves_down)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			1, 20000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 3, 40000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+1,
			self->server_ip, self->client_port, 5, 30000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip+2,
			self->server_ip, self->client_port, 7, 40000, 100);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 196.168.0.1, id 1, remaining 18600; "
			"request from 196.168.0.1, id 3, remaining 38600; "
			"request from 197.168.0.1, id 5, remaining 28600; "
			"request from 198.168.0.1, id 7, remaining 38600",
			unit_log_get());
	EXPECT_EQ(3, self->homa.num_grantable_peers);
	
	homa_remove_grantable_locked(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 197.168.0.1, id 5, remaining 28600; "
			"request from 198.168.0.1, id 7, remaining 38600; "
			"request from 196.168.0.1, id 3, remaining 38600",
			unit_log_get());
	EXPECT_EQ(3, self->homa.num_grantable_peers);
}

TEST_F(homa_incoming, homa_remove_from_grantable__basics)
{
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 196.168.0.1, id 1, remaining 18600",
			unit_log_get());
	struct homa_rpc *srpc = homa_find_server_rpc(&self->hsk,
			self->client_ip, self->client_port, 1);
	EXPECT_NE(NULL, srpc);
	homa_rpc_unlock(srpc);
	
	/* First time: on the list. */
	homa_remove_from_grantable(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	
	/* Second time: not on the list. */
	homa_remove_from_grantable(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_incoming, homa_remove_from_grantable__grant_to_other_message)
{
	self->homa.max_overcommit = 1;
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 3, 30000, 100);

	struct homa_rpc *srpc = homa_find_server_rpc(&self->hsk,
			self->client_ip, self->client_port, 1);
	EXPECT_NE(NULL, srpc);
	homa_rpc_unlock(srpc);
	homa_send_grants(&self->homa);
	unit_log_clear();
	
	mock_xmit_log_verbose = 1;
	homa_rpc_free(srpc);
	EXPECT_SUBSTR("xmit GRANT", unit_log_get());
	EXPECT_SUBSTR("id 3,", unit_log_get());
}
TEST_F(homa_incoming, homa_remove_from_grantable__update_extra_incoming)
{
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request from 196.168.0.1, id 1, remaining 18600",
			unit_log_get());
	struct homa_rpc *srpc = homa_find_server_rpc(&self->hsk,
			self->client_ip, self->client_port, 1);
	EXPECT_NE(NULL, srpc);
	homa_rpc_unlock(srpc);
	srpc->msgin.extra_incoming = 5000;
	
	/* First try: msgin isn't valid. */
	srpc->msgin.total_length = -1;
	atomic_set(&self->homa.extra_incoming, 10000);
	homa_remove_from_grantable(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_SUBSTR("id 1", unit_log_get());
	EXPECT_EQ(5000, srpc->msgin.extra_incoming);
	EXPECT_EQ(10000, atomic_read(&self->homa.extra_incoming));
	
	/* Second try: actually do the decrement. */
	srpc->msgin.total_length = 20000;
	atomic_set(&self->homa.extra_incoming, 10000);
	homa_remove_from_grantable(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, srpc->msgin.extra_incoming);
	EXPECT_EQ(5000, atomic_read(&self->homa.extra_incoming));
}

TEST_F(homa_incoming, homa_rpc_abort__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	unit_log_clear();
	homa_rpc_abort(crpc, -EFAULT);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_responses));
	EXPECT_EQ(RPC_READY, crpc->state);
	EXPECT_EQ(EFAULT, -crpc->error);
	EXPECT_STREQ("homa_remove_from_grantable invoked; "
			"sk->sk_data_ready invoked", unit_log_get());
}
TEST_F(homa_incoming, homa_rpc_abort__socket_shutdown)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	unit_log_clear();
	self->hsk.shutdown = 1;
	homa_rpc_abort(crpc, -EFAULT);
	EXPECT_EQ(RPC_OUTGOING, crpc->state);
	EXPECT_EQ(EFAULT, -crpc->error);
	EXPECT_STREQ("homa_remove_from_grantable invoked", unit_log_get());
	self->hsk.shutdown = 0;
}

TEST_F(homa_incoming, homa_abort_rpcs__basics)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 1600);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2, 5000, 1600);
	struct homa_rpc *crpc3 = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip+1,
			self->server_port, self->client_id+4, 5000, 1600);
	unit_log_clear();
	homa_abort_rpcs(&self->homa, self->server_ip, 0, -EPROTONOSUPPORT);
	EXPECT_EQ(2, unit_list_length(&self->hsk.ready_responses));
	EXPECT_EQ(RPC_READY, crpc1->state);
	EXPECT_EQ(EPROTONOSUPPORT, -crpc1->error);
	EXPECT_EQ(0, -crpc2->error);
	EXPECT_EQ(RPC_OUTGOING, crpc3->state);
}
TEST_F(homa_incoming, homa_abort_rpcs__multiple_sockets)
{
	struct homa_sock hsk1, hsk2;
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 1600);
	struct homa_rpc *crpc2, *crpc3;
	mock_sock_init(&hsk1, &self->homa, self->server_port);
	mock_sock_init(&hsk2, &self->homa, self->server_port+1);
	crpc2 = unit_client_rpc(&hsk1, RPC_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id+2,
			5000, 1600);
	crpc3 = unit_client_rpc(&hsk1, RPC_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id+4,
			5000, 1600);
	unit_log_clear();
	homa_abort_rpcs(&self->homa, self->server_ip, 0, -EPROTONOSUPPORT);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_responses));
	EXPECT_EQ(RPC_READY, crpc1->state);
	EXPECT_EQ(EPROTONOSUPPORT, -crpc1->error);
	EXPECT_EQ(RPC_READY, crpc2->state);
	EXPECT_EQ(EPROTONOSUPPORT, -crpc2->error);
	EXPECT_EQ(RPC_READY, crpc3->state);
	EXPECT_EQ(2, unit_list_length(&hsk1.active_rpcs));
	EXPECT_EQ(2, unit_list_length(&hsk1.ready_responses));
}
TEST_F(homa_incoming, homa_abort_rpcs__select_port)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 1600);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port+1, self->client_id+2, 5000, 1600);
	struct homa_rpc *crpc3 = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id+4, 5000, 1600);
	unit_log_clear();
	homa_abort_rpcs(&self->homa, self->server_ip, self->server_port,
			-ENOTCONN);
	EXPECT_EQ(2, unit_list_length(&self->hsk.ready_responses));
	EXPECT_EQ(RPC_READY, crpc1->state);
	EXPECT_EQ(ENOTCONN, -crpc1->error);
	EXPECT_EQ(RPC_OUTGOING, crpc2->state);
	EXPECT_EQ(RPC_READY, crpc3->state);
	EXPECT_EQ(ENOTCONN, -crpc3->error);
}

TEST_F(homa_incoming, homa_register_interests__bogus_id)
{
	int result;
	result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECV_RESPONSE, 44, &self->addr);
	EXPECT_EQ(EINVAL, -result);
}
TEST_F(homa_incoming, homa_register_interests__id_already_has_interest)
{
	struct homa_interest interest;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	
	crpc->interest = &interest;
	int result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECV_RESPONSE, self->client_id, &self->addr);
	crpc->interest = NULL;
	EXPECT_EQ(EINVAL, -result);
}
TEST_F(homa_incoming, homa_register_interests__socket_shutdown)
{
	int result;
	self->hsk.shutdown = 1;
	result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECV_RESPONSE, 0, &self->addr);
	EXPECT_EQ(ESHUTDOWN, -result);
	self->hsk.shutdown = 0;
}
TEST_F(homa_incoming, homa_register_interests__specified_rpc_ready)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	
	int result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECV_REQUEST|HOMA_RECV_NONBLOCKING, crpc->id,
			&self->addr);
	EXPECT_EQ(0, result);
	EXPECT_EQ(crpc->id, atomic_long_read(&self->interest.id));
	EXPECT_EQ(crpc, self->interest.ready_rpc);
	homa_rpc_unlock(crpc);
}
TEST_F(homa_incoming, homa_register_interests__return_response_by_id)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	
	int result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECV_NONBLOCKING, self->client_id, NULL);
	EXPECT_EQ(0, result);
	EXPECT_EQ(crpc, self->interest.ready_rpc);
	EXPECT_EQ(self->client_id, atomic_long_read(&self->interest.id));
	homa_rpc_unlock(crpc);
}
TEST_F(homa_incoming, homa_register_interests__return_request_by_id)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_READY,
			self->client_ip, self->server_ip, self->client_port,
		        self->server_id, 20000, 100);
	EXPECT_NE(NULL, srpc);
	
	self->addr.sin_addr.s_addr = self->client_ip;
	self->addr.sin_port = htons(self->client_port);
	int result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECV_NONBLOCKING, self->server_id, &self->addr);
	EXPECT_EQ(0, result);
	EXPECT_EQ(srpc, self->interest.ready_rpc);
	EXPECT_EQ(self->server_id, atomic_long_read(&self->interest.id));
	homa_rpc_unlock(srpc);
}
TEST_F(homa_incoming, homa_register_interests__return_from_ready_responses)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	
	int result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECV_REQUEST|HOMA_RECV_RESPONSE
			|HOMA_RECV_NONBLOCKING, 0, &self->addr);
	EXPECT_EQ(0, result);
	EXPECT_EQ(self->client_id, atomic_long_read(&self->interest.id));
	EXPECT_EQ(LIST_POISON1, self->interest.request_links.next);
	EXPECT_EQ(LIST_POISON1, self->interest.response_links.next);
}
TEST_F(homa_incoming, homa_register_interests__return_from_ready_requests)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_READY,
			self->client_ip, self->server_ip, self->client_port,
		        1, 20000, 100);
	EXPECT_NE(NULL, srpc);
	
	int result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECV_REQUEST|HOMA_RECV_RESPONSE
			|HOMA_RECV_NONBLOCKING, 0, &self->addr);
	EXPECT_EQ(0, result);
	EXPECT_EQ(1, atomic_long_read(&self->interest.id));
	EXPECT_EQ(LIST_POISON1, self->interest.request_links.next);
	EXPECT_EQ(LIST_POISON1, self->interest.response_links.next);
}
TEST_F(homa_incoming, homa_register_interests__call_sk_data_ready)
{
	unit_server_rpc(&self->hsk, RPC_READY, self->client_ip,
			self->server_ip, self->client_port,
		        self->server_id, 20000, 100);
	unit_server_rpc(&self->hsk, RPC_READY, self->client_ip,
			self->server_ip, self->client_port,
		        self->server_id+2, 20000, 100);
	
	// First time should call sk_data_ready (for 2nd RPC).
	unit_log_clear();
	int result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECV_REQUEST|HOMA_RECV_RESPONSE
			|HOMA_RECV_NONBLOCKING, 0, NULL);
	EXPECT_EQ(0, result);
	EXPECT_EQ(self->server_id, atomic_long_read(&self->interest.id));
	EXPECT_STREQ("sk->sk_data_ready invoked", unit_log_get());
	
	// Second time shouldn't call sk_data_ready (no more RPCs).
	unit_log_clear();
	result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECV_REQUEST|HOMA_RECV_RESPONSE
			|HOMA_RECV_NONBLOCKING, 0, NULL);
	EXPECT_EQ(0, result);
	EXPECT_EQ(self->server_id+2, atomic_long_read(&self->interest.id));
	EXPECT_STREQ("", unit_log_get());
}

TEST_F(homa_incoming, homa_wait_for_message__rpc_from_register_interests)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	
	struct homa_rpc *rpc = homa_wait_for_message(&self->hsk,
			HOMA_RECV_RESPONSE|HOMA_RECV_NONBLOCKING,
			self->client_id, &self->addr);
	EXPECT_EQ(crpc, rpc);
	homa_rpc_unlock(crpc);
}
TEST_F(homa_incoming, homa_wait_for_message__id_from_register_interests)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	
	struct homa_rpc *rpc = homa_wait_for_message(&self->hsk,
			HOMA_RECV_RESPONSE|HOMA_RECV_NONBLOCKING, 0,
			&self->addr);
	EXPECT_EQ(crpc, rpc);
	homa_rpc_unlock(crpc);
}
TEST_F(homa_incoming, homa_wait_for_message__error_from_register_interests)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	
	self->hsk.shutdown = 1;
	struct homa_rpc *rpc = homa_wait_for_message(&self->hsk,
			HOMA_RECV_RESPONSE|HOMA_RECV_NONBLOCKING,
			self->client_id, &self->addr);
	EXPECT_EQ(ESHUTDOWN, -PTR_ERR(rpc));
	self->hsk.shutdown = 0;
}
TEST_F(homa_incoming, homa_wait_for_message__id_arrives_while_polling)
{
	struct homa_rpc *rpc;
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc1);
	
	hook_rpc = crpc1;
	poll_count = 5;
	self->homa.poll_cycles = 1000000;
	mock_schedule_hook = poll_hook;
	unit_log_clear();
	rpc = homa_wait_for_message(&self->hsk, 0, self->client_id, &self->addr);
	EXPECT_EQ(crpc1, rpc);
	EXPECT_EQ(NULL, crpc1->interest);
	EXPECT_STREQ("wake_up_process pid 0", unit_log_get());
	EXPECT_EQ(0, self->hsk.dead_skbs);
	homa_rpc_unlock(rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__id_not_ready_nonblocking)
{
	struct homa_rpc *rpc;
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	unit_client_rpc(&self->hsk, RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2, 20000, 1600);
	EXPECT_NE(NULL, crpc1);
	
	rpc = homa_wait_for_message(&self->hsk, HOMA_RECV_NONBLOCKING,
			self->client_id, &self->addr);
	EXPECT_EQ(EAGAIN, -PTR_ERR(rpc));
}
TEST_F(homa_incoming, homa_wait_for_message__id_arrives_while_sleeping)
{
	struct homa_rpc *rpc;
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc1);
	
        /* Also, check to see that reaping occurs before sleeping. */
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2, 20000, 20000);
	self->homa.reap_limit = 5;
	homa_rpc_free(crpc2);
	EXPECT_EQ(30, self->hsk.dead_skbs);
	unit_log_clear();
	
	hook_rpc = crpc1;
	mock_schedule_hook = ready_hook;
	rpc = homa_wait_for_message(&self->hsk, 0, self->client_id, &self->addr);
	EXPECT_EQ(crpc1, rpc);
	EXPECT_EQ(NULL, crpc1->interest);
	EXPECT_STREQ("reaped 1236; wake_up_process pid 0; 0 in ready_requests, "
			"0 in ready_responses, 0 in request_interests, "
			"0 in response_interests", unit_log_get());
	EXPECT_EQ(0, self->hsk.dead_skbs);
	homa_rpc_unlock(rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__response_arrives_while_sleeping)
{
	struct homa_rpc *rpc;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	
	hook_rpc = crpc;
	mock_schedule_hook = ready_hook;
	rpc = homa_wait_for_message(&self->hsk,
			HOMA_RECV_RESPONSE|HOMA_RECV_REQUEST, 0, &self->addr);
	EXPECT_EQ(crpc, rpc);
	EXPECT_STREQ("wake_up_process pid 0; 0 in ready_requests, "
			"0 in ready_responses, 0 in request_interests, "
			"0 in response_interests", unit_log_get());
	EXPECT_EQ(0, unit_list_length(&self->hsk.request_interests));
	EXPECT_EQ(0, unit_list_length(&self->hsk.response_interests));
	homa_rpc_unlock(rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__request_arrives_while_sleeping)
{
	struct homa_rpc *rpc;
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
		        1, 20000, 100);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	
	hook_rpc = srpc;
	mock_schedule_hook = ready_hook;
	rpc = homa_wait_for_message(&self->hsk, HOMA_RECV_REQUEST, 0,
			&self->addr);
	EXPECT_EQ(srpc, rpc);
	EXPECT_STREQ("wake_up_process pid 0; 0 in ready_requests, "
			"0 in ready_responses, 0 in request_interests, "
			"0 in response_interests", unit_log_get());
	EXPECT_EQ(0, unit_list_length(&self->hsk.request_interests));
	homa_rpc_unlock(rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__explicit_rpc_deleted_while_sleeping)
{
	struct homa_rpc *rpc;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	
	hook_rpc = crpc;
	mock_schedule_hook = delete_hook;
	rpc = homa_wait_for_message(&self->hsk, HOMA_RECV_RESPONSE,
			self->client_id, &self->addr);
	EXPECT_EQ(EINVAL, -PTR_ERR(rpc));
}
TEST_F(homa_incoming, homa_wait_for_message__rpc_deleted_after_matching)
{
	struct homa_rpc *rpc;
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc1);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2, 20000, 1600);
	EXPECT_NE(NULL, crpc2);
	unit_log_clear();
	
	hook_rpc = crpc1;
	delete_count = 1;
	mock_spin_lock_hook = delete_hook;
	rpc = homa_wait_for_message(&self->hsk,
			HOMA_RECV_RESPONSE|HOMA_RECV_NONBLOCKING, 0,
			&self->addr);
	EXPECT_EQ(crpc2, rpc);
	EXPECT_SUBSTR("RPC appears to have been deleted",
			unit_log_get());
	homa_rpc_unlock(rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__socket_shutdown_while_sleeping)
{
	struct homa_rpc *rpc;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	
	hook_hsk = &self->hsk;
	mock_schedule_hook = shutdown_hook;
	rpc = homa_wait_for_message(&self->hsk,
			HOMA_RECV_RESPONSE|HOMA_RECV_REQUEST, 0, &self->addr);
	EXPECT_EQ(ESHUTDOWN, -PTR_ERR(rpc));
}
TEST_F(homa_incoming, homa_wait_for_message__id_arrives_after_looping_back)
{
	struct homa_rpc *rpc;
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc1);
	unit_log_clear();
	
	hook_rpc = crpc1;
	poll_hook3_count = 0;
	mock_schedule_hook = poll_hook3;
	rpc = homa_wait_for_message(&self->hsk, 0, self->client_id, &self->addr);
	EXPECT_EQ(crpc1, rpc);
	EXPECT_EQ(NULL, crpc1->interest);
	EXPECT_EQ(3, poll_hook3_count);
	homa_rpc_unlock(rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__signal)
{
	struct homa_rpc *rpc;
	
	mock_signal_pending = 1;
	rpc = homa_wait_for_message(&self->hsk, HOMA_RECV_REQUEST, 0,
			&self->addr);
	EXPECT_EQ(EINTR, -PTR_ERR(rpc));
}

TEST_F(homa_incoming, homa_rpc_ready__interest_on_rpc)
{
	struct homa_interest interest;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(NULL, crpc->interest);
	unit_log_clear();
	
	homa_interest_init(&interest);
	interest.thread = &mock_task;
	interest.reg_rpc = crpc;
	crpc->interest = &interest;
	homa_rpc_ready(crpc);
	crpc->interest = NULL;
	EXPECT_EQ(crpc->id, atomic_long_read(&interest.id));
	EXPECT_EQ(NULL, interest.reg_rpc);
	EXPECT_EQ(NULL, crpc->interest);
	EXPECT_STREQ("wake_up_process pid 0", unit_log_get());
}
TEST_F(homa_incoming, homa_rpc_ready__response_interests)
{
	struct homa_interest interest;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(NULL, crpc->interest);
	unit_log_clear();
	
	homa_interest_init(&interest);
	interest.thread = &mock_task;
	list_add_tail(&interest.response_links, &self->hsk.response_interests);
	homa_rpc_ready(crpc);
	EXPECT_EQ(crpc->id, atomic_long_read(&interest.id));
	EXPECT_EQ(0, unit_list_length(&self->hsk.response_interests));
	EXPECT_STREQ("wake_up_process pid 0", unit_log_get());
}
TEST_F(homa_incoming, homa_rpc_ready__queue_on_ready_responses)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	
	homa_rpc_ready(crpc);
	EXPECT_STREQ("sk->sk_data_ready invoked", unit_log_get());
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_responses));
}
TEST_F(homa_incoming, homa_rpc_ready__request_interests)
{
	struct homa_interest interest;
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
		        self->server_id, 20000, 100);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	
	homa_interest_init(&interest);
	interest.thread = &mock_task;
	list_add_tail(&interest.request_links, &self->hsk.request_interests);
	homa_rpc_ready(srpc);
	EXPECT_EQ(srpc->id, atomic_long_read(&interest.id));
	EXPECT_EQ(0, unit_list_length(&self->hsk.request_interests));
	EXPECT_STREQ("wake_up_process pid 0", unit_log_get());
}
TEST_F(homa_incoming, homa_rpc_ready__queue_on_ready_requests)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
		        1, 20000, 100);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	
	homa_rpc_ready(srpc);
	EXPECT_STREQ("sk->sk_data_ready invoked", unit_log_get());
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_requests));
}

TEST_F(homa_incoming, homa_incoming_sysctl_changed__grant_nonfifo)
{
	cpu_khz = 2000000;
	self->homa.poll_usecs = 40;
	homa_incoming_sysctl_changed(&self->homa);
	EXPECT_EQ(80000, self->homa.poll_cycles);
}
TEST_F(homa_incoming, homa_incoming_sysctl_changed__poll_cycles)
{
	self->homa.grant_increment = 10000;
	self->homa.grant_fifo_fraction = 0;
	homa_incoming_sysctl_changed(&self->homa);
	EXPECT_EQ(0, self->homa.grant_nonfifo);
	
	self->homa.grant_fifo_fraction = 100;
	homa_incoming_sysctl_changed(&self->homa);
	EXPECT_EQ(90000, self->homa.grant_nonfifo);
	
	self->homa.grant_fifo_fraction = 500;
	homa_incoming_sysctl_changed(&self->homa);
	EXPECT_EQ(10000, self->homa.grant_nonfifo);
	
	self->homa.grant_fifo_fraction = 2000;
	homa_incoming_sysctl_changed(&self->homa);
	EXPECT_EQ(10000, self->homa.grant_nonfifo);
}