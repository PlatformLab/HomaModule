#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

/* The following variable (and function) are used via mock_schedule_hook
 * to mark an RPC ready.
 */
struct homa_rpc *hook_rpc = NULL;
void ready_hook(void)
{
	homa_rpc_ready(hook_rpc);
	unit_log_printf("; ",
			"%d in ready_requests, %d in ready_responses, "
			"%d in request_interests, %d in response_interests",
			unit_list_length(&hook_rpc->hsk->ready_requests),
			unit_list_length(&hook_rpc->hsk->ready_responses),
			unit_list_length(&hook_rpc->hsk->request_interests),
			unit_list_length(&hook_rpc->hsk->response_interests));
}

/* The following function is used via mock_schedule_hook to delete an RPC. */
void delete_hook(void)
{
	homa_rpc_free(hook_rpc);
}

FIXTURE(homa_incoming) {
	__be32 client_ip;
	int client_port;
	__be32 server_ip;
	int server_port;
	__u64 rpcid;
	struct sockaddr_in server_addr;
	struct homa homa;
	struct homa_sock hsk;
	struct data_header data;
	struct homa_message_in message;
};
FIXTURE_SETUP(homa_incoming)
{
	self->client_ip = unit_get_in_addr("196.168.0.1");
	self->client_port = 40000;
	self->server_ip = unit_get_in_addr("1.2.3.4");
	self->server_port = 99;
	self->rpcid = 12345;
	self->server_addr.sin_family = AF_INET;
	self->server_addr.sin_addr.s_addr = self->server_ip;
	self->server_addr.sin_port =  htons(self->server_port);
	homa_init(&self->homa);
	self->homa.flags |= HOMA_FLAG_DONT_THROTTLE;
	mock_sock_init(&self->hsk, &self->homa, 0, 0);
	self->data = (struct data_header){.common = {
			.sport = htons(self->client_port),
	                .dport = htons(self->server_port), .id = self->rpcid,
			.type = DATA}, .message_length = htonl(10000), .offset = 0,
			.unscheduled = htonl(10000), .cutoff_version = 0,
		        .retransmit = 0};
	homa_message_in_init(&self->message, 10000, 10000);
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_incoming)
{
	homa_message_in_destroy(&self->message);
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_incoming, homa_message_in_init)
{
	struct homa_message_in msgin;
	homa_message_in_init(&msgin, 127, 10000);
	EXPECT_EQ(127, msgin.granted);
	homa_message_in_init(&msgin, 128, 10000);
	homa_message_in_init(&msgin, 130, 10000);
	homa_message_in_init(&msgin, 0x1000, 10000);
	homa_message_in_init(&msgin, 0x3000, 10000);
	homa_message_in_init(&msgin, 1000000, 10000);
	EXPECT_EQ(10000, msgin.granted);
	homa_message_in_init(&msgin, 2000000, 10000);
	EXPECT_EQ(255, unit_get_metrics()->small_msg_bytes[1]);
	EXPECT_EQ(130, unit_get_metrics()->small_msg_bytes[2]);
	EXPECT_EQ(0x1000, unit_get_metrics()->small_msg_bytes[63]);
	EXPECT_EQ(0x3000, unit_get_metrics()->medium_msg_bytes[11]);
	EXPECT_EQ(0, unit_get_metrics()->medium_msg_bytes[15]);
	EXPECT_EQ(3000000, unit_get_metrics()->large_msg_bytes);
}

TEST_F(homa_incoming, homa_add_packet__basics)
{
	self->data.offset = htonl(1400);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	
	self->data.offset = htonl(4200);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 800, 4200));
	
	self->data.offset = 0;
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 0/10000 P1; DATA 1400/10000 P1; DATA 4200/10000 P1",
			unit_log_get());
	EXPECT_EQ(5800, self->message.bytes_remaining);
	
	unit_log_clear();
	self->data.offset = htonl(2800);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 2800));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 0/10000 P1; DATA 1400/10000 P1; DATA 2800/10000 P1; "
			"DATA 4200/10000 P1", unit_log_get());
}
TEST_F(homa_incoming, homa_add_packet__redundant_packet)
{
	self->data.offset = htonl(1400);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 1400/10000 P1", unit_log_get());
}
TEST_F(homa_incoming, homa_add_packet__overlapping_ranges)
{
	self->data.offset = htonl(1400);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	self->data.offset = htonl(2000);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 2000));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 1400/10000 P1; DATA 2000/10000 P1", unit_log_get());
	EXPECT_EQ(8000, self->message.bytes_remaining);
	
	unit_log_clear();
	self->data.offset = htonl(1800);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1800));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 1400/10000 P1; DATA 2000/10000 P1", unit_log_get());
	EXPECT_EQ(8000, self->message.bytes_remaining);
}

TEST_F(homa_incoming, homa_message_in_copy_data)
{
	int count;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 1000, 4000);
	EXPECT_NE(NULL, crpc);
	self->data.message_length = htonl(4000);
	self->data.offset = htonl(1000);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 101000), crpc);
	self->data.offset = htonl(1800);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 201800), crpc);
	self->data.offset = htonl(3200);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			800, 303200), crpc);
	unit_log_clear();
	count = homa_message_in_copy_data(&crpc->msgin, NULL,
			5000);
	EXPECT_STREQ("skb_copy_datagram_iter 0-1399; "
		"skb_copy_datagram_iter 101400-102399; "
		"skb_copy_datagram_iter 202400-203199; "
		"skb_copy_datagram_iter 303200-303999", unit_log_get());
	EXPECT_EQ(4000, count);
	
	unit_log_clear();
	count = homa_message_in_copy_data(&crpc->msgin, NULL, 200);
	EXPECT_STREQ("skb_copy_datagram_iter 0-199", unit_log_get());
	EXPECT_EQ(200, count);
}

TEST_F(homa_incoming, homa_get_resend_range__uninitialized_rpc)
{
	struct homa_message_in msgin;
	struct resend_header resend;
	
	msgin.total_length = -1;
	homa_get_resend_range(&msgin, &resend);
	EXPECT_EQ(0, resend.offset);
	EXPECT_EQ(HOMA_MAX_DATA_PER_PACKET, ntohl(resend.length));
}
TEST_F(homa_incoming, homa_get_resend_range__various_gaps)
{
	struct resend_header resend;
	
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	homa_get_resend_range(&self->message, &resend);
	EXPECT_EQ(1400, ntohl(resend.offset));
	EXPECT_EQ(8600, ntohl(resend.length));
	
	self->data.offset = htonl(8600);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 8600, 8600));
	homa_get_resend_range(&self->message, &resend);
	EXPECT_EQ(1400, ntohl(resend.offset));
	EXPECT_EQ(7200, ntohl(resend.length));
	
	self->data.offset = htonl(6000);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 6000, 6000));
	homa_get_resend_range(&self->message, &resend);
	EXPECT_EQ(1400, ntohl(resend.offset));
	EXPECT_EQ(4600, ntohl(resend.length));
	
	self->data.offset = htonl(4600);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 4600, 4600));
	homa_get_resend_range(&self->message, &resend);
	EXPECT_EQ(1400, ntohl(resend.offset));
	EXPECT_EQ(3200, ntohl(resend.length));
}
TEST_F(homa_incoming, homa_get_resend_range__received_past_granted)
{
	struct resend_header resend;
	
	self->data.message_length = htonl(2500);
	self->data.offset = htonl(0);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));
	self->data.offset = htonl(1500);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));
	self->data.offset = htonl(2900);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1100, 0));
	self->message.granted = 2000;
	homa_get_resend_range(&self->message, &resend);
	EXPECT_EQ(1400, ntohl(resend.offset));
	EXPECT_EQ(100, ntohl(resend.length));
}
TEST_F(homa_incoming, homa_get_resend_range__gap_at_beginning)
{
	struct resend_header resend;
	
	self->data.offset = htonl(6200);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 6200));
	homa_get_resend_range(&self->message, &resend);
	EXPECT_EQ(0, ntohl(resend.offset));
	EXPECT_EQ(6200, ntohl(resend.length));
}

TEST_F(homa_incoming, homa_pkt_dispatch__new_server_rpc)
{
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->client_ip, &self->data.common, 1400, 0));
	EXPECT_EQ(1, unit_list_length(&self->hsk.server_rpcs));
	EXPECT_EQ(1, mock_skb_count());
}
TEST_F(homa_incoming, homa_pkt_dispatch__existing_server_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 10000, 100);
	EXPECT_NE(NULL, srpc);
	EXPECT_EQ(8600, srpc->msgin.bytes_remaining);
	self->data.offset = htonl(1400);
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->client_ip, &self->data.common, 1400, 0));
	EXPECT_EQ(7200, srpc->msgin.bytes_remaining);
}
TEST_F(homa_incoming, homa_pkt_dispatch__unknown_source)
{
	self->data.common.sport = htons(100);
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->client_ip, &self->data.common, 1400, 0));
	EXPECT_EQ(1, mock_skb_count());
}
TEST_F(homa_incoming, homa_pkt_dispatch__cant_create_rpc)
{
	mock_kmalloc_errors = 1;
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->client_ip, &self->data.common, 1400, 0));
	EXPECT_EQ(0, unit_list_length(&self->hsk.server_rpcs));
	EXPECT_EQ(0, mock_skb_count());
}
TEST_F(homa_incoming, homa_pkt_dispatch__cutoffs_for_unknown_client_rpc)
{
	struct homa_peer *peer;
	struct cutoffs_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.id = 99999, .type = CUTOFFS},
		        .unsched_cutoffs = {htonl(10), htonl(9), htonl(8),
			htonl(7), htonl(6), htonl(5), htonl(4), htonl(3)},
			.cutoff_version = 400};
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->server_ip, &h.common, 0, 0));
	peer = homa_peer_find(&self->homa.peers, self->server_ip,
			&self->hsk.inet);
	ASSERT_FALSE(IS_ERR(peer));
	EXPECT_EQ(400, peer->cutoff_version);
	EXPECT_EQ(9, peer->unsched_cutoffs[1]);
	EXPECT_EQ(3, peer->unsched_cutoffs[7]);
}
TEST_F(homa_incoming, homa_pkt_dispatch__unknown_client_rpc)
{
	struct grant_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.id = 99999, .type = GRANT},
		        .offset = htonl(11200),
			.priority = 3};
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->client_ip, &h.common, 0, 0));
	EXPECT_EQ(1, unit_get_metrics()->unknown_rpcs);
}
TEST_F(homa_incoming, homa_pkt_dispatch__existing_client_rpc)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(11200, crpc->msgout.granted);
	unit_log_clear();
	
	struct grant_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.id = self->rpcid, .type = GRANT},
		        .offset = htonl(11200),
			.priority = 3};
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->server_ip, &h.common, 0, 0));
	EXPECT_EQ(11200, crpc->msgout.granted);
}
TEST_F(homa_incoming, homa_pkt_dispatch__unknown_type)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(11200, crpc->msgout.granted);
	unit_log_clear();
	
	struct common_header h = {.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.id = self->rpcid, .type = 99};
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->client_ip, &h, 0, 0));
	EXPECT_EQ(1, unit_get_metrics()->unknown_packet_types);
}

TEST_F(homa_incoming, homa_data_pkt__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 1000, 1600);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	self->data.message_length = htonl(1600);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 0), crpc);
	EXPECT_EQ(RPC_INCOMING, crpc->state);
	EXPECT_EQ(0, unit_list_length(&self->hsk.ready_responses));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(200, crpc->msgin.bytes_remaining);
	
	unit_log_clear();
	self->data.offset = htonl(1400);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			200, 1400), crpc);
	EXPECT_EQ(RPC_READY, crpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_responses));
	EXPECT_EQ(0, crpc->msgin.bytes_remaining);
}
TEST_F(homa_incoming, homa_data_pkt__wrong_rpc_state)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 1400, 5000);
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
			self->server_port, self->rpcid, 1000, 2000);
	EXPECT_NE(NULL, crpc);
	
	crpc->state = RPC_READY;
	self->data.message_length = htonl(2000);
	self->data.offset = htonl(1400);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			600, 1400), crpc);
	EXPECT_EQ(600, crpc->msgin.bytes_remaining);
	crpc->state = RPC_INCOMING;
}
TEST_F(homa_incoming, homa_data_pkt__send_grant)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 100000, 1000);
	EXPECT_NE(NULL, srpc);
	EXPECT_STREQ("xmit GRANT 12600@0", unit_log_get());
	EXPECT_EQ(12600, srpc->msgin.granted);
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
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->client_ip, &self->data.common, 1400, 0));
	EXPECT_STREQ("xmit CUTOFFS from 0.0.0.0:0, dport 40000, id 12345, "
		"length 48 prio 7, cutoffs 19 18 17 16 15 14 13 12, "
		"version 2", unit_log_get());
	
	/* Try again, but this time no comments should be sent because
	 * no time has elapsed since the last cutoffs were sent.
	 */
	unit_log_clear();
	self->homa.cutoff_version = 3;
	self->data.offset = 1400;
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->client_ip, &self->data.common, 1400, 0));
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_incoming, homa_data_pkt__cutoffs_up_to_date)
{
	self->homa.cutoff_version = 123;
	self->data.cutoff_version = htons(123);
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->client_ip, &self->data.common, 1400, 0));
	EXPECT_STREQ("", unit_log_get());
}

TEST_F(homa_incoming, homa_grant_pkt__basics)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 100, 20000);
	EXPECT_NE(NULL, srpc);
	homa_xmit_data(srpc);
	unit_log_clear();
	
	struct grant_header h = {{.sport = htons(srpc->dport),
	                .dport = htons(self->hsk.server_port),
			.id = srpc->id, .type = GRANT},
		        .offset = htonl(12600),
			.priority = 3};
	homa_pkt_dispatch((struct sock *)&self->hsk,
			mock_skb_new(self->client_ip, &h.common, 0, 0));
	EXPECT_EQ(12600, srpc->msgout.granted);
	EXPECT_STREQ("xmit DATA 11200/20000 P3", unit_log_get());
	
	/* Don't let grant offset go backwards. */
	h.offset = htonl(10000);
	unit_log_clear();
	homa_pkt_dispatch((struct sock *)&self->hsk,
			mock_skb_new(self->client_ip, &h.common, 0, 0));
	EXPECT_EQ(12600, srpc->msgout.granted);
	EXPECT_STREQ("", unit_log_get());
	
	/* Wrong state. */
	h.offset = htonl(20000);
	srpc->state = RPC_INCOMING;
	unit_log_clear();
	homa_pkt_dispatch((struct sock *)&self->hsk,
			mock_skb_new(self->client_ip, &h.common, 0, 0));
	EXPECT_EQ(12600, srpc->msgout.granted);
	EXPECT_STREQ("", unit_log_get());
	
	/* Must restore old state to avoid potential crashes. */
	srpc->state = RPC_OUTGOING;
}
TEST_F(homa_incoming, homa_grant_pkt__grant_past_end_of_message)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	
	struct grant_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.id = crpc->id, .type = GRANT},
		        .offset = htonl(25000),
			.priority = 3};
	homa_pkt_dispatch((struct sock *)&self->hsk,
			mock_skb_new(self->client_ip, &h.common, 0, 0));
	EXPECT_EQ(20000, crpc->msgout.granted);
}
TEST_F(homa_incoming, homa_grant_pkt__delete_server_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 100, 20000);
	EXPECT_NE(NULL, srpc);
	EXPECT_FALSE(list_empty(&self->hsk.server_rpcs));

	struct grant_header h = {{.sport = htons(self->client_port),
	                .dport = htons(self->server_port),
			.id = srpc->id, .type = GRANT},
		        .offset = htonl(25000),
			.priority = 3};
	homa_pkt_dispatch((struct sock *)&self->hsk,
			mock_skb_new(self->client_ip, &h.common, 0, 0));
	EXPECT_TRUE(list_empty(&self->hsk.server_rpcs));
}

TEST_F(homa_incoming, homa_resend_pkt__unknown_rpc_from_client)
{
	struct resend_header h = {{.sport = htons(self->client_port),
	                .dport = htons(self->server_port),
			.id = 99999, .type = RESEND},
		        .offset = 0,
			.length = 0,
			.priority = 3};
	mock_xmit_log_verbose = 1;
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->client_ip, &h.common, 0, 0));
	EXPECT_STREQ("xmit RESTART from 0.0.0.0:99, dport 40000, id 99999, "
			"length 48 prio 7", unit_log_get());
}
TEST_F(homa_incoming, homa_resend_pkt__unknown_rpc_from_server)
{
	struct resend_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.id = 99999, .type = RESEND},
		        .offset = 0,
			.length = 0,
			.priority = 3};
	mock_xmit_log_verbose = 1;
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->client_ip, &h.common, 0, 0));
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_incoming, homa_resend_pkt__server_sends_busy)
{
	struct resend_header h = {{.sport = htons(self->client_port),
	                .dport = htons(self->server_port),
			.id = self->rpcid, .type = RESEND},
		        .offset = htonl(100),
			.length = htonl(200),
			.priority = 3};
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_READY,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 100, 20000);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->client_ip, &h.common, 0, 0));
	EXPECT_STREQ("xmit BUSY", unit_log_get());
}
TEST_F(homa_incoming, homa_resend_pkt__client_not_outgoing)
{
	struct resend_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.id = self->rpcid, .type = RESEND},
		        .offset = htonl(100),
			.length = htonl(200),
			.priority = 3};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 2000, 100);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->server_ip, &h.common, 0, 0));
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_incoming, homa_resend_pkt__send_busy_instead_of_data)
{
	struct resend_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.id = self->rpcid, .type = RESEND},
		        .offset = htonl(100),
			.length = htonl(200),
			.priority = 3};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 2000, 100);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->server_ip, &h.common, 0, 0));
	EXPECT_STREQ("xmit BUSY", unit_log_get());
}
TEST_F(homa_incoming, homa_resend_pkt__client_send_data)
{
	struct resend_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.id = self->rpcid, .type = RESEND},
		        .offset = htonl(100),
			.length = htonl(200),
			.priority = 3};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 2000, 100);
	EXPECT_NE(NULL, crpc);
	homa_xmit_data(crpc);
	unit_log_clear();
	
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->server_ip, &h.common, 0, 0));
	EXPECT_STREQ("xmit DATA retrans 0/2000 P3", unit_log_get());
}
TEST_F(homa_incoming, homa_resend_pkt__server_send_data)
{
	struct resend_header h = {{.sport = htons(self->client_port),
	                .dport = htons(self->server_port),
			.id = self->rpcid, .type = RESEND},
		        .offset = htonl(100),
			.length = htonl(2000),
			.priority = 4};
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 100, 20000);
	EXPECT_NE(NULL, srpc);
	homa_xmit_data(srpc);
	unit_log_clear();
	
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->client_ip, &h.common, 0, 0));
	EXPECT_STREQ("xmit DATA retrans 0/20000 P4; "
		"xmit DATA retrans 1400/20000 P4", unit_log_get());
}

TEST_F(homa_incoming, homa_restart_pkt_basics)
{
	struct restart_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.id = self->rpcid, .type = RESTART}};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 2000, 2000);
	EXPECT_NE(NULL, crpc);
	homa_xmit_data(crpc);
	unit_log_clear();
	
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->server_ip, &h.common, 0, 0));
	EXPECT_STREQ("homa_remove_from_grantable invoked; "
		"xmit DATA 0/2000 P6; xmit DATA 1400/2000 P6",
		unit_log_get());
	EXPECT_EQ(-1, crpc->msgin.total_length);
}
TEST_F(homa_incoming, homa_restart_pkt__rpc_ready)
{
	struct restart_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.id = self->rpcid, .type = RESTART}};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 2000, 2000);
	EXPECT_NE(NULL, crpc);
	EXPECT_STREQ("READY", homa_symbol_for_state(crpc));
	unit_log_clear();
	
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->server_ip, &h.common, 0, 0));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_STREQ("READY", homa_symbol_for_state(crpc));
}
	
TEST_F(homa_incoming, homa_cutoffs_pkt_basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(11200, crpc->msgout.granted);
	unit_log_clear();
	
	struct cutoffs_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.id = self->rpcid, .type = CUTOFFS},
		        .unsched_cutoffs = {htonl(10), htonl(9), htonl(8),
			htonl(7), htonl(6), htonl(5), htonl(4), htonl(3)},
			.cutoff_version = 400};
	homa_pkt_dispatch((struct sock *) &self->hsk, mock_skb_new(
			self->server_ip, &h.common, 0, 0));
	EXPECT_EQ(400, crpc->peer->cutoff_version);
	EXPECT_EQ(9, crpc->peer->unsched_cutoffs[1]);
	EXPECT_EQ(3, crpc->peer->unsched_cutoffs[7]);
}
TEST_F(homa_incoming, homa_cutoffs__cant_find_peer)
{	
	struct homa_peer *peer;
	struct cutoffs_header h = {{.sport = htons(self->server_port),
	                .dport = htons(self->client_port),
			.id = self->rpcid, .type = CUTOFFS},
		        .unsched_cutoffs = {htonl(10), htonl(9), htonl(8),
			htonl(7), htonl(6), htonl(5), htonl(4), htonl(3)},
			.cutoff_version = 400};
	struct sk_buff *skb = mock_skb_new(self->server_ip, &h.common, 0, 0);
	mock_kmalloc_errors = 1;
	homa_cutoffs_pkt(skb, &self->hsk);
	EXPECT_EQ(1, unit_get_metrics()->peer_kmalloc_errors);
	peer = homa_peer_find(&self->homa.peers, self->server_ip,
			&self->hsk.inet);
	ASSERT_FALSE(IS_ERR(peer));
	EXPECT_EQ(0, peer->cutoff_version);
}

TEST_F(homa_incoming, homa_manage_grants__stop_tracking_when_fully_granted)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 20000, 100);
	EXPECT_NE(NULL, srpc);
	EXPECT_TRUE(srpc->msgin.possibly_in_grant_queue);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request 12345, remaining 18600", unit_log_get());
	
	srpc->msgin.granted = 20000;
	homa_manage_grants(&self->homa, srpc);
	EXPECT_FALSE(srpc->msgin.possibly_in_grant_queue);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_incoming, homa_manage_grants__insert_in_order)
{
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 100000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 2, 50000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 3, 120000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 4, 70000, 100);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request 2, remaining 48600; "
			"request 4, remaining 68600; "
			"request 1, remaining 98600; "
			"request 3, remaining 118600", unit_log_get());
}
TEST_F(homa_incoming, homa_manage_grants__adjust_priority_order)
{
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 2, 30000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 3, 40000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 4, 50000, 100);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request 1, remaining 18600; "
			"request 2, remaining 28600; "
			"request 3, remaining 38600; "
			"request 4, remaining 48600", unit_log_get());

	struct homa_rpc *srpc = homa_find_server_rpc(&self->hsk,
			self->client_ip, self->client_port, 3);
	EXPECT_NE(NULL, srpc);
	srpc->msgin.bytes_remaining = 28600;
	homa_manage_grants(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request 1, remaining 18600; "
			"request 2, remaining 28600; "
			"request 3, remaining 28600; "
			"request 4, remaining 48600", unit_log_get());
	
	srpc->msgin.bytes_remaining = 28599;
	homa_manage_grants(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request 1, remaining 18600; "
			"request 3, remaining 28599; "
			"request 2, remaining 28600; "
			"request 4, remaining 48600", unit_log_get());

	srpc = homa_find_server_rpc(&self->hsk, self->client_ip,
			self->client_port, 4);
	EXPECT_NE(NULL, srpc);
	srpc->msgin.bytes_remaining = 1000;
	homa_manage_grants(&self->homa, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request 4, remaining 1000; "
			"request 1, remaining 18600; "
			"request 3, remaining 28599; "
			"request 2, remaining 28600", unit_log_get());
}
TEST_F(homa_incoming, homa_manage_grants__pick_message_to_grant)
{
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 2, 30000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 3, 40000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 4, 50000, 100);
	
	/* Initially, all messages have been granted as much as possible. */
	struct homa_rpc *srpc = homa_find_server_rpc(&self->hsk,
			self->client_ip, self->client_port, 3);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	homa_manage_grants(&self->homa, srpc);
	EXPECT_STREQ("", unit_log_get());
	
	/* Messages that need grants are beyond max_overcommit. */
	self->homa.max_overcommit = 2;
	srpc->msgin.bytes_remaining -= 1400;
	unit_log_clear();
	homa_manage_grants(&self->homa, srpc);
	EXPECT_STREQ("", unit_log_get());
	
	/* There is a message to grant. */
	self->homa.max_overcommit = 4;
	unit_log_clear();
	homa_manage_grants(&self->homa, srpc);
	EXPECT_STREQ("xmit GRANT 14000@1", unit_log_get());
}
TEST_F(homa_incoming, homa_manage_grants__choose_priority_level)
{
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 40000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 2, 30000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 3, 20000, 100);
	EXPECT_STREQ("xmit GRANT 12600@0; "
			"xmit GRANT 12600@1; "
			"xmit GRANT 12600@2", unit_log_get());

	struct homa_rpc *srpc = homa_find_server_rpc(&self->hsk,
			self->client_ip, self->client_port, 1);
	EXPECT_NE(NULL, srpc);
	
	/* Share lowest priority level. */
	self->homa.min_prio = 2;
	srpc->msgin.bytes_remaining -= 1400;
	unit_log_clear();
	homa_manage_grants(&self->homa, srpc);
	EXPECT_STREQ("xmit GRANT 14000@2", unit_log_get());
}
TEST_F(homa_incoming, homa_manage_grants__many_messages_of_same_size)
{
	self->homa.max_overcommit = 2;
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	EXPECT_SUBSTR("xmit GRANT", unit_log_get());
	unit_log_clear();
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 2, 20000, 100);
	EXPECT_SUBSTR("xmit GRANT", unit_log_get());
	unit_log_clear();
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 3, 20000, 100);
	EXPECT_STREQ("", unit_log_get());
	unit_log_clear();
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 4, 20000, 100);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_incoming, homa_manage_grants__grant_after_rpc_deleted)
{
	self->homa.max_overcommit = 2;
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 2, 30000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 3, 40000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 4, 50000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 5, 60000, 100);

	struct homa_rpc *srpc = homa_find_server_rpc(&self->hsk,
			self->client_ip, self->client_port, 1);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	homa_rpc_free(srpc);
	EXPECT_STREQ("homa_remove_from_grantable invoked; xmit GRANT 12600@2",
			unit_log_get());
}

TEST_F(homa_incoming, homa_remove_from_grantable__basics)
{
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request 1, remaining 18600", unit_log_get());
	struct homa_rpc *srpc = homa_find_server_rpc(&self->hsk,
			self->client_ip, self->client_port, 1);
	EXPECT_NE(NULL, srpc);
	
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
};
TEST_F(homa_incoming, homa_remove_from_grantable__grant_to_other_message)
{
	self->homa.max_overcommit = 1;
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 1, 20000, 100);
	unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
			self->server_ip, self->client_port, 2, 30000, 100);

	struct homa_rpc *srpc = homa_find_server_rpc(&self->hsk,
			self->client_ip, self->client_port, 1);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	homa_manage_grants(&self->homa, srpc);
	EXPECT_STREQ("", unit_log_get());
	
	unit_log_clear();
	mock_xmit_log_verbose = 1;
	homa_rpc_free(srpc);
	EXPECT_SUBSTR("xmit GRANT", unit_log_get());
	EXPECT_SUBSTR("id 2,", unit_log_get());
}

TEST_F(homa_incoming, homa_rpc_abort)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 20000, 1600);
	unit_log_clear();
	homa_rpc_abort(crpc, -EFAULT);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_responses));
	EXPECT_EQ(RPC_READY, crpc->state);
	EXPECT_EQ(EFAULT, -crpc->error);
	EXPECT_STREQ("homa_remove_from_grantable invoked; "
			"sk->sk_data_ready invoked", unit_log_get());
}

TEST_F(homa_incoming, homa_dest_abort)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 5000, 1600);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 5000, 1600);
	struct homa_rpc *crpc3 = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip+1,
			self->server_port, self->rpcid, 5000, 1600);
	EXPECT_NE(NULL, crpc1);
	unit_log_clear();
	homa_dest_abort(&self->homa, self->server_ip, -EPROTONOSUPPORT);
	EXPECT_STREQ("homa_remove_from_grantable invoked; "
			"sk->sk_data_ready invoked", unit_log_get());
	EXPECT_EQ(2, unit_list_length(&self->hsk.ready_responses));
	EXPECT_EQ(RPC_READY, crpc1->state);
	EXPECT_EQ(EPROTONOSUPPORT, -crpc1->error);
	EXPECT_EQ(0, -crpc2->error);
	EXPECT_EQ(RPC_OUTGOING, crpc3->state);
}

TEST_F(homa_incoming, homa_wait_for_message__bogus_id)
{
	int result;
	struct homa_rpc *rpc = NULL;
	result = homa_wait_for_message(&self->hsk, HOMA_RECV_RESPONSE, 44,
			&rpc);
	EXPECT_EQ(EINVAL, -result);
	EXPECT_EQ(NULL, rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__id_already_has_interest)
{
	int result;
	struct homa_interest interest;
	struct homa_rpc *rpc = NULL;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	
	crpc->interest = &interest;
	result = homa_wait_for_message(&self->hsk, HOMA_RECV_RESPONSE,
			self->rpcid, &rpc);
	crpc->interest = NULL;
	EXPECT_EQ(EINVAL, -result);
	EXPECT_EQ(NULL, rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__id_not_ready)
{
	int result;
	struct homa_rpc *rpc = NULL;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 20000, 1600);
	unit_client_rpc(&self->hsk, RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->rpcid+1, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	
	result = homa_wait_for_message(&self->hsk,
			HOMA_RECV_RESPONSE|HOMA_RECV_NONBLOCKING,
			self->rpcid, &rpc);
	EXPECT_EQ(EAGAIN, -result);
	EXPECT_EQ(NULL, rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__return_specific_id)
{
	int result;
	struct homa_rpc *rpc = NULL;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	
	result = homa_wait_for_message(&self->hsk,
			HOMA_RECV_RESPONSE|HOMA_RECV_NONBLOCKING,
			self->rpcid, &rpc);
	EXPECT_EQ(0, -result);
	EXPECT_EQ(crpc, rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__return_from_ready_responses)
{
	int result;
	struct homa_rpc *rpc = NULL;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	
	result = homa_wait_for_message(&self->hsk,
			HOMA_RECV_RESPONSE|HOMA_RECV_NONBLOCKING, 0, &rpc);
	EXPECT_EQ(0, -result);
	EXPECT_EQ(crpc, rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__return_from_ready_requests)
{
	int result;
	struct homa_rpc *rpc = NULL;
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_READY,
			self->client_ip, self->server_ip, self->client_port,
		        1, 20000, 100);
	EXPECT_NE(NULL, srpc);
	
	result = homa_wait_for_message(&self->hsk,
			HOMA_RECV_REQUEST|HOMA_RECV_NONBLOCKING, 0, &rpc);
	EXPECT_EQ(0, -result);
	EXPECT_EQ(srpc, rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__invalid_flags)
{
	int result;
	struct homa_rpc *rpc = NULL;
	result = homa_wait_for_message(&self->hsk,
			HOMA_RECV_NONBLOCKING, 0, &rpc);
	EXPECT_EQ(EINVAL, -result);
}
TEST_F(homa_incoming, homa_wait_for_message__id_arrives_while_sleeping)
{
	int result;
	struct homa_rpc *rpc = NULL;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	
	hook_rpc = crpc;
	mock_schedule_hook = ready_hook;
	result = homa_wait_for_message(&self->hsk, HOMA_RECV_RESPONSE,
			self->rpcid, &rpc);
	EXPECT_EQ(0, -result);
	EXPECT_EQ(crpc, rpc);
	EXPECT_EQ(NULL, crpc->interest);
	EXPECT_STREQ("wake_up_process; 0 in ready_requests, "
			"0 in ready_responses, 0 in request_interests, "
			"0 in response_interests", unit_log_get());
}
TEST_F(homa_incoming, homa_wait_for_message__response_arrives_while_sleeping)
{
	int result;
	struct homa_rpc *rpc = NULL;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	
	hook_rpc = crpc;
	mock_schedule_hook = ready_hook;
	result = homa_wait_for_message(&self->hsk,
			HOMA_RECV_RESPONSE|HOMA_RECV_REQUEST, 0, &rpc);
	EXPECT_EQ(0, -result);
	EXPECT_EQ(crpc, rpc);
	EXPECT_STREQ("wake_up_process; 0 in ready_requests, "
			"0 in ready_responses, 1 in request_interests, "
			"1 in response_interests", unit_log_get());
	EXPECT_EQ(0, unit_list_length(&self->hsk.request_interests));
	EXPECT_EQ(0, unit_list_length(&self->hsk.response_interests));
}
TEST_F(homa_incoming, homa_wait_for_message__request_arrives_while_sleeping)
{
	int result;
	struct homa_rpc *rpc = NULL;
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
		        1, 20000, 100);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	
	hook_rpc = srpc;
	mock_schedule_hook = ready_hook;
	result = homa_wait_for_message(&self->hsk, HOMA_RECV_REQUEST, 0, &rpc);
	EXPECT_EQ(0, -result);
	EXPECT_EQ(srpc, rpc);
	EXPECT_STREQ("wake_up_process; 0 in ready_requests, "
			"0 in ready_responses, 1 in request_interests, "
			"0 in response_interests", unit_log_get());
	EXPECT_EQ(0, unit_list_length(&self->hsk.request_interests));
}
TEST_F(homa_incoming, homa_wait_for_message__signal)
{
	int result;
	struct homa_rpc *rpc = NULL;
	
	mock_signal_pending = 1;
	result = homa_wait_for_message(&self->hsk, HOMA_RECV_REQUEST, 0, &rpc);
	EXPECT_EQ(EINTR, -result);
	EXPECT_EQ(NULL, rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__rpc_deleted_while_sleeping)
{
	int result;
	struct homa_rpc *rpc = NULL;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	
	hook_rpc = crpc;
	mock_schedule_hook = delete_hook;
	result = homa_wait_for_message(&self->hsk, HOMA_RECV_RESPONSE,
			self->rpcid, &rpc);
	EXPECT_EQ(EINVAL, -result);
	EXPECT_EQ(NULL, rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__wakeup_with_no_rpc)
{
	int result;
	struct homa_rpc *rpc = NULL;
	unit_log_clear();
	
	result = homa_wait_for_message(&self->hsk, HOMA_RECV_RESPONSE, 0, &rpc);
	EXPECT_EQ(EINVAL, -result);
	EXPECT_EQ(NULL, rpc);
}

TEST_F(homa_incoming, homa_rpc_ready__interest_on_rpc)
{
	struct homa_interest interest;
	struct homa_rpc *rpc = NULL;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(NULL, crpc->interest);
	unit_log_clear();
	
	interest.rpc = &rpc;
	interest.rpc_deleted = false;
	crpc->interest = &interest;
	homa_rpc_ready(crpc);
	crpc->interest = NULL;
	EXPECT_EQ(crpc, rpc);
	EXPECT_STREQ("wake_up_process", unit_log_get());
}
TEST_F(homa_incoming, homa_rpc_ready__first_in_response_interests)
{
	struct homa_interest interest;
	struct homa_rpc *rpc = NULL;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	EXPECT_EQ(NULL, crpc->interest);
	unit_log_clear();
	
	interest.rpc = &rpc;
	interest.rpc_deleted = false;
	list_add_tail(&interest.links, &self->hsk.response_interests);
	homa_rpc_ready(crpc);
	list_del(&interest.links);
	EXPECT_EQ(crpc, rpc);
	EXPECT_STREQ("wake_up_process", unit_log_get());
}
TEST_F(homa_incoming, homa_rpc_ready__second_in_response_interests)
{
	struct homa_interest interest1, interest2;
	struct homa_rpc *rpc1 = (struct homa_rpc *) 12345;
	struct homa_rpc *rpc2 = NULL;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	
	interest1.rpc = &rpc1;
	interest1.rpc_deleted = false;
	list_add_tail(&interest1.links, &self->hsk.response_interests);
	interest2.rpc = &rpc2;
	interest2.rpc_deleted = false;
	list_add_tail(&interest2.links, &self->hsk.response_interests);
	homa_rpc_ready(crpc);
	list_del(&interest1.links);
	list_del(&interest2.links);
	EXPECT_NE(crpc, rpc1);
	EXPECT_EQ(crpc, rpc2);
	EXPECT_STREQ("wake_up_process", unit_log_get());
}
TEST_F(homa_incoming, homa_rpc_ready__first_in_request_interests)
{
	struct homa_interest interest;
	struct homa_rpc *rpc = NULL;
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
		        1, 20000, 100);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	
	interest.rpc = &rpc;
	interest.rpc_deleted = false;
	list_add_tail(&interest.links, &self->hsk.request_interests);
	homa_rpc_ready(srpc);
	list_del(&interest.links);
	EXPECT_EQ(srpc, rpc);
	EXPECT_STREQ("wake_up_process", unit_log_get());
}
TEST_F(homa_incoming, homa_rpc_ready__queue_on_ready_responses)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 20000, 1600);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	
	homa_rpc_ready(crpc);
	EXPECT_STREQ("sk->sk_data_ready invoked", unit_log_get());
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_responses));
}