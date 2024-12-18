// SPDX-License-Identifier: BSD-2-Clause

#include "homa_impl.h"
#include "homa_offload.h"
#include "homa_peer.h"
#include "homa_pool.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

/* The following variable (and hook function) are used to mark an RPC
 * ready with an error (but only if thread is sleeping).
 */
struct homa_rpc *hook_rpc;
struct homa_sock *hook_hsk;
int delete_count;
int lock_delete_count;
int hook_granted;
void handoff_hook(char *id)
{
	if (strcmp(id, "schedule") != 0)
		return;
	if (task_is_running(current))
		return;
	hook_rpc->error = -EFAULT;
	homa_rpc_handoff(hook_rpc);
	unit_log_printf("; ",
			"%d in ready_requests, %d in ready_responses, %d in request_interests, %d in response_interests",
			unit_list_length(&hook_rpc->hsk->ready_requests),
			unit_list_length(&hook_rpc->hsk->ready_responses),
			unit_list_length(&hook_rpc->hsk->request_interests),
			unit_list_length(&hook_rpc->hsk->response_interests));
}

/* The following hook function marks an RPC ready after several calls. */
int poll_count;
void poll_hook(char *id)
{
	if (strcmp(id, "schedule") != 0)
		return;
	if (poll_count <= 0)
		return;
	poll_count--;
	if (poll_count == 0) {
		hook_rpc->error = -EFAULT;
		homa_rpc_handoff(hook_rpc);
	}
}

/* The following hook function hands off an RPC (with an error). */
void handoff_hook2(char *id)
{
	if (strcmp(id, "found_rpc") != 0)
		return;

	hook_rpc->error = -ETIMEDOUT;
	homa_rpc_handoff(hook_rpc);
}

/* The following hook function first hands off an RPC, then deletes it. */
int hook3_count;
void handoff_hook3(char *id)
{
	if (hook3_count || (strcmp(id, "found_rpc") != 0))
		return;
	hook3_count++;

	homa_rpc_handoff(hook_rpc);
	homa_rpc_free(hook_rpc);
}

/* The following hook function frees an RPC. */
void delete_hook(char *id)
{
	if (strcmp(id, "schedule") != 0)
		return;
	if (delete_count == 0)
		homa_rpc_free(hook_rpc);
	delete_count--;
}

/* The following hook function frees an RPC when it is locked. */
void lock_delete_hook(char *id)
{
	if (strcmp(id, "spin_lock") != 0)
		return;
	if (lock_delete_count == 0)
		homa_rpc_free(hook_rpc);
	lock_delete_count--;
}

/* The following function is used via unit_hook to free an RPC after it
 * has been matched in homa_wait_for_message.
 */
void match_free_hook(char *id)
{
	if (strcmp(id, "found_rpc") == 0)
		homa_rpc_free(hook_rpc);
}

/* The following hook function shuts down a socket. */
void shutdown_hook(char *id)
{
	if (strcmp(id, "schedule") != 0)
		return;
	homa_sock_shutdown(hook_hsk);
}

/* The following hook function updates hook_rpc->msgin.granted. */
int unlock_count;
void unlock_hook(char *id)
{
	if (strcmp(id, "unlock") != 0)
		return;
	if (unlock_count == 0)
		hook_rpc->msgin.granted = hook_granted;
	unlock_count--;
}

FIXTURE(homa_incoming) {
	struct in6_addr client_ip[5];
	int client_port;
	struct in6_addr server_ip[2];
	int server_port;
	__u64 client_id;
	__u64 server_id;
	union sockaddr_in_union server_addr;
	struct homa homa;
	struct homa_sock hsk;
	struct homa_sock hsk2;
	struct homa_data_hdr data;
	struct homa_interest interest;
};
FIXTURE_SETUP(homa_incoming)
{
	self->client_ip[0] = unit_get_in_addr("196.168.0.1");
	self->client_ip[1] = unit_get_in_addr("197.168.0.1");
	self->client_ip[2] = unit_get_in_addr("198.168.0.1");
	self->client_ip[3] = unit_get_in_addr("199.168.0.1");
	self->client_ip[4] = unit_get_in_addr("200.168.0.1");
	self->client_port = 40000;
	self->server_ip[0] = unit_get_in_addr("1.2.3.4");
	self->server_ip[1] = unit_get_in_addr("2.2.3.4");
	self->server_port = 99;
	self->client_id = 1234;
	self->server_id = 1235;
	homa_init(&self->homa);
	self->homa.num_priorities = 1;
	self->homa.poll_usecs = 0;
	self->homa.flags |= HOMA_FLAG_DONT_THROTTLE;
	self->homa.pacer_fifo_fraction = 0;
	self->homa.grant_fifo_fraction = 0;
	self->homa.unsched_bytes = 10000;
	self->homa.window_param = 10000;
	mock_sock_init(&self->hsk, &self->homa, 0);
	mock_sock_init(&self->hsk2, &self->homa, self->server_port);
	self->server_addr.in6.sin6_family = self->hsk.inet.sk.sk_family;
	self->server_addr.in6.sin6_addr = self->server_ip[0];
	self->server_addr.in6.sin6_port =  htons(self->server_port);
	self->data = (struct homa_data_hdr){.common = {
			.sport = htons(self->client_port),
			.dport = htons(self->server_port),
			.type = DATA,
			.sender_id = cpu_to_be64(self->client_id)},
			.message_length = htonl(10000),
			.incoming = htonl(10000), .cutoff_version = 0,
			.ack = {0, 0},
			.retransmit = 0,
			.seg = {.offset = 0}};
	unit_log_clear();
	delete_count = 0;
	lock_delete_count = 0;
}
FIXTURE_TEARDOWN(homa_incoming)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_incoming, homa_message_in_init__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	EXPECT_EQ(0, homa_message_in_init(crpc, 127, 100));
	EXPECT_EQ(100, crpc->msgin.granted);
	EXPECT_EQ(0, homa_message_in_init(crpc, 128, 500));
	EXPECT_EQ(128, crpc->msgin.granted);
	EXPECT_EQ(1, crpc->msgin.num_bpages);
}
TEST_F(homa_incoming, homa_message_in_init__pool_doesnt_exist)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_pool_destroy(self->hsk.buffer_pool);
	EXPECT_EQ(ENOMEM, -homa_message_in_init(crpc, HOMA_BPAGE_SIZE*2, 0));
	EXPECT_EQ(0, crpc->msgin.num_bpages);
}
TEST_F(homa_incoming, homa_message_in_init__no_buffers_available)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	atomic_set(&self->hsk.buffer_pool->free_bpages, 0);
	EXPECT_EQ(0, homa_message_in_init(crpc, HOMA_BPAGE_SIZE*2, 10000));
	EXPECT_EQ(0, crpc->msgin.num_bpages);
	EXPECT_EQ(0, crpc->msgin.granted);
}
TEST_F(homa_incoming, homa_message_in_init__update_metrics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	EXPECT_EQ(0, homa_message_in_init(crpc, 140, 0));
	EXPECT_EQ(0, homa_message_in_init(crpc, 130, 0));
	EXPECT_EQ(0, homa_message_in_init(crpc, 0xfff, 0));
	EXPECT_EQ(0, homa_message_in_init(crpc, 0xfff0, 0));
	EXPECT_EQ(0, homa_message_in_init(crpc, 0x3000, 0));
	EXPECT_EQ(0, homa_message_in_init(crpc, 1000000, 0));
	EXPECT_EQ(0, homa_message_in_init(crpc, 900000, 0));
	EXPECT_EQ(270, homa_metrics_per_cpu()->small_msg_bytes[2]);
	EXPECT_EQ(0xfff, homa_metrics_per_cpu()->small_msg_bytes[63]);
	EXPECT_EQ(0x3000, homa_metrics_per_cpu()->medium_msg_bytes[11]);
	EXPECT_EQ(0, homa_metrics_per_cpu()->medium_msg_bytes[15]);
	EXPECT_EQ(1900000, homa_metrics_per_cpu()->large_msg_bytes);
}

TEST_F(homa_incoming, homa_gap_retry)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk2, UNIT_RCVD_ONE_PKT,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 10000, 100);

	homa_gap_new(&srpc->msgin.gaps, 1000, 2000);
	homa_gap_new(&srpc->msgin.gaps, 4000, 6000);
	homa_gap_new(&srpc->msgin.gaps, 7000, 8000);
	self->homa.num_priorities = 8;
	unit_log_clear();

	homa_gap_retry(srpc);
	EXPECT_STREQ("xmit RESEND 1000-1999@7; "
			"xmit RESEND 4000-5999@7; "
			"xmit RESEND 7000-7999@7",
			unit_log_get());
}

TEST_F(homa_incoming, homa_add_packet__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	unit_log_clear();
	mock_ns = 5000;
	self->data.seg.offset = htonl(1400);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 800, 4200));
	EXPECT_STREQ("start 0, end 1400, time 5000; start 2800, end 4200, time 5000",
			unit_print_gaps(crpc));

	unit_log_clear();
	self->data.seg.offset = 0;
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));
	EXPECT_STREQ("start 2800, end 4200, time 5000", unit_print_gaps(crpc));
	EXPECT_EQ(6400, crpc->msgin.bytes_remaining);

	unit_log_clear();
	self->data.seg.offset = htonl(2800);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 2800));
	EXPECT_STREQ("", unit_print_gaps(crpc));
	unit_log_clear();
	unit_log_skb_list(&crpc->msgin.packets, 0);
	EXPECT_STREQ("DATA 1400@1400; DATA 800@4200; DATA 1400@0; DATA 1400@2800",
			unit_log_get());
	EXPECT_EQ(4, skb_queue_len(&crpc->msgin.packets));
}
TEST_F(homa_incoming, homa_add_packet__packet_overlaps_message_end)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	unit_log_clear();
	self->data.seg.offset = htonl(9000);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	EXPECT_EQ(0, skb_queue_len(&crpc->msgin.packets));
}
TEST_F(homa_incoming, homa_add_packet__sequential_packets)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	unit_log_clear();
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(1400);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));

	self->data.seg.offset = htonl(2800);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 2800));
	EXPECT_STREQ("", unit_print_gaps(crpc));
	EXPECT_EQ(4200, crpc->msgin.recv_end);
	EXPECT_EQ(3, skb_queue_len(&crpc->msgin.packets));
}
TEST_F(homa_incoming, homa_add_packet__new_gap)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	unit_log_clear();
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 1400, end 4200", unit_print_gaps(crpc));
	EXPECT_EQ(5600, crpc->msgin.recv_end);
	EXPECT_EQ(2, skb_queue_len(&crpc->msgin.packets));
}
TEST_F(homa_incoming, homa_add_packet__no_memory_for_new_gap)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	unit_log_clear();
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	mock_kmalloc_errors = 1;
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("", unit_print_gaps(crpc));
	EXPECT_EQ(1400, crpc->msgin.recv_end);
	EXPECT_EQ(1, skb_queue_len(&crpc->msgin.packets));
}
TEST_F(homa_incoming, homa_add_packet__packet_before_gap)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	unit_log_clear();
	self->data.seg.offset = htonl(0);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 1400, end 4200", unit_print_gaps(crpc));

	self->data.seg.offset = htonl(0);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));
	EXPECT_EQ(2, skb_queue_len(&crpc->msgin.packets));
}
TEST_F(homa_incoming, homa_add_packet__packet_straddles_start_of_gap)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	unit_log_clear();
	self->data.seg.offset = htonl(0);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 1400, end 4200", unit_print_gaps(crpc));

	self->data.seg.offset = htonl(1000);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1000));
	EXPECT_EQ(2, skb_queue_len(&crpc->msgin.packets));
}
TEST_F(homa_incoming, homa_add_packet__packet_extends_past_gap)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	unit_log_clear();
	self->data.seg.offset = htonl(0);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(2000);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 2000));
	EXPECT_STREQ("start 1400, end 2000", unit_print_gaps(crpc));

	self->data.seg.offset = htonl(1400);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	EXPECT_EQ(2, skb_queue_len(&crpc->msgin.packets));
}
TEST_F(homa_incoming, homa_add_packet__packet_at_start_of_gap)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	unit_log_clear();
	self->data.seg.offset = htonl(0);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 1400, end 4200", unit_print_gaps(crpc));

	self->data.seg.offset = htonl(1400);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	EXPECT_EQ(3, skb_queue_len(&crpc->msgin.packets));
	unit_log_clear();
	EXPECT_STREQ("start 2800, end 4200", unit_print_gaps(crpc));
}
TEST_F(homa_incoming, homa_add_packet__packet_covers_entire_gap)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	unit_log_clear();
	self->data.seg.offset = htonl(0);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(2800);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 2800));
	EXPECT_STREQ("start 1400, end 2800", unit_print_gaps(crpc));

	self->data.seg.offset = htonl(1400);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	EXPECT_EQ(3, skb_queue_len(&crpc->msgin.packets));
	EXPECT_STREQ("", unit_print_gaps(crpc));
}
TEST_F(homa_incoming, homa_add_packet__packet_beyond_end_of_gap)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	unit_log_clear();
	self->data.seg.offset = htonl(0);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 1400, end 4200", unit_print_gaps(crpc));

	self->data.seg.offset = htonl(5000);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 5000));
	EXPECT_EQ(2, skb_queue_len(&crpc->msgin.packets));
}
TEST_F(homa_incoming, homa_add_packet__packet_straddles_end_of_gap)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	unit_log_clear();
	self->data.seg.offset = htonl(0);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 1400, end 4200", unit_print_gaps(crpc));

	self->data.seg.offset = htonl(4000);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 4000));
	EXPECT_EQ(2, skb_queue_len(&crpc->msgin.packets));
}
TEST_F(homa_incoming, homa_add_packet__packet_at_end_of_gap)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	unit_log_clear();
	self->data.seg.offset = htonl(0);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 1400, end 4200", unit_print_gaps(crpc));

	self->data.seg.offset = htonl(2800);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 2800));
	EXPECT_EQ(3, skb_queue_len(&crpc->msgin.packets));
	EXPECT_STREQ("start 1400, end 2800", unit_print_gaps(crpc));
}
TEST_F(homa_incoming, homa_add_packet__packet_in_middle_of_gap)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	unit_log_clear();
	mock_ns = 1000;
	self->data.seg.offset = htonl(0);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 1400, end 4200, time 1000",
			unit_print_gaps(crpc));

	self->data.seg.offset = htonl(2000);
	mock_ns = 2000;
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 2000));
	EXPECT_EQ(3, skb_queue_len(&crpc->msgin.packets));
	EXPECT_STREQ("start 1400, end 2000, time 1000; start 3400, end 4200, time 1000",
			unit_print_gaps(crpc));
}
TEST_F(homa_incoming, homa_add_packet__kmalloc_failure_while_splitting_gap)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	unit_log_clear();
	mock_ns = 1000;
	self->data.seg.offset = htonl(0);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 1400, end 4200, time 1000",
			unit_print_gaps(crpc));

	self->data.seg.offset = htonl(2000);
	mock_ns = 2000;
	mock_kmalloc_errors = 1;
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 2000));
	EXPECT_EQ(2, skb_queue_len(&crpc->msgin.packets));
	EXPECT_STREQ("start 1400, end 4200, time 1000", unit_print_gaps(crpc));
}
TEST_F(homa_incoming, homa_add_packet__scan_multiple_gaps)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	unit_log_clear();
	self->data.seg.offset = htonl(1400);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 0, end 1400; start 2800, end 4200",
			unit_print_gaps(crpc));

	self->data.seg.offset = htonl(2800);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 2800));
	EXPECT_EQ(3, skb_queue_len(&crpc->msgin.packets));
	EXPECT_STREQ("start 0, end 1400", unit_print_gaps(crpc));
}
TEST_F(homa_incoming, homa_add_packet__metrics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	crpc->msgin.recv_end = 4200;
	self->data.seg.offset = htonl(0);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));
	EXPECT_EQ(0, skb_queue_len(&crpc->msgin.packets));
	EXPECT_EQ(0, homa_metrics_per_cpu()->resent_discards);
	EXPECT_EQ(1, homa_metrics_per_cpu()->packet_discards);

	self->data.retransmit = 1;
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));
	EXPECT_EQ(0, skb_queue_len(&crpc->msgin.packets));
	EXPECT_EQ(1, homa_metrics_per_cpu()->resent_discards);
	EXPECT_EQ(1, homa_metrics_per_cpu()->packet_discards);

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_EQ(1, skb_queue_len(&crpc->msgin.packets));
	EXPECT_EQ(1, homa_metrics_per_cpu()->resent_packets_used);
}

TEST_F(homa_incoming, homa_copy_to_user__basics)
{
	struct homa_rpc *crpc;

	mock_bpage_size = 2048;
	mock_bpage_shift = 11;
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			1000, 4000);
	ASSERT_NE(NULL, crpc);
	self->data.message_length = htonl(4000);
	self->data.seg.offset = htonl(1400);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 101000), crpc);
	self->data.seg.offset = htonl(2800);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1200, 201800), crpc);

	unit_log_clear();
	mock_copy_to_user_dont_copy = -1;
	EXPECT_EQ(0, -homa_copy_to_user(crpc));
	EXPECT_STREQ("skb_copy_datagram_iter: 1400 bytes to 0x1000000: 0-1399; "
			"skb_copy_datagram_iter: 648 bytes to 0x1000578: 101000-101647; "
			"skb_copy_datagram_iter: 752 bytes to 0x1000800: 101648-102399; "
			"skb_copy_datagram_iter: 1200 bytes to 0x1000af0: 201800-202999",
			unit_log_get());
	EXPECT_EQ(0, skb_queue_len(&crpc->msgin.packets));
}
TEST_F(homa_incoming, homa_copy_to_user__rpc_freed)
{
	struct homa_rpc *crpc;

	mock_bpage_size = 2048;
	mock_bpage_shift = 11;
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			1000, 4000);
	ASSERT_NE(NULL, crpc);
	homa_rpc_free(crpc);

	unit_log_clear();
	mock_copy_to_user_dont_copy = -1;
	EXPECT_EQ(EINVAL, -homa_copy_to_user(crpc));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(1, skb_queue_len(&crpc->msgin.packets));
}
TEST_F(homa_incoming, homa_copy_to_user__multiple_batches)
{
	struct homa_rpc *crpc;
	int offset;

	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			1000, 20000);
	ASSERT_NE(NULL, crpc);
	self->data.message_length = htonl(20000);
	for (offset = 1400; offset < 1400*8; offset += 1400) {
		self->data.seg.offset = htonl(offset);
		homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
				1400, offset), crpc);
	}
	EXPECT_EQ(8, skb_queue_len(&crpc->msgin.packets));

	unit_log_clear();
	mock_copy_to_user_dont_copy = -1;
	EXPECT_EQ(0, -homa_copy_to_user(crpc));
	EXPECT_STREQ("skb_copy_datagram_iter: 1400 bytes to 0x1000000: 0-1399; "
			"skb_copy_datagram_iter: 1400 bytes to 0x1000578: 1400-2799; "
			"skb_copy_datagram_iter: 1400 bytes to 0x1000af0: 2800-4199; "
			"skb_copy_datagram_iter: 1400 bytes to 0x1001068: 4200-5599; "
			"skb_copy_datagram_iter: 1400 bytes to 0x10015e0: 5600-6999; "
			"skb_copy_datagram_iter: 1400 bytes to 0x1001b58: 7000-8399; "
			"skb_copy_datagram_iter: 1400 bytes to 0x10020d0: 8400-9799; "
			"skb_copy_datagram_iter: 1400 bytes to 0x1002648: 9800-11199",
			unit_log_get());
	EXPECT_EQ(0, skb_queue_len(&crpc->msgin.packets));
}
TEST_F(homa_incoming, homa_copy_to_user__nothing_to_copy)
{
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			1000, 20000);
	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(1, skb_queue_len(&crpc->msgin.packets));

	/* First call finds packets to copy. */
	unit_log_clear();
	mock_copy_to_user_dont_copy = -1;
	EXPECT_EQ(0, -homa_copy_to_user(crpc));
	EXPECT_STREQ("skb_copy_datagram_iter: 1400 bytes to 0x1000000: 0-1399",
			unit_log_get());
	EXPECT_EQ(0, skb_queue_len(&crpc->msgin.packets));

	/* Second call finds no packets. */
	unit_log_clear();
	EXPECT_EQ(0, -homa_copy_to_user(crpc));
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_incoming, homa_copy_to_user__many_chunks_for_one_skb)
{
	struct homa_rpc *crpc;

	mock_bpage_size = 512;
	mock_bpage_shift = 9;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			1000, 4000);
	ASSERT_NE(NULL, crpc);
	self->data.message_length = htonl(4000);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			3000, 101000), crpc);

	unit_log_clear();
	mock_copy_to_user_dont_copy = -1;
	EXPECT_EQ(0, -homa_copy_to_user(crpc));
	EXPECT_STREQ("skb_copy_datagram_iter: 512 bytes to 0x1000000: 101000-101511; "
			"skb_copy_datagram_iter: 512 bytes to 0x1000200: 101512-102023; "
			"skb_copy_datagram_iter: 512 bytes to 0x1000400: 102024-102535; "
			"skb_copy_datagram_iter: 512 bytes to 0x1000600: 102536-103047; "
			"skb_copy_datagram_iter: 512 bytes to 0x1000800: 103048-103559; "
			"skb_copy_datagram_iter: 440 bytes to 0x1000a00: 103560-103999",
			unit_log_get());
}
TEST_F(homa_incoming, homa_copy_to_user__skb_data_extends_past_message_end)
{
	struct homa_data_hdr *h;
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			1000, 4000);
	ASSERT_NE(NULL, crpc);
	self->data.message_length = htonl(4000);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			3000, 101000), crpc);

	unit_log_clear();
	mock_copy_to_user_dont_copy = -1;
	h = (struct homa_data_hdr *)skb_peek(&crpc->msgin.packets)->data;
	h->seg.offset = htonl(4000);
	EXPECT_EQ(0, -homa_copy_to_user(crpc));
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_incoming, homa_copy_to_user__error_in_import_ubuf)
{
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			1000, 4000);
	ASSERT_NE(NULL, crpc);

	unit_log_clear();
	mock_import_ubuf_errors = 1;
	EXPECT_EQ(13, -homa_copy_to_user(crpc));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, skb_queue_len(&crpc->msgin.packets));
}
TEST_F(homa_incoming, homa_copy_to_user__error_in_skb_copy_datagram_iter)
{
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			1000, 4000);
	ASSERT_NE(NULL, crpc);

	unit_log_clear();
	mock_copy_data_errors = 1;
	EXPECT_EQ(14, -homa_copy_to_user(crpc));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, skb_queue_len(&crpc->msgin.packets));
}
#ifdef HOMA_TIMETRACE_H
TEST_F(homa_incoming, homa_copy_to_user__timetrace_info)
{
	struct homa_rpc *crpc;
	char traces[1000];
	int offset;

	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			1000, 20000);
	ASSERT_NE(NULL, crpc);
	self->data.message_length = htonl(20000);
	for (offset = 4200; offset < 1400*10; offset += 1400) {
		self->data.seg.offset = htonl(offset);
		homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
				1400, offset), crpc);
	}
	EXPECT_EQ(8, skb_queue_len(&crpc->msgin.packets));

	unit_log_clear();
	mock_copy_to_user_dont_copy = -1;
	tt_init(NULL, NULL);
	EXPECT_EQ(0, -homa_copy_to_user(crpc));
	tt_get_messages(traces, sizeof(traces));
	EXPECT_STREQ("starting copy to user space for id 1234; "
			"copied out bytes 0-1400 for id 1234; "
			"copied out bytes 4200-7000 for id 1234; "
			"finished freeing 3 skbs for id 1234; "
			"starting copy to user space for id 1234; "
			"copied out bytes 7000-11200 for id 1234; "
			"finished freeing 3 skbs for id 1234; "
			"starting copy to user space for id 1234; "
			"copied out bytes 11200-14000 for id 1234; "
			"finished freeing 2 skbs for id 1234",
			traces);
	tt_destroy();
}
#endif

TEST_F(homa_incoming, homa_dispatch_pkts__unknown_socket_ipv4)
{
	struct sk_buff *skb;

	self->data.common.dport = htons(100);

	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);

	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	homa_dispatch_pkts(skb, &self->homa);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_STREQ("icmp_send type 3, code 3", unit_log_get());
}
TEST_F(homa_incoming, homa_dispatch_pkts__unknown_socket_ipv6)
{
	struct sk_buff *skb;

	self->data.common.dport = htons(100);

	// Make sure the test uses IPv6.
	mock_ipv6 = true;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);

	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	homa_dispatch_pkts(skb, &self->homa);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_STREQ("icmp6_send type 1, code 4", unit_log_get());
}
TEST_F(homa_incoming, homa_dispatch_pkts__unknown_socket_free_many_packets)
{
	struct sk_buff *skb, *skb2, *skb3;

	self->data.common.dport = htons(100);

	// Make sure the test uses IPv6.
	mock_ipv6 = true;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);

	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	skb2 = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	skb3 = mock_skb_new(self->client_ip, &self->data.common, 1400, 1400);
	skb->next = skb2;
	skb2->next = skb3;
	homa_dispatch_pkts(skb, &self->homa);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_STREQ("icmp6_send type 1, code 4", unit_log_get());
}
TEST_F(homa_incoming, homa_dispatch_pkts__new_server_rpc)
{
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), &self->homa);
	EXPECT_EQ(1, unit_list_length(&self->hsk2.active_rpcs));
	EXPECT_EQ(1, mock_skb_count());
}
TEST_F(homa_incoming, homa_dispatch_pkts__cant_create_server_rpc)
{
	mock_kmalloc_errors = 1;
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), &self->homa);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(0, mock_skb_count());
	EXPECT_EQ(1, homa_metrics_per_cpu()->server_cant_create_rpcs);
}
TEST_F(homa_incoming, homa_dispatch_pkts__existing_server_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk2, UNIT_RCVD_ONE_PKT,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 10000, 100);

	ASSERT_NE(NULL, srpc);
	EXPECT_EQ(8600, srpc->msgin.bytes_remaining);
	self->data.seg.offset = htonl(1400);
	self->data.common.sender_id = cpu_to_be64(self->client_id);
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), &self->homa);
	EXPECT_EQ(7200, srpc->msgin.bytes_remaining);
}
TEST_F(homa_incoming, homa_dispatch_pkts__non_data_packet_for_existing_server_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk2, UNIT_IN_SERVICE,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 10000, 100);
	struct homa_resend_hdr resend = {.common = {
		.sport = htons(self->client_port),
		.dport = htons(self->server_port),
		.type = RESEND,
		.sender_id = cpu_to_be64(self->client_id)},
		.offset = 0,
		.length = 1000,
		.priority = 3};

	ASSERT_NE(NULL, srpc);
	unit_log_clear();
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &resend.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("xmit BUSY", unit_log_get());
}
TEST_F(homa_incoming, homa_dispatch_pkts__existing_client_rpc)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(10000, crpc->msgout.granted);
	unit_log_clear();

	struct homa_grant_hdr h = {{.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = GRANT},
			.offset = htonl(12600),
			.priority = 3,
			.resend_all = 0};
	homa_dispatch_pkts(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(12600, crpc->msgout.granted);
}
TEST_F(homa_incoming, homa_dispatch_pkts__unknown_client_rpc)
{
	struct homa_grant_hdr h = {{.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(99991),
			.type = UNKNOWN}};

	mock_xmit_log_verbose = 1;
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(1, homa_metrics_per_cpu()->unknown_rpcs);
}
TEST_F(homa_incoming, homa_dispatch_pkts__unknown_server_rpc)
{
	struct homa_resend_hdr h = {{.sport = htons(self->client_port),
			.dport = htons(self->server_port),
			.sender_id = cpu_to_be64(99990),
			.type = GRANT}};

	mock_xmit_log_verbose = 1;
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(0, homa_metrics_per_cpu()->unknown_rpcs);
}
TEST_F(homa_incoming, homa_dispatch_pkts__cutoffs_for_unknown_client_rpc)
{
	struct homa_cutoffs_hdr h = {{.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(99991),
			.type = CUTOFFS},
			.unsched_cutoffs = {htonl(10), htonl(9), htonl(8),
			htonl(7), htonl(6), htonl(5), htonl(4),
			htonl(3)},
			.cutoff_version = 400};
	struct homa_peer *peer;

	homa_dispatch_pkts(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->homa);
	peer = homa_peer_find(self->homa.peers, self->server_ip,
			&self->hsk.inet);
	ASSERT_FALSE(IS_ERR(peer));
	EXPECT_EQ(400, peer->cutoff_version);
	EXPECT_EQ(9, peer->unsched_cutoffs[1]);
	EXPECT_EQ(3, peer->unsched_cutoffs[7]);
}
TEST_F(homa_incoming, homa_dispatch_pkts__resend_for_unknown_server_rpc)
{
	struct homa_resend_hdr h = {{.sport = htons(self->client_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(99990),
			.type = RESEND},
			.offset = 0, .length = 2000, .priority = 5};

	homa_dispatch_pkts(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("xmit UNKNOWN", unit_log_get());
}
TEST_F(homa_incoming, homa_dispatch_pkts__reset_counters)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_grant_hdr h = {.common = {.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = GRANT},
			.offset = htonl(12600), .priority = 3, .resend_all = 0};

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(10000, crpc->msgout.granted);
	unit_log_clear();
	crpc->silent_ticks = 5;
	crpc->peer->outstanding_resends = 2;
	homa_dispatch_pkts(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(0, crpc->silent_ticks);
	EXPECT_EQ(0, crpc->peer->outstanding_resends);

	/* Don't reset silent_ticks for some packet types. */
	h.common.type = CUTOFFS;
	crpc->silent_ticks = 5;
	crpc->peer->outstanding_resends = 2;
	homa_dispatch_pkts(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(5, crpc->silent_ticks);
	EXPECT_EQ(0, crpc->peer->outstanding_resends);
}
TEST_F(homa_incoming, homa_dispatch_pkts__multiple_ack_packets)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk2, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 3000);
	struct sk_buff *skb, *skb2, *skb3;
	struct homa_ack_hdr ack;

	ASSERT_NE(NULL, srpc);
	ack.common = self->data.common;
	ack.common.type = ACK;
	ack.common.sender_id += 100;
	ack.num_acks = htons(1);
	ack.acks[0].server_port = htons(self->server_port);
	ack.acks[0].client_id = cpu_to_be64(self->client_id + 4);
	skb = mock_skb_new(self->client_ip, &ack.common, 0, 0);
	skb2 = mock_skb_new(self->client_ip, &ack.common, 0, 0);
	skb3 = mock_skb_new(self->client_ip, &ack.common, 0, 0);
	skb->next = skb2;
	skb2->next = skb3;

	unit_log_clear();
	homa_dispatch_pkts(skb, &self->homa);
	EXPECT_SUBSTR("ack 1239", unit_log_get());
}
TEST_F(homa_incoming, homa_dispatch_pkts__unknown_type)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(10000, crpc->msgout.granted);
	unit_log_clear();

	struct homa_common_hdr h = {.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id), .type = 99};
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &h, 0, 0), &self->homa);
	EXPECT_EQ(1, homa_metrics_per_cpu()->unknown_packet_types);
}
TEST_F(homa_incoming, homa_dispatch_pkts__handle_ack)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk2, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 3000);

	ASSERT_NE(NULL, srpc);
	self->data.ack = (struct homa_ack) {
		       .server_port = htons(self->server_port),
		       .client_id = cpu_to_be64(self->client_id)};
	self->data.common.sender_id = cpu_to_be64(self->client_id+10);
	unit_log_clear();
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), &self->homa);
	EXPECT_STREQ("DEAD", homa_symbol_for_state(srpc));
	EXPECT_SUBSTR("ack 1235", unit_log_get());
}
TEST_F(homa_incoming, homa_dispatch_pkts__too_many_acks)
{
	struct sk_buff *skb, *skb2, *skb3;

	self->data.ack = (struct homa_ack) {
		       .server_port = htons(self->server_port),
		       .client_id = cpu_to_be64(self->client_id)};
	self->data.common.sender_id = cpu_to_be64(self->client_id+10);
	unit_log_clear();
	skb = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	self->data.ack.client_id = cpu_to_be64(self->client_id+2);
	skb2 = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	self->data.ack.client_id = cpu_to_be64(self->client_id+4);
	skb3 = mock_skb_new(self->client_ip, &self->data.common, 1400, 0);
	skb->next = skb2;
	skb2->next = skb3;
	homa_dispatch_pkts(skb, &self->homa);
	EXPECT_STREQ("sk->sk_data_ready invoked; ack 1237; ack 1235",
				unit_log_get());
}
TEST_F(homa_incoming, homa_dispatch_pkts__invoke_homa_grant_check_rpc)
{
	self->data.incoming = htonl(1000);
	self->data.message_length = htonl(20000);
	homa_dispatch_pkts(mock_skb_new(self->server_ip, &self->data.common,
			0, 0), &self->homa);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_SUBSTR("id 1235", unit_log_get());
}
TEST_F(homa_incoming, homa_dispatch_pkts__forced_reap)
{
	struct homa_rpc *dead = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 20000);
	struct homa_rpc *srpc;
	mock_ns_tick = 10;

	homa_rpc_free(dead);
	EXPECT_EQ(31, self->hsk.dead_skbs);
	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->client_port, self->server_id,
			10000, 5000);
	ASSERT_NE(NULL, srpc);
	self->homa.dead_buffs_limit = 16;

	/* First packet: below the threshold for reaps. */
	self->data.common.dport = htons(self->hsk.port);
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), &self->homa);
	EXPECT_EQ(31, self->hsk.dead_skbs);
	EXPECT_EQ(0, homa_metrics_per_cpu()->data_pkt_reap_ns);

	/* Second packet: must reap. */
	self->homa.dead_buffs_limit = 15;
	self->homa.reap_limit = 10;
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), &self->homa);
	EXPECT_EQ(21, self->hsk.dead_skbs);
	EXPECT_NE(0, homa_metrics_per_cpu()->data_pkt_reap_ns);
}

TEST_F(homa_incoming, homa_data_pkt__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 1600);

	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	crpc->msgout.next_xmit_offset = crpc->msgout.length;
	self->data.message_length = htonl(1600);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 0), crpc);
	EXPECT_EQ(RPC_INCOMING, crpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_responses));
	EXPECT_EQ(200, crpc->msgin.bytes_remaining);
	EXPECT_EQ(1, skb_queue_len(&crpc->msgin.packets));
	EXPECT_EQ(1600, crpc->msgin.granted);
	EXPECT_EQ(1, homa_metrics_per_cpu()->responses_received);
}
TEST_F(homa_incoming, homa_data_pkt__wrong_client_rpc_state)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 2000);

	ASSERT_NE(NULL, crpc);
	crpc->state = RPC_DEAD;
	self->data.message_length = htonl(2000);
	self->data.seg.offset = htonl(1400);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			600, 1400), crpc);
	EXPECT_EQ(600, crpc->msgin.bytes_remaining);
	EXPECT_EQ(1, skb_queue_len(&crpc->msgin.packets));
	crpc->state = RPC_INCOMING;
}
TEST_F(homa_incoming, homa_data_pkt__initialize_msgin)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 1600);

	ASSERT_NE(NULL, crpc);
	self->data.message_length = htonl(1600);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 0), crpc);
	EXPECT_EQ(200, crpc->msgin.bytes_remaining);
	EXPECT_EQ(1600, crpc->msgin.granted);
}
TEST_F(homa_incoming, homa_data_pkt__no_buffer_pool)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 1600);

	ASSERT_NE(NULL, crpc);
	homa_pool_destroy(self->hsk.buffer_pool);
	unit_log_clear();
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 0), crpc);
	EXPECT_STREQ("homa_data_pkt discarded packet", unit_log_get());
}
TEST_F(homa_incoming, homa_data_pkt__wrong_server_rpc_state)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 1400, 5000);

	ASSERT_NE(NULL, srpc);
	unit_log_clear();
	homa_data_pkt(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), srpc);
	EXPECT_EQ(RPC_OUTGOING, srpc->state);
	EXPECT_STREQ("homa_data_pkt discarded packet", unit_log_get());
}
TEST_F(homa_incoming, homa_data_pkt__no_buffers)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 5000);

	EXPECT_NE(NULL, crpc);
	unit_log_clear();

	atomic_set(&self->hsk.buffer_pool->free_bpages, 0);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 0), crpc);
	EXPECT_EQ(1400, homa_metrics_per_cpu()->dropped_data_no_bufs);
	EXPECT_EQ(0, skb_queue_len(&crpc->msgin.packets));
}
TEST_F(homa_incoming, homa_data_pkt__update_delta)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 5000);

	EXPECT_NE(NULL, crpc);
	unit_log_clear();

	/* Total incoming goes up on first packet (count unscheduled bytes). */
	self->data.message_length = htonl(5000);
	self->data.incoming = htonl(4000);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 0), crpc);

	/* Total incoming drops on subsequent packet. */
	self->data.seg.offset = htonl(2800);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 2800), crpc);

	/* Duplicate packet should have no effect. */
	self->data.seg.offset = htonl(2800);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 2800), crpc);
}
TEST_F(homa_incoming, homa_data_pkt__handoff)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 3000);

	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	crpc->msgout.next_xmit_offset = crpc->msgout.length;

	/* First packet triggers handoff. */
	self->data.message_length = htonl(3000);
	self->data.seg.offset = htonl(1400);
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			1400, 0), crpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_responses));
	EXPECT_TRUE(atomic_read(&crpc->flags) & RPC_PKTS_READY);
	EXPECT_EQ(1600, crpc->msgin.bytes_remaining);
	EXPECT_EQ(1, skb_queue_len(&crpc->msgin.packets));
	EXPECT_STREQ("sk->sk_data_ready invoked", unit_log_get());

	/* Second packet doesn't trigger a handoff because one is
	 * already pending.
	 */
	self->data.message_length = htonl(3000);
	self->data.seg.offset = htonl(2800);
	unit_log_clear();
	homa_data_pkt(mock_skb_new(self->server_ip, &self->data.common,
			200, 0), crpc);
	EXPECT_STREQ("", unit_log_get());
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
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), &self->homa);
	EXPECT_SUBSTR("cutoffs 19 18 17 16 15 14 13 12, version 2",
			unit_log_get());

	/* Try again, but this time no comments should be sent because
	 * no time has elapsed since the last cutoffs were sent.
	 */
	unit_log_clear();
	self->homa.cutoff_version = 3;
	self->data.seg.offset = 1400;
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), &self->homa);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_incoming, homa_data_pkt__cutoffs_up_to_date)
{
	self->homa.cutoff_version = 123;
	self->data.cutoff_version = htons(123);
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), &self->homa);
	EXPECT_STREQ("sk->sk_data_ready invoked", unit_log_get());
}

TEST_F(homa_incoming, homa_grant_pkt__basics)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 20000);
	struct homa_grant_hdr h = {{.sport = htons(srpc->dport),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->client_id),
			.type = GRANT},
			.offset = htonl(11000),
			.priority = 3,
			.resend_all = 0};

	ASSERT_NE(NULL, srpc);
	homa_xmit_data(srpc, false);
	unit_log_clear();

	homa_dispatch_pkts(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(11000, srpc->msgout.granted);
	EXPECT_STREQ("xmit DATA 1400@10000", unit_log_get());

	/* Don't let grant offset go backwards. */
	h.offset = htonl(10000);
	unit_log_clear();
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(11000, srpc->msgout.granted);
	EXPECT_STREQ("", unit_log_get());

	/* Wrong state. */
	h.offset = htonl(20000);
	srpc->state = RPC_INCOMING;
	unit_log_clear();
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(11000, srpc->msgout.granted);
	EXPECT_STREQ("", unit_log_get());

	/* Must restore old state to avoid potential crashes. */
	srpc->state = RPC_OUTGOING;
}
TEST_F(homa_incoming, homa_grant_pkt__reset)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 20000);
	struct homa_grant_hdr h = {{.sport = htons(srpc->dport),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->client_id),
			.type = GRANT},
			.offset = htonl(3000),
			.priority = 2,
			.resend_all = 1};

	ASSERT_NE(NULL, srpc);
	homa_xmit_data(srpc, false);
	unit_log_clear();
	EXPECT_EQ(10000, srpc->msgout.granted);
	EXPECT_EQ(10000, srpc->msgout.next_xmit_offset);

	homa_dispatch_pkts(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(10000, srpc->msgout.granted);
	EXPECT_EQ(10000, srpc->msgout.next_xmit_offset);
	EXPECT_STREQ("xmit DATA retrans 1400@0; "
			"xmit DATA retrans 1400@1400; "
			"xmit DATA retrans 1400@2800; "
			"xmit DATA retrans 1400@4200; "
			"xmit DATA retrans 1400@5600; "
			"xmit DATA retrans 1400@7000; "
			"xmit DATA retrans 1400@8400; "
			"xmit DATA retrans 200@9800", unit_log_get());
}
TEST_F(homa_incoming, homa_grant_pkt__grant_past_end_of_message)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_grant_hdr h = {{.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = GRANT},
			.offset = htonl(25000),
			.priority = 3};

	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(20000, crpc->msgout.granted);
}

TEST_F(homa_incoming, homa_resend_pkt__unknown_rpc)
{
	struct homa_resend_hdr h = {{.sport = htons(self->client_port),
			.dport = htons(self->server_port),
			.sender_id = cpu_to_be64(self->client_id),
			.type = RESEND},
			.offset = htonl(100),
			.length = htonl(200),
			.priority = 3};

	homa_dispatch_pkts(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("xmit UNKNOWN", unit_log_get());
}
TEST_F(homa_incoming, homa_resend_pkt__rpc_in_service_server_sends_busy)
{
	struct homa_resend_hdr h = {{.sport = htons(self->client_port),
			.dport = htons(self->server_port),
			.sender_id = cpu_to_be64(self->client_id),
			.type = RESEND},
			.offset = htonl(0),
			.length = htonl(200),
			.priority = 3};
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk2, UNIT_IN_SERVICE,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 2000, 20000);

	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	homa_dispatch_pkts(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("xmit BUSY", unit_log_get());
}
TEST_F(homa_incoming, homa_resend_pkt__rpc_incoming_server_sends_busy)
{
	/* Entire msgin has not been received yet. But we have received
	 * everything we have granted so far.
	 */
	struct homa_resend_hdr h = {{.sport = htons(self->client_port),
			.dport = htons(self->server_port),
			.sender_id = cpu_to_be64(self->client_id),
			.type = RESEND},
			.offset = htonl(1400),
			.length = htonl(200),
			.priority = 3};
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk2, UNIT_RCVD_ONE_PKT,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 2000, 20000);

	ASSERT_NE(NULL, srpc);
	srpc->msgin.granted = 1400;
	unit_log_clear();

	homa_dispatch_pkts(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->homa);
	// The server might send a GRANT right after BUSY so just check substr
	EXPECT_SUBSTR("xmit BUSY", unit_log_get());
}
TEST_F(homa_incoming, homa_resend_pkt__client_not_outgoing)
{
	/* Important to respond to resends even if client thinks the
	 * server must already have received everything.
	 */
	struct homa_resend_hdr h = {{.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = RESEND},
			.offset = htonl(100),
			.length = htonl(200),
			.priority = 3};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 2000, 3000);

	ASSERT_NE(NULL, crpc);
	unit_log_clear();

	homa_dispatch_pkts(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("xmit DATA retrans 1400@0", unit_log_get());
}
TEST_F(homa_incoming, homa_resend_pkt__send_busy_instead_of_data)
{
	struct homa_resend_hdr h = {{.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = RESEND},
			.offset = htonl(100),
			.length = htonl(200),
			.priority = 3};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 2000, 100);

	ASSERT_NE(NULL, crpc);
	unit_log_clear();

	homa_dispatch_pkts(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_SUBSTR("xmit BUSY", unit_log_get());
}
TEST_F(homa_incoming, homa_resend_pkt__client_send_data)
{
	struct homa_resend_hdr h = {{.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = RESEND},
			.offset = htonl(100),
			.length = htonl(200),
			.priority = 3};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 2000, 100);

	ASSERT_NE(NULL, crpc);
	homa_xmit_data(crpc, false);
	unit_log_clear();
	mock_clear_xmit_prios();

	homa_dispatch_pkts(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_SUBSTR("xmit DATA retrans 1400@0", unit_log_get());
	EXPECT_STREQ("3", mock_xmit_prios);
}
TEST_F(homa_incoming, homa_resend_pkt__server_send_data)
{
	struct homa_resend_hdr h = {{.sport = htons(self->client_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->client_id),
			.type = RESEND},
			.offset = htonl(100),
			.length = htonl(2000),
			.priority = 4};
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 20000);

	ASSERT_NE(NULL, srpc);
	homa_xmit_data(srpc, false);
	unit_log_clear();
	mock_clear_xmit_prios();

	homa_dispatch_pkts(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("xmit DATA retrans 1400@0; "
			"xmit DATA retrans 1400@1400", unit_log_get());
	EXPECT_STREQ("4 4", mock_xmit_prios);
}

TEST_F(homa_incoming, homa_unknown_pkt__client_resend_all)
{
	struct homa_unknown_hdr h = {{.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = UNKNOWN}};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 2000, 2000);

	ASSERT_NE(NULL, crpc);
	homa_xmit_data(crpc, false);
	unit_log_clear();

	mock_xmit_log_verbose = 1;
	homa_dispatch_pkts(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_SUBSTR("xmit DATA from 0.0.0.0:32768, dport 99, id 1234, message_length 2000, offset 0, data_length 1400, incoming 2000, RETRANSMIT; "
			"xmit DATA from 0.0.0.0:32768, dport 99, id 1234, message_length 2000, offset 1400, data_length 600, incoming 2000, RETRANSMIT",
			unit_log_get());
	EXPECT_EQ(-1, crpc->msgin.length);
}
TEST_F(homa_incoming, homa_unknown_pkt__client_resend_part)
{
	struct homa_unknown_hdr h = {{.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = UNKNOWN}};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 2000, 2000);

	ASSERT_NE(NULL, crpc);
	crpc->msgout.granted = 1400;
	homa_xmit_data(crpc, false);
	unit_log_clear();

	mock_xmit_log_verbose = 1;
	homa_dispatch_pkts(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_SUBSTR("xmit DATA from 0.0.0.0:32768, dport 99, id 1234, message_length 2000, offset 0, data_length 1400, incoming 1400, RETRANSMIT",
			unit_log_get());
	EXPECT_EQ(-1, crpc->msgin.length);
}
TEST_F(homa_incoming, homa_unknown_pkt__free_server_rpc)
{
	struct homa_unknown_hdr h = {{.sport = htons(self->client_port),
			.dport = htons(self->hsk2.port),
			.sender_id = cpu_to_be64(self->client_id),
			.type = UNKNOWN}};
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk2, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 20000);

	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	homa_dispatch_pkts(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("DEAD", homa_symbol_for_state(srpc));
}

TEST_F(homa_incoming, homa_cutoffs_pkt_basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_cutoffs_hdr h = {{.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = CUTOFFS},
			.unsched_cutoffs = {htonl(10), htonl(9), htonl(8),
			htonl(7), htonl(6), htonl(5), htonl(4), htonl(3)},
			.cutoff_version = 400};

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(10000, crpc->msgout.granted);
	unit_log_clear();

	homa_dispatch_pkts(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(400, crpc->peer->cutoff_version);
	EXPECT_EQ(9, crpc->peer->unsched_cutoffs[1]);
	EXPECT_EQ(3, crpc->peer->unsched_cutoffs[7]);
}
TEST_F(homa_incoming, homa_cutoffs__cant_find_peer)
{
	struct homa_cutoffs_hdr h = {{.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = CUTOFFS},
			.unsched_cutoffs = {htonl(10), htonl(9), htonl(8),
			htonl(7), htonl(6), htonl(5), htonl(4), htonl(3)},
			.cutoff_version = 400};
	struct sk_buff *skb = mock_skb_new(self->server_ip, &h.common, 0, 0);
	struct homa_peer *peer;

	mock_kmalloc_errors = 1;
	homa_cutoffs_pkt(skb, &self->hsk);
	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_kmalloc_errors);
	peer = homa_peer_find(self->homa.peers, self->server_ip,
			&self->hsk.inet);
	ASSERT_FALSE(IS_ERR(peer));
	EXPECT_EQ(0, peer->cutoff_version);
}

TEST_F(homa_incoming, homa_need_ack_pkt__rpc_response_fully_received)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 100, 3000);
	struct homa_need_ack_hdr h = {.common = {
			.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = NEED_ACK}};

	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	mock_xmit_log_verbose = 1;
	homa_dispatch_pkts(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("xmit ACK from 0.0.0.0:32768, dport 99, id 1234, acks",
			unit_log_get());
	EXPECT_EQ(1, homa_metrics_per_cpu()->packets_received[
			NEED_ACK - DATA]);
}
TEST_F(homa_incoming, homa_need_ack_pkt__rpc_response_not_fully_received)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 100, 3000);
	struct homa_need_ack_hdr h = {.common = {
			.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = NEED_ACK}};

	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	mock_xmit_log_verbose = 1;
	homa_dispatch_pkts(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(1, homa_metrics_per_cpu()->packets_received[
			NEED_ACK - DATA]);
}
TEST_F(homa_incoming, homa_need_ack_pkt__rpc_not_incoming)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 100, 3000);
	struct homa_need_ack_hdr h = {.common = {
			.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = NEED_ACK}};

	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	mock_xmit_log_verbose = 1;
	homa_dispatch_pkts(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(1, homa_metrics_per_cpu()->packets_received[
			NEED_ACK - DATA]);
}
TEST_F(homa_incoming, homa_need_ack_pkt__rpc_doesnt_exist)
{
	struct homa_peer *peer = homa_peer_find(self->homa.peers,
			self->server_ip, &self->hsk.inet);
	struct homa_need_ack_hdr h = {.common = {
			.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = NEED_ACK}};

	peer->acks[0].server_port = htons(self->server_port);
	peer->acks[0].client_id = cpu_to_be64(self->client_id+2);
	peer->num_acks = 1;
	mock_xmit_log_verbose = 1;
	homa_dispatch_pkts(mock_skb_new(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("xmit ACK from 0.0.0.0:32768, dport 99, id 1234, acks [sp 99, id 1236]",
			unit_log_get());
}

TEST_F(homa_incoming, homa_ack_pkt__target_rpc_exists)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk2, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 5000);
	struct homa_ack_hdr h = {.common = {
			.sport = htons(self->client_port),
			.dport = htons(self->hsk2.port),
			.sender_id = cpu_to_be64(self->client_id),
			.type = ACK},
			.num_acks = htons(0)};

	ASSERT_NE(NULL, srpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk2.active_rpcs));
	unit_log_clear();
	mock_xmit_log_verbose = 1;
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(0, unit_list_length(&self->hsk2.active_rpcs));
	EXPECT_EQ(1, homa_metrics_per_cpu()->packets_received[ACK - DATA]);
}
TEST_F(homa_incoming, homa_ack_pkt__target_rpc_doesnt_exist)
{
	struct homa_rpc *srpc1 = unit_server_rpc(&self->hsk2, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 5000);
	struct homa_rpc *srpc2 = unit_server_rpc(&self->hsk2, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id+2, 100, 5000);
	struct homa_ack_hdr h = {.common = {
			.sport = htons(self->client_port),
			.dport = htons(self->hsk2.port),
			.sender_id = cpu_to_be64(self->client_id + 10),
			.type = ACK},
			.num_acks = htons(2)};

	ASSERT_NE(NULL, srpc1);
	ASSERT_NE(NULL, srpc2);
	EXPECT_EQ(2, unit_list_length(&self->hsk2.active_rpcs));
	unit_log_clear();
	mock_xmit_log_verbose = 1;
	h.acks[0] = (struct homa_ack) {.server_port = htons(self->server_port),
			.client_id = cpu_to_be64(self->server_id+5)};
	h.acks[1] = (struct homa_ack) {.server_port = htons(self->server_port),
			.client_id = cpu_to_be64(self->server_id+1)};
	homa_dispatch_pkts(mock_skb_new(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(1, unit_list_length(&self->hsk2.active_rpcs));
	EXPECT_STREQ("OUTGOING", homa_symbol_for_state(srpc1));
	EXPECT_STREQ("DEAD", homa_symbol_for_state(srpc2));
}

TEST_F(homa_incoming, homa_rpc_abort__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	homa_rpc_abort(crpc, -EFAULT);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_responses));
	EXPECT_EQ(0, list_empty(&crpc->ready_links));
	EXPECT_EQ(EFAULT, -crpc->error);
	EXPECT_STREQ("sk->sk_data_ready invoked", unit_log_get());
}
TEST_F(homa_incoming, homa_rpc_abort__socket_shutdown)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);

	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	self->hsk.shutdown = 1;
	homa_rpc_abort(crpc, -EFAULT);
	EXPECT_EQ(RPC_OUTGOING, crpc->state);
	EXPECT_EQ(EFAULT, -crpc->error);
	self->hsk.shutdown = 0;
}

TEST_F(homa_incoming, homa_abort_rpcs__basics)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 1600);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2, 5000, 1600);
	struct homa_rpc *crpc3 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip+1,
			self->server_port, self->client_id+4, 5000, 1600);

	ASSERT_NE(NULL, crpc1);
	ASSERT_NE(NULL, crpc2);
	ASSERT_NE(NULL, crpc3);
	unit_log_clear();
	homa_abort_rpcs(&self->homa, self->server_ip, 0, -EPROTONOSUPPORT);
	EXPECT_EQ(2, unit_list_length(&self->hsk.ready_responses));
	EXPECT_EQ(0, list_empty(&crpc1->ready_links));
	EXPECT_EQ(EPROTONOSUPPORT, -crpc1->error);
	EXPECT_EQ(0, list_empty(&crpc2->ready_links));
	EXPECT_EQ(EPROTONOSUPPORT, -crpc2->error);
	EXPECT_EQ(RPC_OUTGOING, crpc3->state);
}
TEST_F(homa_incoming, homa_abort_rpcs__multiple_sockets)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 1600);
	struct homa_rpc *crpc2, *crpc3;

	crpc2 = unit_client_rpc(&self->hsk2, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id+2,
			5000, 1600);
	crpc3 = unit_client_rpc(&self->hsk2, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id+4,
			5000, 1600);
	ASSERT_NE(NULL, crpc1);
	ASSERT_NE(NULL, crpc2);
	ASSERT_NE(NULL, crpc3);
	unit_log_clear();
	homa_abort_rpcs(&self->homa, self->server_ip, 0, -EPROTONOSUPPORT);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_responses));
	EXPECT_EQ(0, list_empty(&crpc1->ready_links));
	EXPECT_EQ(EPROTONOSUPPORT, -crpc1->error);
	EXPECT_EQ(0, list_empty(&crpc2->ready_links));
	EXPECT_EQ(EPROTONOSUPPORT, -crpc2->error);
	EXPECT_EQ(0, list_empty(&crpc3->ready_links));
	EXPECT_EQ(2, unit_list_length(&self->hsk2.active_rpcs));
	EXPECT_EQ(2, unit_list_length(&self->hsk2.ready_responses));
}
TEST_F(homa_incoming, homa_abort_rpcs__select_addr)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 1600);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip+1,
			self->server_port, self->client_id+2, 5000, 1600);
	struct homa_rpc *crpc3 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip+2,
			self->server_port, self->client_id+4, 5000, 1600);

	ASSERT_NE(NULL, crpc1);
	ASSERT_NE(NULL, crpc2);
	ASSERT_NE(NULL, crpc3);
	unit_log_clear();
	homa_abort_rpcs(&self->homa, self->server_ip, self->server_port,
			-ENOTCONN);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_responses));
	EXPECT_EQ(0, list_empty(&crpc1->ready_links));
	EXPECT_EQ(RPC_OUTGOING, crpc2->state);
	EXPECT_EQ(RPC_OUTGOING, crpc3->state);
}
TEST_F(homa_incoming, homa_abort_rpcs__select_port)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 1600);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port+1, self->client_id+2, 5000, 1600);
	struct homa_rpc *crpc3 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id+4, 5000, 1600);

	ASSERT_NE(NULL, crpc1);
	ASSERT_NE(NULL, crpc2);
	ASSERT_NE(NULL, crpc3);
	unit_log_clear();
	homa_abort_rpcs(&self->homa, self->server_ip, self->server_port,
			-ENOTCONN);
	EXPECT_EQ(2, unit_list_length(&self->hsk.ready_responses));
	EXPECT_EQ(0, list_empty(&crpc1->ready_links));
	EXPECT_EQ(ENOTCONN, -crpc1->error);
	EXPECT_EQ(RPC_OUTGOING, crpc2->state);
	EXPECT_EQ(0, list_empty(&crpc1->ready_links));
	EXPECT_EQ(ENOTCONN, -crpc3->error);
}
TEST_F(homa_incoming, homa_abort_rpcs__any_port)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 1600);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port+1, self->client_id+2, 5000, 1600);
	struct homa_rpc *crpc3 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id+4, 5000, 1600);

	ASSERT_NE(NULL, crpc1);
	ASSERT_NE(NULL, crpc2);
	ASSERT_NE(NULL, crpc3);
	unit_log_clear();
	homa_abort_rpcs(&self->homa, self->server_ip, 0, -ENOTCONN);
	EXPECT_EQ(0, list_empty(&crpc1->ready_links));
	EXPECT_EQ(0, list_empty(&crpc2->ready_links));
	EXPECT_EQ(0, list_empty(&crpc3->ready_links));
}
TEST_F(homa_incoming, homa_abort_rpcs__ignore_dead_rpcs)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 1600);

	ASSERT_NE(NULL, crpc);
	homa_rpc_free(crpc);
	EXPECT_EQ(RPC_DEAD, crpc->state);
	unit_log_clear();
	homa_abort_rpcs(&self->homa, self->server_ip, 0, -ENOTCONN);
	EXPECT_EQ(0, crpc->error);
}
TEST_F(homa_incoming, homa_abort_rpcs__free_server_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_MSG,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 20000, 100);

	ASSERT_NE(NULL, srpc);
	unit_log_clear();
	homa_abort_rpcs(&self->homa, self->client_ip, 0, 0);
	EXPECT_EQ(RPC_DEAD, srpc->state);
}

TEST_F(homa_incoming, homa_abort_sock_rpcs__basics)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 1600);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port+1, self->client_id+2, 5000, 1600);
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 20000, 100);

	ASSERT_NE(NULL, crpc1);
	ASSERT_NE(NULL, crpc2);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();
	homa_abort_sock_rpcs(&self->hsk, -ENOTCONN);
	EXPECT_EQ(0, list_empty(&crpc1->ready_links));
	EXPECT_EQ(-ENOTCONN, crpc1->error);
	EXPECT_EQ(0, list_empty(&crpc2->ready_links));
	EXPECT_EQ(-ENOTCONN, crpc2->error);
	EXPECT_EQ(RPC_INCOMING, srpc->state);
}
TEST_F(homa_incoming, homa_abort_sock_rpcs__socket_shutdown)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 1600);
	ASSERT_NE(NULL, crpc1);
	unit_log_clear();
	self->hsk.shutdown = 1;
	homa_abort_sock_rpcs(&self->hsk, -ENOTCONN);
	self->hsk.shutdown = 0;
	EXPECT_EQ(RPC_OUTGOING, crpc1->state);
}
TEST_F(homa_incoming, homa_abort_sock_rpcs__rpc_already_dead)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 1600);

	ASSERT_NE(NULL, crpc);
	homa_rpc_free(crpc);
	EXPECT_EQ(RPC_DEAD, crpc->state);
	unit_log_clear();
	homa_abort_sock_rpcs(&self->hsk, -ENOTCONN);
	EXPECT_EQ(0, crpc->error);
}
TEST_F(homa_incoming, homa_abort_sock_rpcs__free_rpcs)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 1600);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port+1, self->client_id+2, 5000, 1600);

	ASSERT_NE(NULL, crpc1);
	ASSERT_NE(NULL, crpc2);
	unit_log_clear();
	homa_abort_sock_rpcs(&self->hsk, 0);
	EXPECT_EQ(RPC_DEAD, crpc1->state);
	EXPECT_EQ(RPC_DEAD, crpc2->state);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}

TEST_F(homa_incoming, homa_register_interests__id_not_for_client_rpc)
{
	int result;

	result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECVMSG_RESPONSE, 45);
	EXPECT_EQ(EINVAL, -result);
}
TEST_F(homa_incoming, homa_register_interests__no_rpc_for_id)
{
	int result;

	result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECVMSG_RESPONSE, 44);
	EXPECT_EQ(EINVAL, -result);
}
TEST_F(homa_incoming, homa_register_interests__id_already_has_interest)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_interest interest;

	ASSERT_NE(NULL, crpc);

	crpc->interest = &interest;
	int result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECVMSG_RESPONSE, self->client_id);
	EXPECT_EQ(EINVAL, -result);
	crpc->interest = NULL;
}
TEST_F(homa_incoming, homa_register_interests__return_response_by_id)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	int result;

	ASSERT_NE(NULL, crpc);

	result = homa_register_interests(&self->interest, &self->hsk,
			0, self->client_id);
	EXPECT_EQ(0, result);
	EXPECT_EQ(crpc, homa_interest_get_rpc(&self->interest));
	homa_rpc_unlock(crpc);
}
TEST_F(homa_incoming, homa_register_interests__socket_shutdown)
{
	int result;

	self->hsk.shutdown = 1;
	result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECVMSG_RESPONSE, 0);
	EXPECT_EQ(ESHUTDOWN, -result);
	self->hsk.shutdown = 0;
}
TEST_F(homa_incoming, homa_register_interests__specified_id_has_packets)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	int result;

	ASSERT_NE(NULL, crpc);
	result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECVMSG_REQUEST, crpc->id);
	EXPECT_EQ(0, result);
	EXPECT_EQ(crpc, homa_interest_get_rpc(&self->interest));
	homa_rpc_unlock(crpc);
}
TEST_F(homa_incoming, homa_register_interests__specified_id_has_error)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	int result;

	ASSERT_NE(NULL, crpc);
	crpc->error = -EFAULT;

	result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECVMSG_REQUEST|HOMA_RECVMSG_NONBLOCKING, crpc->id);
	EXPECT_EQ(0, result);
	EXPECT_EQ(crpc, homa_interest_get_rpc(&self->interest));
	homa_rpc_unlock(crpc);
}
TEST_F(homa_incoming, homa_register_interests__specified_id_not_ready)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	int result;

	ASSERT_NE(NULL, crpc);
	result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECVMSG_REQUEST, crpc->id);
	EXPECT_EQ(0, result);
	EXPECT_EQ(NULL, homa_interest_get_rpc(&self->interest));
}
TEST_F(homa_incoming, homa_register_interests__return_queued_response)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	int result;

	ASSERT_NE(NULL, crpc);
	result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECVMSG_REQUEST|HOMA_RECVMSG_RESPONSE, 0);
	EXPECT_EQ(0, result);
	EXPECT_EQ(crpc, homa_interest_get_rpc(&self->interest));
	EXPECT_EQ(LIST_POISON1, self->interest.request_links.next);
	EXPECT_EQ(LIST_POISON1, self->interest.response_links.next);
	homa_rpc_unlock(crpc);
}
TEST_F(homa_incoming, homa_register_interests__return_queued_request)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_MSG,
			self->client_ip, self->server_ip, self->client_port,
			1, 20000, 100);
	int result;

	ASSERT_NE(NULL, srpc);
	result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECVMSG_REQUEST|HOMA_RECVMSG_RESPONSE, 0);
	EXPECT_EQ(0, result);
	EXPECT_EQ(srpc, homa_interest_get_rpc(&self->interest));
	EXPECT_EQ(LIST_POISON1, self->interest.request_links.next);
	EXPECT_EQ(LIST_POISON1, self->interest.response_links.next);
	homa_rpc_unlock(srpc);
}
TEST_F(homa_incoming, homa_register_interests__call_sk_data_ready)
{
	struct homa_rpc *srpc1 = unit_server_rpc(&self->hsk, UNIT_RCVD_MSG,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 20000, 100);
	struct homa_rpc *srpc2 = unit_server_rpc(&self->hsk, UNIT_RCVD_MSG,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id+2, 20000, 100);
	int result;

	// First time should call sk_data_ready (for 2nd RPC).
	unit_log_clear();
	result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECVMSG_REQUEST|HOMA_RECVMSG_RESPONSE, 0);
	EXPECT_EQ(0, result);
	EXPECT_EQ(srpc1, homa_interest_get_rpc(&self->interest));
	EXPECT_STREQ("sk->sk_data_ready invoked", unit_log_get());
	homa_rpc_unlock(srpc1);

	// Second time shouldn't call sk_data_ready (no more RPCs).
	unit_log_clear();
	result = homa_register_interests(&self->interest, &self->hsk,
			HOMA_RECVMSG_REQUEST|HOMA_RECVMSG_RESPONSE
			|HOMA_RECVMSG_NONBLOCKING, 0);
	EXPECT_EQ(0, result);
	EXPECT_EQ(srpc2, homa_interest_get_rpc(&self->interest));
	EXPECT_STREQ("", unit_log_get());
	homa_rpc_unlock(srpc2);
}

TEST_F(homa_incoming, homa_wait_for_message__rpc_from_register_interests)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc);
	rpc = homa_wait_for_message(&self->hsk,
			HOMA_RECVMSG_RESPONSE|HOMA_RECVMSG_NONBLOCKING,
			self->client_id);
	EXPECT_EQ(crpc, rpc);
	homa_rpc_unlock(crpc);
}
TEST_F(homa_incoming, homa_wait_for_message__error_from_register_interests)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc);
	self->hsk.shutdown = 1;
	rpc = homa_wait_for_message(&self->hsk,
			HOMA_RECVMSG_RESPONSE|HOMA_RECVMSG_NONBLOCKING,
			self->client_id);
	EXPECT_EQ(ESHUTDOWN, -PTR_ERR(rpc));
	self->hsk.shutdown = 0;
}
TEST_F(homa_incoming, homa_wait_for_message__rpc_arrives_while_polling)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc1);
	hook_rpc = crpc1;
	poll_count = 5;
	unit_hook_register(poll_hook);
	unit_log_clear();
	rpc = homa_wait_for_message(&self->hsk, 0, self->client_id);
	EXPECT_EQ(crpc1, rpc);
	EXPECT_EQ(NULL, crpc1->interest);
	EXPECT_STREQ("wake_up_process pid 0", unit_log_get());
	EXPECT_EQ(0, self->hsk.dead_skbs);
	homa_rpc_unlock(rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__nothing_ready_nonblocking)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *rpc;

	unit_client_rpc(&self->hsk, UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2, 20000, 1600);
	ASSERT_NE(NULL, crpc1);

	rpc = homa_wait_for_message(&self->hsk, HOMA_RECVMSG_NONBLOCKING,
			self->client_id);
	EXPECT_EQ(EAGAIN, -PTR_ERR(rpc));
}
TEST_F(homa_incoming, homa_wait_for_message__rpc_arrives_while_sleeping)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc1);

	/* Also, check to see that reaping occurs before sleeping. */
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2, 20000, 20000);
	self->homa.reap_limit = 5;
	homa_rpc_free(crpc2);
	EXPECT_EQ(31, self->hsk.dead_skbs);
	unit_log_clear();

	hook_rpc = crpc1;
	unit_hook_register(handoff_hook);
	rpc = homa_wait_for_message(&self->hsk, 0, self->client_id);
	EXPECT_EQ(crpc1, rpc);
	EXPECT_EQ(NULL, crpc1->interest);
	EXPECT_STREQ("reaped 1236; wake_up_process pid 0; 0 in ready_requests, 0 in ready_responses, 0 in request_interests, 0 in response_interests",
			unit_log_get());
	EXPECT_EQ(0, self->hsk.dead_skbs);
	homa_rpc_unlock(rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__rpc_arrives_after_giving_up)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc);

	hook_rpc = crpc;
	unit_hook_register(handoff_hook2);
	unit_log_clear();
	rpc = homa_wait_for_message(&self->hsk,
			HOMA_RECVMSG_NONBLOCKING|HOMA_RECVMSG_RESPONSE, 0);
	ASSERT_EQ(crpc, rpc);
	EXPECT_EQ(NULL, crpc->interest);
	EXPECT_EQ(ETIMEDOUT, -rpc->error);
	homa_rpc_unlock(rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__handoff_rpc_then_delete_after_giving_up)
{
	// A key thing this test does it to ensure that RPC_HANDING_OFF
	// gets cleared even though the RPC has been deleted.
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc);

	// Prevent the RPC from being reaped during the test.
	atomic_or(RPC_COPYING_TO_USER, &crpc->flags);

	hook_rpc = crpc;
	hook3_count = 0;
	unit_hook_register(handoff_hook3);
	unit_log_clear();
	rpc = homa_wait_for_message(&self->hsk,
			HOMA_RECVMSG_NONBLOCKING|HOMA_RECVMSG_RESPONSE, 0);
	EXPECT_EQ(EAGAIN, -PTR_ERR(rpc));
	EXPECT_EQ(RPC_COPYING_TO_USER, atomic_read(&crpc->flags));
	EXPECT_EQ(RPC_DEAD, crpc->state);
	atomic_andnot(RPC_COPYING_TO_USER, &crpc->flags);
}
TEST_F(homa_incoming, homa_wait_for_message__explicit_rpc_deleted_while_sleeping)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	hook_rpc = crpc;
	unit_hook_register(delete_hook);
	rpc = homa_wait_for_message(&self->hsk, HOMA_RECVMSG_RESPONSE,
			self->client_id);
	EXPECT_EQ(EINVAL, -PTR_ERR(rpc));
}
TEST_F(homa_incoming, homa_wait_for_message__socket_shutdown_while_sleeping)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	hook_hsk = &self->hsk;
	unit_hook_register(shutdown_hook);
	rpc = homa_wait_for_message(&self->hsk,
			HOMA_RECVMSG_RESPONSE|HOMA_RECVMSG_REQUEST, 0);
	EXPECT_EQ(ESHUTDOWN, -PTR_ERR(rpc));
}
TEST_F(homa_incoming, homa_wait_for_message__copy_to_user)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc);
	mock_copy_to_user_dont_copy = -1;
	unit_log_clear();
	hook_hsk = &self->hsk;
	rpc = homa_wait_for_message(&self->hsk,
			HOMA_RECVMSG_RESPONSE|HOMA_RECVMSG_NONBLOCKING, 0);
	EXPECT_EQ(EAGAIN, -PTR_ERR(rpc));
	EXPECT_EQ(0, atomic_read(&crpc->flags)
			& (RPC_PKTS_READY|RPC_COPYING_TO_USER));
}
TEST_F(homa_incoming, homa_wait_for_message__rpc_freed_after_matching)
{
	/* Arrange for 2 RPCs to be ready, but delete the first one after
	 * it has matched; this should cause the second one to be matched.
	 */
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2, 20000, 1600);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc1);
	ASSERT_NE(NULL, crpc2);
	unit_log_clear();

	hook_rpc = crpc1;
	unit_hook_register(match_free_hook);
	rpc = homa_wait_for_message(&self->hsk,
			HOMA_RECVMSG_RESPONSE|HOMA_RECVMSG_NONBLOCKING, 0);
	EXPECT_EQ(RPC_DEAD, crpc1->state);
	EXPECT_EQ(crpc2, rpc);
	homa_rpc_unlock(rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__copy_to_user_fails)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	mock_copy_data_errors = 1;

	hook_hsk = &self->hsk;
	rpc = homa_wait_for_message(&self->hsk,
			HOMA_RECVMSG_RESPONSE|HOMA_RECVMSG_NONBLOCKING, 0);
	ASSERT_FALSE(IS_ERR(rpc));
	EXPECT_EQ(crpc, rpc);
	EXPECT_EQ(RPC_PKTS_READY, atomic_read(&crpc->flags) & RPC_PKTS_READY);
	EXPECT_EQ(EFAULT, -rpc->error);
	homa_rpc_unlock(rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__message_complete)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 2000);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc);
	mock_copy_to_user_dont_copy = -1;
	unit_log_clear();

	hook_hsk = &self->hsk;
	rpc = homa_wait_for_message(&self->hsk,
			HOMA_RECVMSG_RESPONSE|HOMA_RECVMSG_NONBLOCKING, 0);
	ASSERT_FALSE(IS_ERR(rpc));
	EXPECT_EQ(crpc, rpc);
	EXPECT_EQ(0, atomic_read(&crpc->flags)
			& (RPC_PKTS_READY|RPC_COPYING_TO_USER));
	homa_rpc_unlock(rpc);
}
TEST_F(homa_incoming, homa_wait_for_message__signal)
{
	struct homa_rpc *rpc;

	mock_signal_pending = 1;
	rpc = homa_wait_for_message(&self->hsk, HOMA_RECVMSG_REQUEST, 0);
	EXPECT_EQ(EINTR, -PTR_ERR(rpc));
}

TEST_F(homa_incoming, homa_choose_interest__empty_list)
{
	struct homa_interest *result = homa_choose_interest(&self->homa,
			&self->hsk.request_interests,
			offsetof(struct homa_interest, request_links));

	EXPECT_EQ(NULL, result);
}
TEST_F(homa_incoming, homa_choose_interest__find_idle_core)
{
	struct homa_interest interest1, interest2, interest3;

	homa_interest_init(&interest1);
	interest1.core = 1;
	list_add_tail(&interest1.request_links, &self->hsk.request_interests);
	homa_interest_init(&interest2);
	interest2.core = 2;
	list_add_tail(&interest2.request_links, &self->hsk.request_interests);
	homa_interest_init(&interest3);
	interest3.core = 3;
	list_add_tail(&interest3.request_links, &self->hsk.request_interests);

	mock_ns = 5000;
	self->homa.busy_ns = 1000;
	per_cpu(homa_offload_core, 1).last_active = 4100;
	per_cpu(homa_offload_core, 2).last_active = 3500;
	per_cpu(homa_offload_core, 3).last_active = 2000;

	struct homa_interest *result = homa_choose_interest(&self->homa,
			&self->hsk.request_interests,
			offsetof(struct homa_interest, request_links));
	ASSERT_NE(NULL, result);
	EXPECT_EQ(2, result->core);
	INIT_LIST_HEAD(&self->hsk.request_interests);
}
TEST_F(homa_incoming, homa_choose_interest__all_cores_busy)
{
	struct homa_interest interest1, interest2, interest3;

	homa_interest_init(&interest1);
	interest1.core = 1;
	list_add_tail(&interest1.request_links, &self->hsk.request_interests);
	homa_interest_init(&interest2);
	interest2.core = 2;
	list_add_tail(&interest2.request_links, &self->hsk.request_interests);
	homa_interest_init(&interest3);
	interest3.core = 3;
	list_add_tail(&interest3.request_links, &self->hsk.request_interests);

	mock_ns = 5000;
	self->homa.busy_ns = 1000;
	per_cpu(homa_offload_core, 1).last_active = 4100;
	per_cpu(homa_offload_core, 2).last_active = 4001;
	per_cpu(homa_offload_core, 3).last_active = 4800;

	struct homa_interest *result = homa_choose_interest(&self->homa,
			&self->hsk.request_interests,
			offsetof(struct homa_interest, request_links));
	INIT_LIST_HEAD(&self->hsk.request_interests);
	ASSERT_NE(NULL, result);
	EXPECT_EQ(1, result->core);
}

TEST_F(homa_incoming, homa_rpc_handoff__handoff_already_in_progress)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_interest interest;

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(NULL, crpc->interest);
	unit_log_clear();

	homa_interest_init(&interest);
	interest.thread = &mock_task;
	interest.reg_rpc = crpc;
	crpc->interest = &interest;
	atomic_or(RPC_HANDING_OFF, &crpc->flags);
	homa_rpc_handoff(crpc);
	crpc->interest = NULL;
	EXPECT_EQ(NULL, homa_interest_get_rpc(&interest));
	EXPECT_STREQ("", unit_log_get());
	atomic_andnot(RPC_HANDING_OFF, &crpc->flags);
}
TEST_F(homa_incoming, homa_rpc_handoff__rpc_already_enqueued)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_interest interest;

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(NULL, crpc->interest);
	unit_log_clear();

	/* First handoff enqueues the RPC. */
	homa_rpc_handoff(crpc);
	EXPECT_FALSE(list_empty(&crpc->ready_links));
	unit_log_clear();

	/* Second handoff does nothing, even though an interest is available. */

	homa_interest_init(&interest);
	interest.thread = &mock_task;
	interest.reg_rpc = crpc;
	crpc->interest = &interest;
	atomic_or(RPC_HANDING_OFF, &crpc->flags);
	homa_rpc_handoff(crpc);
	crpc->interest = NULL;
	EXPECT_EQ(NULL, homa_interest_get_rpc(&interest));
	EXPECT_STREQ("", unit_log_get());
	atomic_andnot(RPC_HANDING_OFF, &crpc->flags);
}
TEST_F(homa_incoming, homa_rpc_handoff__interest_on_rpc)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_interest interest;

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(NULL, crpc->interest);
	unit_log_clear();

	homa_interest_init(&interest);
	interest.thread = &mock_task;
	interest.reg_rpc = crpc;
	crpc->interest = &interest;
	homa_rpc_handoff(crpc);
	crpc->interest = NULL;
	EXPECT_EQ(crpc, homa_interest_get_rpc(&interest));
	EXPECT_EQ(NULL, interest.reg_rpc);
	EXPECT_EQ(NULL, crpc->interest);
	EXPECT_STREQ("wake_up_process pid 0", unit_log_get());
	atomic_andnot(RPC_HANDING_OFF, &crpc->flags);
}
TEST_F(homa_incoming, homa_rpc_handoff__response_interests)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_interest interest;

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(NULL, crpc->interest);
	unit_log_clear();

	homa_interest_init(&interest);
	interest.thread = &mock_task;
	list_add_tail(&interest.response_links, &self->hsk.response_interests);
	homa_rpc_handoff(crpc);
	EXPECT_EQ(crpc, homa_interest_get_rpc(&interest));
	EXPECT_EQ(0, unit_list_length(&self->hsk.response_interests));
	EXPECT_STREQ("wake_up_process pid 0", unit_log_get());
	atomic_andnot(RPC_HANDING_OFF, &crpc->flags);
}
TEST_F(homa_incoming, homa_rpc_handoff__queue_on_ready_responses)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);

	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	homa_rpc_handoff(crpc);
	EXPECT_STREQ("sk->sk_data_ready invoked", unit_log_get());
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_responses));
}
TEST_F(homa_incoming, homa_rpc_handoff__request_interests)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 20000, 100);
	struct homa_interest interest;

	ASSERT_NE(NULL, srpc);
	unit_log_clear();
	homa_interest_init(&interest);
	interest.thread = &mock_task;
	list_add_tail(&interest.request_links, &self->hsk.request_interests);
	homa_rpc_handoff(srpc);
	EXPECT_EQ(srpc, homa_interest_get_rpc(&interest));
	EXPECT_EQ(0, unit_list_length(&self->hsk.request_interests));
	EXPECT_STREQ("wake_up_process pid 0", unit_log_get());
	atomic_andnot(RPC_HANDING_OFF, &srpc->flags);
}
TEST_F(homa_incoming, homa_rpc_handoff__queue_on_ready_requests)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			1, 20000, 100);

	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	homa_rpc_handoff(srpc);
	EXPECT_STREQ("sk->sk_data_ready invoked", unit_log_get());
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_requests));
}
TEST_F(homa_incoming, homa_rpc_handoff__detach_interest)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_interest interest;

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(NULL, crpc->interest);
	unit_log_clear();

	homa_interest_init(&interest);
	interest.thread = &mock_task;
	interest.reg_rpc = crpc;
	crpc->interest = &interest;
	list_add_tail(&interest.response_links, &self->hsk.response_interests);
	list_add_tail(&interest.request_links, &self->hsk.request_interests);
	EXPECT_EQ(1, unit_list_length(&self->hsk.response_interests));
	EXPECT_EQ(1, unit_list_length(&self->hsk.request_interests));

	homa_rpc_handoff(crpc);
	crpc->interest = NULL;
	EXPECT_EQ(crpc, homa_interest_get_rpc(&interest));
	EXPECT_EQ(NULL, interest.reg_rpc);
	EXPECT_EQ(NULL, crpc->interest);
	EXPECT_EQ(0, unit_list_length(&self->hsk.response_interests));
	EXPECT_EQ(0, unit_list_length(&self->hsk.request_interests));
	atomic_andnot(RPC_HANDING_OFF, &crpc->flags);
}
TEST_F(homa_incoming, homa_rpc_handoff__update_last_app_active)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_interest interest;

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(NULL, crpc->interest);
	unit_log_clear();

	homa_interest_init(&interest);
	interest.thread = &mock_task;
	interest.reg_rpc = crpc;
	interest.core = 2;
	crpc->interest = &interest;
	mock_ns = 10000;
	per_cpu(homa_offload_core, 2).last_app_active = 444;
	homa_rpc_handoff(crpc);
	EXPECT_STREQ("wake_up_process pid 0", unit_log_get());
	EXPECT_EQ(10000, per_cpu(homa_offload_core, 2).last_app_active);
	atomic_andnot(RPC_HANDING_OFF, &crpc->flags);
}

TEST_F(homa_incoming, homa_incoming_sysctl_changed__grant_nonfifo)
{
	self->homa.fifo_grant_increment = 10000;
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
TEST_F(homa_incoming, homa_incoming_sysctl_changed__limit_on_max_overcommit)
{
	self->homa.max_overcommit = 2;
	homa_incoming_sysctl_changed(&self->homa);
	EXPECT_EQ(2, self->homa.max_overcommit);

	self->homa.max_overcommit = HOMA_MAX_GRANTS;
	homa_incoming_sysctl_changed(&self->homa);
	EXPECT_EQ(HOMA_MAX_GRANTS, self->homa.max_overcommit);

	self->homa.max_overcommit = HOMA_MAX_GRANTS+1;
	homa_incoming_sysctl_changed(&self->homa);
	EXPECT_EQ(HOMA_MAX_GRANTS, self->homa.max_overcommit);
}
TEST_F(homa_incoming, homa_incoming_sysctl_changed__convert_usec_to_ns)
{
	self->homa.busy_usecs = 53;
	self->homa.gro_busy_usecs = 140;
	homa_incoming_sysctl_changed(&self->homa);
	EXPECT_EQ(53000, self->homa.busy_ns);
	EXPECT_EQ(140000, self->homa.gro_busy_ns);
}
