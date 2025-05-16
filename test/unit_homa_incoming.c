// SPDX-License-Identifier: BSD-2-Clause

#include "homa_impl.h"
#include "homa_grant.h"
#include "homa_interest.h"
#include "homa_pacer.h"
#include "homa_peer.h"
#include "homa_pool.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#ifndef __STRIP__ /* See strip.py */
#include "homa_offload.h"
#endif /* See strip.py */

static struct homa_rpc *hook_rpc;
static int delete_count;
static int lock_delete_count;
static int hook_count;
static struct homa_sock *hook_shutdown_hsk;

static void wait_hook4(char *id)
{
	if (strcmp(id, "schedule") != 0 &&
	    strcmp(id, "do_wait_intr_irq") != 0 &&
	    strcmp(id, "prepare_to_wait") != 0)
		return;
	if (hook_count <= 0)
		return;
	hook_count--;
	if (hook_count != 0)
		return;
	if (hook_shutdown_hsk)
		homa_sock_shutdown(hook_shutdown_hsk);
	else
		homa_rpc_handoff(hook_rpc);
}

static void handoff_hook(char *id)
{
	if (strcmp(id, "spin_lock") != 0)
		return;
	if (hook_count <= 0)
		return;
	hook_count--;
	if (hook_count == 0) {
		hook_rpc->error = -ENOENT;
		homa_rpc_handoff(hook_rpc);
	}
}


#ifdef __STRIP__ /* See strip.py */
int mock_message_in_init(struct homa_rpc *rpc, int length, int unsched)
{
	return homa_message_in_init(rpc, length);
}
#define homa_message_in_init(rpc, length, unsched) \
		mock_message_in_init(rpc, length, unsched)
#endif /* See strip.py */

FIXTURE(homa_incoming) {
	struct in6_addr client_ip[5];
	int client_port;
	struct in6_addr server_ip[2];
	int server_port;
	u64 client_id;
	u64 server_id;
	union sockaddr_in_union server_addr;
	struct homa homa;
	struct homa_net *hnet;
	struct homa_sock hsk;
	struct homa_sock hsk2;
	struct homa_data_hdr data;
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
	self->hnet = mock_alloc_hnet(&self->homa);
#ifndef __STRIP__ /* See strip.py */
	self->homa.num_priorities = 1;
	self->homa.poll_cycles = 0;
#endif /* See strip.py */
	self->homa.flags |= HOMA_FLAG_DONT_THROTTLE;
	self->homa.pacer->fifo_fraction = 0;
#ifndef __STRIP__ /* See strip.py */
	self->homa.unsched_bytes = 10000;
	self->homa.grant->window = 10000;
#endif /* See strip.py */
	mock_sock_init(&self->hsk, self->hnet, 0);
	mock_sock_init(&self->hsk2, self->hnet, self->server_port);
	self->server_addr.in6.sin6_family = self->hsk.inet.sk.sk_family;
	self->server_addr.in6.sin6_addr = self->server_ip[0];
	self->server_addr.in6.sin6_port =  htons(self->server_port);
	memset(&self->data, 0, sizeof(self->data));
	self->data.common = (struct homa_common_hdr){
		.sport = htons(self->client_port),
		.dport = htons(self->server_port),
		.type = DATA,
		.sender_id = cpu_to_be64(self->client_id)
	};
	self->data.message_length = htonl(10000);
#ifndef __STRIP__ /* See strip.py */
	self->data.incoming = htonl(10000);
#endif /* See strip.py */
	unit_log_clear();
	delete_count = 0;
	lock_delete_count = 0;
	hook_shutdown_hsk = NULL;
}
FIXTURE_TEARDOWN(homa_incoming)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

#ifndef __STRIP__ /* See strip.py */
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
#endif /* See strip.py */
TEST_F(homa_incoming, homa_message_in_init__message_too_long)
{
	struct homa_rpc *srpc;
	int created;

	self->data.message_length = htonl(HOMA_MAX_MESSAGE_LENGTH+1);
	srpc = homa_rpc_alloc_server(&self->hsk, self->client_ip, &self->data,
			&created);
	ASSERT_TRUE(IS_ERR(srpc));
	EXPECT_EQ(EINVAL, -PTR_ERR(srpc));
}
TEST_F(homa_incoming, homa_message_in_init__no_buffer_region)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_pool_free(self->hsk.buffer_pool);
	self->hsk.buffer_pool = homa_pool_alloc(&self->hsk);
	EXPECT_EQ(ENOMEM, -homa_message_in_init(crpc, HOMA_BPAGE_SIZE*2, 0));
	EXPECT_EQ(0, crpc->msgin.num_bpages);
	EXPECT_EQ(-1, crpc->msgin.length);
}
TEST_F(homa_incoming, homa_message_in_init__no_buffers_available)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	atomic_set(&self->hsk.buffer_pool->free_bpages, 0);
	EXPECT_EQ(0, homa_message_in_init(crpc, HOMA_BPAGE_SIZE*2, 10000));
	EXPECT_EQ(0, crpc->msgin.num_bpages);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(0, crpc->msgin.granted);
#endif /* See strip.py */
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_incoming, homa_message_in_init__update_metrics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	EXPECT_EQ(0, homa_message_in_init(crpc, 140, 140));
	EXPECT_EQ(0, homa_message_in_init(crpc, 130, 130));
	EXPECT_EQ(0, homa_message_in_init(crpc, 0xfff, 0xfff));
	EXPECT_EQ(0, homa_message_in_init(crpc, 0xfff0, 0xfff0));
	EXPECT_EQ(0, homa_message_in_init(crpc, 0x3000, 0x3000));
	EXPECT_EQ(0, homa_message_in_init(crpc, 1000000, 1000000));
	EXPECT_EQ(0, homa_message_in_init(crpc, 900000, 900000));
	EXPECT_EQ(270, homa_metrics_per_cpu()->small_msg_bytes[2]);
	EXPECT_EQ(0xfff, homa_metrics_per_cpu()->small_msg_bytes[63]);
	EXPECT_EQ(0x3000, homa_metrics_per_cpu()->medium_msg_bytes[11]);
	EXPECT_EQ(0, homa_metrics_per_cpu()->medium_msg_bytes[15]);
	EXPECT_EQ(1900000, homa_metrics_per_cpu()->large_msg_bytes);
}
#endif /* See strip.py */

TEST_F(homa_incoming, homa_gap_retry)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk2, UNIT_RCVD_ONE_PKT,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 10000, 100);

	homa_gap_alloc(&srpc->msgin.gaps, 1000, 2000);
	homa_gap_alloc(&srpc->msgin.gaps, 4000, 6000);
	homa_gap_alloc(&srpc->msgin.gaps, 7000, 8000);
#ifndef __STRIP__ /* See strip.py */
	self->homa.num_priorities = 8;
#endif /* See strip.py */
	unit_log_clear();

	homa_gap_retry(srpc);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("xmit RESEND 1000-1999@7; "
			"xmit RESEND 4000-5999@7; "
			"xmit RESEND 7000-7999@7",
			unit_log_get());
#else /* See strip.py */
	EXPECT_STREQ("xmit RESEND 1000-1999; "
			"xmit RESEND 4000-5999; "
			"xmit RESEND 7000-7999",
			unit_log_get());
#endif /* See strip.py */
}

TEST_F(homa_incoming, homa_add_packet__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	unit_log_clear();
	mock_clock = 5000;
	self->data.seg.offset = htonl(1400);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 1400));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 800, 4200));
	EXPECT_STREQ("start 0, end 1400, time 5000; start 2800, end 4200, time 5000",
			unit_print_gaps(crpc));

	unit_log_clear();
	self->data.seg.offset = 0;
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 0));
	EXPECT_STREQ("start 2800, end 4200, time 5000", unit_print_gaps(crpc));
	EXPECT_EQ(6400, crpc->msgin.bytes_remaining);

	unit_log_clear();
	self->data.seg.offset = htonl(2800);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
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
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
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
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(1400);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 1400));

	self->data.seg.offset = htonl(2800);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
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
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
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
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	mock_kmalloc_errors = 1;
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
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
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 1400, end 4200", unit_print_gaps(crpc));

	self->data.seg.offset = htonl(0);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
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
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 1400, end 4200", unit_print_gaps(crpc));

	self->data.seg.offset = htonl(1000);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
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
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(2000);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 2000));
	EXPECT_STREQ("start 1400, end 2000", unit_print_gaps(crpc));

	self->data.seg.offset = htonl(1400);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
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
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 1400, end 4200", unit_print_gaps(crpc));

	self->data.seg.offset = htonl(1400);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
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
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(2800);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 2800));
	EXPECT_STREQ("start 1400, end 2800", unit_print_gaps(crpc));

	self->data.seg.offset = htonl(1400);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
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
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 1400, end 4200", unit_print_gaps(crpc));

	self->data.seg.offset = htonl(5000);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
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
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 1400, end 4200", unit_print_gaps(crpc));

	self->data.seg.offset = htonl(4000);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
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
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 1400, end 4200", unit_print_gaps(crpc));

	self->data.seg.offset = htonl(2800);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
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
	mock_clock = 1000;
	self->data.seg.offset = htonl(0);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 1400, end 4200, time 1000",
			unit_print_gaps(crpc));

	self->data.seg.offset = htonl(2000);
	mock_clock = 2000;
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
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
	mock_clock = 1000;
	self->data.seg.offset = htonl(0);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 1400, end 4200, time 1000",
			unit_print_gaps(crpc));

	self->data.seg.offset = htonl(2000);
	mock_clock = 2000;
	mock_kmalloc_errors = 1;
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
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
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 0));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 0, end 1400; start 2800, end 4200",
			unit_print_gaps(crpc));

	self->data.seg.offset = htonl(2800);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 2800));
	EXPECT_EQ(3, skb_queue_len(&crpc->msgin.packets));
	EXPECT_STREQ("start 0, end 1400", unit_print_gaps(crpc));
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_incoming, homa_add_packet__metrics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

	homa_message_in_init(crpc, 10000, 0);
	crpc->msgin.recv_end = 4200;
	self->data.seg.offset = htonl(0);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 0));
	EXPECT_EQ(0, skb_queue_len(&crpc->msgin.packets));
	EXPECT_EQ(0, homa_metrics_per_cpu()->resent_discards);
	EXPECT_EQ(1, homa_metrics_per_cpu()->packet_discards);

	self->data.retransmit = 1;
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 0));
	EXPECT_EQ(0, skb_queue_len(&crpc->msgin.packets));
	EXPECT_EQ(1, homa_metrics_per_cpu()->resent_discards);
	EXPECT_EQ(1, homa_metrics_per_cpu()->packet_discards);

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_EQ(1, skb_queue_len(&crpc->msgin.packets));
	EXPECT_EQ(1, homa_metrics_per_cpu()->resent_packets_used);
}
#endif /* See strip.py */

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
	homa_data_pkt(mock_skb_alloc(self->server_ip, &self->data.common,
			1400, 101000), crpc);
	self->data.seg.offset = htonl(2800);
	homa_data_pkt(mock_skb_alloc(self->server_ip, &self->data.common,
			1200, 201800), crpc);
	EXPECT_NE(0, atomic_read(&crpc->flags) & RPC_PKTS_READY);

	unit_log_clear();
	mock_copy_to_user_dont_copy = -1;
	homa_rpc_lock(crpc);
	EXPECT_EQ(0, -homa_copy_to_user(crpc));
	homa_rpc_unlock(crpc);
	EXPECT_STREQ("skb_copy_datagram_iter: 1400 bytes to 0x1000000: 0-1399; "
			"skb_copy_datagram_iter: 648 bytes to 0x1000578: 101000-101647; "
			"skb_copy_datagram_iter: 752 bytes to 0x1000800: 101648-102399; "
			"skb_copy_datagram_iter: 1200 bytes to 0x1000af0: 201800-202999",
			unit_log_get());
	EXPECT_EQ(0, skb_queue_len(&crpc->msgin.packets));
	EXPECT_EQ(0, atomic_read(&crpc->flags) & RPC_PKTS_READY);
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
	homa_rpc_end(crpc);

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
		homa_data_pkt(mock_skb_alloc(self->server_ip, &self->data.common,
				1400, offset), crpc);
	}
	EXPECT_EQ(8, skb_queue_len(&crpc->msgin.packets));

	unit_log_clear();
	mock_copy_to_user_dont_copy = -1;
	homa_rpc_lock(crpc);
	EXPECT_EQ(0, -homa_copy_to_user(crpc));
	homa_rpc_unlock(crpc);
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
	homa_rpc_lock(crpc);
	EXPECT_EQ(0, -homa_copy_to_user(crpc));
	homa_rpc_unlock(crpc);
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
	homa_data_pkt(mock_skb_alloc(self->server_ip, &self->data.common,
			3000, 101000), crpc);

	unit_log_clear();
	mock_copy_to_user_dont_copy = -1;
	homa_rpc_lock(crpc);
	EXPECT_EQ(0, -homa_copy_to_user(crpc));
	homa_rpc_unlock(crpc);
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
	homa_data_pkt(mock_skb_alloc(self->server_ip, &self->data.common,
			3000, 101000), crpc);

	unit_log_clear();
	mock_copy_to_user_dont_copy = -1;
	h = (struct homa_data_hdr *)skb_peek(&crpc->msgin.packets)->data;
	h->seg.offset = htonl(4000);
	homa_rpc_lock(crpc);
	EXPECT_EQ(0, -homa_copy_to_user(crpc));
	homa_rpc_unlock(crpc);
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
	homa_rpc_lock(crpc);
	EXPECT_EQ(13, -homa_copy_to_user(crpc));
	homa_rpc_unlock(crpc);
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
	homa_rpc_lock(crpc);
	EXPECT_EQ(14, -homa_copy_to_user(crpc));
	homa_rpc_unlock(crpc);
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
		homa_data_pkt(mock_skb_alloc(self->server_ip, &self->data.common,
				1400, offset), crpc);
	}
	EXPECT_EQ(8, skb_queue_len(&crpc->msgin.packets));

	unit_log_clear();
	mock_copy_to_user_dont_copy = -1;
	tt_init(NULL);
	homa_rpc_lock(crpc);
	EXPECT_EQ(0, -homa_copy_to_user(crpc));
	homa_rpc_unlock(crpc);
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
	mock_sock_init(&self->hsk, self->hnet, 0);

	skb = mock_skb_alloc(self->client_ip, &self->data.common, 1400, 1400);
	unit_log_clear();
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
	mock_sock_init(&self->hsk, self->hnet, 0);

	skb = mock_skb_alloc(self->client_ip, &self->data.common, 1400, 1400);
	unit_log_clear();
	homa_dispatch_pkts(skb, &self->homa);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_STREQ("icmp6_send type 1, code 4", unit_log_get());
}
TEST_F(homa_incoming, homa_dispatch_pkts__server_not_enabled)
{
	struct sk_buff *skb;

	self->data.common.dport = htons(100);

	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, self->hnet, 0);
	self->hsk.is_server = false;

	skb = mock_skb_alloc(self->client_ip, &self->data.common, 1400, 1400);
	unit_log_clear();
	homa_dispatch_pkts(skb, &self->homa);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_STREQ("icmp_send type 3, code 3", unit_log_get());
}
TEST_F(homa_incoming, homa_dispatch_pkts__unknown_socket_free_many_packets)
{
	struct sk_buff *skb, *skb2, *skb3;

	self->data.common.dport = htons(100);

	// Make sure the test uses IPv6.
	mock_ipv6 = true;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, self->hnet, 0);

	skb = mock_skb_alloc(self->client_ip, &self->data.common, 1400, 1400);
	skb2 = mock_skb_alloc(self->client_ip, &self->data.common, 1400, 1400);
	skb3 = mock_skb_alloc(self->client_ip, &self->data.common, 1400, 1400);
	skb->next = skb2;
	skb2->next = skb3;
	unit_log_clear();
	homa_dispatch_pkts(skb, &self->homa);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_STREQ("icmp6_send type 1, code 4", unit_log_get());
}
TEST_F(homa_incoming, homa_dispatch_pkts__new_server_rpc)
{
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &self->data.common,
			1400, 0), &self->homa);
	EXPECT_EQ(1, unit_list_length(&self->hsk2.active_rpcs));
	EXPECT_EQ(1, mock_skb_count());
}
TEST_F(homa_incoming, homa_dispatch_pkts__cant_create_server_rpc)
{
	mock_kmalloc_errors = 1;
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &self->data.common,
			1400, 0), &self->homa);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(0, mock_skb_count());
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->server_cant_create_rpcs);
#endif /* See strip.py */
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
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &self->data.common,
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
#ifndef __STRIP__ /* See strip.py */
		.length = 1000,
		.priority = 3};
#else /* See strip.py */
		.length = 1000};
#endif /* See strip.py */

	ASSERT_NE(NULL, srpc);
	unit_log_clear();
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &resend.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("xmit BUSY", unit_log_get());
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_incoming, homa_dispatch_pkts__existing_client_rpc)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(RPC_OUTGOING, crpc->state);
	unit_log_clear();

	crpc->msgout.next_xmit_offset = crpc->msgout.length;
	self->data.message_length = htonl(1600);
	homa_data_pkt(mock_skb_alloc(self->server_ip, &self->data.common,
			1400, 0), crpc);
	EXPECT_EQ(RPC_INCOMING, crpc->state);
	EXPECT_EQ(200, crpc->msgin.bytes_remaining);
}
TEST_F(homa_incoming, homa_dispatch_pkts__unknown_client_rpc)
{
	struct homa_grant_hdr h = {{.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(99991),
			.type = RPC_UNKNOWN}};

	mock_xmit_log_verbose = 1;
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &h.common, 0, 0),
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
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &h.common, 0, 0),
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

	homa_dispatch_pkts(mock_skb_alloc(self->server_ip, &h.common, 0, 0),
			&self->homa);
	peer = homa_peer_find(&self->hsk, self->server_ip);
	ASSERT_FALSE(IS_ERR(peer));
	EXPECT_EQ(400, peer->cutoff_version);
	EXPECT_EQ(9, peer->unsched_cutoffs[1]);
	EXPECT_EQ(3, peer->unsched_cutoffs[7]);
	homa_peer_put(peer);
}
#endif /* See strip.py */
TEST_F(homa_incoming, homa_dispatch_pkts__resend_for_unknown_server_rpc)
{
	struct homa_resend_hdr h = {{.sport = htons(self->client_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(99990),
			.type = RESEND},
#ifndef __STRIP__ /* See strip.py */
			.offset = 0, .length = 2000, .priority = 5};
#else /* See strip.py */
			.offset = 0, .length = 2000};
#endif /* See strip.py */

	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("xmit RPC_UNKNOWN", unit_log_get());
}
#ifndef __STRIP__ /* See strip.py */
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
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(10000, crpc->msgout.granted);
#endif /* See strip.py */
	unit_log_clear();
	crpc->silent_ticks = 5;
	crpc->peer->outstanding_resends = 2;
	homa_dispatch_pkts(mock_skb_alloc(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(0, crpc->silent_ticks);
	EXPECT_EQ(0, crpc->peer->outstanding_resends);

	/* Don't reset silent_ticks for some packet types. */
	h.common.type = CUTOFFS;
	crpc->silent_ticks = 5;
	crpc->peer->outstanding_resends = 2;
	homa_dispatch_pkts(mock_skb_alloc(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(5, crpc->silent_ticks);
	EXPECT_EQ(0, crpc->peer->outstanding_resends);
}
#endif /* See strip.py */
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
	skb = mock_skb_alloc(self->client_ip, &ack.common, 0, 0);
	skb2 = mock_skb_alloc(self->client_ip, &ack.common, 0, 0);
	skb3 = mock_skb_alloc(self->client_ip, &ack.common, 0, 0);
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
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(10000, crpc->msgout.granted);
#endif /* See strip.py */
	unit_log_clear();

	struct homa_common_hdr h = {.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id), .type = 99};
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &h, 0, 0), &self->homa);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->unknown_packet_types);
#endif /* See strip.py */
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
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &self->data.common,
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
	skb = mock_skb_alloc(self->client_ip, &self->data.common, 1400, 0);
	self->data.ack.client_id = cpu_to_be64(self->client_id+2);
	skb2 = mock_skb_alloc(self->client_ip, &self->data.common, 1400, 0);
	self->data.ack.client_id = cpu_to_be64(self->client_id+4);
	skb3 = mock_skb_alloc(self->client_ip, &self->data.common, 1400, 0);
	skb->next = skb2;
	skb2->next = skb3;
	homa_dispatch_pkts(skb, &self->homa);
	EXPECT_STREQ("sk->sk_data_ready invoked; ack 1237; ack 1235",
				unit_log_get());
}
#if 0
#ifndef __STRIP__ /* See strip.py */
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
#endif /* See strip.py */
#endif
TEST_F(homa_incoming, homa_dispatch_pkts__forced_reap)
{
	struct homa_rpc *dead = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 20000);
	struct homa_rpc *srpc;
	mock_clock_tick = 10;

	homa_rpc_end(dead);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(31, self->hsk.dead_skbs);
#else /* See strip.py */
	EXPECT_EQ(30, self->hsk.dead_skbs);
#endif /* See strip.py */
	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->client_port, self->server_id,
			10000, 5000);
	ASSERT_NE(NULL, srpc);
	self->homa.dead_buffs_limit = 16;

	/* First packet: below the threshold for reaps. */
	self->data.common.dport = htons(self->hsk.port);
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &self->data.common,
			1400, 0), &self->homa);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(31, self->hsk.dead_skbs);
#else /* See strip.py */
	EXPECT_EQ(30, self->hsk.dead_skbs);
#endif /* See strip.py */
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(0, homa_metrics_per_cpu()->data_pkt_reap_cycles);
#endif /* See strip.py */

	/* Second packet: must reap. */
	self->homa.dead_buffs_limit = 15;
	self->homa.reap_limit = 10;
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &self->data.common,
			1400, 0), &self->homa);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(21, self->hsk.dead_skbs);
#else /* See strip.py */
	EXPECT_EQ(20, self->hsk.dead_skbs);
#endif /* See strip.py */
#ifndef __STRIP__ /* See strip.py */
	EXPECT_NE(0, homa_metrics_per_cpu()->data_pkt_reap_cycles);
#endif /* See strip.py */
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
	homa_data_pkt(mock_skb_alloc(self->server_ip, &self->data.common,
			1400, 0), crpc);
	EXPECT_EQ(RPC_INCOMING, crpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_rpcs));
	EXPECT_EQ(200, crpc->msgin.bytes_remaining);
	EXPECT_EQ(1, skb_queue_len(&crpc->msgin.packets));
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1600, crpc->msgin.granted);
	EXPECT_EQ(1, homa_metrics_per_cpu()->responses_received);
#endif /* See strip.py */
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
	homa_data_pkt(mock_skb_alloc(self->server_ip, &self->data.common,
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
	homa_data_pkt(mock_skb_alloc(self->server_ip, &self->data.common,
			1400, 0), crpc);
	EXPECT_EQ(200, crpc->msgin.bytes_remaining);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1600, crpc->msgin.granted);
#endif /* See strip.py */
}
TEST_F(homa_incoming, homa_data_pkt__no_buffer_pool)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 1600);

	ASSERT_NE(NULL, crpc);
	homa_pool_free(self->hsk.buffer_pool);
	self->hsk.buffer_pool = homa_pool_alloc(&self->hsk);
	unit_log_clear();
	homa_data_pkt(mock_skb_alloc(self->server_ip, &self->data.common,
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
	homa_data_pkt(mock_skb_alloc(self->client_ip, &self->data.common,
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
	homa_data_pkt(mock_skb_alloc(self->server_ip, &self->data.common,
			1400, 0), crpc);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1400, homa_metrics_per_cpu()->dropped_data_no_bufs);
#endif /* See strip.py */
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
#ifndef __STRIP__ /* See strip.py */
	self->data.incoming = htonl(4000);
#endif /* See strip.py */
	homa_data_pkt(mock_skb_alloc(self->server_ip, &self->data.common,
			1400, 0), crpc);

	/* Total incoming drops on subsequent packet. */
	self->data.seg.offset = htonl(2800);
	homa_data_pkt(mock_skb_alloc(self->server_ip, &self->data.common,
			1400, 2800), crpc);

	/* Duplicate packet should have no effect. */
	self->data.seg.offset = htonl(2800);
	homa_data_pkt(mock_skb_alloc(self->server_ip, &self->data.common,
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
	homa_data_pkt(mock_skb_alloc(self->server_ip, &self->data.common,
			1400, 0), crpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_rpcs));
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
	homa_data_pkt(mock_skb_alloc(self->server_ip, &self->data.common,
			200, 0), crpc);
	EXPECT_STREQ("", unit_log_get());
}
#ifndef __STRIP__ /* See strip.py */
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
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &self->data.common,
			1400, 0), &self->homa);
	EXPECT_SUBSTR("cutoffs 19 18 17 16 15 14 13 12, version 2",
			unit_log_get());

	/* Try again, but this time no comments should be sent because
	 * no time has elapsed since the last cutoffs were sent.
	 */
	unit_log_clear();
	self->homa.cutoff_version = 3;
	self->data.seg.offset = 1400;
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &self->data.common,
			1400, 0), &self->homa);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_incoming, homa_data_pkt__cutoffs_up_to_date)
{
	self->homa.cutoff_version = 123;
	self->data.cutoff_version = htons(123);
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &self->data.common,
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
	homa_rpc_lock(srpc);
	homa_xmit_data(srpc, false);
	homa_rpc_unlock(srpc);
	unit_log_clear();

	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(11000, srpc->msgout.granted);
	EXPECT_STREQ("xmit DATA 1400@10000", unit_log_get());

	/* Don't let grant offset go backwards. */
	h.offset = htonl(10000);
	unit_log_clear();
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(11000, srpc->msgout.granted);
	EXPECT_STREQ("", unit_log_get());

	/* Wrong state. */
	h.offset = htonl(20000);
	srpc->state = RPC_INCOMING;
	unit_log_clear();
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &h.common, 0, 0),
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
	homa_rpc_lock(srpc);
	homa_xmit_data(srpc, false);
	homa_rpc_unlock(srpc);
	unit_log_clear();
	EXPECT_EQ(10000, srpc->msgout.granted);
	EXPECT_EQ(10000, srpc->msgout.next_xmit_offset);

	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &h.common, 0, 0),
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
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(20000, crpc->msgout.granted);
}
#endif /* See strip.py */

TEST_F(homa_incoming, homa_resend_pkt__unknown_rpc)
{
	struct homa_resend_hdr h = {{.sport = htons(self->client_port),
			.dport = htons(self->server_port),
			.sender_id = cpu_to_be64(self->client_id),
			.type = RESEND},
			.offset = htonl(100),
			.length = htonl(200)};

	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("xmit RPC_UNKNOWN", unit_log_get());
}
TEST_F(homa_incoming, homa_resend_pkt__rpc_in_service_server_sends_busy)
{
	struct homa_resend_hdr h = {{.sport = htons(self->client_port),
			.dport = htons(self->server_port),
			.sender_id = cpu_to_be64(self->client_id),
			.type = RESEND},
			.offset = htonl(0),
			.length = htonl(200)};
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk2, UNIT_IN_SERVICE,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 2000, 20000);

	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &h.common, 0, 0),
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
			.length = htonl(200)};
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk2, UNIT_RCVD_ONE_PKT,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 2000, 20000);

	ASSERT_NE(NULL, srpc);
#ifndef __STRIP__ /* See strip.py */
	srpc->msgin.granted = 1400;
#endif /* See strip.py */
	unit_log_clear();

	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &h.common, 0, 0),
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
			.length = htonl(200)};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 2000, 3000);

	ASSERT_NE(NULL, crpc);
	unit_log_clear();

	homa_dispatch_pkts(mock_skb_alloc(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("xmit DATA retrans 1400@0", unit_log_get());
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_incoming, homa_resend_pkt__send_busy_instead_of_data)
{
	struct homa_resend_hdr h = {{.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = RESEND},
			.offset = htonl(100),
			.length = htonl(200)};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 2000, 100);

	ASSERT_NE(NULL, crpc);
	unit_log_clear();

	homa_dispatch_pkts(mock_skb_alloc(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_SUBSTR("xmit BUSY", unit_log_get());
}
#endif /* See strip.py */
TEST_F(homa_incoming, homa_resend_pkt__client_send_data)
{
	struct homa_resend_hdr h = {{.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = RESEND},
			.offset = htonl(100),
#ifndef __STRIP__ /* See strip.py */
			.length = htonl(200),
			.priority = 3};
#else /* See strip.py */
			.length = htonl(200)};
#endif /* See strip.py */
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 2000, 100);

	ASSERT_NE(NULL, crpc);
	homa_rpc_lock(crpc);
	homa_xmit_data(crpc, false);
	homa_rpc_unlock(crpc);
	unit_log_clear();
	mock_clear_xmit_prios();

	homa_dispatch_pkts(mock_skb_alloc(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_SUBSTR("xmit DATA retrans 1400@0", unit_log_get());
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("3", mock_xmit_prios);
#endif /* See strip.py */
}
TEST_F(homa_incoming, homa_resend_pkt__server_send_data)
{
	struct homa_resend_hdr h = {{.sport = htons(self->client_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->client_id),
			.type = RESEND},
			.offset = htonl(100),
#ifndef __STRIP__ /* See strip.py */
			.length = htonl(2000),
			.priority = 4};
#else /* See strip.py */
			.length = htonl(2000)};
#endif /* See strip.py */
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 20000);

	ASSERT_NE(NULL, srpc);
	homa_rpc_lock(srpc);
	homa_xmit_data(srpc, false);
	homa_rpc_unlock(srpc);
	unit_log_clear();
	mock_clear_xmit_prios();

	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("xmit DATA retrans 1400@0; "
			"xmit DATA retrans 1400@1400", unit_log_get());
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("4 4", mock_xmit_prios);
#endif /* See strip.py */
}

TEST_F(homa_incoming, homa_unknown_pkt__client_resend_all)
{
	struct homa_rpc_unknown_hdr h = {{.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = RPC_UNKNOWN}};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 2000, 2000);

	ASSERT_NE(NULL, crpc);
	homa_rpc_lock(crpc);
	homa_xmit_data(crpc, false);
	homa_rpc_unlock(crpc);
	unit_log_clear();

	mock_xmit_log_verbose = 1;
	homa_dispatch_pkts(mock_skb_alloc(self->server_ip, &h.common, 0, 0),
			&self->homa);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_SUBSTR("xmit DATA from 0.0.0.0:32768, dport 99, id 1234, message_length 2000, offset 0, data_length 1400, incoming 2000, RETRANSMIT; "
			"xmit DATA from 0.0.0.0:32768, dport 99, id 1234, message_length 2000, offset 1400, data_length 600, incoming 2000, RETRANSMIT",
			unit_log_get());
#else /* See strip.py */
	EXPECT_SUBSTR("xmit DATA from 0.0.0.0:32768, dport 99, id 1234, message_length 2000, offset 0, data_length 1400, RETRANSMIT; "
			"xmit DATA from 0.0.0.0:32768, dport 99, id 1234, message_length 2000, offset 1400, data_length 600, RETRANSMIT",
			unit_log_get());
#endif /* See strip.py */
	EXPECT_EQ(-1, crpc->msgin.length);
}
TEST_F(homa_incoming, homa_unknown_pkt__client_resend_part)
{
	struct homa_rpc_unknown_hdr h = {{.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = RPC_UNKNOWN}};
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 2000, 2000);

	ASSERT_NE(NULL, crpc);
#ifndef __STRIP__ /* See strip.py */
	crpc->msgout.granted = 1400;
#endif /* See strip.py */
	homa_rpc_lock(crpc);
	homa_xmit_data(crpc, false);
	homa_rpc_unlock(crpc);
	unit_log_clear();

	mock_xmit_log_verbose = 1;
	homa_dispatch_pkts(mock_skb_alloc(self->server_ip, &h.common, 0, 0),
			&self->homa);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_SUBSTR("xmit DATA from 0.0.0.0:32768, dport 99, id 1234, message_length 2000, offset 0, data_length 1400, incoming 1400, RETRANSMIT",
			unit_log_get());
#else /* See strip.py */
	EXPECT_SUBSTR("xmit DATA from 0.0.0.0:32768, dport 99, id 1234, message_length 2000, offset 0, data_length 1400, RETRANSMIT",
			unit_log_get());
#endif /* See strip.py */
	EXPECT_EQ(-1, crpc->msgin.length);
}
TEST_F(homa_incoming, homa_unknown_pkt__free_server_rpc)
{
	struct homa_rpc_unknown_hdr h = {{.sport = htons(self->client_port),
			.dport = htons(self->hsk2.port),
			.sender_id = cpu_to_be64(self->client_id),
			.type = RPC_UNKNOWN}};
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk2, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 20000);

	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("DEAD", homa_symbol_for_state(srpc));
}

#ifndef __STRIP__ /* See strip.py */
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

	homa_dispatch_pkts(mock_skb_alloc(self->server_ip, &h.common, 0, 0),
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
	struct sk_buff *skb = mock_skb_alloc(self->server_ip, &h.common, 0, 0);
	struct homa_peer *peer;

	mock_kmalloc_errors = 1;
	homa_cutoffs_pkt(skb, &self->hsk);
	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_kmalloc_errors);
	peer = homa_peer_find(&self->hsk, self->server_ip);
	ASSERT_FALSE(IS_ERR(peer));
	EXPECT_EQ(0, peer->cutoff_version);
	homa_peer_put(peer);
}
#endif /* See strip.py */

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
	homa_dispatch_pkts(mock_skb_alloc(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("xmit ACK from 0.0.0.0:32768, dport 99, id 1234, acks",
			unit_log_get());
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->packets_received[
			NEED_ACK - DATA]);
#endif /* See strip.py */
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
	homa_dispatch_pkts(mock_skb_alloc(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("", unit_log_get());
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->packets_received[
			NEED_ACK - DATA]);
#endif /* See strip.py */
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
	homa_dispatch_pkts(mock_skb_alloc(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("", unit_log_get());
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->packets_received[
			NEED_ACK - DATA]);
#endif /* See strip.py */
}
TEST_F(homa_incoming, homa_need_ack_pkt__rpc_doesnt_exist)
{
	struct homa_peer *peer = homa_peer_find(&self->hsk, self->server_ip);
	struct homa_need_ack_hdr h = {.common = {
			.sport = htons(self->server_port),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(self->server_id),
			.type = NEED_ACK}};

	peer->acks[0].server_port = htons(self->server_port);
	peer->acks[0].client_id = cpu_to_be64(self->client_id+2);
	peer->num_acks = 1;
	mock_xmit_log_verbose = 1;
	homa_dispatch_pkts(mock_skb_alloc(self->server_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_STREQ("xmit ACK from 0.0.0.0:32768, dport 99, id 1234, acks [sp 99, id 1236]",
			unit_log_get());
	homa_peer_put(peer);
}

TEST_F(homa_incoming, homa_ack_pkt__target_rpc_exists_no_extras)
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
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(0, unit_list_length(&self->hsk2.active_rpcs));
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->packets_received[ACK - DATA]);
#endif /* See strip.py */
}
TEST_F(homa_incoming, homa_ack_pkt__target_rpc_exists_plus_extras)
{
	struct homa_rpc *srpc1 = unit_server_rpc(&self->hsk2, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 5000);
	struct homa_rpc *srpc2 = unit_server_rpc(&self->hsk2, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id+2, 100, 5000);
	struct homa_rpc *srpc3 = unit_server_rpc(&self->hsk2, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id+4, 100, 5000);
	struct homa_ack_hdr h = {.common = {
			.sport = htons(self->client_port),
			.dport = htons(self->hsk2.port),
			.sender_id = cpu_to_be64(self->client_id),
			.type = ACK},
			.num_acks = htons(2)};

	ASSERT_NE(NULL, srpc1);
	ASSERT_NE(NULL, srpc2);
	ASSERT_NE(NULL, srpc3);
	EXPECT_EQ(3, unit_list_length(&self->hsk2.active_rpcs));
	unit_log_clear();
	mock_xmit_log_verbose = 1;
	h.acks[0] = (struct homa_ack) {.server_port = htons(self->server_port),
			.client_id = cpu_to_be64(self->server_id+1)};
	h.acks[1] = (struct homa_ack) {.server_port = htons(self->server_port),
			.client_id = cpu_to_be64(self->server_id+3)};
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &h.common, 0, 0),
			&self->homa);
	EXPECT_EQ(0, unit_list_length(&self->hsk2.active_rpcs));
	EXPECT_STREQ("DEAD", homa_symbol_for_state(srpc1));
	EXPECT_STREQ("DEAD", homa_symbol_for_state(srpc2));
	EXPECT_STREQ("DEAD", homa_symbol_for_state(srpc2));
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
	homa_dispatch_pkts(mock_skb_alloc(self->client_ip, &h.common, 0, 0),
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
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_rpcs));
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
	EXPECT_EQ(2, unit_list_length(&self->hsk.ready_rpcs));
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
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_rpcs));
	EXPECT_EQ(0, list_empty(&crpc1->ready_links));
	EXPECT_EQ(EPROTONOSUPPORT, -crpc1->error);
	EXPECT_EQ(0, list_empty(&crpc2->ready_links));
	EXPECT_EQ(EPROTONOSUPPORT, -crpc2->error);
	EXPECT_EQ(0, list_empty(&crpc3->ready_links));
	EXPECT_EQ(2, unit_list_length(&self->hsk2.active_rpcs));
	EXPECT_EQ(2, unit_list_length(&self->hsk2.ready_rpcs));
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
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_rpcs));
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
	EXPECT_EQ(2, unit_list_length(&self->hsk.ready_rpcs));
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
	homa_rpc_end(crpc);
	EXPECT_EQ(RPC_DEAD, crpc->state);
	unit_log_clear();
	homa_abort_rpcs(&self->homa, self->server_ip, 0, -ENOTCONN);
	EXPECT_EQ(-EINVAL, crpc->error);
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
	homa_rpc_end(crpc);
	EXPECT_EQ(RPC_DEAD, crpc->state);
	unit_log_clear();
	homa_abort_sock_rpcs(&self->hsk, -ENOTCONN);
	EXPECT_EQ(-EINVAL, crpc->error);
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

TEST_F(homa_incoming, homa_wait_private__rpc_not_private)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(EINVAL, -homa_wait_private(crpc, 0));
}
TEST_F(homa_incoming, homa_wait_private__available_immediately)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);

	ASSERT_NE(NULL, crpc);
	ASSERT_EQ(RPC_PKTS_READY, atomic_read(&crpc->flags));
	atomic_or(RPC_PRIVATE, &crpc->flags);
	homa_rpc_lock(crpc);
	EXPECT_EQ(0, homa_wait_private(crpc, 0));
	homa_rpc_unlock(crpc);
	ASSERT_EQ(RPC_PRIVATE, atomic_read(&crpc->flags));
	IF_NO_STRIP(EXPECT_EQ(1, homa_metrics_per_cpu()->wait_none));
}
TEST_F(homa_incoming, homa_wait_private__rpc_has_error)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);

	ASSERT_NE(NULL, crpc);
	ASSERT_EQ(RPC_PKTS_READY, atomic_read(&crpc->flags));
	atomic_or(RPC_PRIVATE, &crpc->flags);
	crpc->error = -ENOENT;
	homa_rpc_lock(crpc);
	EXPECT_EQ(ENOENT, -homa_wait_private(crpc, 0));
	homa_rpc_unlock(crpc);
	EXPECT_EQ(RPC_PKTS_READY, atomic_read(&crpc->flags) & RPC_PKTS_READY);
}
TEST_F(homa_incoming, homa_wait_private__copy_to_user_fails)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);

	ASSERT_NE(NULL, crpc);
	ASSERT_EQ(RPC_PKTS_READY, atomic_read(&crpc->flags));
	atomic_or(RPC_PRIVATE, &crpc->flags);
	mock_copy_data_errors = 1;
	homa_rpc_lock(crpc);
	EXPECT_EQ(EFAULT, -homa_wait_private(crpc, 0));
	homa_rpc_unlock(crpc);
}
TEST_F(homa_incoming, homa_wait_private__nonblocking)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);

	ASSERT_NE(NULL, crpc);
	atomic_or(RPC_PRIVATE, &crpc->flags);

	homa_rpc_lock(crpc);
	EXPECT_EQ(EAGAIN, -homa_wait_private(crpc, 1));
	homa_rpc_unlock(crpc);
	IF_NO_STRIP(EXPECT_EQ(1, homa_metrics_per_cpu()->wait_fast));
}
TEST_F(homa_incoming, homa_wait_private__signal_notify_race)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1000);

	ASSERT_NE(NULL, crpc);
	atomic_or(RPC_PRIVATE, &crpc->flags);
	IF_NO_STRIP(self->homa.poll_cycles = 0);
	unit_hook_register(handoff_hook);
	hook_rpc = crpc;
	hook_count = 2;
	mock_prepare_to_wait_errors = 1;

	homa_rpc_lock(crpc);
	EXPECT_EQ(ENOENT, -homa_wait_private(crpc, 0));
	homa_rpc_unlock(crpc);
	IF_NO_STRIP(EXPECT_EQ(1, homa_metrics_per_cpu()->wait_block));
	EXPECT_EQ(0, mock_prepare_to_wait_errors);
}

TEST_F(homa_incoming, homa_wait_shared__socket_already_shutdown)
{
	struct homa_rpc *rpc;

	self->hsk.shutdown = 1;

	rpc = homa_wait_shared(&self->hsk, 0);
	EXPECT_TRUE(IS_ERR(rpc));
	EXPECT_EQ(ESHUTDOWN, -PTR_ERR(rpc));
	self->hsk.shutdown = 0;
}
TEST_F(homa_incoming, homa_wait_shared__rpc_already_ready)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc);
	ASSERT_EQ(RPC_PKTS_READY, atomic_read(&crpc->flags));

	rpc = homa_wait_shared(&self->hsk, 0);
	ASSERT_FALSE(IS_ERR(rpc));
	EXPECT_EQ(crpc, rpc);
	EXPECT_EQ(0, crpc->msgin.packets.qlen);
	IF_NO_STRIP(EXPECT_EQ(1, homa_metrics_per_cpu()->wait_none));
	homa_rpc_unlock(rpc);
}
TEST_F(homa_incoming, homa_wait_shared__multiple_rpcs_already_ready)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2, 1000, 1600);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc);
	ASSERT_NE(NULL, crpc2);

	unit_log_clear();
	rpc = homa_wait_shared(&self->hsk, 0);
	ASSERT_FALSE(IS_ERR(rpc));
	EXPECT_EQ(crpc, rpc);
	homa_rpc_unlock(rpc);
	EXPECT_SUBSTR("sk->sk_data_ready invoked", unit_log_get());
}
TEST_F(homa_incoming, homa_wait_shared__nonblocking)
{
	struct homa_rpc *rpc;

	rpc = homa_wait_shared(&self->hsk, 1);
	EXPECT_TRUE(IS_ERR(rpc));
	EXPECT_EQ(EAGAIN, -PTR_ERR(rpc));
	IF_NO_STRIP(EXPECT_EQ(1, homa_metrics_per_cpu()->wait_fast));
}
TEST_F(homa_incoming, homa_wait_shared__signal_race_with_handoff)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc);
	crpc->error = -ENOENT;
	unit_hook_register(handoff_hook);
	hook_rpc = crpc;
	hook_count = 2;
	mock_prepare_to_wait_errors = 1;

	rpc = homa_wait_shared(&self->hsk, 0);
	EXPECT_EQ(crpc, rpc);
	EXPECT_EQ(ENOENT, -rpc->error);
	IF_NO_STRIP(EXPECT_EQ(1, homa_metrics_per_cpu()->wait_block));
	homa_rpc_unlock(rpc);
}
TEST_F(homa_incoming, homa_wait_shared__socket_shutdown_while_blocked)
{
	struct homa_rpc *rpc;

	unit_hook_register(wait_hook4);
	hook_shutdown_hsk = &self->hsk;
	hook_count = 4;

	rpc = homa_wait_shared(&self->hsk, 0);
	EXPECT_TRUE(IS_ERR(rpc));
	EXPECT_EQ(ESHUTDOWN, -PTR_ERR(rpc));
	EXPECT_EQ(1, self->hsk.shutdown);
	self->hsk.shutdown = 0;
	IF_NO_STRIP(EXPECT_EQ(1, homa_metrics_per_cpu()->wait_block));
}
TEST_F(homa_incoming, homa_wait_shared__copy_to_user_fails)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc);
	ASSERT_EQ(RPC_PKTS_READY, atomic_read(&crpc->flags));
	mock_copy_data_errors = 1;

	rpc = homa_wait_shared(&self->hsk, 0);
	EXPECT_EQ(crpc, rpc);
	EXPECT_EQ(EFAULT, -rpc->error);
	homa_rpc_unlock(rpc);
}
TEST_F(homa_incoming, homa_wait_shared__rpc_has_error)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(2, crpc->msgin.packets.qlen);
	crpc->error = -ENOENT;

	rpc = homa_wait_shared(&self->hsk, 0);
	EXPECT_EQ(crpc, rpc);
	EXPECT_EQ(2, crpc->msgin.packets.qlen);
	homa_rpc_unlock(rpc);
}
TEST_F(homa_incoming, homa_wait_shared__rpc_dead)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_rpc *rpc;

	ASSERT_NE(NULL, crpc);
	ASSERT_NE(NULL, crpc2);
	homa_rpc_end(crpc);

	rpc = homa_wait_shared(&self->hsk, 0);
	EXPECT_EQ(crpc2, rpc);
	homa_rpc_unlock(rpc);
}

TEST_F(homa_incoming, homa_rpc_handoff__private_rpc)
{
	struct homa_interest interest;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);

	ASSERT_NE(NULL, crpc);
	atomic_or(RPC_PRIVATE, &crpc->flags);
	homa_interest_init_private(&interest, crpc);
	mock_log_wakeups = 1;
	unit_log_clear();

	homa_rpc_handoff(crpc);
	EXPECT_STREQ("wake_up", unit_log_get());
	EXPECT_EQ(1, atomic_read(&interest.ready));
	EXPECT_TRUE(list_empty(&self->hsk.ready_rpcs));
	homa_interest_unlink_private(&interest);
}
TEST_F(homa_incoming, homa_rpc_handoff__handoff_to_shared_interest)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);
	struct homa_interest interest1, interest2;

	ASSERT_NE(NULL, crpc);
	homa_interest_init_shared(&interest1, &self->hsk);
	homa_interest_init_shared(&interest2, &self->hsk);
	EXPECT_EQ(2, unit_list_length(&self->hsk.interests));
	unit_log_clear();

	homa_rpc_handoff(crpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.interests));
	EXPECT_EQ(0, atomic_read(&interest1.ready));
	EXPECT_EQ(1, atomic_read(&interest2.ready));
	EXPECT_EQ(crpc, interest2.rpc);
	homa_rpc_put(crpc);
	homa_interest_unlink_shared(&interest1);
	IF_NO_STRIP(EXPECT_EQ(1, homa_metrics_per_cpu()->handoffs_thread_waiting));
}
TEST_F(homa_incoming, homa_rpc_handoff__queue_rpc_on_socket)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 1600);

	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	mock_log_wakeups = 1;

	/* First call should queue RPC. */
	homa_rpc_handoff(crpc);
	EXPECT_STREQ("sk->sk_data_ready invoked", unit_log_get());
	EXPECT_FALSE(list_empty(&self->hsk.ready_rpcs));

	/* Calling again should do nothing (already queued). */
	unit_log_clear();
	homa_rpc_handoff(crpc);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_FALSE(list_empty(&self->hsk.ready_rpcs));
}

#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_incoming, homa_incoming_sysctl_changed__convert_usec_to_cycles)
{
	self->homa.poll_usecs = 27;
	self->homa.busy_usecs = 53;
	self->homa.gro_busy_usecs = 140;
	self->homa.bpage_lease_usecs = 700;
	homa_incoming_sysctl_changed(&self->homa);
	EXPECT_EQ(27000, self->homa.poll_cycles);
	EXPECT_EQ(53000, self->homa.busy_cycles);
	EXPECT_EQ(140000, self->homa.gro_busy_cycles);
	EXPECT_EQ(700000, self->homa.bpage_lease_cycles);
}
#endif /* See strip.py */
