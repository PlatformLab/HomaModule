// SPDX-License-Identifier: BSD-2-Clause

#include "homa_impl.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#include "homa_skb.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

/* The following hook function frees hook_rpc. */
static struct homa_rpc *hook_rpc;
static void unlock_hook(char *id)
{
	if (strcmp(id, "unlock") != 0)
		return;
	if (hook_rpc) {
		homa_rpc_free(hook_rpc);
		hook_rpc = NULL;
	}
}

/* The following hook function frees an RPC when it is locked. */
void lock_free_hook(char *id)
{
	if (strcmp(id, "spin_lock") != 0)
		return;
	if (hook_rpc) {
		homa_rpc_free(hook_rpc);
		hook_rpc = NULL;
	}
}

FIXTURE(homa_outgoing) {
	struct in6_addr client_ip[1];
	int client_port;
	struct in6_addr server_ip[1];
	int server_port;
	__u64 client_id;
	__u64 server_id;
	struct homa homa;
	struct homa_sock hsk;
	union sockaddr_in_union server_addr;
	struct homa_peer *peer;
};
FIXTURE_SETUP(homa_outgoing)
{
	self->client_ip[0] = unit_get_in_addr("196.168.0.1");
	self->client_port = 40000;
	self->server_ip[0] = unit_get_in_addr("1.2.3.4");
	self->server_port = 99;
	self->client_id = 1234;
	self->server_id = 1235;
	homa_init(&self->homa);
	mock_ns = 10000;
	atomic64_set(&self->homa.link_idle_time, 10000);
	self->homa.ns_per_mbyte = 1000000;
	self->homa.flags |= HOMA_FLAG_DONT_THROTTLE;
	mock_sock_init(&self->hsk, &self->homa, self->client_port);
	self->server_addr.in6.sin6_family = AF_INET;
	self->server_addr.in6.sin6_addr = self->server_ip[0];
	self->server_addr.in6.sin6_port = htons(self->server_port);
	self->peer = homa_peer_find(self->homa.peers,
			&self->server_addr.in6.sin6_addr, &self->hsk.inet);
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_outgoing)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_outgoing, set_priority__priority_mapping)
{
	struct homa_rpc *srpc;
	struct grant_header h;

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	h.offset = htonl(12345);
	h.priority = 4;
	h.resend_all = 0;
	EXPECT_EQ(0, homa_xmit_control(GRANT, &h, sizeof(h), srpc));
	self->homa.priority_map[7] = 3;
	EXPECT_EQ(0, homa_xmit_control(GRANT, &h, sizeof(h), srpc));
	EXPECT_STREQ("7 3", mock_xmit_prios);
}

TEST_F(homa_outgoing, homa_fill_data_interleaved)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	char buffer[1000];

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 10000);

	unit_log_clear();
	struct sk_buff *skb = homa_new_data_packet(crpc, iter, 10000, 5000,
			1500);
	EXPECT_STREQ("_copy_from_iter 1500 bytes at 1000; "
			"_copy_from_iter 1500 bytes at 2500; "
			"_copy_from_iter 1500 bytes at 4000; "
			"_copy_from_iter 500 bytes at 5500", unit_log_get());

	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 2, message_length 10000, offset 10000, data_length 1500, incoming 10000, extra segs 1500@11500 1500@13000 500@14500",
			homa_print_packet(skb, buffer, sizeof(buffer)));
	EXPECT_EQ(5000 + sizeof32(struct data_header)
			+ 3*sizeof32(struct seg_header), skb->len);
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_fill_data_interleaved__error_copying_data)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	struct sk_buff *skb;

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 10000);

	unit_log_clear();
	mock_copy_data_errors = 1;
	skb = homa_new_data_packet(crpc, iter, 10000, 5000, 1500);
	EXPECT_EQ(EFAULT, -PTR_ERR(skb));
}

TEST_F(homa_outgoing, homa_new_data_packet__one_segment)
{
	struct iov_iter *iter = unit_iov_iter((void *) 1000, 5000);
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);
	struct sk_buff *skb;
	char buffer[1000];

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 500);

	unit_log_clear();
	skb = homa_new_data_packet(crpc, iter, 5000, 500, 2000);
	EXPECT_STREQ("_copy_from_iter 500 bytes at 1000", unit_log_get());

	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 2, message_length 500, offset 5000, data_length 500, incoming 500",
			homa_print_packet(skb, buffer, sizeof(buffer)));

	EXPECT_EQ(0, skb_shinfo(skb)->gso_segs);
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_new_data_packet__cant_allocate_skb)
{
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);
	struct sk_buff *skb;

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 500);

	unit_log_clear();
	mock_alloc_skb_errors = 1;
	skb = homa_new_data_packet(crpc, iter, 0, 500, 2000);
	EXPECT_TRUE(IS_ERR(skb));
	EXPECT_EQ(ENOMEM, -PTR_ERR(skb));
}
TEST_F(homa_outgoing, homa_new_data_packet__multiple_segments_homa_fill_data_interleaved)
{
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);
	struct sk_buff *skb;
	char buffer[1000];

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 10000);

	unit_log_clear();
	skb = homa_new_data_packet(crpc, iter, 10000, 5000, 1500);
	EXPECT_STREQ("_copy_from_iter 1500 bytes at 1000; "
			"_copy_from_iter 1500 bytes at 2500; "
			"_copy_from_iter 1500 bytes at 4000; "
			"_copy_from_iter 500 bytes at 5500", unit_log_get());
	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 2, message_length 10000, offset 10000, data_length 1500, incoming 10000, extra segs 1500@11500 1500@13000 500@14500",
			homa_print_packet(skb, buffer, sizeof(buffer)));

	EXPECT_EQ(4*(sizeof(struct data_header) + crpc->hsk->ip_header_length
			+ HOMA_ETH_OVERHEAD) + 5000,
			homa_get_skb_info(skb)->wire_bytes);
	EXPECT_EQ(5000, homa_get_skb_info(skb)->data_bytes);
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_new_data_packet__error_in_homa_fill_data_interleaved)
{
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 10000);

	unit_log_clear();
	mock_alloc_page_errors = -1;
	struct sk_buff *skb = homa_new_data_packet(crpc, iter, 10000, 5000,
			1500);
	EXPECT_TRUE(IS_ERR(skb));
	EXPECT_EQ(ENOMEM, -PTR_ERR(skb));
}
TEST_F(homa_outgoing, homa_new_data_packet__multiple_segments_tcp_hijacking)
{
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	struct homa_rpc *crpc;
	struct homa_sock hsk;
	struct sk_buff *skb;
	char buffer[1000];

	self->homa.hijack_tcp = 1;
	mock_sock_init(&hsk, &self->homa, self->client_port+1);
	crpc = homa_rpc_new_client(&hsk, &self->server_addr);
	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 10000);

	unit_log_clear();
	skb = homa_new_data_packet(crpc, iter, 10000, 5000, 1500);
	EXPECT_STREQ("_copy_from_iter 5000 bytes at 1000", unit_log_get());

	EXPECT_STREQ("DATA from 0.0.0.0:40001, dport 99, id 2, message_length 10000, offset 10000, data_length 1500, incoming 10000, extra segs 1500@11500 1500@13000 500@14500",
			homa_print_packet(skb, buffer, sizeof(buffer)));
	kfree_skb(skb);
	homa_sock_destroy(&hsk);
}
TEST_F(homa_outgoing, homa_new_data_packet__error_copying_data_hijacking_path)
{
	struct iov_iter *iter = unit_iov_iter((void *) 1000, 5000);
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);
	struct sk_buff *skb;

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 500);

	unit_log_clear();
	mock_copy_data_errors = 1;
	skb = homa_new_data_packet(crpc, iter, 5000, 500, 2000);
	EXPECT_TRUE(IS_ERR(skb));
	EXPECT_EQ(EFAULT, -PTR_ERR(skb));
}
TEST_F(homa_outgoing, homa_new_data_packet__gso_information)
{
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);
	struct sk_buff *skb;

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 10000);

	unit_log_clear();
	skb = homa_new_data_packet(crpc, iter, 10000, 5000, 1500);

	EXPECT_EQ(4, skb_shinfo(skb)->gso_segs);
	EXPECT_EQ(1500 + sizeof(struct seg_header),
		  skb_shinfo(skb)->gso_size);
	EXPECT_EQ(SKB_GSO_TCPV6, skb_shinfo(skb)->gso_type);
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_new_data_packet__gso_force_software)
{
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);
	struct sk_buff *skb;

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 10000);
	self->homa.gso_force_software = 1;

	unit_log_clear();
	skb = homa_new_data_packet(crpc, iter, 10000, 5000, 1500);
	EXPECT_EQ(13, skb_shinfo(skb)->gso_type);
	kfree_skb(skb);
}

TEST_F(homa_outgoing, homa_message_out_fill__basics)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);

	ASSERT_FALSE(crpc == NULL);
	ASSERT_EQ(0, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, 3000), 0));
	homa_rpc_unlock(crpc);
	EXPECT_EQ(3000, crpc->msgout.granted);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_STREQ("mtu 1496, max_seg_data 1400, max_gso_data 1400; "
			"_copy_from_iter 1400 bytes at 1000; "
			"_copy_from_iter 1400 bytes at 2400; "
			"_copy_from_iter 200 bytes at 3800", unit_log_get());
	unit_log_clear();
	unit_log_message_out_packets(&crpc->msgout, 1);
	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 2, message_length 3000, offset 0, data_length 1400, incoming 3000; "
		     "DATA from 0.0.0.0:40000, dport 99, id 2, message_length 3000, offset 1400, data_length 1400, incoming 3000; "
		     "DATA from 0.0.0.0:40000, dport 99, id 2, message_length 3000, offset 2800, data_length 200, incoming 3000",
		     unit_log_get());
	EXPECT_EQ(3, crpc->msgout.num_skbs);
	EXPECT_EQ(3000, crpc->msgout.copied_from_user);
}
TEST_F(homa_outgoing, homa_message_out_fill__message_too_long)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);

	ASSERT_FALSE(crpc == NULL);
	EXPECT_EQ(EINVAL, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, HOMA_MAX_MESSAGE_LENGTH+1),
			0));
	homa_rpc_unlock(crpc);
}
TEST_F(homa_outgoing, homa_message_out_fill__zero_length_message)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);

	ASSERT_FALSE(crpc == NULL);
	EXPECT_EQ(EINVAL, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, 0), 0));
	homa_rpc_unlock(crpc);
}
TEST_F(homa_outgoing, homa_message_out_fill__gso_force_software)
{
	struct homa_rpc *crpc1 = homa_rpc_new_client(&self->hsk,
			&self->server_addr);
	struct homa_rpc *crpc2;

	ASSERT_FALSE(crpc1 == NULL);
	homa_rpc_unlock(crpc1);
	mock_net_device.gso_max_size = 10000;
	mock_xmit_log_verbose = 1;
	self->homa.gso_force_software = 0;
	ASSERT_EQ(0, -homa_message_out_fill(crpc1,
			unit_iov_iter((void *) 1000, 5000), 0));
	unit_log_clear();
	homa_xmit_data(crpc1, false);
	EXPECT_SUBSTR("xmit DATA", unit_log_get());
	EXPECT_NOSUBSTR("TSO disabled", unit_log_get());

	crpc2 = homa_rpc_new_client(&self->hsk, &self->server_addr);
	ASSERT_FALSE(crpc2 == NULL);
	homa_rpc_unlock(crpc2);
	self->homa.gso_force_software = 1;
	ASSERT_EQ(0, -homa_message_out_fill(crpc2,
			unit_iov_iter((void *) 1000, 5000), 0));
	unit_log_clear();
	homa_xmit_data(crpc2, false);
	EXPECT_SUBSTR("TSO disabled", unit_log_get());
}
TEST_F(homa_outgoing, homa_message_out_fill__gso_limit_less_than_mtu)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);

	ASSERT_FALSE(crpc == NULL);
	unit_log_clear();
	mock_net_device.gso_max_size = 10000;
	self->homa.max_gso_size = 1000;
	ASSERT_EQ(0, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, 5000), 0));
	homa_rpc_unlock(crpc);
	EXPECT_SUBSTR("max_seg_data 1400, max_gso_data 1400;", unit_log_get());
}
TEST_F(homa_outgoing, homa_message_out_fill__include_acks)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);
	struct data_header h;

	ASSERT_FALSE(crpc == NULL);
	crpc->peer->acks[0] = (struct homa_ack) {
		.client_port = htons(100),
		.server_port = htons(200),
		.client_id = cpu_to_be64(1000)};
	crpc->peer->num_acks = 1;
	ASSERT_EQ(0, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, 500), 0));
	homa_rpc_unlock(crpc);
	homa_skb_get(crpc->msgout.packets, &h, 0, sizeof(h));
	EXPECT_STREQ("client_port 100, server_port 200, client_id 1000",
			unit_ack_string(&h.ack));
}
TEST_F(homa_outgoing, homa_message_out_fill__multiple_segs_per_skbuff)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);

	ASSERT_FALSE(crpc == NULL);
	mock_net_device.gso_max_size = 5000;
	unit_log_clear();
	ASSERT_EQ(0, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, 10000), 0));
	homa_rpc_unlock(crpc);
	EXPECT_SUBSTR("_copy_from_iter 1400 bytes at 1000; "
			"_copy_from_iter 1400 bytes at 2400; "
			"_copy_from_iter 1400 bytes at 3800; "
			"_copy_from_iter 1400 bytes at 5200; "
			"_copy_from_iter 1400 bytes at 6600; "
			"_copy_from_iter 1400 bytes at 8000; "
			"_copy_from_iter 1400 bytes at 9400; "
			"_copy_from_iter 200 bytes at 10800",
			unit_log_get());
	unit_log_clear();
	unit_log_filled_skbs(crpc->msgout.packets, 0);
	EXPECT_STREQ("DATA 1400@0 1400@1400 1400@2800; "
			"DATA 1400@4200 1400@5600 1400@7000; "
			"DATA 1400@8400 200@9800",
			unit_log_get());
	EXPECT_EQ(4200, homa_get_skb_info(crpc->msgout.packets)->data_bytes);
}
TEST_F(homa_outgoing, homa_message_out_fill__rpc_freed_during_copy)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);

	ASSERT_FALSE(crpc == NULL);
	unit_hook_register(unlock_hook);
	hook_rpc = crpc;
	ASSERT_EQ(EINVAL, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, 3000), 0));
	EXPECT_EQ(0, crpc->msgout.num_skbs);
	EXPECT_EQ(RPC_DEAD, crpc->state);
	homa_rpc_unlock(crpc);
}
TEST_F(homa_outgoing, homa_message_out_fill__add_to_throttled)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);

	ASSERT_FALSE(crpc == NULL);
	ASSERT_EQ(0, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, 5000), 1));
	homa_rpc_unlock(crpc);
	unit_log_clear();
	unit_log_filled_skbs(crpc->msgout.packets, 0);
	EXPECT_STREQ("DATA 1400@0; DATA 1400@1400; DATA 1400@2800; "
			"DATA 800@4200",
			unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 2, next_offset 0",
			unit_log_get());
}
TEST_F(homa_outgoing, homa_message_out_fill__too_short_for_pipelining)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr);

	ASSERT_FALSE(crpc == NULL);
	ASSERT_EQ(0, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, 1000), 1));
	homa_rpc_unlock(crpc);
	EXPECT_SUBSTR("xmit DATA 1000@0", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}

TEST_F(homa_outgoing, homa_xmit_control__server_request)
{
	struct homa_rpc *srpc;
	struct grant_header h;

	homa_sock_bind(self->homa.port_map, &self->hsk, self->server_port);
	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->client_port, self->server_id,
			10000, 10000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	h.offset = htonl(12345);
	h.priority = 4;
	h.resend_all = 0;
	h.common.sender_id = cpu_to_be64(self->client_id);
	mock_xmit_log_verbose = 1;
	EXPECT_EQ(0, homa_xmit_control(GRANT, &h, sizeof(h), srpc));
	EXPECT_STREQ("xmit GRANT from 0.0.0.0:99, dport 40000, id 1235, offset 12345, grant_prio 4",
			unit_log_get());
	EXPECT_STREQ("7", mock_xmit_prios);
}
TEST_F(homa_outgoing, homa_xmit_control__client_response)
{
	struct homa_rpc *crpc;
	struct grant_header h;

	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			100, 10000);
	ASSERT_NE(NULL, crpc);
	unit_log_clear();

	h.offset = htonl(12345);
	h.priority = 4;
	h.resend_all = 0;
	mock_xmit_log_verbose = 1;
	EXPECT_EQ(0, homa_xmit_control(GRANT, &h, sizeof(h), crpc));
	EXPECT_STREQ("xmit GRANT from 0.0.0.0:40000, dport 99, id 1234, offset 12345, grant_prio 4",
			unit_log_get());
	EXPECT_STREQ("7", mock_xmit_prios);
}

TEST_F(homa_outgoing, __homa_xmit_control__cant_alloc_skb)
{
	struct homa_rpc *srpc;
	struct grant_header h;

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	h.common.type = GRANT;
	h.offset = htonl(12345);
	h.priority = 4;
	h.resend_all = 0;
	mock_xmit_log_verbose = 1;
	mock_alloc_skb_errors = 1;
	EXPECT_EQ(ENOBUFS, -__homa_xmit_control(&h, sizeof(h), srpc->peer,
			&self->hsk));
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_outgoing, __homa_xmit_control__pad_packet)
{
	struct homa_rpc *srpc;
	struct busy_header h;

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();
	EXPECT_EQ(0, homa_xmit_control(BUSY, &h, 10, srpc));
	EXPECT_STREQ("padded control packet with 16 bytes; "
			"xmit unknown packet type 0x0",
			unit_log_get());
}
TEST_F(homa_outgoing, __homa_xmit_control__ipv4_error)
{
	struct homa_rpc *srpc;
	struct grant_header h;

	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, self->client_port);

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	h.offset = htonl(12345);
	h.priority = 4;
	h.resend_all = 0;
	mock_xmit_log_verbose = 1;
	mock_ip_queue_xmit_errors = 1;
	EXPECT_EQ(ENETDOWN, -homa_xmit_control(GRANT, &h, sizeof(h), srpc));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(1, homa_metrics_per_cpu()->control_xmit_errors);
}
TEST_F(homa_outgoing, __homa_xmit_control__ipv6_error)
{
	struct homa_rpc *srpc;
	struct grant_header h;

	// Make sure the test uses IPv6.
	mock_ipv6 = true;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, self->client_port);

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	h.offset = htonl(12345);
	h.priority = 4;
	h.resend_all = 0;
	mock_xmit_log_verbose = 1;
	mock_ip6_xmit_errors = 1;
	EXPECT_EQ(ENETDOWN, -homa_xmit_control(GRANT, &h, sizeof(h), srpc));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(1, homa_metrics_per_cpu()->control_xmit_errors);
}

TEST_F(homa_outgoing, homa_xmit_unknown)
{
	struct grant_header h = {{.sport = htons(self->client_port),
			.dport = htons(self->server_port),
			.sender_id = cpu_to_be64(99990),
			.type = GRANT},
			.offset = htonl(11200),
			.priority = 3,
			.resend_all = 0};
	struct sk_buff *skb;

	mock_xmit_log_verbose = 1;
	skb = mock_skb_new(self->client_ip, &h.common, 0, 0);
	homa_xmit_unknown(skb, &self->hsk);
	EXPECT_STREQ("xmit UNKNOWN from 0.0.0.0:99, dport 40000, id 99991",
			unit_log_get());
	kfree_skb(skb);
}

TEST_F(homa_outgoing, homa_xmit_data__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 6000, 1000);

	crpc->msgout.sched_priority = 2;
	crpc->msgout.unscheduled = 2000;
	crpc->msgout.granted = 5000;
	homa_peer_set_cutoffs(crpc->peer, INT_MAX, 0, 0, 0, 0, INT_MAX,
			7000, 0);
	unit_log_clear();
	mock_clear_xmit_prios();
	homa_xmit_data(crpc, false);
	EXPECT_STREQ("xmit DATA 1400@0; "
			"xmit DATA 1400@1400; "
			"xmit DATA 1400@2800; "
			"xmit DATA 1400@4200", unit_log_get());
	EXPECT_STREQ("6 6 2 2", mock_xmit_prios);
	EXPECT_EQ(5600, crpc->msgout.next_xmit_offset);
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_outgoing, homa_xmit_data__stop_because_no_more_granted)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 6000, 1000);

	unit_log_clear();
	crpc->msgout.granted = 1000;
	homa_xmit_data(crpc, false);
	EXPECT_STREQ("xmit DATA 1400@0", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_outgoing, homa_xmit_data__below_throttle_min)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 200, 1000);

	unit_log_clear();
	atomic64_set(&self->homa.link_idle_time, 11000);
	self->homa.max_nic_queue_ns = 500;
	self->homa.throttle_min_bytes = 250;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	homa_xmit_data(crpc, false);
	EXPECT_STREQ("xmit DATA 200@0", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_outgoing, homa_xmit_data__force)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 6000, 1000);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2, 5000, 1000);

	/* First, get an RPC on the throttled list. */
	atomic64_set(&self->homa.link_idle_time, 11000);
	self->homa.max_nic_queue_ns = 3000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	homa_xmit_data(crpc1, false);
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 1234, next_offset 2800", unit_log_get());

	/* Now force transmission. */
	unit_log_clear();
	homa_xmit_data(crpc2, true);
	EXPECT_STREQ("xmit DATA 1400@0; wake_up_process pid -1",
			unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 1234, next_offset 2800; "
			"request id 1236, next_offset 1400", unit_log_get());
}
TEST_F(homa_outgoing, homa_xmit_data__throttle)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 6000, 1000);

	unit_log_clear();
	atomic64_set(&self->homa.link_idle_time, 11000);
	self->homa.max_nic_queue_ns = 3000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;

	homa_xmit_data(crpc, false);
	EXPECT_STREQ("xmit DATA 1400@0; "
			"xmit DATA 1400@1400; "
			"wake_up_process pid -1", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 1234, next_offset 2800", unit_log_get());
}
TEST_F(homa_outgoing, homa_xmit_data__rpc_freed)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 6000, 1000);

	crpc->msgout.unscheduled = 2000;
	crpc->msgout.granted = 5000;

	unit_log_clear();
	unit_hook_register(lock_free_hook);
	hook_rpc = crpc;
	homa_xmit_data(crpc, false);
	EXPECT_STREQ("xmit DATA 1400@0; homa_rpc_free invoked",
			unit_log_get());
	EXPECT_EQ(1400, crpc->msgout.next_xmit_offset);
}

TEST_F(homa_outgoing, __homa_xmit_data__update_cutoff_version)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 1000);

	crpc->peer->cutoff_version = htons(123);
	mock_xmit_log_verbose = 1;
	unit_log_clear();
	skb_get(crpc->msgout.packets);
	__homa_xmit_data(crpc->msgout.packets, crpc, 4);
	EXPECT_SUBSTR("cutoff_version 123", unit_log_get());
}
TEST_F(homa_outgoing, __homa_xmit_data__fill_dst)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 1000);
	struct dst_entry *dst;
	int old_refcount;

	unit_log_clear();
	dst = crpc->peer->dst;
	old_refcount = atomic_read(&dst->__rcuref.refcnt);

	skb_get(crpc->msgout.packets);
	__homa_xmit_data(crpc->msgout.packets, crpc, 6);
	EXPECT_STREQ("xmit DATA 1000@0", unit_log_get());
	EXPECT_EQ(dst, skb_dst(crpc->msgout.packets));
	EXPECT_EQ(old_refcount+1, atomic_read(&dst->__rcuref.refcnt));
}
TEST_F(homa_outgoing, __homa_xmit_data__ipv4_transmit_error)
{
	struct homa_rpc *crpc;

	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, self->client_port);

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			1000, 1000);
	unit_log_clear();
	mock_ip_queue_xmit_errors = 1;
	skb_get(crpc->msgout.packets);
	__homa_xmit_data(crpc->msgout.packets, crpc, 5);
	EXPECT_EQ(1, homa_metrics_per_cpu()->data_xmit_errors);
}
TEST_F(homa_outgoing, __homa_xmit_data__ipv6_transmit_error)
{
	struct homa_rpc *crpc;

	// Make sure the test uses IPv6.
	mock_ipv6 = true;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, self->client_port);

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			100, 1000);
	unit_log_clear();
	mock_ip6_xmit_errors = 1;
	skb_get(crpc->msgout.packets);
	__homa_xmit_data(crpc->msgout.packets, crpc, 5);
	EXPECT_EQ(1, homa_metrics_per_cpu()->data_xmit_errors);
}

TEST_F(homa_outgoing, homa_resend_data__basics)
{
	struct homa_rpc *crpc;

	mock_net_device.gso_max_size = 5000;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			16000, 1000);
	unit_log_clear();
	mock_clear_xmit_prios();
	mock_xmit_log_verbose = 1;

	/* Helps to detect errors in computing seg_offset. */
	skb_push(crpc->msgout.packets, 8);

	homa_resend_data(crpc, 7000, 10000, 2);
	EXPECT_STREQ("xmit DATA from 0.0.0.0:40000, dport 99, id 1234, message_length 16000, offset 7000, data_length 1400, incoming 10000, RETRANSMIT; "
			"xmit DATA from 0.0.0.0:40000, dport 99, id 1234, message_length 16000, offset 8400, data_length 1400, incoming 10000, RETRANSMIT; "
			"xmit DATA from 0.0.0.0:40000, dport 99, id 1234, message_length 16000, offset 9800, data_length 200, incoming 10000, RETRANSMIT",
			unit_log_get());
	EXPECT_STREQ("2 2 2", mock_xmit_prios);

	unit_log_clear();
	mock_clear_xmit_prios();
	mock_xmit_log_verbose = 0;
	homa_resend_data(crpc, 1500, 1500, 3);
	EXPECT_STREQ("", unit_log_get());

	unit_log_clear();
	mock_clear_xmit_prios();
	mock_xmit_log_verbose = 0;
	homa_resend_data(crpc, 2800, 4200, 3);
	EXPECT_STREQ("xmit DATA retrans 1400@2800", unit_log_get());
	EXPECT_STREQ("3", mock_xmit_prios);

	unit_log_clear();
	mock_clear_xmit_prios();
	mock_xmit_log_verbose = 0;
	homa_resend_data(crpc, 4199, 4201, 7);
	EXPECT_STREQ("xmit DATA retrans 1400@2800; "
			"xmit DATA retrans 1400@4200", unit_log_get());
	EXPECT_STREQ("7 7", mock_xmit_prios);

	unit_log_clear();
	mock_xmit_log_verbose = 0;
	homa_resend_data(crpc, 16000, 17000, 7);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_outgoing, homa_resend_data__packet_doesnt_use_gso)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 2000);

	unit_log_clear();
	homa_resend_data(crpc, 500, 1500, 2);
	EXPECT_STREQ("xmit DATA retrans 1000@0", unit_log_get());
}
TEST_F(homa_outgoing, homa_resend_data__cant_allocate_skb)
{
	struct homa_rpc *crpc;

	mock_net_device.gso_max_size = 5000;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			16000, 1000);

	unit_log_clear();
	mock_clear_xmit_prios();
	mock_alloc_skb_errors = 1;
	homa_resend_data(crpc, 7000, 10000, 2);
	EXPECT_STREQ("skb allocation error", unit_log_get());
}
TEST_F(homa_outgoing, homa_resend_data__set_incoming)
{
	struct homa_rpc *crpc;

	mock_net_device.gso_max_size = 5000;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			16000, 1000);
	unit_log_clear();
	mock_xmit_log_verbose = 1;
	EXPECT_EQ(10000, crpc->msgout.granted);
	homa_resend_data(crpc, 8400, 8800, 2);
	EXPECT_SUBSTR("incoming 10000", unit_log_get());

	unit_log_clear();
	homa_resend_data(crpc, 12900, 13000, 2);
	EXPECT_SUBSTR("incoming 14200", unit_log_get());

	unit_log_clear();
	homa_resend_data(crpc, 15700, 16500, 2);
	EXPECT_SUBSTR("incoming 16000", unit_log_get());
}
TEST_F(homa_outgoing, homa_resend_data__error_copying_data)
{
	struct homa_rpc *crpc;

	mock_net_device.gso_max_size = 5000;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			16000, 1000);
	unit_log_clear();
	mock_clear_xmit_prios();
	mock_max_skb_frags = 0;
	homa_resend_data(crpc, 7000, 10000, 2);
	EXPECT_STREQ("homa_resend_data got error 22 while copying data",
			unit_log_get());
}
TEST_F(homa_outgoing, homa_resend_data__set_homa_info)
{
	struct homa_rpc *crpc;

	mock_net_device.gso_max_size = 5000;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			16000, 1000);
	unit_log_clear();
	mock_xmit_log_homa_info = 1;
	homa_resend_data(crpc, 8400, 8800, 2);
	EXPECT_STREQ("xmit DATA retrans 1400@8400; "
		     "homa_info: wire_bytes 1538, data_bytes 1400, seg_length 1400, offset 8400",
		     unit_log_get());
}

TEST_F(homa_outgoing, homa_outgoing_sysctl_changed)
{
	self->homa.link_mbps = 10000;
	homa_outgoing_sysctl_changed(&self->homa);
	EXPECT_EQ(808000, self->homa.ns_per_mbyte);

	self->homa.link_mbps = 1000;
	homa_outgoing_sysctl_changed(&self->homa);
	EXPECT_EQ(8080000, self->homa.ns_per_mbyte);

	self->homa.link_mbps = 40000;
	homa_outgoing_sysctl_changed(&self->homa);
	EXPECT_EQ(202000, self->homa.ns_per_mbyte);
}

TEST_F(homa_outgoing, homa_check_nic_queue__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 500, 1000);

	homa_get_skb_info(crpc->msgout.packets)->wire_bytes = 500;
	unit_log_clear();
	atomic64_set(&self->homa.link_idle_time, 9000);
	mock_ns = 8000;
	self->homa.max_nic_queue_ns = 1000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	EXPECT_EQ(1, homa_check_nic_queue(&self->homa, crpc->msgout.packets,
			false));
	EXPECT_EQ(9500, atomic64_read(&self->homa.link_idle_time));
}
TEST_F(homa_outgoing, homa_check_nic_queue__queue_full)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 500, 1000);

	homa_get_skb_info(crpc->msgout.packets)->wire_bytes = 500;
	unit_log_clear();
	atomic64_set(&self->homa.link_idle_time, 9000);
	mock_ns = 7999;
	self->homa.max_nic_queue_ns = 1000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	EXPECT_EQ(0, homa_check_nic_queue(&self->homa, crpc->msgout.packets,
			false));
	EXPECT_EQ(9000, atomic64_read(&self->homa.link_idle_time));
}
TEST_F(homa_outgoing, homa_check_nic_queue__queue_full_but_force)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 500, 1000);

	homa_get_skb_info(crpc->msgout.packets)->wire_bytes = 500;
	unit_log_clear();
	atomic64_set(&self->homa.link_idle_time, 9000);
	mock_ns = 7999;
	self->homa.max_nic_queue_ns = 1000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	EXPECT_EQ(1, homa_check_nic_queue(&self->homa, crpc->msgout.packets,
			true));
	EXPECT_EQ(9500, atomic64_read(&self->homa.link_idle_time));
}
TEST_F(homa_outgoing, homa_check_nic_queue__pacer_metrics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 500, 1000);

	homa_get_skb_info(crpc->msgout.packets)->wire_bytes = 500;
	homa_add_to_throttled(crpc);
	unit_log_clear();
	atomic64_set(&self->homa.link_idle_time, 9000);
	self->homa.pacer_wake_time = 9800;
	mock_ns = 10000;
	self->homa.max_nic_queue_ns = 1000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	EXPECT_EQ(1, homa_check_nic_queue(&self->homa, crpc->msgout.packets,
			true));
	EXPECT_EQ(10500, atomic64_read(&self->homa.link_idle_time));
	EXPECT_EQ(500, homa_metrics_per_cpu()->pacer_bytes);
	EXPECT_EQ(200, homa_metrics_per_cpu()->pacer_lost_ns);
}
TEST_F(homa_outgoing, homa_check_nic_queue__queue_empty)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 500, 1000);

	homa_get_skb_info(crpc->msgout.packets)->wire_bytes = 500;
	unit_log_clear();
	atomic64_set(&self->homa.link_idle_time, 9000);
	mock_ns = 10000;
	self->homa.max_nic_queue_ns = 1000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	EXPECT_EQ(1, homa_check_nic_queue(&self->homa, crpc->msgout.packets,
			true));
	EXPECT_EQ(10500, atomic64_read(&self->homa.link_idle_time));
}

/* Don't know how to unit test homa_pacer_main... */

TEST_F(homa_outgoing, homa_pacer_xmit__basics)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id,
			5000, 1000);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2,
			10000, 1000);
	struct homa_rpc *crpc3 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id+4,
			150000, 1000);

	homa_add_to_throttled(crpc1);
	homa_add_to_throttled(crpc2);
	homa_add_to_throttled(crpc3);
	self->homa.max_nic_queue_ns = 2000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	unit_log_clear();
	homa_pacer_xmit(&self->homa);
	EXPECT_STREQ("xmit DATA 1400@0; xmit DATA 1400@1400",
		unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 1234, next_offset 2800; "
		"request id 1236, next_offset 0; "
		"request id 1238, next_offset 0", unit_log_get());
}
TEST_F(homa_outgoing, homa_pacer_xmit__xmit_fifo)
{
	struct homa_rpc *crpc1, *crpc2, *crpc3;

	mock_ns = 10000;
	crpc1 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, 2, 20000, 1000);
	mock_ns = 11000;
	crpc2 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, 4, 10000, 1000);
	mock_ns = 12000;
	crpc3 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, 6, 30000, 1000);
	homa_add_to_throttled(crpc1);
	homa_add_to_throttled(crpc2);
	homa_add_to_throttled(crpc3);

	/* First attempt: pacer_fifo_count doesn't reach zero. */
	self->homa.max_nic_queue_ns = 1300;
	self->homa.pacer_fifo_count = 200;
	self->homa.pacer_fifo_fraction = 150;
	mock_ns= 13000;
	atomic64_set(&self->homa.link_idle_time, 10000);
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	unit_log_clear();
	mock_xmit_log_verbose = 1;
	homa_pacer_xmit(&self->homa);
	EXPECT_SUBSTR("id 4, message_length 10000, offset 0, data_length 1400",
			unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 4, next_offset 1400; "
			"request id 2, next_offset 0; "
			"request id 6, next_offset 0", unit_log_get());
	EXPECT_EQ(50, self->homa.pacer_fifo_count);

	/* Second attempt: pacer_fifo_count reaches zero. */
	atomic64_set(&self->homa.link_idle_time, 10000);
	unit_log_clear();
	homa_pacer_xmit(&self->homa);
	EXPECT_SUBSTR("id 2, message_length 20000, offset 0, data_length 1400",
			unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 4, next_offset 1400; "
			"request id 2, next_offset 1400; "
			"request id 6, next_offset 0", unit_log_get());
	EXPECT_EQ(900, self->homa.pacer_fifo_count);
}
TEST_F(homa_outgoing, homa_pacer_xmit__pacer_busy)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id,
			10000, 1000);

	homa_add_to_throttled(crpc);
	self->homa.max_nic_queue_ns = 2000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	mock_trylock_errors = 1;
	unit_log_clear();
	homa_pacer_xmit(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 1234, next_offset 0", unit_log_get());
}
TEST_F(homa_outgoing, homa_pacer_xmit__queue_empty)
{
	self->homa.max_nic_queue_ns = 2000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	unit_log_clear();
	homa_pacer_xmit(&self->homa);
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_outgoing, homa_pacer_xmit__nic_queue_fills)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id,
			10000, 1000);

	homa_add_to_throttled(crpc);
	self->homa.max_nic_queue_ns = 2001;
	mock_ns = 10000;
	atomic64_set(&self->homa.link_idle_time, 12000);
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	unit_log_clear();
	homa_pacer_xmit(&self->homa);
	EXPECT_STREQ("xmit DATA 1400@0", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 1234, next_offset 1400", unit_log_get());
}
TEST_F(homa_outgoing, homa_pacer_xmit__rpc_locked)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id,
			5000, 1000);

	homa_add_to_throttled(crpc);
	self->homa.max_nic_queue_ns = 2000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	unit_log_clear();
	mock_trylock_errors = ~1;
	homa_pacer_xmit(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(1, homa_metrics_per_cpu()->pacer_skipped_rpcs);
	unit_log_clear();
	mock_trylock_errors = 0;
	homa_pacer_xmit(&self->homa);
	EXPECT_STREQ("xmit DATA 1400@0; xmit DATA 1400@1400",
		unit_log_get());
}
TEST_F(homa_outgoing, homa_pacer_xmit__remove_from_queue)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 2,
			1000, 1000);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 4,
			10000, 1000);

	homa_add_to_throttled(crpc1);
	homa_add_to_throttled(crpc2);
	self->homa.max_nic_queue_ns = 2000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	unit_log_clear();
	homa_pacer_xmit(&self->homa);
	EXPECT_STREQ("xmit DATA 1000@0; xmit DATA 1400@0",
			unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 4, next_offset 1400", unit_log_get());
	EXPECT_TRUE(list_empty(&crpc1->throttled_links));
}

/* Don't know how to unit test homa_pacer_stop... */

TEST_F(homa_outgoing, homa_add_to_throttled__basics)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 2, 10000, 1000);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 4, 5000, 1000);
	struct homa_rpc *crpc3 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 6, 15000, 1000);
	struct homa_rpc *crpc4 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 8, 12000, 1000);
	struct homa_rpc *crpc5 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 10, 10000, 1000);

	/* Basics: add one RPC. */
	homa_add_to_throttled(crpc1);
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 2, next_offset 0", unit_log_get());

	/* Check priority ordering. */
	homa_add_to_throttled(crpc2);
	homa_add_to_throttled(crpc3);
	homa_add_to_throttled(crpc4);
	homa_add_to_throttled(crpc5);
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 4, next_offset 0; "
		"request id 2, next_offset 0; "
		"request id 10, next_offset 0; "
		"request id 8, next_offset 0; "
		"request id 6, next_offset 0", unit_log_get());

	/* Don't reinsert if already present. */
	homa_add_to_throttled(crpc1);
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 4, next_offset 0; "
		"request id 2, next_offset 0; "
		"request id 10, next_offset 0; "
		"request id 8, next_offset 0; "
		"request id 6, next_offset 0", unit_log_get());
}
TEST_F(homa_outgoing, homa_add_to_throttled__inc_metrics)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 1000);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2, 10000, 1000);
	struct homa_rpc *crpc3 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id+4, 15000, 1000);

	homa_add_to_throttled(crpc1);
	EXPECT_EQ(1, homa_metrics_per_cpu()->throttle_list_adds);
	EXPECT_EQ(0, homa_metrics_per_cpu()->throttle_list_checks);

	homa_add_to_throttled(crpc2);
	EXPECT_EQ(2, homa_metrics_per_cpu()->throttle_list_adds);
	EXPECT_EQ(1, homa_metrics_per_cpu()->throttle_list_checks);

	homa_add_to_throttled(crpc3);
	EXPECT_EQ(3, homa_metrics_per_cpu()->throttle_list_adds);
	EXPECT_EQ(3, homa_metrics_per_cpu()->throttle_list_checks);
}

TEST_F(homa_outgoing, homa_remove_from_throttled)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 1000);

	homa_add_to_throttled(crpc);
	EXPECT_FALSE(list_empty(&self->homa.throttled_rpcs));

	// First attempt will remove.
	unit_log_clear();
	homa_remove_from_throttled(crpc);
	EXPECT_TRUE(list_empty(&self->homa.throttled_rpcs));
	EXPECT_STREQ("removing id 1234 from throttled list", unit_log_get());

	// Second attempt: nothing to do.
	unit_log_clear();
	homa_remove_from_throttled(crpc);
	EXPECT_TRUE(list_empty(&self->homa.throttled_rpcs));
	EXPECT_STREQ("", unit_log_get());
}
