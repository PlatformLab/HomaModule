// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

#include "homa_impl.h"
#include "homa_grant.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#ifndef __STRIP__ /* See strip.py */
#include "homa_pacer.h"
#include "homa_qdisc.h"
#include "homa_skb.h"
#else /* See strip.py */
#include "homa_stub.h"
#endif /* See strip.py */

#ifndef __STRIP__ /* See strip.py */
#define XMIT_DATA(rpc, force) homa_xmit_data(rpc, force)
#else /* See strip.py */
#define XMIT_DATA(rpc, force) homa_xmit_data(rpc)
#endif /* See strip.py */

/* The following hook function frees hook_rpc. */
static struct homa_rpc *hook_rpc;
static void unlock_hook(char *id)
{
	if (strcmp(id, "unlock") != 0)
		return;
	if (hook_rpc) {
		homa_rpc_end(hook_rpc);
		hook_rpc = NULL;
	}
}

/* The following hook function frees an RPC when it is locked. */
static void lock_free_hook(char *id)
{
	if (strcmp(id, "spin_lock") != 0)
		return;
	if (hook_rpc) {
		homa_rpc_end(hook_rpc);
		hook_rpc = NULL;
	}
}

#ifdef __STRIP__ /* See strip.py */
static void mock_resend_data(struct homa_rpc *rpc, int start, int end,
		      int priority)
{
	homa_resend_data(rpc, start, end);
}
#define homa_resend_data(rpc, start, end, priority) \
		mock_resend_data(rpc, start, end, priority);
#endif /* See strip.py */

/* Compute the expected "truesize" value for a Homa packet, given
 * the number of bytes of message data in the packet.
 */
static int true_size(int msg_bytes)
{
	return SKB_TRUESIZE(msg_bytes + HOMA_SKB_EXTRA +
		sizeof(struct homa_skb_info) + sizeof(struct homa_data_hdr));
}

FIXTURE(homa_outgoing) {
	struct in6_addr client_ip[1];
	int client_port;
	struct in6_addr server_ip[1];
	int server_port;
	u64 client_id;
	u64 server_id;
	struct homa homa;
	struct homa_net *hnet;
	struct net_device *dev;
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
	self->hnet = mock_hnet(0, &self->homa);
	self->dev = mock_dev(0, &self->homa);
	mock_clock = 10000;
#ifndef __STRIP__ /* See strip.py */
	self->homa.pacer->cycles_per_mbyte = 1000000;
	self->homa.flags |= HOMA_FLAG_DONT_THROTTLE;
	self->homa.unsched_bytes = 10000;
	self->homa.grant->window = 10000;
	self->homa.qshared->fifo_fraction = 0;
#endif /* See strip.py */
	mock_sock_init(&self->hsk, self->hnet, self->client_port);
	self->server_addr.in6.sin6_family = AF_INET;
	self->server_addr.in6.sin6_addr = self->server_ip[0];
	self->server_addr.in6.sin6_port = htons(self->server_port);
	self->peer = homa_peer_get(&self->hsk,
				    &self->server_addr.in6.sin6_addr);
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_outgoing)
{
	homa_peer_release(self->peer);
	homa_destroy(&self->homa);
	unit_teardown();
}

#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_outgoing, set_priority__priority_mapping)
{
	struct homa_grant_hdr h;
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	h.offset = htonl(12345);
	h.priority = 4;
	EXPECT_EQ(0, homa_xmit_control(GRANT, &h, sizeof(h), srpc));
	self->homa.priority_map[7] = 3;
	EXPECT_EQ(0, homa_xmit_control(GRANT, &h, sizeof(h), srpc));
	EXPECT_STREQ("7 3", mock_xmit_prios);
}
#endif /* See strip.py */

TEST_F(homa_outgoing, homa_fill_data_interleaved)
{
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	char buffer[1000];

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 10000);

	unit_log_clear();
	struct sk_buff *skb = homa_tx_data_pkt_alloc(crpc, iter, 10000, 5000,
			1500);
	EXPECT_STREQ("_copy_from_iter 1500 bytes at 1000; "
			"_copy_from_iter 1500 bytes at 2500; "
			"_copy_from_iter 1500 bytes at 4000; "
			"_copy_from_iter 500 bytes at 5500", unit_log_get());

#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 2, message_length 10000, offset 10000, data_length 1500, incoming 10000, extra segs 1500@11500 1500@13000 500@14500",
			homa_print_packet(skb, buffer, sizeof(buffer)));
#else /* See strip.py */
	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 2, message_length 10000, offset 10000, data_length 1500, extra segs 1500@11500 1500@13000 500@14500",
			homa_print_packet(skb, buffer, sizeof(buffer)));
#endif /* See strip.py */
	EXPECT_EQ(5000 + sizeof(struct homa_data_hdr)
			+ 3*sizeof(struct homa_seg_hdr), skb->len);
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_fill_data_interleaved__error_copying_data)
{
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	struct sk_buff *skb;

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 10000);

	unit_log_clear();
	mock_copy_data_errors = 1;
	skb = homa_tx_data_pkt_alloc(crpc, iter, 10000, 5000, 1500);
	EXPECT_EQ(EFAULT, -PTR_ERR(skb));
}

TEST_F(homa_outgoing, homa_tx_data_pkt_alloc__one_segment)
{
	struct iov_iter *iter = unit_iov_iter((void *) 1000, 5000);
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);
	struct sk_buff *skb;
	char buffer[1000];

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 500);

	unit_log_clear();
	skb = homa_tx_data_pkt_alloc(crpc, iter, 5000, 500, 2000);
	EXPECT_STREQ("_copy_from_iter 500 bytes at 1000", unit_log_get());

#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 2, message_length 500, offset 5000, data_length 500, incoming 500",
			homa_print_packet(skb, buffer, sizeof(buffer)));
#else /* See strip.py */
	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 2, message_length 500, offset 5000, data_length 500",
			homa_print_packet(skb, buffer, sizeof(buffer)));
#endif /* See strip.py */

	EXPECT_EQ(0, skb_shinfo(skb)->gso_segs);
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_tx_data_pkt_alloc__cant_allocate_skb)
{
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);
	struct sk_buff *skb;

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 500);

	unit_log_clear();
	mock_alloc_skb_errors = 1;
	skb = homa_tx_data_pkt_alloc(crpc, iter, 0, 500, 2000);
	EXPECT_TRUE(IS_ERR(skb));
	EXPECT_EQ(ENOMEM, -PTR_ERR(skb));
	EXPECT_STREQ("couldn't allocate sk_buff for outgoing message",
		     self->hsk.error_msg);
}
TEST_F(homa_outgoing, homa_tx_data_pkt_alloc__include_acks)
{
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);
	struct homa_data_hdr h;
	struct sk_buff *skb;

	ASSERT_NE(NULL, crpc);
	homa_rpc_unlock(crpc);

	crpc->peer->acks[0] = (struct homa_ack) {
		.server_port = htons(200),
		.client_id = cpu_to_be64(1000)};
	crpc->peer->num_acks = 1;

	homa_message_out_init(crpc, 500);
	skb = homa_tx_data_pkt_alloc(crpc, iter, 0, 500, 2000);
	ASSERT_NE(NULL, skb);

	homa_skb_get(skb, &h, 0, sizeof(h));
	EXPECT_STREQ("server_port 200, client_id 1000",
			unit_ack_string(&h.ack));
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_tx_data_pkt_alloc__multiple_segments_homa_fill_data_interleaved)
{
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);
	struct sk_buff *skb;
	char buffer[1000];

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 10000);

	unit_log_clear();
	skb = homa_tx_data_pkt_alloc(crpc, iter, 10000, 5000, 1500);
	EXPECT_STREQ("_copy_from_iter 1500 bytes at 1000; "
			"_copy_from_iter 1500 bytes at 2500; "
			"_copy_from_iter 1500 bytes at 4000; "
			"_copy_from_iter 500 bytes at 5500", unit_log_get());
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 2, message_length 10000, offset 10000, data_length 1500, incoming 10000, extra segs 1500@11500 1500@13000 500@14500",
			homa_print_packet(skb, buffer, sizeof(buffer)));
#else /* See strip.py */
	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 2, message_length 10000, offset 10000, data_length 1500, extra segs 1500@11500 1500@13000 500@14500",
			homa_print_packet(skb, buffer, sizeof(buffer)));
#endif /* See strip.py */

	EXPECT_EQ(4*(sizeof(struct homa_data_hdr) + crpc->hsk->ip_header_length
			+ HOMA_ETH_OVERHEAD) + 5000,
			homa_get_skb_info(skb)->wire_bytes);
	EXPECT_EQ(5000, homa_get_skb_info(skb)->data_bytes);
	kfree_skb(skb);
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_outgoing, homa_tx_data_pkt_alloc__error_in_homa_fill_data_interleaved)
{
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 10000);

	unit_log_clear();
	mock_alloc_page_errors = -1;
	struct sk_buff *skb = homa_tx_data_pkt_alloc(crpc, iter, 10000, 5000,
			1500);
	EXPECT_TRUE(IS_ERR(skb));
	EXPECT_EQ(ENOMEM, -PTR_ERR(skb));
}
TEST_F(homa_outgoing, homa_tx_data_pkt_alloc__multiple_segments_tcp_hijacking)
{
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	struct homa_rpc *crpc;
	struct homa_sock hsk;
	struct sk_buff *skb;
	char buffer[1000];

	self->homa.hijack_tcp = 1;
	mock_sock_init(&hsk, self->hnet, self->client_port+1);
	crpc = homa_rpc_alloc_client(&hsk, &self->server_addr);
	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 10000);

	unit_log_clear();
	skb = homa_tx_data_pkt_alloc(crpc, iter, 10000, 5000, 1500);
	EXPECT_STREQ("_copy_from_iter 5000 bytes at 1000", unit_log_get());

	EXPECT_STREQ("DATA from 0.0.0.0:40001, dport 99, id 2, message_length 10000, offset 10000, data_length 1500, incoming 10000, extra segs 1500@11500 1500@13000 500@14500",
			homa_print_packet(skb, buffer, sizeof(buffer)));
	kfree_skb(skb);
	unit_sock_destroy(&hsk);
}
TEST_F(homa_outgoing, homa_tx_data_pkt_alloc__error_copying_data_hijacking_path)
{
	struct iov_iter *iter = unit_iov_iter((void *) 1000, 5000);
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);
	struct sk_buff *skb;

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 500);

	unit_log_clear();
	mock_copy_data_errors = 1;
	skb = homa_tx_data_pkt_alloc(crpc, iter, 5000, 500, 2000);
	EXPECT_TRUE(IS_ERR(skb));
	EXPECT_EQ(EFAULT, -PTR_ERR(skb));
}
#endif /* See strip.py */
TEST_F(homa_outgoing, homa_tx_data_pkt_alloc__gso_information)
{
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);
	struct sk_buff *skb;

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 10000);

	unit_log_clear();
	skb = homa_tx_data_pkt_alloc(crpc, iter, 10000, 5000, 1500);

	EXPECT_EQ(4, skb_shinfo(skb)->gso_segs);
	EXPECT_EQ(1500 + sizeof(struct homa_seg_hdr),
		  skb_shinfo(skb)->gso_size);
	EXPECT_EQ(SKB_GSO_TCPV6, skb_shinfo(skb)->gso_type);
	kfree_skb(skb);
}
TEST_F(homa_outgoing, homa_tx_data_pkt_alloc__gso_force_software)
{
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);
	struct sk_buff *skb;

	homa_rpc_unlock(crpc);
	homa_message_out_init(crpc, 10000);
	self->homa.gso_force_software = 1;

	unit_log_clear();
	skb = homa_tx_data_pkt_alloc(crpc, iter, 10000, 5000, 1500);
	EXPECT_EQ(13, skb_shinfo(skb)->gso_type);
	kfree_skb(skb);
}

TEST_F(homa_outgoing, homa_message_out_fill__basics)
{
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);

        mock_set_ipv6(&self->hsk);

	ASSERT_FALSE(crpc == NULL);
	ASSERT_EQ(0, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, 3000), 0));
	homa_rpc_unlock(crpc);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(3000, crpc->msgout.granted);
#endif /* See strip.py */
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_SUBSTR("mtu 1496, max_seg_data 1400, max_gso_data 1400; "
			"_copy_from_iter 1400 bytes at 1000; "
			"_copy_from_iter 1400 bytes at 2400; "
			"_copy_from_iter 200 bytes at 3800", unit_log_get());
	unit_log_clear();
	unit_log_message_out_packets(&crpc->msgout, 1);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 2, message_length 3000, offset 0, data_length 1400, incoming 3000; "
		     "DATA from 0.0.0.0:40000, dport 99, id 2, message_length 3000, offset 1400, data_length 1400, incoming 3000; "
		     "DATA from 0.0.0.0:40000, dport 99, id 2, message_length 3000, offset 2800, data_length 200, incoming 3000",
		     unit_log_get());
#else /* See strip.py */
	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 2, message_length 3000, offset 0, data_length 1400; "
		     "DATA from 0.0.0.0:40000, dport 99, id 2, message_length 3000, offset 1400, data_length 1400; "
		     "DATA from 0.0.0.0:40000, dport 99, id 2, message_length 3000, offset 2800, data_length 200",
		     unit_log_get());
#endif /* See strip.py */
	EXPECT_EQ(3, crpc->msgout.num_skbs);
	EXPECT_EQ(3000, crpc->msgout.copied_from_user);
}
TEST_F(homa_outgoing, homa_message_out_fill__message_too_long)
{
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);

	ASSERT_FALSE(crpc == NULL);
	EXPECT_EQ(EINVAL, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, HOMA_MAX_MESSAGE_LENGTH+1),
			0));
	EXPECT_STREQ("message length exceeded HOMA_MAX_MESSAGE_LENGTH",
		     self->hsk.error_msg);
	homa_rpc_unlock(crpc);
	EXPECT_EQ(0, crpc->msgout.skb_memory);
	EXPECT_EQ(1, refcount_read(&self->hsk.sock.sk_wmem_alloc));
}
TEST_F(homa_outgoing, homa_message_out_fill__zero_length_message)
{
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);

	ASSERT_FALSE(crpc == NULL);
	EXPECT_EQ(EINVAL, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, 0), 0));
	homa_rpc_unlock(crpc);
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_outgoing, homa_message_out_fill__gso_geometry_hijacking)
{
	struct homa_rpc *crpc1, *crpc2;

	crpc1 = homa_rpc_alloc_client(&self->hsk, &self->server_addr);
	ASSERT_FALSE(crpc1 == NULL);
	homa_rpc_unlock(crpc1);

	crpc2 = homa_rpc_alloc_client(&self->hsk, &self->server_addr);
	ASSERT_FALSE(crpc2 == NULL);
	homa_rpc_unlock(crpc2);

        mock_set_ipv6(&self->hsk);
	self->hsk.sock.sk_protocol = IPPROTO_TCP;

	/* First try: not quite enough space for 3 packets in GSO. */
	self->dev->gso_max_size = mock_mtu - 1 +
			2 * UNIT_TEST_DATA_PER_PACKET;
	homa_rpc_lock(crpc1);
	ASSERT_EQ(0, -homa_message_out_fill(crpc1,
			unit_iov_iter((void *) 1000, 10000), 0));
	homa_rpc_unlock(crpc1);
	EXPECT_SUBSTR("max_seg_data 1400, max_gso_data 2800", unit_log_get());

	/* Second try: just barely enough space for 3 packets in GSO. */
	self->dev->gso_max_size += 1;
	unit_log_clear();
	homa_rpc_lock(crpc2);
	ASSERT_EQ(0, -homa_message_out_fill(crpc2,
			unit_iov_iter((void *) 1000, 10000), 0));
	homa_rpc_unlock(crpc2);
	EXPECT_SUBSTR("max_seg_data 1400, max_gso_data 4200", unit_log_get());
}
#endif /* See strip.py */
TEST_F(homa_outgoing, homa_message_out_fill__gso_geometry_no_hijacking)
{
	struct homa_rpc *crpc1, *crpc2;

	crpc1 = homa_rpc_alloc_client(&self->hsk, &self->server_addr);
	ASSERT_FALSE(crpc1 == NULL);
        mock_set_ipv6(&self->hsk);

	/* First try: not quite enough space for 3 packets in GSO. */
	self->dev->gso_max_size = mock_mtu - 1 +
			2 * (UNIT_TEST_DATA_PER_PACKET +
			     sizeof(struct homa_seg_hdr));
	ASSERT_EQ(0, -homa_message_out_fill(crpc1,
			unit_iov_iter((void *) 1000, 10000), 0));
	homa_rpc_unlock(crpc1);
	EXPECT_SUBSTR("max_seg_data 1400, max_gso_data 2800", unit_log_get());

	/* Second try: just barely enough space for 3 packets in GSO. */
	crpc2 = homa_rpc_alloc_client(&self->hsk, &self->server_addr);
	ASSERT_FALSE(crpc2 == NULL);
	self->dev->gso_max_size += 1;
	unit_log_clear();
	ASSERT_EQ(0, -homa_message_out_fill(crpc2,
			unit_iov_iter((void *) 1000, 10000), 0));
	homa_rpc_unlock(crpc2);
	EXPECT_SUBSTR("max_seg_data 1400, max_gso_data 4200", unit_log_get());
}
TEST_F(homa_outgoing, homa_message_out_fill__gso_limit_less_than_mtu)
{
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);

	ASSERT_FALSE(crpc == NULL);
	unit_log_clear();
	self->dev->gso_max_size = 10000;
	self->homa.max_gso_size = 1000;
	ASSERT_EQ(0, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, 5000), 0));
	homa_rpc_unlock(crpc);
	EXPECT_SUBSTR("max_seg_data 1400, max_gso_data 1400;", unit_log_get());
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_outgoing, homa_message_out_fill__disable_overlap_xmit_because_of_homa_qdisc)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *crpc;

	qdev = homa_qdisc_qdev_get(self->dev);
	crpc = homa_rpc_alloc_client(&self->hsk, &self->server_addr);

	ASSERT_FALSE(crpc == NULL);
	ASSERT_EQ(0, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, 5000), 1));
	homa_rpc_unlock(crpc);
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	homa_qdisc_qdev_put(qdev);
}
#endif /* See strip.py */
TEST_F(homa_outgoing, homa_message_out_fill__multiple_segs_per_skbuff)
{
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);

	ASSERT_FALSE(crpc == NULL);
	self->dev->gso_max_size = 5000;
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
TEST_F(homa_outgoing, homa_message_out_fill__error_in_homa_tx_data_packet_alloc)
{
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);

	ASSERT_FALSE(crpc == NULL);
        mock_set_ipv6(&self->hsk);
	mock_copy_data_errors = 2;

	EXPECT_EQ(EFAULT, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, 3000), 0));
	EXPECT_STREQ("couldn't copy message body into packet buffers",
		     self->hsk.error_msg);
	homa_rpc_unlock(crpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(1, crpc->msgout.num_skbs);
	EXPECT_EQ(true_size(1400), crpc->msgout.skb_memory);
	EXPECT_EQ(true_size(1400) + 1,
		  refcount_read(&self->hsk.sock.sk_wmem_alloc));
}
TEST_F(homa_outgoing, homa_message_out_fill__rpc_freed_during_copy)
{
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);

	ASSERT_FALSE(crpc == NULL);
	unit_hook_register(unlock_hook);
	hook_rpc = crpc;
	ASSERT_EQ(EINVAL, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, 3000), 0));
	EXPECT_STREQ("rpc deleted while creating outgoing message", self->hsk.error_msg);
	EXPECT_EQ(0, crpc->msgout.num_skbs);
	EXPECT_EQ(RPC_DEAD, crpc->state);
	EXPECT_EQ(0, crpc->msgout.skb_memory);
	EXPECT_EQ(1, refcount_read(&self->hsk.sock.sk_wmem_alloc));
	homa_rpc_unlock(crpc);
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_outgoing, homa_message_out_fill__xmit_packets)
{
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);

	ASSERT_FALSE(crpc == NULL);
	self->homa.unsched_bytes = 2800;
	ASSERT_EQ(0, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, 5000), 1));
	homa_rpc_unlock(crpc);
	EXPECT_SUBSTR(" _copy_from_iter 1400 bytes at 1000; "
		     "xmit DATA 1400@0; "
		     "_copy_from_iter 1400 bytes at 2400; "
		     "xmit DATA 1400@1400; "
		     "_copy_from_iter 1400 bytes at 3800; "
		     "_copy_from_iter 800 bytes at 5200", unit_log_get());
}
#endif /* See strip.py */
TEST_F(homa_outgoing, homa_message_out_fill__packet_memory_accounting)
{
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);

        mock_set_ipv6(&self->hsk);

	ASSERT_FALSE(crpc == NULL);
	ASSERT_EQ(0, -homa_message_out_fill(crpc,
			unit_iov_iter((void *) 1000, 3000), 0));
	homa_rpc_unlock(crpc);
	unit_log_clear();
	EXPECT_EQ(3, crpc->msgout.num_skbs);
	EXPECT_EQ(2 * true_size(1400) + true_size(200),
		  crpc->msgout.skb_memory);
	EXPECT_EQ(2 * true_size(1400) + true_size(200) + 1,
		  refcount_read(&self->hsk.sock.sk_wmem_alloc));
}

TEST_F(homa_outgoing, homa_xmit_control__server_request)
{
	struct homa_busy_hdr h;
	struct homa_rpc *srpc;

	homa_sock_bind(self->hnet, &self->hsk, self->server_port);
	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->client_port, self->server_id,
			10000, 10000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	mock_xmit_log_verbose = 1;
	EXPECT_EQ(0, homa_xmit_control(BUSY, &h, sizeof(h), srpc));
	EXPECT_STREQ("xmit BUSY from 0.0.0.0:99, dport 40000, id 1235",
			unit_log_get());
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("7", mock_xmit_prios);
#endif /* See strip.py */
}
TEST_F(homa_outgoing, homa_xmit_control__client_response)
{
	struct homa_busy_hdr h;
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			100, 10000);
	ASSERT_NE(NULL, crpc);
	unit_log_clear();

	mock_xmit_log_verbose = 1;
	EXPECT_EQ(0, homa_xmit_control(BUSY, &h, sizeof(h), crpc));
	EXPECT_STREQ("xmit BUSY from 0.0.0.0:40000, dport 99, id 1234",
			unit_log_get());
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("7", mock_xmit_prios);
#endif /* See strip.py */
}

TEST_F(homa_outgoing, __homa_xmit_control__cant_alloc_skb)
{
	struct homa_busy_hdr h;
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	h.common.type = BUSY;
	mock_xmit_log_verbose = 1;
	mock_alloc_skb_errors = 1;
	EXPECT_EQ(ENOBUFS, -__homa_xmit_control(&h, sizeof(h), srpc->peer,
			&self->hsk));
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_outgoing, __homa_xmit_control__pad_packet)
{
	struct homa_rpc *srpc;
	struct homa_busy_hdr h;

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();
	EXPECT_EQ(0, homa_xmit_control(BUSY, &h, 10, srpc));
	EXPECT_STREQ("padded control packet with 16 bytes; "
			"xmit unknown packet type 0x0",
			unit_log_get());
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_outgoing, __homa_xmit_control__ipv4_error)
{
	struct homa_grant_hdr h;
	struct homa_rpc *srpc;

	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	unit_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, self->hnet, self->client_port);

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	h.offset = htonl(12345);
	h.priority = 4;
	mock_xmit_log_verbose = 1;
	mock_ip_queue_xmit_errors = 1;
	EXPECT_EQ(ENETDOWN, -homa_xmit_control(GRANT, &h, sizeof(h), srpc));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(1, homa_metrics_per_cpu()->control_xmit_errors);
}
TEST_F(homa_outgoing, __homa_xmit_control__ipv6_error)
{
	struct homa_grant_hdr h;
	struct homa_rpc *srpc;

	// Make sure the test uses IPv6.
	mock_ipv6 = true;
	unit_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, self->hnet, self->client_port);

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	h.offset = htonl(12345);
	h.priority = 4;
	mock_xmit_log_verbose = 1;
	mock_ip6_xmit_errors = 1;
	EXPECT_EQ(ENETDOWN, -homa_xmit_control(GRANT, &h, sizeof(h), srpc));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(1, homa_metrics_per_cpu()->control_xmit_errors);
}

TEST_F(homa_outgoing, homa_xmit_unknown)
{
	struct homa_grant_hdr h = {{.sport = htons(self->client_port),
			.dport = htons(self->server_port),
			.sender_id = cpu_to_be64(99990),
			.type = GRANT},
			.offset = htonl(11200)};
	struct sk_buff *skb;

	mock_xmit_log_verbose = 1;
	skb = mock_skb_alloc(self->client_ip, &h.common, 0, 0);
	homa_xmit_unknown(skb, &self->hsk);
	EXPECT_STREQ("xmit RPC_UNKNOWN from 0.0.0.0:99, dport 40000, id 99991",
			unit_log_get());
	kfree_skb(skb);
}
#endif /* See strip.py */

TEST_F(homa_outgoing, homa_xmit_data__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 6000, 1000);

#ifndef __STRIP__ /* See strip.py */
	crpc->msgout.sched_priority = 2;
	crpc->msgout.unscheduled = 2000;
	crpc->msgout.granted = 5000;
	homa_peer_set_cutoffs(crpc->peer, INT_MAX, 0, 0, 0, 0, INT_MAX,
			7000, 0);
#else /* See strip.py */
	unit_reset_tx(crpc);
#endif /* See strip.py */

	unit_log_clear();
	mock_clear_xmit_prios();
	homa_rpc_lock(crpc);
	XMIT_DATA(crpc, false);
	homa_rpc_unlock(crpc);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("xmit DATA 1400@0; "
			"xmit DATA 1400@1400; "
			"xmit DATA 1400@2800; "
			"xmit DATA 1400@4200", unit_log_get());
	EXPECT_STREQ("6 6 2 2", mock_xmit_prios);
	EXPECT_EQ(5600, crpc->msgout.next_xmit_offset);
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("", unit_log_get());
#else /* See strip.py */
	EXPECT_STREQ("xmit DATA 1400@0; "
			"xmit DATA 1400@1400; "
			"xmit DATA 1400@2800; "
			"xmit DATA 1400@4200; "
			"xmit DATA 400@5600", unit_log_get());
	EXPECT_EQ(6000, crpc->msgout.next_xmit_offset);
#endif /* See strip.py */
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_outgoing, homa_xmit_data__stop_because_no_more_granted)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 6000, 1000);

	unit_log_clear();
	crpc->msgout.granted = 1000;
	homa_rpc_lock(crpc);
	XMIT_DATA(crpc, false);
	homa_rpc_unlock(crpc);
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
	atomic64_set(&self->homa.pacer->link_idle_time, 11000);
	self->homa.qshared->max_nic_est_backlog_cycles = 500;
	self->homa.qshared->defer_min_bytes = 250;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	homa_rpc_lock(crpc);
	XMIT_DATA(crpc, false);
	homa_rpc_unlock(crpc);
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
	atomic64_set(&self->homa.pacer->link_idle_time, 11000);
	self->homa.qshared->max_nic_est_backlog_cycles = 3000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;
	homa_rpc_lock(crpc1);
	XMIT_DATA(crpc1, false);
	homa_rpc_unlock(crpc1);
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 1234, next_offset 2800", unit_log_get());

	/* Now force transmission. */
	unit_log_clear();
	homa_rpc_lock(crpc2);
	XMIT_DATA(crpc2, true);
	homa_rpc_unlock(crpc2);
	EXPECT_STREQ("xmit DATA 1400@0", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 1234, next_offset 2800; "
			"request id 1236, next_offset 1400", unit_log_get());
}
TEST_F(homa_outgoing, homa_xmit_data__dont_throttle_because_homa_qdisc_in_use)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *crpc;

	qdev = homa_qdisc_qdev_get(self->dev);
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 2000, 1000);
	unit_log_clear();
	atomic64_set(&self->homa.pacer->link_idle_time, 1000000);
	self->homa.qshared->max_nic_est_backlog_cycles = 0;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;

	homa_rpc_lock(crpc);
	XMIT_DATA(crpc, false);
	homa_rpc_unlock(crpc);
	EXPECT_STREQ("xmit DATA 1400@0; xmit DATA 600@1400", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_outgoing, homa_xmit_data__throttle)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 6000, 1000);

	unit_log_clear();
	atomic64_set(&self->homa.pacer->link_idle_time, 11000);
	self->homa.qshared->max_nic_est_backlog_cycles = 3000;
	self->homa.flags &= ~HOMA_FLAG_DONT_THROTTLE;

	homa_rpc_lock(crpc);
	XMIT_DATA(crpc, false);
	homa_rpc_unlock(crpc);
	EXPECT_STREQ("xmit DATA 1400@0; "
			"xmit DATA 1400@1400", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 1234, next_offset 2800", unit_log_get());
}
TEST_F(homa_outgoing, homa_xmit_data__metrics_for_client_rpc)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 6000, 1000);

	crpc->msgout.granted = 4000;
	homa_rpc_lock(crpc);
	XMIT_DATA(crpc, false);
	EXPECT_EQ(4200, homa_metrics_per_cpu()->client_request_bytes_done);
	EXPECT_EQ(0, homa_metrics_per_cpu()->client_requests_done);

	crpc->msgout.granted = 6000;
	XMIT_DATA(crpc, false);
	EXPECT_EQ(6000, homa_metrics_per_cpu()->client_request_bytes_done);
	EXPECT_EQ(1, homa_metrics_per_cpu()->client_requests_done);
	homa_rpc_unlock(crpc);
}
TEST_F(homa_outgoing, homa_xmit_data__metrics_for_server_rpc)
{
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->client_port,
			       self->server_id, 1000, 10000);

	srpc->msgout.granted = 4000;
	homa_rpc_lock(srpc);
	XMIT_DATA(srpc, false);
	EXPECT_EQ(4200, homa_metrics_per_cpu()->server_response_bytes_done);
	EXPECT_EQ(0, homa_metrics_per_cpu()->server_responses_done);

	srpc->msgout.granted = 9900;
	XMIT_DATA(srpc, false);
	EXPECT_EQ(10000, homa_metrics_per_cpu()->server_response_bytes_done);
	EXPECT_EQ(1, homa_metrics_per_cpu()->server_responses_done);
	homa_rpc_unlock(srpc);
}
#endif /* See strip.py */
TEST_F(homa_outgoing, homa_xmit_data__rpc_freed)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 6000, 1000);

#ifndef __STRIP__ /* See strip.py */
	crpc->msgout.unscheduled = 2000;
	crpc->msgout.granted = 5000;
#else /* See strip.py */
	unit_reset_tx(crpc);
#endif /* See strip.py */

	unit_log_clear();
	homa_rpc_lock(crpc);
	unit_hook_register(lock_free_hook);
	hook_rpc = crpc;
	XMIT_DATA(crpc, false);
	homa_rpc_unlock(crpc);
	EXPECT_STREQ("xmit DATA 1400@0; homa_rpc_end invoked",
			unit_log_get());
	EXPECT_EQ(1400, crpc->msgout.next_xmit_offset);
}

#ifndef __STRIP__ /* See strip.py */
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
#endif /* See strip.py */
TEST_F(homa_outgoing, __homa_xmit_data__fill_dst)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 1000);
	struct dst_entry *dst;
	int old_refcount;

#ifdef __STRIP__ /* See strip.py */
	unit_reset_tx(crpc);
#endif /* See strip.py */
	unit_log_clear();
	dst = crpc->peer->dst;
	old_refcount = atomic_read(&dst->__rcuref.refcnt);

	skb_get(crpc->msgout.packets);
#ifndef __STRIP__ /* See strip.py */
	__homa_xmit_data(crpc->msgout.packets, crpc, 6);
#else /* See strip.py */
	__homa_xmit_data(crpc->msgout.packets, crpc);
#endif /* See strip.py */
	EXPECT_STREQ("xmit DATA 1000@0", unit_log_get());
	EXPECT_EQ(dst, skb_dst(crpc->msgout.packets));
	EXPECT_EQ(old_refcount+1, atomic_read(&dst->__rcuref.refcnt));
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_outgoing, __homa_xmit_data__ipv4_transmit_error)
{
	struct homa_rpc *crpc;

	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	unit_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, self->hnet, self->client_port);

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
	unit_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, self->hnet, self->client_port);

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			100, 1000);
	unit_log_clear();
	mock_ip6_xmit_errors = 1;
	skb_get(crpc->msgout.packets);
	__homa_xmit_data(crpc->msgout.packets, crpc, 5);
	EXPECT_EQ(1, homa_metrics_per_cpu()->data_xmit_errors);
}
#endif /* See strip.py */

TEST_F(homa_outgoing, homa_resend_data__basics)
{
	struct homa_rpc *crpc;

	self->dev->gso_max_size = 5000;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			16000, 1000);
	unit_log_clear();
	mock_clear_xmit_prios();
	mock_xmit_log_verbose = 1;

	/* Helps to detect errors in computing seg_offset. */
	skb_push(crpc->msgout.packets, 8);

	homa_resend_data(crpc, 7000, 10000, 2);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("xmit DATA from 0.0.0.0:40000, dport 99, id 1234, message_length 16000, offset 7000, data_length 1400, incoming 10000, RETRANSMIT; "
			"xmit DATA from 0.0.0.0:40000, dport 99, id 1234, message_length 16000, offset 8400, data_length 1400, incoming 10000, RETRANSMIT; "
			"xmit DATA from 0.0.0.0:40000, dport 99, id 1234, message_length 16000, offset 9800, data_length 200, incoming 10000, RETRANSMIT",
			unit_log_get());
#else /* See strip.py */
	EXPECT_STREQ("xmit DATA from 0.0.0.0:40000, dport 99, id 1234, message_length 16000, offset 7000, data_length 1400, RETRANSMIT; "
			"xmit DATA from 0.0.0.0:40000, dport 99, id 1234, message_length 16000, offset 8400, data_length 1400, RETRANSMIT; "
			"xmit DATA from 0.0.0.0:40000, dport 99, id 1234, message_length 16000, offset 9800, data_length 1400, RETRANSMIT",
			unit_log_get());
#endif /* See strip.py */
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("2 2 2", mock_xmit_prios);
#endif /* See strip.py */

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
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("3", mock_xmit_prios);
#endif /* See strip.py */

	unit_log_clear();
	mock_clear_xmit_prios();
	mock_xmit_log_verbose = 0;
	homa_resend_data(crpc, 4199, 4201, 7);
	EXPECT_STREQ("xmit DATA retrans 1400@2800; "
			"xmit DATA retrans 1400@4200", unit_log_get());
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("7 7", mock_xmit_prios);
#endif /* See strip.py */

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

	self->dev->gso_max_size = 5000;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			16000, 1000);

	unit_log_clear();
	mock_clear_xmit_prios();
	mock_alloc_skb_errors = 1;
	homa_resend_data(crpc, 7000, 10000, 2);
	EXPECT_STREQ("skb allocation error", unit_log_get());
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_outgoing, homa_resend_data__set_incoming)
{
	struct homa_rpc *crpc;

	self->dev->gso_max_size = 5000;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			16000, 1000);
	unit_log_clear();
	mock_xmit_log_verbose = 1;
	EXPECT_EQ(10000, crpc->msgout.granted);
	homa_resend_data(crpc, 8400, 8800, 2);
	EXPECT_SUBSTR("incoming 8800", unit_log_get());
}
TEST_F(homa_outgoing, homa_resend_data__error_copying_data)
{
	struct homa_rpc *crpc;

	self->dev->gso_max_size = 5000;
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
#endif /* See strip.py */
TEST_F(homa_outgoing, homa_resend_data__update_to_free_and_set_homa_info)
{
	struct homa_skb_info *homa_info;
	struct homa_rpc *crpc;
	struct sk_buff *skb;

	mock_set_ipv6(&self->hsk);
	self->dev->gso_max_size = 5000;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			16000, 1000);
	unit_log_clear();
	homa_resend_data(crpc, 8400, 8800, 2);
	skb = crpc->msgout.to_free;
	ASSERT_NE(NULL, skb);
	homa_info = homa_get_skb_info(skb);
	EXPECT_EQ(NULL, homa_info->next_skb);
	EXPECT_EQ(1538, homa_info->wire_bytes);
	EXPECT_EQ(1400, homa_info->data_bytes);
	EXPECT_EQ(1400, homa_info->seg_length);
	EXPECT_EQ(8400, homa_info->offset);
	EXPECT_EQ(crpc, homa_info->rpc);
	EXPECT_EQ(1, refcount_read(&skb->users));
	IF_NO_STRIP(EXPECT_EQ(6, crpc->msgout.num_skbs));
}

TEST_F(homa_outgoing, homa_rpc_tx_end)
{
	struct homa_rpc *crpc;
	struct sk_buff *skbs[5];
	struct sk_buff *skb;
	int i;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
		               self->server_ip, self->server_port,
			       self->client_id, 6000, 1000);
	ASSERT_EQ(5, crpc->msgout.num_skbs);

	/* First call: no packets passed to IP stack. */
	crpc->msgout.next_xmit_offset = 0;
	EXPECT_EQ(0, homa_rpc_tx_end(crpc));

	for (skb = crpc->msgout.packets, i = 0; skb != NULL;
	     skb = homa_get_skb_info(skb)->next_skb, i++) {
		skbs[i] = skb;
		skb_get(skb);
		EXPECT_EQ(2, refcount_read(&skbs[i]->users));
	}
	EXPECT_EQ(5, i);

	/* Second call: all packets passed to IP, but no packets complete. */
	crpc->msgout.next_xmit_offset = 6000;
	EXPECT_EQ(0, homa_rpc_tx_end(crpc));

	/* Third call: packets 0 and 3 transmitted. */
	kfree_skb(skbs[0]);
	kfree_skb(skbs[3]);
	EXPECT_EQ(1400, homa_rpc_tx_end(crpc));
	EXPECT_EQ(skbs[1], crpc->msgout.first_not_tx);

	/* Fourth call: all packets transmitted. */
	kfree_skb(skbs[1]);
	kfree_skb(skbs[2]);
	kfree_skb(skbs[4]);
	EXPECT_EQ(6000, homa_rpc_tx_end(crpc));
	EXPECT_EQ(NULL, crpc->msgout.first_not_tx);
}