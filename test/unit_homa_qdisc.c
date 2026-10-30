// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

#include "homa_impl.h"
#include "homa_qdisc.h"
#include "homa_rpc.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

static struct sk_buff *qdisc_packet(struct homa_rpc *rpc,
				     struct in6_addr *src, struct in6_addr *dst,
				     int offset, int payload, int stride)
{
	struct homa_data_hdr h = {
		.common = {
			.sport = htons(rpc ? rpc->hsk->port : 40000),
			.dport = htons(rpc ? rpc->dport : 99),
			.type = DATA,
			.sender_id = cpu_to_be64(rpc ? rpc->id : 1000)
		},
		.msg_length = htonl(rpc ? rpc->msgout.length : 10000)
	};
	int records = stride ? DIV_ROUND_UP(payload, stride) : 1;
	int len = sizeof(struct udphdr) + records * sizeof(h) + payload;
	struct udphdr udp = {
		.source = htons(HOMA_UDP_PORT), .dest = htons(HOMA_UDP_PORT),
		.len = htons(len), .check = htons(1)
	};
	struct sk_buff *skb = mock_raw_skb(src, dst, IPPROTO_UDP,
					 len + sizeof(struct homa_skb_info));
	int left = payload;

	memcpy(skb_put(skb, sizeof(udp)), &udp, sizeof(udp));
	do {
		int bytes = stride ? min(left, stride) : left;

		h.seg.offset = htonl(offset);
		memcpy(skb_put(skb, sizeof(h)), &h, sizeof(h));
		memset(skb_put(skb, bytes), 0xab, bytes);
		offset += bytes;
		left -= bytes;
	} while (left);
	if (records > 1) {
		skb_shinfo(skb)->gso_type = SKB_GSO_UDP_L4;
		skb_shinfo(skb)->gso_size = sizeof(h) + stride;
		skb_shinfo(skb)->gso_segs = records;
	}
	if (mock_ipv6)
		skb_push(skb, sizeof(struct ipv6hdr));
	else {
		skb_push(skb, sizeof(struct iphdr));
		ip_hdr(skb)->ihl = 5;
	}
	homa_get_skb_info(skb)->data_bytes = payload;
	homa_get_skb_info(skb)->dont_defer = false;
	qdisc_skb_cb(skb)->pkt_len = skb->len;
	return skb;
}

static struct net_device *create_hook_dev;
static int create_hook_count;

static void qdisc_create_hook(char *id)
{
	if (!strcmp(id, "mutex_lock") && create_hook_count > 0 &&
	    --create_hook_count == 0)
		homa_qdisc_qdev_get(create_hook_dev);
}

static struct homa_qdisc_dev *sleep_hook_qdev;
static struct sk_buff *sleep_hook_skb;
static int sleep_hook_count;

static void qdisc_sleep_hook(char *id)
{
	if (strcmp(id, "prepare_to_wait"))
		return;
	if (sleep_hook_skb) {
		homa_qdisc_defer_homa(sleep_hook_qdev, sleep_hook_skb);
		sleep_hook_skb = NULL;
	}
	if (sleep_hook_count > 0 && --sleep_hook_count == 0)
		mock_exit_thread = true;
}

FIXTURE(homa_qdisc) {
	struct homa homa;
	struct homa_net *hnet;
	struct homa_sock hsk;
	struct in6_addr src, dst;
	struct net_device *dev;
	struct netdev_queue txqs[2];
	struct Qdisc *sch[2];
	struct homa_qdisc *q[2];
};
FIXTURE_SETUP(homa_qdisc)
{
	int i;

	homa_qdisc_register();
	homa_init(&self->homa);
	self->hnet = mock_hnet(0, &self->homa);
	self->src = unit_get_in_addr("196.168.0.1");
	self->dst = unit_get_in_addr("1.2.3.4");
	mock_sock_init(&self->hsk, self->hnet, 40000);
	self->dev = mock_dev(0, &self->homa);
	memset(self->txqs, 0, sizeof(self->txqs));
	self->dev->_tx = self->txqs;
	self->dev->num_tx_queues = 2;
	self->dev->real_num_tx_queues = 2;
	for (i = 0; i < 2; i++) {
		self->txqs[i].dev = self->dev;
		self->sch[i] = mock_alloc_qdisc(&self->txqs[i]);
		self->txqs[i].qdisc = self->sch[i];
		ASSERT_EQ(0, homa_qdisc_init(self->sch[i], NULL, NULL));
		self->q[i] = qdisc_priv(self->sch[i]);
	}
	mock_clock = 10000;
	create_hook_count = 0;
	sleep_hook_count = 0;
	sleep_hook_skb = NULL;
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_qdisc)
{
	int i;

	homa_sock_shutdown(&self->hsk);
	homa_sock_destroy(&self->hsk.sock);
	for (i = 0; i < 2; i++) {
		homa_qdisc_destroy(self->sch[i]);
		kfree(self->sch[i]);
	}
	homa_destroy(&self->homa);
	homa_qdisc_unregister();
	unit_teardown();
}

static struct homa_rpc *qdisc_rpc(struct homa_sock *hsk,
				  struct in6_addr *src, struct in6_addr *dst,
				  u64 id)
{
	return unit_client_rpc(hsk, UNIT_OUTGOING, src, dst, 99, id, 10000, 10000);
}

/**
 * qdisc_split_skb() - Move all of the bytes of @skb beyond the first
 * @linear bytes (counted from skb->data) into a page fragment.
 * @skb:     Packet to convert.
 * @linear:  Number of bytes to leave in the linear part of the skb.
 */
static void qdisc_split_skb(struct sk_buff *skb, int linear)
{
	struct page *page = alloc_page(GFP_KERNEL);
	int rest = skb->len - linear;

	EXPECT_NE(NULL, page);
	if (!page)
		return;
	/* The mock page_address() is the struct page itself, so the packet
	 * bytes must be copied only after skb_fill_page_desc has read the
	 * page header.
	 */
	skb_fill_page_desc(skb, 0, page, 0, rest);
	memcpy(page_address(page), skb->data + linear, rest);
	skb->tail -= rest;
	skb->data_len = rest;
}

/**
 * qdisc_defers() - Enqueue a packet in a congested qdisc and report whether
 * it was deferred.
 * @sch:   Qdisc to use.
 * @skb:   Packet to enqueue.
 * Return: True if @skb was deferred by the pacer logic (a deferred skb is
 *         left on its RPC's deferred list); false if it was queued in @sch
 *         instead.
 */
static bool qdisc_defers(struct Qdisc *sch, struct sk_buff *skb)
{
	struct homa_qdisc_dev *qdev = ((struct homa_qdisc *)qdisc_priv(sch))->qdev;
	struct sk_buff *to_free = NULL;
	int qlen = sch->q.qlen;

	qdev->max_nic_queue_bytes = 1;
	atomic_set(&qdev->total_nic_queue, 1000);
	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(skb, sch, &to_free));
	EXPECT_EQ(NULL, to_free);
	return sch->q.qlen == qlen && homa_qdisc_any_deferred(qdev);
}

TEST_F(homa_qdisc, is_homa_pkt__udp_data_both_families)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *rpc = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	bool saved = mock_ipv6;
	int family;

	ASSERT_NE(NULL, rpc);
	for (family = 0; family < 2; family++) {
		struct sk_buff *skb;

		mock_ipv6 = family;
		skb = qdisc_packet(rpc, &self->src, &self->dst, 0, 2801, 1400);
		EXPECT_TRUE(qdisc_defers(self->sch[0], skb));
		EXPECT_EQ(skb, skb_peek(&rpc->qrpc.packets));
		EXPECT_EQ(skb, homa_qdisc_get_deferred_homa(qdev));
		kfree_skb(skb);
	}
	mock_ipv6 = saved;
}

TEST_F(homa_qdisc, is_homa_pkt__control_packet_types)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	int type;

	for (type = DATA + 1; type <= MAX_OP; type++) {
		struct sk_buff *skb = qdisc_packet(NULL, &self->src, &self->dst,
						   0, 100, 0);

		((struct homa_common_hdr *)(udp_hdr(skb) + 1))->type = type;
		EXPECT_FALSE(qdisc_defers(self->sch[0], skb));
	}
	EXPECT_EQ(MAX_OP - DATA, self->sch[0]->q.qlen);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
}

TEST_F(homa_qdisc, is_homa_pkt__not_homa)
{
	struct homa_rpc *rpc = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	bool saved = mock_ipv6;
	int family, which;

	ASSERT_NE(NULL, rpc);
	for (family = 0; family < 2; family++) {
		mock_ipv6 = family;
		for (which = 0; which < 7; which++) {
			struct sk_buff *skb = qdisc_packet(rpc, &self->src,
							   &self->dst, 0, 1400, 0);
			u8 *protocol = mock_ipv6 ? &ipv6_hdr(skb)->nexthdr :
						   &ip_hdr(skb)->protocol;

			switch (which) {
			case 0: *protocol = IPPROTO_TCP; break;
			case 1: *protocol = IPPROTO_HOMA; break;
			case 2: udp_hdr(skb)->source = htons(HOMA_UDP_PORT + 1); break;
			case 3: udp_hdr(skb)->dest = htons(HOMA_UDP_PORT + 1); break;
			case 4: udp_hdr(skb)->source = 0; break;
			case 5: *protocol = IPPROTO_UDP + 1; break;
			case 6:
				__skb_trim(skb, skb_transport_offset(skb) +
					   sizeof(struct udphdr) + 5);
				break;
			}
			EXPECT_FALSE(qdisc_defers(self->sch[0], skb));
			EXPECT_FALSE(homa_qdisc_any_deferred(self->q[0]->qdev));
		}
	}
	EXPECT_EQ(14, self->sch[0]->q.qlen);
	mock_ipv6 = saved;
}

TEST_F(homa_qdisc, is_homa_pkt__only_pull_homa_header)
{
	int linear = sizeof(struct iphdr) + sizeof(struct udphdr) + 5;
	bool saved = mock_ipv6;
	struct sk_buff *skb;

	/* The Homa common header is not linear: it gets pulled. */
	mock_ipv6 = false;
	skb = qdisc_packet(NULL, &self->src, &self->dst, 0, 100, 0);
	((struct homa_common_hdr *)(udp_hdr(skb) + 1))->type = BUSY;
	qdisc_split_skb(skb, linear);
	EXPECT_EQ(linear, skb_headlen(skb));
	EXPECT_FALSE(qdisc_defers(self->sch[0], skb));
	EXPECT_EQ(sizeof(struct iphdr) + sizeof(struct udphdr) +
		  sizeof(struct homa_common_hdr), skb_headlen(skb));

	/* TCP and other-port UDP packets never have headers pulled. */
	skb = qdisc_packet(NULL, &self->src, &self->dst, 0, 100, 0);
	ip_hdr(skb)->protocol = IPPROTO_TCP;
	qdisc_split_skb(skb, linear);
	EXPECT_FALSE(qdisc_defers(self->sch[0], skb));
	EXPECT_EQ(linear, skb_headlen(skb));
	skb = qdisc_packet(NULL, &self->src, &self->dst, 0, 100, 0);
	udp_hdr(skb)->dest = htons(123);
	qdisc_split_skb(skb, linear);
	EXPECT_FALSE(qdisc_defers(self->sch[0], skb));
	EXPECT_EQ(linear, skb_headlen(skb));
	mock_ipv6 = saved;
}

TEST_F(homa_qdisc, enqueue__pkt_len_from_qdisc_skb_cb)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct sk_buff *skb = qdisc_packet(NULL, &self->src, &self->dst, 0, 2817, 1400);
	struct sk_buff *to_free = NULL;

	/* qdisc_pkt_len already includes the IP and UDP headers of every
	 * GSO segment; link_idle accounting adds only one frame overhead.
	 */
	qdev->cycles_per_mibyte = 1 << 20;
	skb_set_queue_mapping(skb, 1);
	qdisc_skb_cb(skb)->pkt_len = 5000;
	((struct homa_data_hdr *)(udp_hdr(skb) + 1))->msg_length = htonl(100);
	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(skb, self->sch[1], &to_free));
	EXPECT_EQ(mock_clock + 5000 + HOMA_ETH_FRAME_OVERHEAD,
		  atomic64_read(&qdev->link_idle_time));
	EXPECT_EQ(5000, atomic_read(&qdev->total_nic_queue));
}

TEST_F(homa_qdisc, generic_tcp_and_udp_always_pass_through)
{
	int protocol;
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;

	qdev->max_nic_queue_bytes = 1;
	atomic_set(&qdev->total_nic_queue, 100000);
	atomic64_set(&qdev->link_idle_time, 1000000);
	for (protocol = 0; protocol < 2; protocol++) {
		struct sk_buff *skb = qdisc_packet(NULL, &self->src, &self->dst, 0, 3000, 0);
		struct sk_buff *to_free = NULL;

		udp_hdr(skb)->dest = htons(123);
		if (protocol) {
			if (mock_ipv6)
				ipv6_hdr(skb)->nexthdr = IPPROTO_TCP;
			else
				ip_hdr(skb)->protocol = IPPROTO_TCP;
		}
		EXPECT_EQ(NET_XMIT_SUCCESS,
			  homa_qdisc_enqueue(skb, self->sch[0], &to_free));
		EXPECT_EQ(NULL, to_free);
		EXPECT_EQ(protocol + 1, self->sch[0]->q.qlen);
		EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	}
}

TEST_F(homa_qdisc, enqueue_short_message_and_pacer_reentry)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct sk_buff *skb = qdisc_packet(NULL, &self->src, &self->dst, 0, 100, 0);
	struct sk_buff *to_free = NULL;
	u64 idle;

	((struct homa_data_hdr *)(udp_hdr(skb) + 1))->msg_length = htonl(100);
	atomic64_set(&qdev->link_idle_time, 1000000);
	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(skb, self->sch[0], &to_free));
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	idle = atomic64_read(&qdev->link_idle_time);
	EXPECT_GT(idle, 1000000);
	skb = qdisc_packet(NULL, &self->src, &self->dst, 0, 1500, 0);
	homa_get_skb_info(skb)->dont_defer = true;
	qdisc_skb_cb(skb)->pkt_len = 1600;
	atomic_set(&qdev->total_nic_queue, 1000);
	qdev->max_nic_queue_bytes = 1;
	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(skb, self->sch[0], &to_free));
	EXPECT_EQ(2, self->sch[0]->q.qlen);
	EXPECT_EQ(2600, atomic_read(&qdev->total_nic_queue));
	EXPECT_EQ(idle, atomic64_read(&qdev->link_idle_time));
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
}

TEST_F(homa_qdisc, enqueue_defer_srpt_rpc_order_and_payload_accounting)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *a = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			&self->src, &self->dst, 99, 1234, 10000, 10000);
	struct homa_rpc *b = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			&self->src, &self->dst, 99, 1236, 10000, 10000);
	struct sk_buff *first, *second, *result, *to_free = NULL;
	int bytes, second_bytes;

	ASSERT_NE(NULL, a);
	ASSERT_NE(NULL, b);
	self->homa.qshared->fifo_fraction = 0;
	qdev->max_nic_queue_bytes = 1;
	atomic_set(&qdev->total_nic_queue, 1000);
	first = qdisc_packet(a, &self->src, &self->dst, 2000, 2817, 1400);
	second = qdisc_packet(b, &self->src, &self->dst, 7000, 1000, 0);
	second_bytes = qdisc_pkt_len(second);
	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(first, self->sch[0], &to_free));
	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(second, self->sch[0], &to_free));
	EXPECT_EQ(0, self->sch[0]->q.qlen);
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(8000, a->qrpc.tx_left);
	EXPECT_EQ(3000, b->qrpc.tx_left);
	EXPECT_EQ(second, homa_qdisc_get_deferred_homa(qdev));
	EXPECT_EQ(2000, b->qrpc.tx_left);
	kfree_skb(second);
	bytes = qdisc_pkt_len(first);
	result = homa_qdisc_get_deferred_homa(qdev);
	EXPECT_EQ(first, result);
	EXPECT_EQ(10000 - 2000 - 2817, a->qrpc.tx_left);
	EXPECT_EQ(-bytes - second_bytes, qdev->srpt_bytes);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	kfree_skb(first);
}

TEST_F(homa_qdisc, deferred_fifo_and_flush_rpc)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *a = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			&self->src, &self->dst, 99, 1234, 10000, 10000);
	struct homa_rpc *b = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			&self->src, &self->dst, 99, 1236, 10000, 10000);
	struct sk_buff *first, *second;

	ASSERT_NE(NULL, a);
	ASSERT_NE(NULL, b);
	a->msgout.init_time = 100;
	b->msgout.init_time = 200;
	first = qdisc_packet(a, &self->src, &self->dst, 1000, 1000, 0);
	second = qdisc_packet(b, &self->src, &self->dst, 7000, 1000, 0);
	homa_qdisc_defer_homa(qdev, first);
	homa_qdisc_defer_homa(qdev, second);
	qdev->srpt_bytes = 0;
	EXPECT_EQ(a, homa_qdisc_get_oldest(qdev));
	EXPECT_EQ(first, homa_qdisc_get_deferred_homa(qdev));
	EXPECT_GT(homa_metrics_per_cpu()->pacer_fifo_bytes, 0);
	kfree_skb(first);
	EXPECT_EQ(7000, homa_qdisc_deferred_offset(b));
	homa_qdisc_flush_rpc(b);
	EXPECT_EQ(-1, homa_qdisc_deferred_offset(b));
	EXPECT_EQ(NULL, homa_qdisc_get_deferred_homa(qdev));
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
}

TEST_F(homa_qdisc, pacer_transmits_deferred_and_obeys_congestion)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			&self->src, &self->dst, 99, 1234, 10000, 10000);
	struct sk_buff *skb;
	int bytes;

	ASSERT_NE(NULL, rpc);
	skb = qdisc_packet(rpc, &self->src, &self->dst, 0, 2817, 1400);
	bytes = qdisc_pkt_len(skb);
	homa_qdisc_defer_homa(qdev, skb);
	atomic64_set(&qdev->link_idle_time, mock_clock + 100000);
	EXPECT_EQ(0, homa_qdisc_pacer(qdev));
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));
	atomic64_set(&qdev->link_idle_time, 0);
	EXPECT_EQ(bytes, homa_qdisc_pacer(qdev));
	EXPECT_EQ(1, homa_metrics_per_cpu()->pacer_homa_packets);
	EXPECT_EQ(bytes, homa_metrics_per_cpu()->pacer_homa_bytes);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
}

TEST_F(homa_qdisc, homa_qdisc_update_link_idle__nic_idle)
{
	struct homa_qdisc_dev qdev;

	memset(&qdev, 0, sizeof(qdev));
	qdev.cycles_per_mibyte = 1 << 20;     /* 1 cycle per byte. */
	mock_clock = 1000;

	EXPECT_EQ(1, homa_qdisc_update_link_idle(&qdev, 200, 0));
	EXPECT_EQ(1200 + HOMA_ETH_FRAME_OVERHEAD,
		  atomic64_read(&qdev.link_idle_time));
}

TEST_F(homa_qdisc, homa_qdisc_update_link_idle__queue_too_long)
{
	struct homa_qdisc_dev qdev;

	memset(&qdev, 0, sizeof(qdev));
	qdev.cycles_per_mibyte = 1 << 20;     /* 1 cycle per byte. */
	mock_clock = 1000;
	atomic64_set(&qdev.link_idle_time, 1100);

	/* First attempt: queue too long. */
	EXPECT_EQ(0, homa_qdisc_update_link_idle(&qdev, 200, 99));
	EXPECT_EQ(1100, atomic64_read(&qdev.link_idle_time));

	/* Second attempt tolerates longer queue. */
	EXPECT_EQ(1, homa_qdisc_update_link_idle(&qdev, 200, 110));
	EXPECT_EQ(1300 + HOMA_ETH_FRAME_OVERHEAD,
		  atomic64_read(&qdev.link_idle_time));
}

TEST_F(homa_qdisc, homa_qdisc_update_link_idle__ignore_queue_length)
{
	struct homa_qdisc_dev qdev;

	memset(&qdev, 0, sizeof(qdev));
	qdev.cycles_per_mibyte = 1 << 20;     /* 1 cycle per byte. */
	mock_clock = 1000;
	atomic64_set(&qdev.link_idle_time, 1200);

	EXPECT_EQ(1, homa_qdisc_update_link_idle(&qdev, 120, -1));
	EXPECT_EQ(1320 + HOMA_ETH_FRAME_OVERHEAD,
		  atomic64_read(&qdev.link_idle_time));
}

TEST_F(homa_qdisc, add_queued_and_refresh_dql)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct sk_buff *skb = qdisc_packet(NULL, &self->src, &self->dst, 0, 700, 0);

	skb_set_queue_mapping(skb, 1);
	qdisc_skb_cb(skb)->pkt_len = 800;
	atomic_set(&qdev->total_nic_queue, 1000);
	qdev->nic_queues[1].num_queued = 2000;
	self->txqs[1].dql.num_queued = 2500;
	self->txqs[1].dql.num_completed = 1500;
	atomic_set(&qdev->nic_queues[1].length, 400);
	homa_qdisc_add_queued(qdev, skb);
	EXPECT_EQ(3300, qdev->nic_queues[1].num_queued);
	EXPECT_EQ(1800, atomic_read(&qdev->nic_queues[1].length));
	EXPECT_EQ(2400, atomic_read(&qdev->total_nic_queue));
	self->txqs[1].dql.num_completed = 2000;
	homa_qdisc_refresh_from_dql(qdev);
	EXPECT_EQ(1300, atomic_read(&qdev->nic_queues[1].length));
	kfree_skb(skb);
}

TEST_F(homa_qdisc, rpc_priority_bytes_age_and_address_tiebreak)
{
	struct homa_rpc a = {}, b = {};

	a.qrpc.tx_left = 100;
	b.qrpc.tx_left = 200;
	EXPECT_TRUE(homa_qdisc_precedes(&a, &b));
	EXPECT_FALSE(homa_qdisc_precedes(&b, &a));
	b.qrpc.tx_left = 100;
	a.msgout.init_time = 10;
	b.msgout.init_time = 20;
	EXPECT_TRUE(homa_qdisc_precedes(&a, &b));
	EXPECT_FALSE(homa_qdisc_precedes(&b, &a));
	b.msgout.init_time = 10;
	EXPECT_EQ(&a < &b, homa_qdisc_precedes(&a, &b));
	EXPECT_EQ(&b < &a, homa_qdisc_precedes(&b, &a));
}

TEST_F(homa_qdisc, shared_device_references_and_sysctl_compatibility)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;

	EXPECT_EQ(qdev, self->q[1]->qdev);
	EXPECT_EQ(0, self->q[0]->ix);
	EXPECT_EQ(1, self->q[1]->ix);
	EXPECT_EQ(2, refcount_read(&qdev->refs));
	self->homa.qshared->fifo_fraction = 200;
	self->homa.qshared->max_link_usage = 4;
	homa_qdisc_update_sysctl_deps(self->homa.qshared);
	EXPECT_EQ(4 * (1 << HOMA_FIFO_WEIGHT_SHIFT), self->homa.qshared->fifo_weight);
	EXPECT_EQ(5, self->homa.qshared->max_link_usage);
}

TEST_F(homa_qdisc, allocation_and_rcu_cleanup_errors)
{
	struct homa_qdisc_shared *shared;
	void *object = kmalloc(100, GFP_KERNEL);

	mock_kmalloc_errors = 1;
	homa_rcu_kfree(object);
	EXPECT_SUBSTR("homa_rcu_kfree kmalloc failed", unit_log_get());
	mock_kmalloc_errors = 1;
	shared = homa_qdisc_shared_alloc();
	EXPECT_EQ(-ENOMEM, PTR_ERR(shared));
	mock_register_sysctl_errors = 1;
	shared = homa_qdisc_shared_alloc();
	EXPECT_EQ(-ENOMEM, PTR_ERR(shared));
}

TEST_F(homa_qdisc, homa_rcu_kfree__kmalloc_succeeds)
{
	homa_rcu_kfree(kmalloc(100, GFP_KERNEL));
	EXPECT_SUBSTR("call_rcu invoked", unit_log_get());
}

TEST_F(homa_qdisc, homa_rcu_kfree_callback)
{
	struct homa_rcu_kfreer *freer = kmalloc(sizeof(*freer), GFP_KERNEL);

	ASSERT_NE(NULL, freer);
	freer->object = kmalloc(200, GFP_KERNEL);
	homa_rcu_kfree_callback(&freer->rcu_head);
}

TEST_F(homa_qdisc, homa_qdisc_shared_alloc__success)
{
	struct homa_qdisc_shared *shared = homa_qdisc_shared_alloc();

	ASSERT_FALSE(IS_ERR(shared));
	EXPECT_TRUE(list_empty(&shared->qdevs));
	EXPECT_EQ(50, shared->fifo_fraction);
	EXPECT_EQ(1000, shared->defer_min_bytes);
	EXPECT_EQ(99, shared->max_link_usage);
	ASSERT_NE(NULL, shared->sysctl_header);
	homa_qdisc_shared_free(shared);
	EXPECT_SUBSTR("unregister_net_sysctl_table", unit_log_get());
	EXPECT_SUBSTR("call_rcu invoked", unit_log_get());
}

TEST_F(homa_qdisc, homa_qdisc_shared_free__unfreed_qdevs)
{
	struct homa_qdisc_shared *saved = self->homa.qshared;
	struct homa_qdisc_shared *shared = homa_qdisc_shared_alloc();
	struct homa_qdisc_dev *qdev;

	ASSERT_FALSE(IS_ERR(shared));
	self->homa.qshared = shared;
	qdev = homa_qdisc_qdev_get(self->dev);
	ASSERT_FALSE(IS_ERR(qdev));
	EXPECT_EQ(1, unit_list_length(&shared->qdevs));
	self->homa.qshared = saved;
	mock_printk_output[0] = 0;
	homa_qdisc_shared_free(shared);
	EXPECT_SUBSTR("found 1 live qdevs", mock_printk_output);
	EXPECT_EQ(NULL, qdev->pacer_kthread);
	EXPECT_TRUE(list_empty(&qdev->links));
	homa_qdisc_qdev_put(qdev);
	EXPECT_EQ(1, unit_list_length(&saved->qdevs));
}

TEST_F(homa_qdisc, homa_qdisc_qdev_get__basics)
{
	struct homa_qdisc_dev *qdev = homa_qdisc_qdev_get(mock_dev(1, &self->homa));

	ASSERT_FALSE(IS_ERR(qdev));
	EXPECT_EQ(1, refcount_read(&qdev->refs));
	EXPECT_EQ(2, unit_list_length(&self->homa.qshared->qdevs));
	EXPECT_TRUE(RB_EMPTY_ROOT(&qdev->deferred_rpcs.rb_root));
	EXPECT_EQ(10000, qdev->link_mbps);
	ASSERT_NE(NULL, qdev->pacer_kthread);
	homa_qdisc_qdev_put(qdev);
	EXPECT_EQ(1, unit_list_length(&self->homa.qshared->qdevs));
}

TEST_F(homa_qdisc, homa_qdisc_get__use_existing)
{
	struct homa_qdisc_dev *existing = self->q[0]->qdev;
	struct homa_qdisc_dev *other = homa_qdisc_qdev_get(mock_dev(1, &self->homa));

	ASSERT_FALSE(IS_ERR(other));
	EXPECT_EQ(existing, homa_qdisc_qdev_get(self->dev));
	EXPECT_EQ(3, refcount_read(&existing->refs));
	EXPECT_EQ(other, homa_qdisc_qdev_get(other->dev));
	EXPECT_EQ(2, refcount_read(&other->refs));
	homa_qdisc_qdev_put(existing);
	homa_qdisc_qdev_put(other);
	EXPECT_EQ(2, unit_list_length(&self->homa.qshared->qdevs));
	homa_qdisc_qdev_put(other);
	EXPECT_EQ(1, unit_list_length(&self->homa.qshared->qdevs));
}

TEST_F(homa_qdisc, homa_qdisc_qdev_get__race_when_creating)
{
	struct homa_qdisc_dev *qdev;

	create_hook_dev = mock_dev(1, &self->homa);
	create_hook_count = 1;
	unit_hook_register(qdisc_create_hook);
	qdev = homa_qdisc_qdev_get(create_hook_dev);
	ASSERT_FALSE(IS_ERR(qdev));
	EXPECT_EQ(2, refcount_read(&qdev->refs));
	EXPECT_EQ(2, unit_list_length(&self->homa.qshared->qdevs));
	EXPECT_SUBSTR("race in homa_qdisc_qdev_get", unit_log_get());
	homa_qdisc_qdev_put(qdev);
	EXPECT_EQ(1, refcount_read(&qdev->refs));
	homa_qdisc_qdev_put(qdev);
	EXPECT_EQ(1, unit_list_length(&self->homa.qshared->qdevs));
}

TEST_F(homa_qdisc, homa_qdisc_qdev_get__kmalloc_failure)
{
	struct net_device *dev = mock_dev(1, &self->homa);
	struct homa_qdisc_dev *qdev;
	int errors;

	for (errors = 1; errors <= 2; errors++) {
		mock_kmalloc_errors = errors;
		qdev = homa_qdisc_qdev_get(dev);
		ASSERT_TRUE(IS_ERR(qdev));
		EXPECT_EQ(-ENOMEM, PTR_ERR(qdev));
		EXPECT_EQ(1, unit_list_length(&self->homa.qshared->qdevs));
	}
}

TEST_F(homa_qdisc, homa_qdisc_qdev_get__initialize_nic_queues)
{
	struct net_device *dev = mock_dev(1, &self->homa);
	struct netdev_queue queues[3] = {};
	struct homa_qdisc_dev *qdev;

	dev->_tx = queues;
	dev->num_tx_queues = 3;
	dev->real_num_tx_queues = 2;
	queues[0].dql.num_queued = 100;
	queues[1].dql.num_queued = 200;
	queues[2].dql.num_queued = 300;
	qdev = homa_qdisc_qdev_get(dev);
	ASSERT_FALSE(IS_ERR(qdev));
	EXPECT_EQ(100, qdev->nic_queues[0].num_queued);
	EXPECT_EQ(200, qdev->nic_queues[1].num_queued);
	EXPECT_EQ(0, qdev->nic_queues[2].num_queued);
	homa_qdisc_qdev_put(qdev);
	dev->_tx = &mock_net_queue;
}

TEST_F(homa_qdisc, homa_qdisc_qdev_get__cant_create_thread)
{
	struct net_device *dev = mock_dev(1, &self->homa);
	struct homa_qdisc_dev *qdev;

	mock_kthread_create_errors = 1;
	qdev = homa_qdisc_qdev_get(dev);
	ASSERT_TRUE(IS_ERR(qdev));
	EXPECT_EQ(-EACCES, PTR_ERR(qdev));
	EXPECT_EQ(1, unit_list_length(&self->homa.qshared->qdevs));
}

TEST_F(homa_qdisc, homa_qdisc_init__basics)
{
	struct netdev_queue queue = {.dev = self->dev};
	struct Qdisc *sch = mock_alloc_qdisc(&queue);
	struct homa_qdisc *q;

	EXPECT_EQ(0, homa_qdisc_init(sch, NULL, NULL));
	q = qdisc_priv(sch);
	EXPECT_EQ(self->q[0]->qdev, q->qdev);
	EXPECT_EQ(-1, q->ix);
	EXPECT_EQ(3, refcount_read(&q->qdev->refs));
	EXPECT_EQ(10240, sch->limit);
	homa_qdisc_destroy(sch);
	EXPECT_EQ(2, refcount_read(&self->q[0]->qdev->refs));
	kfree(sch);
}

TEST_F(homa_qdisc, homa_qdisc_init__cant_create_new_qdisc_dev)
{
	struct netdev_queue queue = {.dev = mock_dev(1, &self->homa)};
	struct Qdisc *sch = mock_alloc_qdisc(&queue);

	mock_kmalloc_errors = 1;
	EXPECT_EQ(-ENOMEM, homa_qdisc_init(sch, NULL, NULL));
	EXPECT_EQ(1, unit_list_length(&self->homa.qshared->qdevs));
	kfree(sch);
}

TEST_F(homa_qdisc, homa_qdisc_destroy)
{
	struct netdev_queue queue = {.dev = mock_dev(1, &self->homa)};
	struct Qdisc *sch = mock_alloc_qdisc(&queue);
	struct sk_buff *skb = qdisc_packet(NULL, &self->src, &self->dst, 0, 100, 0);

	ASSERT_EQ(0, homa_qdisc_init(sch, NULL, NULL));
	qdisc_enqueue_tail(skb, sch);
	EXPECT_EQ(1, sch->q.qlen);
	homa_qdisc_destroy(sch);
	EXPECT_EQ(0, sch->q.qlen);
	EXPECT_EQ(1, unit_list_length(&self->homa.qshared->qdevs));
	kfree(sch);
}

TEST_F(homa_qdisc, homa_qdisc_add_queued__no_lag)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct sk_buff *skb = qdisc_packet(NULL, &self->src, &self->dst, 0, 700, 0);

	skb_set_queue_mapping(skb, 1);
	qdisc_skb_cb(skb)->pkt_len = 800;
	qdev->nic_queues[1].num_queued = 2000;
	self->txqs[1].dql.num_queued = 1000;
	self->txqs[1].dql.num_completed = 1500;
	atomic_set(&qdev->nic_queues[1].length, 400);
	atomic_set(&qdev->total_nic_queue, 1000);
	homa_qdisc_add_queued(qdev, skb);
	EXPECT_EQ(2800, qdev->nic_queues[1].num_queued);
	EXPECT_EQ(1300, atomic_read(&qdev->nic_queues[1].length));
	EXPECT_EQ(1900, atomic_read(&qdev->total_nic_queue));
	kfree_skb(skb);
}

TEST_F(homa_qdisc, homa_qdisc_add_queued__counter_wraparound)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct sk_buff *skb = qdisc_packet(NULL, &self->src, &self->dst, 0, 100, 0);

	qdisc_skb_cb(skb)->pkt_len = 100;
	qdev->nic_queues[0].num_queued = U32_MAX - 15;
	self->txqs[0].dql.num_queued = 16;
	self->txqs[0].dql.num_completed = U32_MAX - 31;
	homa_qdisc_add_queued(qdev, skb);
	EXPECT_EQ(116, qdev->nic_queues[0].num_queued);
	EXPECT_EQ(148, atomic_read(&qdev->nic_queues[0].length));
	self->txqs[0].dql.num_queued = U32_MAX - 15;
	homa_qdisc_add_queued(qdev, skb);
	EXPECT_EQ(216, qdev->nic_queues[0].num_queued);
	EXPECT_EQ(248, atomic_read(&qdev->total_nic_queue));
	kfree_skb(skb);
}

TEST_F(homa_qdisc, homa_qdisc_enqueue__short_final_packet_in_long_message)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *rpc = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	struct sk_buff *skb, *to_free = NULL;

	ASSERT_NE(NULL, rpc);
	skb = qdisc_packet(rpc, &self->src, &self->dst, 9900, 100, 0);
	atomic64_set(&qdev->link_idle_time, 1000000);
	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(skb, self->sch[0], &to_free));
	EXPECT_EQ(NULL, to_free);
	EXPECT_EQ(0, self->sch[0]->q.qlen);
	EXPECT_EQ(skb, skb_peek(&rpc->qrpc.packets));
	EXPECT_EQ(100, rpc->qrpc.tx_left);
	EXPECT_EQ(1000000, atomic64_read(&qdev->link_idle_time));
}

TEST_F(homa_qdisc, homa_qdisc_enqueue__defer_homa_packet_because_of_other_deferred_packets)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *rpc = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	struct sk_buff *first, *second, *to_free = NULL;

	ASSERT_NE(NULL, rpc);
	first = qdisc_packet(rpc, &self->src, &self->dst, 0, 1400, 0);
	second = qdisc_packet(rpc, &self->src, &self->dst, 1400, 1400, 0);
	atomic64_set(&qdev->link_idle_time, 1000000);
	homa_qdisc_enqueue(first, self->sch[0], &to_free);
	atomic64_set(&qdev->link_idle_time, 0);
	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(second, self->sch[1], &to_free));
	EXPECT_EQ(0, self->sch[0]->q.qlen);
	EXPECT_EQ(0, self->sch[1]->q.qlen);
	EXPECT_EQ(2, skb_queue_len(&rpc->qrpc.packets));
	EXPECT_EQ(first, skb_peek(&rpc->qrpc.packets));
	EXPECT_EQ(0, atomic64_read(&qdev->link_idle_time));
	EXPECT_EQ(0, atomic_read(&qdev->total_nic_queue));
}

TEST_F(homa_qdisc, homa_qdisc_enqueue__update_queue_lengths)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct sk_buff *skb = qdisc_packet(NULL, &self->src, &self->dst, 0, 1400, 0);
	struct sk_buff *to_free = NULL;

	qdev->cycles_per_mibyte = 1 << 20;
	qdisc_skb_cb(skb)->pkt_len = 8000;
	skb_set_queue_mapping(skb, 1);
	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(skb, self->sch[1], &to_free));
	EXPECT_EQ(1, self->sch[1]->q.qlen);
	EXPECT_EQ(mock_clock + 8000 + HOMA_ETH_FRAME_OVERHEAD,
		  atomic64_read(&qdev->link_idle_time));
	EXPECT_EQ(8000, qdev->nic_queues[1].num_queued);
	EXPECT_EQ(8000, atomic_read(&qdev->nic_queues[1].length));
	EXPECT_EQ(8000, atomic_read(&qdev->total_nic_queue));
	EXPECT_EQ(htons(HOMA_UDP_PORT), udp_hdr(skb)->dest);
}

TEST_F(homa_qdisc, homa_qdisc_enqueue__control_packet_bypasses_congestion)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct sk_buff *skb = qdisc_packet(NULL, &self->src, &self->dst, 0, 100, 0);
	struct sk_buff *to_free = NULL;
	int bytes;

	((struct homa_common_hdr *)(udp_hdr(skb) + 1))->type = BUSY;
	bytes = qdisc_pkt_len(skb) + HOMA_ETH_FRAME_OVERHEAD;
	qdev->cycles_per_mibyte = 1 << 20;
	qdev->max_nic_queue_bytes = 1;
	atomic_set(&qdev->total_nic_queue, 10000);
	atomic64_set(&qdev->link_idle_time, 1000000);
	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(skb, self->sch[0], &to_free));
	EXPECT_EQ(1, self->sch[0]->q.qlen);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(1000000 + bytes, atomic64_read(&qdev->link_idle_time));
}

TEST_F(homa_qdisc, homa_qdisc_defer_homa__multiple_pkts_for_rpc)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *rpc = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	struct sk_buff *packets[4];
	int offsets[] = {1000, 6000, 2500, 4000};
	int i;

	ASSERT_NE(NULL, rpc);
	for (i = 0; i < ARRAY_SIZE(packets); i++) {
		packets[i] = qdisc_packet(rpc, &self->src, &self->dst, offsets[i], 500, 0);
		homa_qdisc_defer_homa(qdev, packets[i]);
	}
	EXPECT_EQ(4, skb_queue_len(&rpc->qrpc.packets));
	EXPECT_EQ(9000, rpc->qrpc.tx_left);
	EXPECT_EQ(&rpc->qrpc.rb_node, rb_first_cached(&qdev->deferred_rpcs));
	for (i = 0; i < ARRAY_SIZE(packets); i++) {
		EXPECT_EQ(packets[i], homa_qdisc_get_deferred_homa(qdev));
		kfree_skb(packets[i]);
	}
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
}

TEST_F(homa_qdisc, homa_qdisc_defer_homa__dont_update_tx_left)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *rpc = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);

	ASSERT_NE(NULL, rpc);
	rpc->qrpc.tx_left = 2000;
	homa_qdisc_defer_homa(qdev, qdisc_packet(rpc, &self->src, &self->dst, 5000, 500, 0));
	EXPECT_EQ(2000, rpc->qrpc.tx_left);
}

TEST_F(homa_qdisc, homa_qdisc_defer_homa__nic_backlog_cycles_metric_and_wake_up_pacer)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *rpc = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);

	ASSERT_NE(NULL, rpc);
	mock_log_wakeups = 1;
	mock_clock = 5000;
	unit_log_clear();
	homa_qdisc_defer_homa(qdev, qdisc_packet(rpc, &self->src, &self->dst, 1000, 500, 0));
	EXPECT_EQ(5000, qdev->last_defer);
	EXPECT_EQ(0, homa_metrics_per_cpu()->nic_backlog_cycles);
	EXPECT_STREQ("wake_up", unit_log_get());
	mock_clock = 12000;
	unit_log_clear();
	homa_qdisc_defer_homa(qdev, qdisc_packet(rpc, &self->src, &self->dst, 2000, 500, 0));
	EXPECT_EQ(12000, qdev->last_defer);
	EXPECT_EQ(7000, homa_metrics_per_cpu()->nic_backlog_cycles);
	EXPECT_STREQ("wake_up", unit_log_get());
}

TEST_F(homa_qdisc, homa_qdisc_defer_homa__rpc_has_ended)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct sk_buff *skb = qdisc_packet(NULL, &self->src, &self->dst, 0, 100, 0);

	homa_qdisc_defer_homa(qdev, skb);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(0, qdev->last_defer);
	EXPECT_EQ(SKB_DROP_REASON_NO_SOCKET, mock_drop_reasons[mock_num_drop_reasons - 1]);
}

TEST_F(homa_qdisc, homa_qdisc_insert_rb__long_left_chain)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *rpcs[5];
	struct rb_node *node;
	int i;

	for (i = 0; i < ARRAY_SIZE(rpcs); i++) {
		rpcs[i] = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234 + 2 * i);
		ASSERT_NE(NULL, rpcs[i]);
		homa_qdisc_defer_homa(qdev, qdisc_packet(rpcs[i], &self->src, &self->dst,
							4000 + 1000 * i, 500, 0));
	}
	node = rb_first_cached(&qdev->deferred_rpcs);
	for (i = ARRAY_SIZE(rpcs) - 1; i >= 0; i--) {
		ASSERT_NE(NULL, node);
		EXPECT_EQ(&rpcs[i]->qrpc.rb_node, node);
		node = rb_next(node);
	}
	EXPECT_EQ(NULL, node);
}

TEST_F(homa_qdisc, homa_qdisc_insert_rb__long_right_chain)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *rpcs[5];
	struct rb_node *node;
	int i;

	for (i = 0; i < ARRAY_SIZE(rpcs); i++) {
		rpcs[i] = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234 + 2 * i);
		ASSERT_NE(NULL, rpcs[i]);
		homa_qdisc_defer_homa(qdev, qdisc_packet(rpcs[i], &self->src, &self->dst,
							8000 - 1000 * i, 500, 0));
	}
	node = rb_first_cached(&qdev->deferred_rpcs);
	for (i = 0; i < ARRAY_SIZE(rpcs); i++) {
		ASSERT_NE(NULL, node);
		EXPECT_EQ(&rpcs[i]->qrpc.rb_node, node);
		node = rb_next(node);
	}
	EXPECT_EQ(NULL, node);
}

TEST_F(homa_qdisc, homa_qdisc_insert_rb__update_oldest_rpc)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *a = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	struct homa_rpc *b = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1236);
	struct homa_rpc *c = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1238);

	ASSERT_NE(NULL, a);
	ASSERT_NE(NULL, b);
	ASSERT_NE(NULL, c);
	a->msgout.init_time = 10000;
	b->msgout.init_time = 5000;
	c->msgout.init_time = 5001;
	homa_qdisc_defer_homa(qdev, qdisc_packet(a, &self->src, &self->dst, 5000, 500, 0));
	EXPECT_EQ(NULL, qdev->oldest_rpc);
	qdev->oldest_rpc = a;
	homa_qdisc_defer_homa(qdev, qdisc_packet(b, &self->src, &self->dst, 7000, 500, 0));
	EXPECT_EQ(b, qdev->oldest_rpc);
	homa_qdisc_defer_homa(qdev, qdisc_packet(c, &self->src, &self->dst, 3000, 500, 0));
	EXPECT_EQ(b, qdev->oldest_rpc);
}

TEST_F(homa_qdisc, homa_qdisc_get_oldest__cached_scan_and_empty)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *a = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	struct homa_rpc *b = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1236);
	struct homa_rpc *c = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1238);

	ASSERT_NE(NULL, a);
	ASSERT_NE(NULL, b);
	ASSERT_NE(NULL, c);
	EXPECT_EQ(NULL, homa_qdisc_get_oldest(qdev));
	a->msgout.init_time = 5000;
	b->msgout.init_time = 6000;
	c->msgout.init_time = 4000;
	homa_qdisc_defer_homa(qdev, qdisc_packet(a, &self->src, &self->dst, 1000, 500, 0));
	homa_qdisc_defer_homa(qdev, qdisc_packet(b, &self->src, &self->dst, 3000, 500, 0));
	homa_qdisc_defer_homa(qdev, qdisc_packet(c, &self->src, &self->dst, 2000, 500, 0));
	EXPECT_EQ(c, homa_qdisc_get_oldest(qdev));
	c->msgout.init_time = 7000;
	EXPECT_EQ(c, homa_qdisc_get_oldest(qdev));
	qdev->oldest_rpc = NULL;
	EXPECT_EQ(a, homa_qdisc_get_oldest(qdev));
}

TEST_F(homa_qdisc, homa_qdisc_get_deferred_homa__fifo_disabled)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *a = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	struct homa_rpc *b = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1236);
	struct sk_buff *first, *second;

	ASSERT_NE(NULL, a);
	ASSERT_NE(NULL, b);
	a->msgout.init_time = 100;
	b->msgout.init_time = 200;
	first = qdisc_packet(a, &self->src, &self->dst, 0, 500, 0);
	second = qdisc_packet(b, &self->src, &self->dst, 5000, 500, 0);
	homa_qdisc_defer_homa(qdev, first);
	homa_qdisc_defer_homa(qdev, second);
	self->homa.qshared->fifo_fraction = 0;
	qdev->srpt_bytes = -100;
	EXPECT_EQ(second, homa_qdisc_get_deferred_homa(qdev));
	EXPECT_EQ(0, homa_metrics_per_cpu()->pacer_fifo_bytes);
	kfree_skb(second);
	EXPECT_EQ(first, homa_qdisc_get_deferred_homa(qdev));
	kfree_skb(first);
}

TEST_F(homa_qdisc, homa_qdisc_get_deferred_homa__update_tx_left)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *rpc = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);

	ASSERT_NE(NULL, rpc);
	homa_qdisc_defer_homa(qdev, qdisc_packet(rpc, &self->src, &self->dst, 3000, 500, 0));
	homa_qdisc_defer_homa(qdev, qdisc_packet(rpc, &self->src, &self->dst, 4000, 500, 0));
	rpc->qrpc.tx_left = 6000;
	kfree_skb(homa_qdisc_get_deferred_homa(qdev));
	EXPECT_EQ(6000, rpc->qrpc.tx_left);
	kfree_skb(homa_qdisc_get_deferred_homa(qdev));
	EXPECT_EQ(5500, rpc->qrpc.tx_left);
	EXPECT_EQ(NULL, homa_qdisc_get_deferred_homa(qdev));
}

TEST_F(homa_qdisc, homa_qdisc_get_deferred_homa__reposition_rpc_in_rbtree)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *a = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	struct homa_rpc *b = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1236);
	struct sk_buff *first, *second, *third;
	int bytes;

	ASSERT_NE(NULL, a);
	ASSERT_NE(NULL, b);
	a->msgout.init_time = 100;
	b->msgout.init_time = 200;
	first = qdisc_packet(a, &self->src, &self->dst, 0, 1500, 0);
	second = qdisc_packet(a, &self->src, &self->dst, 1500, 1500, 0);
	third = qdisc_packet(b, &self->src, &self->dst, 1000, 1000, 0);
	bytes = qdisc_pkt_len(first);
	homa_qdisc_defer_homa(qdev, first);
	homa_qdisc_defer_homa(qdev, second);
	homa_qdisc_defer_homa(qdev, third);
	EXPECT_EQ(&b->qrpc.rb_node, rb_first_cached(&qdev->deferred_rpcs));
	qdev->oldest_rpc = a;
	qdev->srpt_bytes = -100;
	EXPECT_EQ(first, homa_qdisc_get_deferred_homa(qdev));
	EXPECT_EQ(&a->qrpc.rb_node, rb_first_cached(&qdev->deferred_rpcs));
	EXPECT_EQ(8500, a->qrpc.tx_left);
	EXPECT_EQ(-100 + ((bytes * self->homa.qshared->fifo_weight) >> HOMA_FIFO_WEIGHT_SHIFT),
		  qdev->srpt_bytes);
	EXPECT_EQ(bytes, homa_metrics_per_cpu()->pacer_fifo_bytes);
	kfree_skb(first);
	qdev->oldest_rpc = b;
	qdev->srpt_bytes = -100;
	EXPECT_EQ(third, homa_qdisc_get_deferred_homa(qdev));
	EXPECT_EQ(NULL, qdev->oldest_rpc);
	EXPECT_EQ(second, skb_peek(&a->qrpc.packets));
	kfree_skb(third);
}

TEST_F(homa_qdisc, homa_qdisc_get_deferred_homa__nic_backlog_cycles_metric)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *rpc = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);

	ASSERT_NE(NULL, rpc);
	mock_clock = 5000;
	homa_qdisc_defer_homa(qdev, qdisc_packet(rpc, &self->src, &self->dst, 2000, 500, 0));
	homa_qdisc_defer_homa(qdev, qdisc_packet(rpc, &self->src, &self->dst, 3000, 500, 0));
	mock_clock = 12000;
	kfree_skb(homa_qdisc_get_deferred_homa(qdev));
	EXPECT_EQ(5000, qdev->last_defer);
	EXPECT_EQ(0, homa_metrics_per_cpu()->nic_backlog_cycles);
	mock_clock = 14000;
	kfree_skb(homa_qdisc_get_deferred_homa(qdev));
	EXPECT_EQ(0, qdev->last_defer);
	EXPECT_EQ(9000, homa_metrics_per_cpu()->nic_backlog_cycles);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
}

TEST_F(homa_qdisc, homa_qdisc_flush_rpc__no_qdev)
{
	struct homa_rpc *rpc = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);

	ASSERT_NE(NULL, rpc);
	EXPECT_EQ(NULL, rpc->qrpc.qdev);
	homa_qdisc_flush_rpc(rpc);
	EXPECT_EQ(0, homa_metrics_per_cpu()->qdisc_flushes);
}

TEST_F(homa_qdisc, homa_qdisc_flush_rpc__update_last_defer_and_metrics)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *a = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	struct homa_rpc *b = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1236);

	ASSERT_NE(NULL, a);
	ASSERT_NE(NULL, b);
	mock_clock = 5000;
	homa_qdisc_defer_homa(qdev, qdisc_packet(a, &self->src, &self->dst, 1000, 500, 0));
	homa_qdisc_defer_homa(qdev, qdisc_packet(a, &self->src, &self->dst, 1500, 500, 0));
	homa_qdisc_defer_homa(qdev, qdisc_packet(b, &self->src, &self->dst, 2000, 500, 0));
	qdev->oldest_rpc = a;
	mock_clock = 12000;
	homa_qdisc_flush_rpc(a);
	EXPECT_TRUE(skb_queue_empty(&a->qrpc.packets));
	EXPECT_EQ(NULL, qdev->oldest_rpc);
	EXPECT_EQ(5000, qdev->last_defer);
	EXPECT_EQ(0, homa_metrics_per_cpu()->nic_backlog_cycles);
	EXPECT_EQ(&b->qrpc.rb_node, rb_first_cached(&qdev->deferred_rpcs));
	homa_qdisc_flush_rpc(b);
	EXPECT_EQ(0, qdev->last_defer);
	EXPECT_EQ(7000, homa_metrics_per_cpu()->nic_backlog_cycles);
	EXPECT_EQ(2, homa_metrics_per_cpu()->qdisc_flushes);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
}

TEST_F(homa_qdisc, homa_qdisc_free_homa)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *a = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	struct homa_rpc *b = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1236);

	ASSERT_NE(NULL, a);
	ASSERT_NE(NULL, b);
	EXPECT_EQ(0, homa_qdisc_xmit_deferred_homa(qdev));
	homa_qdisc_defer_homa(qdev, qdisc_packet(a, &self->src, &self->dst, 1000, 500, 0));
	homa_qdisc_defer_homa(qdev, qdisc_packet(b, &self->src, &self->dst, 2000, 500, 0));
	homa_qdisc_free_homa(qdev);
	EXPECT_TRUE(skb_queue_empty(&a->qrpc.packets));
	EXPECT_TRUE(skb_queue_empty(&b->qrpc.packets));
	EXPECT_EQ(NULL, qdev->oldest_rpc);
	EXPECT_EQ(0, qdev->last_defer);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(SKB_DROP_REASON_QUEUE_PURGE, mock_drop_reasons[mock_num_drop_reasons - 1]);
}

TEST_F(homa_qdisc, homa_qdisc_dev_callback)
{
	struct homa_qdisc_dev *qdev = kzalloc(sizeof(*qdev), GFP_KERNEL);
	struct homa_rpc rpc = {};

	ASSERT_NE(NULL, qdev);
	qdev->hnet = self->hnet;
	qdev->nic_queues = kmalloc(2 * sizeof(*qdev->nic_queues), GFP_KERNEL);
	spin_lock_init(&qdev->defer_lock);
	qdev->deferred_rpcs = RB_ROOT_CACHED;
	qdev->last_defer = mock_clock;
	rpc.msgout.length = 10000;
	rpc.qrpc.tx_left = 10000;
	skb_queue_head_init(&rpc.qrpc.packets);
	__skb_queue_tail(&rpc.qrpc.packets,
			 qdisc_packet(NULL, &self->src, &self->dst, 0, 100, 0));
	homa_qdisc_insert_rb(qdev, &rpc);
	homa_qdisc_dev_callback(&qdev->rcu_head);
	EXPECT_TRUE(skb_queue_empty(&rpc.qrpc.packets));
	EXPECT_EQ(SKB_DROP_REASON_QUEUE_PURGE, mock_drop_reasons[mock_num_drop_reasons - 1]);
}

TEST_F(homa_qdisc, homa_qdisc_update_link_idle__cmpxchg_conflicts)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;

	qdev->cycles_per_mibyte = 1 << 20;
	mock_cmpxchg_errors = 0xf;
	EXPECT_EQ(1, homa_qdisc_update_link_idle(qdev, 200, 0));
	EXPECT_EQ(mock_clock + 200 + HOMA_ETH_FRAME_OVERHEAD,
		  atomic64_read(&qdev->link_idle_time));
	EXPECT_EQ(4, homa_metrics_per_cpu()->idle_time_conflicts);
}

TEST_F(homa_qdisc, homa_qdisc_pacer_main)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *rpc = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);

	ASSERT_NE(NULL, rpc);
	sleep_hook_qdev = qdev;
	sleep_hook_skb = qdisc_packet(rpc, &self->src, &self->dst, 1000, 500, 0);
	sleep_hook_count = 10;
	unit_hook_register(qdisc_sleep_hook);
	unit_log_clear();
	EXPECT_EQ(0, homa_qdisc_pacer_main(qdev));
	EXPECT_EQ(0, sleep_hook_count);
	EXPECT_EQ(NULL, sleep_hook_skb);
	EXPECT_SUBSTR("__dev_queue_xmit invoked for id 1234, offset 1000", unit_log_get());
	EXPECT_EQ(1, homa_metrics_per_cpu()->pacer_homa_packets);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
}

TEST_F(homa_qdisc, homa_qdisc_pacer__pacer_already_running)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *rpc = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);

	ASSERT_NE(NULL, rpc);
	homa_qdisc_defer_homa(qdev, qdisc_packet(rpc, &self->src, &self->dst, 0, 1000, 0));
	mock_trylock_errors = 1;
	unit_log_clear();
	EXPECT_EQ(0, homa_qdisc_pacer(qdev));
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, atomic64_read(&qdev->link_idle_time));
	EXPECT_EQ(0, homa_metrics_per_cpu()->pacer_homa_packets);
}

TEST_F(homa_qdisc, homa_qdisc_pacer__nic_queues_overloaded)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *rpc = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	struct sk_buff *skb;
	int bytes;

	ASSERT_NE(NULL, rpc);
	skb = qdisc_packet(rpc, &self->src, &self->dst, 0, 1000, 0);
	bytes = qdisc_pkt_len(skb);
	homa_qdisc_defer_homa(qdev, skb);
	qdev->max_nic_queue_bytes = 1000;
	qdev->nic_queues[1].num_queued = 1010;
	atomic_set(&qdev->nic_queues[1].length, 1010);
	atomic_set(&qdev->total_nic_queue, 1010);
	mock_clock = 1000;
	EXPECT_EQ(0, homa_qdisc_pacer(qdev));
	EXPECT_EQ(1000, qdev->congest_start);
	EXPECT_EQ(1010, atomic_read(&qdev->total_nic_queue));
	EXPECT_EQ(0, homa_metrics_per_cpu()->nic_congest_cycles);
	self->txqs[1].dql.num_completed = 11;
	mock_clock = 4000;
	EXPECT_EQ(bytes, homa_qdisc_pacer(qdev));
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(999, atomic_read(&qdev->total_nic_queue));
	EXPECT_EQ(999, atomic_read(&qdev->nic_queues[1].length));
	EXPECT_EQ(3000, homa_metrics_per_cpu()->nic_congest_cycles);
	EXPECT_EQ(0, qdev->congest_start);
}

TEST_F(homa_qdisc, homa_qdisc_pacer__record_bubble)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;

	self->homa.qshared->max_nic_est_backlog_cycles = 5000;
	atomic64_set(&qdev->link_idle_time, 1000);
	mock_clock = 0;
	EXPECT_EQ(0, homa_qdisc_pacer(qdev));
	EXPECT_EQ(0, homa_metrics_per_cpu()->pacer_bubble_cycles);
	mock_clock = 3000;
	EXPECT_EQ(0, homa_qdisc_pacer(qdev));
	EXPECT_EQ(0, homa_metrics_per_cpu()->pacer_bubble_cycles);
	qdev->unfinished = true;
	EXPECT_EQ(0, homa_qdisc_pacer(qdev));
	EXPECT_EQ(2000, homa_metrics_per_cpu()->pacer_bubble_cycles);
	EXPECT_FALSE(qdev->unfinished);
	EXPECT_EQ(1000, atomic64_read(&qdev->link_idle_time));
}

TEST_F(homa_qdisc, homa_qdisc_pacer__return_after_one_packet)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *a = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	struct homa_rpc *b = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1236);
	struct sk_buff *skb;
	int bytes;

	ASSERT_NE(NULL, a);
	ASSERT_NE(NULL, b);
	skb = qdisc_packet(a, &self->src, &self->dst, 5000, 500, 0);
	bytes = qdisc_pkt_len(skb);
	homa_qdisc_defer_homa(qdev, skb);
	homa_qdisc_defer_homa(qdev, qdisc_packet(b, &self->src, &self->dst, 4000, 500, 0));
	self->homa.qshared->fifo_fraction = 0;
	self->homa.qshared->max_nic_est_backlog_cycles = 100;
	qdev->cycles_per_mibyte = 1 << 20;
	atomic64_set(&qdev->link_idle_time, mock_clock + 100);
	EXPECT_EQ(bytes, homa_qdisc_pacer(qdev));
	EXPECT_TRUE(skb_queue_empty(&a->qrpc.packets));
	EXPECT_EQ(1, skb_queue_len(&b->qrpc.packets));
	EXPECT_EQ(mock_clock + 100 + bytes + HOMA_ETH_FRAME_OVERHEAD,
		  atomic64_read(&qdev->link_idle_time));
	EXPECT_TRUE(qdev->unfinished);
	EXPECT_EQ(1, homa_metrics_per_cpu()->pacer_homa_packets);
}

TEST_F(homa_qdisc, homa_qdisc_pacer__xmit_multiple_packets)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *rpc = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	struct sk_buff *skb;
	int i, bytes = 0;

	ASSERT_NE(NULL, rpc);
	self->homa.qshared->max_nic_est_backlog_cycles = 100000;
	for (i = 0; i < 6; i++) {
		skb = qdisc_packet(rpc, &self->src, &self->dst, i * 500, 500, 0);
		bytes = qdisc_pkt_len(skb);
		homa_qdisc_defer_homa(qdev, skb);
	}
	EXPECT_EQ(5 * bytes, homa_qdisc_pacer(qdev));
	EXPECT_EQ(1, skb_queue_len(&rpc->qrpc.packets));
	EXPECT_TRUE(qdev->unfinished);
	EXPECT_EQ(5, homa_metrics_per_cpu()->pacer_homa_packets);
	EXPECT_EQ(bytes, homa_qdisc_pacer(qdev));
	EXPECT_FALSE(qdev->unfinished);
	EXPECT_EQ(6, homa_metrics_per_cpu()->pacer_homa_packets);
	EXPECT_EQ(6 * bytes, homa_metrics_per_cpu()->pacer_homa_bytes);
}

TEST_F(homa_qdisc, homa_qdisc_xmit_deferred_homa__packet_available)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *rpc = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	struct sk_buff *skb;
	int bytes;

	ASSERT_NE(NULL, rpc);
	skb = qdisc_packet(rpc, &self->src, &self->dst, 0, 1000, 0);
	bytes = qdisc_pkt_len(skb);
	homa_qdisc_defer_homa(qdev, skb);
	qdev->cycles_per_mibyte = 1 << 20;
	unit_log_clear();
	EXPECT_EQ(bytes, homa_qdisc_xmit_deferred_homa(qdev));
	EXPECT_STREQ("__dev_queue_xmit invoked for id 1234, offset 0", unit_log_get());
	EXPECT_EQ(mock_clock + bytes + HOMA_ETH_FRAME_OVERHEAD,
		  atomic64_read(&qdev->link_idle_time));
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(0, homa_qdisc_xmit_deferred_homa(qdev));
}

TEST_F(homa_qdisc, homa_qdisc_pacer_check__enqueue_packet)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_qdisc_dev *other = homa_qdisc_qdev_get(mock_dev(1, &self->homa));
	struct homa_rpc *rpc = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	struct sk_buff *skb;
	int bytes;

	ASSERT_FALSE(IS_ERR(other));
	ASSERT_NE(NULL, rpc);
	skb = qdisc_packet(rpc, &self->src, &self->dst, 0, 1000, 0);
	bytes = qdisc_pkt_len(skb);
	homa_qdisc_defer_homa(qdev, skb);
	self->homa.qshared->max_nic_est_backlog_cycles = 12000;
	atomic64_set(&qdev->link_idle_time, 20000);
	mock_clock = 13000;
	homa_qdisc_pacer_check(&self->homa);
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(1, homa_metrics_per_cpu()->pacer_checks);
	EXPECT_EQ(0, homa_metrics_per_cpu()->pacer_helps);
	mock_clock = 15000;
	homa_qdisc_pacer_check(&self->homa);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(2, homa_metrics_per_cpu()->pacer_checks);
	EXPECT_EQ(1, homa_metrics_per_cpu()->pacer_helps);
	EXPECT_EQ(bytes, homa_metrics_per_cpu()->pacer_help_bytes);
	homa_qdisc_pacer_check(&self->homa);
	EXPECT_EQ(3, homa_metrics_per_cpu()->pacer_checks);
	EXPECT_EQ(1, homa_metrics_per_cpu()->pacer_helps);
	homa_qdisc_qdev_put(other);
}

TEST_F(homa_qdisc, homa_qdisc_refresh_from_dql__basics_and_real_queue_limit)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;

	qdev->nic_queues[0].num_queued = 2000;
	qdev->nic_queues[1].num_queued = 3000;
	atomic_set(&qdev->nic_queues[0].length, 1000);
	atomic_set(&qdev->nic_queues[1].length, 2000);
	atomic_set(&qdev->total_nic_queue, 3000);
	self->txqs[0].dql.num_completed = 1500;
	self->txqs[1].dql.num_completed = 2000;
	self->dev->real_num_tx_queues = 1;
	homa_qdisc_refresh_from_dql(qdev);
	EXPECT_EQ(500, atomic_read(&qdev->nic_queues[0].length));
	EXPECT_EQ(2000, atomic_read(&qdev->nic_queues[1].length));
	EXPECT_EQ(2500, atomic_read(&qdev->total_nic_queue));
	self->dev->real_num_tx_queues = 2;
	homa_qdisc_refresh_from_dql(qdev);
	EXPECT_EQ(1000, atomic_read(&qdev->nic_queues[1].length));
	EXPECT_EQ(1500, atomic_read(&qdev->total_nic_queue));
}

TEST_F(homa_qdisc, homa_qdisc_refresh_from_dql__skip_queue_with_zero_length_in_qdev)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;

	qdev->nic_queues[0].num_queued = 2000;
	qdev->nic_queues[1].num_queued = 2000;
	self->txqs[0].dql.num_completed = 1500;
	self->txqs[1].dql.num_completed = 500;
	atomic_set(&qdev->nic_queues[1].length, 300);
	atomic_set(&qdev->total_nic_queue, 3000);
	homa_qdisc_refresh_from_dql(qdev);
	EXPECT_EQ(0, atomic_read(&qdev->nic_queues[0].length));
	EXPECT_EQ(1500, atomic_read(&qdev->nic_queues[1].length));
	EXPECT_EQ(4200, atomic_read(&qdev->total_nic_queue));
}

TEST_F(homa_qdisc, homa_qdev_update_sysctl__basics)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;

	self->homa.link_mbps = 25000;
	mock_link_mbps = 8000;
	self->homa.qshared->max_link_usage = 90;
	self->homa.qshared->max_nic_queue_usecs = 50;
	qdev->srpt_bytes = -1000;
	homa_qdev_update_sysctl(qdev);
	EXPECT_EQ(8000, qdev->link_mbps);
	EXPECT_EQ(1165084, qdev->cycles_per_mibyte);
	EXPECT_EQ(50000, qdev->max_nic_queue_bytes);
	EXPECT_EQ(0, qdev->srpt_bytes);
}

TEST_F(homa_qdisc, homa_qdev_update_sysctl__cant_get_link_speed_from_dev)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;

	self->homa.link_mbps = 16000;
	mock_link_mbps = 8000;
	mock_ethtool_ksettings_errors = 1;
	homa_qdev_update_sysctl(qdev);
	EXPECT_EQ(16000, qdev->link_mbps);
	EXPECT_EQ(529583, qdev->cycles_per_mibyte);
}

TEST_F(homa_qdisc, homa_qdisc_update_sysctl_deps__fifo_fraction)
{
	struct homa_qdisc_shared *shared = self->homa.qshared;

	shared->fifo_fraction = 500;
	homa_qdisc_update_sysctl_deps(shared);
	EXPECT_EQ(1 << HOMA_FIFO_WEIGHT_SHIFT, shared->fifo_weight);
	shared->fifo_fraction = 200;
	homa_qdisc_update_sysctl_deps(shared);
	EXPECT_EQ(4 * (1 << HOMA_FIFO_WEIGHT_SHIFT), shared->fifo_weight);
	shared->fifo_fraction = 800;
	homa_qdisc_update_sysctl_deps(shared);
	EXPECT_EQ((1 << HOMA_FIFO_WEIGHT_SHIFT) / 4, shared->fifo_weight);
	shared->fifo_fraction = 0;
	shared->fifo_weight = -1;
	homa_qdisc_update_sysctl_deps(shared);
	EXPECT_EQ(-1, shared->fifo_weight);
}

TEST_F(homa_qdisc, homa_qdisc_update_sysctl_deps__max_nic_est_backlog_cycles)
{
	self->homa.qshared->max_nic_est_backlog_usecs = 6;
	homa_qdisc_update_sysctl_deps(self->homa.qshared);
	EXPECT_EQ(6000, self->homa.qshared->max_nic_est_backlog_cycles);
}

TEST_F(homa_qdisc, homa_qdisc_update_sysctl_deps__limit_max_link_usage)
{
	int values[] = {4, 6, 100, 101};
	int expected[] = {5, 6, 100, 100};
	int i;

	for (i = 0; i < ARRAY_SIZE(values); i++) {
		self->homa.qshared->max_link_usage = values[i];
		homa_qdisc_update_sysctl_deps(self->homa.qshared);
		EXPECT_EQ(expected[i], self->homa.qshared->max_link_usage);
	}
}

TEST_F(homa_qdisc, homa_qdisc_update_sysctl_deps__update_all_qdevs)
{
	struct net_device *dev = mock_dev(1, &self->homa);
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_qdisc_dev *other;

	dev->ethtool_ops = NULL;
	self->homa.link_mbps = 16000;
	mock_link_mbps = 40000;
	other = homa_qdisc_qdev_get(dev);
	ASSERT_FALSE(IS_ERR(other));
	homa_qdev_update_sysctl(qdev);
	EXPECT_EQ(40000, qdev->link_mbps);
	EXPECT_EQ(16000, other->link_mbps);
	self->homa.link_mbps = 25000;
	mock_link_mbps = 8000;
	homa_qdisc_update_sysctl_deps(self->homa.qshared);
	EXPECT_EQ(8000, qdev->link_mbps);
	EXPECT_EQ(25000, other->link_mbps);
	EXPECT_EQ(0, other->srpt_bytes);
	homa_qdisc_qdev_put(other);
}

TEST_F(homa_qdisc, homa_qdisc_enqueue__defer_nonlinear_udp_homa_packet)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *rpc = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	struct sk_buff *skb, *to_free = NULL;
	int transport;

	ASSERT_NE(NULL, rpc);
	skb = qdisc_packet(rpc, &self->src, &self->dst, 2000, 2817, 1400);

	/* Like real DATA packets: the first Homa header is linear, while
	 * the rest of the (GSO) buffer is in a fragment.
	 */
	transport = skb_transport_offset(skb);
	qdisc_split_skb(skb, transport + sizeof(struct udphdr) +
			sizeof(struct homa_data_hdr));
	ASSERT_TRUE(skb_is_nonlinear(skb));
	atomic64_set(&qdev->link_idle_time, 1000000);
	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(skb, self->sch[0], &to_free));
	EXPECT_EQ(NULL, to_free);
	EXPECT_EQ(0, self->sch[0]->q.qlen);
	EXPECT_EQ(skb, skb_peek(&rpc->qrpc.packets));
	EXPECT_EQ(transport, skb_transport_offset(skb));
	EXPECT_EQ(8000, rpc->qrpc.tx_left);
	EXPECT_EQ(skb, homa_qdisc_get_deferred_homa(qdev));
	EXPECT_EQ(5183, rpc->qrpc.tx_left);
	kfree_skb(skb);
}

TEST_F(homa_qdisc, homa_qdisc_get_deferred_homa__last_packet_for_rpc)
{
	struct homa_qdisc_dev *qdev = self->q[0]->qdev;
	struct homa_rpc *a = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1234);
	struct homa_rpc *b = qdisc_rpc(&self->hsk, &self->src, &self->dst, 1236);
	struct sk_buff *first;

	ASSERT_NE(NULL, a);
	ASSERT_NE(NULL, b);
	first = qdisc_packet(a, &self->src, &self->dst, 5000, 500, 0);
	homa_qdisc_defer_homa(qdev, first);
	homa_qdisc_defer_homa(qdev, qdisc_packet(b, &self->src, &self->dst, 2000, 500, 0));
	homa_qdisc_defer_homa(qdev, qdisc_packet(b, &self->src, &self->dst, 3000, 500, 0));
	qdev->oldest_rpc = a;
	qdev->srpt_bytes = 1;
	EXPECT_EQ(first, homa_qdisc_get_deferred_homa(qdev));
	EXPECT_TRUE(skb_queue_empty(&a->qrpc.packets));
	EXPECT_EQ(NULL, qdev->oldest_rpc);
	EXPECT_EQ(&b->qrpc.rb_node, rb_first_cached(&qdev->deferred_rpcs));
	EXPECT_EQ(2, skb_queue_len(&b->qrpc.packets));
	kfree_skb(first);
}
