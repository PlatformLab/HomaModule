// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

#include "homa_impl.h"
#include "homa_pacer.h"
#include "homa_qdisc.h"
#include "homa_rpc.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#include <net/pkt_sched.h>

/**
 * new_test_skb() - Create a new skb for use in testing qdisc stuff.
 * The skb will have a small data area plus homa_skb_info.
 * @rpc:        RPC that the packet belongs to (stored in the homa_skb_info
 *              for the packet).
 * @saddr:      Source address for packet.
 * @offset:     Offset of packet data within output message.
 * @length:     Number of bytes of message data in packet; also used as
 *              qdisc_skb_cb(skb)->pkt_len.
 */
static struct sk_buff *new_test_skb(struct homa_rpc *rpc,
				    struct in6_addr *saddr, int offset,
				    int length)
{
	struct homa_skb_info *info;
	struct homa_data_hdr data;
	struct sk_buff *skb;

	data.common = (struct homa_common_hdr){
		.sport = htons(rpc->hsk->port),
		.dport = htons(rpc->dport),
		.type = DATA,
		.sender_id = cpu_to_be64(rpc->id)
	};
	data.message_length = htonl(rpc->msgout.length);
	data.seg.offset = htonl(offset);
	skb = mock_skb_alloc(saddr, &data.common,
			     length + sizeof(struct homa_skb_info), 0);
	info = homa_get_skb_info(skb);
	info->rpc = rpc;
	info->data_bytes = length;
	info->offset = offset;
	qdisc_skb_cb(skb)->pkt_len = length;
	return skb;
}

void log_deferred(struct homa_qdisc_dev *qdev)
{
	struct homa_skb_info *info;
	struct rb_node *node;
	struct homa_rpc *rpc;
	struct sk_buff *skb;

	for (node = rb_first_cached(&qdev->deferred_rpcs); node;
	     node = rb_next(node)) {
		rpc = container_of(node, struct homa_rpc, qrpc.rb_node);
		unit_log_printf("; ", "[id %llu, offsets", rpc->id);
        	skb_queue_walk(&rpc->qrpc.packets, skb) {
			info = homa_get_skb_info(skb);
			unit_log_printf(" ", "%d", info->offset);
		}
		unit_log_printf("", "]");
	}
}

static struct homa_qdisc_dev *hook_qdev;
static int hook_sleep_count;
static void pacer_sleep_hook(char *id) {
	if (strcmp(id, "prepare_to_wait") != 0)
		return;
	if (hook_sleep_count > 0) {
		hook_sleep_count--;
		if (hook_sleep_count == 0)
			mock_exit_thread = true;
	}
}

FIXTURE(homa_qdisc) {
	struct homa homa;
	struct homa_net *hnet;
	struct in6_addr addr;
	struct net_device *dev;
#define NUM_TXQS 4
	struct netdev_queue txqs[NUM_TXQS];
	struct Qdisc *qdiscs[NUM_TXQS];
	struct ethtool_ops ethtool_ops;
	struct in6_addr client_ip;
	struct in6_addr server_ip;
	int client_port;
	int server_port;
	u64 client_id;
	u64 server_id;
	struct homa_sock hsk;
	struct homa_data_hdr data;
};
FIXTURE_SETUP(homa_qdisc)
{
	int i;

	homa_qdisc_register();
	homa_init(&self->homa);
	self->hnet = mock_hnet(0, &self->homa);
	self->addr = unit_get_in_addr("1.2.3.4");
	self->dev = mock_dev(0, &self->homa);
	self->dev->_tx = self->txqs;
	self->dev->num_tx_queues = NUM_TXQS;
	self->dev->nd_net.net = mock_net_for_hnet(self->hnet);
	self->dev->ethtool_ops = &self->ethtool_ops;
	memset(&self->ethtool_ops, 0, sizeof(self->ethtool_ops));
	self->ethtool_ops.get_link_ksettings = mock_get_link_ksettings;

	memset(&self->txqs, 0, sizeof(self->txqs));
	memset(&self->qdiscs, 0, sizeof(self->qdiscs));
	for (i = 0; i < NUM_TXQS; i++) {
		self->txqs[i].state = 0;
		self->txqs[i].dev = self->dev;
		self->qdiscs[i] = mock_alloc_qdisc(&self->txqs[i]);
		self->txqs[i].qdisc = self->qdiscs[i];
	}
	mock_net_queue.dev = self->dev;

	self->client_ip = unit_get_in_addr("196.168.0.1");
	self->server_ip = unit_get_in_addr("1.2.3.4");
	self->client_port = 40000;
	self->server_port = 99;
	self->client_id = 1234;
	self->server_id = 1235;
	mock_sock_init(&self->hsk, self->hnet, self->client_port);

	self->data.common = (struct homa_common_hdr){
		.sport = htons(1000),
		.dport = htons(2000),
		.type = DATA,
		.sender_id = cpu_to_be64(100)
	};
	self->data.message_length = htonl(10000);

	mock_clock = 10000;
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_qdisc)
{
	int i;

	for (i = 0; i < NUM_TXQS; i++)
		kfree(self->qdiscs[i]);
	homa_destroy(&self->homa);
	homa_qdisc_unregister();
	unit_teardown();
}

TEST_F(homa_qdisc, homa_qdisc_qdev_get__create_new)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);
	EXPECT_FALSE(IS_ERR(qdev));
	EXPECT_EQ(1, qdev->refs);

	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_get__use_existing)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);
	EXPECT_FALSE(IS_ERR(qdev));
	EXPECT_EQ(1, qdev->refs);

	EXPECT_EQ(qdev, homa_qdisc_qdev_get(self->hnet, self->dev));
	EXPECT_EQ(2, qdev->refs);

	homa_qdisc_qdev_put(qdev);
	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_qdev_get__kmalloc_failure)
{
	struct homa_qdisc_dev *qdev;

	mock_kmalloc_errors = 1;
	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);
	EXPECT_TRUE(IS_ERR(qdev));
	EXPECT_EQ(ENOMEM, -PTR_ERR(qdev));
}
TEST_F(homa_qdisc, homa_qdisc_qdev_get__cant_create_thread)
{
	struct homa_qdisc_dev *qdev;

	mock_kthread_create_errors = 1;
	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);
	EXPECT_TRUE(IS_ERR(qdev));
	EXPECT_EQ(EACCES, -PTR_ERR(qdev));
}

TEST_F(homa_qdisc, homa_qdisc_qdev_put)
{
	struct homa_qdisc_dev *qdev, *qdev2;

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);
	EXPECT_FALSE(IS_ERR(qdev));
	homa_qdisc_qdev_get(self->hnet, self->dev);
	EXPECT_EQ(2, qdev->refs);

	homa_qdisc_qdev_put(qdev);
	EXPECT_EQ(1, qdev->refs);
	qdev2 = list_first_entry_or_null(&self->hnet->qdisc_devs,
				         struct homa_qdisc_dev, links);
	EXPECT_EQ(qdev, qdev2);

	homa_qdisc_qdev_put(qdev);
	qdev2 = list_first_entry_or_null(&self->hnet->qdisc_devs,
				         struct homa_qdisc_dev, links);
	EXPECT_EQ(NULL, qdev2);
}

TEST_F(homa_qdisc, homa_qdisc_init__basics)
{
	struct Qdisc *qdisc = mock_alloc_qdisc(&mock_net_queue);
	struct homa_qdisc_dev *qdev;
	struct homa_qdisc *q;

	EXPECT_EQ(0, homa_qdisc_init(qdisc, NULL, NULL));
	qdev = list_first_entry_or_null(&self->hnet->qdisc_devs,
				        struct homa_qdisc_dev, links);
	ASSERT_NE(NULL, qdev);
	EXPECT_EQ(1, qdev->refs);
	EXPECT_EQ(10000, qdev->link_mbps);
	EXPECT_EQ(10240, qdisc->limit);
	q = qdisc_priv(qdisc);
	EXPECT_EQ(-1, q->ix);
	homa_qdisc_destroy(qdisc);
	kfree(qdisc);
}
TEST_F(homa_qdisc, homa_qdisc_init__cant_create_new_qdisc_dev)
{
	struct Qdisc *qdisc = mock_alloc_qdisc(&mock_net_queue);
	struct homa_qdisc_dev *qdev;

	mock_kmalloc_errors = 1;
	EXPECT_EQ(ENOMEM, -homa_qdisc_init(qdisc, NULL, NULL));
	qdev = list_first_entry_or_null(&self->hnet->qdisc_devs,
				        struct homa_qdisc_dev, links);
	EXPECT_EQ(NULL, qdev);
	kfree(qdisc);
}
TEST_F(homa_qdisc, homa_qdisc_init__set_qix)
{
	struct Qdisc *qdisc = mock_alloc_qdisc(&self->txqs[2]);
	struct homa_qdisc *q;

	EXPECT_EQ(0, homa_qdisc_init(qdisc, NULL, NULL));
	q = qdisc_priv(qdisc);
	EXPECT_EQ(2, q->ix);
	homa_qdisc_destroy(qdisc);
	kfree(qdisc);
}

TEST_F(homa_qdisc, homa_qdisc_destroy)
{
	struct Qdisc *qdisc, *qdisc2;
	struct homa_qdisc_dev *qdev;

	qdisc = mock_alloc_qdisc(&mock_net_queue);
	EXPECT_EQ(0, homa_qdisc_init(qdisc, NULL, NULL));
	qdisc2 = mock_alloc_qdisc(&mock_net_queue);
	EXPECT_EQ(0, homa_qdisc_init(qdisc2, NULL, NULL));
	qdev = list_first_entry_or_null(&self->hnet->qdisc_devs,
				        struct homa_qdisc_dev, links);
	EXPECT_NE(NULL, qdev);
	EXPECT_EQ(2, qdev->refs);

	homa_qdisc_destroy(qdisc2);
	EXPECT_EQ(1, qdev->refs);

	homa_qdisc_destroy(qdisc);
	qdev = list_first_entry_or_null(&self->hnet->qdisc_devs,
				        struct homa_qdisc_dev, links);
	EXPECT_EQ(NULL, qdev);
	kfree(qdisc);
	kfree(qdisc2);
}

TEST_F(homa_qdisc, _homa_qdisc_homa_qdisc_set_qixs_object)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);

	/* Simple working case. */
	homa_qdisc_set_qixs(qdev);
	EXPECT_EQ(0, qdev->pacer_qix);
	EXPECT_EQ(1, qdev->redirect_qix);

	/* No qdisc in devnet_queue. */
	self->txqs[0].qdisc = NULL;
	homa_qdisc_set_qixs(qdev);
	EXPECT_EQ(1, qdev->pacer_qix);
	EXPECT_EQ(2, qdev->redirect_qix);

	/* Qdisc isn't Homa. */
	self->txqs[2].qdisc->ops = NULL;
	homa_qdisc_set_qixs(qdev);
	EXPECT_EQ(1, qdev->pacer_qix);
	EXPECT_EQ(3, qdev->redirect_qix);

	/* Can't find separate qdisc for short_pkt_qix. */
	self->txqs[3].qdisc->ops = NULL;
	homa_qdisc_set_qixs(qdev);
	EXPECT_EQ(1, qdev->pacer_qix);
	EXPECT_EQ(1, qdev->redirect_qix);

	/* Can't find any Homa qdiscs. */
	self->txqs[1].qdisc->ops = NULL;
	homa_qdisc_set_qixs(qdev);
	EXPECT_EQ(-1, qdev->pacer_qix);
	EXPECT_EQ(-1, qdev->redirect_qix);

	homa_qdisc_qdev_put(qdev);
}

TEST_F(homa_qdisc, homa_qdisc_enqueue__packet_not_homa)
{
	struct Qdisc *qdisc = mock_alloc_qdisc(&mock_net_queue);
	struct sk_buff *skb, *to_free;
	struct homa_rpc *srpc;
	struct homa_qdisc *q;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
			       &self->server_ip, self->client_port,
			       self->server_id, 100, 7100);
	ASSERT_NE(NULL, srpc);

	EXPECT_EQ(0, homa_qdisc_init(qdisc, NULL, NULL));
	q = qdisc_priv(qdisc);
	atomic64_set(&q->qdev->link_idle_time, 1000000);
	q->ix = 3;
	skb = new_test_skb(srpc, &self->addr, 0, 1500);
	if (skb_is_ipv6(skb))
		ipv6_hdr(skb)->nexthdr = IPPROTO_TCP;
	else
		ip_hdr(skb)->protocol = IPPROTO_TCP;
	to_free = NULL;
	unit_log_clear();

	homa_qdisc_enqueue(skb, qdisc, &to_free);
	EXPECT_EQ(NULL, to_free);
	EXPECT_FALSE(homa_qdisc_any_deferred(q->qdev));
	EXPECT_EQ(1, qdisc->q.qlen);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_LT(1000000, atomic64_read(&q->qdev->link_idle_time));

	homa_qdisc_destroy(qdisc);
	kfree(qdisc);
}
TEST_F(homa_qdisc, homa_qdisc_enqueue__short_message)
{
	struct Qdisc *qdisc = mock_alloc_qdisc(&mock_net_queue);
	struct sk_buff *skb, *to_free;
	struct homa_rpc *srpc;
	struct homa_qdisc *q;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
			       &self->server_ip, self->client_port,
			       self->server_id, 100, 200);
	ASSERT_NE(NULL, srpc);

	EXPECT_EQ(0, homa_qdisc_init(qdisc, NULL, NULL));
	q = qdisc_priv(qdisc);
	atomic64_set(&q->qdev->link_idle_time, 1000000);
	q->ix = 3;
	skb = new_test_skb(srpc, &self->addr, 0, 200);
	to_free = NULL;
	unit_log_clear();

	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(skb, qdisc, &to_free));
	EXPECT_EQ(NULL, to_free);
	EXPECT_FALSE(homa_qdisc_any_deferred(q->qdev));
	EXPECT_EQ(1, qdisc->q.qlen);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_LT(1000000, atomic64_read(&q->qdev->link_idle_time));

	homa_qdisc_destroy(qdisc);
	kfree(qdisc);
}
TEST_F(homa_qdisc, homa_qdisc_enqueue__short_final_packet_in_long_message)
{
	struct Qdisc *qdisc = mock_alloc_qdisc(&mock_net_queue);
	struct sk_buff *skb, *to_free;
	struct homa_rpc *srpc;
	struct homa_qdisc *q;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
			       &self->server_ip, self->client_port,
			       self->server_id, 100, 7100);
	ASSERT_NE(NULL, srpc);

	EXPECT_EQ(0, homa_qdisc_init(qdisc, NULL, NULL));
	q = qdisc_priv(qdisc);
	atomic64_set(&q->qdev->link_idle_time, 1000000);
	q->ix = 3;
	self->data.message_length = htonl(3000);
	self->data.seg.offset = htonl(2800);
	skb = new_test_skb(srpc, &self->addr, 7000, 100);
	to_free = NULL;
	unit_log_clear();

	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(skb, qdisc, &to_free));
	EXPECT_EQ(NULL, to_free);
	EXPECT_TRUE(homa_qdisc_any_deferred(q->qdev));
	EXPECT_EQ(0, qdisc->q.qlen);

	homa_qdisc_destroy(qdisc);
	kfree(qdisc);
}
TEST_F(homa_qdisc, homa_qdisc_enqueue__defer_homa_packet)
{
	struct Qdisc *qdisc = mock_alloc_qdisc(&mock_net_queue);
	struct sk_buff *skb, *to_free;
	struct homa_rpc *srpc;
	struct homa_qdisc *q;
	u64 idle;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
			       &self->server_ip, self->client_port,
			       self->server_id, 100, 7100);
	ASSERT_NE(NULL, srpc);

	/* First packet is deferred because the NIC queue is full. */
	EXPECT_EQ(0, homa_qdisc_init(qdisc, NULL, NULL));
	q = qdisc_priv(qdisc);
	idle = mock_clock + 1 + self->homa.pacer->max_nic_queue_cycles + 1;
	atomic64_set(&q->qdev->link_idle_time, idle);
	skb = new_test_skb(srpc, &self->addr, 0, 1500);
	to_free = NULL;
	unit_log_clear();
	mock_log_wakeups = 1;

	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(skb, qdisc, &to_free));
	EXPECT_EQ(NULL, to_free);
	EXPECT_TRUE(homa_qdisc_any_deferred(q->qdev));
	EXPECT_STREQ("wake_up", unit_log_get());

	/* Second packet is deferred even though NIC not busy, because
	 * there are other packets waiting.
	 */
	atomic64_set(&q->qdev->link_idle_time, 0);
	self->data.common.sender_id = cpu_to_be64(101);
	skb = new_test_skb(srpc, &self->addr, 1500, 1500);
	to_free = NULL;

	unit_log_clear();
	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(skb, qdisc, &to_free));
	EXPECT_EQ(NULL, to_free);
	log_deferred(q->qdev);
	EXPECT_STREQ("[id 1235, offsets 0 1500]", unit_log_get());

	homa_qdisc_destroy(qdisc);
	kfree(qdisc);
}
TEST_F(homa_qdisc, homa_qdisc_enqueue__drop_packet_queue_over_limit)
{
	struct Qdisc *qdisc = mock_alloc_qdisc(&mock_net_queue);
	struct sk_buff *skb, *to_free;
	struct homa_rpc *srpc;
	struct homa_qdisc *q;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
			       &self->server_ip, self->client_port,
			       self->server_id, 100, 7100);
	ASSERT_NE(NULL, srpc);

	EXPECT_EQ(0, homa_qdisc_init(qdisc, NULL, NULL));
	q = qdisc_priv(qdisc);
	q->ix = 3;
	skb = new_test_skb(srpc, &self->addr, 0, 1500);
	qdisc->limit = 1;
	qdisc->q.qlen = 5;
	to_free = NULL;
	unit_log_clear();

	EXPECT_EQ(NET_XMIT_DROP, homa_qdisc_enqueue(skb, qdisc, &to_free));
	ASSERT_NE(NULL, to_free);
	EXPECT_FALSE(homa_qdisc_any_deferred(q->qdev));
	EXPECT_EQ(5, qdisc->q.qlen);

	kfree_skb(to_free);
	homa_qdisc_destroy(qdisc);
	kfree(qdisc);
}
TEST_F(homa_qdisc, homa_qdisc_enqueue__use_special_queue)
{
	struct sk_buff *skb, *to_free;
	struct homa_rpc *srpc;
	struct homa_qdisc *q;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
			       &self->server_ip, self->client_port,
			       self->server_id, 100, 10000);
	ASSERT_NE(NULL, srpc);

	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[1], NULL, NULL));
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	q = qdisc_priv(self->qdiscs[1]);
	q->qdev->pacer_qix = 1;
	q->qdev->redirect_qix = 3;
	skb = new_test_skb(srpc, &self->addr, 0, 1500);
	unit_log_clear();

	spin_lock(qdisc_lock(self->qdiscs[1]));
	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(skb, self->qdiscs[1],
						       &to_free));
	spin_unlock(qdisc_lock(self->qdiscs[1]));
	ASSERT_NE(NULL, to_free);
	EXPECT_FALSE(homa_qdisc_any_deferred(q->qdev));
	EXPECT_EQ(0, self->qdiscs[1]->q.qlen);
	EXPECT_EQ(1, self->qdiscs[3]->q.qlen);

	homa_qdisc_destroy(self->qdiscs[1]);
	homa_qdisc_destroy(self->qdiscs[3]);
}

TEST_F(homa_qdisc, homa_qdisc_defer_homa__basics)
{
	struct homa_rpc *srpc1, *srpc2, *srpc3, *srpc4;
	struct homa_qdisc_dev *qdev;

	srpc1 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	srpc2 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 2, 10000, 10000);
	srpc3 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 4, 10000, 10000);
	srpc4 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 6, 10000, 10000);

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);

	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc1, &self->addr, 5000, 1500));
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc2, &self->addr, 4000, 1500));
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc3, &self->addr, 8000, 1500));
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc4, &self->addr, 5000, 1500));
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1239, offsets 8000]; "
		     "[id 1235, offsets 5000]; "
		     "[id 1241, offsets 5000]; "
		     "[id 1237, offsets 4000]", unit_log_get());
	EXPECT_EQ(5000, srpc1->qrpc.tx_left);
	EXPECT_EQ(6000, srpc2->qrpc.tx_left);
	EXPECT_EQ(2000, srpc3->qrpc.tx_left);
	EXPECT_EQ(5000, srpc4->qrpc.tx_left);
        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_defer_homa__multiple_pkts_for_rpc)
{
	struct homa_rpc *srpc1, *srpc2;
	struct homa_qdisc_dev *qdev;

	srpc1 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	srpc2 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 2, 10000, 10000);

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);

	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc1, &self->addr, 1000, 1500));
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc2, &self->addr, 2000, 1500));
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc1, &self->addr, 6000, 1500));
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc1, &self->addr, 2500, 1500));
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc1, &self->addr, 4000, 1500));
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1237, offsets 2000]; "
		     "[id 1235, offsets 1000 6000 2500 4000]",
		     unit_log_get());
        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_defer_homa__dont_update_tx_left)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	srpc->qrpc.tx_left = 2000;

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);

	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 5000, 500));
	EXPECT_EQ(2000, srpc->qrpc.tx_left);
        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_defer_homa__throttled_cycles_metric)
{
	struct homa_rpc *srpc1, *srpc2;
	struct homa_qdisc_dev *qdev;

	srpc1 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	srpc2 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 2, 10000, 10000);

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);

	mock_clock = 5000;
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc1, &self->addr, 1000, 1500));
	EXPECT_EQ(5000, qdev->last_defer);
	EXPECT_EQ(0, homa_metrics_per_cpu()->throttled_cycles);

	mock_clock = 12000;
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc2, &self->addr, 2000, 1500));
	EXPECT_EQ(12000, qdev->last_defer);
	EXPECT_EQ(7000, homa_metrics_per_cpu()->throttled_cycles);

        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_defer_homa__wake_up_pacer)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;
	struct sk_buff *skb;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);

	skb = new_test_skb(srpc, &self->addr, 5000, 1500);
	unit_log_clear();
	mock_log_wakeups = 1;
	homa_qdisc_defer_homa(qdev, skb);
	EXPECT_STREQ("wake_up", unit_log_get());
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1235, offsets 5000]", unit_log_get());
        homa_qdisc_qdev_put(qdev);
}

TEST_F(homa_qdisc, homa_qdisc_insert_rb__basics)
{
	struct homa_rpc *srpc1, *srpc2, *srpc3;
	struct homa_qdisc_dev *qdev;

	srpc1 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	srpc2 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 2, 10000, 10000);
	srpc3 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 4, 10000, 10000);

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);

	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc1, &self->addr, 5000, 1500));
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc2, &self->addr, 7000, 1500));
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc3, &self->addr, 3000, 1500));
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1237, offsets 7000]; "
		     "[id 1235, offsets 5000]; "
		     "[id 1239, offsets 3000]",
		     unit_log_get());
        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_insert_rb__long_left_chain)
{
	struct homa_rpc *srpc1, *srpc2, *srpc3, *srpc4;
	struct homa_qdisc_dev *qdev;

	srpc1 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	srpc2 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 2, 10000, 10000);
	srpc3 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 4, 10000, 10000);
	srpc4 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 6, 10000, 10000);

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);

	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc1, &self->addr, 5000, 1500));
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc2, &self->addr, 6000, 1500));
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc3, &self->addr, 7000, 1500));
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc4, &self->addr, 8000, 1500));
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1241, offsets 8000]; "
		     "[id 1239, offsets 7000]; "
		     "[id 1237, offsets 6000]; "
		     "[id 1235, offsets 5000]",
		     unit_log_get());
        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_insert_rb__long_right_chain)
{
	struct homa_rpc *srpc1, *srpc2, *srpc3, *srpc4;
	struct homa_qdisc_dev *qdev;

	srpc1 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	srpc2 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 2, 10000, 10000);
	srpc3 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 4, 10000, 10000);
	srpc4 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id +6 , 10000, 10000);

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);

	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc1, &self->addr, 5000, 1500));
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc2, &self->addr, 4000, 1500));
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc3, &self->addr, 3000, 1500));
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc4, &self->addr, 2000, 1500));
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1235, offsets 5000]; "
		     "[id 1237, offsets 4000]; "
		     "[id 1239, offsets 3000]; "
		     "[id 1241, offsets 2000]",
		     unit_log_get());
        homa_qdisc_qdev_put(qdev);
}

TEST_F(homa_qdisc, homa_qdisc_dequeue_homa__no_deferred_rpcs)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));

	EXPECT_EQ(NULL, homa_qdisc_dequeue_homa(qdev));
        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_dequeue_homa__multiple_packets_for_rpc)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;
	struct sk_buff *skb;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);

	skb = new_test_skb(srpc, &self->addr, 2000, 500);
	homa_qdisc_defer_homa(qdev, skb);
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 3000, 500));
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 4000, 500));
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1235, offsets 2000 3000 4000]", unit_log_get());

	EXPECT_EQ(skb, homa_qdisc_dequeue_homa(qdev));
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1235, offsets 3000 4000]", unit_log_get());
	kfree_skb(skb);
        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_dequeue_homa__last_packet_for_rpc)
{
	struct homa_rpc *srpc1, *srpc2;
	struct homa_qdisc_dev *qdev;
	struct sk_buff *skb;

	srpc1 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc1);
	srpc2 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 2, 10000, 10000);
	ASSERT_NE(NULL, srpc2);

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);

	skb = new_test_skb(srpc1, &self->addr, 5000, 500);
	homa_qdisc_defer_homa(qdev, skb);
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc2, &self->addr, 2000, 500));
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc2, &self->addr, 3000, 500));
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1235, offsets 5000]; [id 1237, offsets 2000 3000]",
		     unit_log_get());

	EXPECT_EQ(skb, homa_qdisc_dequeue_homa(qdev));
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1237, offsets 2000 3000]", unit_log_get());
	kfree_skb(skb);
        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_dequeue_homa__update_tx_left)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);

	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 3000, 500));
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 4000, 500));
	srpc->qrpc.tx_left = 6000;

	/* First packet doesn't update tx_left. */
	kfree_skb(homa_qdisc_dequeue_homa(qdev));
	EXPECT_EQ(6000, srpc->qrpc.tx_left);

	/* Second packet does update tx_left. */
	kfree_skb(homa_qdisc_dequeue_homa(qdev));
	EXPECT_EQ(5500, srpc->qrpc.tx_left);

        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_dequeue_homa__throttled_cycles_metric)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);

	mock_clock = 5000;
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 2000, 500));
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 3000, 500));
	EXPECT_EQ(0, homa_metrics_per_cpu()->throttled_cycles);
	EXPECT_EQ(5000, qdev->last_defer);

	mock_clock = 12000;
	kfree_skb(homa_qdisc_dequeue_homa(qdev));
	EXPECT_EQ(0, homa_metrics_per_cpu()->throttled_cycles);
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));

	kfree_skb(homa_qdisc_dequeue_homa(qdev));
	EXPECT_EQ(7000, homa_metrics_per_cpu()->throttled_cycles);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
        homa_qdisc_qdev_put(qdev);
}

TEST_F(homa_qdisc, homa_qdisc_free_homa)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);

	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 1000, 500));
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 2000, 500));
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 3000, 500));
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 4000, 500));
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 5000, 500));
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1235, offsets 1000 2000 3000 4000 5000]",
		     unit_log_get());

        homa_qdisc_free_homa(qdev);
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("", unit_log_get());
        homa_qdisc_qdev_put(qdev);
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
TEST_F(homa_qdisc, homa_qdisc_update_link_idle__pacer_lost_cycles_metric)
{
	struct homa_qdisc_dev qdev;

	/* qdev->pacer_wake_time < idle */
	mock_clock = 10000;
	memset(&qdev, 0, sizeof(qdev));
	qdev.cycles_per_mibyte = 1 << 20;     /* 1 cycle per byte. */
	atomic64_set(&qdev.link_idle_time, 4000);
	qdev.pacer_wake_time = 2000;

        homa_qdisc_update_link_idle(&qdev, 200, 0);
	EXPECT_EQ(6000, homa_metrics_per_cpu()->pacer_lost_cycles);

	/* qdev->pacer_wake_time > idle */
	atomic64_set(&qdev.link_idle_time, 4000);
	qdev.pacer_wake_time = 8000;

        homa_qdisc_update_link_idle(&qdev, 200, 0);
	EXPECT_EQ(8000, homa_metrics_per_cpu()->pacer_lost_cycles);

	/* pacer_inactive */
	atomic64_set(&qdev.link_idle_time, 4000);
	qdev.pacer_wake_time = 0;

        homa_qdisc_update_link_idle(&qdev, 200, 0);
	EXPECT_EQ(8000, homa_metrics_per_cpu()->pacer_lost_cycles);
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
TEST_F(homa_qdisc, homa_qdisc_update_link_idle__cmpxchg_conflicts)
{
	struct homa_qdisc_dev qdev;

	memset(&qdev, 0, sizeof(qdev));
	qdev.cycles_per_mibyte = 1 << 20;     /* 1 cycle per byte. */
	mock_clock = 1000;
	mock_cmpxchg_errors = 0xf;

	EXPECT_EQ(1, homa_qdisc_update_link_idle(&qdev, 200, 0));
	EXPECT_EQ(1200 + HOMA_ETH_FRAME_OVERHEAD,
		  atomic64_read(&qdev.link_idle_time));
	EXPECT_EQ(4, homa_metrics_per_cpu()->idle_time_conflicts);
}
TEST_F(homa_qdisc, homa_qdisc_update_link_idle__pacer_bytes_metric)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);
	ASSERT_FALSE(IS_ERR(qdev));

	/* No deferred packets. */
        homa_qdisc_update_link_idle(qdev, 200, -1);
	EXPECT_EQ(0, homa_metrics_per_cpu()->pacer_bytes);

	/* Deferred packets. */
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc, &self->addr, 0, 1500));
        homa_qdisc_update_link_idle(qdev, 500, -1);
	EXPECT_EQ(500, homa_metrics_per_cpu()->pacer_bytes);

	homa_qdisc_qdev_put(qdev);
}

TEST_F(homa_qdisc, homa_qdisc_pacer_main__basics)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);
	EXPECT_FALSE(IS_ERR(qdev));

	unit_hook_register(pacer_sleep_hook);
	hook_qdev = qdev;
	hook_sleep_count = 3;
	mock_clock_tick = 200;

	homa_qdisc_pacer_main(qdev);
	EXPECT_EQ(400, homa_metrics_per_cpu()->pacer_cycles);

	homa_qdisc_qdev_put(qdev);
}

TEST_F(homa_qdisc, homa_qdisc_pacer__queue_empty)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);
	unit_log_clear();

	homa_qdisc_pacer(qdev);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, atomic64_read(&qdev->link_idle_time));

	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_pacer__pacer_lock_unavailable)
{
	struct homa_qdisc_dev *qdev;
	u64 link_idle;
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);
	link_idle = atomic64_read(&qdev->link_idle_time);
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 0, 1000));
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	qdev->pacer_qix = 3;
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	unit_log_clear();

	mock_trylock_errors = 1;
	homa_qdisc_pacer(qdev);
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	EXPECT_EQ(link_idle, atomic64_read(&qdev->link_idle_time));

	homa_qdisc_destroy(self->qdiscs[3]);
	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_pacer__enqueue_packet)
{
	struct homa_qdisc_dev *qdev;
	u64 link_idle;
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);
	link_idle = atomic64_read(&qdev->link_idle_time);
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 0, 1000));
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	qdev->pacer_qix = 3;
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	unit_log_clear();

	homa_qdisc_pacer(qdev);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(1, self->qdiscs[3]->q.qlen);
	EXPECT_LT(link_idle, atomic64_read(&qdev->link_idle_time));

	homa_qdisc_destroy(self->qdiscs[3]);
	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_pacer__spin_until_link_idle)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	qdev->pacer_qix = 3;
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 0, 1000));

	mock_clock = 0;
	mock_clock_tick = 1000;
	atomic64_set(&qdev->link_idle_time, 10000);
	self->homa.pacer->max_nic_queue_cycles = 3500;
	unit_log_clear();

	homa_qdisc_pacer(qdev);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(1, self->qdiscs[3]->q.qlen);

	/* Packet will get transmitted when mock_clock ticks to 7000, but
	 * clock ticks once more in homa_qdisc_update_link_idle, then once
	 * in homa_qdisc_dequeue_homa (to update metrics when the queue
	 * empties) and once more in homa_qdisc_pacer before it returns.
	 */
	EXPECT_EQ(10000, mock_clock);

	homa_qdisc_destroy(self->qdiscs[3]);
	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_pacer__return_after_one_packet)
{
	struct homa_rpc *srpc1, *srpc2;
	struct homa_qdisc_dev *qdev;
	struct sk_buff *skb;

	srpc1 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc1);
	srpc2 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 2, 10000, 10000);
	ASSERT_NE(NULL, srpc2);

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	qdev->pacer_qix = 3;
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);

	skb = new_test_skb(srpc1, &self->addr, 5000, 1500);
	homa_qdisc_defer_homa(qdev, skb);
	skb = new_test_skb(srpc2, &self->addr, 4000, 1500);
	homa_qdisc_defer_homa(qdev, skb);
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1235, offsets 5000]; [id 1237, offsets 4000]", unit_log_get());

	mock_clock = atomic64_read(&qdev->link_idle_time);
	self->homa.pacer->max_nic_queue_cycles = 100;
	unit_log_clear();

	homa_qdisc_pacer(qdev);
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1237, offsets 4000]", unit_log_get());
	EXPECT_EQ(1, self->qdiscs[3]->q.qlen);
	EXPECT_LT(mock_clock + 100, atomic64_read(&qdev->link_idle_time));

	homa_qdisc_destroy(self->qdiscs[3]);
	homa_qdisc_qdev_put(qdev);
}

TEST_F(homa_qdisc, homa_qdisc_redirect_skb__use_pacer_qix)
{
	struct homa_qdisc_dev *qdev;
	struct sk_buff *skb;
	int status;

	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[1], NULL, NULL));
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	qdev = ((struct homa_qdisc *) qdisc_priv(self->qdiscs[1]))->qdev;
	qdev->pacer_qix = 1;
	qdev->redirect_qix = 3;
	skb = mock_skb_alloc(&self->addr, &self->data.common, 1500, 0);
	unit_log_clear();

	status = homa_qdisc_redirect_skb(skb, qdev, true);
	EXPECT_EQ(NET_XMIT_SUCCESS, status);
	EXPECT_EQ(1, self->qdiscs[1]->q.qlen);
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	EXPECT_EQ(1, mock_netif_schedule_calls);

	homa_qdisc_destroy(self->qdiscs[1]);
	homa_qdisc_destroy(self->qdiscs[3]);
}
TEST_F(homa_qdisc, homa_qdisc_redirect_skb__use_redirect_qix)
{
	struct homa_qdisc_dev *qdev;
	struct sk_buff *skb;
	int status;

	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[1], NULL, NULL));
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	qdev = ((struct homa_qdisc *) qdisc_priv(self->qdiscs[1]))->qdev;
	qdev->pacer_qix = 1;
	qdev->redirect_qix = 3;
	skb = mock_skb_alloc(&self->addr, &self->data.common, 1500, 0);
	unit_log_clear();

	status = homa_qdisc_redirect_skb(skb, qdev, false);
	EXPECT_EQ(NET_XMIT_SUCCESS, status);
	EXPECT_EQ(0, self->qdiscs[1]->q.qlen);
	EXPECT_EQ(1, self->qdiscs[3]->q.qlen);

	homa_qdisc_destroy(self->qdiscs[1]);
	homa_qdisc_destroy(self->qdiscs[3]);
}
TEST_F(homa_qdisc, homa_qdisc_redirect_skb__redirect_qix_invalid)
{
	struct homa_qdisc_dev *qdev;
	struct sk_buff *skb;
	int status;
	int i;

	for (i = 0; i < 4; i++)
		EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[i], NULL, NULL));
	qdev = ((struct homa_qdisc *) qdisc_priv(self->qdiscs[0]))->qdev;
	qdev->pacer_qix = 3;
	qdev->redirect_qix = 5;
	skb = mock_skb_alloc(&self->addr, &self->data.common, 1500, 0);
	unit_log_clear();

	status = homa_qdisc_redirect_skb(skb, qdev, false);
	EXPECT_EQ(NET_XMIT_SUCCESS, status);
	EXPECT_EQ(1, self->qdiscs[1]->q.qlen);
	EXPECT_EQ(0, qdev->pacer_qix);
	EXPECT_EQ(1, qdev->redirect_qix);

	for (i = 0; i < 4; i++)
		homa_qdisc_destroy(self->qdiscs[i]);
}
TEST_F(homa_qdisc, homa_qdisc_redirect_skb__redirect_qix_not_a_homa_qdisc)
{
	struct homa_qdisc_dev *qdev;
	struct sk_buff *skb;
	int status;
	int i;

	for (i = 0; i < 4; i++)
		EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[i], NULL, NULL));
	qdev = ((struct homa_qdisc *) qdisc_priv(self->qdiscs[0]))->qdev;
	qdev->pacer_qix = 3;
	qdev->redirect_qix = 0;
	self->qdiscs[0]->ops = NULL;
	skb = mock_skb_alloc(&self->addr, &self->data.common, 1500, 0);
	unit_log_clear();

	status = homa_qdisc_redirect_skb(skb, qdev, false);
	EXPECT_EQ(NET_XMIT_SUCCESS, status);
	EXPECT_EQ(1, self->qdiscs[2]->q.qlen);
	EXPECT_EQ(1, qdev->pacer_qix);
	EXPECT_EQ(2, qdev->redirect_qix);

	for (i = 0; i < 4; i++)
		homa_qdisc_destroy(self->qdiscs[i]);
}
TEST_F(homa_qdisc, homa_qdisc_redirect_skb__no_suitable_qdisc)
{
	struct homa_qdisc_dev *qdev;
	struct sk_buff *skb;
	int status;
	int i;

	for (i = 0; i < 4; i++) {
		EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[i], NULL, NULL));
		self->qdiscs[i]->ops = NULL;
	}
	qdev = ((struct homa_qdisc *) qdisc_priv(self->qdiscs[0]))->qdev;
	qdev->pacer_qix = 3;
	qdev->redirect_qix = 0;
	skb = mock_skb_alloc(&self->addr, &self->data.common, 1500, 0);
	unit_log_clear();

	status = homa_qdisc_redirect_skb(skb, qdev, false);
	EXPECT_EQ(NET_XMIT_DROP, status);
	EXPECT_EQ(-1, qdev->pacer_qix);
	EXPECT_EQ(-1, qdev->redirect_qix);
	EXPECT_EQ(0, mock_netif_schedule_calls);

	for (i = 0; i < 4; i++)
		homa_qdisc_destroy(self->qdiscs[i]);
}

TEST_F(homa_qdisc, homa_qdisc_update_sysctl__basics)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);
	EXPECT_FALSE(IS_ERR(qdev));

	self->homa.link_mbps = 25000;
	mock_link_mbps = 8000;
	homa_qdisc_update_sysctl(qdev);
	EXPECT_EQ(8000, qdev->link_mbps);
	EXPECT_EQ(1059061, qdev->cycles_per_mibyte);

	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_update_sysctl__cant_get_link_speed_from_dev)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->hnet, self->dev);
	EXPECT_FALSE(IS_ERR(qdev));

	self->homa.link_mbps = 16000;
	mock_link_mbps = 8000;
	mock_ethtool_ksettings_errors = 1;
	homa_qdisc_update_sysctl(qdev);
	EXPECT_EQ(16000, qdev->link_mbps);
	EXPECT_EQ(529530, qdev->cycles_per_mibyte);

	homa_qdisc_qdev_put(qdev);
}

TEST_F(homa_qdisc, homa_qdisc_update_all_sysctl)
{
	struct Qdisc *qdisc = mock_alloc_qdisc(&mock_net_queue);
	struct netdev_queue txq2;
	struct net_device net_device2;
        struct homa_qdisc *q, *q2;
	struct Qdisc *qdisc2;

	memset(&txq2, 0, sizeof(txq2));
	memset(&net_device2, 0, sizeof(net_device2));
	txq2.dev = &net_device2;
	net_device2.nd_net.net = &mock_nets[0];
	qdisc2 = mock_alloc_qdisc(&txq2);

	self->homa.link_mbps = 16000;
	mock_link_mbps = 40000;

	EXPECT_EQ(0, homa_qdisc_init(qdisc, NULL, NULL));
	EXPECT_EQ(0, homa_qdisc_init(qdisc2, NULL, NULL));
	q = qdisc_priv(qdisc);
	q2 = qdisc_priv(qdisc2);
	EXPECT_EQ(40000, q->qdev->link_mbps);
	EXPECT_EQ(16000, q2->qdev->link_mbps);

	self->homa.link_mbps = 25000;
	mock_link_mbps = 8000;
	homa_qdisc_update_all_sysctl(self->hnet);

	EXPECT_EQ(8000, q->qdev->link_mbps);
	EXPECT_EQ(25000, q2->qdev->link_mbps);

	homa_qdisc_destroy(qdisc);
	kfree(qdisc);
	homa_qdisc_destroy(qdisc2);
	kfree(qdisc2);
}

TEST_F(homa_qdisc, homa_qdisc_precedes__bytes_left)
{
	struct homa_rpc *srpc1, *srpc2, *srpc3;

	srpc1 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	srpc2 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 2, 10000, 10000);
	srpc3 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 4, 10000, 10000);

	srpc1->qrpc.tx_left = 5000;
	srpc2->qrpc.tx_left = 3000;
	srpc3->qrpc.tx_left = 7000;
	EXPECT_EQ(0, homa_qdisc_precedes(srpc1, srpc2));
	EXPECT_EQ(1, homa_qdisc_precedes(srpc1, srpc3));
}
TEST_F(homa_qdisc, homa_qdisc_precedes__init_time)
{
	struct homa_rpc *srpc1, *srpc2, *srpc3;

	srpc1 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	srpc1->msgout.init_time = 1000;
	srpc2 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 2, 10000, 10000);
	srpc2->msgout.init_time = 500;
	srpc3 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 4, 10000, 10000);
	srpc3->msgout.init_time = 2000;

	EXPECT_EQ(0, homa_qdisc_precedes(srpc1, srpc2));
	EXPECT_EQ(1, homa_qdisc_precedes(srpc1, srpc3));
}
TEST_F(homa_qdisc, homa_qdisc_precedes__rpc_struct_address)
{
	struct homa_rpc *srpc1, *srpc2, *srpc3;
	int result;

	srpc1 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	srpc2 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 2, 10000, 10000);
	srpc3 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 4, 10000, 10000);

	if (srpc1 > srpc2)
		result = homa_qdisc_precedes(srpc1, srpc2);
	else
		result = homa_qdisc_precedes(srpc2, srpc1);
	EXPECT_EQ(0, result);
	if (srpc1 < srpc3)
		result = homa_qdisc_precedes(srpc1, srpc3);
	else
		result = homa_qdisc_precedes(srpc3, srpc1);
	EXPECT_EQ(1, result);
}