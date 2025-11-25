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
	qdisc_skb_cb(skb)->pkt_len = length + 100;
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

static struct homa_qdisc_dev *exit_hook_qdev;
static int exit_hook_count;
static void exit_hook(char *id) {
	if (strcmp(id, "prepare_to_wait") != 0)
		return;
	if (exit_hook_count > 0) {
		exit_hook_count--;
		if (exit_hook_count == 0)
			mock_exit_thread = true;
	}
}

static struct homa_qdisc_dev *defer_hook_qdev;
static struct sk_buff *defer_hook_skb;
static void defer_hook(char *id)
{
	if (strcmp(id, "prepare_to_wait") == 0 && defer_hook_qdev) {
		homa_qdisc_defer_homa(defer_hook_qdev, defer_hook_skb);
		defer_hook_qdev = NULL;
	}
}

static int create_hook_count;
static struct net_device *hook_dev;
static void qdev_create_hook(char *id)
{
	if (strcmp(id, "mutex_lock") != 0)
		return;
	if (create_hook_count <= 0)
		return;
	create_hook_count--;
	if (create_hook_count == 0)
		homa_qdisc_qdev_get(hook_dev);
}

static u64 xmit_clock;
static void xmit_hook(char *id)
{
	if (strcmp(id, "pacer_xmit") != 0)
		return;
	if (xmit_clock == 0)
		xmit_clock = mock_clock;
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

	for (i = 0; i < NUM_TXQS; i++) {
		struct homa_qdisc *q = qdisc_priv(self->qdiscs[i]);
		if (q->qdev)
			homa_qdisc_destroy(self->qdiscs[i]);
		kfree(self->qdiscs[i]);
	}
	homa_destroy(&self->homa);
	homa_qdisc_unregister();
	unit_teardown();
}

TEST_F(homa_qdisc, homa_rcu_kfree__kmalloc_succeeds)
{
	/* Nothing to check in this test; if it fails, test infrastructure
	 * will detect memory alloc-free mismatches.
	 */

	homa_rcu_kfree(kmalloc(100, GFP_KERNEL));
}
TEST_F(homa_qdisc, homa_rcu_kfree__kmalloc_fails)
{
	mock_kmalloc_errors = 2;
	homa_rcu_kfree(kmalloc(100, GFP_KERNEL));
	EXPECT_STREQ("homa_rcu_kfree kmalloc failed", unit_log_get());
}

TEST_F(homa_qdisc, homa_rcu_kfree_callback)
{
	struct homa_rcu_kfreer *freer;

	/* Any errors in freeing will be detected by test infrastructure. */
	freer = kmalloc(sizeof(*freer), GFP_KERNEL);
	freer->object = kmalloc(200, GFP_KERNEL);
	homa_rcu_kfree_callback(&freer->rcu_head);
}

TEST_F(homa_qdisc, homa_qdisc_shared_alloc__success)
{
	struct homa_qdisc_shared *qshared;

	qshared = homa_qdisc_shared_alloc();
	ASSERT_FALSE(IS_ERR(qshared));
	EXPECT_EQ(0, unit_list_length(&qshared->qdevs));
	kfree(qshared);
}
TEST_F(homa_qdisc, homa_qdisc_shared_alloc__kmalloc_failure)
{
	struct homa_qdisc_shared *qshared;

	mock_kmalloc_errors = 1;
	qshared = homa_qdisc_shared_alloc();
	ASSERT_TRUE(IS_ERR(qshared));
	EXPECT_EQ(ENOMEM, -PTR_ERR(qshared));
}
TEST_F(homa_qdisc, homa_qdisc_shared_alloc__cant_register_sysctls)
{
	struct homa_qdisc_shared *qshared;

	mock_register_sysctl_errors = 1;
	qshared = homa_qdisc_shared_alloc();
	ASSERT_TRUE(IS_ERR(qshared));
	EXPECT_EQ(ENOMEM, -PTR_ERR(qshared));
}

TEST_F(homa_qdisc, homa_qdisc_shared_free__basics)
{
	struct homa_qdisc_shared *qshared;

	/* Test infrastructure will report any inconsistencie in
	 * memory allocation.
	 */
	qshared = homa_qdisc_shared_alloc();
	homa_qdisc_shared_free(qshared);
	EXPECT_STREQ("unregister_net_sysctl_table; call_rcu invoked",
		     unit_log_get());
}
TEST_F(homa_qdisc, homa_qdisc_shared_free__unfreed_qdevs)
{
	struct homa_qdisc_shared *qshared, *saved_qshared;
	struct homa_qdisc_dev *qdev;

	qshared = homa_qdisc_shared_alloc();
	saved_qshared = self->homa.qshared;
	self->homa.qshared = qshared;
	qdev = homa_qdisc_qdev_get(self->dev);
	EXPECT_EQ(1, unit_list_length(&qshared->qdevs));
	self->homa.qshared = saved_qshared;
	mock_printk_output[0] = 0;
	homa_qdisc_shared_free(qshared);
	EXPECT_STREQ("homa_qdisc_devs_free found 1 live qdevs "
		     "(should have been none)", mock_printk_output);
	homa_qdisc_qdev_put(qdev);
}

TEST_F(homa_qdisc, homa_qdisc_qdev_get__basics)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->dev);
	EXPECT_FALSE(IS_ERR(qdev));
	EXPECT_EQ(1, refcount_read(&qdev->refs));
	EXPECT_EQ(1, unit_list_length(&self->homa.qshared->qdevs));

	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_get__use_existing)
{
	struct homa_qdisc_dev *qdev, *qdev2;

	/* Arrange for the desired qdev not to be first on this list, to
	 * exercise list traversal.
	 */
	qdev = homa_qdisc_qdev_get(self->dev);
	qdev2 = homa_qdisc_qdev_get(mock_dev(1, &self->homa));

	EXPECT_FALSE(IS_ERR(qdev));
	EXPECT_EQ(2, unit_list_length(&self->homa.qshared->qdevs));
	EXPECT_EQ(1, refcount_read(&qdev->refs));

	EXPECT_EQ(qdev, homa_qdisc_qdev_get(self->dev));
	EXPECT_EQ(2, refcount_read(&qdev->refs));

	homa_qdisc_qdev_put(qdev2);
	homa_qdisc_qdev_put(qdev);
	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_qdev_get__race_when_creating)
{
	struct homa_qdisc_dev *qdev;

	unit_hook_register(qdev_create_hook);
	hook_dev = self->dev;
	create_hook_count = 1;
	unit_log_clear();
	qdev = homa_qdisc_qdev_get(self->dev);
	EXPECT_FALSE(IS_ERR(qdev));
	EXPECT_EQ(1, unit_list_length(&self->homa.qshared->qdevs));
	EXPECT_EQ(2, refcount_read(&qdev->refs));
	EXPECT_SUBSTR("race in homa_qdisc_qdev_get", unit_log_get());

	homa_qdisc_qdev_put(qdev);
	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_qdev_get__kmalloc_failure)
{
	struct homa_qdisc_dev *qdev;

	mock_kmalloc_errors = 1;
	qdev = homa_qdisc_qdev_get(self->dev);
	EXPECT_TRUE(IS_ERR(qdev));
	EXPECT_EQ(ENOMEM, -PTR_ERR(qdev));
}
TEST_F(homa_qdisc, homa_qdisc_qdev_get__cant_create_thread)
{
	struct homa_qdisc_dev *qdev;

	mock_kthread_create_errors = 1;
	qdev = homa_qdisc_qdev_get(self->dev);
	EXPECT_TRUE(IS_ERR(qdev));
	EXPECT_EQ(EACCES, -PTR_ERR(qdev));
}

TEST_F(homa_qdisc, homa_qdisc_qdev_put)
{
	struct homa_qdisc_dev *qdev1, *qdev2, *qdev3;

	qdev1 = homa_qdisc_qdev_get(self->dev);
	EXPECT_FALSE(IS_ERR(qdev1));
	qdev2 = homa_qdisc_qdev_get(mock_dev(1, &self->homa));
	EXPECT_FALSE(IS_ERR(qdev2));
	qdev3 = homa_qdisc_qdev_get(mock_dev(2, &self->homa));
	EXPECT_FALSE(IS_ERR(qdev3));

	EXPECT_EQ(qdev2, homa_qdisc_qdev_get(mock_dev(1, &self->homa)));
	EXPECT_EQ(2, refcount_read(&qdev2->refs));

	/* First call: refcount doesn't hit zero. */
	homa_qdisc_qdev_put(qdev2);
	EXPECT_EQ(1, refcount_read(&qdev2->refs));
	EXPECT_EQ(3, unit_list_length(&self->homa.qshared->qdevs));

	/* Second call: refcount hits zero. */
	homa_qdisc_qdev_put(qdev2);
	EXPECT_EQ(2, unit_list_length(&self->homa.qshared->qdevs));

	homa_qdisc_qdev_put(qdev3);
	homa_qdisc_qdev_put(qdev1);
	EXPECT_EQ(0, unit_list_length(&self->homa.qshared->qdevs));
}

TEST_F(homa_qdisc, homa_qdisc_dev_callback)
{
	struct homa_rpc *srpc1, *srpc2;
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->dev);
	srpc1 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	srpc2 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 2, 10000, 10000);

	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc1, &self->addr, 1000, 1500));
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc2, &self->addr, 2000, 1500));
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1237, offsets 2000]; [id 1235, offsets 1000]",
		     unit_log_get());

	/* If skbs aren't freed, test infrastructure will complain. */
        homa_qdisc_qdev_put(qdev);
	EXPECT_EQ(0, unit_list_length(&self->homa.qshared->qdevs));
}

TEST_F(homa_qdisc, homa_qdisc_init__basics)
{
	struct Qdisc *qdisc = mock_alloc_qdisc(&mock_net_queue);
	struct homa_qdisc_dev *qdev;
	struct homa_qdisc *q;

	EXPECT_EQ(0, homa_qdisc_init(qdisc, NULL, NULL));
	qdev = list_first_or_null_rcu(&self->homa.qshared->qdevs,
				      struct homa_qdisc_dev, links);
	ASSERT_NE(NULL, qdev);
	EXPECT_EQ(1, refcount_read(&qdev->refs));
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

	mock_kmalloc_errors = 1;
	EXPECT_EQ(ENOMEM, -homa_qdisc_init(qdisc, NULL, NULL));
	EXPECT_EQ(0, unit_list_length(&self->homa.qshared->qdevs));
	kfree(qdisc);
}

TEST_F(homa_qdisc, homa_qdisc_destroy)
{
	struct Qdisc *qdisc, *qdisc2;
	struct homa_qdisc_dev *qdev;
	struct homa_qdisc *q, *q2;

	qdisc = mock_alloc_qdisc(&mock_net_queue);
	EXPECT_EQ(0, homa_qdisc_init(qdisc, NULL, NULL));
	q = qdisc_priv(qdisc);
	q->ix = 3;
	qdisc2 = mock_alloc_qdisc(&mock_net_queue);
	EXPECT_EQ(0, homa_qdisc_init(qdisc2, NULL, NULL));
	q2 = qdisc_priv(qdisc2);
	q2->ix = 4;
	qdev = list_first_or_null_rcu(&self->homa.qshared->qdevs,
				      struct homa_qdisc_dev, links);
	EXPECT_NE(NULL, qdev);
	EXPECT_EQ(2, refcount_read(&qdev->refs));

	mock_queue_index = 3;
	homa_qdisc_defer_tcp(q, mock_tcp_skb(&self->addr, 5000, 1000));
	mock_queue_index = 4;
	homa_qdisc_defer_tcp(q, mock_tcp_skb(&self->addr, 6000, 1100));
	mock_queue_index = 3;
	homa_qdisc_defer_tcp(q, mock_tcp_skb(&self->addr, 7000, 1100));

	homa_qdisc_destroy(qdisc);
	EXPECT_EQ(1, refcount_read(&qdev->refs));
	EXPECT_EQ(1, skb_queue_len(&qdev->deferred_tcp));

	homa_qdisc_destroy(qdisc2);
	EXPECT_EQ(0, unit_list_length(&self->homa.qshared->qdevs));
	kfree(qdisc);
	kfree(qdisc2);
}

TEST_F(homa_qdisc, homa_qdisc_enqueue__defer_short_tcp_packet)
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
	mock_queue_index = 3;

	/* First packet is long and gets deferred because of link_idle_time. */
	skb = mock_tcp_skb(&self->addr, 5000, 1500);
	to_free = NULL;
	homa_qdisc_enqueue(skb, qdisc, &to_free);
	EXPECT_EQ(NULL, to_free);
	EXPECT_EQ(1, atomic_read(&q->num_deferred_tcp));
	EXPECT_EQ(1000000, atomic64_read(&q->qdev->link_idle_time));

	/* Second packet is short, but must be deferred to maintain order
	 * within qdisc.
	 */
	skb = mock_tcp_skb(&self->addr, 6000, 500);
	to_free = NULL;
	homa_qdisc_enqueue(skb, qdisc, &to_free);
	EXPECT_EQ(NULL, to_free);
	EXPECT_EQ(2, atomic_read(&q->num_deferred_tcp));
	EXPECT_EQ(1000000, atomic64_read(&q->qdev->link_idle_time));

	homa_qdisc_destroy(qdisc);
	kfree(qdisc);
}
TEST_F(homa_qdisc, homa_qdisc_enqueue__xmit_short_tcp_packet)
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
	skb = mock_tcp_skb(&self->addr, 5000, 500);
	to_free = NULL;
	unit_log_clear();

	homa_qdisc_enqueue(skb, qdisc, &to_free);
	EXPECT_EQ(NULL, to_free);
	EXPECT_FALSE(homa_qdisc_any_deferred(q->qdev));
	EXPECT_EQ(1, qdisc->q.qlen);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_LT(1000000, atomic64_read(&q->qdev->link_idle_time));
	EXPECT_EQ(1, homa_metrics_per_cpu()->qdisc_tcp_packets);

	homa_qdisc_destroy(qdisc);
	kfree(qdisc);
}
TEST_F(homa_qdisc, homa_qdisc_enqueue__defer_tcp_packet_because_of_homa_deferred)
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
	mock_queue_index = 3;

	/* First packet is Homa, gets deferred because of link_idle_time. */
	skb = new_test_skb(srpc, &self->addr, 0, 1500);
	to_free = NULL;
	homa_qdisc_enqueue(skb, qdisc, &to_free);
	EXPECT_EQ(NULL, to_free);
	EXPECT_TRUE(homa_qdisc_any_deferred(q->qdev));
	EXPECT_EQ(1000000, atomic64_read(&q->qdev->link_idle_time));

	/* Second packet is TCP, gets deferred because of deferred Homa
	 * packet.
	 */
	mock_clock = 1000000;
	skb = mock_tcp_skb(&self->addr, 6000, 1500);
	to_free = NULL;
	homa_qdisc_enqueue(skb, qdisc, &to_free);
	EXPECT_EQ(NULL, to_free);
	EXPECT_EQ(1, atomic_read(&q->num_deferred_tcp));
	EXPECT_EQ(1000000, atomic64_read(&q->qdev->link_idle_time));

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
	idle = mock_clock + 1 + self->homa.qshared->max_nic_queue_cycles + 1;
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

TEST_F(homa_qdisc, homa_qdisc_defer_tcp__basics)
{
	struct homa_rpc *srpc;
	struct homa_qdisc *q;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
			       &self->server_ip, self->client_port,
			       self->server_id, 100, 10000);
	ASSERT_NE(NULL, srpc);

	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[2], NULL, NULL));
	q = qdisc_priv(self->qdiscs[2]);
	q->ix = 2;
	mock_queue_index = 2;

	homa_qdisc_defer_tcp(q, mock_tcp_skb(&self->addr, 5000, 1500));
	EXPECT_EQ(1, skb_queue_len(&q->qdev->deferred_tcp));
	EXPECT_EQ(1, atomic_read(&q->num_deferred_tcp));

	homa_qdisc_defer_tcp(q, mock_tcp_skb(&self->addr, 7000, 1500));
	EXPECT_EQ(2, skb_queue_len(&q->qdev->deferred_tcp));
	EXPECT_EQ(2, atomic_read(&q->num_deferred_tcp));
}
TEST_F(homa_qdisc, homa_qdisc_defer_tcp__update_metrics_and_wakeup)
{
	struct homa_rpc *srpc;
	struct homa_qdisc *q;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
			       &self->server_ip, self->client_port,
			       self->server_id, 100, 10000);
	ASSERT_NE(NULL, srpc);
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[2], NULL, NULL));
	q = qdisc_priv(self->qdiscs[2]);
	q->ix = 7;
	mock_queue_index = 7;
	mock_log_wakeups = 1;

	/* First packet: qdev->last_defer is 0. */
	EXPECT_EQ(0, q->qdev->last_defer);
	mock_clock = 5000;
	unit_log_clear();
	homa_qdisc_defer_tcp(q, mock_tcp_skb(&self->addr, 5000, 1500));
	EXPECT_EQ(5000, q->qdev->last_defer);
	EXPECT_EQ(0, homa_metrics_per_cpu()->nic_backlog_cycles);
	EXPECT_STREQ("wake_up", unit_log_get());

	/* Second packet: qdev->last_defer != 0. */
	mock_clock = 15000;
	unit_log_clear();
	homa_qdisc_defer_tcp(q, mock_tcp_skb(&self->addr, 7000, 1500));
	EXPECT_EQ(15000, q->qdev->last_defer);
	EXPECT_EQ(10000, homa_metrics_per_cpu()->nic_backlog_cycles);
	EXPECT_STREQ("", unit_log_get());
}

TEST_F(homa_qdisc, homa_qdisc_defer_homa__basics)
{
	struct homa_rpc *srpc1, *srpc2, *srpc3, *srpc4;
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->dev);
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

	qdev = homa_qdisc_qdev_get(self->dev);
	srpc1 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	srpc2 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 2, 10000, 10000);

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

	qdev = homa_qdisc_qdev_get(self->dev);
	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	srpc->qrpc.tx_left = 2000;

	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 5000, 500));
	EXPECT_EQ(2000, srpc->qrpc.tx_left);
        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_defer_homa__nic_backlog_cycles_metric)
{
	struct homa_rpc *srpc1, *srpc2;
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->dev);
	srpc1 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	srpc2 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 2, 10000, 10000);

	mock_clock = 5000;
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc1, &self->addr, 1000, 1500));
	EXPECT_EQ(5000, qdev->last_defer);
	EXPECT_EQ(0, homa_metrics_per_cpu()->nic_backlog_cycles);

	mock_clock = 12000;
	homa_qdisc_defer_homa(qdev,
			      new_test_skb(srpc2, &self->addr, 2000, 1500));
	EXPECT_EQ(12000, qdev->last_defer);
	EXPECT_EQ(7000, homa_metrics_per_cpu()->nic_backlog_cycles);

        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_defer_homa__wake_up_pacer)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;
	struct sk_buff *skb;

	qdev = homa_qdisc_qdev_get(self->dev);
	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);

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

	qdev = homa_qdisc_qdev_get(self->dev);
	srpc1 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	srpc2 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 2, 10000, 10000);
	srpc3 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 4, 10000, 10000);

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

	qdev = homa_qdisc_qdev_get(self->dev);
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

	qdev = homa_qdisc_qdev_get(self->dev);
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

TEST_F(homa_qdisc, homa_qdisc_xmit_deferred_tcp__basics)
{
	struct homa_qdisc *q;

	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[2], NULL, NULL));
	q = qdisc_priv(self->qdiscs[2]);
	q->ix = 2;
	mock_queue_index = 2;
	homa_qdisc_defer_tcp(q, mock_tcp_skb(&self->addr, 5000, 1000));
	atomic64_set(&q->qdev->link_idle_time, 20000);

	EXPECT_EQ(1100, homa_qdisc_xmit_deferred_tcp(q->qdev));
	EXPECT_EQ(1, self->qdiscs[2]->q.qlen);
	EXPECT_EQ(0, skb_queue_len(&q->qdev->deferred_tcp));
	EXPECT_LT(20000, atomic64_read(&q->qdev->link_idle_time));
}
TEST_F(homa_qdisc, homa_qdisc_xmit_deferred_tcp__no_deferred_packets)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->dev);
	unit_log_clear();
	EXPECT_EQ(0, homa_qdisc_xmit_deferred_tcp(qdev));
	EXPECT_EQ(0, self->qdiscs[2]->q.qlen);
	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_xmit_deferred_tcp__backlog_cycles_metric)
{
	struct homa_qdisc *q1;

	mock_clock = 10000;
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[1], NULL, NULL));
	q1 = qdisc_priv(self->qdiscs[1]);
	q1->ix = 1;
	mock_queue_index = 1;
	homa_qdisc_defer_tcp(q1, mock_tcp_skb(&self->addr, 5000, 1000));
	homa_qdisc_defer_tcp(q1, mock_tcp_skb(&self->addr, 6000, 1100));
	homa_qdisc_defer_tcp(q1, mock_tcp_skb(&self->addr, 6000, 1200));

	mock_clock = 11000;
	EXPECT_EQ(1100, homa_qdisc_xmit_deferred_tcp(q1->qdev));
	EXPECT_EQ(0, homa_metrics_per_cpu()->nic_backlog_cycles);
	mock_clock = 12000;
	EXPECT_EQ(1200, homa_qdisc_xmit_deferred_tcp(q1->qdev));
	EXPECT_EQ(0, homa_metrics_per_cpu()->nic_backlog_cycles);
	mock_clock = 13000;
	EXPECT_EQ(1300, homa_qdisc_xmit_deferred_tcp(q1->qdev));
	EXPECT_EQ(3000, homa_metrics_per_cpu()->nic_backlog_cycles);
	EXPECT_EQ(0, q1->qdev->last_defer);
}
TEST_F(homa_qdisc, homa_qdisc_xmit_deferred_tcp__qdisc_not_homa)
{
	const struct Qdisc_ops *saved_ops;
	struct homa_qdisc *q;

	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[2], NULL, NULL));
	q = qdisc_priv(self->qdiscs[2]);
	q->ix = 2;
	mock_queue_index = 2;
	homa_qdisc_defer_tcp(q, mock_tcp_skb(&self->addr, 5000, 1000));
	saved_ops = self->qdiscs[2]->ops;
	self->qdiscs[2]->ops = NULL;

	EXPECT_EQ(1100, homa_qdisc_xmit_deferred_tcp(q->qdev));
	EXPECT_EQ(0, self->qdiscs[2]->q.qlen);
	EXPECT_EQ(0, skb_queue_len(&q->qdev->deferred_tcp));
	self->qdiscs[2]->ops = saved_ops;
}

TEST_F(homa_qdisc, homa_qdisc_get_deferred_homa__no_deferred_rpcs)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->dev);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));

	EXPECT_EQ(NULL, homa_qdisc_get_deferred_homa(qdev));
        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_get_deferred_homa__multiple_packets_for_rpc)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;
	struct sk_buff *skb;

	qdev = homa_qdisc_qdev_get(self->dev);
	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	skb = new_test_skb(srpc, &self->addr, 2000, 500);
	homa_qdisc_defer_homa(qdev, skb);
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 3000, 500));
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 4000, 500));
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1235, offsets 2000 3000 4000]", unit_log_get());

	EXPECT_EQ(skb, homa_qdisc_get_deferred_homa(qdev));
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1235, offsets 3000 4000]", unit_log_get());
	kfree_skb(skb);
        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_get_deferred_homa__last_packet_for_rpc)
{
	struct homa_rpc *srpc1, *srpc2;
	struct homa_qdisc_dev *qdev;
	struct sk_buff *skb;

	qdev = homa_qdisc_qdev_get(self->dev);
	srpc1 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc1);
	srpc2 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 2, 10000, 10000);
	ASSERT_NE(NULL, srpc2);

	skb = new_test_skb(srpc1, &self->addr, 5000, 500);
	homa_qdisc_defer_homa(qdev, skb);
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc2, &self->addr, 2000,
						 500));
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc2, &self->addr, 3000,
						 500));
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1235, offsets 5000]; [id 1237, offsets 2000 3000]",
		     unit_log_get());

	EXPECT_EQ(skb, homa_qdisc_get_deferred_homa(qdev));
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1237, offsets 2000 3000]", unit_log_get());
	kfree_skb(skb);
        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_get_deferred_homa__update_tx_left)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;

	qdev = homa_qdisc_qdev_get(self->dev);
	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 3000, 500));
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 4000, 500));
	srpc->qrpc.tx_left = 6000;

	/* First packet doesn't update tx_left. */
	kfree_skb(homa_qdisc_get_deferred_homa(qdev));
	EXPECT_EQ(6000, srpc->qrpc.tx_left);

	/* Second packet does update tx_left. */
	kfree_skb(homa_qdisc_get_deferred_homa(qdev));
	EXPECT_EQ(5500, srpc->qrpc.tx_left);

        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_get_deferred_homa__nic_backlog_cycles_metric)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;

	qdev = homa_qdisc_qdev_get(self->dev);
	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	mock_clock = 5000;
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 2000, 500));
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 3000, 500));
	EXPECT_EQ(0, homa_metrics_per_cpu()->nic_backlog_cycles);
	EXPECT_EQ(5000, qdev->last_defer);

	mock_clock = 12000;
	kfree_skb(homa_qdisc_get_deferred_homa(qdev));
	EXPECT_EQ(0, homa_metrics_per_cpu()->nic_backlog_cycles);
	EXPECT_EQ(5000, qdev->last_defer);
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));

	mock_clock = 14000;
	kfree_skb(homa_qdisc_get_deferred_homa(qdev));
	EXPECT_EQ(9000, homa_metrics_per_cpu()->nic_backlog_cycles);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(0, qdev->last_defer);
        homa_qdisc_qdev_put(qdev);
}

TEST_F(homa_qdisc, homa_qdisc_xmit_deferred_homa__no_packets_available)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->dev);
	EXPECT_EQ(0, homa_qdisc_xmit_deferred_homa(qdev));
        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_xmit_deferred_homa__packet_available)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;
	u64 link_idle;

	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	mock_clock = 10000;
	mock_queue_index = 3;
	qdev = homa_qdisc_qdev_get(self->dev);
	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	link_idle = atomic64_read(&qdev->link_idle_time);
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 0, 1000));
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));

	mock_clock = 11000;
	EXPECT_EQ(1100, homa_qdisc_xmit_deferred_homa(qdev));
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(1, self->qdiscs[3]->q.qlen);
	EXPECT_LT(link_idle, atomic64_read(&qdev->link_idle_time));

        homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_xmit_deferred_homa__qdisc_not_homa)
{
	const struct Qdisc_ops *saved_ops;
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;
	u64 link_idle;

	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	mock_clock = 10000;
	mock_queue_index = 3;
	qdev = homa_qdisc_qdev_get(self->dev);
	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	link_idle = atomic64_read(&qdev->link_idle_time);
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 0, 1000));
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));

	mock_clock = 11000;
	saved_ops = self->qdiscs[3]->ops;
	self->qdiscs[3]->ops = NULL;
	EXPECT_EQ(1100, homa_qdisc_xmit_deferred_homa(qdev));
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	EXPECT_LT(link_idle, atomic64_read(&qdev->link_idle_time));
	self->qdiscs[3]->ops = saved_ops;

        homa_qdisc_qdev_put(qdev);
}

TEST_F(homa_qdisc, homa_qdisc_free_homa)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;

	qdev = homa_qdisc_qdev_get(self->dev);
	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

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

TEST_F(homa_qdisc, homa_qdisc_pacer_main)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;

	/* This test checks for two things:
	 * (a) proper handling of deferred packets that arrive while sleeping
	 * (b) proper thread exit
	 */
	qdev = homa_qdisc_qdev_get(self->dev);
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	mock_queue_index = 3;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
			       &self->server_ip, self->client_port,
			       self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	exit_hook_qdev = qdev;
	exit_hook_count = 10;
	unit_hook_register(exit_hook);
	defer_hook_qdev = qdev;
	defer_hook_skb = new_test_skb(srpc, &self->addr, 1000, 500);
	unit_hook_register(defer_hook);

	homa_qdisc_pacer_main(qdev);
	EXPECT_EQ(1, self->qdiscs[3]->q.qlen);
	EXPECT_EQ(1, homa_metrics_per_cpu()->pacer_homa_packets);
	EXPECT_EQ(0, exit_hook_count);

	homa_qdisc_qdev_put(qdev);
}

TEST_F(homa_qdisc, homa_qdisc_pacer__spin_until_link_idle)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;

	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	mock_queue_index = 3;
	qdev = homa_qdisc_qdev_get(self->dev);

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 0, 1000));

	mock_clock = 0;
	mock_clock_tick = 1000;
	atomic64_set(&qdev->link_idle_time, 10000);
	self->homa.qshared->max_nic_queue_cycles = 3500;
	unit_log_clear();
	unit_hook_register(xmit_hook);
	xmit_clock = 0;

	homa_qdisc_pacer(qdev, false);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(1, self->qdiscs[3]->q.qlen);
	EXPECT_EQ(7000, xmit_clock);

	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_pacer__return_after_one_packet)
{
	struct homa_rpc *srpc1, *srpc2;
	struct homa_qdisc_dev *qdev;
	struct sk_buff *skb;

	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	mock_queue_index = 3;

	qdev = homa_qdisc_qdev_get(self->dev);
	srpc1 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc1);
	srpc2 = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id + 2, 10000, 10000);
	ASSERT_NE(NULL, srpc2);

	skb = new_test_skb(srpc1, &self->addr, 5000, 1500);
	homa_qdisc_defer_homa(qdev, skb);
	skb = new_test_skb(srpc2, &self->addr, 4000, 1500);
	homa_qdisc_defer_homa(qdev, skb);
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1235, offsets 5000]; [id 1237, offsets 4000]",
		     unit_log_get());

	mock_clock = atomic64_read(&qdev->link_idle_time);
	self->homa.qshared->max_nic_queue_cycles = 100;
	unit_log_clear();

	homa_qdisc_pacer(qdev, false);
	unit_log_clear();
	log_deferred(qdev);
	EXPECT_STREQ("[id 1237, offsets 4000]", unit_log_get());
	EXPECT_EQ(1, self->qdiscs[3]->q.qlen);
	EXPECT_LT(mock_clock + 100, atomic64_read(&qdev->link_idle_time));

	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_pacer__pacer_lock_unavailable)
{
	struct homa_qdisc_dev *qdev;
	u64 link_idle;
	struct homa_rpc *srpc;

	qdev = homa_qdisc_qdev_get(self->dev);
	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	link_idle = atomic64_read(&qdev->link_idle_time);
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 0, 1000));
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	unit_log_clear();

	mock_trylock_errors = 1;
	homa_qdisc_pacer(qdev, false);
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	EXPECT_EQ(link_idle, atomic64_read(&qdev->link_idle_time));

	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_pacer__no_deferred_packets)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->dev);
	qdev->homa_credit = -1000;

	homa_qdisc_pacer(qdev, false);
	EXPECT_EQ(0, atomic64_read(&qdev->link_idle_time));
	EXPECT_EQ(-1000, qdev->homa_credit);

	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_pacer__xmit_homa_packet_no_tcp)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;

	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	mock_queue_index = 3;
	qdev = homa_qdisc_qdev_get(self->dev);
	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 0, 1000));
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));
	qdev->homa_credit = -100;
	qdev->hnet->homa->qshared->homa_share = 40;

	homa_qdisc_pacer(qdev, false);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(1, self->qdiscs[3]->q.qlen);
	EXPECT_EQ(-65999, qdev->homa_credit);
	EXPECT_EQ(1, homa_metrics_per_cpu()->pacer_homa_packets);
	EXPECT_EQ(1100, homa_metrics_per_cpu()->pacer_homa_bytes);
	EXPECT_EQ(0, homa_metrics_per_cpu()->pacer_help_bytes);

	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_pacer__xmit_tcp_no_homa)
{
	struct homa_qdisc_dev *qdev;
	struct homa_qdisc *q;

	qdev = homa_qdisc_qdev_get(self->dev);
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[2], NULL, NULL));
	q = qdisc_priv(self->qdiscs[2]);
	q->ix = 2;
	mock_queue_index = 2;

	homa_qdisc_defer_tcp(q, mock_tcp_skb(&self->addr, 5000, 1100));
	homa_qdisc_defer_tcp(q, mock_tcp_skb(&self->addr, 5000, 1200));
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));
	qdev->homa_credit = 1000;
	qdev->hnet->homa->qshared->homa_share = 40;

	homa_qdisc_pacer(qdev, false);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(2, self->qdiscs[2]->q.qlen);
	EXPECT_EQ(52000, qdev->homa_credit);
	EXPECT_EQ(2, homa_metrics_per_cpu()->pacer_tcp_packets);
	EXPECT_EQ(2500, homa_metrics_per_cpu()->pacer_tcp_bytes);
	EXPECT_EQ(0, homa_metrics_per_cpu()->pacer_help_bytes);

	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_pacer__both_protocols_have_packets_choose_tcp)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;
	struct homa_qdisc *q;

	qdev = homa_qdisc_qdev_get(self->dev);
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[2], NULL, NULL));
	q = qdisc_priv(self->qdiscs[2]);
	q->ix = 2;
	mock_queue_index = 2;
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 0, 1000));
	homa_qdisc_defer_tcp(q, mock_tcp_skb(&self->addr, 5000, 1100));
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	qdev->homa_credit = -100;
	qdev->hnet->homa->qshared->homa_share = 40;

	/* Arrange for the the NIC queue to exceed its limit once the next
	 * packet is transmitted.
	 */
	atomic64_set(&qdev->link_idle_time, 1000000);
	qdev->hnet->homa->qshared->max_nic_queue_cycles = 10000;
	mock_clock = 1000000 - 10000 + 100;

	homa_qdisc_pacer(qdev, false);
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(1, self->qdiscs[2]->q.qlen);
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	EXPECT_EQ(40*1200 - 100, qdev->homa_credit);
	EXPECT_EQ(1, homa_metrics_per_cpu()->pacer_tcp_packets);
	EXPECT_EQ(1200, homa_metrics_per_cpu()->pacer_tcp_bytes);
	EXPECT_EQ(0, homa_metrics_per_cpu()->pacer_help_bytes);

	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_pacer__xmit_multiple_packets)
{
	struct homa_qdisc_dev *qdev;
	struct homa_qdisc *q;

	qdev = homa_qdisc_qdev_get(self->dev);
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[2], NULL, NULL));
	q = qdisc_priv(self->qdiscs[2]);
	q->ix = 2;
	mock_queue_index = 2;

	homa_qdisc_defer_tcp(q, mock_tcp_skb(&self->addr, 5000, 1100));
	homa_qdisc_defer_tcp(q, mock_tcp_skb(&self->addr, 5000, 1200));
	homa_qdisc_defer_tcp(q, mock_tcp_skb(&self->addr, 5000, 1300));
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));
	qdev->hnet->homa->qshared->homa_share = 40;
	qdev->hnet->homa->qshared->max_nic_queue_cycles = 100000;

	homa_qdisc_pacer(qdev, false);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(3, self->qdiscs[2]->q.qlen);
	EXPECT_EQ(3, homa_metrics_per_cpu()->pacer_tcp_packets);
	EXPECT_EQ(3900, homa_metrics_per_cpu()->pacer_tcp_bytes);
	EXPECT_EQ(0, homa_metrics_per_cpu()->pacer_help_bytes);

	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_pacer__pacer_help_bytes_metric)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;

	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	mock_queue_index = 3;
	qdev = homa_qdisc_qdev_get(self->dev);
	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);

	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 0, 800));
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));
	unit_log_clear();

	homa_qdisc_pacer(qdev, true);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));
	EXPECT_EQ(1, homa_metrics_per_cpu()->pacer_homa_packets);
	EXPECT_EQ(900, homa_metrics_per_cpu()->pacer_homa_bytes);
	EXPECT_EQ(900, homa_metrics_per_cpu()->pacer_help_bytes);

	homa_qdisc_qdev_put(qdev);
}

TEST_F(homa_qdisc, homa_qdisc_pacer_check__enqueue_packet)
{
	struct homa_qdisc_dev *qdev, *qdev2;
	struct homa_rpc *srpc;

	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	mock_queue_index = 3;

	/* Create 2 qdevs to verify that homa_qdisc_pacer_check loops over
	 * all qdevs.
	 */
	qdev2 = homa_qdisc_qdev_get(mock_dev(1, &self->homa));
	qdev = homa_qdisc_qdev_get(self->dev);
	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 0, 1000));
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));

	atomic64_set(&qdev->link_idle_time, 20000);
	mock_clock = 15000;
	self->homa.qshared->max_nic_queue_cycles = 12000;

	homa_qdisc_pacer_check(&self->homa);
	EXPECT_EQ(1, self->qdiscs[3]->q.qlen);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));

	homa_qdisc_qdev_put(qdev);
	homa_qdisc_qdev_put(qdev2);
}
TEST_F(homa_qdisc, homa_qdisc_pacer_check__no_deferred_rpcs)
{
	struct homa_qdisc_dev *qdev, *qdev2;

	/* Create 2 qdevs to verify that homa_qdisc_pacer_check loops over
	 * all qdevs.
	 */
	qdev2 = homa_qdisc_qdev_get(mock_dev(1, &self->homa));
	qdev = homa_qdisc_qdev_get(self->dev);
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);

	atomic64_set(&qdev->link_idle_time, 20000);
	mock_clock = 15000;
	self->homa.qshared->max_nic_queue_cycles = 12000;

	homa_qdisc_pacer_check(&self->homa);
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	EXPECT_FALSE(homa_qdisc_any_deferred(qdev));

	homa_qdisc_qdev_put(qdev);
	homa_qdisc_qdev_put(qdev2);
}
TEST_F(homa_qdisc, homa_qdisc_pacer_check__lag_not_long_enough)
{
	struct homa_qdisc_dev *qdev;
	struct homa_rpc *srpc;

	qdev = homa_qdisc_qdev_get(self->dev);
	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
				&self->server_ip, self->client_port,
				self->server_id, 10000, 10000);
	ASSERT_NE(NULL, srpc);
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	homa_qdisc_defer_homa(qdev, new_test_skb(srpc, &self->addr, 0, 1000));
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));

	atomic64_set(&qdev->link_idle_time, 20000);
	mock_clock = 13000;
	self->homa.qshared->max_nic_queue_cycles = 12000;

	homa_qdisc_pacer_check(&self->homa);
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	EXPECT_TRUE(homa_qdisc_any_deferred(qdev));

	homa_qdisc_qdev_put(qdev);
}

TEST_F(homa_qdisc, homa_qdevc_update_sysctl__basics)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->dev);
	EXPECT_FALSE(IS_ERR(qdev));

	self->homa.link_mbps = 25000;
	mock_link_mbps = 8000;
	self->homa.qshared->max_link_usage = 90;
	homa_qdev_update_sysctl(qdev);
	EXPECT_EQ(8000, qdev->link_mbps);
	EXPECT_EQ(1165084, qdev->cycles_per_mibyte);

	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdev_update_sysctl__cant_get_link_speed_from_dev)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->dev);
	EXPECT_FALSE(IS_ERR(qdev));

	self->homa.link_mbps = 16000;
	mock_link_mbps = 8000;
	mock_ethtool_ksettings_errors = 1;
	homa_qdev_update_sysctl(qdev);
	EXPECT_EQ(16000, qdev->link_mbps);
	EXPECT_EQ(529583, qdev->cycles_per_mibyte);

	homa_qdisc_qdev_put(qdev);
}

TEST_F(homa_qdisc, homa_qdisc_update_sysctl_deps__max_nic_queue_cycles)
{
	self->homa.qshared->max_nic_queue_ns = 6000;
	self->homa.link_mbps = 10000;
	homa_qdisc_update_sysctl_deps(self->homa.qshared);
	EXPECT_EQ(6000, self->homa.qshared->max_nic_queue_cycles);
}
TEST_F(homa_qdisc, homa_qdisc_update_sysctl_deps__limit_homa_share)
{
	self->homa.qshared->homa_share = -1;
	homa_qdisc_update_sysctl_deps(self->homa.qshared);
	EXPECT_EQ(0, self->homa.qshared->homa_share);

	self->homa.qshared->homa_share = 0;
	homa_qdisc_update_sysctl_deps(self->homa.qshared);
	EXPECT_EQ(0, self->homa.qshared->homa_share);

	self->homa.qshared->homa_share = 100;
	homa_qdisc_update_sysctl_deps(self->homa.qshared);
	EXPECT_EQ(100, self->homa.qshared->homa_share);

	self->homa.qshared->homa_share = 101;
	homa_qdisc_update_sysctl_deps(self->homa.qshared);
	EXPECT_EQ(100, self->homa.qshared->homa_share);
}
TEST_F(homa_qdisc, homa_qdisc_update_sysctl_deps__limit_max_link_usage)
{
	self->homa.qshared->max_link_usage = 4;
	homa_qdisc_update_sysctl_deps(self->homa.qshared);
	EXPECT_EQ(5, self->homa.qshared->max_link_usage);

	self->homa.qshared->max_link_usage = 6;
	homa_qdisc_update_sysctl_deps(self->homa.qshared);
	EXPECT_EQ(6, self->homa.qshared->max_link_usage);

	self->homa.qshared->max_link_usage = 100;
	homa_qdisc_update_sysctl_deps(self->homa.qshared);
	EXPECT_EQ(100, self->homa.qshared->max_link_usage);

	self->homa.qshared->max_link_usage = 101;
	homa_qdisc_update_sysctl_deps(self->homa.qshared);
	EXPECT_EQ(100, self->homa.qshared->max_link_usage);
}
TEST_F(homa_qdisc, homa_qdisc_update_sysctl_deps__update_all_qdevs)
{
	struct Qdisc *qdisc = mock_alloc_qdisc(&mock_net_queue);
	struct netdev_queue txq2;
	struct net_device net_device2;
        struct homa_qdisc *q, *q2;
	struct Qdisc *qdisc2;

	/* qdisc has a net device that provides link speed; qdisc2, created
	 * below, has a net device that doesn't provide link speed, so it
	 * uses homa->link_mbps.
	 */
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
	homa_qdisc_update_sysctl_deps(self->homa.qshared);

	EXPECT_EQ(8000, q->qdev->link_mbps);
	EXPECT_EQ(25000, q2->qdev->link_mbps);

	homa_qdisc_destroy(qdisc);
	kfree(qdisc);
	homa_qdisc_destroy(qdisc2);
	kfree(qdisc2);
}

/* Inline functions in homa_qdisc.h: */

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