// SPDX-License-Identifier: BSD-2-Clause

#include "homa_impl.h"
#include "homa_pacer.h"
#include "homa_qdisc.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#include <net/pkt_sched.h>

/**
 * new_test_skb() - Create a new skb for use in testing qdisc stuff.
 * The skb will have a small data area plus homa_skb_info and
 * @rpc_name:   Store this as the rpc field in homa_skb_info. This string
 *              will be included in messages generated about the skb.
 * @bytes_left: Store this as the @bytes_left field in homa_skb_info.
 */
static struct sk_buff *new_test_skb(char *rpc_name, int bytes_left)
{
	struct homa_skb_info *info;
	struct sk_buff *skb;

	skb = alloc_skb(100 + sizeof(struct homa_skb_info), GFP_ATOMIC);
	info = homa_get_skb_info(skb);
	info->rpc = rpc_name;
	info->bytes_left = bytes_left;
	return skb;
}

/**
 * log_skb_list() - Print info to the unit test log describing a list of
 * skb's (including sibling sub-lists)a.
 * @list:   List to print out.
 */
void log_skb_list(struct sk_buff_head *list)
{
	struct homa_skb_info *info;
	struct sk_buff *skb;

        skb_queue_walk(list, skb) {
		info = homa_get_skb_info(skb);
		unit_log_printf("; ", "%s:%d", (char *)info->rpc,
				info->bytes_left);
		if (info->next_sibling) {
			struct sk_buff *sibling = info->next_sibling;
			char *separator = " [";

			while (sibling) {
				struct homa_skb_info *sibling_info =
						homa_get_skb_info(sibling);

				unit_log_printf(separator, "%s:%d",
						(char *)sibling_info->rpc,
						sibling_info->bytes_left);
				separator = " ";
				sibling = sibling_info->next_sibling;
			}
			unit_log_printf("", "]");
		}
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
	struct net_device dev;
#define NUM_TXQS 4
	struct netdev_queue txqs[NUM_TXQS];
	struct Qdisc *qdiscs[NUM_TXQS];
	struct ethtool_ops ethtool_ops;
	struct homa_data_hdr data;
};
FIXTURE_SETUP(homa_qdisc)
{
	int i;

	homa_qdisc_register();
	homa_init(&self->homa);
	self->hnet = mock_alloc_hnet(&self->homa);
	self->addr = unit_get_in_addr("1.2.3.4");
	memset(&self->dev, 0, sizeof(self->dev));
	self->dev._tx = self->txqs;
	self->dev.num_tx_queues = NUM_TXQS;
	self->dev.nd_net.net = self->hnet->net;
	self->dev.ethtool_ops = &self->ethtool_ops;
	memset(&self->ethtool_ops, 0, sizeof(self->ethtool_ops));
	self->ethtool_ops.get_link_ksettings = mock_get_link_ksettings;

	memset(&self->txqs, 0, sizeof(self->txqs));
	memset(&self->qdiscs, 0, sizeof(self->qdiscs));
	for (i = 0; i < NUM_TXQS; i++) {
		self->txqs[i].state = 0;
		self->txqs[i].dev = &self->dev;
		self->qdiscs[i] = mock_alloc_qdisc(&self->txqs[i]);
		self->txqs[i].qdisc = self->qdiscs[i];
	}
	mock_net_queue.dev = &mock_net_device;

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

	qdev = homa_qdisc_qdev_get(self->hnet, &mock_net_device);
	EXPECT_FALSE(IS_ERR(qdev));
	EXPECT_EQ(1, qdev->refs);

	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_get__use_existing)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->hnet, &mock_net_device);
	EXPECT_FALSE(IS_ERR(qdev));
	EXPECT_EQ(1, qdev->refs);

	EXPECT_EQ(qdev, homa_qdisc_qdev_get(self->hnet, &mock_net_device));
	EXPECT_EQ(2, qdev->refs);

	homa_qdisc_qdev_put(qdev);
	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_qdev_get__kmalloc_failure)
{
	struct homa_qdisc_dev *qdev;

	mock_kmalloc_errors = 1;
	qdev = homa_qdisc_qdev_get(self->hnet, &mock_net_device);
	EXPECT_TRUE(IS_ERR(qdev));
	EXPECT_EQ(ENOMEM, -PTR_ERR(qdev));
}
TEST_F(homa_qdisc, homa_qdisc_qdev_get__cant_create_thread)
{
	struct homa_qdisc_dev *qdev;

	mock_kthread_create_errors = 1;
	qdev = homa_qdisc_qdev_get(self->hnet, &mock_net_device);
	EXPECT_TRUE(IS_ERR(qdev));
	EXPECT_EQ(EACCES, -PTR_ERR(qdev));
}

TEST_F(homa_qdisc, homa_qdisc_qdev_put)
{
	struct homa_qdisc_dev *qdev, *qdev2;

	qdev = homa_qdisc_qdev_get(self->hnet, &mock_net_device);
	EXPECT_FALSE(IS_ERR(qdev));
	homa_qdisc_qdev_get(self->hnet, &mock_net_device);
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

	qdev = homa_qdisc_qdev_get(self->hnet, &self->dev);

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

TEST_F(homa_qdisc, homa_qdisc_enqueue__defer_homa_packet)
{
	struct Qdisc *qdisc = mock_alloc_qdisc(&mock_net_queue);
	struct sk_buff *skb, *to_free;
	struct homa_qdisc *q;
	u64 idle;

	EXPECT_EQ(0, homa_qdisc_init(qdisc, NULL, NULL));
	q = qdisc_priv(qdisc);
	idle = mock_clock + 1 + self->homa.pacer->max_nic_queue_cycles + 1;
	atomic64_set(&q->qdev->link_idle_time, idle);
	skb = mock_skb_alloc(&self->addr, &self->data.common, 1500, 0);
	qdisc_skb_cb(skb)->pkt_len = 1500;
	to_free = NULL;

	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(skb, qdisc, &to_free));
	EXPECT_EQ(NULL, to_free);
	EXPECT_EQ(1, q->qdev->homa_deferred.qlen);
	EXPECT_STREQ("wake_up_process pid 0", unit_log_get());

	homa_qdisc_destroy(qdisc);
	kfree(qdisc);
}
TEST_F(homa_qdisc, homa_qdisc_enqueue__short_packet)
{
	struct Qdisc *qdisc = mock_alloc_qdisc(&mock_net_queue);
	struct sk_buff *skb, *to_free;
	struct homa_qdisc *q;

	EXPECT_EQ(0, homa_qdisc_init(qdisc, NULL, NULL));
	q = qdisc_priv(qdisc);
	atomic64_set(&q->qdev->link_idle_time, 1000000);
	q->ix = 3;
	skb = mock_skb_alloc(&self->addr, &self->data.common, 100, 0);
	qdisc_skb_cb(skb)->pkt_len = 100;
	to_free = NULL;
	unit_log_clear();

	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(skb, qdisc, &to_free));
	EXPECT_EQ(NULL, to_free);
	EXPECT_EQ(0, q->qdev->homa_deferred.qlen);
	EXPECT_EQ(1, qdisc->q.qlen);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_LT(1000000, atomic64_read(&q->qdev->link_idle_time));

	homa_qdisc_destroy(qdisc);
	kfree(qdisc);
}
TEST_F(homa_qdisc, homa_qdisc_enqueue__packet_not_homa)
{
	struct Qdisc *qdisc = mock_alloc_qdisc(&mock_net_queue);
	struct sk_buff *skb, *to_free;
	struct homa_qdisc *q;

	EXPECT_EQ(0, homa_qdisc_init(qdisc, NULL, NULL));
	q = qdisc_priv(qdisc);
	atomic64_set(&q->qdev->link_idle_time, 1000000);
	q->ix = 3;
	skb = mock_skb_alloc(&self->addr, &self->data.common, 1500, 0);
	qdisc_skb_cb(skb)->pkt_len = 1500;
	if (skb_is_ipv6(skb))
		ipv6_hdr(skb)->nexthdr = IPPROTO_TCP;
	else
		ip_hdr(skb)->protocol = IPPROTO_TCP;
	to_free = NULL;
	unit_log_clear();

	homa_qdisc_enqueue(skb, qdisc, &to_free);
	EXPECT_EQ(NULL, to_free);
	EXPECT_EQ(0, q->qdev->homa_deferred.qlen);
	EXPECT_EQ(1, qdisc->q.qlen);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_LT(1000000, atomic64_read(&q->qdev->link_idle_time));

	homa_qdisc_destroy(qdisc);
	kfree(qdisc);
}
TEST_F(homa_qdisc, homa_qdisc_enqueue__drop_packet_queue_over_limit)
{
	struct Qdisc *qdisc = mock_alloc_qdisc(&mock_net_queue);
	struct sk_buff *skb, *to_free;
	struct homa_qdisc *q;

	EXPECT_EQ(0, homa_qdisc_init(qdisc, NULL, NULL));
	q = qdisc_priv(qdisc);
	q->ix = 3;
	skb = mock_skb_alloc(&self->addr, &self->data.common, 1500, 0);
	qdisc->limit = 1;
	qdisc->q.qlen = 5;
	to_free = NULL;
	unit_log_clear();

	EXPECT_EQ(NET_XMIT_DROP, homa_qdisc_enqueue(skb, qdisc, &to_free));
	ASSERT_NE(NULL, to_free);
	EXPECT_EQ(0, q->qdev->homa_deferred.qlen);
	EXPECT_EQ(5, qdisc->q.qlen);

	kfree_skb(to_free);
	homa_qdisc_destroy(qdisc);
	kfree(qdisc);
}
TEST_F(homa_qdisc, homa_qdisc_enqueue__use_special_queue)
{
	struct sk_buff *skb, *to_free;
	struct homa_qdisc *q;

	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[1], NULL, NULL));
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	q = qdisc_priv(self->qdiscs[1]);
	q->qdev->pacer_qix = 1;
	q->qdev->redirect_qix = 3;
	skb = mock_skb_alloc(&self->addr, &self->data.common, 1500, 0);
	unit_log_clear();

	EXPECT_EQ(NET_XMIT_SUCCESS, homa_qdisc_enqueue(skb, self->qdiscs[1],
						       &to_free));
	ASSERT_NE(NULL, to_free);
	EXPECT_EQ(0, q->qdev->homa_deferred.qlen);
	EXPECT_EQ(0, self->qdiscs[1]->q.qlen);
	EXPECT_EQ(1, self->qdiscs[3]->q.qlen);

	homa_qdisc_destroy(self->qdiscs[1]);
	homa_qdisc_destroy(self->qdiscs[3]);
}

TEST_F(homa_qdisc, homa_qdisc_srpt_enqueue__basics)
{
	struct sk_buff_head list;

	skb_queue_head_init(&list);
	homa_qdisc_srpt_enqueue(&list, new_test_skb("msg1", 1000));
	homa_qdisc_srpt_enqueue(&list, new_test_skb("msg2", 2000));
	homa_qdisc_srpt_enqueue(&list, new_test_skb("msg3", 500));
	homa_qdisc_srpt_enqueue(&list, new_test_skb("msg4", 1000));
	log_skb_list(&list);
	EXPECT_STREQ("msg3:500; msg1:1000; msg4:1000; msg2:2000", unit_log_get());
        homa_qdisc_srpt_free(&list);
}
TEST_F(homa_qdisc, homa_qdisc_srpt_enqueue__multiple_pkts_for_rpc)
{
	struct sk_buff_head list;

	skb_queue_head_init(&list);
	homa_qdisc_srpt_enqueue(&list, new_test_skb("msg1", 1000));
	homa_qdisc_srpt_enqueue(&list, new_test_skb("msg2", 2000));
	homa_qdisc_srpt_enqueue(&list, new_test_skb("msg1", 800));
	homa_qdisc_srpt_enqueue(&list, new_test_skb("msg1", 600));
	homa_qdisc_srpt_enqueue(&list, new_test_skb("msg1", 400));
	log_skb_list(&list);
	EXPECT_STREQ("msg1:1000 [msg1:800 msg1:600 msg1:400]; msg2:2000",
		     unit_log_get());
        homa_qdisc_srpt_free(&list);
}

TEST_F(homa_qdisc, homa_qdisc_srpt_dequeue__list_empty)
{
	struct sk_buff_head list;

	skb_queue_head_init(&list);
	EXPECT_EQ(NULL, homa_qdisc_srpt_dequeue(&list));
}
TEST_F(homa_qdisc, homa_qdisc_srpt_dequeue__no_siblings)
{
	struct sk_buff *skb;
	struct sk_buff_head list;

	skb_queue_head_init(&list);
	skb = new_test_skb("msg1", 1000);
	homa_qdisc_srpt_enqueue(&list, skb);
	homa_qdisc_srpt_enqueue(&list, new_test_skb("msg2", 2000));
	homa_qdisc_srpt_enqueue(&list, new_test_skb("msg3", 3000));
	log_skb_list(&list);
	EXPECT_STREQ("msg1:1000; msg2:2000; msg3:3000", unit_log_get());

	EXPECT_EQ(skb, homa_qdisc_srpt_dequeue(&list));
	unit_log_clear();
	log_skb_list(&list);
	EXPECT_STREQ("msg2:2000; msg3:3000", unit_log_get());
	kfree_skb(skb);
        homa_qdisc_srpt_free(&list);
}
TEST_F(homa_qdisc, homa_qdisc_srpt_dequeue__siblings)
{
	struct sk_buff *skb1, *skb2;
	struct sk_buff_head list;

	skb_queue_head_init(&list);
	skb1 = new_test_skb("msg1", 1000);
	homa_qdisc_srpt_enqueue(&list, skb1);
	skb2 = new_test_skb("msg2", 2000);
	homa_qdisc_srpt_enqueue(&list, skb2);
	homa_qdisc_srpt_enqueue(&list, new_test_skb("msg3", 3000));
	log_skb_list(&list);
	EXPECT_STREQ("msg1:1000; msg2:2000; msg3:3000", unit_log_get());

	EXPECT_EQ(skb1, homa_qdisc_srpt_dequeue(&list));
	unit_log_clear();
	log_skb_list(&list);
	EXPECT_STREQ("msg2:2000; msg3:3000", unit_log_get());
	kfree_skb(skb1);

	EXPECT_EQ(skb2, homa_qdisc_srpt_dequeue(&list));
	unit_log_clear();
	log_skb_list(&list);
	EXPECT_STREQ("msg3:3000", unit_log_get());
	kfree_skb(skb2);
        homa_qdisc_srpt_free(&list);
}

TEST_F(homa_qdisc, homa_qdisc_srpt_free)
{
	struct sk_buff_head list;

	skb_queue_head_init(&list);
	homa_qdisc_srpt_enqueue(&list, new_test_skb("msg1", 500));
	homa_qdisc_srpt_enqueue(&list, new_test_skb("msg2", 1000));
	homa_qdisc_srpt_enqueue(&list, new_test_skb("msg2", 600));
	homa_qdisc_srpt_enqueue(&list, new_test_skb("msg2", 400));
	homa_qdisc_srpt_enqueue(&list, new_test_skb("msg3", 2000));
	log_skb_list(&list);
	EXPECT_STREQ("msg1:500; msg2:1000 [msg2:600 msg2:400]; msg3:2000",
		     unit_log_get());

        homa_qdisc_srpt_free(&list);
	unit_log_clear();
	log_skb_list(&list);
	EXPECT_STREQ("", unit_log_get());
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

TEST_F(homa_qdisc, homa_qdisc_pacer_main__basics)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->hnet, &mock_net_device);
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

	qdev = homa_qdisc_qdev_get(self->hnet, &mock_net_device);
	unit_log_clear();

	homa_qdisc_pacer(qdev);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, atomic64_read(&qdev->link_idle_time));

	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_pacer__enqueue_packet)
{
	struct homa_qdisc_dev *qdev;
	u64 link_idle;

	qdev = homa_qdisc_qdev_get(self->hnet, &self->dev);
	link_idle = atomic64_read(&qdev->link_idle_time);
	homa_qdisc_srpt_enqueue(&qdev->homa_deferred,
				new_test_skb("msg1", 1000));
	EXPECT_EQ(1, qdev->homa_deferred.qlen);
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	qdev->pacer_qix = 3;
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	unit_log_clear();

	homa_qdisc_pacer(qdev);
	EXPECT_EQ(0, qdev->homa_deferred.qlen);
	EXPECT_EQ(1, self->qdiscs[3]->q.qlen);
	EXPECT_LT(link_idle, atomic64_read(&qdev->link_idle_time));

	homa_qdisc_destroy(self->qdiscs[3]);
	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_pacer__pacer_lock_unavailable)
{
	struct homa_qdisc_dev *qdev;
	u64 link_idle;

	qdev = homa_qdisc_qdev_get(self->hnet, &self->dev);
	link_idle = atomic64_read(&qdev->link_idle_time);
	homa_qdisc_srpt_enqueue(&qdev->homa_deferred,
				new_test_skb("msg1", 1000));
	EXPECT_EQ(1, qdev->homa_deferred.qlen);
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	qdev->pacer_qix = 3;
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	unit_log_clear();

	mock_trylock_errors = 1;
	homa_qdisc_pacer(qdev);
	EXPECT_EQ(1, qdev->homa_deferred.qlen);
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	EXPECT_EQ(link_idle, atomic64_read(&qdev->link_idle_time));

	homa_qdisc_destroy(self->qdiscs[3]);
	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_pacer__spin_until_link_idle)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_get(self->hnet, &self->dev);
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	qdev->pacer_qix = 3;
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	homa_qdisc_srpt_enqueue(&qdev->homa_deferred,
				new_test_skb("msg1", 1000));

	mock_clock = 0;
	mock_clock_tick = 1000;
	atomic64_set(&qdev->link_idle_time, 10000);
	self->homa.pacer->max_nic_queue_cycles = 3500;
	unit_log_clear();

	homa_qdisc_pacer(qdev);
	EXPECT_EQ(0, qdev->homa_deferred.qlen);
	EXPECT_EQ(1, self->qdiscs[3]->q.qlen);

	/* Packet will get transmitted when mock_clock ticks to 7000, but
	 * clock ticks once more in homa_qdisc_update_link_idle, then once
	 * in homa_qdisc_pacer before it returns.
	 */
	EXPECT_EQ(9000, mock_clock);

	homa_qdisc_destroy(self->qdiscs[3]);
	homa_qdisc_qdev_put(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_pacer__return_after_one_packet)
{
	struct homa_qdisc_dev *qdev;
	struct sk_buff *skb;

	qdev = homa_qdisc_qdev_get(self->hnet, &self->dev);
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	qdev->pacer_qix = 3;
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);

	skb = new_test_skb("msg1", 1000);
	qdisc_skb_cb(skb)->pkt_len = 1500;
	homa_qdisc_srpt_enqueue(&qdev->homa_deferred, skb);
	skb = new_test_skb("msg2", 1000);
	qdisc_skb_cb(skb)->pkt_len = 1500;
	homa_qdisc_srpt_enqueue(&qdev->homa_deferred, skb);
	EXPECT_EQ(2, qdev->homa_deferred.qlen);

	mock_clock = atomic64_read(&qdev->link_idle_time);
	self->homa.pacer->max_nic_queue_cycles = 100;
	unit_log_clear();

	homa_qdisc_pacer(qdev);
	EXPECT_EQ(1, qdev->homa_deferred.qlen);
	EXPECT_EQ(1, self->qdiscs[3]->q.qlen);
	EXPECT_LT(mock_clock + 100, atomic64_read(&qdev->link_idle_time));

	homa_qdisc_destroy(self->qdiscs[3]);
	homa_qdisc_qdev_put(qdev);
}

TEST_F(homa_qdisc, homa_qdisc_enqueue_special__use_pacer_qix)
{
	struct sk_buff *skb;
	struct homa_qdisc_dev *qdev;
	int status;

	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[1], NULL, NULL));
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	qdev = ((struct homa_qdisc *) qdisc_priv(self->qdiscs[1]))->qdev;
	qdev->pacer_qix = 1;
	qdev->redirect_qix = 3;
	skb = mock_skb_alloc(&self->addr, &self->data.common, 1500, 0);
	unit_log_clear();

	status = homa_qdisc_enqueue_special(skb, qdev, true);
	EXPECT_EQ(NET_XMIT_SUCCESS, status);
	EXPECT_EQ(1, self->qdiscs[1]->q.qlen);
	EXPECT_EQ(0, self->qdiscs[3]->q.qlen);
	EXPECT_EQ(1, mock_netif_schedule_calls);

	homa_qdisc_destroy(self->qdiscs[1]);
	homa_qdisc_destroy(self->qdiscs[3]);
}
TEST_F(homa_qdisc, homa_qdisc_enqueue_special__use_redirect_qix)
{
	struct sk_buff *skb;
	struct homa_qdisc_dev *qdev;
	int status;

	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[1], NULL, NULL));
	EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[3], NULL, NULL));
	qdev = ((struct homa_qdisc *) qdisc_priv(self->qdiscs[1]))->qdev;
	qdev->pacer_qix = 1;
	qdev->redirect_qix = 3;
	skb = mock_skb_alloc(&self->addr, &self->data.common, 1500, 0);
	unit_log_clear();

	status = homa_qdisc_enqueue_special(skb, qdev, false);
	EXPECT_EQ(NET_XMIT_SUCCESS, status);
	EXPECT_EQ(0, self->qdiscs[1]->q.qlen);
	EXPECT_EQ(1, self->qdiscs[3]->q.qlen);

	homa_qdisc_destroy(self->qdiscs[1]);
	homa_qdisc_destroy(self->qdiscs[3]);
}
TEST_F(homa_qdisc, homa_qdisc_enqueue_special__redirect_qix_invalid)
{
	struct sk_buff *skb;
	struct homa_qdisc_dev *qdev;
	int status;
	int i;

	for (i = 0; i < 4; i++)
		EXPECT_EQ(0, homa_qdisc_init(self->qdiscs[i], NULL, NULL));
	qdev = ((struct homa_qdisc *) qdisc_priv(self->qdiscs[0]))->qdev;
	qdev->pacer_qix = 3;
	qdev->redirect_qix = 5;
	skb = mock_skb_alloc(&self->addr, &self->data.common, 1500, 0);
	unit_log_clear();

	status = homa_qdisc_enqueue_special(skb, qdev, false);
	EXPECT_EQ(NET_XMIT_SUCCESS, status);
	EXPECT_EQ(1, self->qdiscs[1]->q.qlen);
	EXPECT_EQ(0, qdev->pacer_qix);
	EXPECT_EQ(1, qdev->redirect_qix);

	for (i = 0; i < 4; i++)
		homa_qdisc_destroy(self->qdiscs[i]);
}
TEST_F(homa_qdisc, homa_qdisc_enqueue_special__redirect_qix_not_a_homa_qdisc)
{
	struct sk_buff *skb;
	struct homa_qdisc_dev *qdev;
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

	status = homa_qdisc_enqueue_special(skb, qdev, false);
	EXPECT_EQ(NET_XMIT_SUCCESS, status);
	EXPECT_EQ(1, self->qdiscs[2]->q.qlen);
	EXPECT_EQ(1, qdev->pacer_qix);
	EXPECT_EQ(2, qdev->redirect_qix);

	for (i = 0; i < 4; i++)
		homa_qdisc_destroy(self->qdiscs[i]);
}
TEST_F(homa_qdisc, homa_qdisc_enqueue_special__no_suitable_qdisc)
{
	struct sk_buff *skb;
	struct homa_qdisc_dev *qdev;
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

	status = homa_qdisc_enqueue_special(skb, qdev, false);
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

	qdev = homa_qdisc_qdev_get(self->hnet, &mock_net_device);
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

	qdev = homa_qdisc_qdev_get(self->hnet, &mock_net_device);
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