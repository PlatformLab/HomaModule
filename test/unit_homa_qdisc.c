// SPDX-License-Identifier: BSD-2-Clause

#include "homa_impl.h"
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
	struct Qdisc *qdisc;
};
FIXTURE_SETUP(homa_qdisc)
{
	homa_init(&self->homa);
	self->hnet = mock_alloc_hnet(&self->homa);
	self->qdisc = mock_qdisc_new(&mock_net_queue);
	mock_clock = 10000;
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_qdisc)
{
	kfree(self->qdisc);
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_qdisc, homa_qdisc_init__basics)
{
	struct homa_qdisc_dev *qdev;

	EXPECT_EQ(0, homa_qdisc_init(self->qdisc, NULL, NULL));
	qdev = list_first_entry_or_null(&self->hnet->qdisc_devs,
				        struct homa_qdisc_dev, links);
	ASSERT_NE(NULL, qdev);
	EXPECT_EQ(1, qdev->num_qdiscs);
	EXPECT_EQ(10000, qdev->link_mbps);
	EXPECT_EQ(10240, self->qdisc->limit);
	homa_qdisc_destroy(self->qdisc);
}
TEST_F(homa_qdisc, homa_qdisc_init__cant_create_new_qdisc_dev)
{
	struct homa_qdisc_dev *qdev;

	mock_kmalloc_errors = 1;
	EXPECT_EQ(ENOMEM, -homa_qdisc_init(self->qdisc, NULL, NULL));
	qdev = list_first_entry_or_null(&self->hnet->qdisc_devs,
				        struct homa_qdisc_dev, links);
	EXPECT_EQ(NULL, qdev);
}
TEST_F(homa_qdisc, homa_qdisc_init__existing_qdisc_dev)
{
	struct homa_qdisc_dev *qdev;
	struct Qdisc *sch2;

	EXPECT_EQ(0, homa_qdisc_init(self->qdisc, NULL, NULL));
	qdev = list_first_entry_or_null(&self->hnet->qdisc_devs,
				        struct homa_qdisc_dev, links);
	EXPECT_NE(NULL, qdev);
	EXPECT_EQ(1, qdev->num_qdiscs);

	sch2 = mock_qdisc_new(&mock_net_queue);
	EXPECT_EQ(0, homa_qdisc_init(sch2, NULL, NULL));
	EXPECT_EQ(2, qdev->num_qdiscs);
	homa_qdisc_destroy(sch2);
	kfree(sch2);
	homa_qdisc_destroy(self->qdisc);
}

TEST_F(homa_qdisc, homa_qdisc_qdev_new__success)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_new(self->hnet, &mock_net_device);
	EXPECT_FALSE(IS_ERR(qdev));

	homa_qdisc_qdev_destroy(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_qdev_new__kmalloc_failure)
{
	struct homa_qdisc_dev *qdev;

	mock_kmalloc_errors = 1;
	qdev = homa_qdisc_qdev_new(self->hnet, &mock_net_device);
	EXPECT_TRUE(IS_ERR(qdev));
	EXPECT_EQ(ENOMEM, -PTR_ERR(qdev));
}
TEST_F(homa_qdisc, homa_qdisc_qdev_new__cant_create_thread)
{
	struct homa_qdisc_dev *qdev;

	mock_kthread_create_errors = 1;
	qdev = homa_qdisc_qdev_new(self->hnet, &mock_net_device);
	EXPECT_TRUE(IS_ERR(qdev));
	EXPECT_EQ(EACCES, -PTR_ERR(qdev));
}

TEST_F(homa_qdisc, homa_qdisc_destroy)
{
	struct homa_qdisc_dev *qdev;
	struct Qdisc *sch2;

	EXPECT_EQ(0, homa_qdisc_init(self->qdisc, NULL, NULL));
	sch2 = mock_qdisc_new(&mock_net_queue);
	EXPECT_EQ(0, homa_qdisc_init(sch2, NULL, NULL));
	qdev = list_first_entry_or_null(&self->hnet->qdisc_devs,
				        struct homa_qdisc_dev, links);
	EXPECT_NE(NULL, qdev);
	EXPECT_EQ(2, qdev->num_qdiscs);

	homa_qdisc_destroy(sch2);
	EXPECT_EQ(1, qdev->num_qdiscs);
	kfree(sch2);

	homa_qdisc_destroy(self->qdisc);
	qdev = list_first_entry_or_null(&self->hnet->qdisc_devs,
				        struct homa_qdisc_dev, links);
	EXPECT_EQ(NULL, qdev);
}

TEST_F(homa_qdisc, homa_qdisc_qdev_destroy)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_new(self->hnet, &mock_net_device);
	EXPECT_FALSE(IS_ERR(qdev));

	/* The test infrastructure will warn if these packets aren't all
	 * freed.
	 */
	homa_qdisc_srpt_enqueue(&qdev->homa_deferred, new_test_skb("msg1", 80));
	homa_qdisc_srpt_enqueue(&qdev->homa_deferred, new_test_skb("msg1", 60));
	homa_qdisc_srpt_enqueue(&qdev->tcp_deferred, new_test_skb("msg3", 20));

	homa_qdisc_qdev_destroy(qdev);
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

	qdev = homa_qdisc_qdev_new(self->hnet, &mock_net_device);
	EXPECT_FALSE(IS_ERR(qdev));

	unit_hook_register(pacer_sleep_hook);
	hook_qdev = qdev;
	hook_sleep_count = 3;
	mock_clock_tick = 200;

	homa_qdisc_pacer_main(qdev);
	EXPECT_EQ(400, homa_metrics_per_cpu()->pacer_cycles);

	homa_qdisc_qdev_destroy(qdev);
}

TEST_F(homa_qdisc, homa_qdisc_update_sysctl__basics)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_new(self->hnet, &mock_net_device);
	EXPECT_FALSE(IS_ERR(qdev));

	self->homa.link_mbps = 25000;
	mock_link_mbps = 8000;
	homa_qdisc_update_sysctl(qdev);
	EXPECT_EQ(8000, qdev->link_mbps);
	EXPECT_EQ(1059061, qdev->cycles_per_mibyte);

	homa_qdisc_qdev_destroy(qdev);
}
TEST_F(homa_qdisc, homa_qdisc_update_sysctl__cant_get_link_speed_from_dev)
{
	struct homa_qdisc_dev *qdev;

	qdev = homa_qdisc_qdev_new(self->hnet, &mock_net_device);
	EXPECT_FALSE(IS_ERR(qdev));

	self->homa.link_mbps = 16000;
	mock_link_mbps = 8000;
	mock_ethtool_ksettings_errors = 1;
	homa_qdisc_update_sysctl(qdev);
	EXPECT_EQ(16000, qdev->link_mbps);
	EXPECT_EQ(529530, qdev->cycles_per_mibyte);

	homa_qdisc_qdev_destroy(qdev);
}

TEST_F(homa_qdisc, homa_qdisc_update_all_sysctl)
{
        struct homa_qdisc *q, *q2;
	struct netdev_queue net_queue2;
	struct net_device net_device2;
	struct Qdisc *sch2;

	memset(&net_queue2, 0, sizeof(net_queue2));
	memset(&net_device2, 0, sizeof(net_device2));
	net_queue2.dev = &net_device2;
	net_device2.nd_net.net = &mock_nets[0];
	sch2 = mock_qdisc_new(&net_queue2);
	self->homa.link_mbps = 16000;
	mock_link_mbps = 40000;

	EXPECT_EQ(0, homa_qdisc_init(self->qdisc, NULL, NULL));
	EXPECT_EQ(0, homa_qdisc_init(sch2, NULL, NULL));
	q = qdisc_priv(self->qdisc);
	q2 = qdisc_priv(sch2);
	EXPECT_EQ(40000, q->qdev->link_mbps);
	EXPECT_EQ(16000, q2->qdev->link_mbps);

	self->homa.link_mbps = 25000;
	mock_link_mbps = 8000;
	homa_qdisc_update_all_sysctl(self->hnet);

	EXPECT_EQ(8000, q->qdev->link_mbps);
	EXPECT_EQ(25000, q2->qdev->link_mbps);

	homa_qdisc_destroy(self->qdisc);
	homa_qdisc_destroy(sch2);
	kfree(sch2);
}