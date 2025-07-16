/* SPDX-License-Identifier: BSD-2-Clause */

/* This file contains definitions related to Homa's special-purpose
 * queuing discipline
 */

#ifdef __UNIT_TEST__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif /* __UNIT_TEST__*/
#include <net/sch_generic.h>
#ifdef __UNIT_TEST__
#pragma GCC diagnostic pop
#endif /* __UNIT_TEST__*/

#ifndef _HOMA_QDISC_H
#define _HOMA_QDISC_H

/**
 * struct homa_qdisc - Contains Homa-specific data for a single instance of
 * the homa queuing discipline
 */
struct homa_qdisc {
	/** @dev: Info shared among all qdiscs for a net_device. */
	struct homa_qdisc_dev *qdev;

	/** @queue: Packets waiting to be transmitted. */
	struct sk_buff_head queue;
};

/**
 * struct homa_qdisc_dev - Contains information shared across all of the
 * homa_qdiscs associated with a net_device.
 */
struct homa_qdisc_dev {
	/** @dev: Device common to all qdiscs using this struct. */
	struct net_device *dev;

	/**
	 * @homa_net: Homa's information about the network namesapce
	 * this object belongs to.
	 */
	struct homa_net *hnet;

	/**
	 * @num_qdiscs: Number of homa_qdisc objects referencing this struct.
	 * Access only when holding homa->qdisc_devs_lock.
	 */
	int num_qdiscs;

	/** @link_mbps: Speed of the link associated with @dev, in Mbps. */
	int link_mbps;

	/**
	 * @cycles_per_mibyte: The number of homa_clock cycles that it takes
	 * to transmit 2**20 bytes on the link associated with @dev; computed
	 * from @link_mbps. This is actually a slight overestimate (if we
	 * underestimate, the link queue could grow without bound during
	 * periods of high traffic).
	 */
	int cycles_per_mibyte;

	/**
	 * @link_idle_time: The time, measured by homa_clock, at which we
	 * estimate that all of the packets passed to @dev will have been
	 * transmitted. May be in the past.
	 */
	atomic64_t link_idle_time __aligned(L1_CACHE_BYTES);

	/** @links: Used to link this struct into homa->qdisc_devs. */
	struct list_head links;

	/**
	 * @homa_deferred: Homa packets whose transmission was deferred
	 * because the NIC queue was too long. The queue is in SRPT order.
	 */
	struct sk_buff_head homa_deferred;

	/**
	 * @tcp_deferred: TCP packets whose transmission was deferred
	 * because the NIC queue was too long. The queue is in order of
	 * packet arrival at the qdisc.
	 */
	struct sk_buff_head tcp_deferred;

	/**
	 * @pacer_kthread: Kernel thread that eventually transmits packets
	 * on homa_deferred and tcp_deferred.
	 */
	struct task_struct *pacer_kthread;

	/**
	 * @pacer_sleep: Used to block the pacer thread when there
	 * are no throttled RPCs.
	 */
	struct wait_queue_head pacer_sleep;

	/**
	 * @pacer_mutex: Ensures that only one instance of
	 * homa_qdisc_pacer runs at a time. Only used in "try" mode:
	 * never block on this.
	 */
	spinlock_t pacer_mutex __aligned(L1_CACHE_BYTES);

	/**
	 * @pacer_skb: The current skb that the pacer has selected for
	 * transmission and is pushing through __dev_xmit_skb. This skb
	 * should be transmitted without any further delay or accounting.
	 */
	struct sk_buff *pacer_skb;
};

void            homa_qdisc_destroy(struct Qdisc *sch);
int             homa_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
				   struct sk_buff **to_free);
int             homa_qdisc_init(struct Qdisc *sch, struct nlattr *opt,
				struct netlink_ext_ack *extack);
int             homa_qdisc_pacer_main(void *device);
void            homa_qdisc_qdev_destroy(struct homa_qdisc_dev *qdev);
struct homa_qdisc_dev *
		homa_qdisc_qdev_new(struct homa_net *hnet,
				    struct net_device *dev);
int             homa_qdisc_register(void);
void            homa_qdisc_resubmit_skb(struct sk_buff *skb,
					struct net_device *dev, int queue);
void            homa_qdisc_srpt_enqueue(struct sk_buff_head *list,
					struct sk_buff *skb);
struct sk_buff *
                homa_qdisc_srpt_dequeue(struct sk_buff_head *list);
void            homa_qdisc_srpt_free(struct sk_buff_head *list);
void            homa_qdisc_unregister(void);
void            homa_qdisc_update_all_sysctl(struct homa_net *hnet);
int             homa_qdisc_update_link_idle(struct homa_qdisc_dev *qdev,
					    int bytes, int max_queue_ns);
void            homa_qdisc_update_sysctl(struct homa_qdisc_dev *qdev);
void            homa_qdisc_pacer(struct homa_qdisc_dev *qdev);

#endif /* _HOMA_QDISC_H */