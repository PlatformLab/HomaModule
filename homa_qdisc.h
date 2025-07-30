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

	/**
	 * @ix: Index of this qdisc's transmit queue among all those for
	 * its net_device.
	 */
	int ix;
};

/**
 * struct homa_qdisc_dev - Contains information shared across all of the
 * homa_qdiscs associated with a net_device.
 */
struct homa_qdisc_dev {
	/** @dev: Device common to all qdiscs using this struct. */
	struct net_device *dev;

	/**
	 * @homa_net: Homa's information about the network namespace
	 * this object belongs to.
	 */
	struct homa_net *hnet;

	/**
	 * @refs: Reference count (e.g. includes one reference for each
	 * homa_qdisc that references this object).  Must hold
	 * hnet->qdisc_devs_lock to access.
	 */
	int refs;

	/**
	 * @pacer_qix: Index of a netdev_queue within dev that is reserved
	 * for the pacer to use for transmitting packets. We segregate paced
	 * traffic (which is almost entirely large packets) from non-paced
	 * traffic (mostly small packets). All the paced traffic goes to a
	 * single transmit queue, and though we try to limit the length of
	 * this queue, there are situations where the queue can still build
	 * up (under some scenarios it appears that NICs cannot actually
	 * transmit at line rate). If the pacer queue is segregated, queue
	 * buildup there will not affect non-paced packets. In order to
	 * reserve pacer_qix for pacer traffic, short-packet traffic that
	 * is assigned to that queue must be redirected to another queue;
	 * redirect_qix is used for that. -1 means there currently isn't
	 * a netdev_queue assigned for pacer traffic. Note: this field is
	 * a hint; the value must be verified under RCU to have a Homa qdisc
	 * before using.
	 */
	int pacer_qix;

	/**
	 * @redirect_qix: Index of a netdev_queue within dev; packets
	 * originally passed to pacer_qix are redirected here, so that
	 * pacer_qix is used only for packets sent by the pacer. -1 means
	 * there isn't currently a netdev_queue assigned for this purpose.
	 * This field is a hint that must be verified under RCU before using
	 * to be sure it still refers to a Homa qdisc. May be the same as
	 * pacer_qix if there is only one Homa qdisc associated with dev.
	 */
	int redirect_qix;

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
	 * @last_defer: The most recent homa_clock() time when a packet was
	 * added to homa_deferred or tcp_deferred.
	 */
	u64 last_defer;

	/**
	 * @pacer_wake_time: homa_clock() time when the pacer woke up (if
	 * the pacer is running) or 0 if the pacer is sleeping.
	 */
	u64 pacer_wake_time;

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
};

void            homa_qdisc_defer_homa(struct homa_qdisc_dev *qdev,
				      struct sk_buff *skb);
struct sk_buff *
		homa_qdisc_dequeue_homa(struct homa_qdisc_dev *qdev);
void            homa_qdisc_destroy(struct Qdisc *sch);
int             homa_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
				   struct sk_buff **to_free);
void            homa_qdisc_free_homa(struct homa_qdisc_dev *qdev);
int             homa_qdisc_init(struct Qdisc *sch, struct nlattr *opt,
				struct netlink_ext_ack *extack);
int             homa_qdisc_pacer_main(void *device);
struct homa_qdisc_dev *
		homa_qdisc_qdev_get(struct homa_net *hnet,
				    struct net_device *dev);
void            homa_qdisc_qdev_put(struct homa_qdisc_dev *qdev);
int             homa_qdisc_redirect_skb(struct sk_buff *skb,
					struct homa_qdisc_dev *qdev,
					bool pacer);
int             homa_qdisc_register(void);
void            homa_qdisc_set_qixs(struct homa_qdisc_dev *qdev);
void            homa_qdisc_unregister(void);
void            homa_qdisc_update_all_sysctl(struct homa_net *hnet);
int             homa_qdisc_update_link_idle(struct homa_qdisc_dev *qdev,
					    int bytes, int max_queue_ns);
void            homa_qdisc_update_sysctl(struct homa_qdisc_dev *qdev);
void            homa_qdisc_pacer(struct homa_qdisc_dev *qdev);

/**
 * homa_qdisc_active() - Return true if homa qdiscs are enabled for @hnet
 * (so the old pacer should not be used), false otherwise.
 * @hnet:    Homa's information about a network namespace.
 * Return:   See above.
 */
static inline bool homa_qdisc_active(struct homa_net *hnet)
{
	return !list_empty(&hnet->qdisc_devs);
}

#endif /* _HOMA_QDISC_H */
