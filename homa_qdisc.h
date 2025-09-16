/* SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+ */

/* This file contains definitions related to Homa's special-purpose
 * queuing discipline
 */

#include "homa_rpc.h"

#ifdef __UNIT_TEST__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif /* __UNIT_TEST__*/
#include <net/sch_generic.h>
#ifdef __UNIT_TEST__
#pragma GCC diagnostic pop
#endif /* __UNIT_TEST__*/

#include <linux/rbtree.h>

#ifndef _HOMA_QDISC_H
#define _HOMA_QDISC_H

/**
 * struct homa_qdisc - Contains Homa-specific data for a single instance of
 * the homa queuing discipline
 */
struct homa_qdisc {
	/** @qdev: Info shared among all qdiscs for a net_device. */
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
	 * @hnet: Homa's information about the network namespace
	 * this object belongs to.
	 */
	struct homa_net *hnet;

	/**
	 * @refs: Reference count (e.g. includes one reference for each
	 * homa_qdisc that references this object).  Must hold
	 * hnet->qdisc_devs_lock to access.
	 */
	refcount_t refs;

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
	 * @deferred_rpcs: Contains all homa_rpc's with deferred packets, in
	 * SRPT order.
	 */
	struct rb_root_cached deferred_rpcs;

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
	 * @defer_lock: Sychronizes access to information about deferred
	 * packets, including deferred_rpcs, tcp_deferred, and last_defer.
	 */
	spinlock_t defer_lock;

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

	/**
	 * @rcu_head: Holds state of a pending call_rcu invocation when
	 * this struct is deleted.
	 */
	struct rcu_head rcu_head;
};

/**
 * struct homa_qdisc_qdevs - There is one of these structs for each
 * struct homa. Used to manage all of the homa_qdisc_devs for the
 * struct homa.
 */
struct homa_qdisc_qdevs {
	/**
	 * @mutex: Must hold when modifying qdevs. Can scan qdevs
	 * without locking using RCU.
	 */
	struct mutex mutex;

	/** @num_devs: Number of entries currently in use in @qdevs. */
	int num_qdevs;

	/**
	 * @qdevs: Pointers to all homa_qdisc_devs that exist for this
	 * struct homa. Scan and/or retrieve pointers using RCU. Storage
	 * for this is dynamically allocated, must be kfreed.
	 */
	struct homa_qdisc_dev **qdevs;
};

/**
 * struct homa_rcu_kfreer - Used by homa_rcu_kfree to defer kfree-ing
 * an object until it is RCU-safe.
 */
struct homa_rcu_kfreer {
	/** @rcu_head: Holds state of a pending call_rcu invocation. */
	struct rcu_head rcu_head;

	/** object: Kfree this after waiting until RCU has synced. */
	void *object;
};

void            homa_qdisc_defer_homa(struct homa_qdisc_dev *qdev,
				      struct sk_buff *skb);
struct sk_buff *
		homa_qdisc_dequeue_homa(struct homa_qdisc_dev *qdev);
void            homa_qdisc_destroy(struct Qdisc *sch);
void            homa_qdisc_dev_callback(struct rcu_head *head);
struct homa_qdisc_qdevs *
		homa_qdisc_qdevs_alloc(void);
void            homa_qdisc_qdevs_free(struct homa_qdisc_qdevs *qdevs);
int             homa_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
				   struct sk_buff **to_free);
void            homa_qdisc_free_homa(struct homa_qdisc_dev *qdev);
int             homa_qdisc_init(struct Qdisc *sch, struct nlattr *opt,
				struct netlink_ext_ack *extack);
void            homa_qdisc_insert_rb(struct homa_qdisc_dev *qdev,
				     struct homa_rpc *rpc);
void            homa_qdisc_pacer(struct homa_qdisc_dev *qdev);
void            homa_qdisc_pacer_check(struct homa *homa);
int             homa_qdisc_pacer_main(void *device);
struct homa_qdisc_dev *
		homa_qdisc_qdev_get(struct net_device *dev);
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
void            homa_rcu_kfree(void *object);
void            homa_rcu_kfree_callback(struct rcu_head *head);

/**
 * homa_qdisc_active() - Return true if homa qdiscs are enabled for @hnet
 * (so the old pacer should not be used), false otherwise.
 * @homa:    Information about the Homa transport.
 * Return:   See above.
 */
static inline bool homa_qdisc_active(struct homa *homa)
{
	return homa->qdevs->num_qdevs > 0;
}

/**
 * homa_qdisc_rpc_init() - Initialize a homa_rpc_qdisc struct.
 * @qrpc:  Struct to initialize
 */
static inline void homa_qdisc_rpc_init(struct homa_rpc_qdisc *qrpc)
{
	skb_queue_head_init(&qrpc->packets);
	qrpc->tx_left = HOMA_MAX_MESSAGE_LENGTH;
}

/**
 * homa_qdisc_any_deferred() - Returns true if there are currently any
 * deferred packets in a homa_qdisc_dev, false if there are none.
 * @qdev:      Holds info about deferred packets.
 * Return:     See above.
 */
static inline bool homa_qdisc_any_deferred(struct homa_qdisc_dev *qdev)
{
	return rb_first_cached(&qdev->deferred_rpcs) ||
	       !skb_queue_empty(&qdev->tcp_deferred);
}

/**
 * homa_qdisc_precedes() - Return true if @rpc1 is considered "less"
 * than @rpc2 for the purposes of qdev->deferred_rpcs, or false if @rpc1
 * is consdered "greater" (ties not allowed).
 * @rpc1:    RPC to compare
 * @rpc2:    RPC to compare; must be different from rpc1.
 */
static inline bool homa_qdisc_precedes(struct homa_rpc *rpc1,
				       struct homa_rpc *rpc2)
{
	/* The primary metric for comparison is bytes left to transmit;
	 * in case of ties, use RPC age as secondar metric (oldest RPC
	 * is "less"), and if still tied (highly unlikely) use the
	 * addresses of the RPCs as a tie-breaker.
	 */
	if (rpc1->qrpc.tx_left < rpc2->qrpc.tx_left)
		return true;
	else if (rpc2->qrpc.tx_left < rpc1->qrpc.tx_left)
		return false;
	if (rpc1->msgout.init_time < rpc2->msgout.init_time)
		return true;
	else if (rpc2->msgout.init_time < rpc1->msgout.init_time)
		return false;
	return rpc1 < rpc2;
}

#endif /* _HOMA_QDISC_H */
