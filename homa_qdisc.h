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
	/** @sch: The Qdisc that this structure is associated with. */
	struct Qdisc *sch;

	/** @qdev: Info shared among all qdiscs for a net_device. */
	struct homa_qdisc_dev *qdev;

	/**
	 * @ix: Index of this qdisc's transmit queue among all those for
	 * its net_device.
	 */
	int ix;

	/**
	 * @deferred_tcp: List of non-Homa packets for this qdisc that have
	 * been deferred because of NIC overload, in order of arrival.
	 * Synchronize with qdev->defer_lock.
	 */
	struct sk_buff_head deferred_tcp;

	/**
	 * @defer_links: Used to link this object into qdev->deferred_qdiscs
	 * when deferred_tcp is nonempty. This will be an empty list if
	 * deferred_tcp is nonempty. Synchronized with qdev->defer_lock.
	 */
	struct list_head defer_links;
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
	 * @links: Used to link this object into the qdevs list in a
	 * homa_qdisc_shared struct.
	 */
	struct list_head links;

	/**
	 * @link_idle_time: The time, measured by homa_clock, at which we
	 * estimate that all of the packets passed to @dev will have been
	 * transmitted. May be in the past.
	 */
	atomic64_t link_idle_time __aligned(L1_CACHE_BYTES);

	/**
	 * @deferred_rpcs: Contains all homa_rpc's with deferred packets, in
	 * SRPT order.
	 */
	struct rb_root_cached deferred_rpcs;

	/**
	 * @deferred_qdiscs: List of all homa_qdiscs with non-Homa packets
	 * that have been deferred because of NIC overload.
	 */
	struct list_head deferred_qdiscs;

	/**
	 * @next_qdisc: Points to either the defer_links field in a homa_qdisc
	 * or to deferred_qdiscs above. Used to select the next non-Homa packet
	 * for transmission. Note: this may refer to deferred_qdiscs even when
	 * deferred_qdiscs is nonempty.
	 */
	struct list_head *next_qdisc;

	/**
	 * @last_defer: The most recent homa_clock() time when a packet was
	 * deferred, or 0 if there are currently no deferred packets.
	 */
	u64 last_defer;

	/**
	 * @homa_credit: When there are both Homa and TCP deferred packets,
	 * this is used to balance output between them according to the
	 * homa_share sysctl value. Positive means that Homa packets should
	 * be transmitted next, zero or negative means TCP. When a TCP
	 * packet is transmitted, this is incremented by the packet length
	 * times homa_share; when a Homa packet is transmitted, it is
	 * decremented by packet length times (100 - homa_share). Used only
	 * by the pacer, so no need for synchronization.
	 */
	int homa_credit;

	/**
	 * @defer_lock: Synchronizes access to information about deferred
	 * packets, including deferred_rpcs, deferred_qdiscs, next_qdisc,
	 * last_defer, and some information in homa_qdiscs.
	 */
	spinlock_t defer_lock;

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
 * struct homa_qdisc_shared - There is one of these structs for each
 * struct homa. Contains information that is shared across all homq_qdiscs
 * and homa_qdisc_devs for the struct homa.
 */
struct homa_qdisc_shared {
	/**
	 * @mutex: Must hold when modifying qdevs. Can scan qdevs
	 * without locking using RCU.
	 */
	struct mutex mutex;

	/**
	 * @qdevs: RCU list of all homa_qdisc_devs that currently
	 * exist for this struct homa.
	 */
	struct list_head qdevs;

	/**
	 * @fifo_fraction: Out of every 1000 packets transmitted by the
	 * pacer, this number will be transmitted from the oldest message
	 * rather than the highest-priority message. Set externally via
	 * sysctl.
	 */
	int fifo_fraction;

	/**
	 * @max_nic_queue_ns: Limits the NIC queue length: we won't queue
	 * up a packet for transmission if link_idle_time is this many
	 * nanoseconds in the future (or more). Set externally via sysctl.
	 */
	int max_nic_queue_ns;

	/**
	 * @max_nic_queue_cycles: Same as max_nic_queue_ns except in
	 * homa_clock() units.
	 */
	int max_nic_queue_cycles;

	/**
	 * @defer_min_bytes: If a packet has fewer bytes than this, then it
	 * will be transmitted immediately, regardless of NIC queue length.
	 * We have this limit because for very small packets CPU overheads
	 * make it impossible to keep up with the NIC so (a) the NIC queue
	 * can't grow and (b) using the pacer would serialize all of these
	 * packets through a single core, which makes things even worse.
	 * Set externally via sysctl.
	 */
	int defer_min_bytes;

	/**
	 * @homa_share: When the uplink is overloaded, this determines how
	 * to share bandwidth between TCP and Homa. It gives the percentage
	 * of bandwidth that Homa will receive; TCP (and all other protocols,
	 * such as UDP) get the remainder. Must be between 0 and 100,
	 * inclusive.
	 */
	int homa_share;

	/**
	 * @max_link_usage: An integer <= 100 indicating the maximum percentage
	 * of uplink bandwidth that Homa will attempt to utilize. A smaller
	 * value reduces the likelihood of queue buildup in the NIC, but
	 * also prevents full link utilization.
	 */
	int max_link_usage;

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @sysctl_header: Used to remove sysctl values when this structure
	 * is destroyed.
	 */
	struct ctl_table_header *sysctl_header;
#endif /* See strip.py */
};

/**
 * struct homa_rcu_kfreer - Used by homa_rcu_kfree to defer kfree-ing
 * an object until it is RCU-safe.
 */
struct homa_rcu_kfreer {
	/** @rcu_head: Holds state of a pending call_rcu invocation. */
	struct rcu_head rcu_head;

	/** @object: Kfree this after waiting until RCU has synced. */
	void *object;
};

void            homa_qdev_update_sysctl(struct homa_qdisc_dev *qdev);
void            homa_qdisc_defer_homa(struct homa_qdisc_dev *qdev,
				      struct sk_buff *skb);
void            homa_qdisc_defer_tcp(struct homa_qdisc *q, struct sk_buff *skb);
void            homa_qdisc_destroy(struct Qdisc *sch);
void            homa_qdisc_dev_callback(struct rcu_head *head);
int             homa_qdisc_dointvec(const struct ctl_table *table, int write,
				    void *buffer, size_t *lenp, loff_t *ppos);
int             homa_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
				   struct sk_buff **to_free);
void            homa_qdisc_free_homa(struct homa_qdisc_dev *qdev);
struct sk_buff *homa_qdisc_get_deferred_homa(struct homa_qdisc_dev *qdev);
int             homa_qdisc_init(struct Qdisc *sch, struct nlattr *opt,
				struct netlink_ext_ack *extack);
void            homa_qdisc_insert_rb(struct homa_qdisc_dev *qdev,
				     struct homa_rpc *rpc);
void            homa_qdisc_pacer(struct homa_qdisc_dev *qdev, bool help);
void            homa_qdisc_pacer_check(struct homa *homa);
int             homa_qdisc_pacer_main(void *device);
struct homa_qdisc_dev *
		homa_qdisc_qdev_get(struct net_device *dev);
void            homa_qdisc_qdev_put(struct homa_qdisc_dev *qdev);
int             homa_qdisc_register(void);
struct homa_qdisc_shared *
		homa_qdisc_shared_alloc(void);
void            homa_qdisc_shared_free(struct homa_qdisc_shared *qshared);
void            homa_qdisc_unregister(void);
int             homa_qdisc_update_link_idle(struct homa_qdisc_dev *qdev,
					    int bytes, int max_queue_ns);
void            homa_qdisc_update_sysctl_deps(struct homa_qdisc_shared *qshared);
int             homa_qdisc_xmit_deferred_homa(struct homa_qdisc_dev *qdev);
int             homa_qdisc_xmit_deferred_tcp(struct homa_qdisc_dev *qdev);
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
	return list_first_or_null_rcu(&homa->qshared->qdevs,
				      struct homa_qdisc_dev, links) != NULL;
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
	       !list_empty(&qdev->deferred_qdiscs);
}

/**
 * homa_qdisc_schedule_skb() - Enqueue an skb on a qdisc and schedule the
 * qdisc for execution.
 * @skb:         Packet buffer to queue for output
 * @qdisc:       homa_qdisc on which to schedule it.
 */
static inline void homa_qdisc_schedule_skb(struct sk_buff *skb,
					   struct Qdisc *qdisc) {
	spin_lock_bh(qdisc_lock(qdisc));
	qdisc_enqueue_tail(skb, qdisc);
	spin_unlock_bh(qdisc_lock(qdisc));
	__netif_schedule(qdisc);
}

/**
 * homa_qdisc_precedes() - Return true if @rpc1 is considered "less" than
 * @rpc2 (i.e. higher priority) for the purposes of qdev->deferred_rpcs, or
 * false if @rpc1 is consdered "greater" (ties not allowed).
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
