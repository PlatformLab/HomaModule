/* SPDX-License-Identifier: BSD-2-Clause */

/* This file defines structs and functions related to the Homa pacer,
 * which implements SRPT for packet output. In order to do that, it
 * throttles packet transmission to prevent the buildup of
 * large queues in the NIC.
 */

#ifndef _HOMA_PACER_H
#define _HOMA_PACER_H

#include "homa_impl.h"
#ifndef __STRIP__ /* See strip.py */
#include "homa_metrics.h"
#endif /* See strip.py */

/**
 * struct homa_pacer - Contains information that the pacer users to
 * manage packet output. There is one instance of this object stored
 * in each struct homa.
 */
struct homa_pacer {
	/** @homa: Transport that this pacer is associated with. */
	struct homa *homa;

	/**
	 * @mutex: Ensures that only one instance of homa_pacer_xmit
	 * runs at a time. Only used in "try" mode: never block on this.
	 */
	spinlock_t mutex;

	/**
	 * @fifo_count: When this becomes <= zero, it's time for the
	 * pacer to allow the oldest RPC to transmit.
	 */
	int fifo_count;

	/**
	 * @wake_time: homa_clock() time when the pacer woke up (if the pacer
	 * is running) or 0 if the pacer is sleeping.
	 */
	u64 wake_time;

	/**
	 * @throttle_lock: Used to synchronize access to @throttled_rpcs. Must
	 * hold when inserting or removing an RPC from throttled_rpcs.
	 */
	spinlock_t throttle_lock;

	/**
	 * @throttled_rpcs: Contains all homa_rpcs that have bytes ready
	 * for transmission, but which couldn't be sent without exceeding
	 * the NIC queue limit.
	 */
	struct list_head throttled_rpcs;

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @throttle_add: The most recent homa_clock() time when an RPC was
	 * added to @throttled_rpcs.
	 */
	u64 throttle_add;
#endif /* See strip.py */

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
	 * @link_mbps: The raw bandwidth of the network uplink, in
	 * units of 1e06 bits per second.  Set externally via sysctl.
	 */
	int link_mbps;

	/**
	 * @cycles_per_mbyte: the number of homa_clock() cycles that it takes to
	 * transmit 10**6 bytes on our uplink. This is actually a slight
	 * overestimate of the value, to ensure that we don't underestimate
	 * NIC queue length and queue too many packets.
	 */
	u32 cycles_per_mbyte;

	/**
	 * @throttle_min_bytes: If a packet has fewer bytes than this, then it
	 * bypasses the throttle mechanism and is transmitted immediately.
	 * We have this limit because for very small packets CPU overheads
	 * make it impossible to keep up with the NIC so (a) the NIC queue
	 * can't grow and (b) using the pacer would serialize all of these
	 * packets through a single core, which makes things even worse.
	 * Set externally via sysctl.
	 */
	int throttle_min_bytes;

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @sysctl_header: Used to remove sysctl values when this structure
	 * is destroyed.
	 */
	struct ctl_table_header *sysctl_header;
#endif /* See strip.py */

	/**
	 * @exit: true means that the pacer thread should exit as
	 * soon as possible.
	 */
	bool exit;

	/**
	 * @wait_queue: Used to block the pacer thread when there
	 * are no throttled RPCs.
	 */
	struct wait_queue_head wait_queue;

	/**
	 * @kthread: Kernel thread that transmits packets from
	 * throttled_rpcs in a way that limits queue buildup in the
	 * NIC.
	 */
	struct task_struct *kthread;

	/**
	 * @kthread_done: Used to wait for @kthread to exit.
	 */
	struct completion kthread_done;

	/**
	 * @link_idle_time: The homa_clock() time at which we estimate
	 * that all of the packets we have passed to the NIC for transmission
	 * will have been transmitted. May be in the past. This estimate
	 * assumes that only Homa is transmitting data, so it could be a
	 * severe underestimate if there is competing traffic from, say, TCP.
	 */
	atomic64_t link_idle_time ____cacheline_aligned_in_smp;
};

struct homa_pacer *homa_pacer_alloc(struct homa *homa, struct net *net);
int      homa_pacer_check_nic_q(struct homa_pacer *pacer,
				struct sk_buff *skb, bool force);
int      homa_pacer_dointvec(const struct ctl_table *table, int write,
			     void *buffer, size_t *lenp, loff_t *ppos);
void     homa_pacer_free(struct homa_pacer *pacer);
void     homa_pacer_unmanage_rpc(struct homa_rpc *rpc);
void     homa_pacer_log_throttled(struct homa_pacer *pacer);
int      homa_pacer_main(void *transport);
void     homa_pacer_manage_rpc(struct homa_rpc *rpc);
void     homa_pacer_throttle_lock_slow(struct homa_pacer *pacer);
void     homa_pacer_update_sysctl_deps(struct homa_pacer *pacer);
void     homa_pacer_xmit(struct homa_pacer *pacer);

/**
 * homa_pacer_check() - This method is invoked at various places in Homa to
 * see if the pacer needs to transmit more packets and, if so, transmit
 * them. It's needed because the pacer thread may get descheduled by
 * Linux, result in output stalls.
 * @pacer:    Pacer information for a Homa transport.
 */
static inline void homa_pacer_check(struct homa_pacer *pacer)
{
	if (list_empty(&pacer->throttled_rpcs))
		return;

	/* The ">> 1" in the line below gives homa_pacer_main the first chance
	 * to queue new packets; if the NIC queue becomes more than half
	 * empty, then we will help out here.
	 */
	if ((homa_clock() + (pacer->max_nic_queue_cycles >> 1)) <
			atomic64_read(&pacer->link_idle_time))
		return;
	tt_record("homa_check_pacer calling homa_pacer_xmit");
	homa_pacer_xmit(pacer);
	INC_METRIC(pacer_needed_help, 1);
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_pacer_throttle_lock() - Acquire the throttle lock. If the lock
 * isn't immediately available, record stats on the waiting time.
 * @pacer:    Pacer information for a Homa transport.
 */
static inline void homa_pacer_throttle_lock(struct homa_pacer *pacer)
	__acquires(&pacer->throttle_lock)
{
	if (!spin_trylock_bh(&pacer->throttle_lock))
		homa_pacer_throttle_lock_slow(pacer);
}
#else /* See strip.py */
/**
 * homa_pacer_throttle_lock() - Acquire the throttle lock.
 * @pacer:    Pacer information for a Homa transport.
 */
static inline void homa_pacer_throttle_lock(struct homa_pacer *pacer)
	__acquires(&pacer->throttle_lock)
{
	spin_lock_bh(&pacer->throttle_lock);
}
#endif /* See strip.py */

/**
 * homa_pacer_throttle_unlock() - Release the throttle lock.
 * @pacer:    Pacer information for a Homa transport.
 */
static inline void homa_pacer_throttle_unlock(struct homa_pacer *pacer)
	__releases(&pacer->throttle_lock)
{
	spin_unlock_bh(&pacer->throttle_lock);
}

#endif /* _HOMA_PACER_H */
