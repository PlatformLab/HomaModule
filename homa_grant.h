/* SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+ */

/* This file contains definitions that related to generating grants. */

#ifndef _HOMA_GRANT_H
#define _HOMA_GRANT_H

#include "homa_rpc.h"

/**
 * define HOMA_MAX_GRANTS - Used to size various data structures for grant
 * management; the max_overcommit sysctl parameter must never be greater than
 * this.
 */
#define HOMA_MAX_GRANTS 8

/**
 * struct homa_active_rpc - Stores information about an RPC that is eligible
 * to receive grants. This information is immutable, so it changes only when
 * RPCs are moved into and out of grant->active_rpcs. All of the immutable
 * information for all active RPCs is concentrated into a few cache lines to
 * minimize cache misses when scanning active RPCs. Must hold both the grant
 * lock and @rpc's lock to make updates.
 */
struct homa_active_rpc {
	/** @rpc: The RPC that this information pertains to. */
	struct homa_rpc *rpc;

	/** @peer: A copy of @rpc->peer. */
	struct homa_peer *peer;

	/**
	 * @birth: A copy of @rpc->birth.
	 */
	u64 birth;
};

/**
 * struct homa_grant - Holds information used to manage the sending of
 * grants for incoming messages. There is one instance of this object
 * stored in each struct homa.
 */
struct homa_grant {
	/* ------------------------------------------------------------
	 * Information that changes when the contents of @active_rpcs
	 * and/or @grantable_peers change. This information does not
	 * change in the normal process of issuing grants to the active
	 * RPCs.
	 * ------------------------------------------------------------
	 */

	/**
	 * @lock: The grant lock: must be held while inserting an RPC into
	 * grant-related structures, removing it, or changing its position
	 * in the structures. Acquire this lock *before* acquiring an RPC
	 * lock.
	 */
	spinlock_t lock ____cacheline_aligned_in_smp;

	/**
	 * @lock_time: homa_clock() time when @lock was last locked. Used
	 * for computing statistics.
	 */
	u64 lock_time;

	/**
	 * @grantable_peers: Contains all peers with entries in their
	 * grantable_rpcs lists. The list is sorted in decreasing SRPT
	 * priority order.
	 */
	struct list_head grantable_peers;

	/**
	 * @num_grantable_rpcs: Total number of RPCs in  @active_rpcs or
	 * @grantable_peers.
	 */
	int num_grantable_rpcs;

	/**
	 * @max_grantable_rpcs: The largest value that has been seen for
	 * num_grantable_rpcs since this value was reset to 0 (it can be
	 * reset externally using sysctl).
	 */
	int max_grantable_rpcs;

	/**
	 * @last_grantable_change: The homa_clock() time of the most recent
	 * increment or decrement of num_grantable_rpcs; used for computing
	 * statistics.
	 */
	u64 last_grantable_change;

	/**
	 * @num_active: Number of entries in @active_rpcs that are
	 * occupied (note: occupied entries are not necessarily contiguous
	 * at the start of the array).
	 */
	int num_active;

	/**
	 * @window: Current window to use for grants; depends on @num_active
	 * and @window_param.
	 */
	int window;

	/**
	 * @active_rpcs: Immutable information about the highest priority
	 * RPCs that have the RPC_GRANTABLE flag set. This array balances
	 * incoming RPCs across peers, so that each peer gets at least one
	 * RPC in this list before any peer gets a second active RPC. Only
	 * RPCs in this array are eligible to receive grants. Information in
	 * this arry is immutable except when RPCs are moved into or out of
	 * the array.
	 *
	 * The entries in this array are not kept in priority order, which
	 * means the array must be scanned to to determine an RPC's priority.
	 * A previous implementation tried to maintain an order, but it is
	 * hard to maintain a precise order without frequent acquisitions of
	 * the global lock. Scanning the array is cheaper than contending for
	 * the global lock.
	 */
	struct homa_active_rpc active_rpcs[HOMA_MAX_GRANTS];

	/* ------------------------------------------------------------
	 * Data that is modified frequenty while issuing grants.
	 * ------------------------------------------------------------
	 */

	/**
	 * @total_incoming: the total number of bytes that we expect to receive
	 * (across all messages) even if we don't send out any more grants
	 * (includes granted but unreceived bytes, plus unreceived unscheduled
	 * bytes that we know about). This can potentially be negative, if
	 * a peer sends more bytes than granted (see synchronization note in
	 * homa_send_grants for why we have to allow this possibility).
	 * Manuipulated locklessly with atomic ops.
	 */
	atomic_t total_incoming ____cacheline_aligned_in_smp;

	/**
	 * @needy_active: Bit i of this value is 1 if the RPC in slot i of
	 * @active_rpcs has available window that it could not grant because
	 * @max_incoming was exceeded. This variable is manipulated locklessly
	 * with set_bit and clear_bit. This field and @active_remaining are
	 * updated frequently during grant management, so they are in a
	 * separate cache line from @active_rpcs
	 */
	unsigned long needy_active;

        /**
	 * @active_remaining: For each RPC in @active_rpcs, this keeps a
	 * copy of @msgin->bytes_remaining for that RPC. We keep copies here
	 * so that all of the active RPCs can be scanned quickly with at
	 * most a single cache miss. Unused slots have the value -1.
	 * Must hold the RPC lock to make updates.
	 */
	int active_remaining[HOMA_MAX_GRANTS];

	/**
	 * @fifo_grant_time: The time when we should issue the next FIFO
	 * grant.
	 */
	u64 fifo_grant_time;

	/* ------------------------------------------------------------
	 * Information that rarely changes.
	 * ------------------------------------------------------------
	 */

	/** @homa: The struct homa that this object belongs to. */
	struct homa *homa;

	/**
	 * @max_incoming: Homa will try to ensure that @total_incoming does
	 * not exceeds this value.  Set externally via sysctl.
	 */
	int max_incoming;

	/**
	 * @window_param: Set externally via sysctl to select a policy for
	 * computing grant windows (how much granted but not yet received
	 * data an incoming message may have). If nonzero, then it specifies
	 * a (static) size for windows. 0 means compute windows dynamically
	 * based on the number of RPCs we're currently granting to.
	 */
	int window_param;

	/**
	 * @windows: Maps from <number of RPCs in @active_rpcs> to the
	 * window size to use during grants. Computed from @window_param.
	 */
	int windows[HOMA_MAX_GRANTS + 1];

	/**
	 * @max_overcommit: The maximum number of messages to which Homa will
	 * send grants at any given point in time.  Set externally via sysctl.
	 */
	int max_overcommit;

	/**
	 * @fifo_grant_increment: how many additional bytes to grant in
	 * a "pity" grant sent to the oldest outstanding message. Set
	 * externally via sysctl.
	 */
	int fifo_grant_increment;

	/**
	 * @fifo_fraction: The fraction (in thousandths) of granted
	 * bytes that should go to the *oldest* incoming message, rather
	 * than the highest priority ones. Set externally via sysctl.
	 */
	int fifo_fraction;

	/**
	 * @fifo_grant_interval: The time (in homa_clock units) between
	 * successive FIFO grants.
	 */
	u64 fifo_grant_interval;

	/**
	 * @oldest_rpc: The RPC with incoming data whose start_cycles is
	 * farthest in the past). NULL means either there are no incoming
	 * RPCs or the oldest needs to be recomputed. There is always a
	 * reference taken for this RPC. Must hold grant_lock to update.
	 */
	struct homa_rpc *oldest_rpc;

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @sysctl_header: Used to remove sysctl values when this structure
	 * is destroyed.
	 */
	struct ctl_table_header *sysctl_header;
#endif /* See strip.py */
} ____cacheline_aligned_in_smp;

void     homa_grant_add_active(struct homa_grant *grant, struct homa_rpc *rpc,
			       int slot);
struct homa_grant
	*homa_grant_alloc(struct homa *homa);
void     homa_grant_adjust_peer(struct homa_grant *grant,
				struct homa_peer *peer);
void     homa_grant_check_fifo(struct homa_grant *grant);
void     homa_grant_check_needy(struct homa_grant *grant);
void     homa_grant_check_rpc(struct homa_rpc *rpc);
int      homa_grant_dointvec(const struct ctl_table *table, int write,
			     void *buffer, size_t *lenp, loff_t *ppos);
void     homa_grant_find_oldest(struct homa_grant *grant);
int      homa_grant_find_victim(struct homa_grant *grant, struct homa_rpc *rpc);
void     homa_grant_free(struct homa_grant *grant);
void     homa_grant_init_rpc(struct homa_rpc *rpc, int unsched);
void     homa_grant_insert_grantable(struct homa_grant *grant,
				     struct homa_rpc *rpc);
void     homa_grant_manage_rpc(struct homa_grant *grant, struct homa_rpc *rpc);
void     homa_grant_lock_slow(struct homa_grant *grant);
int      homa_grant_outranks(struct homa_rpc *rpc1,
			     struct homa_rpc *rpc2);
void     homa_grant_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
int      homa_grant_priority(struct homa *homa, int rank);
void     homa_grant_promote_queued(struct homa_grant *grant, int slot);
void     homa_grant_promote_rpc(struct homa_grant *grant, struct homa_rpc *rpc);
void     homa_grant_remove_active(struct homa_grant *grant, int slot);
void     homa_grant_remove_grantable(struct homa_grant *grant,
				     struct homa_rpc *rpc);
void     homa_grant_send(struct homa_rpc *rpc, int priority);
void     homa_grant_try_send(struct homa_grant *grant, struct homa_rpc *rpc,
			     bool check_needy);
void     homa_grant_unmanage_rpc(struct homa_rpc *rpc);
void     homa_grant_update_incoming(struct homa_grant *grant,
				    struct homa_rpc *rpc);
void     homa_grant_update_sysctl_deps(struct homa_grant *grant);
int      homa_grant_window(struct homa_grant *grant);

/**
 * homa_grant_lock() - Acquire the grant lock. If the lock
 * isn't immediately available, record stats on the waiting time.
 * @grant:   Grant management info.
 */
static inline void homa_grant_lock(struct homa_grant *grant)
	__acquires(grant->lock)
{
	if (!spin_trylock_bh(&grant->lock))
		homa_grant_lock_slow(grant);
	grant->lock_time = homa_clock();
	INC_METRIC(grant_locks, 1);
}

/**
 * homa_grant_add_lock() - This function is invoked in situations where
 * an RPC lock is held but we now need to hold both the RPC lock and the
 * grant lock. Because of the locking order rules, we can't block on the
 * grant lock while holding an RPC lock. So, if the grant lock is busy
 * we release the RPC lock, get the grant lock, then relock the RPC.
 */
static inline void homa_grant_add_lock(struct homa_grant *grant,
				       struct homa_rpc *rpc)
	__must_hold(rpc->bucket->lock)
	__acquires(grant->lock)
{
	if (spin_trylock_bh(&grant->lock)) {
		grant->lock_time = homa_clock();
		INC_METRIC(grant_locks, 1);
		return;
	}
	homa_rpc_unlock(rpc);
	homa_grant_lock_slow(grant);
	grant->lock_time = homa_clock();
	homa_rpc_lock(rpc);
}

/**
 * homa_grant_unlock() - Release the grant lock.
 * @grant:   Grant management info.
 */
static inline void homa_grant_unlock(struct homa_grant *grant)
	__releases(grant->grant_lock)
{
	INC_METRIC(grant_lock_cycles, homa_clock() - grant->lock_time);
	spin_unlock_bh(&grant->lock);
}

#endif /* _HOMA_GRANT_H */
