/* SPDX-License-Identifier: BSD-2-Clause */

/* This file contains definitions that related to generating grants. */

#ifndef _HOMA_GRANT_H
#define _HOMA_GRANT_H

#include "homa_rpc.h"

/**
 * define HOMA_MAX_GRANTS - Used to size various data structures for grant
 * management; the max_overcommit sysctl parameter must never be greater than
 * this.
 */
#define HOMA_MAX_GRANTS 10

/**
 * struct homa_grant - Holds information used to manage the sending of
 * grants for incoming messages. There is one instance of this object
 * stored in each struct homa.
 */
struct homa_grant {
	/**
	 * @total_incoming: the total number of bytes that we expect to receive
	 * (across all messages) even if we don't send out any more grants
	 * (includes granted but unreceived bytes, plus unreceived unscheduled
	 * bytes that we know about). This can potentially be negative, if
	 * a peer sends more bytes than granted (see synchronization note in
	 * homa_send_grants for why we have to allow this possibility).
	 */
	atomic_t total_incoming;

	/**
	 * @stalled_rank: rank of the highest-priority RPC (i.e., lowest
	 * rank) whose incoming message could not be fully granted because
	 * @total_incoming exceeded @max_incoming. INT_MAX means there are
	 * no stalled RPCs.
	 */
	atomic_t stalled_rank;

	/**
	 * @max_incoming: Homa will try to ensure that the total number of
	 * bytes senders have permission to send to this host (either
	 * unscheduled bytes or granted bytes) does not exceeds this value.
	 * Set externally via sysctl.
	 */
	int max_incoming;

	/**
	 * @lock: The grant lock: used to synchronize access to grant-related
	 * fields below as well as some fields in homa_rpc structs.
	 */
	spinlock_t lock ____cacheline_aligned_in_smp;

	/**
	 * @lock_time: homa_clock() time when lock was last locked. Used
	 * for computing statistics.
	 */
	u64 lock_time;

	/**
	 * @num_active_rpcs: Number of entries in @active_rpcs that are
	 * currently used.
	 */
	int num_active_rpcs;

	/**
	 * @active_rpcs: The highest-priority RPCs that still need grants.
	 * Lower index in the list means higher priority. If an RPC is in
	 * this array then it is not in @grantable_peers.
	 */
	struct homa_rpc *active_rpcs[HOMA_MAX_GRANTS];

	/**
	 * @grantable_peers: Contains all peers with entries in their
	 * grantable_rpcs lists. The list is sorted in priority order of
	 * the highest priority RPC for each peer (fewer ungranted bytes ->
	 * higher priority).
	 */
	struct list_head grantable_peers;

	/**
	 * @num_grantable_rpcs: Total number of RPCs with incoming
	 * messages that still need grants. Includes entries in both
	 * @active_rpcs and @grantable_peers.
	 */
	int num_grantable_rpcs;

	/**
	 * @last_grantable_change: The homa_clock() time of the most recent
	 * increment or decrement of num_grantable_rpcs; used for computing
	 * statistics.
	 */
	u64 last_grantable_change;

	/**
	 * @max_grantable_rpcs: The largest value that has been seen for
	 * num_grantable_rpcs since this value was reset to 0 (it can be
	 * reset externally using sysctl).
	 */
	int max_grantable_rpcs;

	/**
	 * @window: Maximum number of granted but not yet received bytes for
	 * an incoming message. Computed from @window_param.
	 */
	int window;

	/**
	 * @window_param: Set externally via sysctl to select a policy for
	 * computing grant windows (how much granted but not yet received
	 * data an incoming message may have). If nonzero, then it specifies
	 * a (static) size for windows. 0 means compute windows dynamically
	 * based on the number of RPCs we're currently granting to.
	 */
	int window_param;

	/**
	 * @max_rpcs_per_peer: If there are multiple incoming messages from
	 * the same peer, Homa will only issue grants to this many of them
	 * at a time.  Set externally via sysctl.
	 */
	int max_rpcs_per_peer;

	/**
	 * @max_overcommit: The maximum number of messages to which Homa will
	 * send grants at any given point in time.  Set externally via sysctl.
	 */
	int max_overcommit;

	/**
	 * @recalc_usecs: Length of the priority recalculation interval, in
	 * microseconds. Each interval, priorities of the active messages
	 * get resorted if they have drifted out of order. Set externally
	 * via sysctl.
	 */
	int recalc_usecs;

	/**
	 * @recalc_cycles: Same as @recalc_usec except in homa_clock() units.
	 */
	int recalc_cycles;

	/**
	 * @next_recalc: Time in homa_clock() units at which priorities
	 * should be recalculated.
	 */
	u64 next_recalc;

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
	 * @grant_nonfifo: How many bytes should be granted using the
	 * normal priority system between grants to the oldest message.
	 */
	int grant_nonfifo;

	/**
	 * @grant_nonfifo_left: Counts down bytes granted using the normal
	 * priority mechanism. When this reaches zero, it's time to grant
	 * to the oldest message.
	 */
	int grant_nonfifo_left;

	/**
	 * @oldest_rpc: The RPC with incoming data whose start_cycles is
	 * farthest in the past). NULL means either there are no incoming
	 * RPCs or the oldest needs to be recomputed. Must hold grant_lock
	 * to update.
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

/**
 * struct homa_grant_candidates() - Accumulates information about RPCs that
 * can potentially be issued grants. Used in order to defer the actual
 * granting until it is safe to acquire locks for the RPCs.
 */
struct homa_grant_candidates {
	/**
	 * @inserts: Total number of RPCs that have been inserted in this
	 * structure over its lifetime. Low-order bits indicate where the
	 * next RPC should be inserted.
	 */
	u32 inserts;

	/**
	 * @removes: Total number of RPCs that have been removed from this
	 * structure over its lifetime. Low-order bits give index of next
	 * RPC to be checked for possible grant.
	 */
	u32 removes;

	/* Maximum number of RPCs that can be stored in @rpcs. If space
	 * runs out some potentially grant-worthy RPCs may be ignored,
	 * but they will get another chance in a future call to
	 * homa_grant_check_all. Must be a power of 2.
	 */
#define HOMA_MAX_CAND_RPCS 8
#define HOMA_CAND_MASK (HOMA_MAX_CAND_RPCS - 1)

	/** @rpcs: RPCs that should be considered for sending grants. */
	struct homa_rpc *rpcs[HOMA_MAX_CAND_RPCS];

};

struct homa_grant
	*homa_grant_alloc(void);
void     homa_grant_cand_add(struct homa_grant_candidates *cand,
			     struct homa_rpc *rpc);
void     homa_grant_cand_check(struct homa_grant_candidates *cand,
			       struct homa_grant *grant);
void     homa_grant_check_rpc(struct homa_rpc *rpc);
int      homa_grant_dointvec(const struct ctl_table *table, int write,
			     void *buffer, size_t *lenp, loff_t *ppos);
void     homa_grant_end_rpc(struct homa_rpc *rpc);
void     homa_grant_find_oldest(struct homa *homa);
int      homa_grant_fix_order(struct homa_grant *grant);
void     homa_grant_free(struct homa_grant *grant);
void     homa_grant_init_rpc(struct homa_rpc *rpc, int unsched);
struct homa_rpc
	*homa_grant_insert_active(struct homa_rpc *rpc);
void     homa_grant_insert_grantable(struct homa_rpc *rpc);
void     homa_grant_manage_rpc(struct homa_rpc *rpc);
void     homa_grant_lock_slow(struct homa_grant *grant);
void     homa_grant_log_tt(struct homa *homa);
int      homa_grant_outranks(struct homa_rpc *rpc1,
			     struct homa_rpc *rpc2);
void     homa_grant_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
int      homa_grant_priority(struct homa *homa, int rank);
void     homa_grant_remove_active(struct homa_rpc *rpc,
				  struct homa_grant_candidates *cand);
void     homa_grant_remove_grantable(struct homa_rpc *rpc);
void     homa_grant_send(struct homa_rpc *rpc, int priority);
void     homa_grant_unmanage_rpc(struct homa_rpc *rpc,
				 struct homa_grant_candidates *cand);
int      homa_grant_update_granted(struct homa_rpc *rpc,
				   struct homa_grant *grant);
void     homa_grant_update_incoming(struct homa_rpc *rpc,
				    struct homa_grant *grant);
void     homa_grant_update_sysctl_deps(struct homa_grant *grant);
int      homa_grant_window(struct homa_grant *grant);

/**
 * homa_grant_cand_init() - Reset @cand to an empty state.
 * @cand:  Structure to initialize.
 */
static inline void homa_grant_cand_init(struct homa_grant_candidates *cand)
{
	cand->inserts = 0;
	cand->removes = 0;
}

/**
 * homa_grant_cand_empty() - Returns true if there are no RPCs in @cand,
 * false otherwise
 * @cand:  Structure to check.
 * Return: See above.
 */
static inline bool homa_grant_cand_empty(struct homa_grant_candidates *cand)
{
	return cand->inserts == cand->removes;
}

/**
 * homa_grant_lock() - Acquire the grant lock. If the lock
 * isn't immediately available, record stats on the waiting time.
 * @grant:   Grant management info.
 */
static inline void homa_grant_lock(struct homa_grant *grant)
	__acquires(&grant->lock)
{
	if (!spin_trylock_bh(&grant->lock))
		homa_grant_lock_slow(grant);
	grant->lock_time = homa_clock();
}

/**
 * homa_grant_unlock() - Release the grant lock.
 * @grant:   Grant management info.
 */
static inline void homa_grant_unlock(struct homa_grant *grant)
	__releases(&grant->grant_lock)
{
	INC_METRIC(grant_lock_cycles, homa_clock() - grant->lock_time);
	spin_unlock_bh(&grant->lock);
}

#endif /* _HOMA_GRANT_H */
