/* SPDX-License-Identifier: BSD-2-Clause */

/* This file contains definitions that related to generating grants. */

#ifndef _HOMA_GRANT_H
#define _HOMA_GRANT_H

#include "homa_rpc.h"

int      homa_grantable_lock_slow(struct homa *homa, int recalc);
void     homa_grant_add_rpc(struct homa_rpc *rpc);
void     homa_grant_check_rpc(struct homa_rpc *rpc);
void     homa_grant_end_rpc(struct homa_rpc *rpc);
void     homa_grant_find_oldest(struct homa *homa);
int      homa_grant_get_offset(struct homa_rpc *rpc, struct homa *homa);
void     homa_grant_log_tt(struct homa *homa);
int      homa_grant_outranks(struct homa_rpc *rpc1,
			     struct homa_rpc *rpc2);
int      homa_grant_pick_rpcs(struct homa *homa, struct homa_rpc **rpcs,
			      int max_rpcs);
void     homa_grant_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
void     homa_grant_recalc(struct homa *homa);
void     homa_grant_remove_rpc(struct homa_rpc *rpc);
void     homa_grant_send(struct homa_rpc *rpc);
void     homa_grant_update_incoming(struct homa_rpc *rpc,
				    struct homa *homa);

/**
 * homa_grantable_lock() - Acquire the grantable lock. If the lock
 * isn't immediately available, record stats on the waiting time.
 * @homa:    Overall data about the Homa protocol implementation.
 * @recalc:  Nonzero means the caller is homa_grant_recalc; if another thread
 *           is already recalculating, can return without waiting for the lock.
 * Return:   Nonzero means this thread now owns the grantable lock. Zero
 *           means the lock was not acquired and there is no need for this
 *           thread to do the work of homa_grant_recalc because some other
 *           thread started a fresh calculation after this method was invoked.
 */
static inline int homa_grantable_lock(struct homa *homa, int recalc)
	__acquires(&homa->grantable_lock)
{
	int result;

	if (spin_trylock_bh(&homa->grantable_lock))
		result = 1;
	else
		result = homa_grantable_lock_slow(homa, recalc);
	homa->grantable_lock_time = sched_clock();
	return result;
}

/**
 * homa_grantable_unlock() - Release the grantable lock.
 * @homa:    Overall data about the Homa protocol implementation.
 */
static inline void homa_grantable_unlock(struct homa *homa)
	__releases(&homa->grantable_lock)
{
	INC_METRIC(grantable_lock_ns, sched_clock() -
		   homa->grantable_lock_time);
	spin_unlock_bh(&homa->grantable_lock);
}

/**
 * homa_grant_needy_bit() - Return a bit mask with the bit set in the
 * position in @homa->grant_needy_ranks for @rank.
 * @rank:     Rank of an RPC (corresponds to position in @homa->active_rpcs).
 * Return:    A value with a 1-bit in the position corresponding to @rank,
 *            or 0 if rank is -1 or >= HOMA_MAX_PRIORITIES.
 */
static inline int homa_grant_needy_bit(int rank)
{
	/* Eliminate any bits that conflict with HOMA_MAX_PRIORITIES. */
	return (1 << rank) & ((1 << HOMA_MAX_PRIORITIES) - 1);
}

#endif /* _HOMA_GRANT_H */
