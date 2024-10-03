/* SPDX-License-Identifier: BSD-2-Clause */

/* This file contains definitions that related to generating grants. */

#ifndef _HOMA_GRANT_H
#define _HOMA_GRANT_H

extern int      homa_grantable_lock_slow(struct homa *homa, int recalc);
extern void     homa_grant_add_rpc(struct homa_rpc *rpc);
extern void     homa_grant_check_rpc(struct homa_rpc *rpc);
extern void     homa_grant_find_oldest(struct homa *homa);
extern void     homa_grant_free_rpc(struct homa_rpc *rpc);
extern void     homa_grant_log_tt(struct homa *homa);
extern int      homa_grant_outranks(struct homa_rpc *rpc1,
		    struct homa_rpc *rpc2);
extern int      homa_grant_pick_rpcs(struct homa *homa, struct homa_rpc **rpcs,
		    int max_rpcs);
extern void     homa_grant_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
extern void     homa_grant_recalc(struct homa *homa, int locked);
extern void     homa_grant_remove_rpc(struct homa_rpc *rpc);
extern int      homa_grant_send(struct homa_rpc *rpc, struct homa *homa);
extern int      homa_grant_update_incoming(struct homa_rpc *rpc,
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
{
	int result;

	if (spin_trylock_bh(&homa->grantable_lock))
		result = 1;
	else
		result = homa_grantable_lock_slow(homa, recalc);
	homa->grantable_lock_time = get_cycles();
	return result;
}

/**
 * homa_grantable_unlock() - Release the grantable lock.
 * @homa:    Overall data about the Homa protocol implementation.
 */
static inline void homa_grantable_unlock(struct homa *homa)
{
	INC_METRIC(grantable_lock_cycles, get_cycles()
			- homa->grantable_lock_time);
	spin_unlock_bh(&homa->grantable_lock);
}

#endif /* _HOMA_GRANT_H */