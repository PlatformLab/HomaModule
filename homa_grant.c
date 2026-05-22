// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

/* This file contains functions related to issuing grants for incoming
 * messages.
 */

#include "homa_impl.h"
#include "homa_grant.h"
#include "homa_pacer.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#include "homa_wire.h"

/* DESIGN NOTES:
 * 1. Avoid global lock. The simplest way to implement granting is to
 *    acquire a global lock every time any grant decision is made. Homa
 *    was originally implemented this way, but the grant lock suffered
 *    from high contention (and its gets worse with faster networks).
 *
 *    This module has been reimplemented several times to reduce usage
 *    of the global lock. Unfortunately that tends to result in high
 *    complexity and subtle bugs.
 *
 *    The current approach divides grantable RPCs into two groups: the
 *    highest priority RPCS, which are eligible to receive grants at the
 *    current time (called "active"), and lower priority RPCs that may not
 *    receive grants right now. The number of active RPCs is limited by the
 *    "max_overcommit" parameter. The active RPCs are kept in a small
 *    array (@active_rpcs) in no particular order; the inactive ones are
 *    kept in two-level list structure, ordered by priority.
 *
 *    The grant lock must be held when moving RPCs into or out of
 *    @active_rpcs, or when manipulating the lists of low-priority RPCs.
 *    But grants can be issued to the active RPCs (the fast path) without
 *    holding the grant lock.
 *
 * 2. Racy scans. @active_rpcs is not kept in sorted order (the order can
 *    change frequently as packets arrive, and re-ordering would require
 *    the grant lock). Instead, several operations must scan all of the
 *    entries in @active_rpcs (e.g., to decide what priority level to
 *    use in an outgoing grant).  The size of @active_rpcs is relatively
 *    small, so this is not very expensive. However, fast-path operations
 *    do the scanning without holding the grant lock, which means that
 *    @active_rpcs could be undergoing updates as it is being scanned.
 *    These racy scans tolerate concurrent updates: the worst that can
 *    happen is for a suboptimal priority to be used in a grant.
 *
 * 3. Locking issues. Several operations require both the grant lock and
 *    and an RPC lock. The locking order requires that the grant lock
 *    be acquired first, but it is often the case that an RPC lock
 *    is already held when a need for the grant lock arises. When this
 *    happens the RPC lock may have to be temporarily dropped while
 *    acquiring the grant lock.
 *
 *    Anytime that the lock on an RPC is not held, some other entity could
 *    acquire the lock and end the RPC. Once that has happened, we must
 *    be very careful not to perform any state updates that undo the
 *    cleanups performed by homa_rpc_end.
 *
 *    Unfortunately there are quite a few places in this module where RPC
 *    locks get released and reacquired. Rather than trying to deal with
 *    dead RPCs everywhere an RPC lock is acquired, we assume that an RPC
 *    could be dead at any point. Any state change that is disallowed for
 *    dead RPCs (such as adding to @active_rpcs or the priority queues, or
 *    updating @rec_incoming in an RPC) must skip its updates if that is the
 *    case. This code can be found by searching for places whrere the
 *    RPC_GRANTABLE flag is tested; this flag gets turned off when an
 *    RPC is ended. Note that code that removes an RPC from the granting
 *    structures is safe even after death, so no checks are needed there.
 */

#ifndef __STRIP__ /* See strip.py */
/* Used to enable sysctl access to grant-specific configuration parameters. The
 * @data fields are actually offsets within a struct homa_grant; these are
 * converted to pointers into a net-specific struct grant later.
 */
#define OFFSET(field) ((void *)offsetof(struct homa_grant, field))
static struct ctl_table grant_ctl_table[] = {
	{
		.procname	= "fifo_grant_increment",
		.data		= OFFSET(fifo_grant_increment),
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_grant_dointvec
	},
	{
		.procname	= "grant_fifo_fraction",
		.data		= OFFSET(fifo_fraction),
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_grant_dointvec
	},
	{
		.procname	= "max_grantable_rpcs",
		.data		= OFFSET(max_grantable_rpcs),
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_grant_dointvec
	},
	{
		.procname	= "max_incoming",
		.data		= OFFSET(max_incoming),
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_grant_dointvec
	},
	{
		.procname	= "max_overcommit",
		.data		= OFFSET(max_overcommit),
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_grant_dointvec
	},
	{
		.procname	= "window",
		.data		= OFFSET(window_param),
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_grant_dointvec
	},
};
#endif /* See strip.py */

/**
 * homa_grant_alloc() - Allocate and initialize a new grant object, which
 * will hold grant management information for @homa.
 * @homa:   The struct homa that the new object is associated with.
 * Return:  A pointer to the new struct grant, or a negative errno.
 */
struct homa_grant *homa_grant_alloc(struct homa *homa)
{
	struct homa_grant *grant;
	int err;
	int i;

	grant = kzalloc(sizeof(*grant), GFP_KERNEL);
	if (!grant)
		return ERR_PTR(-ENOMEM);
	spin_lock_init(&grant->lock);
	grant->lock_time = homa_clock();
	INIT_LIST_HEAD(&grant->grantable_peers);
	for (i = 0; i < HOMA_MAX_GRANTS; i++)
		grant->active_remaining[i] = -1;
	grant->last_grantable_change = grant->lock_time;
	grant->homa = homa;
	grant->max_incoming = 400000;
	grant->window_param = 0;
	grant->max_overcommit = 8;
	grant->fifo_grant_increment = 50000;
	grant->fifo_fraction = 50;

#ifndef __STRIP__ /* See strip.py */
	grant->sysctl_header = register_net_sysctl(&init_net, "net/homa",
						   grant_ctl_table);
	if (!grant->sysctl_header) {
		err = -ENOMEM;
		pr_err("couldn't register sysctl parameters for Homa grants\n");
		goto error;
	}
#endif /* See strip.py */
	homa_grant_update_sysctl_deps(grant);
	return grant;

error:
	homa_grant_free(grant);
	return ERR_PTR(err);
}

/**
 * homa_grant_free() - Cleanup and free the grant object for a Homa
 * transport.
 * @grant:    Object to free; caller must not reference the object
 *            again once this function returns.
 */
void homa_grant_free(struct homa_grant *grant)
{
#ifndef __STRIP__ /* See strip.py */
	if (grant->sysctl_header) {
		unregister_net_sysctl_table(grant->sysctl_header);
		grant->sysctl_header = NULL;
	}
#endif /* See strip.py */
	kfree(grant);
}

/**
 * homa_grant_init_rpc() - Initialize grant-related information for an
 * RPC's incoming message.
 * @rpc:          RPC being initialized. Grant-related fields in msgin
 *                are assumed to be zero.  Must be locked by caller.
 * @unsched:      Number of unscheduled bytes in the incoming message for @rpc.
 */
void homa_grant_init_rpc(struct homa_rpc *rpc, int unsched)
	__must_hold(rpc->bucket->lock)
{
	rpc->msgin.active_ix = -1;
	if (unsched >= rpc->msgin.length)
		unsched = rpc->msgin.length;
	else
		set_bit(RPC_GRANTABLE, &rpc->flags);
	rpc->msgin.granted = unsched;
	rpc->msgin.prev_grant = unsched;
}

/**
 * homa_grant_add_active() - Insert an RPC into @active_rpcs.
 * @grant:  Grant data containing @active_rpcs.
 * @rpc:    RPC to insert.
 * @slot:   Slot in @active_rpcs in which to insert @rpc.
 * Return: NULL if there was room to insert @rpc without ejecting any other
 *         RPC. Otherwise, returns an RPC that must be added to
 *         homa->grantable_peers (could be either @rpc or some other RPC
 *         that @rpc displaced).
 */
void homa_grant_add_active(struct homa_grant *grant, struct homa_rpc *rpc,
			   int slot)
	__must_hold(grant->lock)
	__must_hold(rpc->bucket->lock)
{
	if (!test_bit(RPC_GRANTABLE, &rpc->flags))
		return;
	grant->active_rpcs[slot].rpc = rpc;
	grant->active_rpcs[slot].peer = rpc->peer;
	grant->active_rpcs[slot].birth = rpc->msgin.birth;
	grant->active_remaining[slot] = rpc->msgin.bytes_remaining;
	rpc->peer->active_rpcs++;
	grant->num_active++;
	grant->window = grant->windows[grant->num_active];
	rpc->msgin.active_ix = slot;
}

/**
 * homa_grant_remove_active() - Remove an RPC from active_rpcs.
 * @grant:  Overall grant information.
 * @slot:   Index of slot in @active_rpcs that should be vacated. Must
 *          currently be occupied.
 */
void homa_grant_remove_active(struct homa_grant *grant, int slot)
	__must_hold(grant->lock)
	__must_hold(rpc->bucket->lock)
{
	grant->active_rpcs[slot].rpc->msgin.active_ix = -1;
	grant->active_rpcs[slot].rpc = NULL;
	grant->active_rpcs[slot].peer->active_rpcs--;
	grant->active_remaining[slot] = -1;
	grant->num_active--;
	grant->window = grant->windows[grant->num_active];
	clear_bit(slot, &grant->needy_active);
}

/**
 * homa_grant_outranks() - Returns nonzero if rpc1 should be considered
 * higher priority for grants than rpc2, and zero if the two RPCS are
 * equivalent or rpc2 is higher priority.
 * @rpc1:     First RPC to consider.
 * @rpc2:     Second RPC to consider.
 * Return: see above
 */
int homa_grant_outranks(struct homa_rpc *rpc1, struct homa_rpc *rpc2)
{
	/* The primary criterion is number of unreceived bytes in the
	 * message. Secondary choice is message age (so "full size" messages
	 * will be received in FIFO order).
	 *
	 * An earlier version of Homa used ungranted bytes instead of
	 * unreceived bytes, but this resulted in priority inversion:
	 * - Message A arrives from a host with length 1000000; 800000 bytes
	 *   are granted immediately, leaving 200000 ungranted
	 * - Message B arrives from the same host with length 400000, of which
	 *   300000 bytes are ungranted.
	 * - If there is room for only one active message from that host,
	 *   it will be message A.
	 * - As a result, message B won't be granted until message A completes;
	 *   if the sender's SRPT mechanism chooses not to transmit A, then
	 *   B won't be transmitted either.
	 */
	int rem_diff;

	rem_diff = rpc1->msgin.bytes_remaining - rpc2->msgin.bytes_remaining;
	return rem_diff < 0 || ((rem_diff == 0) &&
				(rpc1->msgin.birth < rpc2->msgin.birth));
}

/**
 * homa_grant_priority() - Return the appropriate priority to use in a
 * grant for an incoming message.
 * @homa:     Overall information about the Homa transport.
 * @rank:     The number of RPCs with higher grant priority than the
 *            RPC being granted.
 * Return:    See above.
 */
int homa_grant_priority(struct homa *homa, int rank)
{
	int max_sched_prio, extra_levels, priority;

	/* If there aren't enough active RPCs to consume all of the priority
	 * levels, use only the lower levels; this allows faster preemption
	 * if a new high-priority message appears.
	 */
	max_sched_prio = homa->max_sched_prio;
	priority = max_sched_prio - rank;
	extra_levels = max_sched_prio + 1 - homa->grant->num_active;
	if (extra_levels >= 0)
		priority -= extra_levels;
	return (priority < 0) ? 0 : priority;
}

/**
 * homa_grant_find_victim() - Scan the RPCs in @active_rpcs to identify
 * a slot to use for a new RPC.
 * @grant:      Overall information about grants
 * @rpc:        RPC that is being proposed for insertion into @active_rpcs
 * Return:      Index of a slot to replace (which may be empty), or -1 if
 *              all slots are in use and all have prioritiy greater than @rpc.
 */
int homa_grant_find_victim(struct homa_grant *grant, struct homa_rpc *rpc)
	__must_hold(grant->lock)
{
	int lp, lp_remaining, i, cand_remaining;
	int lp_peer_active, cand_peer_active;
	struct homa_peer *cand_peer;

	/* Scan all slots to find the lowest priority one ("lp"), according
	 * to the following considerations:
	 * - Prefer an empty slot if available.
	 * - Prefer slot with lowest SRPT priority.
	 * - However, if there are peers with multiple RPCs in @active_rpcs,
	 *   choose a victim from one of the peers with the highest
	 *   number of RPCs in @active_rpcs.
	 */
	lp = -1;
	lp_peer_active = 0;
	for (i = 0; i < grant->max_overcommit; i++) {
		cand_remaining = READ_ONCE(grant->active_remaining[i]);
		if (cand_remaining < 0)
			return i;
		cand_peer = grant->active_rpcs[i].peer;
		cand_peer_active = cand_peer->active_rpcs;
		if (cand_peer == rpc->peer)
			/* This increment reflects the state if both this
			 * RPC and @rpc are active.
			 */
			cand_peer_active++;
		if (cand_peer_active != lp_peer_active) {
			if (cand_peer_active > lp_peer_active) {
				lp = i;
				lp_peer_active = cand_peer_active;
				lp_remaining = cand_remaining;
			}
			continue;
		}
		if (lp_remaining > cand_remaining)
			continue;
		if ((lp_remaining == cand_remaining) &&
		    (grant->active_rpcs[lp].birth >
		     grant->active_rpcs[i].birth))
			continue;
		lp = i;
		lp_peer_active = cand_peer_active;
		lp_remaining = cand_remaining;
	}

	/* We now have a non-empty "lp" slot; see if it has lower priority
	 * than @rpc. Note: when we get here, lp can't have a smaller
	 * peer_active than rpc (if it did, we would have chosen a
	 * different lp).
	 */
	if (lp_peer_active > (rpc->peer->active_rpcs + 1))
		return lp;
	if ((grant->active_remaining[lp] > rpc->msgin.bytes_remaining))
		return lp;
	if (grant->active_remaining[lp] < rpc->msgin.bytes_remaining)
		return -1;
	if ((grant->active_rpcs[lp].birth > rpc->msgin.birth))
		return lp;
	return -1;
}

/**
 * homa_grant_adjust_peer() - This function is invoked when the contents
 * of a peer's grantable_rpcs list has changed, so it's possible that
 * the position of this peer in grantable_peers is no longer correct. The
 * function adjusts the position of peer in grantable_peers (which could
 * include adding or removing the peer to/from grantable_peers).
 * @grant:         Overall information about grants
 * @peer:          Peer to adjust
 */
void homa_grant_adjust_peer(struct homa_grant *grant, struct homa_peer *peer)
	__must_hold(&grant->lock)
{
	struct homa_rpc *head, *other_rpc;
	struct homa_peer *other_peer;

	if (list_empty(&peer->grantable_rpcs)) {
		list_del_init(&peer->grantable_links);
		return;
	}

	head = list_first_entry(&peer->grantable_rpcs,
				struct homa_rpc, grantable_links);
	if (list_empty(&peer->grantable_links)) {
		/* Must add peer to grantable_peers. */
		list_for_each_entry(other_peer, &grant->grantable_peers,
				    grantable_links) {
			other_rpc = list_first_entry(&other_peer->grantable_rpcs,
						     struct homa_rpc,
						     grantable_links);
			if (homa_grant_outranks(head, other_rpc)) {
				list_add_tail(&peer->grantable_links,
					      &other_peer->grantable_links);
				return;
			}
		}
		list_add_tail(&peer->grantable_links, &grant->grantable_peers);
		return;
	}

	/* The peer is on grantable_peers; this loop moves it upward, if
	 * needed.
	 */
	while (peer != list_first_entry(&grant->grantable_peers,
					struct homa_peer, grantable_links)) {
		other_peer = list_prev_entry(peer, grantable_links);
		other_rpc = list_first_entry(&other_peer->grantable_rpcs,
					     struct homa_rpc, grantable_links);
		if (!homa_grant_outranks(head, other_rpc))
			break;
		__list_del_entry(&other_peer->grantable_links);
		list_add(&other_peer->grantable_links, &peer->grantable_links);
	}

	/* This loop moves the peer downward in grantable_peers, if needed. */
	while (peer != list_last_entry(&grant->grantable_peers,
				       struct homa_peer, grantable_links)) {
		other_peer = list_next_entry(peer, grantable_links);
		other_rpc = list_first_entry(&other_peer->grantable_rpcs,
					     struct homa_rpc, grantable_links);
		if (!homa_grant_outranks(other_rpc, head))
			break;
		__list_del_entry(&peer->grantable_links);
		list_add(&peer->grantable_links, &other_peer->grantable_links);
	}
}

/**
 * homa_grant_insert_grantable() - Insert an RPC into the grantable list
 * for its peer.
 * @grant:  Overall grant management information.
 * @rpc:    The RPC to add. Must not currently be in either active_rpcs
 *          or grantable_peers.
 */
void homa_grant_insert_grantable(struct homa_grant *grant, struct homa_rpc *rpc)
	__must_hold(rpc->hsk->homa->grant->lock)
{
	struct homa_peer *peer = rpc->peer;
	struct homa_rpc *other;

	if (!test_bit(RPC_GRANTABLE, &rpc->flags))
		return;

	/* Insert @rpc in the right place in the grantable_rpcs list for
	 * its peer.
	 */
	list_for_each_entry(other, &peer->grantable_rpcs, grantable_links) {
		if (homa_grant_outranks(rpc, other)) {
			list_add_tail(&rpc->grantable_links,
				      &other->grantable_links);
			goto position_peer;
		}
	}
	list_add_tail(&rpc->grantable_links, &peer->grantable_rpcs);

position_peer:
	homa_grant_adjust_peer(grant, peer);
}

/**
 * homa_grant_remove_grantable() - Unlink an RPC from the grantable lists.
 * @grant:   Overall information about grants
 * @rpc:     RPC to remove from grantable lists.  Must currently be in
 *           a grantable list.
 */
void homa_grant_remove_grantable(struct homa_grant *grant, struct homa_rpc *rpc)
	__must_hold(grant->lock)
	__must_hold(rpc->bucket->lock)
{
	struct homa_peer *peer = rpc->peer;
	struct homa_rpc *head;

	head =  list_first_entry(&peer->grantable_rpcs,
				 struct homa_rpc, grantable_links);
	list_del_init(&rpc->grantable_links);
	if (rpc == head)
		homa_grant_adjust_peer(grant, peer);
}

/**
 * homa_grant_manage_rpc() - Insert an RPC into the priority-based data
 * structures for managing grantable RPCs (active_rpcs or grantable_peers).
 * Ensures that the RPC will eventually be sent grants.
 * @grant:  Overall grant management information.
 * @rpc:    The RPC to add. Must be locked and referenced by caller. The
 *          RPC is temporarily unlocked by this function, so it may be
 *          dead on return.
 */
void homa_grant_manage_rpc(struct homa_grant *grant, struct homa_rpc *rpc)
	__must_hold(rpc->bucket->lock)
{
	struct homa_rpc *bumped;
	u64 time;
	int slot;

	homa_rpc_unlock(rpc);
	/* In this gap, another core can call this function, so that rpc
	 * is actually managed by the time we acquire the grant lock. In
	 * addition, rpc can potentially be dead by the time the rpc
	 * lock is reacquired below.
	 */
	homa_grant_lock(grant);

	/* See if there is an active slot available, or if an existing active
	 * RPC can be demoted.
	 */
	slot = homa_grant_find_victim(grant, rpc);
	if (slot >= 0) {
		/* If the victim slot was occupied, move its RP
		 * from @active_rpcs to a grantable list.
		 */
		bumped = grant->active_rpcs[slot].rpc;
		if (bumped) {
			homa_rpc_lock(bumped);
			homa_grant_remove_active(grant, slot);
			homa_grant_insert_grantable(grant, bumped);
			homa_rpc_unlock(bumped);
		}
	}
	homa_rpc_lock(rpc);

	/* Now that we have both the RPC lock and the grant lock, recheck to
	 * make sure rpc is still alive and unmanaged.
	 */
	if (test_bit(RPC_GRANT_MANAGED, &rpc->flags) ||
	    !test_bit(RPC_GRANTABLE, &rpc->flags)) {
		/* There is no need to insert this RPC after all (but if we
		 * emptied a slot in @active_rpcs we need to refill it).
		 */
		if (slot >= 0) {
			homa_rpc_unlock(rpc);
			homa_grant_promote_queued(grant, slot);
			homa_grant_unlock(grant);
			homa_rpc_lock(rpc);
		} else {
			homa_grant_unlock(grant);
		}
		return;
	}

	if (slot >= 0)
		homa_grant_add_active(grant, rpc, slot);
	else
		homa_grant_insert_grantable(grant, rpc);
	set_bit(RPC_GRANT_MANAGED, &rpc->flags);

	/* Update statistics. */
	time = homa_clock();
	INC_METRIC(grantable_rpcs_integral, grant->num_grantable_rpcs *
		   (time - grant->last_grantable_change));
	grant->last_grantable_change = time;
	grant->num_grantable_rpcs++;
	tt_record2("Incremented num_grantable_rpcs to %d, id %d",
		   grant->num_grantable_rpcs, rpc->id);
	if (grant->num_grantable_rpcs > grant->max_grantable_rpcs)
		grant->max_grantable_rpcs = grant->num_grantable_rpcs;
	homa_grant_unlock(grant);
}

/**
 * homa_grant_unmanage_rpc() - Make sure that an RPC is no longer present
 * in the priority structures used to manage grants (active_rpcs and
 * grantable_rpcs). The RPC will no longer receive grants. If a slot in
 * @active_rpcs is opened up, this function will try to promote an RPC
 * from the grantable lists.
 * @rpc:     RPC to unlink. Gets unlocked temporarily by this function,
 *           so may be dead on return.
 */
void homa_grant_unmanage_rpc(struct homa_rpc *rpc)
	__must_hold(rpc->bucket->lock)
{
	struct homa_grant *grant;
	bool removed = false;

	if (!test_bit(RPC_GRANTABLE, &rpc->flags))
		return;

	grant = rpc->hsk->homa->grant;
	homa_grant_add_lock(grant, rpc);

	clear_bit(RPC_GRANTABLE, &rpc->flags);
	clear_bit(RPC_GRANT_MANAGED, &rpc->flags);

	if (rpc->msgin.active_ix >= 0) {
		int slot = rpc->msgin.active_ix;

		homa_grant_remove_active(grant, slot);
		removed = true;
		if (!list_empty(&grant->grantable_peers)) {
			homa_rpc_unlock(rpc);
			homa_grant_promote_queued(grant, slot);
			homa_rpc_lock(rpc);
		}
	} else if (!list_empty(&rpc->grantable_links)) {
		homa_grant_remove_grantable(grant, rpc);
		removed = true;
	}
	if (removed) {
		u64 time = homa_clock();

		INC_METRIC(grantable_rpcs_integral, grant->num_grantable_rpcs
				* (time - grant->last_grantable_change));
		grant->last_grantable_change = time;
		grant->num_grantable_rpcs--;
		tt_record2("Decremented num_grantable_rpcs to %d, id %d",
			   grant->num_grantable_rpcs, rpc->id);
	}
	if (rpc == grant->oldest_rpc) {
		homa_rpc_put(rpc);
		grant->oldest_rpc = NULL;
	}
	if (rpc->msgin.rec_incoming != 0) {
		atomic_sub(rpc->msgin.rec_incoming, &grant->total_incoming);
		rpc->msgin.rec_incoming = 0;
	}

	homa_grant_unlock(grant);
}

/**
 * homa_grant_promote_queued() - This function is invoked when a slot
 * becomes available in @active_rpcs. It checks to see if there are any
 * queued RPCs; if so, it promotes the highest-priority one into the slot.
 * @grant:       Overall information about granting, such as @active_rpcs.
 * @slot:        Slot in @grant->active_rpcs that is unoccupied.
 */
void homa_grant_promote_queued(struct homa_grant *grant, int slot)
	__must_hold(grant->lock)
{
	struct homa_peer *peer, *best_peer;
	struct homa_rpc *rpc;
	int best_active;

	/* Priority for choice: first choose from peer with fewest active
	 * RPCs; then pick peer with highest SRPT priority (closest to front
	 * of list).
	 */
	best_peer = NULL;
	best_active = 1000;
	list_for_each_entry(peer, &grant->grantable_peers, grantable_links) {
		if (peer->active_rpcs == 0) {
			best_peer = peer;
			break;
		}
		if (peer->active_rpcs < best_active) {
			best_active = peer->active_rpcs;
			best_peer = peer;
		}
	}
	if (!best_peer)
		return;
	rpc =	list_first_entry(&best_peer->grantable_rpcs, struct homa_rpc,
				 grantable_links);
	homa_rpc_lock(rpc);
	homa_grant_remove_grantable(grant, rpc);
	homa_grant_add_active(grant, rpc, slot);
	set_bit(slot, &grant->needy_active);
	homa_rpc_unlock(rpc);
}

/**
 * homa_grant_promote_rpc() - This function is invoked when the grant priority
 * of an inactive RPC may have increased (e.g., because data packets arrived);
 * it adjusts the position of the RPC within the grantable lists and may
 * promote it into grant->active_rpcs.
 * @grant:  Overall grant management information.
 * @rpc:    The RPC to consider for promotion. Must currently be managed for
 *          grants. The lock may be released and reacquired.
 */
void homa_grant_promote_rpc(struct homa_grant *grant, struct homa_rpc *rpc)
	__must_hold(rpc->bucket->lock)
{
	struct homa_peer *peer = rpc->peer;
	struct homa_rpc *other, *victim;
	int slot;

	homa_grant_add_lock(grant, rpc);
	if (list_empty(&rpc->grantable_links))
		goto done;

	/* Promote within the grantable list for its peer. */
	while (rpc != list_first_entry(&peer->grantable_rpcs,
				       struct homa_rpc, grantable_links)) {
		other = list_prev_entry(rpc, grantable_links);
		if (!homa_grant_outranks(rpc, other))
			goto done;
		list_del(&rpc->grantable_links);
		list_add_tail(&rpc->grantable_links, &other->grantable_links);
	}

	/* If the RPC is now the highest priority one for its peer, see if
	 * it can be promoted into active_rpcs.
	 */
	if (rpc != list_first_entry(&peer->grantable_rpcs,
				    struct homa_rpc, grantable_links))
		goto done;

	/* The RPC is now the highest priority one for its peer; see if
	 * it can be promoted into active_rpcs.
	 */
	slot = homa_grant_find_victim(grant, rpc);
	if (slot >= 0) {
		victim = grant->active_rpcs[slot].rpc;
		if (victim) {
			homa_rpc_unlock(rpc);
			homa_rpc_lock(victim);
			homa_grant_remove_active(grant, slot);
			homa_grant_insert_grantable(grant, victim);
			homa_rpc_unlock(victim);
			homa_rpc_lock(rpc);
		}
		homa_grant_remove_grantable(grant, rpc);
		homa_grant_add_active(grant, rpc, slot);
	} else {
		/* See if the peer can be promoted in the global list. */
		homa_grant_adjust_peer(grant, peer);
	}

done:
	homa_grant_unlock(grant);
}

/**
 * homa_grant_update_incoming() - Figure out how much incoming data there is
 * for an RPC (i.e., data that has been granted but not yet received) and make
 * sure this is properly reflected in rpc->msgin.incoming and
 * homa->total_incoming. Also, if the RPC is not in @active_rpcs and its grant
 * priority has changed, see if it can be promoted into @active_rpcs
 * @rpc:    RPC to check; must be locked.
 * @grant:  Grant information for a Homa transport.
 */
void homa_grant_update_incoming(struct homa_grant *grant, struct homa_rpc *rpc)
	__must_hold(rpc->bucket->lock)
{
	int incoming, delta;

	incoming = rpc->msgin.granted - (rpc->msgin.length -
					 rpc->msgin.bytes_remaining);
	if (incoming < 0)
		incoming = 0;
	delta = incoming - rpc->msgin.rec_incoming;
	if (delta != 0 && test_bit(RPC_GRANTABLE, &rpc->flags)) {
		atomic_add(delta, &grant->total_incoming);
		rpc->msgin.rec_incoming = incoming;
		if (rpc->msgin.active_ix < 0)
			homa_grant_promote_rpc(rpc->hsk->homa->grant, rpc);
	}
}

/**
 * homa_grant_send() - Issue a GRANT packet for the current grant offset
 * of an incoming RPC.
 * @rpc:      RPC for which to issue GRANT. Should not be locked (to
 *            minimize lock contention, since sending a packet is slow),
 *            but caller must hold a reference to keep it from being reaped.
 *            The msgin.resend_all field will be cleared.
 * @priority: Priority level to use for the grant.
 */
void homa_grant_send(struct homa_rpc *rpc, int priority)
{
	struct homa_grant_hdr grant;

	grant.offset = htonl(rpc->msgin.granted);
	grant.priority = priority;
	tt_record4("sending grant for id %d, offset %d, priority %d, increment %d",
		   rpc->id, rpc->msgin.granted, grant.priority,
		   rpc->msgin.granted - rpc->msgin.prev_grant);
	rpc->msgin.prev_grant = rpc->msgin.granted;
	homa_xmit_control(GRANT, &grant, sizeof(grant), rpc);
}

/**
 * homa_grant_try_send() - Send a grant to an RPC, if needed and appropriate.
 * If the RPC is ready for a grant but we can't send one now (because of
 * needy RPCs or insufficient headroom), add the RPC to grant->needy_active.
 * This function also takes care of sending FIFO grants as needed.
 * @grant:        Overall information about grants.
 * @rpc:          RPC to check; must be in grant->active_rpcs.
 * @check_needy:  True means don't issue a grant if there are needy RPCs.
 *                False means don't consider grant->needy_active.
 */
void homa_grant_try_send(struct homa_grant *grant, struct homa_rpc *rpc,
			 bool check_needy)
	__must_hold(rpc->bucket->lock)
{
	int i, received, delta, avl_incoming, rank;
	int birth, cand_remaining, other_remaining;
	bool fully_granted = false;

	if (!test_bit(RPC_GRANTABLE, &rpc->flags))
		return;

	/* See if we can issue a new grant for the RPC. */
	received = rpc->msgin.length - rpc->msgin.bytes_remaining;
	delta = received + grant->window - rpc->msgin.granted;
	if (delta <= 0)
	        /* The RPC already has a full window of grant. */
		return;
	if (delta > (rpc->msgin.length - rpc->msgin.granted))
		delta = rpc->msgin.length - rpc->msgin.granted;
	avl_incoming = grant->max_incoming -
		       atomic_read(&grant->total_incoming);
	if (avl_incoming <= 0 ||
	    (check_needy && grant->needy_active != 0))
	        /* Can't grant to this RPC: either no headroom in incoming
		 * or needy RPCs might have priority.
		 */
		goto needy;
	if (delta > avl_incoming)
		delta = avl_incoming;
	else
		fully_granted = true;
	rpc->msgin.granted += delta;
	rpc->msgin.rec_incoming += delta;
	atomic_add(delta, &grant->total_incoming);

	/* Scan the active RPCs to compute rpc's rank (how many active RPCs
	 * have higher grant priority). This is racy in that the priority
	 * information for other RPCs could be changing as we access it.
	 * That's OK, though: the worst that can happen is to compute
	 * a suboptimal priority.
	 */
	rank = 0;
	cand_remaining = rpc->msgin.bytes_remaining;
	birth = rpc->msgin.birth;
	for (i = 0; i < HOMA_MAX_GRANTS; i++) {
		if (!grant->active_rpcs[i].rpc ||
		    grant->active_rpcs[i].rpc == rpc)
			continue;
		other_remaining = READ_ONCE(grant->active_remaining[i]);
		if (cand_remaining < other_remaining)
			continue;
		if (cand_remaining == other_remaining &&
		    birth <= grant->active_rpcs[i].birth)
			continue;
		rank++;
	}

	/* Sending a grant takes a long time, so release the RPC lock to
	 * allow others to use the RPC. This is also a convenient time to check
	 * for FIFO grants, since that requires us to release the lock also.
	 */
	homa_rpc_unlock(rpc);
	homa_grant_send(rpc, homa_grant_priority(grant->homa, rank));
	homa_grant_check_fifo(grant);
	homa_rpc_lock(rpc);

needy:
	if (!fully_granted)
		set_bit(rpc->msgin.active_ix, &grant->needy_active);
}

/**
 * homa_grant_check_needy() - If there is available headroom for grants and
 * there are RPCs in @needy_active, apply the headroom to those RPCs in
 * priority order.
 * @grant:    Grant management info. Must not be locked (and caller must
 *            not hold any RPC locks).
 */
void homa_grant_check_needy(struct homa_grant *grant)
{
	int i, cand_remaining, best, best_remaining;
	struct homa_rpc *rpc;

	while (1) {
		if (atomic_read(&grant->total_incoming) >= grant->max_incoming)
			return;
		if (READ_ONCE(grant->needy_active) == 0)
			return;

		/* Need the grant lock to make sure RPCs don't get removed
		 * from @active_rpcs until after we have acquired the lock
		 * for a needy RPC; otherwise RPCs could get deleted from
		 * under us.
		 */
		homa_grant_lock(grant);

		/* Find the highest-priority needy RPC. */
		best = -1;
		best_remaining = HOMA_MAX_MESSAGE_LENGTH + 1;
		for (i = 0; i < HOMA_MAX_GRANTS; i++) {
			if (!test_bit(i, &grant->needy_active))
				continue;
			cand_remaining = READ_ONCE(grant->active_remaining[i]);
			if (cand_remaining > best_remaining)
				continue;
			if (cand_remaining == best_remaining &&
			    grant->active_rpcs[i].birth >
			    grant->active_rpcs[best].birth)
				continue;
			best = i;
			best_remaining = cand_remaining;
		}

		if (best < 0) {
			/* Racing threads must have taken care of all needy. */
			homa_grant_unlock(grant);
			return;
		}
		rpc = grant->active_rpcs[best].rpc;

		/* We need to take a reference on rpc to ensure that it stays
		 * alive through the call to homa_grant_try_send. Otherwise,
		 * once we release the grant lock, it could be removed from
		 * @active_rpcs, leaving it unprotected against reaping.
		 */
		homa_rpc_hold(rpc);
		homa_rpc_lock(rpc);
		homa_grant_unlock(grant);
		clear_bit(best, &grant->needy_active);
		homa_grant_try_send(grant, rpc, false);
		INC_METRIC(needy_grants, 1);
		homa_rpc_unlock(rpc);
		homa_rpc_put(rpc);
	}
}

/**
 * homa_grant_check_rpc() - This is the primary function invoked by code
 * outside this module. It is responsible for updating grant state and issuing
 * grant packets.  It is invoked when the state of an RPC has changed in
 * ways that might permit grants to be issued (either to this RPC or other
 * RPCs), such as the arrival of a DATA packet.
 * @rpc:    RPC to check. Must be locked by the caller. The lock may get
 *          released and reacquired, which means it's possible that the
 *          RPC will be dead on return.
 */
void homa_grant_check_rpc(struct homa_rpc *rpc)
	__must_hold(rpc->bucket->lock)
{
	struct homa_grant *grant = rpc->hsk->homa->grant;

	if (!test_bit(RPC_GRANTABLE, &rpc->flags))
		return;

	tt_record4("homa_grant_check_rpc starting for id %d, granted %d, remaining %d, length %d",
		   rpc->id, rpc->msgin.granted, rpc->msgin.bytes_remaining,
		   rpc->msgin.length);
	INC_METRIC(grant_check_calls, 1);

	if (rpc->msgin.bytes_remaining == 0) {
		homa_grant_unmanage_rpc(rpc);
		goto check_needy;
	}

	/* In theory it would be possible to call homa_grant_manage_rpc from
	 * homa_grant_init_rpc, which would eliminate the need for this check.
	 * However, homa_grant_manage_rpc may have to release the RPC lock,
	 * which could allow the RPC to be killed, and that would create
	 * extra complexity in the contexts where homa_grant_init_rpc is
	 * invoked. Thus it's cleaner to do it here, since we already have
	 * to deal with the consequences of releasing the RPC lock.
	 */
	if (!test_bit(RPC_GRANT_MANAGED, &rpc->flags)) {
		if (rpc->msgin.num_bpages <= 0)
			goto check_needy;
		homa_grant_manage_rpc(grant, rpc);
	}

	homa_grant_update_incoming(grant, rpc);
	if (rpc->msgin.active_ix >= 0)
		homa_grant_try_send(grant, rpc, true);

check_needy:
	if (grant->needy_active != 0) {
		homa_rpc_unlock(rpc);
		homa_grant_check_needy(grant);
		homa_rpc_lock(rpc);
	}
	tt_record2("homa_grant_check_rpc finished with id %d, total_incoming %d",
		   rpc->id, atomic_read(&grant->total_incoming));
}

/**
 * homa_grant_find_oldest() - Recompute the value of homa->grant->oldest_rpc.
 * @grant:      Overall grant management information. @grant->oldest_rpc
 *              must be NULL.
 */
void homa_grant_find_oldest(struct homa_grant *grant)
	__must_hold(grant->lock)
{
	int max_incoming = grant->window +  2 * grant->fifo_grant_increment;
	struct homa_rpc *rpc, *oldest;
	struct homa_peer *peer;
	u64 oldest_birth;
	int i;

	oldest = NULL;
	oldest_birth = ~0;

	/* Check the grantable lists. */
	list_for_each_entry(peer, &grant->grantable_peers, grantable_links) {
		list_for_each_entry(rpc, &peer->grantable_rpcs,
				    grantable_links) {
			if (rpc->msgin.birth >= oldest_birth)
				continue;
			if (rpc->msgin.rec_incoming >= max_incoming) {
				/* This RPC has been granted way more bytes
				 * than the grant window. This can only
				 * happen for FIFO grants, and it means the
				 * peer isn't responding to grants we've sent.
				 * Pick a different "oldest" RPC.
				 */
				continue;
			}
			if (rpc->msgin.granted >= rpc->msgin.length)
				continue;
			oldest = rpc;
			oldest_birth = rpc->msgin.birth;
		}
	}

	/* Check the active RPCs. */
	for (i = 0; i < HOMA_MAX_GRANTS; i++) {
		rpc = grant->active_rpcs[i].rpc;
		if (!rpc)
			continue;
		if (rpc->msgin.birth >= oldest_birth)
			continue;
		if (rpc->msgin.rec_incoming >= max_incoming)
			continue;
		if (rpc->msgin.granted >= rpc->msgin.length)
			continue;
		oldest = rpc;
		oldest_birth = rpc->msgin.birth;
	}

	if (oldest) {
		homa_rpc_hold(oldest);
		tt_record1("homa_grant_find_oldest chose id %d", oldest->id);
	}
	grant->oldest_rpc = oldest;
}

/**
 * homa_grant_check_fifo() - Check to see if it is time to make the next
 * FIFO grant; if so, make the grant. FIFO grants keep long messages from
 * being starved by Homa's SRPT grant mechanism.
 * @grant:      Overall grant management information.
 */
void homa_grant_check_fifo(struct homa_grant *grant)
{
	struct homa_rpc *rpc;
	int old_granted;
	u64 now;

	/* Note: placing this check before locking saves lock overhead
	 * in the normal case where it's not yet time for the next FIFO
	 * grant. This results in a race (2 cores could simultaneously
	 * decide to make FIFO grants) but that is relatively harmless
	 * (an occasional extra FIFO grant).
	 */
	now = homa_clock();
	if (now < grant->fifo_grant_time)
		return;
	homa_grant_lock(grant);
	grant->fifo_grant_time = now + grant->fifo_grant_interval;
	if (grant->fifo_fraction == 0 || grant->fifo_grant_increment == 0) {
		homa_grant_unlock(grant);
		return;
	}

	/* See if there is an RPC to grant. */
	rpc = grant->oldest_rpc;
	if (rpc) {
		/* If the oldest RPC hasn't been responding to FIFO grants
		 * then switch to a different RPC. Also switch if the oldest
		 * RPC is fully granted.
		 */
		int max_incoming = grant->window + 2 *
				   grant->fifo_grant_increment;
		if (rpc->msgin.rec_incoming >= max_incoming ||
		    rpc->msgin.granted >= rpc->msgin.length) {
			grant->oldest_rpc = NULL;
			homa_rpc_put(rpc);
			rpc = NULL;
		}
	}
	if (!rpc) {
		homa_grant_find_oldest(grant);
		rpc = grant->oldest_rpc;
		if (!rpc) {
			homa_grant_unlock(grant);
			return;
		}
	}

	/* Need the RPC lock to send a grant; can release the grant lock
	 * once the RPC has been locked. We must take a reference on the
	 * RPC, because the RPC will be unlocked at various points below;
	 * without the reference, the RPC could be killed.
	 */
	homa_rpc_lock(rpc);
	homa_grant_unlock(grant);
	if (rpc->state == RPC_DEAD) {
		homa_rpc_unlock(rpc);
		return;
	}
	homa_rpc_hold(rpc);
	old_granted = rpc->msgin.granted;
	rpc->msgin.granted += grant->fifo_grant_increment;
	if (rpc->msgin.granted >= rpc->msgin.length)
		rpc->msgin.granted = rpc->msgin.length;
	INC_METRIC(fifo_grant_bytes, rpc->msgin.granted - old_granted);
	tt_record3("homa_grant_check_fifo granted %d more bytes to id %d, granted now %d",
		   rpc->msgin.granted - old_granted, rpc->id, rpc->msgin.granted);
	homa_grant_update_incoming(grant, rpc);
	homa_rpc_unlock(rpc);
	homa_grant_send(rpc, homa_high_priority(grant->homa));
	homa_rpc_put(rpc);
}

/**
 * homa_grant_lock_slow() - This function implements the slow path for
 * acquiring the grant lock. It is invoked when the lock isn't immediately
 * available. It waits for the lock, but also records statistics about
 * the waiting time.
 * @grant:    Grant management information.
 */
void homa_grant_lock_slow(struct homa_grant *grant)
	__acquires(grant->lock)
{
	u64 start = homa_clock();

	tt_record("beginning wait for grant lock");
	spin_lock_bh(&grant->lock);
	tt_record("ending wait for grant lock");
	INC_METRIC(grant_lock_misses, 1);
	INC_METRIC(grant_lock_miss_cycles, homa_clock() - start);
}

/**
 * homa_grant_update_sysctl_deps() - Invoked whenever a sysctl value is changed;
 * updates variables that depend on sysctl-settable values.
 * @grant:    Structure in which to update information.
 */
void homa_grant_update_sysctl_deps(struct homa_grant *grant)
{
	u64 fifo_mbps, clocks_per_fifo_mbit, interval;
	int i;

	if (grant->max_overcommit > HOMA_MAX_GRANTS)
		grant->max_overcommit = HOMA_MAX_GRANTS;

	if (grant->fifo_fraction > 500)
		grant->fifo_fraction = 500;
	fifo_mbps = (u64)grant->homa->link_mbps * grant->fifo_fraction;
	do_div(fifo_mbps, 1000);
	if (fifo_mbps > 0 && grant->fifo_grant_increment > 0) {
		clocks_per_fifo_mbit = 1000 * homa_clock_khz();
		do_div(clocks_per_fifo_mbit, fifo_mbps);
		interval = clocks_per_fifo_mbit * grant->fifo_grant_increment *
			   8;
		do_div(interval, 1000000);
		grant->fifo_grant_interval = interval;
	} else {
		grant->fifo_grant_interval = 1000 * homa_clock_khz();
	}

	/* Dynamic window sizing uses the approach described in the paper
	 * "Dynamic Queue Length Thresholds for Shared-Memory Packet Switches"
	 * with an alpha value of 1. The idea is to maintain unused incoming
	 * capacity (for new RPC arrivals) equal to the amount of incoming
	 * allocated to each of the currently active RPCs.
	 */
	for (i = 0; i <= HOMA_MAX_GRANTS; i++) {
		if (grant->window_param != 0) {
			grant->windows[i] = grant->window_param;
		} else {
			u64 window;

			window = grant->max_incoming;
			do_div(window, i + 1);
			grant->windows[i] = window;
		}
	}
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_grant_dointvec() - This function is a wrapper around proc_dointvec. It
 * is invoked to read and write grant-related sysctl values.
 * @table:    sysctl table describing value to be read or written.
 * @write:    Nonzero means value is being written, 0 means read.
 * @buffer:   Address in user space of the input/output data.
 * @lenp:     Not exactly sure.
 * @ppos:     Not exactly sure.
 *
 * Return: 0 for success, nonzero for error.
 */
int homa_grant_dointvec(const struct ctl_table *table, int write,
			void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table table_copy;
	struct homa_grant *grant;
	int result;

	grant = homa_net(current->nsproxy->net_ns)->homa->grant;

	/* Generate a new ctl_table that refers to a field in the
	 * net-specific struct homa.
	 */
	table_copy = *table;
	table_copy.data = ((char *)grant) + (uintptr_t)table_copy.data;

	result = proc_dointvec(&table_copy, write, buffer, lenp, ppos);
	if (write)
		homa_grant_update_sysctl_deps(grant);
	return result;
}
#endif /* See strip.py */
