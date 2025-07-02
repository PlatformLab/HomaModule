// SPDX-License-Identifier: BSD-2-Clause

/* This file contains functions related to issuing grants for incoming
 * messages.
 */

#include "homa_impl.h"
#include "homa_grant.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#include "homa_wire.h"

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
		.procname	= "grant_recalc_usecs",
		.data		= OFFSET(recalc_usecs),
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
		.procname	= "max_rpcs_per_peer",
		.data		= OFFSET(max_rpcs_per_peer),
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
 * Return:  A pointer to the new struct grant, or a negative errno.
 */
struct homa_grant *homa_grant_alloc(void)
{
	struct homa_grant *grant;
	int err;

	grant = kzalloc(sizeof(*grant), GFP_KERNEL);
	if (!grant)
		return ERR_PTR(-ENOMEM);
	atomic_set(&grant->stalled_rank, INT_MAX);
	grant->max_incoming = 400000;
	spin_lock_init(&grant->lock);
	INIT_LIST_HEAD(&grant->grantable_peers);
	grant->window_param = 10000;
	grant->max_rpcs_per_peer = 1;
	grant->max_overcommit = 8;
	grant->recalc_usecs = 20;
	grant->fifo_grant_increment = 10000;
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
	grant->next_recalc = homa_clock() + grant->recalc_cycles;
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
 * RPC's incoming message (may add the RPC to grant priority queues).
 * @rpc:          RPC being initialized. Grant-related fields in msgin
 *                are assumed to be zero.  Must be locked by caller.
 * @unsched:      Number of unscheduled bytes in the incoming message for @rpc.
 */
void homa_grant_init_rpc(struct homa_rpc *rpc, int unsched)
	__must_hold(rpc->bucket->lock)
{
	rpc->msgin.rank = -1;
	if (rpc->msgin.num_bpages == 0)
		/* Can't issue grants until buffer space becomes available. */
		return;
	if (unsched >= rpc->msgin.length) {
		rpc->msgin.granted = rpc->msgin.length;
		rpc->msgin.prev_grant = rpc->msgin.granted;
		return;
	}
	rpc->msgin.granted = unsched;
	rpc->msgin.prev_grant = unsched;
	homa_grant_manage_rpc(rpc);
}

/**
 * homa_grant_end_rpc() - This function is invoked when homa_rpc_end is
 * invoked; it cleans up any state related to grants for that RPC's
 * incoming message.
 * @rpc:   The RPC to clean up. Must be locked by the caller. This function
 *         may release and then reacquire the lock.
 */
void homa_grant_end_rpc(struct homa_rpc *rpc)
	__must_hold(rpc->bucket->lock)
{
	struct homa_grant *grant = rpc->hsk->homa->grant;
	struct homa_grant_candidates cand;

	if (rpc->msgin.granted < rpc->msgin.length) {
		homa_grant_cand_init(&cand);
		homa_grant_unmanage_rpc(rpc, &cand);
		if (!homa_grant_cand_empty(&cand)) {
			homa_rpc_hold(rpc);
			homa_rpc_unlock(rpc);
			homa_grant_cand_check(&cand, grant);
			homa_rpc_lock(rpc);
			homa_rpc_put(rpc);
		}
	}

	if (rpc->msgin.rec_incoming != 0) {
		atomic_sub(rpc->msgin.rec_incoming, &grant->total_incoming);
		rpc->msgin.rec_incoming = 0;
	}
}

/**
 * homa_grant_window() - Return the window size (maximum number of granted
 * but not received bytes for a message) given current conditions.
 * @grant:     Overall information for grant management.
 * Return:     See above.
 */
int homa_grant_window(struct homa_grant *grant)
{
	u64 window;

	window = grant->window_param;
	if (window == 0) {
		/* Dynamic window sizing uses the approach described in the
		 * paper "Dynamic Queue Length Thresholds for Shared-Memory
		 * Packet Switches" with an alpha value of 1. The idea is to
		 * maintain unused incoming capacity (for new RPC arrivals)
		 * equal to the amount of incoming allocated to each of the
		 * current RPCs.
		 */
		window = grant->max_incoming;
		do_div(window, grant->num_active_rpcs + 1);
	}
	return window;
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
	/* Fewest ungranted bytes is the primary criterion; if those are
	 * equal, then favor the older RPC.
	 */
	int grant_diff;

	grant_diff = (rpc1->msgin.length - rpc1->msgin.granted) -
		     (rpc2->msgin.length - rpc2->msgin.granted);
	return grant_diff < 0 || ((grant_diff == 0) &&
				  (rpc1->msgin.birth < rpc2->msgin.birth));
}

/**
 * homa_grant_priority() - Return the appropriate priority to use in a
 * grant for an incoming message.
 * @homa:     Overall information about the Homa transport.
 * @rank:     Position of the message's RPC in active_rpcs (lower means
 *            higher priority).
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
	extra_levels = max_sched_prio + 1 - homa->grant->num_active_rpcs;
	if (extra_levels >= 0)
		priority -= extra_levels;
	return (priority < 0) ? 0 : priority;
}

/**
 * homa_grant_insert_active() - Try to insert an RPC in homa->active_rpcs.
 * @rpc:   RPC to insert (if possible).
 * Return: NULL if there was room to insert @rpc without ejecting any other
 *         RPC. Otherwise, returns an RPC that must be added to
 *         homa->grantable_peers (could be either @rpc or some other RPC
 *         that @rpc displaced).
 */
struct homa_rpc *homa_grant_insert_active(struct homa_rpc *rpc)
	__must_hold(&rpc->hsk->homa->grant->lock)
{
	struct homa_grant *grant = rpc->hsk->homa->grant;
	struct homa_rpc *other, *result;
	int insert_after;
	int last_to_copy;
	int peer_index;
	int i;

	/* Scan active_rpcs backwards to find the lowest-priority message
	 * with higher priority than @rpc. Also find the lowest-priority
	 * message with the same peer as @rpc, if one appears.
	 */
	insert_after = -1;
	peer_index = -1;
	for (i = grant->num_active_rpcs - 1; i >= 0; i--) {
		other = grant->active_rpcs[i];
		if (!homa_grant_outranks(rpc, other)) {
			insert_after = i;
			break;
		}
		if (peer_index < 0 && other->peer == rpc->peer)
			peer_index = i;
	}

	if (rpc->peer->active_rpcs >= grant->max_rpcs_per_peer) {
		if (peer_index <= i)
			/* All the other RPCs with the same peer are higher
			 * priority than @rpc and we can't have any more RPCs
			 * with the same peer, so bump @rpc.
			 */
			return rpc;

		/* Bump the lowest priority RPC from the same peer to make room
		 * for the new RPC. @rpc will be in a slot with lower index
		 * (higher priority) than the bumped one.
		 */
		result = grant->active_rpcs[peer_index];
		result->msgin.rank = -1;
		result->peer->active_rpcs--;
		last_to_copy = peer_index - 1;
	} else {
		if (insert_after >= grant->max_overcommit - 1)
			/* active_rpcs is full and @rpc is too low priority;
			 * bump it.
			 */
			return rpc;

		if (grant->num_active_rpcs >= grant->max_overcommit) {
			result = grant->active_rpcs[grant->num_active_rpcs - 1];
			result->msgin.rank = -1;
			result->peer->active_rpcs--;
			last_to_copy = grant->num_active_rpcs - 2;
		} else {
			result = NULL;
			last_to_copy = grant->num_active_rpcs - 1;
			grant->num_active_rpcs++;
		}
	}

	/* Move existing RPCs in active_rpcs down to make room for @rpc. */
	for (i = last_to_copy; i > insert_after; i--) {
		other = grant->active_rpcs[i];
		other->msgin.rank = i + 1;
		grant->active_rpcs[i + 1] = other;
	}
	grant->active_rpcs[insert_after + 1] = rpc;
	rpc->msgin.rank = insert_after + 1;
	rpc->peer->active_rpcs++;

	return result;
}

/**
 * homa_grant_insert_grantable() - Insert an RPC into the grantable list
 * for its peer.
 * @rpc:    The RPC to add. Must not currently be in either active_rpcs
 *          or grantable_peers.
 */
void homa_grant_insert_grantable(struct homa_rpc *rpc)
	__must_hold(&rpc->hsk->homa->grant->lock)
{
	struct homa_grant *grant = rpc->hsk->homa->grant;
	struct homa_peer *peer = rpc->peer;
	struct homa_peer *other_peer;
	struct homa_rpc *other;

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
	/* At this point rpc is positioned correctly on the list for its peer.
	 * However, the peer may need to be added to, or moved upward in,
	 * grantable_peers.
	 */
	if (list_empty(&peer->grantable_links)) {
		/* Must add peer to grantable_peers. */
		list_for_each_entry(other_peer, &grant->grantable_peers,
				    grantable_links) {
			other = list_first_entry(&other_peer->grantable_rpcs,
						 struct homa_rpc,
						 grantable_links);
			if (homa_grant_outranks(rpc, other)) {
				list_add_tail(&peer->grantable_links,
					      &other_peer->grantable_links);
				return;
			}
		}
		list_add_tail(&peer->grantable_links, &grant->grantable_peers);
		return;
	}
	/* The peer is on grantable_peers, but it may need to move upward. */
	while (peer != list_first_entry(&grant->grantable_peers,
					struct homa_peer, grantable_links)) {
		struct homa_peer *prev_peer = list_prev_entry(peer,
							      grantable_links);
		other = list_first_entry(&prev_peer->grantable_rpcs,
					 struct homa_rpc, grantable_links);
		if (!homa_grant_outranks(rpc, other))
			break;
		__list_del_entry(&prev_peer->grantable_links);
		list_add(&prev_peer->grantable_links, &peer->grantable_links);
	}
}

/**
 * homa_grant_manage_rpc() - Insert an RPC into the priority-based data
 * structures for managing grantable RPCs (active_rpcs or grantable_peers).
 * Ensures that the RPC will be sent grants as needed.
 * @rpc:    The RPC to add. Must be locked by caller.
 */
void homa_grant_manage_rpc(struct homa_rpc *rpc)
	__must_hold(&rpc->bucket->lock)
{
	struct homa_grant *grant = rpc->hsk->homa->grant;
	struct homa_rpc *bumped;
	u64 time = homa_clock();

	BUG_ON(rpc->msgin.rank >= 0 || !list_empty(&rpc->grantable_links));

	homa_grant_lock(grant);

	INC_METRIC(grantable_rpcs_integral, grant->num_grantable_rpcs *
		   (time - grant->last_grantable_change));
	grant->last_grantable_change = time;
	grant->num_grantable_rpcs++;
	tt_record2("Incremented num_grantable_rpcs to %d, id %d",
		   grant->num_grantable_rpcs, rpc->id);
	if (grant->num_grantable_rpcs > grant->max_grantable_rpcs)
		grant->max_grantable_rpcs = grant->num_grantable_rpcs;
	rpc->msgin.birth = time;

	bumped = homa_grant_insert_active(rpc);
	if (bumped)
		homa_grant_insert_grantable(bumped);
	grant->window = homa_grant_window(grant);

	homa_grant_unlock(grant);
}

/**
 * homa_grant_remove_grantable() - Unlink an RPC from the grantable lists,
 * so it will no longer be considered for grants.
 * @rpc:     RPC to remove from grantable lists.  Must currently be in
 *           a grantable list.
 */
void homa_grant_remove_grantable(struct homa_rpc *rpc)
	__must_hold(&rpc->hsk->homa->grant->lock)
{
	struct homa_grant *grant = rpc->hsk->homa->grant;
	struct homa_peer *peer = rpc->peer;
	struct homa_rpc *other;
	struct homa_rpc *head;

	head =  list_first_entry(&peer->grantable_rpcs,
				 struct homa_rpc, grantable_links);
	list_del_init(&rpc->grantable_links);
	if (rpc != head)
		return;

	/* The removed RPC was at the front of the peer's list. This means
	 * we may have to adjust the position of the peer in the peer list,
	 * or perhaps remove it.
	 */
	if (list_empty(&peer->grantable_rpcs)) {
		list_del_init(&peer->grantable_links);
		return;
	}

	/* The peer may have to move down in Homa's list (its highest priority
	 * may now be lower).
	 */
	head = list_first_entry(&peer->grantable_rpcs,
				struct homa_rpc, grantable_links);
	while (peer != list_last_entry(&grant->grantable_peers,
				       struct homa_peer, grantable_links)) {
		struct homa_peer *next_peer = list_next_entry(peer,
							      grantable_links);
		other = list_first_entry(&next_peer->grantable_rpcs,
					 struct homa_rpc, grantable_links);
		if (!homa_grant_outranks(other, head))
			break;
		__list_del_entry(&peer->grantable_links);
		list_add(&peer->grantable_links, &next_peer->grantable_links);
	}
}

/**
 * homa_grant_remove_active() - Remove an RPC from active_rpcs and promote
 * an RPC from grantable_peers if possible.
 * @rpc:    RPC that no longer needs grants. Must have rank > 0.
 * @cand:   If an RPC is promoted into active_rpcs it is added here.
 */
void homa_grant_remove_active(struct homa_rpc *rpc,
			      struct homa_grant_candidates *cand)
	__must_hold(&rpc->hsk->homa->grant->lock)
{
	struct homa_grant *grant = rpc->hsk->homa->grant;
	struct homa_peer *peer;
	struct homa_rpc *other;
	int i;

	for (i = rpc->msgin.rank + 1; i < grant->num_active_rpcs; i++) {
		other = grant->active_rpcs[i];
		other->msgin.rank = i - 1;
		grant->active_rpcs[i - 1] = other;
	}
	rpc->msgin.rank = -1;
	rpc->peer->active_rpcs--;
	grant->num_active_rpcs--;
	grant->active_rpcs[grant->num_active_rpcs] = NULL;

	/* Pull the highest-priority entry (if there is one) from
	 * grantable_peers into active_rpcs.
	 */
	list_for_each_entry(peer, &grant->grantable_peers, grantable_links) {
		if (peer->active_rpcs >= grant->max_rpcs_per_peer)
			continue;
		other =	list_first_entry(&peer->grantable_rpcs,
					 struct homa_rpc,
					 grantable_links);
		homa_grant_remove_grantable(other);
		peer->active_rpcs++;
		grant->active_rpcs[grant->num_active_rpcs] = other;
		other->msgin.rank = grant->num_active_rpcs;
		grant->num_active_rpcs++;
		homa_grant_cand_add(cand, other);
		break;
	}
}

/**
 * homa_grant_unmanage_rpc() - Make sure that an RPC is no longer present
 * in the priority structures used to manage grants (active_rpcs and
 * grantable_rpcs). The RPC will no longer receive grants.
 * @rpc:     RPC to unlink.
 * @cand:    If an RPC is promoted into active_rpcs, it is added here.
 */
void homa_grant_unmanage_rpc(struct homa_rpc *rpc,
			     struct homa_grant_candidates *cand)
	__must_hold(&rpc->bucket->lock)
{
	struct homa_grant *grant = rpc->hsk->homa->grant;
	u64 time = homa_clock();

	homa_grant_lock(grant);

	INC_METRIC(grantable_rpcs_integral, grant->num_grantable_rpcs
			* (time - grant->last_grantable_change));
	grant->last_grantable_change = time;
	grant->num_grantable_rpcs--;
	tt_record2("Decremented num_grantable_rpcs to %d, id %d",
		   grant->num_grantable_rpcs, rpc->id);

	if (rpc->msgin.rank >= 0)
		homa_grant_remove_active(rpc, cand);
	if (!list_empty(&rpc->grantable_links))
		homa_grant_remove_grantable(rpc);
	grant->window = homa_grant_window(grant);

	homa_grant_unlock(grant);
}

/**
 * homa_grant_update_incoming() - Figure out how much incoming data there is
 * for an RPC (i.e., data that has been granted but not yet received) and make
 * sure this is properly reflected in rpc->msgin.incoming
 * and homa->total_incoming.
 * @rpc:    RPC to check; must be locked.
 * @grant:  Grant information for a Homa transport.
 */
void homa_grant_update_incoming(struct homa_rpc *rpc, struct homa_grant *grant)
	__must_hold(&rpc->bucket->lock)
{
	int incoming, delta;

	incoming = rpc->msgin.granted - (rpc->msgin.length -
					 rpc->msgin.bytes_remaining);
	if (incoming < 0)
		incoming = 0;
	delta = incoming - rpc->msgin.rec_incoming;
	if (delta != 0)
		atomic_add(delta, &grant->total_incoming);
	rpc->msgin.rec_incoming = incoming;
}

/**
 * homa_grant_update_granted() - Compute a new grant offset for an RPC.
 * @rpc:   RPC whose msgin.granted should be updated. Must be locked by
 *         caller.
 * @grant: Information for managing grants. This function may set
 *         incoming_hit_limit.
 * Return: >= 0 means the offset was increased and a grant should be
 *         sent for the RPC; the return value gives the priority to
 *         use in the grant. -1 means the grant offset was not changed
 *         and no grant should be sent.
 */
int homa_grant_update_granted(struct homa_rpc *rpc, struct homa_grant *grant)
	__must_hold(&rpc->bucket->lock)
{
	int received, new_grant_offset, incoming_delta, avl_incoming, rank;
	int prev_stalled;

	/* Don't increase the grant if the node has been slow to send
	 * data already granted: no point in wasting grants on this
	 * node.
	 */
	if (rpc->silent_ticks > 1)
		return -1;
	rank = READ_ONCE(rpc->msgin.rank);
	if (rank < 0 || rpc->msgin.granted >= rpc->msgin.length)
		return -1;

	received = rpc->msgin.length - rpc->msgin.bytes_remaining;
	new_grant_offset = received + grant->window;
	if (new_grant_offset > rpc->msgin.length)
		new_grant_offset = rpc->msgin.length;
	incoming_delta = new_grant_offset - received - rpc->msgin.rec_incoming;
	avl_incoming = grant->max_incoming - atomic_read(&grant->total_incoming);
	if (avl_incoming < incoming_delta) {
		tt_record4("insufficient headroom for grant for RPC id %d "
			   "(rank %d): desired incoming %d, shortfall %d",
			   rpc->id, rank, new_grant_offset - received,
			   incoming_delta - avl_incoming);
		prev_stalled = atomic_read(&grant->stalled_rank);
		while (prev_stalled > rank)
			prev_stalled = atomic_cmpxchg(&grant->stalled_rank,
						      prev_stalled, rank);
		new_grant_offset -= incoming_delta - avl_incoming;
	}
	if (new_grant_offset <= rpc->msgin.granted)
		return -1;
	rpc->msgin.granted = new_grant_offset;

	/* The reason we compute the priority here rather than, say, in
	 * homa_grant_send is that rpc->msgin.rank could change to -1
	 * before homa_grant_send is invoked (it could change at any time,
	 * since we don't have homa->grant->lock; that's why READ_ONCE
	 * is used above). It's OK to still send a grant in that case, but
	 * we need to have a meaningful priority level for it.
	 */
	return homa_grant_priority(rpc->hsk->homa, rank);
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
	grant.resend_all = rpc->msgin.resend_all;
	if (grant.resend_all)
		rpc->msgin.resend_all = 0;
	tt_record4("sending grant for id %d, offset %d, priority %d, increment %d",
		   rpc->id, rpc->msgin.granted, grant.priority,
		   rpc->msgin.granted - rpc->msgin.prev_grant);
	rpc->msgin.prev_grant = rpc->msgin.granted;
	homa_xmit_control(GRANT, &grant, sizeof(grant), rpc);
}

/**
 * homa_grant_check_rpc() - This function is responsible for generating
 * grant packets.  Is invoked whenever a data packet arrives for RPC; it
 * checks the state of that RPC (as well as other RPCs) and generates
 * grant packets as appropriate.
 * @rpc:    RPC to check. Must be locked by the caller.
 */
void homa_grant_check_rpc(struct homa_rpc *rpc)
	__must_hold(&rpc->bucket->lock)
{
	struct homa_grant *grant = rpc->hsk->homa->grant;
	int needy_rank, stalled_rank, rank;
	struct homa_grant_candidates cand;
	int locked = 0;
	u64 now;
	int i;

	/* The challenge for this function is to minimize use of the grant
	 * lock, since that is global. Early versions of Homa acquired the
	 * grant lock on every call to this function, but that resulted in
	 * too much contention for the grant lock (especially at network
	 * speeds of 100 Gbps or more).
	 *
	 * This implementation is designed in the hopes that most calls can
	 * follow a fast path that does not require the grant lock: just
	 * update grant state for @rpc and possibly issue a new grant for
	 * @rpc, without considering other RPCs.
	 *
	 * However, there are some situations where other RPCs must be
	 * considered:
	 * 1. If there are higher-priority RPCs that are stalled (they would
	 *    like to issue grants but could not because @total_incoming
	 *    was exceeded), then they must get first shot at any headroom
	 *    that has become available.
	 * 2. The priority order of RPCs could change, if data packets arrive
	 *    for lower priority RPCs but not for higher priority ones.
	 *    Rather than checking every time data arrives (which would
	 *    require the grant lock), we recheck the priorities at regular
	 *    time intervals.
	 * 3. Occasionally we need to send grants to the oldest message (FIFO
	 *    priority) in order to prevent starvation.
	 *
	 * Each of these situations requires the grant lock.
	 **/

	if (rpc->msgin.length < 0 || rpc->msgin.num_bpages <= 0 ||
	    rpc->state == RPC_DEAD)
		return;

	tt_record4("homa_grant_check_rpc starting for id %d, granted %d, recv_end %d, length %d",
		   rpc->id, rpc->msgin.granted, rpc->msgin.recv_end,
		   rpc->msgin.length);
	INC_METRIC(grant_check_calls, 1);

	needy_rank = INT_MAX;
	now = homa_clock();
	homa_grant_update_incoming(rpc, grant);
	if (now >= READ_ONCE(grant->next_recalc)) {
		/* Situation 2. */
		locked = 1;
		tt_record1("homa_grant_check_rpc acquiring grant lock to fix order (id %d)",
			   rpc->id);
		homa_grant_lock(grant);
		grant->next_recalc = now + grant->recalc_cycles;
		needy_rank = homa_grant_fix_order(grant);
		homa_grant_unlock(grant);
		tt_record1("homa_grant_check_rpc released grant lock (id %d)",
			   rpc->id);
		INC_METRIC(grant_check_recalcs, 1);
	}

	rank = READ_ONCE(rpc->msgin.rank);
	stalled_rank = atomic_read(&grant->stalled_rank);
	if (stalled_rank < needy_rank)
		needy_rank = stalled_rank;

	if (rank >= 0 && rank <= needy_rank) {
		int priority;

		/* Fast path. */
		priority = homa_grant_update_granted(rpc, grant);
		homa_grant_update_incoming(rpc, grant);
		if (priority >= 0) {
			homa_grant_cand_init(&cand);
			if (rpc->msgin.granted >= rpc->msgin.length)
				homa_grant_unmanage_rpc(rpc, &cand);

			/* Sending a grant is slow, so release the RPC lock while
			 * sending the grant to reduce contention.
			 */
			homa_rpc_hold(rpc);
			homa_rpc_unlock(rpc);
			homa_grant_send(rpc, priority);
			if (!homa_grant_cand_empty(&cand))
				homa_grant_cand_check(&cand, grant);
			homa_rpc_lock(rpc);
			homa_rpc_put(rpc);
		}
	}

	if (needy_rank < INT_MAX &&
	    atomic_read(&grant->total_incoming) < grant->max_incoming) {
		UNIT_HOOK("grant_check_needy");
		/* Situations 1 and 2. */
		stalled_rank = atomic_xchg(&grant->stalled_rank, INT_MAX);
		if (stalled_rank < needy_rank)
			needy_rank = stalled_rank;
		homa_grant_cand_init(&cand);
		locked = 1;
		tt_record3("homa_grant_check_rpc acquiring grant lock, needy_rank %d, id %d, num_active %d",
			   needy_rank, rpc->id, grant->num_active_rpcs);
		homa_grant_lock(grant);
		for (i = needy_rank; i < grant->num_active_rpcs; i++) {
			struct homa_rpc *rpc2 = grant->active_rpcs[i];

			if (rpc2->msgin.rec_incoming < grant->window &&
			    rpc2->state != RPC_DEAD)
				homa_grant_cand_add(&cand, rpc2);
		}
		homa_grant_unlock(grant);
		tt_record1("homa_grant_check_rpc released grant lock (id %d)",
			   rpc->id);
		if (!homa_grant_cand_empty(&cand)) {
			homa_rpc_hold(rpc);
			homa_rpc_unlock(rpc);
			homa_grant_cand_check(&cand, grant);
			homa_rpc_lock(rpc);
			homa_rpc_put(rpc);
		}
		INC_METRIC(grant_check_others, 1);
	}

	INC_METRIC(grant_check_locked, locked);
	tt_record1("homa_grant_check_rpc finished with id %d", rpc->id);
}

/**
 * homa_grant_fix_order() - This function scans all of the RPCS in
 * @active_rpcs and repairs any priority inversions that may exist.
 * @grant:      Overall grant management information.
 * Return:      The new rank of the highest-priority RPC whose rank improved,
 *              or INT_MAX if no RPCs were promoted.
 */
int homa_grant_fix_order(struct homa_grant *grant)
	__must_hold(&grant->lock)
{
	struct homa_rpc *rpc, *other;
	int result = INT_MAX;
	int i, j;

	for (i = 1; i < grant->num_active_rpcs; i++) {
		rpc = grant->active_rpcs[i];
		for (j = i - 1; j >= 0; j--) {
			other = grant->active_rpcs[j];
			if (!homa_grant_outranks(rpc, other))
				break;
			grant->active_rpcs[j + 1] = other;
			other->msgin.rank = j + 1;
			grant->active_rpcs[j] = rpc;
			rpc->msgin.rank = j;
			if (j < result)
				result = j;
			INC_METRIC(grant_priority_bumps, 1);
		}
	}
	return result;
}

/**
 * homa_grant_find_oldest() - Recompute the value of homa->oldest_rpc.
 * @homa:    Overall data about the Homa protocol implementation. The
 *           grant_lock must be held by the caller.
 */
void homa_grant_find_oldest(struct homa *homa)
{
	int max_incoming = homa->grant->window + 2 * homa->grant->fifo_grant_increment;
	struct homa_rpc *rpc, *oldest;
	struct homa_peer *peer;
	u64 oldest_birth;

	oldest = NULL;
	oldest_birth = ~0;

	/* Find the oldest message that doesn't currently have an
	 * outstanding "pity grant".
	 */
	list_for_each_entry(peer, &homa->grant->grantable_peers, grantable_links) {
		list_for_each_entry(rpc, &peer->grantable_rpcs,
				    grantable_links) {
			int received, incoming;

			if (rpc->msgin.birth >= oldest_birth)
				continue;

			received = (rpc->msgin.length
					- rpc->msgin.bytes_remaining);
			incoming = rpc->msgin.granted - received;
			if (incoming >= max_incoming) {
				/* This RPC has been granted way more bytes
				 * than by the grant window. This can only
				 * happen for FIFO grants, and it means the
				 * peer isn't responding to grants we've sent.
				 * Pick a different "oldest" RPC.
				 */
				continue;
			}
			oldest = rpc;
			oldest_birth = rpc->msgin.birth;
		}
	}
	homa->grant->oldest_rpc = oldest;
}

#ifndef __STRIP__ /* See strip.py */
#if 0
/**
 * homa_choose_fifo_grant() - This function is invoked occasionally to give
 * a high-priority grant to the oldest incoming message. We do this in
 * order to reduce the starvation that SRPT can cause for long messages.
 * Note: this method is obsolete and should never be invoked; it's code is
 * being retained until fifo grants are reimplemented using the new grant
 * mechanism.
 * @homa:    Overall data about the Homa protocol implementation. The
 *           grant lock must be held by the caller.
 * Return: An RPC to which to send a FIFO grant, or NULL if there is
 *         no appropriate RPC. This method doesn't actually send a grant,
 *         but it updates @msgin.granted to reflect the desired grant.
 *         Also updates homa->total_incoming.
 */
struct homa_rpc *homa_choose_fifo_grant(struct homa *homa)
{
	struct homa_rpc *rpc, *oldest;
	u64 oldest_birth;
	int granted;

	oldest = NULL;
	oldest_birth = ~0;

	/* Find the oldest message that doesn't currently have an
	 * outstanding "pity grant".
	 */
	list_for_each_entry(rpc, &homa->grantable_rpcs, grantable_links) {
		int received, on_the_way;

		if (rpc->msgin.birth >= oldest_birth)
			continue;

		received = (rpc->msgin.length
				- rpc->msgin.bytes_remaining);
		on_the_way = rpc->msgin.granted - received;
		if (on_the_way > homa->unsched_bytes) {
			/* The last "pity" grant hasn't been used
			 * up yet.
			 */
			continue;
		}
		oldest = rpc;
		oldest_birth = rpc->msgin.birth;
	}
	if (!oldest)
		return NULL;
	INC_METRIC(fifo_grants, 1);
	if ((oldest->msgin.length - oldest->msgin.bytes_remaining)
			== oldest->msgin.granted)
		INC_METRIC(fifo_grants_no_incoming, 1);

	oldest->silent_ticks = 0;
	granted = homa->fifo_grant_increment;
	oldest->msgin.granted += granted;
	if (oldest->msgin.granted >= oldest->msgin.length) {
		granted -= oldest->msgin.granted - oldest->msgin.length;
		oldest->msgin.granted = oldest->msgin.length;
		// homa_remove_grantable_locked(homa, oldest);
	}

	/* Try to update homa->total_incoming; if we can't lock
	 * the RPC, just skip it (waiting could deadlock), and it
	 * will eventually get updated elsewhere.
	 */
	if (homa_rpc_try_lock(oldest)) {
		homa_grant_update_incoming(oldest, homa);
		homa_rpc_unlock(oldest);
	}

	if (oldest->msgin.granted < (oldest->msgin.length
				- oldest->msgin.bytes_remaining)) {
		/* We've already received all of the bytes in the new
		 * grant; most likely this means that the sender sent extra
		 * data after the last fifo grant (e.g. by rounding up to a
		 * TSO packet). Don't send this grant.
		 */
		return NULL;
	}
	return oldest;
}
#endif
#endif /* See strip.py */

/**
 * homa_grant_cand_add() - Add an RPC into the struct, if there is
 * space. After this function is called, homa_grant_cand_check must
 * eventually be called to process the entries and release reference
 * counts.
 * @cand:   Structure in which to add @rpc.
 * @rpc:    RPC to add.  If added successfully its reference count will
 *          be incremented
 */
void homa_grant_cand_add(struct homa_grant_candidates *cand,
			 struct homa_rpc *rpc)
{
	if (cand->inserts < cand->removes + HOMA_MAX_CAND_RPCS) {
		homa_rpc_hold(rpc);
		cand->rpcs[cand->inserts & HOMA_CAND_MASK] = rpc;
		cand->inserts++;
	}
}

/**
 * homa_grant_cand_check() - Scan all of the entries in @cand, issuing
 * grants if possible and releasing reference counts. This function
 * will acquire each RPCs lock, so the caller must not hold RPC locks
 * or locks that conflict with RPC locks, such as the
 * grant lock.
 * @cand:    Check all of the RPCs in this struct.
 * @grant:   Grant management information.
 */
void homa_grant_cand_check(struct homa_grant_candidates *cand,
			   struct homa_grant *grant)
{
	struct homa_rpc *rpc;
	int priority;
	bool locked;

	while (cand->removes < cand->inserts) {
		rpc = cand->rpcs[cand->removes & HOMA_CAND_MASK];
		cand->removes++;
		homa_rpc_lock(rpc);
		locked = true;

		if (rpc->state != RPC_DEAD) {
			priority = homa_grant_update_granted(rpc, grant);
			if (priority >= 0) {
				homa_grant_update_incoming(rpc, grant);
				if (rpc->msgin.granted >= rpc->msgin.length)
					homa_grant_unmanage_rpc(rpc, cand);
				homa_rpc_unlock(rpc);
				locked = false;
				homa_grant_send(rpc, priority);
			}
		}
		if (locked)
			homa_rpc_unlock(rpc);
		homa_rpc_put(rpc);
	}
}

/**
 * homa_grant_lock_slow() - This function implements the slow path for
 * acquiring the grant lock. It is invoked when the lock isn't immediately
 * available. It waits for the lock, but also records statistics about
 * the waiting time.
 * @grant:    Grant management information.
 */
void homa_grant_lock_slow(struct homa_grant *grant)
	__acquires(&grant->lock)
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
	u64 tmp;

	if (grant->max_overcommit > HOMA_MAX_GRANTS)
		grant->max_overcommit = HOMA_MAX_GRANTS;

	if (grant->fifo_fraction > 500)
		grant->fifo_fraction = 500;
	tmp = grant->fifo_fraction;
	if (tmp != 0)
		tmp = (1000 * grant->fifo_grant_increment) / tmp -
				grant->fifo_grant_increment;
	grant->grant_nonfifo = tmp;

	grant->recalc_cycles = homa_usecs_to_cycles(grant->recalc_usecs);

	grant->window = homa_grant_window(grant);
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

	grant = homa_net_from_net(current->nsproxy->net_ns)->homa->grant;

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
