// SPDX-License-Identifier: BSD-2-Clause

/* This file contains functions related to issuing grants for incoming
 * messages.
 */

#include "homa_impl.h"
#include "homa_wire.h"

/**
 * homa_grant_outranks() - Returns nonzero if rpc1 should be considered
 * higher priority for grants than rpc2, and zero if the two RPCS are
 * equivalent or rpc2 is higher priority.
 * @rpc1:     First RPC to consider.
 * @rpc2:     Second RPC to consider.
 */
inline int homa_grant_outranks(struct homa_rpc *rpc1, struct homa_rpc *rpc2)
{
	/* Fewest bytes remaining is the primary criterion; if those are
	 * equal, then favor the older RPC.
	 */
	return (rpc1->msgin.bytes_remaining < rpc2->msgin.bytes_remaining)
			|| ((rpc1->msgin.bytes_remaining
			== rpc2->msgin.bytes_remaining)
			&& (rpc1->msgin.birth < rpc2->msgin.birth));
}

/**
 * homa_grant_update_incoming() - Figure out how much incoming data there is
 * for an RPC (i.e., data that has been granted but not yet received) and make
 * sure this is properly reflected in homa->total_incoming.
 * @rpc:   RPC to check; must be locked by the caller and its msgin must be
 *         properly initialized.
 * @homa:  Overall information about the Homa transport.
 * Return: A nonzero return value means that this update caused
 *         homa->total_incoming to drop below homa->max_incoming, when it
 *         had previously been at or above that level. This means that it
 *         may be possible to send out additional grants to some RPCs (doing
 *         this is left to the caller).
 */
inline int homa_grant_update_incoming(struct homa_rpc *rpc, struct homa *homa)
{
	int incoming = rpc->msgin.granted - (rpc->msgin.length
			- rpc->msgin.bytes_remaining);

	if (incoming < 0)
		incoming = 0;
	if (incoming != rpc->msgin.rec_incoming) {
		int delta = incoming - rpc->msgin.rec_incoming;
		int old = atomic_fetch_add(delta, &homa->total_incoming);

		rpc->msgin.rec_incoming = incoming;
		return ((old >= homa->max_incoming)
				&& ((old + delta) < homa->max_incoming));
	}
	return 0;
}

/**
 * homa_grant_add_rpc() - Make sure that an RPC is present in the grantable
 * list for its peer and in the appropriate position, and that the peer is
 * present in the overall grantable list for Homa and in the correct
 * position. The caller must hold the grantable lock and the RPC's lock.
 * @rpc:    The RPC to add/reposition.
 */
void homa_grant_add_rpc(struct homa_rpc *rpc)
{
	struct homa_rpc *candidate;
	struct homa_peer *peer = rpc->peer;
	struct homa_peer *peer_cand;
	struct homa *homa = rpc->hsk->homa;

	/* Make sure this message is in the right place in the grantable_rpcs
	 * list for its peer.
	 */
	if (list_empty(&rpc->grantable_links)) {
		/* Message not yet tracked; add it in priority order to
		 * the peer's list.
		 */
		__u64 time = get_cycles();

		INC_METRIC(grantable_rpcs_integral, homa->num_grantable_rpcs
				* (time - homa->last_grantable_change));
		homa->last_grantable_change = time;
		homa->num_grantable_rpcs++;
		tt_record2("Incremented num_grantable_rpcs to %d, id %d",
				homa->num_grantable_rpcs, rpc->id);
		if (homa->num_grantable_rpcs > homa->max_grantable_rpcs)
			homa->max_grantable_rpcs = homa->num_grantable_rpcs;
		rpc->msgin.birth = time;
		list_for_each_entry(candidate, &peer->grantable_rpcs,
				grantable_links) {
			if (homa_grant_outranks(rpc, candidate)) {
				list_add_tail(&rpc->grantable_links,
						&candidate->grantable_links);
				goto position_peer;
			}
		}
		list_add_tail(&rpc->grantable_links, &peer->grantable_rpcs);
	} else {
		while (rpc != list_first_entry(&peer->grantable_rpcs,
				struct homa_rpc, grantable_links)) {
			/* Message is on the list, but its priority may have
			 * increased because of the recent packet arrival. If
			 * so, adjust its position in the list.
			 */
			candidate = list_prev_entry(rpc, grantable_links);
			if (!homa_grant_outranks(rpc, candidate))
				goto position_peer;
			__list_del_entry(&candidate->grantable_links);
			list_add(&candidate->grantable_links, &rpc->grantable_links);
		}
	}

position_peer:
	/* At this point rpc is positioned correctly on the list for its peer.
	 * However, the peer may need to be added to, or moved upward on,
	 * homa->grantable_peers.
	 */
	if (list_empty(&peer->grantable_links)) {
		/* Must add peer to the overall Homa list. */
		list_for_each_entry(peer_cand, &homa->grantable_peers,
				grantable_links) {
			candidate = list_first_entry(&peer_cand->grantable_rpcs,
					struct homa_rpc, grantable_links);
			if (homa_grant_outranks(rpc, candidate)) {
				list_add_tail(&peer->grantable_links,
						&peer_cand->grantable_links);
				goto done;
			}
		}
		list_add_tail(&peer->grantable_links, &homa->grantable_peers);
		goto done;
	}
	/* The peer is on Homa's list, but it may need to move upward. */
	while (peer != list_first_entry(&homa->grantable_peers,
			struct homa_peer, grantable_links)) {
		struct homa_peer *prev_peer = list_prev_entry(
			peer, grantable_links);
		candidate = list_first_entry(&prev_peer->grantable_rpcs,
				struct homa_rpc, grantable_links);
		if (!homa_grant_outranks(rpc, candidate))
			goto done;
		__list_del_entry(&prev_peer->grantable_links);
		list_add(&prev_peer->grantable_links, &peer->grantable_links);
	}
done:
}

/**
 * homa_grant_remove_rpc() - Unlink an RPC from the grantable lists, so it will
 * no longer be considered for grants. The caller must hold the grantable lock.
 * @rpc:     RPC to remove from grantable lists.  Must currently be in
 *           a grantable list.
 */
void homa_grant_remove_rpc(struct homa_rpc *rpc)
{
	struct homa_rpc *head;
	struct homa_peer *peer = rpc->peer;
	struct homa_rpc *candidate;
	struct homa *homa = rpc->hsk->homa;
	__u64 time = get_cycles();

	if (list_empty(&rpc->grantable_links))
		return;

	if (homa->oldest_rpc == rpc)
		homa->oldest_rpc = NULL;

	head =  list_first_entry(&peer->grantable_rpcs,
			struct homa_rpc, grantable_links);
	list_del_init(&rpc->grantable_links);
	INC_METRIC(grantable_rpcs_integral, homa->num_grantable_rpcs
			* (time - homa->last_grantable_change));
	homa->last_grantable_change = time;
	homa->num_grantable_rpcs--;
	tt_record2("Decremented num_grantable_rpcs to %d, id %d",
			homa->num_grantable_rpcs, rpc->id);
	if (rpc != head)
		return;

	/* The removed RPC was at the front of the peer's list. This means
	 * we may have to adjust the position of the peer in Homa's list,
	 * or perhaps remove it.
	 */
	if (list_empty(&peer->grantable_rpcs)) {
		list_del_init(&peer->grantable_links);
		return;
	}

	/* The peer may have to move down in Homa's list (removal of
	 * an RPC can't cause the peer to move up).
	 */
	head =  list_first_entry(&peer->grantable_rpcs,
			struct homa_rpc, grantable_links);
	while (peer != list_last_entry(&homa->grantable_peers, struct homa_peer,
			grantable_links)) {
		struct homa_peer *next_peer = list_next_entry(
				peer, grantable_links);
		candidate = list_first_entry(&next_peer->grantable_rpcs,
				struct homa_rpc, grantable_links);
		if (!homa_grant_outranks(rpc, candidate))
			break;
		__list_del_entry(&peer->grantable_links);
		list_add(&peer->grantable_links, &next_peer->grantable_links);
	}
}

/**
 * homa_grant_send() - See if it is appropriate to send a grant to an RPC;
 * if so, create the grant and send it.
 * @rpc:   The RPC to check for possible grant. Must be locked by the caller.
 * @homa:  Overall information about the Homa transport.
 * Return: Nonzero if a grant was sent, 0 if not.
 */
int homa_grant_send(struct homa_rpc *rpc, struct homa *homa)
{
	int incoming, increment, available;
	struct grant_header grant;

	/* Compute how many additional bytes to grant. */
	incoming = rpc->msgin.granted - (rpc->msgin.length
		- rpc->msgin.bytes_remaining);
	if (incoming < 0) {
		rpc->msgin.granted = rpc->msgin.length
				- rpc->msgin.bytes_remaining;
		incoming = 0;
	}
	increment = homa->grant_window - incoming;
	if (increment > (rpc->msgin.length - rpc->msgin.granted))
		increment = rpc->msgin.length - rpc->msgin.granted;
	available = homa->max_incoming - atomic_read(&homa->total_incoming)
			+ rpc->msgin.rec_incoming - incoming;
	if (increment > available)
		increment = available;
	if (increment <= 0)
		return 0;

	/* Don't increment the grant if the node has been slow to send
	 * data already granted: no point in wasting grants on this
	 * node.
	 */
	if (rpc->silent_ticks > 1)
		return 0;

	rpc->msgin.granted += increment;

	/* Send the grant. */
	grant.offset = htonl(rpc->msgin.granted);
	grant.priority = rpc->msgin.priority;
	grant.resend_all = rpc->msgin.resend_all;
	rpc->msgin.resend_all = 0;
	tt_record4("sending grant for id %llu, offset %d, priority %d, increment %d",
			rpc->id, rpc->msgin.granted, rpc->msgin.priority,
			increment);
	homa_xmit_control(GRANT, &grant, sizeof(grant), rpc);
	return 1;
}

/**
 * homa_grant_check_rpc() - This function is invoked when the state of an
 * RPC has changed (such as packets arriving). It checks the state of the
 * RPC relative to outgoing grants and takes any appropriate actions that
 * are needed (such as adding the RPC to the grantable list or sending
 * grants).
 * @rpc:    RPC to check. Must be locked by the caller. Note: THIS FUNCTION
 *          WILL RELEASE THE LOCK before returning.
 */
void homa_grant_check_rpc(struct homa_rpc *rpc)
{
	/* Overall design notes:
	 * The grantable lock has proven to be a performance bottleneck,
	 * particularly as network speeds increase. homa_grant_recalc must
	 * acquire that lock in order to recompute the set of messages
	 * we will grant to. The current design of this module tries to
	 * avoid calls to homa_grant_recalc by saving the current grant
	 * configuration in homa->active_rpcs etc. Then this function can
	 * issue new grants to an RPC in many cases without calling
	 * homa_grant_recalc or acquiring grantable_lock. Unfortunately
	 * there are quite a few situations where homa_grant_recalc must
	 * be called, which create a lot of special cases in this function.
	 */
	struct homa *homa = rpc->hsk->homa;
	int rank, recalc;


	if ((rpc->msgin.length < 0) || (rpc->state == RPC_DEAD)
			|| (rpc->msgin.num_bpages <= 0)) {
		homa_rpc_unlock(rpc);
		goto done;
	}

	if (rpc->msgin.granted >= rpc->msgin.length) {
		homa_grant_update_incoming(rpc, homa);
		homa_rpc_unlock(rpc);
		goto done;
	}

	tt_record4("homa_grant_check_rpc starting for id %d, granted %d, recv_end %d, length %d",
			rpc->id, rpc->msgin.granted, rpc->msgin.recv_end,
			rpc->msgin.length);

	/* This message requires grants; if it is a new message, set up
	 * granting.
	 */
	if (list_empty(&rpc->grantable_links)) {
		homa_grant_update_incoming(rpc, homa);
		homa_grantable_lock(homa, 0);
		homa_grant_add_rpc(rpc);
		recalc = ((homa->num_active_rpcs < homa->max_overcommit)
				|| (rpc->msgin.bytes_remaining < atomic_read(
				&homa->active_remaining[homa->max_overcommit-1])));
		homa_rpc_unlock(rpc);
		if (recalc)
			homa_grant_recalc(homa, 1);
		else
			homa_grantable_unlock(homa);
		goto done;
	}

	/* Not a new message; see if we can upgrade the message's priority. */
	rank = atomic_read(&rpc->msgin.rank);
	if (rank < 0) {
		homa_grant_update_incoming(rpc, homa);
		if (rpc->msgin.bytes_remaining < atomic_read(
				&homa->active_remaining[homa->max_overcommit-1])) {
			homa_rpc_unlock(rpc);
			INC_METRIC(grant_priority_bumps, 1);
			homa_grant_recalc(homa, 0);
		} else {
			homa_rpc_unlock(rpc);
		}
		goto done;
	}
	atomic_set(&homa->active_remaining[rank], rpc->msgin.bytes_remaining);
	if ((rank > 0) && (rpc->msgin.bytes_remaining < atomic_read(
			&homa->active_remaining[rank-1]))) {
		homa_grant_update_incoming(rpc, homa);
		homa_rpc_unlock(rpc);
		INC_METRIC(grant_priority_bumps, 1);
		homa_grant_recalc(homa, 0);
		goto done;
	}

	/* Getting here should be the normal case: see if we can send a new
	 * grant for this message.
	 */
	homa_grant_send(rpc, homa);
	recalc = homa_grant_update_incoming(rpc, homa);

	/* Is the message now fully granted? */
	if (rpc->msgin.granted >= rpc->msgin.length) {
		homa_grantable_lock(homa, 0);
		homa_grant_remove_rpc(rpc);
		homa_rpc_unlock(rpc);
		homa_grant_recalc(homa, 1);
		goto done;
	}

	homa_rpc_unlock(rpc);
	if (recalc)
		homa_grant_recalc(homa, 0);
done:
	tt_record1("homa_grant_check_rpc finished with id %d", rpc->id);
}

/**
 * homa_grant_recalc() - Recompute which RPCs should currently receive grants,
 * and what priorities to use for each. If needed, send out grant packets to
 * ensure that all appropriate grants have been issued. This function is
 * invoked whenever something happens that could change the contents or order
 * of homa->active_rpcs. No RPC locks may be held when this function is invoked,
 * because RPC locks will be acquired here.
 * @homa:        Overall information about the Homa transport.
 * @locked:      Normally this function will acquire (and release)
 *               homa->grantable_lock. If this value is nonzero, it means
 *               the caller has already acquired homa->grantable_lock. In
 *               either case the lock will be released upon return.
 */
void homa_grant_recalc(struct homa *homa, int locked)
{
	int i, active, try_again;
	__u64 start;

	/* The tricky part of this method is that we need to release
	 * homa->grantable_lock before actually sending grants, because
	 * (a) we need to hold the RPC lock while sending grants, and
	 * (b) sending grants takes a while, and holding grantable_lock
	 * would significantly increase contention for it.
	 * This array hold a copy of homa->active_rpcs.
	 */
	struct homa_rpc *active_rpcs[HOMA_MAX_GRANTS];

	tt_record("homa_grant_recalc starting");
	INC_METRIC(grant_recalc_calls, 1);
	if (!locked) {
		if (!homa_grantable_lock(homa, 1)) {
			INC_METRIC(grant_recalc_skips, 1);
			return;
		}
	}
	start = get_cycles();

	/* We may have to recalculate multiple times if grants sent in one
	 * round cause messages to be completely granted, opening up
	 * opportunities to grant to additional messages.
	 */
	while (1) {
		try_again = 0;
		atomic_inc(&homa->grant_recalc_count);

		/* Clear the existing grant calculation. */
		for (i = 0; i < homa->num_active_rpcs; i++)
			atomic_set(&homa->active_rpcs[i]->msgin.rank, -1);

		/* Recompute which RPCs we'll grant to and initialize info
		 * about them.
		 */
		active = homa_grant_pick_rpcs(homa, homa->active_rpcs,
				homa->max_overcommit);
		homa->num_active_rpcs = active;
		for (i = 0; i < active; i++) {
			int extra_levels;
			struct homa_rpc *rpc = homa->active_rpcs[i];

			active_rpcs[i] = rpc;
			atomic_inc(&rpc->grants_in_progress);
			atomic_set(&rpc->msgin.rank, i);
			atomic_set(&homa->active_remaining[i],
					rpc->msgin.bytes_remaining);

			/* Compute the priority to use for this RPC's grants:
			 * if there aren't enough RPCs to consume all of the
			 * priority levels, use only the lower levels; this
			 * allows faster preemption if a new high-priority
			 * message appears.
			 */
			rpc->msgin.priority = homa->max_sched_prio - i;
			extra_levels = homa->max_sched_prio + 1
					- homa->num_active_rpcs;
			if (extra_levels >= 0)
				rpc->msgin.priority -= extra_levels;
			if (rpc->msgin.priority < 0)
				rpc->msgin.priority = 0;
		}

		/* Compute the maximum window size for any RPC. Dynamic window
		 * sizing uses the approach inspired by the paper "Dynamic Queue
		 * Length Thresholds for Shared-Memory Packet Switches" with an
		 * alpha value of 1. The idea is to maintain unused incoming
		 * capacity (for new RPC arrivals) equal to the amount of
		 * incoming allocated to each of the current RPCs.
		 */
		if (homa->window_param != 0)
			homa->grant_window = homa->window_param;
		else
			homa->grant_window = homa->max_incoming/
					(homa->num_active_rpcs+1);

		/* See comment above, which explains why this is here. */
		homa_grantable_unlock(homa);

		for (i = 0; i < active; i++) {
			struct homa_rpc *rpc = active_rpcs[i];


			homa_rpc_lock(rpc, "homa_grant_recalc");
			homa_grant_send(rpc, homa);
			try_again += homa_grant_update_incoming(rpc, homa);
			if (rpc->msgin.granted >= rpc->msgin.length) {
				homa_grantable_lock(homa, 0);
				try_again += 1;
				homa_grant_remove_rpc(rpc);
				homa_grantable_unlock(homa);
			}
			homa_rpc_unlock(rpc);
			atomic_dec(&rpc->grants_in_progress);
		}

		if (try_again == 0)
			break;
		INC_METRIC(grant_recalc_loops, 1);
		if (!homa_grantable_lock(homa, 1)) {
			INC_METRIC(grant_recalc_skips, 1);
			break;
		}
	}
	INC_METRIC(grant_recalc_cycles, get_cycles() - start);
}

/**
 * homa_grant_pick_rpcs() - Scan the grantable lists to identify the highest
 * priority RPCs for granting, subject to homa->max_rpcs_per_peer.
 * @homa:      Overall data about the Homa protocol implementation.
 * @rpcs:      The selected RPCs will be stored in this array, in
 *             decreasing priority order.
 * @max_rpcs:  Maximum number of RPCs to return in @rpcs.
 * Return:     The number of RPCs actually stored in @rpcs.
 */
int homa_grant_pick_rpcs(struct homa *homa, struct homa_rpc **rpcs,
		int max_rpcs)
{
	struct homa_peer *peer;
	struct homa_rpc *rpc;
	int num_rpcs = 0;

	/* Iterate over peers, in decreasing order of "highest priority
	 * RPC from this peer".
	 */
	list_for_each_entry(peer, &homa->grantable_peers, grantable_links) {
		int rpcs_from_peer = 0;

		/* Consider up to homa->max_rpcs_per_peer from this peer,
		 * in decreasing order of priority.
		 */
		list_for_each_entry(rpc, &peer->grantable_rpcs,
				grantable_links) {
			int i, pos;

			/* Figure out where this RPC should be positioned
			 * in the result.
			 */
			for (i = num_rpcs-1; i >= 0; i--) {
				if (!homa_grant_outranks(rpc, rpcs[i]))
					break;
			}

			/* Rpc must go at position i+1. */
			pos = i + 1;
			if (pos >= max_rpcs)
				break;
			if (num_rpcs < max_rpcs) {
				for (i = num_rpcs-1; i >= pos; i--)
					rpcs[i+1] = rpcs[i];
				num_rpcs++;
			} else {
				for (i = max_rpcs-2; i >= pos; i--)
					rpcs[i+1] = rpcs[i];
			}
			rpcs[pos] = rpc;
			rpcs_from_peer++;
			if (rpcs_from_peer >= homa->max_rpcs_per_peer)
				break;
		}
		if (rpcs_from_peer == 0) {
			/* If even the best RPC from this peer didn't fit,
			 * then no RPCS from any other peer will fit.
			 */
			break;
		}
	}
	return num_rpcs;
}


/**
 * homa_grant_find_oldest() - Recompute the value of homa->oldest_rpc.
 * @homa:    Overall data about the Homa protocol implementation. The
 *           grantable_lock must be held by the caller.
 */
void homa_grant_find_oldest(struct homa *homa)
{
	struct homa_rpc *rpc, *oldest;
	struct homa_peer *peer;
	__u64 oldest_birth;
	int max_incoming = homa->grant_window + 2*homa->fifo_grant_increment;

	oldest = NULL;
	oldest_birth = ~0;

	/* Find the oldest message that doesn't currently have an
	 * outstanding "pity grant".
	 */
	list_for_each_entry(peer, &homa->grantable_peers, grantable_links) {
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
	homa->oldest_rpc = oldest;
}
/**
 * homa_grant_free_rpc() - This function is invoked when an RPC is freed;
 * it cleans up any state related to grants for that RPC's incoming message.
 * @rpc:   The RPC to clean up. Must be locked by the caller.
 */
void homa_grant_free_rpc(struct homa_rpc *rpc)
{
	struct homa *homa = rpc->hsk->homa;

	if (!list_empty(&rpc->grantable_links)) {
		homa_grantable_lock(homa, 0);
		homa_grant_remove_rpc(rpc);
		if (atomic_read(&rpc->msgin.rank) >= 0) {
			/* Very tricky code below. We have to unlock the RPC before
			 * calling homa_grant_recalc. This creates a risk that the
			 * RPC could be reaped before the lock is reacquired.
			 * However, this function is only called from a specific
			 * place in homa_rpc_free where the RPC hasn't yet been put
			 * on the reap list, so there is no way it can be reaped
			 * until we return.
			 */
			homa_rpc_unlock(rpc);
			homa_grant_recalc(homa, 1);
			homa_rpc_lock(rpc, "homa_grant_free_rpc");
		} else
			homa_grantable_unlock(homa);
	}

	if (rpc->msgin.rec_incoming != 0)
		atomic_sub(rpc->msgin.rec_incoming, &homa->total_incoming);
}

/**
 * homa_grantable_lock_slow() - This function implements the slow path for
 * acquiring the grantable lock. It is invoked when the lock isn't immediately
 * available. It waits for the lock, but also records statistics about
 * the waiting time.
 * @homa:    Overall data about the Homa protocol implementation.
 * @recalc:  Nonzero means the caller is homa_grant_recalc; if another thread
 *           is already recalculating, can return without waiting for the lock.
 * Return:   Nonzero means this thread now owns the grantable lock. Zero
 *           means the lock was not acquired and there is no need for this
 *           thread to do the work of homa_grant_recalc because some other
 *           thread started a fresh calculation after this method was invoked.
 */
int homa_grantable_lock_slow(struct homa *homa, int recalc)
{
	int result = 0;
	__u64 start = get_cycles();
	int starting_count = atomic_read(&homa->grant_recalc_count);

	tt_record("beginning wait for grantable lock");
	while (1) {
		if (spin_trylock_bh(&homa->grantable_lock)) {
			tt_record("ending wait for grantable lock");
			result = 1;
			break;
		}
		if (recalc && atomic_read(&homa->grant_recalc_count)
				!= starting_count) {
			tt_record("skipping wait for grantable lock: recalc elsewhere");
			break;
		}
	}
	INC_METRIC(grantable_lock_misses, 1);
	INC_METRIC(grantable_lock_miss_cycles, get_cycles() - start);
	return result;
}

/**
 * homa_grant_log_tt() - Generate timetrace records describing all of
 * the active RPCs (those we are currently granting to).
 * @homa:  Overall information about the Homa transport.
 */
void homa_grant_log_tt(struct homa *homa)
{
	int i;

	homa_grantable_lock(homa, 0);
	tt_record1("homa_grant_log_tt found %d active RPCs:",
			homa->num_active_rpcs);
	for (i = 0; i < homa->num_active_rpcs; i++) {
		tt_record2("active_rpcs[%d]: id %d", i,
				homa->active_rpcs[i]->id);
		homa_rpc_log_tt(homa->active_rpcs[i]);
	}
	homa_grantable_unlock(homa);
}
