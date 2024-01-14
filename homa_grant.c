/* Copyright (c) 2024 Homa Developers
 * SPDX-License-Identifier: BSD-1-Clause
 */

/* This file contains functions related to issuing grants for incoming
 * messages.
 */

#include "homa_impl.h"

/**
 * homa_grant_prio() - Returns nonzero if rpc1 should be considered
 * higher priority for grants than rpc2, and zero if the two RPCS are
 * equivalent or rpc2 is higher priority.
 * @rpc1     First RPC to consider.
 * @rpc2     Second RPC to consider.
 */
int inline homa_grant_prio(struct homa_rpc *rpc1, struct homa_rpc *rpc2)
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
		rpc->msgin.birth = get_cycles();
		list_for_each_entry(candidate, &peer->grantable_rpcs,
				grantable_links) {
			if (homa_grant_prio(rpc, candidate)) {
				list_add_tail(&rpc->grantable_links,
						&candidate->grantable_links);
				goto position_peer;
			}
		}
		list_add_tail(&rpc->grantable_links, &peer->grantable_rpcs);
	} else while (rpc != list_first_entry(&peer->grantable_rpcs,
			struct homa_rpc, grantable_links)) {
		/* Message is on the list, but its priority may have
		 * increased because of the recent packet arrival. If so,
		 * adjust its position in the list.
		 */
		candidate = list_prev_entry(rpc, grantable_links);
		if (!homa_grant_prio(rpc, candidate))
			goto position_peer;
		__list_del_entry(&candidate->grantable_links);
		list_add(&candidate->grantable_links, &rpc->grantable_links);
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
			if (homa_grant_prio(rpc, candidate)) {
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
		if (!homa_grant_prio(rpc, candidate))
			goto done;
		__list_del_entry(&prev_peer->grantable_links);
		list_add(&prev_peer->grantable_links, &peer->grantable_links);
	}
    done:
}

/**
 * homa_remove_rpc() - Unlink an RPC from the grantable lists, so it will no
 * longer be considered for grants. The caller must hold the grantable lock.
 * @rpc:     RPC to remove from grantable lists.  Must currently be in
 *           a grantable list.
 */
void homa_grant_remove_rpc(struct homa_rpc *rpc)
{
	struct homa_rpc *head;
	struct homa_peer *peer = rpc->peer;
	struct homa_rpc *candidate;
	struct homa *homa = rpc->hsk->homa;

	head =  list_first_entry(&peer->grantable_rpcs,
			struct homa_rpc, grantable_links);
	list_del_init(&rpc->grantable_links);
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
		if (!homa_grant_prio(rpc, candidate))
			break;
		__list_del_entry(&peer->grantable_links);
		list_add(&peer->grantable_links, &next_peer->grantable_links);
	}
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
				if (!homa_grant_prio(rpc, rpcs[i]))
					break;
			}

			/* Rpc must go at position i+1. */
			pos = i + 1;
			if (pos >= max_rpcs)
				break;
			for (i = num_rpcs-1; i >= pos; i--)
				rpcs[i+1] = rpcs[i];
			rpcs[pos] = rpc;
			num_rpcs++;
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
 * homa_grant_update_incoming() - Figure out how much incoming data there is
 * for an RPC (i.e., data that has been granted but not yet received) and make
 * sure this is properly reflected in homa->total_incoming.
 * @rpc:   RPC to check; must be locked by the caller.
 */
void homa_grant_update_incoming(struct homa_rpc *rpc) {
	int new_incoming;

	if (rpc->msgin.length < 0)
		return;
	new_incoming = rpc->msgin.granted - (rpc->msgin.length
		- rpc->msgin.bytes_remaining);

	if (new_incoming < 0)
		new_incoming = 0;
	if (new_incoming != rpc->msgin.rec_incoming) {
		// homa_grant_check_validation(rpc->hsk->homa);
		atomic_add(new_incoming - rpc->msgin.rec_incoming,
				&rpc->hsk->homa->total_incoming);
		tt_record4("homa_grant adjusted total_incoming for id %d; "
				"new %d, old %d, total %d",
				rpc->id, new_incoming, rpc->msgin.rec_incoming,
				atomic_read(&rpc->hsk->homa->total_incoming));
		tt_record3("length %d, rem %d, granted %d", rpc->msgin.length,
				rpc->msgin.bytes_remaining, rpc->msgin.granted);
		rpc->msgin.rec_incoming = new_incoming;
	}

}