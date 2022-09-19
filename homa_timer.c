/* Copyright (c) 2019-2022 Stanford University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* This file handles timing-related functions for Homa, such as retries
 * and timeouts. */

#include "homa_impl.h"

/**
 * homa_check_rpc() -  Invoked for each RPC during each timer pass; does
 * most of the work of checking for time-related actions such as sending
 * resends, declaring a host dead, and sending requests for acks. Itt is
 * separate from homa_timer because homa_timer got too long and deeply
 * indented.
 * @rpc:     RPC to check; must be locked by the caller.
 * Return    Nonzero means this server has timed out; it's up to the caller
 *           to abort RPCs involving that server.
 */
int homa_check_rpc(struct homa_rpc *rpc)
{
	const char *us, *them;
	struct resend_header resend;
	struct homa *homa = rpc->hsk->homa;
	struct homa_peer *peer;

	/* See if we need to request an ack for this RPC. */
	if (!homa_is_client(rpc->id) && (rpc->state == RPC_OUTGOING)
			&& (rpc->msgout.next_packet == NULL)) {
		if (rpc->done_timer_ticks == 0)
			rpc->done_timer_ticks = homa->timer_ticks;
		else {
			/* >= comparison that handles tick wrap-around. */
			if ((rpc->done_timer_ticks + homa->request_ack_ticks
					- 1 - homa->timer_ticks) & 1<<31) {
				struct need_ack_header h;
				homa_xmit_control(NEED_ACK, &h, sizeof(h), rpc);
				tt_record4("Sent NEED_ACK for RPC id %d to "
						"peer 0x%x, port %d, ticks %d",
						rpc->id,
						ip6_as_be32(rpc->peer->addr),
						rpc->dport, homa->timer_ticks
						- rpc->done_timer_ticks);
			}
		}
	}

	if ((rpc->state == RPC_OUTGOING)
			&& (homa_rpc_send_offset(rpc) < rpc->msgout.granted)) {
		/* There are granted bytes that we haven't transmitted, so
		 * no need to be concerned about lack of traffic from the peer.
		 */
		rpc->silent_ticks = 0;
		return 0;
	}

	if ((rpc->state == RPC_INCOMING) && ((rpc->msgin.total_length
			- rpc->msgin.bytes_remaining)
			>= rpc->msgin.incoming)) {
		/* We've received everything that we've granted, so we
		 * shouldn't expect to hear anything until we grant more.
		 */
		rpc->silent_ticks = 0;
		return 0;
	}

	/* The -1 below is so that this RPC in considered in the
	 * computation of peer->least_recent_rpc just before it reaches
	 * homa->resend_ticks; the resend won't actually occur for
	 * another tick.
	 */
	if (rpc->silent_ticks < (homa->resend_ticks-1))
		return 0;

	peer = rpc->peer;
	if (peer->outstanding_resends
			>= rpc->hsk->homa->timeout_resends) {
		INC_METRIC(peer_timeouts, 1);
		tt_record4("peer 0x%x timed out for RPC id %d, "
				"state %d, outstanding_resends %d",
				ip6_as_be32(peer->addr),
				rpc->id, rpc->state,
				peer->outstanding_resends);
		if (homa->verbose)
			printk(KERN_NOTICE "Homa peer %s timed out, id %llu",
					homa_print_ipv6_addr(&peer->addr),
					rpc->id);
		homa_freeze(rpc, PEER_TIMEOUT, "Freezing because of peer "
				"timeout, id %d, peer 0x%x");
		peer->outstanding_resends = 0;
		return 1;
	}

	/* Resends serve two purposes: to force retransmission of lost packets,
	 * and to detect if servers have crashed. We only send one resend to
	 * a given peer at a time: if many RPCs need resends to the same peer,
	 * it's almost certainly because the peer is overloaded, so we don't
	 * want to add to its load by sending lots of resends; we just want to
	 * make sure that it is still alive. However, if there are multiple
	 * RPCs that need resends, we need to rotate between them, so that
	 * every RPC eventually gets a resend. In earlier versions of Homa
	 * we only sent to the oldest RPC, but this led to distributed
	 * deadlock in situations where the oldest RPC can't make progress
	 * until some other RPC makes progress (e.g. a server is waiting
	 * to receive one RPC before it replies to another, or some RPC is
	 * first on @peer->grantable_rpcs, so it blocks transmissions of
	 * other RPCs.
	 */

	/* First, collect information that will identify the RPC most
	 * in need of a resend; this will be used during the *next*
	 * homa_timer pass.
	 */
	if (peer->current_ticks != homa->timer_ticks) {
		/* Reset info for this peer.*/
		peer->resend_rpc = peer->least_recent_rpc;
		peer->least_recent_rpc = NULL;
		peer->least_recent_ticks = homa->timer_ticks;
		peer->current_ticks = homa->timer_ticks;
	}

	if ((rpc != peer->resend_rpc) ||
			(homa->timer_ticks - rpc->peer->most_recent_resend)
			< homa->resend_interval) {
		/* We're not sending a resend to this RPC now. Update info
		 * about the best RPC for the next resend. Note: comparing
		 * values in the face of wrap-around and compiler
		 * optimizations is tricky; don't change the comparison below
		 * unless you're sure you know what you are doing.
		 */
	       if (!((peer->least_recent_ticks - rpc->resend_timer_ticks)
			       & (1U<<31))) {
		       peer->least_recent_rpc = rpc;
		       peer->least_recent_ticks = rpc->resend_timer_ticks;
	       }
	       return 0;
	}

	/* Issue a resend for this RPC. */
	rpc->resend_timer_ticks = homa->timer_ticks;
	rpc->peer->most_recent_resend = homa->timer_ticks;
	rpc->peer->outstanding_resends++;
	homa_get_resend_range(&rpc->msgin, &resend);
	resend.priority = homa->num_priorities-1;
	homa_xmit_control(RESEND, &resend, sizeof(resend), rpc);
	if (homa_is_client(rpc->id)) {
		us = "client";
		them = "server";
		tt_record4("Sent RESEND for client RPC id %llu, server 0x%x:%d, "
				"offset %d",
				rpc->id, ip6_as_be32(rpc->peer->addr),
				rpc->dport, ntohl(resend.offset));
	} else {
		us = "server";
		them = "client";
		tt_record4("Sent RESEND for server RPC id %llu, client 0x%x:%d "
				"offset %d",
				rpc->id, ip6_as_be32(rpc->peer->addr),
				rpc->dport, ntohl(resend.offset));
	}
	if (homa->verbose) {
		printk(KERN_NOTICE "Homa %s RESEND to %s %s:%d for id %llu, "
				"offset %d, length %d", us, them,
				homa_print_ipv6_addr(&rpc->peer->addr),
				rpc->dport, rpc->id, ntohl(resend.offset),
				ntohl(resend.length));
	}
	return 0;
}

/**
 * homa_timer() - This function is invoked at regular intervals ("ticks")
 * to implement retries and aborts for Homa.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_timer(struct homa *homa)
{
	struct homa_socktab_scan scan;
	struct homa_sock *hsk;
	struct homa_rpc *rpc;
	cycles_t start, end;
	struct homa_peer *dead_peer = NULL;
	int rpc_count = 0;
	int total_rpcs = 0;

	start = get_cycles();
	homa->timer_ticks++;

	/* Scan all existing RPCs in all sockets.  The rcu_read_lock
	 * below prevents sockets from being deleted during the scan.
	 */
	rcu_read_lock();
	for (hsk = homa_socktab_start_scan(&homa->port_map, &scan);
			hsk !=  NULL; hsk = homa_socktab_next(&scan)) {
		while (hsk->dead_skbs >= homa->dead_buffs_limit) {
			/* If we get here, it means that homa_wait_for_message
			 * isn't keeping up with RPC reaping, so we'll help
			 * out.  See reap.txt for more info. */
			uint64_t start = get_cycles();
			tt_record("homa_timer calling homa_rpc_reap");
			if (homa_rpc_reap(hsk, hsk->homa->reap_limit) == 0)
				break;
			INC_METRIC(timer_reap_cycles, get_cycles() - start);
		}

		if (list_empty(&hsk->active_rpcs) || hsk->shutdown)
			continue;

		if (!homa_protect_rpcs(hsk))
			continue;
		list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
			total_rpcs++;
			homa_rpc_lock(rpc);
			if ((rpc->state == RPC_READY)
					|| (rpc->state == RPC_IN_SERVICE)) {
				rpc->silent_ticks = 0;
				homa_rpc_unlock(rpc);
				continue;
			}
			rpc->silent_ticks++;
			if (homa_check_rpc(rpc))
				dead_peer = rpc->peer;
			homa_rpc_unlock(rpc);
			rpc_count++;
			if (rpc_count >= 10) {
				/* Give other kernel threads a chance to run
				 * on this core. Must release the RCU read lock
				 * while doing this.
				 */
				rcu_read_unlock();
				schedule();
				rcu_read_lock();
				rpc_count = 0;
			}
		}
		homa_unprotect_rpcs(hsk);
	}
	rcu_read_unlock();
	if (dead_peer) {
		/* We only timeout one peer per call to this function (it's
		 * tricky from a synchronization standpoint to handle the
		 * crash in the middle of the loop above, and trying to
		 * remember more than one dead peer until we get here adds
		 * complexity). If there's more than one dead peer, we'll
		 * timeout another one in the next call.
		 */
		homa_abort_rpcs(homa, &dead_peer->addr, 0, -ETIMEDOUT);
	}

	if (total_rpcs > 0)
		tt_record1("homa_timer finished scanning %d RPCs", total_rpcs);

	end = get_cycles();
	INC_METRIC(timer_cycles, end-start);
//	tt_record("homa_timer finishing");
}
