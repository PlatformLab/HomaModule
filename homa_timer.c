/* Copyright (c) 2019, Stanford University
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
 * homa_check_timeout() -  This does most of the work of detecting timeouts
 * and requesting resends; it is separate from homa_timer because homa_timer
 * got too long and deeply indented.
 * @rpc:     RPC to check; must be locked by the caller.
 * Return    Nonzero means this server has timed out; it's up to the caller
 *           to abort RPCs.
 */
int homa_check_timeout(struct homa_rpc *rpc)
{
	const char *us, *them;
	struct resend_header resend;
	struct homa *homa = rpc->hsk->homa;

	if (rpc->silent_ticks < homa->resend_ticks)
		return 0;
	
	if (rpc->is_client) {
		if (rpc->msgout.next_packet && (homa_data_offset(
				rpc->msgout.next_packet) < rpc->msgout.granted)) {
			/* We haven't transmitted all of the granted bytes in
			 * the request, so there's no need to be concerned
			 * about the lack of traffic from the server.
			 */
			rpc->silent_ticks = 0;
			return 0;
		}
		if ((rpc->state == RPC_INCOMING) && ((rpc->msgin.total_length
				- rpc->msgin.bytes_remaining)
				>= rpc->msgin.incoming)) {
			/* We've received everything that we've granted, so we
			 * shouldn't expect to hear anything until we grant
			 * more. However, if we don't communicate with the
			 * server, it will eventually timeout and discard
			 * the response. To prevent this, send a BUSY packet.
			 */
			struct busy_header busy;
			homa_xmit_control(BUSY, &busy, sizeof(busy), rpc);
			rpc->silent_ticks = 0;
			return 0;
		}
		if (rpc->peer->outstanding_resends
				>= rpc->hsk->homa->timeout_resends) {
			INC_METRIC(client_peer_timeouts, 1);
			tt_record4("server timed out: peer 0x%x, RPC id %d, "
					"state %d, outstanding_resends %d",
					htonl(rpc->peer->addr),
					rpc->id, rpc->state,
					rpc->peer->outstanding_resends);
			if (homa->verbose)
				printk(KERN_NOTICE "Homa server timeout, "
						"server %s:%d, id %llu",
						homa_print_ipv4_addr(
							rpc->peer->addr),
						rpc->dport, rpc->id);
			if (!tt_frozen) {
				struct freeze_header freeze;
				tt_record2("Freezing because of server timeout,"
						" id %d, peer 0x%x",
						rpc->id,
						htonl(rpc->peer->addr));
				homa_xmit_control(FREEZE, &freeze,
						sizeof(freeze), rpc);
				tt_freeze();
			}
			return 1;
		}
	} else {
		/* Server RPC */
		if ((rpc->state == RPC_INCOMING) && ((rpc->msgin.total_length
				- rpc->msgin.bytes_remaining)
				>= rpc->msgin.incoming)) {
			/* We've received everything that we've granted, so we
			 * shouldn't expect to hear anything until we grant
			 * more.
			 */
			rpc->silent_ticks = 0;
			return 0;
		}
		if (rpc->silent_ticks >= homa->rpc_discard_ticks) {
			INC_METRIC(server_rpc_discards, 1);
			tt_record2("discarding server RPC: peer 0x%x, id %d",
					ntohl(rpc->peer->addr), rpc->id);
			if (rpc->hsk->homa->verbose)
				printk(KERN_NOTICE "Homa server discarding "
						"RPC, client %s:%d, id %llu",
						homa_print_ipv4_addr(
							rpc->peer->addr),
						rpc->dport, rpc->id);
			return 1;
		}

		/* Don't send RESENDs in RPC_OUTGOING state: it's up to the
		 * client to handle this.
		 */
		if (rpc->state != RPC_INCOMING)
			return 0;
	}
	
	/* Resends serve two purposes: to force retransmission of lost packets,
	 * and to detect if servers have crashed. We only send one resend to
	 * a given peer at a time: if many RPCs need resends to the same peer,
	 * it's almost certainly because the peer is overloaded, so we don't
	 * want to add to its load by sending lots of resends; we just want to
	 * make sure that it is still alive. Since homa_timer scans RPCs in
	 * order of age, we will only send resends for the oldest RPC (thus
	 * every RPC will eventually issue a resend if it really needs one
	 * because of a packet loss). Note: if an RPC is at the front of the
	 * peer's grantable list, we will send a resend for it even if we
	 * have already sent one resend during this timer tick. If we don't,
	 * a lost packet for that RPC could result in RPCs from that peer
	 * getting "stuck".
	 */
	if ((rpc->peer->most_recent_resend == homa->timer_ticks)
			&& (rpc == list_first_entry(&rpc->peer->grantable_rpcs,
			struct homa_rpc, grantable_links)))
		goto resend;
	if ((homa->timer_ticks - rpc->peer->most_recent_resend)
			< homa->resend_interval)
		return 0;
	rpc->peer->most_recent_resend = homa->timer_ticks;
	rpc->peer->outstanding_resends++;

resend:
	homa_get_resend_range(&rpc->msgin, &resend);
	resend.priority = homa->num_priorities-1;
	homa_xmit_control(RESEND, &resend, sizeof(resend), rpc);
	if (rpc->is_client) {
		us = "client";
		them = "server";
		tt_record4("Sent RESEND for client RPC id %llu, server 0x%x:%d, "
				"offset %d",
				rpc->id, htonl(rpc->peer->addr), rpc->dport,
				ntohl(resend.offset));
	} else {
		us = "server";
		them = "client";
		tt_record4("Sent RESEND for server RPC id %llu, client 0x%x:%d "
				"offset %d",
				rpc->id, htonl(rpc->peer->addr), rpc->dport,
				ntohl(resend.offset));
	}
	if (homa->verbose) {
		printk(KERN_NOTICE "Homa %s RESEND to %s %s:%d for id %llu, "
				"offset %d, length %d", us, them,
				homa_print_ipv4_addr(rpc->peer->addr),
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
	
	start = get_cycles();
	homa->timer_ticks++;
//	tt_record("homa_timer starting");

	/* Scan all existing RPCs in all sockets.  The rcu_read_lock
	 * below prevents sockets from being deleted during the scan.
	 */
	rcu_read_lock();
	for (hsk = homa_socktab_start_scan(&homa->port_map, &scan);
			hsk !=  NULL; hsk = homa_socktab_next(&scan)) {
		if (list_empty(&hsk->active_rpcs) || hsk->shutdown)
			continue;
		
		if (!homa_protect_rpcs(hsk))
			continue;
		list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
			homa_rpc_lock(rpc);
			if ((rpc->state == RPC_READY)
					|| (rpc->state == RPC_IN_SERVICE)) {
				rpc->silent_ticks = 0;
				homa_rpc_unlock(rpc);
				continue;
			}
			rpc->silent_ticks++;
			if (homa_check_timeout(rpc)) {
				if (rpc->is_client)
					dead_peer = rpc->peer;
				else
					homa_rpc_free(rpc);
			}
			homa_rpc_unlock(rpc);
			rpc_count++;
			if (rpc_count >= 10) {
				/* Give other kernel threads a chance to run
				 * on this core.
				 */
				schedule();
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
		homa_peer_abort(homa, dead_peer->addr, -ETIMEDOUT);
	}
	end = get_cycles();
	INC_METRIC(timer_cycles, end-start);
//	tt_record("homa_timer finishing");
}