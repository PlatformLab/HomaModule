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
 * @rpc:     RPC with silent_ticks >= homa->resend_ticks. Must be locked
 *           by the caller.
 * Return    Nonzero means this server has timed out; it's up to the caller
 *           to abort RPCs.
 */
int homa_check_timeout(struct homa_rpc *rpc)
{
	const char *us, *them;
	struct resend_header resend;
	struct homa *homa = rpc->hsk->homa;
	
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
			homa_xmit_control(BUSY, &busy, sizeof(busy),rpc);
			rpc->silent_ticks = 0;
			return 0;
		}
		if (rpc->num_resends >= rpc->hsk->homa->abort_resends) {
			if (homa->verbose)
				printk(KERN_NOTICE "Homa client RPC timeout, "
						"server %s:%d, id %llu",
						homa_print_ipv4_addr(
						rpc->peer->addr),
						rpc->dport, rpc->id);
			tt_record2("Client RPC timeout, id %llu, port %d",
					rpc->id, rpc->dport);
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
		if (rpc->num_resends >= rpc->hsk->homa->abort_resends) {
			return 1;
		}

		/* Don't send RESENDs in RPC_OUTGOING state: it's up to the
		 * client to handle this.
		 */
		if (rpc->state != RPC_INCOMING)
			return 0;
	}

	/* Must issue a RESEND. */
	if ((homa->timer_ticks - rpc->peer->last_resend_tick)
			< homa->resend_interval)
		return 0;
	rpc->peer->last_resend_tick = homa->timer_ticks;
	rpc->num_resends++;
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
	bool print_active = false;
	int num_active = 0;
	struct homa_peer *dead_peer = NULL;
	
	start = get_cycles();
	homa->timer_ticks++;
	if (homa->flags & HOMA_FLAG_LOG_ACTIVE_RPCS) {
		print_active = true;
		homa->flags &= ~HOMA_FLAG_LOG_ACTIVE_RPCS;
	}

	/* Scan all existing RPCs in all sockets.  The rcu_read_lock
	 * below prevents sockets from being deleted during the scan.
	 */
	rcu_read_lock();
	for (hsk = homa_socktab_start_scan(&homa->port_map, &scan);
			hsk !=  NULL; hsk = homa_socktab_next(&scan)) {
		if (list_empty(&hsk->active_rpcs) || hsk->shutdown)
			continue;
		
		atomic_inc(&hsk->reap_disable);
		list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
			homa_rpc_lock(rpc);
			if (unlikely(print_active)) {
				int in_remaining = 0;
				int incoming = 0;
				int out_sent = rpc->msgout.length;
				if (rpc->msgin.total_length > 0) {
					in_remaining =
						rpc->msgin.bytes_remaining;
					incoming = rpc->msgin.incoming;
				}
				if (rpc->msgout.next_packet)
					out_sent = homa_data_offset(
							rpc->msgout.next_packet);
				printk(KERN_NOTICE "Active %s RPC, peer "
					"%s, port %u, id %llu, state %s, "
					"silent %d, msgin remaining %d/%d "
					"incoming %d, msgout sent %d/%d, "
					"error %d\n",
					rpc->is_client ? "client" : "server",
					homa_print_ipv4_addr(rpc->peer->addr),
					rpc->dport, rpc->id,
					homa_symbol_for_state(rpc),
					rpc->silent_ticks,
					in_remaining, rpc->msgin.total_length,
					incoming, out_sent,
					rpc->msgout.length, rpc->error);
				num_active++;
			}
			if ((rpc->state == RPC_READY)
					|| (rpc->state == RPC_IN_SERVICE)) {
				rpc->silent_ticks = 0;
				homa_rpc_unlock(rpc);
				continue;
			}
			rpc->silent_ticks++;
			if (rpc->silent_ticks >= homa->resend_ticks) {
				if (homa_check_timeout(rpc)) {
					tt_record4("rpc timed out: peer 0x%x, "
							"port %d, id %d,"
							"state %d",
							htonl(rpc->peer->addr),
							rpc->dport, rpc->id,
							rpc->state);
					if (rpc->is_client) {
						if (!tt_frozen) {
							struct freeze_header freeze;
							tt_record2("Freezing because of RPC timeout, id %d, peer 0x%x", rpc->id, htonl(rpc->peer->addr));
							tt_freeze();
							homa_xmit_control(FREEZE,
								&freeze,
								sizeof(freeze),rpc);
						}
						dead_peer = rpc->peer;
					} else {
						INC_METRIC(server_rpc_timeouts, 1);
						if (rpc->hsk->homa->verbose)
							printk(KERN_NOTICE "Homa server "
								"RPC timeout, client "
								"%s:%d, id %llu",
								homa_print_ipv4_addr(
									rpc->peer->addr),
								rpc->dport, rpc->id);
						homa_rpc_free(rpc);
					}
				}
			}
			homa_rpc_unlock(rpc);
		}
		if (print_active) {
			struct list_head *pos;
			int requests = 0;
			int responses = 0;
			homa_sock_lock(hsk, "homa_timer");
			list_for_each(pos, &hsk->ready_requests) {
				requests++;
			}
			list_for_each(pos, &hsk->ready_responses) {
				responses++;
			}
			homa_sock_unlock(hsk);
			printk(KERN_NOTICE "%d ready requests, %d ready "
					"responses for socket\n",
					requests, responses);
		}
		atomic_dec(&hsk->reap_disable);
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
	if (print_active && num_active) {
		printk(KERN_NOTICE "Found %d active Homa RPCs\n", num_active);
	}
	end = get_cycles();
	INC_METRIC(timer_cycles, end-start);
}