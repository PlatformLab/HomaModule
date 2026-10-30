// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

/* This file handles timing-related functions for Homa, such as retries
 * and timeouts.
 */

/* Homa Retransmission Strategy:
 *
 * (This documentation is referenced in several other places in the Homa code)
 *
 * As a general rule, retransmission of lost packets is receiver-driven in
 * Homa: the receiver notices that it has not received expected message
 * data within an expected time window, so it issues RESEND packets to
 * request retransmission. However, there are some situations where the
 * receiver may not even be aware that data is incoming (for example, if
 * all of the initial packets of a request message are lost); these
 * situations require special handling.
 *
 * The bullet points below walk through the life of an RPC, showing how
 * packet loss at each point is handled. If you see this comment in a
 * version of Homa where the packet type START_MSG is not defined, then
 * there will be no START_MSG packets and all messages will be unscheduled.
 *
 * 1. The START_MSG packet for a scheduled request is lost: the client notices
 *    that it has not received any grants from the peer, so it retransmits the
 *    START_MSG.
 * 2. All of the DATA packets for an unscheduled request are lost, so the server
 *    has no knowledge of the RPC: the client sends a RESEND packet for the
 *    response; the server returns an RPC_UNKNOWN packet; then the client
 *    retransmits the entire request message.
 * 3. DATA packets for a request are lost, but the server has received at
 *    least one DATA or START_MSG packet: the server's homa_timer notices
 *    an excessive delay in the arrival of data and sends RESEND packet(s)
 *    to request retransmission.
 * 4. The START_MSG packet for a scheduled response is lost: the client sends
 *    a RESEND packet for the response; the server then retransmits the
 *    START_MSG packet (it sends START_MSG rather than DATA so that the client
 *    knows it must issue grants for the message).
 * 5. All of the DATA packets for an unscheduled response are lost: the
 *    client sends a RESEND packet for the response; the server then
 *    retransmits the response message.
 * 6. DATA packets for a response are lost, but the client has received at
 *    least one DATA or START_MSG packet: the client's homa_timer notices
 *    an excessive delay in the arrival of data and sends RESEND packet(s)
 *    to request retransmission.
 *
 * To the client, cases 2, 4, and 5 are initially indistinguishable and
 * are all handled the same way, by issuing a RESEND for the entire response.
 *
 * There are some situations where a RESEND packet is sent but the
 * recipient has not yet transmitted the "missing" packets (intentionally).
 * For example, if the server application takes a long time to generate a
 * response message, the client may issue a RESEND (this appears like cases 2,
 * 4, and 5). Another example is if the sender of a message has not sent
 * packets because it has been using its uplink bandwidth for higher priority
 * messages. In cases like this, when a RESEND packet arrives the recipient
 * returns a BUSY packet to indicate that it cannot (or has chosen not to)
 * send the desired packets. When a recipient receives a BUSY packet it resets
 * its timeout mechanism (it will eventually issue aditional RESENDs if the
 * desired packets do not arrive, but it will wait longer before doing so).
 */

#include "homa_impl.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#include "homa_tx_pool.h"
#ifndef __STRIP__ /* See strip.py */
#include "homa_grant.h"
#endif /* See strip.py */

/**
 * homa_timer_check_rpc() -  Invoked for each RPC during each timer pass; does
 * most of the work of checking for time-related actions such as sending
 * resends, aborting RPCs for which there is no response, and sending
 * requests for acks. It is separate from homa_timer because homa_timer
 * got too long and deeply indented.
 * @rpc:     RPC to check; must be locked by the caller.
 */
void homa_timer_check_rpc(struct homa_rpc *rpc)
	__must_hold(rpc->bucket->lock)
{
	struct homa *homa = rpc->hsk->homa;
	int tx_end = homa_rpc_tx_end(rpc);

	/* See if we need to request an ack for this RPC. */
	if (!homa_is_client(rpc->id) && rpc->state == RPC_OUTGOING &&
	    tx_end == rpc->msgout.length) {
		if (rpc->done_timer_ticks == 0) {
			rpc->done_timer_ticks = homa->timer_ticks;
		} else {
			/* >= comparison that handles tick wrap-around. */
			if ((rpc->done_timer_ticks + homa->request_ack_ticks
					- 1 - homa->timer_ticks) & 1U << 31) {
				struct homa_need_ack_hdr h;

				homa_xmit_control(NEED_ACK, &h, sizeof(h), rpc);
				tt_record4("Sent NEED_ACK for RPC id %d to peer 0x%x, port %d, ticks %d",
					   rpc->id,
					   tt_addr(rpc->route->peer->addr),
					   rpc->dport, homa->timer_ticks
					   - rpc->done_timer_ticks);
			}
		}
	}

	/* Check for conditions under which it isn't a problem if we haven't
	 * heard from the peer.
	 */
	if (rpc->state == RPC_INCOMING) {
#ifndef __STRIP__ /* See strip.py */
		if ((rpc->msgin.length - rpc->msgin.bytes_remaining)
				>= rpc->msgin.granted) {
			/* We've received everything that we've granted, so we
			 * shouldn't expect to hear anything until we grant more.
			 */
			rpc->silent_ticks = 0;
			return;
		}
#endif /* See strip.py */
		if (rpc->msgin.num_bpages == 0) {
			/* Waiting for buffer space, so no problem. */
			rpc->silent_ticks = 0;
			return;
		}
	} else if (!homa_is_client(rpc->id)) {
		/* We're the server and we've received the input message;
		 * no need to worry about retries.
		 */
		rpc->silent_ticks = 0;
		return;
	}

	if (rpc->state == RPC_OUTGOING) {
#ifndef __STRIP__ /* See strip.py */
		if (tx_end < rpc->msgout.granted) {
#else /* See strip.py */
		if (tx_end < rpc->msgout.length) {
#endif /* See strip.py */
			/* There are granted bytes that we haven't transmitted,
			 * so no need to be concerned; the ball is in our court.
			 */
			rpc->silent_ticks = 0;
			return;
		}
	}

	if (rpc->silent_ticks < homa->resend_ticks)
		return;
	if (rpc->silent_ticks >= homa->timeout_ticks) {
		INC_METRIC(rpc_timeouts, 1);
		tt_record3("RPC id %d, peer 0x%x, aborted because of timeout, state %d",
			   rpc->id, tt_addr(rpc->route->peer->addr), rpc->state);
#ifndef __STRIP__ /* See strip.py */
#if 0
		homa_rpc_log_active_tt(homa, 0);
		tt_record1("Freezing because of RPC abort (id %d)", rpc->id);
		homa_freeze_peers();
		tt_freeze();
#endif
		if (homa->verbose)
			pr_notice("RPC id %llu, peer %s, aborted because of timeout, state %d\n",
				  rpc->id,
				  homa_print_ipv6_addr(&rpc->route->peer->addr),
				  rpc->state);
#endif /* See strip.py */
		homa_rpc_abort(rpc, -ETIMEDOUT);
		return;
	}
	if (((rpc->silent_ticks - homa->resend_ticks) % homa->resend_interval)
			== 0)
		homa_request_retrans(rpc);
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
	int rpc_count = 0;

#ifndef __STRIP__ /* See strip.py */
	static u64 prev_grant_count;
	int total_incoming_rpcs = 0;
	int sum_incoming_rec = 0;
	static int zero_count;
	int sum_incoming = 0;
	int total_rpcs = 0;
	u64 total_grants;
	cycles_t start;
	cycles_t end;
	int core;
#endif /* See strip.py */

	homa->timer_ticks++;

#ifndef __STRIP__ /* See strip.py */
	start = homa_clock();
	total_grants = 0;
	for (core = 0; core < nr_cpu_ids; core++) {
		struct homa_metrics *m = homa_metrics_per_cpu();

		total_grants += m->packets_sent[GRANT - DATA];
	}

	if (atomic_read(&homa->grant->total_incoming) != 0 ||
	    homa->grant->num_grantable_rpcs != 0 ||
	    homa->grant->num_active != 0 ||
	    total_grants - prev_grant_count != 0)
		tt_record4("homa_timer found total_incoming %d, num_grantable_rpcs %d, num_active_rpcs %d, new grants %d",
			   atomic_read(&homa->grant->total_incoming),
			   homa->grant->num_grantable_rpcs,
			   homa->grant->num_active,
			   total_grants - prev_grant_count);
	if (total_grants == prev_grant_count &&
	    homa->grant->num_grantable_rpcs > 20) {
		zero_count++;
		if (zero_count > 3 && !atomic_read(&tt_frozen) && 0) {
			pr_err("%s found no grants going out\n", __func__);
			homa_rpc_log_active_tt(homa, 0);
			tt_record("freezing because no grants are going out");
			homa_freeze_peers();
			tt_freeze();
		}
	} else {
		zero_count = 0;
	}
	prev_grant_count = total_grants;
#endif /* See strip.py */

	/* Scan all existing RPCs in all sockets. */
	for (hsk = homa_socktab_start_scan(homa->socktab, &scan);
			hsk; hsk = homa_socktab_next(&scan)) {
		while (hsk->dead_frags > homa->dead_frags_limit) {
			/* If we get here, it means that Homa isn't keeping
			 * up with RPC reaping, so we'll help out.  See
			 * "RPC Reaping Strategy" in homa_rpc_reap code for
			 * details.
			 */
#ifndef __STRIP__ /* See strip.py */
			u64 rpc_start = homa_clock();
#endif /* See strip.py */

			tt_record("homa_timer calling homa_rpc_reap");
			if (homa_rpc_reap(hsk) == 0)
				break;
			INC_METRIC(timer_reap_cycles, homa_clock() - rpc_start);
		}

		if (list_empty(&hsk->active_rpcs) || hsk->shutdown)
			continue;

		if (!homa_protect_rpcs(hsk))
			continue;
		rcu_read_lock();
		list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
			IF_NO_STRIP(total_rpcs++);

			homa_rpc_lock(rpc);
			if (rpc->state == RPC_IN_SERVICE) {
				rpc->silent_ticks = 0;
				homa_rpc_unlock(rpc);
				continue;
#ifndef __STRIP__ /* See strip.py */
			} else if (rpc->state == RPC_INCOMING) {
				total_incoming_rpcs += 1;
				sum_incoming_rec += rpc->msgin.rec_incoming;
				sum_incoming += rpc->msgin.granted
						- (rpc->msgin.length
						- rpc->msgin.bytes_remaining);
#endif /* See strip.py */
			}
			rpc->silent_ticks++;
			homa_timer_check_rpc(rpc);
			homa_rpc_unlock(rpc);
			rpc_count++;
			if (rpc_count >= 10) {
				/* Give other kernel threads a chance to run
				 * on this core.
				 */
				rcu_read_unlock();
				schedule();
				rcu_read_lock();
				rpc_count = 0;
			}
		}
		rcu_read_unlock();
		homa_unprotect_rpcs(hsk);
	}
	homa_socktab_end_scan(&scan);
#ifndef __STRIP__ /* See strip.py */
	if (total_incoming_rpcs > 0)
		tt_record4("homa_timer found %d incoming RPCs, incoming sum %d, rec_sum %d, homa->total_incoming %d",
			   total_incoming_rpcs, sum_incoming, sum_incoming_rec,
			   atomic_read(&homa->grant->total_incoming));
#endif /* See strip.py */
	homa_tx_pool_gc(homa);
	homa_route_gc(homa->peertab);
#ifndef __STRIP__ /* See strip.py */
	homa_snapshot_rpcs();
	end = homa_clock();
	INC_METRIC(timer_cycles, end - start);
#endif /* See strip.py */
}
