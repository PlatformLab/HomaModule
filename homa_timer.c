// SPDX-License-Identifier: BSD-2-Clause

/* This file handles timing-related functions for Homa, such as retries
 * and timeouts.
 */

#include "homa_impl.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#include "homa_skb.h"

/**
 * homa_check_rpc() -  Invoked for each RPC during each timer pass; does
 * most of the work of checking for time-related actions such as sending
 * resends, aborting RPCs for which there is no response, and sending
 * requests for acks. It is separate from homa_timer because homa_timer
 * got too long and deeply indented.
 * @rpc:     RPC to check; must be locked by the caller.
 */
void homa_check_rpc(struct homa_rpc *rpc)
{
	struct homa *homa = rpc->hsk->homa;
	struct homa_resend_hdr resend;
	const char *us, *them;

	/* See if we need to request an ack for this RPC. */
	if (!homa_is_client(rpc->id) && rpc->state == RPC_OUTGOING &&
	    rpc->msgout.next_xmit_offset >= rpc->msgout.length) {
		if (rpc->done_timer_ticks == 0) {
			rpc->done_timer_ticks = homa->timer_ticks;
		} else {
			/* >= comparison that handles tick wrap-around. */
			if ((rpc->done_timer_ticks + homa->request_ack_ticks
					- 1 - homa->timer_ticks) & 1 << 31) {
				struct homa_need_ack_hdr h;

				homa_xmit_control(NEED_ACK, &h, sizeof(h), rpc);
				tt_record4("Sent NEED_ACK for RPC id %d to peer 0x%x, port %d, ticks %d",
					   rpc->id,
					   tt_addr(rpc->peer->addr),
					   rpc->dport, homa->timer_ticks
					   - rpc->done_timer_ticks);
			}
		}
	}

	if (rpc->state == RPC_INCOMING) {
		if ((rpc->msgin.length - rpc->msgin.bytes_remaining)
				>= rpc->msgin.granted) {
			/* We've received everything that we've granted, so we
			 * shouldn't expect to hear anything until we grant more.
			 */
			rpc->silent_ticks = 0;
			return;
		}
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
		if (rpc->msgout.next_xmit_offset < rpc->msgout.granted) {
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
			   rpc->id, tt_addr(rpc->peer->addr), rpc->state);
		homa_rpc_log_active_tt(homa, 0);
		tt_record1("Freezing because of RPC abort (id %d)", rpc->id);
		homa_freeze_peers(homa);
		tt_freeze();
		if (homa->verbose)
			pr_notice("RPC id %llu, peer %s, aborted because of timeout, state %d\n",
				  rpc->id,
				  homa_print_ipv6_addr(&rpc->peer->addr),
				  rpc->state);
		homa_rpc_abort(rpc, -ETIMEDOUT);
		return;
	}
	if (((rpc->silent_ticks - homa->resend_ticks) % homa->resend_interval)
			!= 0)
		return;

	/* Issue a resend for the bytes just after the last ones received
	 * (gaps in the middle were already handled by homa_gap_retry above).
	 */
	if (rpc->msgin.length < 0) {
		/* Haven't received any data for this message; request
		 * retransmission of just the first packet (the sender
		 * will send at least one full packet, regardless of
		 * the length below).
		 */
		resend.offset = htonl(0);
		resend.length = htonl(100);
	} else {
		homa_gap_retry(rpc);
		resend.offset = htonl(rpc->msgin.recv_end);
		resend.length = htonl(rpc->msgin.granted - rpc->msgin.recv_end);
		if (resend.length == 0)
			return;
	}
	resend.priority = homa->num_priorities - 1;
	homa_xmit_control(RESEND, &resend, sizeof(resend), rpc);
#ifndef __STRIP__ /* See strip.py */
	if (homa_is_client(rpc->id)) {
		us = "client";
		them = "server";
		tt_record4("Sent RESEND for client RPC id %llu, server 0x%x:%d, offset %d",
			   rpc->id, tt_addr(rpc->peer->addr),
			   rpc->dport, rpc->msgin.recv_end);
		tt_record4("length %d, granted %d, rem %d, rec_incoming %d",
			   rpc->msgin.length, rpc->msgin.granted,
			   rpc->msgin.bytes_remaining,
			   rpc->msgin.rec_incoming);
	} else {
		us = "server";
		them = "client";
		tt_record4("Sent RESEND for server RPC id %llu, client 0x%x:%d offset %d",
			   rpc->id, tt_addr(rpc->peer->addr), rpc->dport,
			   rpc->msgin.recv_end);
		tt_record4("length %d, granted %d, rem %d, rec_incoming %d",
			   rpc->msgin.length, rpc->msgin.granted,
			   rpc->msgin.bytes_remaining,
			   rpc->msgin.rec_incoming);
	}
#endif /* See strip.py */
	if (homa->verbose)
		pr_notice("Homa %s RESEND to %s %s:%d for id %llu, offset %d, length %d\n", us, them,
			  homa_print_ipv6_addr(&rpc->peer->addr),
			  rpc->dport, rpc->id, rpc->msgin.recv_end,
			  rpc->msgin.granted - rpc->msgin.recv_end);
}

/**
 * homa_timer() - This function is invoked at regular intervals ("ticks")
 * to implement retries and aborts for Homa.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_timer(struct homa *homa)
{
	struct homa_socktab_scan scan;
	static __u64 prev_grant_count;
	int total_incoming_rpcs = 0;
	int sum_incoming_rec = 0;
	struct homa_sock *hsk;
	static int zero_count;
	struct homa_rpc *rpc;
	int sum_incoming = 0;
	cycles_t start, end;
	__u64 total_grants;
	int total_rpcs = 0;
	int rpc_count = 0;
	int core;

	start = sched_clock();
	homa->timer_ticks++;

	total_grants = 0;
	for (core = 0; core < nr_cpu_ids; core++) {
		struct homa_metrics *m = homa_metrics_per_cpu();

		total_grants += m->packets_sent[GRANT - DATA];
	}

	tt_record4("homa_timer found total_incoming %d, num_grantable_rpcs %d, num_active_rpcs %d, new grants %d",
		   atomic_read(&homa->total_incoming),
		   homa->num_grantable_rpcs,
		   homa->num_active_rpcs,
		   total_grants - prev_grant_count);
	if (total_grants == prev_grant_count &&
	    homa->num_grantable_rpcs > 20) {
		zero_count++;
		if (zero_count > 3 && !atomic_read(&tt_frozen) && 0) {
			pr_err("%s found no grants going out\n", __func__);
			homa_rpc_log_active_tt(homa, 0);
			tt_record("freezing because no grants are going out");
			homa_freeze_peers(homa);
			tt_freeze();
		}
	} else {
		zero_count = 0;
	}
	prev_grant_count = total_grants;

	/* Scan all existing RPCs in all sockets.  The rcu_read_lock
	 * below prevents sockets from being deleted during the scan.
	 */
	rcu_read_lock();
	for (hsk = homa_socktab_start_scan(homa->port_map, &scan);
			hsk; hsk = homa_socktab_next(&scan)) {
		while (hsk->dead_skbs >= homa->dead_buffs_limit) {
			/* If we get here, it means that homa_wait_for_message
			 * isn't keeping up with RPC reaping, so we'll help
			 * out.  See reap.txt for more info.
			 */
			__u64 start = sched_clock();

			tt_record("homa_timer calling homa_rpc_reap");
			if (homa_rpc_reap(hsk, false) == 0)
				break;
			INC_METRIC(timer_reap_ns, sched_clock() - start);
		}

		if (list_empty(&hsk->active_rpcs) || hsk->shutdown)
			continue;

		if (!homa_protect_rpcs(hsk))
			continue;
		list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
			total_rpcs++;
			homa_rpc_lock(rpc, "homa_timer");
			if (rpc->state == RPC_IN_SERVICE) {
				rpc->silent_ticks = 0;
				homa_rpc_unlock(rpc);
				continue;
			} else if (rpc->state == RPC_INCOMING) {
				total_incoming_rpcs += 1;
				sum_incoming_rec += rpc->msgin.rec_incoming;
				sum_incoming += rpc->msgin.granted
						- (rpc->msgin.length
						- rpc->msgin.bytes_remaining);
			}
			rpc->silent_ticks++;
			homa_check_rpc(rpc);
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
	homa_socktab_end_scan(&scan);
	rcu_read_unlock();
	tt_record4("homa_timer found %d incoming RPCs, incoming sum %d, rec_sum %d, homa->total_incoming %d",
		   total_incoming_rpcs, sum_incoming, sum_incoming_rec,
		   atomic_read(&homa->total_incoming));
	homa_skb_release_pages(homa);
	end = sched_clock();
	INC_METRIC(timer_ns, end - start);
}
