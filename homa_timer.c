/* This file handles timing-related functions for Homa, such as retries
 * and timeouts. */

#include "homa_impl.h"

/**
 * homa_timer() - This function is invoked at regular intervals ("ticks")
 * to implement retries and aborts for Homa.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_timer(struct homa *homa)
{
	struct homa_socktab_scan scan;
	struct homa_sock *hsk;
	struct homa_rpc *rpc, *tmp;
	struct resend_header resend;
	cycles_t start, end;
	bool print_active = false;
	int num_active = 0;

	start = get_cycles();
	if (homa->flags & HOMA_FLAG_LOG_ACTIVE_RPCS) {
		print_active = true;
		homa->flags &= ~HOMA_FLAG_LOG_ACTIVE_RPCS;
	}

	/* Scan all existing RPCs in all sockets. */
	rcu_read_lock();
	for (hsk = homa_socktab_start_scan(&homa->port_map, &scan);
			hsk !=  NULL; hsk = homa_socktab_next(&scan)) {
		/* Skip the (expensive) lock acquisition if there's no
		 * work to do.
		 */
		if (list_empty(&hsk->active_rpcs))
			continue;
		bh_lock_sock_nested((struct sock *) hsk);
		if (unlikely(sock_owned_by_user((struct sock *) hsk))) {
			bh_unlock_sock((struct sock *) hsk);
			continue;
		}
		
		list_for_each_entry_safe(rpc, tmp, &hsk->active_rpcs,
				rpc_links) {
			const char *us, *them;
			if (unlikely(print_active)) {
				int in_remaining = 0;
				int in_granted = 0;
				int out_sent = 0;
				if (rpc->msgin.total_length > 0) {
					in_remaining =
						rpc->msgin.bytes_remaining;
					in_granted = rpc->msgin.granted;
				}
				if (rpc->msgout.length >= 0)
					out_sent =  rpc->msgout.next_offset;
				printk(KERN_NOTICE "Active %s RPC, peer "
					"%s, port %u, id %llu, state %s, "
					"silent %d, msgin remaining %d/%d "
					"granted %d, msgout sent %d/%d, "
					"error %d\n",
					rpc->is_client ? "client" : "server",
					homa_print_ipv4_addr(rpc->peer->addr),
					rpc->dport, rpc->id,
					homa_symbol_for_state(rpc),
					rpc->silent_ticks,
					in_remaining, rpc->msgin.total_length,
					in_granted, out_sent,
					rpc->msgout.length, rpc->error);
				num_active++;
			}
			if ((rpc->state == RPC_READY)
					|| (rpc->state == RPC_IN_SERVICE)) {
				rpc->silent_ticks = 0;
				continue;
			}
			rpc->silent_ticks++;
			if (rpc->silent_ticks < homa->resend_ticks)
				continue;
			if (rpc->is_client) {
				if (rpc->msgout.next_offset < rpc->msgout.granted) {
					/* We haven't transmitted all of the
					 * granted bytes in the request, so
					 * there's no need to be concerned about
					 * the lack of traffic from the server.
					 */
					rpc->silent_ticks = 0;
					continue;
				}
				if ((rpc->state == RPC_INCOMING)
						&& ((rpc->msgin.total_length
						- rpc->msgin.bytes_remaining)
						>= rpc->msgin.granted)) {
					/* We've received everything that we've
					 * granted, so we shouldn't expect to
					 * hear anything until we grant more.
					 * However, if we don't communicate with
					 * the server, it will eventually
					 * timeout and discard the response. To
					 * prevent this, send a BUSY packet.
					 */
					struct busy_header busy;
					homa_xmit_control(BUSY, &busy, sizeof(busy),
							rpc);
					rpc->silent_ticks = 0;
					continue;
				}
				if (rpc->silent_ticks >= homa->abort_ticks) {
					if (homa->verbose)
						printk(KERN_NOTICE
							"Homa client RPC "
							"timeout, server %s:%d, "
							"id %llu",
							homa_print_ipv4_addr(
							rpc->peer->addr),
							rpc->dport, rpc->id);
					tt_record2("Client RPC timeout, id "
							"%llu, port %d",
							rpc->id, rpc->dport);
					INC_METRIC(client_rpc_timeouts, 1);
					homa_rpc_abort(rpc, -ETIMEDOUT);
					continue;
				}
			} else {
				/* Server RPC */
				if ((rpc->state == RPC_INCOMING)
						&& ((rpc->msgin.total_length
						- rpc->msgin.bytes_remaining)
						>= rpc->msgin.granted)) {
					/* We've received everything that we've
					 * granted, so we shouldn't expect to
					 * hear anything until we grant more.
					 */
					rpc->silent_ticks = 0;
					continue;
				}
				if (rpc->silent_ticks >= homa->abort_ticks) {
					if (homa->verbose)
						printk(KERN_NOTICE
							"Homa server RPC "
							"timeout, client %s:%d, "
							"id %llu",
							homa_print_ipv4_addr(
							rpc->peer->addr),
							rpc->dport, rpc->id);
					INC_METRIC(server_rpc_timeouts, 1);
					homa_rpc_free(rpc);
					continue;
				}

				/* Don't send RESENDs in RPC_OUTGOING: it's up
				 * to the client to handle this.
				 */
				if (rpc->state != RPC_INCOMING)
					continue;
			}
			
			/* Must issue a RESEND. */
			homa_get_resend_range(&rpc->msgin, &resend);
			resend.priority = homa->max_prio;
			homa_xmit_control(RESEND, &resend, sizeof(resend), rpc);
			if (rpc->is_client) {
				us = "server";
				them = "client";
				tt_record3("Sent RESEND for client RPC id "
						"%llu, server 0x%x:%d",
						rpc->id, htonl(rpc->peer->addr),
						rpc->dport);
			} else {
				us = "client";
				them = "server";
				tt_record3("Sent RESEND for server RPC id "
						"%llu, server 0x%x:%d",
						rpc->id, htonl(rpc->peer->addr),
						rpc->dport);
			}
			if (homa->verbose) {
				printk(KERN_NOTICE "Homa %s RESEND to "
					"%s %s:%d for id %llu, offset %d,"
					"length %d", us, them,
					homa_print_ipv4_addr(rpc->peer->addr),
					rpc->dport, rpc->id,
					ntohl(resend.offset),
					ntohl(resend.length));
			}
		}
		if (print_active) {
			struct list_head *pos;
			int requests = 0;
			int responses = 0;
			list_for_each(pos, &hsk->ready_requests) {
				requests++;
			}
			list_for_each(pos, &hsk->ready_responses) {
				responses++;
			}
			printk(KERN_NOTICE "%d ready requests, %d ready "
					"responses for socket\n",
					requests, responses);
		}
		bh_unlock_sock((struct sock *) hsk);
	}
	rcu_read_unlock();
	if (print_active && num_active) {
		printk(KERN_NOTICE "Found %d active Homa RPCs\n", num_active);
	}
	end = get_cycles();
	INC_METRIC(timer_cycles, end-start);
}