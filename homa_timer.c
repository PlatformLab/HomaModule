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
	struct homa_rpc *srpc, *crpc, *tmp;
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
		if (list_empty(&hsk->server_rpcs)
				&& list_empty(&hsk->client_rpcs))
			continue;
		bh_lock_sock_nested((struct sock *) hsk);
		if (unlikely(sock_owned_by_user((struct sock *) hsk))) {
			bh_unlock_sock((struct sock *) hsk);
			continue;
		}
		
		/* Server RPCs*/
		list_for_each_entry_safe(srpc, tmp, &hsk->server_rpcs,
				rpc_links) {
			if (unlikely(print_active)) {
				char addr_buffer[20];
				int in_remaining = 0;
				int in_granted = 0;
				int out_sent = 0;
				if (srpc->msgin.total_length > 0) {
					in_remaining =
						srpc->msgin.bytes_remaining;
					in_granted = srpc->msgin.granted;
				}
				if (srpc->msgout.length >= 0)
					out_sent =  srpc->msgout.next_offset;
				homa_print_ipv4_addr(srpc->peer->addr,
					addr_buffer);
				printk(KERN_NOTICE "Active server RPC to "
					"%s, port %u, id %llu, state %s, "
					"silent %d, msgin remaining %d/%d "
					"granted %d, msgout sent %d/%d\n",
					addr_buffer, srpc->dport, srpc->id,
					homa_symbol_for_state(srpc),
					srpc->silent_ticks,
					in_remaining, srpc->msgin.total_length,
					in_granted, out_sent,
					srpc->msgout.length);
				num_active++;
			}
			if ((srpc->state == RPC_READY)
					|| (srpc->state == RPC_IN_SERVICE)) {
				/* Nothing to worry about while we are
				 * servicing the RPC.
				 */
				continue;
			}
			srpc->silent_ticks++;
			if (srpc->silent_ticks < homa->resend_ticks)
				continue;
			if ((srpc->state == RPC_INCOMING)
					&& ((srpc->msgin.total_length
					- srpc->msgin.bytes_remaining)
					>= srpc->msgin.granted)) {
				/* We've received everything that we've
				 * granted, so we shouldn't expect to hear
				 * anything until we grant more.
				 */
				srpc->silent_ticks = 0;
				continue;
			}
			if (srpc->silent_ticks >= homa->abort_ticks) {
				if (homa->verbose) {
					char addr_buffer[20];
					homa_print_ipv4_addr(srpc->peer->addr,
						addr_buffer);
					printk(KERN_NOTICE "Homa server RPC "
						"timeout, client %s:%d, id %llu",
						addr_buffer, srpc->dport,
						srpc->id);
				}
				INC_METRIC(server_rpc_timeouts, 1);
				homa_rpc_free(srpc);
				continue;
			}

			/* Don't send RESENDs in RPC_OUTGOING: it's up to
			 * the client to handle this.
			 */
			if (srpc->state != RPC_INCOMING)
				continue;
			homa_get_resend_range(&srpc->msgin, &resend);
			resend.priority = homa->max_prio;
			homa_xmit_control(RESEND, &resend, sizeof(resend), srpc);
			if (homa->verbose) {
				char addr_buffer[20];
				homa_print_ipv4_addr(srpc->peer->addr,
					addr_buffer);
				printk(KERN_NOTICE "Homa server RESEND to "
					"client %s:%d for id %llu, offset %d,"
					"length %d",
					addr_buffer, srpc->dport, srpc->id,
					ntohl(resend.offset),
					ntohl(resend.length));
			}
		}
		
		/* Client RPCs*/
		list_for_each_entry_safe(crpc, tmp, &hsk->client_rpcs,
				rpc_links) {
			if (unlikely(print_active)) {
				char addr_buffer[20];
				int in_remaining = 0;
				int in_granted = 0;
				int out_sent = 0;
				if (srpc->msgin.total_length > 0) {
					in_remaining =
						srpc->msgin.bytes_remaining;
					in_granted = srpc->msgin.granted;
				}
				if (srpc->msgout.length >= 0)
					out_sent =  srpc->msgout.next_offset;
				homa_print_ipv4_addr(crpc->peer->addr,
					addr_buffer);
				printk(KERN_NOTICE "Active client RPC from "
					"%s, port %u, id %llu, state %s, "
					"silent %d, msgin remaining %d/%d, "
					"granted %d, msgout sent %d/%d, "
					"error %d\n",
					addr_buffer, crpc->dport, crpc->id,
					homa_symbol_for_state(crpc),
					crpc->silent_ticks,
					in_remaining, crpc->msgin.total_length,
					in_granted, out_sent,
					crpc->msgout.length, crpc->error);
				num_active++;
			}
			crpc->silent_ticks++;
			if (crpc->silent_ticks < homa->resend_ticks)
				continue;
			if (crpc->msgout.next_offset < crpc->msgout.granted) {
				/* We haven't transmitted all of the granted
				 * bytes in the request, so there's no need
				 * to be concerned about the lack of traffic
				 * from the server.
				 */
				crpc->silent_ticks = 0;
				continue;
			}
			if ((crpc->state == RPC_INCOMING)
					&& ((crpc->msgin.total_length
					- crpc->msgin.bytes_remaining)
					>= crpc->msgin.granted)) {
				/* We've received everything that we've
				 * granted, so we shouldn't expect to hear
				 * anything until we grant more. However,
				 * if we don't communicate with the server, it
				 * will eventually timeout and discard the
				 * response. To prevent this, send a BUSY
				 * packet.
				 */
				struct busy_header busy;
				homa_xmit_control(BUSY, &busy, sizeof(busy),
						crpc);
				crpc->silent_ticks = 0;
				continue;
			}
			if (crpc->state == RPC_READY) {
				crpc->silent_ticks = 0;
				continue;
			}
			if (crpc->silent_ticks >= homa->abort_ticks) {
				if (homa->verbose) {
					char addr_buffer[20];
					homa_print_ipv4_addr(crpc->peer->addr,
						addr_buffer);
					printk(KERN_NOTICE "Homa client RPC "
						"timeout, server %s:%d, id %llu",
						addr_buffer, crpc->dport,
						crpc->id);
				}
				INC_METRIC(client_rpc_timeouts, 1);
				homa_rpc_abort(crpc, -ETIMEDOUT);
				continue;
			}
			homa_get_resend_range(&crpc->msgin, &resend);
			resend.priority = homa->max_prio;
			homa_xmit_control(RESEND, &resend, sizeof(resend),
					crpc);
			if (homa->verbose) {
				char addr_buffer[20];
				homa_print_ipv4_addr(crpc->peer->addr,
					addr_buffer);
				printk(KERN_NOTICE "Homa client RESEND to "
					"server %s:%d for id %llu, offset %d,"
					"length %d",
					addr_buffer, crpc->dport, crpc->id,
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
	if (print_active) {
		printk(KERN_NOTICE "Found %d active Homa RPCs\n", num_active);
	}
	end = get_cycles();
	INC_METRIC(timer_cycles, end-start);
}