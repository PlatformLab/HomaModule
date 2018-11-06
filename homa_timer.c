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

	start = get_cycles();

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
					&& (srpc->msgin.bytes_remaining
					+ srpc->msgin.granted
					== srpc->msgin.total_length)) {
				/* We've received everything that we've
				 * granted, so we shouldn't expect to hear
				 * anything until we grant more.
				 */
				srpc->silent_ticks = 0;
				continue;
			}
			if (srpc->silent_ticks >= homa->abort_ticks) {
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
		}
		
		/* Client RPCs*/
		list_for_each_entry_safe(crpc, tmp, &hsk->client_rpcs,
				rpc_links) {
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
					&& (crpc->msgin.granted
					== (crpc->msgin.total_length
					- crpc->msgin.bytes_remaining))) {
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
			if (crpc->silent_ticks >= homa->abort_ticks) {
				INC_METRIC(client_rpc_timeouts, 1);
				homa_rpc_abort(crpc, -ETIMEDOUT);
				continue;
			}
			if ((crpc->state == RPC_READY)
					|| (crpc->state == RPC_CLIENT_DONE)) {
				crpc->silent_ticks = 0;
				continue;
			}
			homa_get_resend_range(&crpc->msgin, &resend);
			resend.priority = homa->max_prio;
			homa_xmit_control(RESEND, &resend, sizeof(resend),
					crpc);
		}
		bh_unlock_sock((struct sock *) hsk);
	}
	rcu_read_unlock();
	end = get_cycles();
	INC_METRIC(timer_cycles, end-start);
}