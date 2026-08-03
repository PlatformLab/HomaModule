// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

/* This file contains functions for managing homa_rpc structs. */

#include "homa_impl.h"
#include "homa_interest.h"
#include "homa_peer.h"
#include "homa_pool.h"
#include "homa_tx_pool.h"

#ifndef __STRIP__ /* See strip.py */
#include "homa_grant.h"
#include "homa_qdisc.h"
#endif /* See strip.py */

/**
 * homa_rpc_alloc_client() - Allocate and initialize a client RPC (one that
 * is used to issue an outgoing request). Doesn't send any packets. Invoked
 * with no locks held.
 * @hsk:      Socket to which the RPC belongs.
 * @dest:     Address of host (ip and port) to which the RPC will be sent.
 *
 * Return:    A printer to the newly allocated object, or a negative
 *            errno if an error occurred. The RPC will be locked; the
 *            caller must eventually unlock it. Sets hsk->error_msg on errors.
 */
struct homa_rpc *homa_rpc_alloc_client(struct homa_sock *hsk,
				       const union sockaddr_in_union *dest)
	__cond_acquires(crpc->bucket->lock)
{
	struct in6_addr dest_addr_as_ipv6 = canonical_ipv6_addr(dest);
	struct homa_rpc_bucket *bucket;
	struct homa_rpc *crpc;
	int err;

	crpc = kzalloc(sizeof(*crpc), GFP_KERNEL);
	if (unlikely(!crpc)) {
		hsk->error_msg = "couldn't allocate memory for client RPC";
		return ERR_PTR(-ENOMEM);
	}

	/* Initialize fields that don't require the socket lock. */
	crpc->hsk = hsk;
	crpc->id = atomic64_fetch_add(2, &hsk->homa->next_outgoing_id);
	bucket = homa_client_rpc_bucket(hsk, crpc->id);
	crpc->bucket = bucket;
	crpc->state = RPC_OUTGOING;
	refcount_set(&crpc->refs, 1);
	crpc->route = homa_route_get(hsk, &dest_addr_as_ipv6);
	if (IS_ERR(crpc->route)) {
		err = PTR_ERR(crpc->route);
		crpc->route = NULL;
		goto error;
	}
	crpc->dport = ntohs(dest->in6.sin6_port);
	crpc->msgin.length = -1;
	crpc->msgout.length = -1;
	IF_NO_STRIP(homa_qdisc_rpc_init(&crpc->qrpc));
	INIT_LIST_HEAD(&crpc->ready_links);
	INIT_LIST_HEAD(&crpc->buf_links);
	INIT_LIST_HEAD(&crpc->dead_links);
#ifndef __STRIP__ /* See strip.py */
	INIT_LIST_HEAD(&crpc->grantable_links);
#endif /* See strip.py */
	crpc->resend_timer_ticks = hsk->homa->timer_ticks;
	crpc->magic = HOMA_RPC_MAGIC;
	crpc->start_time = homa_clock();

	/* Initialize fields that require locking. This allows the most
	 * expensive work, such as copying in the message from user space,
	 * to be performed without holding locks. Also, can't hold spin
	 * locks while doing things that could block, such as memory allocation.
	 */
	homa_bucket_lock(bucket, crpc->id);
	homa_sock_lock(hsk);
	if (hsk->shutdown) {
		homa_sock_unlock(hsk);
		homa_rpc_unlock(crpc);
		hsk->error_msg = "socket has been shut down";
		err = -ESHUTDOWN;
		goto error;
	}
	hlist_add_head(&crpc->hash_links, &bucket->rpcs);
	rcu_read_lock();
	list_add_tail_rcu(&crpc->active_links, &hsk->active_rpcs);
	rcu_read_unlock();
	homa_sock_unlock(hsk);

	return crpc;

error:
	if (crpc->route)
		homa_route_release(crpc->route);
	kfree(crpc);
	return ERR_PTR(err);
}

/**
 * homa_rpc_alloc_server() - Allocate and initialize a server RPC (one that is
 * used to manage an incoming request). If appropriate, the RPC will also
 * be handed off (we do it here, while we have the socket locked, to avoid
 * acquiring the socket lock a second time later for the handoff).
 * @hsk:      Socket that owns this RPC.
 * @source:   IP address (network byte order) of the RPC's client.
 * @h:        Header for the first data packet received for this RPC; used
 *            to initialize the RPC.
 *
 * Return:  A pointer to a new RPC, which is locked, or a negative errno
 *          if an error occurred. If there is already an RPC corresponding
 *          to h, then it is returned instead of creating a new RPC.
 */
struct homa_rpc *homa_rpc_alloc_server(struct homa_sock *hsk,
				       const struct in6_addr *source,
				       struct homa_data_hdr *h)
	__cond_acquires(srpc->bucket->lock)
{
	u64 id = homa_local_id(h->common.sender_id);
	struct homa_rpc_bucket *bucket;
	struct homa_rpc *srpc = NULL;
	int err;

	if (!hsk->buffer_pool)
		return ERR_PTR(-ENOMEM);

	/* Lock the bucket, and make sure no-one else has already created
	 * the desired RPC.
	 */
	bucket = homa_server_rpc_bucket(hsk, id);
	homa_bucket_lock(bucket, id);
	hlist_for_each_entry(srpc, &bucket->rpcs, hash_links) {
		if (srpc->id == id &&
		    srpc->dport == ntohs(h->common.sport) &&
		    ipv6_addr_equal(&srpc->route->peer->addr, source)) {
			/* RPC already exists; just return it instead
			 * of creating a new RPC.
			 */
			return srpc;
		}
	}

	/* Initialize fields that don't require the socket lock. */
	srpc = kzalloc(sizeof(*srpc), GFP_ATOMIC);
	if (!srpc) {
		err = -ENOMEM;
		goto error;
	}

	/* Must be initialized before any errors can occur in this function. */
	INIT_LIST_HEAD(&srpc->buf_links);

	srpc->hsk = hsk;
	srpc->bucket = bucket;
	srpc->state = RPC_INCOMING;
	refcount_set(&srpc->refs, 1);
	srpc->route = homa_route_get(hsk, source);
	if (IS_ERR(srpc->route)) {
		err = PTR_ERR(srpc->route);
		srpc->route = NULL;
		goto error;
	}
	srpc->dport = ntohs(h->common.sport);
	srpc->id = id;
	srpc->msgin.length = -1;
	srpc->msgout.length = -1;
	IF_NO_STRIP(homa_qdisc_rpc_init(&srpc->qrpc));
	INIT_LIST_HEAD(&srpc->ready_links);
	INIT_LIST_HEAD(&srpc->dead_links);
#ifndef __STRIP__ /* See strip.py */
	INIT_LIST_HEAD(&srpc->grantable_links);
#endif /* See strip.py */
	srpc->resend_timer_ticks = hsk->homa->timer_ticks;
	srpc->magic = HOMA_RPC_MAGIC;
	srpc->start_time = homa_clock();
#ifndef __STRIP__ /* See strip.py */
	tt_record2("Incoming message for id %d has %d unscheduled bytes",
		   srpc->id, ntohl(h->incoming));
#endif /* See strip.py */
#ifndef __STRIP__ /* See strip.py */
	err = homa_message_in_init(srpc, ntohl(h->message_length),
				   ntohl(h->incoming));
#else /* See strip.py */
	err = homa_message_in_init(srpc, ntohl(h->message_length));
#endif /* See strip.py */
	if (err != 0)
		goto error;

	/* Initialize fields that require socket to be locked. */
	homa_sock_lock(hsk);
	if (hsk->shutdown) {
		homa_sock_unlock(hsk);
		err = -ESHUTDOWN;
		goto error;
	}
	hlist_add_head(&srpc->hash_links, &bucket->rpcs);
	list_add_tail_rcu(&srpc->active_links, &hsk->active_rpcs);
	homa_sock_unlock(hsk);
	if (ntohl(h->seg.offset) == 0 && srpc->msgin.num_bpages > 0) {
		set_bit(RPC_PKTS_READY, &srpc->flags);
		homa_rpc_handoff(srpc);
	}
	INC_METRIC(requests_received, 1);
	return srpc;

error:
	if (srpc) {
		homa_pool_release(srpc);
		if (srpc->route)
			homa_route_release(srpc->route);
	}
	homa_bucket_unlock(bucket, id);
	kfree(srpc);
	return ERR_PTR(err);
}

/**
 * homa_rpc_ack() - Handle one or more acknowledgments for RPCs.
 * @hsk:      Socket on which the ack(s) were received. Can sometimes be used
 *            to avoid a socket lookup.
 * @rpc:      RPC for which caller holds lock (NULL if none).
 * @saddr:    Source address from which the ack was received (the client
 *            node for the RPC)
 * @num_acks: Number of acknowlegments in @acks
 * @acks:     Information about one or more RPCs from @saddr that may now be
 *            deleted safely.
 */
void homa_rpc_ack(struct homa_sock *hsk, struct homa_rpc *rpc,
		  const struct in6_addr *saddr, int num_acks,
		  struct homa_ack *acks)
{
	struct homa_sock *hsk2;
	struct homa_rpc *rpc2;
	u16 server_port;
	u64 id;
	int i;

	if (rpc)
		homa_rpc_unlock(rpc);
	for (i = 0; i < num_acks; i++) {
		struct homa_ack *ack = &acks[i];

		server_port = ntohs(ack->server_port);
		id = homa_local_id(ack->client_id);
		UNIT_LOG("; ", "ack %llu", id);
		if (hsk->port != server_port) {
			/* Without RCU, sockets other than hsk can be deleted
			 * out from under us.
			 */
			hsk2 = homa_sock_find(hsk->hnet, server_port);
			if (!hsk2)
				continue;
		} else {
			hsk2 = hsk;
		}
		rpc2 = homa_rpc_find_server(hsk2, saddr, id);
		if (rpc2) {
			tt_record1("homa_rpc_acked freeing id %d", rpc2->id);
			homa_rpc_end(rpc2);
			homa_rpc_unlock(rpc2); /* Locked by homa_rpc_find_server. */
		}
		if (hsk2 != hsk)
			sock_put(&hsk2->sock);
	}
	if (rpc)
		homa_rpc_lock(rpc);
}

/**
 * homa_rpc_end() - Stop all activity on an RPC and begin the process of
 * releasing its resources; this process will continue in the background
 * until homa_rpc_reap eventually completes it.
 * @rpc:  Structure to clean up, or NULL. Must be locked. Its socket must
 *        not be locked. The RPC may still be used after this function returns
 *        (there are many places where the RPC lock is temporarily released,
 *        and it would add too much complexity to put checks for death
 *        every time the lock is reacquired). However, any code that could
 *        make the RPC visible again must check rpc->state; if the RPC is
 *        dead then that code must no-op itself.
 */
void homa_rpc_end(struct homa_rpc *rpc)
	__must_hold(rpc->bucket->lock)
{
	/* The goal for this function is to make the RPC inaccessible,
	 * so that no other code will ever access it again. However, don't
	 * actually release resources or tear down the internal structure
	 * of the RPC; leave that to homa_rpc_reap, which runs later. There
	 * are two reasons for this. First, releasing resources may be
	 * expensive, so we don't want to keep the caller waiting; homa_rpc_reap
	 * will run in situations where there is time to spare. Second, there
	 * may be other code that currently has pointers to this RPC but
	 * temporarily released the lock (e.g. to copy data to/from user space).
	 * It isn't safe to clean up until that code has finished its work and
	 * released any pointers to the RPC (homa_rpc_reap will ensure that
	 * this has happened). So, this function should only make changes
	 * needed to make the RPC inaccessible.
	 */
	if (!rpc || rpc->state == RPC_DEAD)
		return;
	UNIT_LOG("; ", "homa_rpc_end invoked");
	tt_record2("homa_rpc_end invoked for id %d, port %d", rpc->id,
		   rpc->hsk->port);
	rpc->state = RPC_DEAD;
	rpc->error = -EINVAL;

#ifndef __STRIP__ /* See strip.py */
	/* The following line must occur before the socket is locked. This is
	 * necessary because homa_grant_unmanage_rpc may release the RPC lock
	 * and reacquire it.
	 */
	if (rpc->msgin.length >= 0)
		homa_grant_unmanage_rpc(rpc);
#endif /* See strip.py */

	/* Unlink from all lists, so no-one will ever find this RPC again. */
	homa_sock_lock(rpc->hsk);
	__hlist_del(&rpc->hash_links);
	list_del_rcu(&rpc->active_links);
	list_add_tail(&rpc->dead_links, &rpc->hsk->dead_rpcs);
	__list_del_entry(&rpc->ready_links);
	homa_pool_unlink(rpc);
	homa_interest_notify_private(rpc);
	homa_qdisc_flush_rpc(rpc);

	rpc->hsk->dead_frags += rpc->msgout.num_frags + 1;
	if (rpc->hsk->dead_frags > rpc->hsk->homa->max_dead_frags)
		/* This update isn't thread-safe; it's just a
		 * statistic so it's OK if updates occasionally get
		 * missed.
		 */
		rpc->hsk->homa->max_dead_frags = rpc->hsk->dead_frags;

	homa_sock_unlock(rpc->hsk);
}

/**
 * homa_rpc_abort() - Terminate an RPC.
 * @rpc:     RPC to be terminated.  Must be locked by caller.
 * @error:   A negative errno value indicating the error that caused the abort.
 *           If this is a client RPC, the error will be returned to the
 *           application; if it's a server RPC, the error is ignored and
 *           we just free the RPC.
 */
void homa_rpc_abort(struct homa_rpc *rpc, int error)
	__must_hold(rpc->bucket->lock)
{
	if (!homa_is_client(rpc->id)) {
		INC_METRIC(server_rpc_discards, 1);
		tt_record3("aborting server RPC: peer 0x%x, id %d, error %d",
			   tt_addr(rpc->route->peer->addr), rpc->id, error);
		homa_rpc_end(rpc);
		return;
	}
	tt_record3("aborting client RPC: peer 0x%x, id %d, error %d",
		   tt_addr(rpc->route->peer->addr), rpc->id, error);
	rpc->error = error;
	homa_rpc_handoff(rpc);
}

/**
 * homa_abort_rpcs() - Abort all RPCs to/from a particular peer.
 * @homa:    Overall data about the Homa protocol implementation.
 * @addr:    Address (network order) of the destination whose RPCs are
 *           to be aborted.
 * @port:    If nonzero, then RPCs will only be aborted if they were
 *	     targeted at this server port.
 * @error:   Negative errno value indicating the reason for the abort.
 */
void homa_abort_rpcs(struct homa *homa, const struct in6_addr *addr,
		     int port, int error)
{
	struct homa_socktab_scan scan;
	struct homa_sock *hsk;
	struct homa_rpc *rpc;

	for (hsk = homa_socktab_start_scan(homa->socktab, &scan); hsk;
	     hsk = homa_socktab_next(&scan)) {
		/* Skip the (expensive) lock acquisition if there's no
		 * work to do.
		 */
		if (list_empty(&hsk->active_rpcs))
			continue;
		if (!homa_protect_rpcs(hsk))
			continue;
		rcu_read_lock();
		list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
			if (!ipv6_addr_equal(&rpc->route->peer->addr, addr))
				continue;
			if (port && rpc->dport != port)
				continue;
			homa_rpc_lock(rpc);
			if (rpc->state != RPC_DEAD)
				homa_rpc_abort(rpc, error);
			homa_rpc_unlock(rpc);
		}
		rcu_read_unlock();
		homa_unprotect_rpcs(hsk);
	}
	homa_socktab_end_scan(&scan);
}

/**
 * homa_rpc_reap() - Invoked to release resources associated with dead
 * RPCs for a given socket. Each call will do a small amount of work; there
 * may still be unreaped RPCs on return.
 * @hsk:      Homa socket that may contain dead RPCs. Must not be locked by the
 *            caller; this function will lock and release.
 *
 * Return: A return value of 0 means that we ran out of work to do; calling
 *         again may not do any work (there could be unreaped RPCs, but if so,
 *         they cannot currently be reaped).  A value greater than zero means
 *         there is still more reaping work to be done.
 */
int homa_rpc_reap(struct homa_sock *hsk)
{
	/* RPC Reaping Strategy:
	 *
	 * (Note: there are references to this comment elsewhere in the
	 * Homa code)
	 *
	 * This function is separate from homa_rpc_end for two reasons.
	 * First, there may be outstanding references to an RPC when
	 * homa_rpc_end is invoked; the storage for the RPC cannot be
	 * freed until all of those references have been released.
	 * Second, reaping an RPC is potentially expensive (if it owns a
	 * lot of buffer memory) and homa_rpc_end could be invoked in
	 * homa_softirq when there are short messages waiting to be processed.
	 * Taking time to reap a long RPC could result in delays for
	 * subsequent short RPCs. This second reason is less important
	 * now than it used to be (in earlier versions of Homa skbs for both
	 * inbound and outbound messages were retained until the RPC was
	 * reaped, and freeing the skbs was relatively expensive; now no
	 * skbs are retained; there are only pages of tx message memory to
	 * return to homa_tx_pool).
	 *
	 * Thus Homa doesn't reap immediately in homa_rpc_end. Instead, dead
	 * RPCs are queued up and reaping occurs in this function, which is
	 * invoked later. The challenge is to do this so that (a) we don't allow
	 * large numbers of dead RPCs to accumulate and (b) we minimize the
	 * impact of reaping on latency of unrelated messages.
	 *
	 * The primary place where homa_rpc_reap is invoked is when threads
	 * are waiting for incoming messages. The thread has nothing else to
	 * do (it may even be polling for input), so reaping can be performed
	 * with no latency impact on the application.  However, if a machine
	 * is overloaded then it may never wait, so this mechanism isn't always
	 * sufficient.
	 *
	 * Homa now reaps in two other places, if reaping while waiting for
	 * messages isn't adequate:
	 * 1. If too many dead RPCs accumulate, then homa_timer will call
	 *    homa_rpc_reap.
	 * 2. If the timer thread cannot keep up with all the reaping to be
	 *    done then as a last resort homa_dispatch_pkts will reap in small
	 *    increments (a few sk_buffs or RPCs) for every incoming batch
	 *    of packets. This is undesirable because it will impact Homa's
	 *    latency.
	 *
	 * During the introduction of homa_pools for managing input
	 * buffers, freeing of packets for incoming messages was moved to
	 * homa_copy_to_user under the assumption that this code wouldn't be
	 * on the critical path. However, there is evidence that with
	 * fast networks (e.g. 100 Gbps) copying to user space is the
	 * bottleneck for incoming messages, and packet freeing takes about
	 * 20-25% of the total time in homa_copy_to_user. So, it may eventually
	 * be desirable to move packet freeing out of homa_copy_to_user.
	 */
#ifdef __UNIT_TEST__
#define BATCH_MAX_RPCS 3
#define BATCH_MAX_FRAGS 10
#else /* __UNIT_TEST__ */
#define BATCH_MAX_RPCS 5
#define BATCH_MAX_FRAGS 30
#endif /* __UNIT_TEST__ */
	struct homa_rpc *rpcs[BATCH_MAX_RPCS];
	int checked_all_rpcs;
	int total_dead_frags;
	struct homa_rpc *rpc;
	struct homa_rpc *tmp;
	int i, num_rpcs;

	INC_METRIC(reaper_calls, 1);

	/* Each iteration through the following loop will reap
	 * up to BATCH_MAX_RPCS RPCs.
	 */
	checked_all_rpcs = list_empty(&hsk->dead_rpcs);
	if (checked_all_rpcs)
		return 0;
	num_rpcs = 0;
	total_dead_frags = 0;

	homa_sock_lock(hsk);
	if (atomic_read(&hsk->protect_count)) {
		INC_METRIC(disabled_reaps, 1);
		tt_record3("homa_rpc_reap returning for port %d: protect_count %d, dead_frags %d",
			   hsk->port, atomic_read(&hsk->protect_count),
			   hsk->dead_frags);
		homa_sock_unlock(hsk);
		return 0;
	}

	/* Collect freeable RPCs. */
	list_for_each_entry_safe(rpc, tmp, &hsk->dead_rpcs, dead_links) {
		int refs;

		if (num_rpcs >= BATCH_MAX_RPCS ||
			total_dead_frags >= BATCH_MAX_FRAGS)
			goto release;

		/* Make sure that all outstanding uses of the RPC have
		 * completed. We can read the reference count safely
		 * only when we're holding the lock. Note: it isn't
		 * safe to block while locking the RPC here, since we
		 * hold the socket lock.
		 */
		if (homa_rpc_try_lock(rpc)) {
			refs = refcount_read(&rpc->refs);
			homa_rpc_unlock(rpc);
		} else {
			refs = 2;
		}
		if (refs > 1) {
			INC_METRIC(deferred_rpc_reaps, 1);
			continue;
		}

		rpcs[num_rpcs] = rpc;
		num_rpcs++;
		list_del(&rpc->dead_links);
		hsk->dead_frags -= (rpc->msgout.num_frags + 1);
		total_dead_frags += rpc->msgout.num_frags;
	}
	checked_all_rpcs = true;

	/* Free all of the collected resources; release the socket lock
	 * while doing this.
	 */
release:
	homa_sock_unlock(hsk);
	for (i = 0; i < num_rpcs; i++) {
		IF_NO_STRIP(int tx_left);

		rpc = rpcs[i];
		UNIT_LOG("; ", "reaped %llu", rpc->id);

		/* Free any unconsumed input packets and gaps (there
		 * shouldn't usually be any of either).
		 */
		if (rpc->msgin.length >= 0) {
			struct sk_buff *skb;

			for (skb = __skb_dequeue(&rpc->msgin.packets); skb;
			     skb = __skb_dequeue(&rpc->msgin.packets))
				consume_skb(skb);
			while (1) {
				struct homa_gap *gap;

				gap = list_first_entry_or_null(&rpc->msgin.gaps,
							       struct homa_gap,
							       links);
				if (!gap)
					break;
				list_del(&gap->links);
				kfree(gap);
			}
		}
		if (skb_queue_len(&rpc->qrpc.packets) > 0) {
			tt_record2("Freezing because homa_rpc_reap found %d packets in qdisc queue for id %d",
				   skb_queue_len(&rpc->qrpc.packets), rpc->id);
			tt_record("Freezing cluster");
			homa_freeze_peers();
			tt_record("Finished freezing cluster");
			tt_freeze();
			pr_err("homa_rpc_end found %d skbs in qdisc queue for rpc id %llu\n",
			       skb_queue_len(&rpc->qrpc.packets), rpc->id);
			homa_qdisc_flush_rpc(rpc);
		}

		if (rpc->route) {
			homa_route_release(rpc->route);
			rpc->route = NULL;
		}
		homa_pool_release(rpc);
		homa_tx_pool_free(hsk->homa, rpc->msgout.num_frags,
					rpc->msgout.frags);
		WARN_ON(refcount_sub_and_test(rpc->msgout.frag_bytes,
						&hsk->sock.sk_wmem_alloc));
		if (rpc->msgout.frags != &rpc->msgout.frag)
			kfree(rpc->msgout.frags);
		tt_record2("homa_rpc_reap finished reaping id %d, port %d",
				rpc->id, rpc->hsk->port);
#ifndef __STRIP__ /* See strip.py */
		tx_left = rpc->msgout.length -
			rpc->msgout.next_xmit_offset;
		if (homa_is_client(rpc->id)) {
			INC_METRIC(client_response_bytes_done,
					rpc->msgin.bytes_remaining);
			INC_METRIC(client_responses_done,
					rpc->msgin.bytes_remaining != 0);
			if (tx_left > 0) {
				INC_METRIC(client_request_bytes_done,
						tx_left);
				INC_METRIC(client_requests_done, 1);
			}
		} else {
			INC_METRIC(server_request_bytes_done,
					rpc->msgin.bytes_remaining);
			INC_METRIC(server_requests_done,
					rpc->msgin.bytes_remaining != 0);
			if (tx_left > 0) {
				INC_METRIC(server_response_bytes_done,
						tx_left);
				INC_METRIC(server_responses_done, 1);
			}
		}
#endif /* See strip.py */
		rpc->state = 0;
		rpc->magic = 0;
		kfree(rpc);
	}
	homa_sock_wakeup_wmem(hsk);
	tt_record3("reaped %d rpcs; %d dead frags remain for port %d",
			num_rpcs, hsk->dead_frags, hsk->port);
	if (hsk->buffer_pool)
		homa_pool_check_waiting(hsk->buffer_pool);
	return !checked_all_rpcs;
}

/**
 * homa_abort_sock_rpcs() - Abort all outgoing (client-side) RPCs on a given
 * socket.
 * @hsk:         Socket whose RPCs should be aborted.
 * @error:       Zero means that the aborted RPCs should be freed immediately.
 *               A nonzero value means that the RPCs should be marked
 *               complete, so that they can be returned to the application;
 *               this value (a negative errno) will be returned from
 *               recvmsg.
 */
void homa_abort_sock_rpcs(struct homa_sock *hsk, int error)
{
	struct homa_rpc *rpc;

	if (list_empty(&hsk->active_rpcs))
		return;
	if (!homa_protect_rpcs(hsk))
		return;
	rcu_read_lock();
	list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
		if (!homa_is_client(rpc->id))
			continue;
		homa_rpc_lock(rpc);
		if (rpc->state == RPC_DEAD) {
			homa_rpc_unlock(rpc);
			continue;
		}
		tt_record4("homa_abort_sock_rpcs aborting id %u on port %d, peer 0x%x, error %d",
			   rpc->id, hsk->port,
			   tt_addr(rpc->route->peer->addr), error);
		if (error)
			homa_rpc_abort(rpc, error);
		else
			homa_rpc_end(rpc);
		homa_rpc_unlock(rpc);
	}
	rcu_read_unlock();
	homa_unprotect_rpcs(hsk);
}

/**
 * homa_rpc_find_client() - Locate client-side information about the RPC that
 * a packet belongs to, if there is any. Thread-safe without socket lock.
 * @hsk:      Socket via which packet was received.
 * @id:       Unique identifier for the RPC.
 *
 * Return:    A pointer to the homa_rpc for this id, or NULL if none.
 *            The RPC will be locked; the caller must eventually unlock it
 *            by invoking homa_rpc_unlock.
 */
struct homa_rpc *homa_rpc_find_client(struct homa_sock *hsk, u64 id)
	__cond_acquires(crpc->bucket->lock)
{
	struct homa_rpc_bucket *bucket = homa_client_rpc_bucket(hsk, id);
	struct homa_rpc *crpc;

	homa_bucket_lock(bucket, id);
	hlist_for_each_entry(crpc, &bucket->rpcs, hash_links) {
		if (crpc->id == id)
			return crpc;
	}
	homa_bucket_unlock(bucket, id);
	return NULL;
}

/**
 * homa_rpc_find_server() - Locate server-side information about the RPC that
 * a packet belongs to, if there is any. Thread-safe without socket lock.
 * @hsk:      Socket via which packet was received.
 * @saddr:    Address from which the packet was sent.
 * @id:       Unique identifier for the RPC (must have server bit set).
 *
 * Return:    A pointer to the homa_rpc matching the arguments, or NULL
 *            if none. The RPC will be locked; the caller must eventually
 *            unlock it by invoking homa_rpc_unlock.
 */
struct homa_rpc *homa_rpc_find_server(struct homa_sock *hsk,
				      const struct in6_addr *saddr, u64 id)
	__cond_acquires(srpc->bucket->lock)
{
	struct homa_rpc_bucket *bucket = homa_server_rpc_bucket(hsk, id);
	struct homa_rpc *srpc;

	homa_bucket_lock(bucket, id);
	hlist_for_each_entry(srpc, &bucket->rpcs, hash_links) {
		if (srpc->id == id && ipv6_addr_equal(&srpc->route->peer->addr,
						      saddr))
			return srpc;
	}
	homa_bucket_unlock(bucket, id);
	return NULL;
}

/**
 * homa_rpc_find_from_skb() - Given an skb for a Homa packet, find the homa_rpc
 * associated with the packet and lock it.
 * @skb:        Packet buffer; must contain a Homa packet that is "fully
 *              populated" (e.g. the dev field and IP header are initialized).
 * @incoming:   True means this is an incoming packet, false means outgoing.
 * Return:      Pointer an RPC that has been locked; the caller is responsible
 *              for unlocking it. If no RPC could be found, NULL is returned.
 */
struct homa_rpc *homa_rpc_find_from_skb(struct sk_buff *skb, bool incoming)
{
	struct homa_common_hdr *h;
	u64 id;
	int port;
	struct homa_rpc *rpc;
	struct homa_sock *hsk;
	struct homa_net *hnet;

	/* Find the appropriate socket.*/
	h = (struct homa_common_hdr *)skb_transport_header(skb);
	id = be64_to_cpu(h->sender_id);
	if (incoming) {
		port = ntohs(h->dport);
		id ^= 1;
	} else {
		port = ntohs(h->sport);
	}
	hnet = homa_net(dev_net(skb->dev));
	hsk = homa_sock_find(hnet, port);
	if (!hsk)
		return NULL;

	/* Look up the RPC (client and server RPCs are handled differently) */
	if (homa_is_client(id)) {
		rpc = homa_rpc_find_client(hsk, id);
	} else {
		if (skb_is_ipv6(skb)) {
			struct in6_addr *addr;

			addr = (incoming) ? &ipv6_hdr(skb)->saddr :
					&ipv6_hdr(skb)->daddr;
			rpc = homa_rpc_find_server(hsk, addr, id);
		} else {
			struct in6_addr addr;

			if (incoming)
				ipv6_addr_set_v4mapped(ip_hdr(skb)->saddr,
						       &addr);
			else
				ipv6_addr_set_v4mapped(ip_hdr(skb)->daddr,
						       &addr);
			rpc = homa_rpc_find_server(hsk, &addr, id);
		}
	}
	sock_put(&hsk->sock);
	return rpc;
}

/**
 * homa_rpc_get_info() - Extract information from an RPC for returning to
 * an application via the HOMAIOCINFO ioctl.
 * @rpc:   RPC for which information is desired.
 * @info:  Structure in which to store the information.
 */
void homa_rpc_get_info(struct homa_rpc *rpc, struct homa_rpc_info *info)
	__must_hold(rpc->bucket->lock)
{
	struct homa_gap *gap;

	memset(info, 0, sizeof(*info));
	info->id = rpc->id;
	if (rpc->hsk->inet.sk.sk_family == AF_INET6) {
		info->peer.in6.sin6_family = AF_INET6;
		info->peer.in6.sin6_addr = rpc->route->peer->addr;
		info->peer.in6.sin6_port = htons(rpc->dport);
	} else {
		info->peer.in6.sin6_family = AF_INET;
		info->peer.in4.sin_addr.s_addr = ipv6_to_ipv4(rpc->route->peer->addr);
		info->peer.in4.sin_port = htons(rpc->dport);
	}
	info->completion_cookie = rpc->completion_cookie;
	if (rpc->msgout.length >= 0) {
		info->tx_length = rpc->msgout.length;
		info->tx_sent = rpc->msgout.next_xmit_offset;
#ifndef __STRIP__ /* See strip.py */
		info->tx_granted = rpc->msgout.granted;
		info->tx_prio = rpc->msgout.sched_priority;
#else /* See strip.py */
		info->tx_granted = rpc->msgout.length;
#endif /* See strip.py */
	} else {
		info->tx_length = -1;
	}
	if (rpc->msgin.length >= 0) {
		info->rx_length = rpc->msgin.length;
		info->rx_remaining = rpc->msgin.bytes_remaining;
		list_for_each_entry(gap, &rpc->msgin.gaps, links) {
			info->rx_gaps++;
			info->rx_gap_bytes += gap->end - gap->start;
		}
#ifndef __STRIP__ /* See strip.py */
		info->rx_granted = rpc->msgin.granted;
#else /* See strip.py */
		info->rx_granted = rpc->msgin.length;
#endif /* See strip.py */
		if (skb_queue_len(&rpc->msgin.packets) > 0)
			info->flags |= HOMA_RPC_RX_COPY;
	} else {
		info->rx_length = -1;
	}
	if (!list_empty(&rpc->buf_links))
		info->flags |= HOMA_RPC_BUF_STALL;
	if (!list_empty(&rpc->ready_links) &&
	    rpc->msgin.bytes_remaining == 0 &&
	    skb_queue_len(&rpc->msgin.packets) == 0)
		info->flags |= HOMA_RPC_RX_READY;
	if (rpc->flags & RPC_PRIVATE)
		info->flags |= HOMA_RPC_PRIVATE;
}
