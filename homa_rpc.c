// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

/* This file contains functions for managing homa_rpc structs. */

#include "homa_impl.h"
#include "homa_interest.h"
#include "homa_peer.h"
#include "homa_pool.h"

#ifndef __STRIP__ /* See strip.py */
#include "homa_grant.h"
#include "homa_pacer.h"
#include "homa_skb.h"
#else /* See strip.py */
#include "homa_stub.h"
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
 *            caller must eventually unlock it.
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
	if (unlikely(!crpc))
		return ERR_PTR(-ENOMEM);

	/* Initialize fields that don't require the socket lock. */
	crpc->hsk = hsk;
	crpc->id = atomic64_fetch_add(2, &hsk->homa->next_outgoing_id);
	bucket = homa_client_rpc_bucket(hsk, crpc->id);
	crpc->bucket = bucket;
	crpc->state = RPC_OUTGOING;
	refcount_set(&crpc->refs, 1);
	crpc->peer = homa_peer_get(hsk, &dest_addr_as_ipv6);
	if (IS_ERR(crpc->peer)) {
		tt_record("error in homa_peer_get");
		err = PTR_ERR(crpc->peer);
		crpc->peer = NULL;
		goto error;
	}
	crpc->dport = ntohs(dest->in6.sin6_port);
	crpc->msgin.length = -1;
	crpc->msgout.length = -1;
	INIT_LIST_HEAD(&crpc->ready_links);
	INIT_LIST_HEAD(&crpc->buf_links);
	INIT_LIST_HEAD(&crpc->dead_links);
#ifndef __STRIP__ /* See strip.py */
	INIT_LIST_HEAD(&crpc->grantable_links);
#endif /* See strip.py */
	INIT_LIST_HEAD(&crpc->throttled_links);
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
	if (crpc->peer)
		homa_peer_release(crpc->peer);
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
 * @created:  Will be set to 1 if a new RPC was created and 0 if an
 *            existing RPC was found.
 *
 * Return:  A pointer to a new RPC, which is locked, or a negative errno
 *          if an error occurred. If there is already an RPC corresponding
 *          to h, then it is returned instead of creating a new RPC.
 */
struct homa_rpc *homa_rpc_alloc_server(struct homa_sock *hsk,
				       const struct in6_addr *source,
				       struct homa_data_hdr *h, int *created)
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
		    ipv6_addr_equal(&srpc->peer->addr, source)) {
			/* RPC already exists; just return it instead
			 * of creating a new RPC.
			 */
			*created = 0;
			return srpc;
		}
	}

	/* Initialize fields that don't require the socket lock. */
	srpc = kzalloc(sizeof(*srpc), GFP_ATOMIC);
	if (!srpc) {
		err = -ENOMEM;
		goto error;
	}
	srpc->hsk = hsk;
	srpc->bucket = bucket;
	srpc->state = RPC_INCOMING;
	refcount_set(&srpc->refs, 1);
	srpc->peer = homa_peer_get(hsk, source);
	if (IS_ERR(srpc->peer)) {
		err = PTR_ERR(srpc->peer);
		srpc->peer = NULL;
		goto error;
	}
	srpc->dport = ntohs(h->common.sport);
	srpc->id = id;
	srpc->msgin.length = -1;
	srpc->msgout.length = -1;
	INIT_LIST_HEAD(&srpc->ready_links);
	INIT_LIST_HEAD(&srpc->buf_links);
	INIT_LIST_HEAD(&srpc->dead_links);
#ifndef __STRIP__ /* See strip.py */
	INIT_LIST_HEAD(&srpc->grantable_links);
#endif /* See strip.py */
	INIT_LIST_HEAD(&srpc->throttled_links);
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
		atomic_or(RPC_PKTS_READY, &srpc->flags);
		homa_rpc_handoff(srpc);
	}
	INC_METRIC(requests_received, 1);
	*created = 1;
	return srpc;

error:
	homa_bucket_unlock(bucket, id);
	if (srpc && srpc->peer)
		homa_peer_release(srpc->peer);
	kfree(srpc);
	return ERR_PTR(err);
}

/**
 * homa_rpc_acked() - This function is invoked when an ack is received
 * for an RPC; if the RPC still exists, is freed.
 * @hsk:     Socket on which the ack was received. May or may not correspond
 *           to the RPC, but can sometimes be used to avoid a socket lookup.
 * @saddr:   Source address from which the act was received (the client
 *           node for the RPC)
 * @ack:     Information about an RPC from @saddr that may now be deleted
 *           safely.
 */
void homa_rpc_acked(struct homa_sock *hsk, const struct in6_addr *saddr,
		    struct homa_ack *ack)
{
	u16 server_port = ntohs(ack->server_port);
	u64 id = homa_local_id(ack->client_id);
	struct homa_sock *hsk2 = hsk;
	struct homa_rpc *rpc;

	UNIT_LOG("; ", "ack %llu", id);
	if (hsk->port != server_port) {
		/* Without RCU, sockets other than hsk can be deleted
		 * out from under us.
		 */
		hsk2 = homa_sock_find(hsk->hnet, server_port);
		if (!hsk2)
			return;
	}
	rpc = homa_rpc_find_server(hsk2, saddr, id);
	if (rpc) {
		tt_record1("homa_rpc_acked freeing id %d", rpc->id);
		homa_rpc_end(rpc);
		homa_rpc_unlock(rpc); /* Locked by homa_rpc_find_server. */
	}
	if (hsk->port != server_port)
		sock_put(&hsk2->sock);
}

/**
 * homa_rpc_end() - Stop all activity on an RPC and begin the process of
 * releasing its resources; this process will continue in the background
 * until homa_rpc_reap eventually completes it.
 * @rpc:  Structure to clean up, or NULL. Must be locked. Its socket must
 *        not be locked. Once this function returns the caller should not
 *        use the RPC except to unlock it.
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
	 * necessary because homa_grant_end_rpc releases the RPC lock and
	 * reacquires it.
	 */
	if (rpc->msgin.length >= 0)
		homa_grant_end_rpc(rpc);
#endif /* See strip.py */

	/* Unlink from all lists, so no-one will ever find this RPC again. */
	homa_sock_lock(rpc->hsk);
	__hlist_del(&rpc->hash_links);
	list_del_rcu(&rpc->active_links);
	list_add_tail(&rpc->dead_links, &rpc->hsk->dead_rpcs);
	__list_del_entry(&rpc->ready_links);
	__list_del_entry(&rpc->buf_links);
	homa_interest_notify_private(rpc);
//	tt_record3("Freeing rpc id %d, socket %d, dead_skbs %d", rpc->id,
//			rpc->hsk->client_port,
//			rpc->hsk->dead_skbs);

	if (rpc->msgin.length >= 0) {
		rpc->hsk->dead_skbs += skb_queue_len(&rpc->msgin.packets);
		while (1) {
			struct homa_gap *gap;

			gap = list_first_entry_or_null(&rpc->msgin.gaps,
						       struct homa_gap, links);
			if (!gap)
				break;
			list_del(&gap->links);
			kfree(gap);
		}
	}
	rpc->hsk->dead_skbs += rpc->msgout.num_skbs;
	if (rpc->hsk->dead_skbs > rpc->hsk->homa->max_dead_buffs)
		/* This update isn't thread-safe; it's just a
		 * statistic so it's OK if updates occasionally get
		 * missed.
		 */
		rpc->hsk->homa->max_dead_buffs = rpc->hsk->dead_skbs;

	homa_sock_unlock(rpc->hsk);
	IF_NO_STRIP(homa_pacer_unmanage_rpc(rpc));
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
			   tt_addr(rpc->peer->addr), rpc->id, error);
		homa_rpc_end(rpc);
		return;
	}
	tt_record3("aborting client RPC: peer 0x%x, id %d, error %d",
		   tt_addr(rpc->peer->addr), rpc->id, error);
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
			if (!ipv6_addr_equal(&rpc->peer->addr, addr))
				continue;
			if (port && rpc->dport != port)
				continue;
			homa_rpc_lock(rpc);
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
 * RPCs for a given socket.
 * @hsk:      Homa socket that may contain dead RPCs. Must not be locked by the
 *            caller; this function will lock and release.
 * @reap_all: False means do a small chunk of work; there may still be
 *            unreaped RPCs on return. True means reap all dead RPCs for
 *            hsk.  Will busy-wait if reaping has been disabled for some RPCs.
 *
 * Return: A return value of 0 means that we ran out of work to do; calling
 *         again will do no work (there could be unreaped RPCs, but if so,
 *         they cannot currently be reaped).  A value greater than zero means
 *         there is still more reaping work to be done.
 */
int homa_rpc_reap(struct homa_sock *hsk, bool reap_all)
{
	/* RPC Reaping Strategy:
	 *
	 * (Note: there are references to this comment elsewhere in the
	 * Homa code)
	 *
	 * Most of the cost of reaping comes from freeing sk_buffs; this can be
	 * quite expensive for RPCs with long messages.
	 *
	 * The natural time to reap is when homa_rpc_end is invoked to
	 * terminate an RPC, but this doesn't work for two reasons. First,
	 * there may be outstanding references to the RPC; it cannot be reaped
	 * until all of those references have been released. Second, reaping
	 * is potentially expensive and RPC termination could occur in
	 * homa_softirq when there are short messages waiting to be processed.
	 * Taking time to reap a long RPC could result in significant delays
	 * for subsequent short RPCs.
	 *
	 * Thus Homa doesn't reap immediately in homa_rpc_end. Instead, dead
	 * RPCs are queued up and reaping occurs in this function, which is
	 * invoked later when it is less likely to impact latency. The
	 * challenge is to do this so that (a) we don't allow large numbers of
	 * dead RPCs to accumulate and (b) we minimize the impact of reaping
	 * on latency.
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
	 * 1. If too may dead skbs accumulate, then homa_timer will call
	 *    homa_rpc_reap.
	 * 2. If this timer thread cannot keep up with all the reaping to be
	 *    done then as a last resort homa_dispatch_pkts will reap in small
	 *    increments (a few sk_buffs or RPCs) for every incoming batch
	 *    of packets . This is undesirable because it will impact Homa's
	 *    performance.
	 *
	 * During the introduction of homa_pools for managing input
	 * buffers, freeing of packets for incoming messages was moved to
	 * homa_copy_to_user under the assumption that this code wouldn't be
	 * on the critical path. However, there is evidence that with
	 * fast networks (e.g. 100 Gbps) copying to user space is the
	 * bottleneck for incoming messages, and packet freeing takes about
	 * 20-25% of the total time in homa_copy_to_user. So, it may eventually
	 * be desirable to remove packet freeing out of homa_copy_to_user.
	 */
#ifdef __UNIT_TEST__
#define BATCH_MAX 3
#else /* __UNIT_TEST__ */
#define BATCH_MAX 10
#endif /* __UNIT_TEST__ */
	struct homa_rpc *rpcs[BATCH_MAX];
	struct sk_buff *skbs[BATCH_MAX];
	int num_skbs, num_rpcs;
	bool checked_all_rpcs;
	struct homa_rpc *rpc;
	struct homa_rpc *tmp;
	int i, batch_size;
	int skbs_to_reap;
	int rx_frees;

	INC_METRIC(reaper_calls, 1);
	INC_METRIC(reaper_dead_skbs, hsk->dead_skbs);

	/* Each iteration through the following loop will reap
	 * BATCH_MAX skbs.
	 */
	skbs_to_reap = hsk->homa->reap_limit;
	checked_all_rpcs = list_empty(&hsk->dead_rpcs);
	while (!checked_all_rpcs) {
		batch_size = BATCH_MAX;
		if (!reap_all) {
			if (skbs_to_reap <= 0)
				break;
			if (batch_size > skbs_to_reap)
				batch_size = skbs_to_reap;
			skbs_to_reap -= batch_size;
		}
		num_skbs = 0;
		num_rpcs = 0;
		rx_frees = 0;

		homa_sock_lock(hsk);
		if (atomic_read(&hsk->protect_count)) {
			INC_METRIC(disabled_reaps, 1);
			tt_record3("homa_rpc_reap returning for port %d: protect_count %d, dead_skbs %d",
				   hsk->port, atomic_read(&hsk->protect_count),
				   hsk->dead_skbs);
			homa_sock_unlock(hsk);
			if (reap_all)
				continue;
			return 0;
		}

		/* Collect buffers and freeable RPCs. */
		list_for_each_entry_safe(rpc, tmp, &hsk->dead_rpcs,
					 dead_links) {
			int refs;

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
			rpc->magic = 0;

			/* For Tx sk_buffs, collect them here but defer
			 * freeing until after releasing the socket lock.
			 */
			if (rpc->msgout.length >= 0) {
				while (rpc->msgout.packets) {
					struct sk_buff *skb =
							rpc->msgout.packets;

					/* This tests whether skb is still in a
					 * transmit queue somewhere; if so,
					 * can't reap the RPC since homa_qdisc
					 * may try to access it via the skb's
					 * homa_skb_info.
					 */
					if (refcount_read(&skb->users) > 1) {
						INC_METRIC(reaper_active_skbs,
							   1);
						goto next_rpc;
					}
					skbs[num_skbs] = skb;
					rpc->msgout.packets =
						homa_get_skb_info(skb)->next_skb;
					num_skbs++;
					rpc->msgout.num_skbs--;
					if (num_skbs >= batch_size)
						goto release;
				}
			}

			/* In the normal case rx sk_buffs will already have been
			 * freed before we got here. Thus it's OK to free
			 * immediately in rare situations where there are
			 * buffers left.
			 */
			if (rpc->msgin.length >= 0 &&
			    !skb_queue_empty_lockless(&rpc->msgin.packets)) {
				rx_frees += skb_queue_len(&rpc->msgin.packets);
				__skb_queue_purge(&rpc->msgin.packets);
			}

			/* If we get here, it means all packets have been
			 *  removed from the RPC.
			 */
			rpcs[num_rpcs] = rpc;
			num_rpcs++;
			list_del(&rpc->dead_links);
			WARN_ON(refcount_sub_and_test(rpc->msgout.skb_memory,
						      &hsk->sock.sk_wmem_alloc));
			if (num_rpcs >= batch_size)
				goto release;

next_rpc:
			continue;
		}
		checked_all_rpcs = true;

		/* Free all of the collected resources; release the socket
		 * lock while doing this.
		 */
release:
		hsk->dead_skbs -= num_skbs + rx_frees;
		homa_sock_unlock(hsk);
		homa_skb_free_many_tx(hsk->homa, skbs, num_skbs);
		for (i = 0; i < num_rpcs; i++) {
			IF_NO_STRIP(int tx_left);

			rpc = rpcs[i];

			UNIT_LOG("; ", "reaped %llu", rpc->id);
			if (unlikely(rpc->msgin.num_bpages))
				homa_pool_release_buffers(rpc->hsk->buffer_pool,
							  rpc->msgin.num_bpages,
							  rpc->msgin.bpage_offsets);
			if (rpc->msgin.length >= 0) {
				while (1) {
					struct homa_gap *gap;

					gap = list_first_entry_or_null(
							&rpc->msgin.gaps,
							struct homa_gap,
							links);
					if (!gap)
						break;
					list_del(&gap->links);
					kfree(gap);
				}
			}
			if (rpc->peer) {
				homa_peer_release(rpc->peer);
				rpc->peer = NULL;
			}
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
			kfree(rpc);
		}
		homa_sock_wakeup_wmem(hsk);
		tt_record4("reaped %d skbs, %d rpcs; %d skbs remain for port %d",
			   num_skbs + rx_frees, num_rpcs, hsk->dead_skbs,
			   hsk->port);
	}
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
			   tt_addr(rpc->peer->addr), error);
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
		if (srpc->id == id && ipv6_addr_equal(&srpc->peer->addr, saddr))
			return srpc;
	}
	homa_bucket_unlock(bucket, id);
	return NULL;
}
