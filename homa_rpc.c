// SPDX-License-Identifier: BSD-2-Clause

/* This file contains functions for managing homa_rpc structs. */

#include "homa_impl.h"
#include "homa_interest.h"
#include "homa_pacer.h"
#include "homa_peer.h"
#include "homa_pool.h"
#ifndef __STRIP__ /* See strip.py */
#include "homa_grant.h"
#include "homa_skb.h"
#endif /* See strip.py */

#ifdef __STRIP__ /* See strip.py */
#include "homa_stub.h"
#endif /* See strip.py */

/**
 * homa_rpc_new_client() - Allocate and construct a client RPC (one that is used
 * to issue an outgoing request). Doesn't send any packets. Invoked with no
 * locks held.
 * @hsk:      Socket to which the RPC belongs.
 * @dest:     Address of host (ip and port) to which the RPC will be sent.
 *
 * Return:    A printer to the newly allocated object, or a negative
 *            errno if an error occurred. The RPC will be locked; the
 *            caller must eventually unlock it.
 */
struct homa_rpc *homa_rpc_new_client(struct homa_sock *hsk,
				     const union sockaddr_in_union *dest)
	__acquires(&crpc->bucket->lock)
{
	struct in6_addr dest_addr_as_ipv6 = canonical_ipv6_addr(dest);
	struct homa_rpc_bucket *bucket;
	struct homa_rpc *crpc;
	int err;

	crpc = kmalloc(sizeof(*crpc), GFP_KERNEL | __GFP_ZERO);
	if (unlikely(!crpc))
		return ERR_PTR(-ENOMEM);

	/* Initialize fields that don't require the socket lock. */
	crpc->hsk = hsk;
	crpc->id = atomic64_fetch_add(2, &hsk->homa->next_outgoing_id);
	bucket = homa_client_rpc_bucket(hsk, crpc->id);
	crpc->bucket = bucket;
	crpc->state = RPC_OUTGOING;
	crpc->peer = homa_peer_find(hsk->homa->peers, &dest_addr_as_ipv6,
				    &hsk->inet);
	if (IS_ERR(crpc->peer)) {
		tt_record("error in homa_peer_find");
		err = PTR_ERR(crpc->peer);
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
	crpc->start_ns = sched_clock();

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
	list_add_tail_rcu(&crpc->active_links, &hsk->active_rpcs);
	homa_sock_unlock(hsk);

	return crpc;

error:
	kfree(crpc);
	return ERR_PTR(err);
}

/**
 * homa_rpc_new_server() - Allocate and construct a server RPC (one that is
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
struct homa_rpc *homa_rpc_new_server(struct homa_sock *hsk,
				     const struct in6_addr *source,
				     struct homa_data_hdr *h, int *created)
	__acquires(&srpc->bucket->lock)
{
	u64 id = homa_local_id(h->common.sender_id);
	struct homa_rpc_bucket *bucket;
	struct homa_rpc *srpc = NULL;
	int err;

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
	srpc = kmalloc(sizeof(*srpc), GFP_ATOMIC | __GFP_ZERO);
	if (!srpc) {
		err = -ENOMEM;
		goto error;
	}
	srpc->hsk = hsk;
	srpc->bucket = bucket;
	srpc->state = RPC_INCOMING;
	srpc->peer = homa_peer_find(hsk->homa->peers, source, &hsk->inet);
	if (IS_ERR(srpc->peer)) {
		err = PTR_ERR(srpc->peer);
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
	srpc->start_ns = sched_clock();
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
	kfree(srpc);
	return ERR_PTR(err);
}

/**
 * homa_rpc_acked() - This function is invoked when an ack is received
 * for an RPC; if the RPC still exists, is freed.
 * @hsk:     Socket on which the ack was received. May or may not correspond
 *           to the RPC, but can sometimes be used to avoid a socket lookup.
 * @saddr:   Source address from which the act was received (the client
 *           note for the RPC)
 * @ack:     Information about an RPC from @saddr that may now be deleted
 *           safely.
 */
void homa_rpc_acked(struct homa_sock *hsk, const struct in6_addr *saddr,
		    struct homa_ack *ack)
{
	__u16 server_port = ntohs(ack->server_port);
	u64 id = homa_local_id(ack->client_id);
	struct homa_sock *hsk2 = hsk;
	struct homa_rpc *rpc;

	UNIT_LOG("; ", "ack %llu", id);
	if (hsk->port != server_port) {
		/* Without RCU, sockets other than hsk can be deleted
		 * out from under us.
		 */
		hsk2 = homa_sock_find(hsk->homa->port_map, server_port);
		if (!hsk2)
			return;
	}
	rpc = homa_find_server_rpc(hsk2, saddr, id);
	if (rpc) {
		tt_record1("homa_rpc_acked freeing id %d", rpc->id);
		homa_rpc_end(rpc);
		homa_rpc_unlock(rpc); /* Locked by homa_find_server_rpc. */
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
	__acquires(&rpc->hsk->lock)
	__releases(&rpc->hsk->lock)
{
	/* The goal for this function is to make the RPC inaccessible,
	 * so that no other code will ever access it again. However, don't
	 * actually release resources; leave that to homa_rpc_reap, which
	 * runs later. There are two reasons for this. First, releasing
	 * resources may be expensive, so we don't want to keep the caller
	 * waiting; homa_rpc_reap will run in situations where there is time
	 * to spare. Second, there may be other code that currently has
	 * pointers to this RPC but temporarily released the lock (e.g. to
	 * copy data to/from user space). It isn't safe to clean up until
	 * that code has finished its work and released any pointers to the
	 * RPC (homa_rpc_reap will ensure that this has happened). So, this
	 * function should only make changes needed to make the RPC
	 * inaccessible.
	 */
	if (!rpc || rpc->state == RPC_DEAD)
		return;
	UNIT_LOG("; ", "homa_rpc_end invoked");
	tt_record1("homa_rpc_end invoked for id %d", rpc->id);
	rpc->state = RPC_DEAD;
	rpc->error = -EINVAL;

#ifndef __STRIP__ /* See strip.py */
	/* The following line must occur before the socket is locked. This is
	 * necessary because homa_grant_end_rpc releases the RPC lock and
	 * reacquires it.
	 */
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
	homa_pacer_unmanage_rpc(rpc);
}

/**
 * homa_rpc_reap() - Invoked to release resources associated with dead
 * RPCs for a given socket. For a large RPC, it can take a long time to
 * free all of its packet buffers, so we try to perform this work
 * off the critical path where it won't delay applications. Each call to
 * this function normally does a small chunk of work (unless reap_all is
 * true). See the file reap.txt for more information.
 * @hsk:      Homa socket that may contain dead RPCs. Must not be locked by the
 *            caller; this function will lock and release.
 * @reap_all: False means do a small chunk of work; there may still be
 *            unreaped RPCs on return. True means reap all dead rpcs for
 *            hsk.  Will busy-wait if reaping has been disabled for some RPCs.
 *
 * Return: A return value of 0 means that we ran out of work to do; calling
 *         again will do no work (there could be unreaped RPCs, but if so,
 *         reaping has been disabled for them).  A value greater than
 *         zero means there is still more reaping work to be done.
 */
int homa_rpc_reap(struct homa_sock *hsk, bool reap_all)
{
#ifdef __UNIT_TEST__
#define BATCH_MAX 3
#else /* __UNIT_TEST__ */
#define BATCH_MAX 20
#endif /* __UNIT_TEST__ */
	struct homa_rpc *rpcs[BATCH_MAX];
	struct sk_buff *skbs[BATCH_MAX];
	int num_skbs, num_rpcs;
	struct homa_rpc *rpc;
	struct homa_rpc *tmp;
	int i, batch_size;
	int skbs_to_reap;
	int rx_frees;
	int result = 0;

	INC_METRIC(reaper_calls, 1);
	INC_METRIC(reaper_dead_skbs, hsk->dead_skbs);

	/* Each iteration through the following loop will reap
	 * BATCH_MAX skbs.
	 */
	skbs_to_reap = hsk->homa->reap_limit;
	while (skbs_to_reap > 0 && !list_empty(&hsk->dead_rpcs)) {
		batch_size = BATCH_MAX;
		if (!reap_all) {
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
			tt_record2("homa_rpc_reap returning: protect_count %d, dead_skbs %d",
				   atomic_read(&hsk->protect_count),
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
			 * completed. We can only be sure if the reference
			 * count is zero when we're holding the lock. Note:
			 * it isn't safe to block while locking the RPC here,
			 * since we hold the socket lock.
			 */
			if (homa_rpc_try_lock(rpc)) {
				refs = atomic_read(&rpc->refs);
				homa_rpc_unlock(rpc);
			} else {
				refs = 1;
			}
			if (refs != 0) {
				INC_METRIC(deferred_rpc_reaps, 1);
				continue;
			}
			rpc->magic = 0;

			/* For Tx sk_buffs, collect them here but defer
			 * freeing until after releasing the socket lock.
			 */
			if (rpc->msgout.length >= 0) {
				while (rpc->msgout.packets) {
					skbs[num_skbs] = rpc->msgout.packets;
					rpc->msgout.packets = homa_get_skb_info(
						rpc->msgout.packets)->next_skb;
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
		}

		/* Free all of the collected resources; release the socket
		 * lock while doing this.
		 */
release:
		hsk->dead_skbs -= num_skbs + rx_frees;
		result = !list_empty(&hsk->dead_rpcs) &&
				(num_skbs + num_rpcs) != 0;
		homa_sock_unlock(hsk);
		homa_skb_free_many_tx(hsk->homa, skbs, num_skbs);
		for (i = 0; i < num_rpcs; i++) {
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
			tt_record2("homa_rpc_reap finished reaping id %d, socket %d",
				   rpc->id, rpc->hsk->port);
			rpc->state = 0;
			kfree(rpc);
		}
		homa_sock_wakeup_wmem(hsk);
		tt_record4("reaped %d skbs, %d rpcs; %d skbs remain for port %d",
			   num_skbs + rx_frees, num_rpcs, hsk->dead_skbs,
			   hsk->port);
		if (!result && !reap_all)
			break;
	}
	homa_pool_check_waiting(hsk->buffer_pool);
	return result;
}

/**
 * homa_find_client_rpc() - Locate client-side information about the RPC that
 * a packet belongs to, if there is any. Thread-safe without socket lock.
 * @hsk:      Socket via which packet was received.
 * @id:       Unique identifier for the RPC.
 *
 * Return:    A pointer to the homa_rpc for this id, or NULL if none.
 *            The RPC will be locked; the caller must eventually unlock it
 *            by invoking homa_rpc_unlock.
 */
struct homa_rpc *homa_find_client_rpc(struct homa_sock *hsk, u64 id)
	__acquires(&crpc->bucket->lock)
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
 * homa_find_server_rpc() - Locate server-side information about the RPC that
 * a packet belongs to, if there is any. Thread-safe without socket lock.
 * @hsk:      Socket via which packet was received.
 * @saddr:    Address from which the packet was sent.
 * @id:       Unique identifier for the RPC (must have server bit set).
 *
 * Return:    A pointer to the homa_rpc matching the arguments, or NULL
 *            if none. The RPC will be locked; the caller must eventually
 *            unlock it by invoking homa_rpc_unlock.
 */
struct homa_rpc *homa_find_server_rpc(struct homa_sock *hsk,
				      const struct in6_addr *saddr, u64 id)
	__acquires(&srpc->bucket->lock)
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

#ifndef __UPSTREAM__ /* See strip.py */
/**
 * homa_rpc_log() - Log info about a particular RPC; this is functionality
 * pulled out of homa_rpc_log_active because its indentation got too deep.
 * @rpc:  RPC for which key info should be written to the system log.
 */
void homa_rpc_log(struct homa_rpc *rpc)
{
	char *type = homa_is_client(rpc->id) ? "Client" : "Server";
	char *peer = homa_print_ipv6_addr(&rpc->peer->addr);

	if (rpc->state == RPC_INCOMING)
		pr_notice("%s RPC INCOMING, id %llu, peer %s:%d, %d/%d bytes received, incoming %d\n",
			  type, rpc->id, peer, rpc->dport,
			  rpc->msgin.length - rpc->msgin.bytes_remaining,
#ifndef __STRIP__
			  rpc->msgin.length, rpc->msgin.granted);
#else
			  rpc->msgin.length, 0);
#endif /* __STRIP__ */
	else if (rpc->state == RPC_OUTGOING) {
		pr_notice("%s RPC OUTGOING, id %llu, peer %s:%d, out length %d, left %d, granted %d, in left %d, resend_ticks %u, silent_ticks %d\n",
			  type, rpc->id, peer, rpc->dport, rpc->msgout.length,
			  rpc->msgout.length - rpc->msgout.next_xmit_offset,
#ifndef __STRIP__
			  rpc->msgout.granted, rpc->msgin.bytes_remaining,
#else
			  0, rpc->msgin.bytes_remaining,
#endif /* __STRIP__ */
			  rpc->resend_timer_ticks, rpc->silent_ticks);
	} else {
		pr_notice("%s RPC %s, id %llu, peer %s:%d, incoming length %d, outgoing length %d\n",
			  type, homa_symbol_for_state(rpc), rpc->id, peer,
			  rpc->dport, rpc->msgin.length, rpc->msgout.length);
	}
}

/**
 * homa_rpc_log_active() - Print information to the system log about all
 * active RPCs. Intended primarily for debugging.
 * @homa:    Overall data about the Homa protocol implementation.
 * @id:      An RPC id: if nonzero, then only RPCs with this id will be
 *           logged.
 */
void homa_rpc_log_active(struct homa *homa, uint64_t id)
{
	struct homa_socktab_scan scan;
	struct homa_sock *hsk;
	struct homa_rpc *rpc;
	int count = 0;

	pr_notice("Logging active Homa RPCs:\n");
	rcu_read_lock();
	for (hsk = homa_socktab_start_scan(homa->port_map, &scan);
	     hsk; hsk = homa_socktab_next(&scan)) {
		if (list_empty(&hsk->active_rpcs) || hsk->shutdown)
			continue;

		if (!homa_protect_rpcs(hsk))
			continue;
		list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
			count++;
			if (id != 0 && id != rpc->id)
				continue;
			homa_rpc_log(rpc);
					}
		homa_unprotect_rpcs(hsk);
	}
	homa_socktab_end_scan(&scan);
	rcu_read_unlock();
	pr_notice("Finished logging active Homa RPCs: %d active RPCs\n", count);
}

/**
 * homa_rpc_log_tt() - Log info about a particular RPC using timetraces.
 * @rpc:  RPC for which key info should be written to the system log.
 */
void homa_rpc_log_tt(struct homa_rpc *rpc)
{
	if (rpc->state == RPC_INCOMING) {
		int received = rpc->msgin.length
				- rpc->msgin.bytes_remaining;
		int rank;

		tt_record4("Incoming RPC id %d, peer 0x%x, %d/%d bytes received",
			   rpc->id, tt_addr(rpc->peer->addr),
			   received, rpc->msgin.length);
#ifndef __STRIP__
		tt_record4("RPC id %d has incoming %d, granted %d, prio %d", rpc->id,
			   rpc->msgin.granted - received,
			   rpc->msgin.granted, rpc->msgin.priority);
		rank = atomic_read(&rpc->msgin.rank);
		if (rpc->hsk->homa->active_rpcs[rank] != rpc)
			rank = -1;
#else /* __STRIP__ */
		rank = -1;
#endif /* __STRIP__ */
		tt_record4("RPC id %d: length %d, remaining %d, rank %d",
			   rpc->id, rpc->msgin.length,
			   rpc->msgin.bytes_remaining, rank);
		if (rpc->msgin.num_bpages == 0)
			tt_record1("RPC id %d is blocked waiting for buffers",
				   rpc->id);
		else
			tt_record2("RPC id %d has %d bpages allocated",
				   rpc->id, rpc->msgin.num_bpages);
	} else if (rpc->state == RPC_OUTGOING) {
		tt_record4("Outgoing RPC id %d, peer 0x%x, %d/%d bytes sent",
			   rpc->id, tt_addr(rpc->peer->addr),
			   rpc->msgout.next_xmit_offset,
			   rpc->msgout.length);
#ifndef __STRIP__
		if (rpc->msgout.granted > rpc->msgout.next_xmit_offset)
			tt_record3("RPC id %d has %d unsent grants (granted %d)",
				   rpc->id, rpc->msgout.granted -
				   rpc->msgout.next_xmit_offset,
				   rpc->msgout.granted);
#endif /* __STRIP__ */
	} else {
		tt_record2("RPC id %d is in state %d", rpc->id, rpc->state);
	}
}

/**
 * homa_rpc_log_active_tt() - Log information about all active RPCs using
 * timetraces.
 * @homa:    Overall data about the Homa protocol implementation.
 * @freeze_count:  If nonzero, FREEZE requests will be sent for this many
 *                 incoming RPCs with outstanding grants
 */
void homa_rpc_log_active_tt(struct homa *homa, int freeze_count)
{
	struct homa_socktab_scan scan;
	struct homa_sock *hsk;
	struct homa_rpc *rpc;
	int count = 0;

#ifndef __STRIP__
	homa_grant_log_tt(homa);
#endif /* __STRIP__ */
	tt_record("Logging active Homa RPCs:");
	rcu_read_lock();
	for (hsk = homa_socktab_start_scan(homa->port_map, &scan);
			hsk; hsk = homa_socktab_next(&scan)) {
		if (list_empty(&hsk->active_rpcs) || hsk->shutdown)
			continue;

		if (!homa_protect_rpcs(hsk))
			continue;
		list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
			struct homa_freeze_hdr freeze;

			count++;
			homa_rpc_log_tt(rpc);
			if (freeze_count == 0)
				continue;
			if (rpc->state != RPC_INCOMING)
				continue;
#ifndef __STRIP__
			if (rpc->msgin.granted <= (rpc->msgin.length
					- rpc->msgin.bytes_remaining))
				continue;
#endif /* __STRIP__ */
			freeze_count--;
			pr_notice("Emitting FREEZE in %s\n", __func__);
			homa_xmit_control(FREEZE, &freeze, sizeof(freeze), rpc);
		}
		homa_unprotect_rpcs(hsk);
	}
	homa_socktab_end_scan(&scan);
	rcu_read_unlock();
	tt_record1("Finished logging (%d active Homa RPCs)", count);
}
#endif /* See strip.py */

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_validate_incoming() - Scan all of the active RPCs to compute what
 * homa_total_incoming should be, and see if it actually matches.
 * @homa:         Overall data about the Homa protocol implementation.
 * @verbose:      Print incoming info for each individual RPC.
 * @link_errors:  Set to 1 if one or more grantable RPCs don't seem to
 *                be linked into the grantable lists.
 * Return:   The difference between the actual value of homa->total_incoming
 *           and the expected value computed from the individual RPCs (positive
 *           means homa->total_incoming is higher than expected).
 */
int homa_validate_incoming(struct homa *homa, int verbose, int *link_errors)
{
	struct homa_socktab_scan scan;
	int total_incoming = 0;
	struct homa_sock *hsk;
	struct homa_rpc *rpc;
	int actual;

	tt_record1("homa_validate_incoming starting, total_incoming %d",
		   atomic_read(&homa->total_incoming));
	*link_errors = 0;
	rcu_read_lock();
	for (hsk = homa_socktab_start_scan(homa->port_map, &scan);
			hsk; hsk = homa_socktab_next(&scan)) {
		if (list_empty(&hsk->active_rpcs) || hsk->shutdown)
			continue;

		if (!homa_protect_rpcs(hsk))
			continue;
		list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
			int incoming;

			if (rpc->state != RPC_INCOMING)
				continue;
			incoming = rpc->msgin.granted -
					(rpc->msgin.length
					- rpc->msgin.bytes_remaining);
			if (incoming < 0)
				incoming = 0;
			if (rpc->msgin.rec_incoming == 0)
				continue;
			total_incoming += rpc->msgin.rec_incoming;
			if (verbose)
				tt_record3("homa_validate_incoming: RPC id %d, incoming %d, rec_incoming %d",
					   rpc->id, incoming,
					   rpc->msgin.rec_incoming);
			if (rpc->msgin.granted >= rpc->msgin.length)
				continue;
			if (list_empty(&rpc->grantable_links)) {
				tt_record1("homa_validate_incoming: RPC id %d not linked in grantable list",
					   rpc->id);
				*link_errors = 1;
			}
			if (list_empty(&rpc->grantable_links)) {
				tt_record1("homa_validate_incoming: RPC id %d peer not linked in grantable list",
					   rpc->id);
				*link_errors = 1;
			}
		}
		homa_unprotect_rpcs(hsk);
	}
	homa_socktab_end_scan(&scan);
	rcu_read_unlock();
	actual = atomic_read(&homa->total_incoming);
	tt_record3("homa_validate_incoming diff %d (expected %d, got %d)",
		   actual - total_incoming, total_incoming, actual);
	return actual - total_incoming;
}
#endif /* See strip.py */
