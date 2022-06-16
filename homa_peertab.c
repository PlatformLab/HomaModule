/* Copyright (c) 2019-2020, Stanford University
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

/* This file manages homa_peertab objects and is responsible for creating
 * and deleting homa_peer objects.
 */

#include "homa_impl.h"

/**
 * homa_peertab_init() - Constructor for homa_peertabs.
 * @peertab:  The object to initialize; previous contents are discarded.
 * 
 * Return:    0 in the normal case, or a negative errno if there was a problem.
 */
int homa_peertab_init(struct homa_peertab *peertab)
{
	/* Note: when we return, the object must be initialized so it's
	 * safe to call homa_peertab_destroy, even if this function returns
	 * an error.
	 */
	int i;
	spin_lock_init(&peertab->write_lock);
	INIT_LIST_HEAD(&peertab->dead_dsts);
	peertab->buckets = (struct hlist_head *) vmalloc(
			HOMA_PEERTAB_BUCKETS * sizeof(*peertab->buckets));
	if (!peertab->buckets)
		return -ENOMEM;
	for (i = 0; i < HOMA_PEERTAB_BUCKETS; i++) {
		INIT_HLIST_HEAD(&peertab->buckets[i]);
	}
	return 0;
}

/**
 * homa_peertab_destroy() - Destructor for homa_peertabs. After this
 * function returns, it is unsafe to use any results from previous calls
 * to homa_peer_find, since all existing homa_peer objects will have been
 * destroyed.
 * @peertab:  The table to destroy.
 */
void homa_peertab_destroy(struct homa_peertab *peertab)
{
	int i;
	struct homa_peer *peer;
	struct hlist_node *next;
	if (!peertab->buckets)
		return;
	
	for (i = 0; i < HOMA_PEERTAB_BUCKETS; i++) {
		hlist_for_each_entry_safe(peer, next, &peertab->buckets[i],
				peertab_links) {
			dst_release(peer->dst);
			kfree(peer);
		}
	}
	vfree(peertab->buckets);
	homa_peertab_gc_dsts(peertab, ~0);
}

/**
 * homa_peertab_gc_dsts() - Invoked to free unused dst_entries, if it is
 * safe to do so.
 * @peertab        The table in which to free entries.
 * @now            Current time, in get_cycles units; entries with expiration
 *                 dates no later than this will be freed. Specify ~0 to
 *                 free all entries.
 */
void homa_peertab_gc_dsts(struct homa_peertab *peertab, __u64 now)
{
	while (!list_empty(&peertab->dead_dsts)) {
		struct homa_dead_dst *dead = list_first_entry(
				&peertab->dead_dsts, struct homa_dead_dst,
				dst_links);
		if (dead->gc_time > now)
			break;
		dst_release(dead->dst);
		list_del(&dead->dst_links);
		kfree(dead);
	}
}

/**
 * homa_peer_find() - Returns the peer associated with a given host; creates
 * a new homa_peer if one doesn't already exist.
 * @peertab:    Peer table in which to perform lookup.
 * @addr:       IPV4 address of the desired host.
 * @inet:       Socket that will be used for sending packets.
 * 
 * Return:      The peer associated with @addr, or a negative errno if an
 *              error occurred. The caller can retain this pointer
 *              indefinitely: peer entries are never deleted except in
 *              homa_peertab_destroy.
 */
struct homa_peer *homa_peer_find(struct homa_peertab *peertab, __be32 addr,
	struct inet_sock *inet)
{
	/* Note: this function uses RCU operators to ensure safety even
	 * if a concurrent call is adding a new entry.
	 */
	struct homa_peer *peer;
	struct rtable *rt;
	__u32 bucket = hash_32(addr, HOMA_PEERTAB_BUCKET_BITS);
	hlist_for_each_entry_rcu(peer, &peertab->buckets[bucket],
			peertab_links) {
		if (peer->addr == addr) {
			return peer;
		}
		INC_METRIC(peer_hash_links, 1);
	}
	
	/* No existing entry; create a new one.
	 * 
	 * Note: after we acquire the lock, we have to check again to
	 * make sure the entry still doesn't exist after grabbing
	 * the lock (it might have been created by a concurrent invocation
	 * of this function). */
	spin_lock_bh(&peertab->write_lock);
	hlist_for_each_entry_rcu(peer, &peertab->buckets[bucket],
			peertab_links) {
		if (peer->addr == addr)
			goto done;
	}
	peer = kmalloc(sizeof(*peer), GFP_ATOMIC);
	if (!peer) {
		peer = (struct homa_peer *) ERR_PTR(-ENOMEM);
		INC_METRIC(peer_kmalloc_errors, 1);
		goto done;
	}
	peer->addr = addr;
	flowi4_init_output(&peer->flow.u.ip4, inet->sk.sk_bound_dev_if,
			inet->sk.sk_mark, inet->tos, RT_SCOPE_UNIVERSE,
			inet->sk.sk_protocol, 0, addr, inet->inet_saddr,
			0, 0, inet->sk.sk_uid);
	security_sk_classify_flow(&inet->sk, &peer->flow);
	rt = ip_route_output_flow(sock_net(&inet->sk), &peer->flow.u.ip4,
			&inet->sk);
	if (IS_ERR(rt)) {
		kfree(peer);
		peer = (struct homa_peer *) PTR_ERR(rt);
		INC_METRIC(peer_route_errors, 1);
		goto done;
	}
	peer->dst = &rt->dst;
	peer->unsched_cutoffs[HOMA_MAX_PRIORITIES-1] = 0;
	peer->unsched_cutoffs[HOMA_MAX_PRIORITIES-2] = INT_MAX;
	peer->cutoff_version = 0;
	peer->last_update_jiffies = 0;
	INIT_LIST_HEAD(&peer->grantable_rpcs);
	INIT_LIST_HEAD(&peer->grantable_links);
	hlist_add_head_rcu(&peer->peertab_links, &peertab->buckets[bucket]);
	peer->outstanding_resends = 0;
	peer->most_recent_resend = 0;
	peer->least_recent_rpc = NULL;
	peer->least_recent_ticks = 0;
	peer->current_ticks = -1;
	peer->resend_rpc = NULL;
	peer->num_acks = 0;
	spin_lock_init(&peer->ack_lock);
	INC_METRIC(peer_new_entries, 1);
	
    done:
	spin_unlock_bh(&peertab->write_lock);
	return peer;
}

/**
 * homa_dst_refresh() - This method is called when the dst for a peer is
 * obsolete; it releases that dst and creates a new one.
 * @peertab:  Table containing the peer.
 * @peer:     Peer whose dst is obsolete.
 * @hsk:      Socket that will be used to transmit data to the peer.
 */
void homa_dst_refresh(struct homa_peertab *peertab, struct homa_peer *peer,
		struct homa_sock *hsk)
{
	struct rtable *rt;
	struct sock *sk = &hsk->inet.sk;
	
	spin_lock_bh(&peertab->write_lock);
	flowi4_init_output(&peer->flow.u.ip4, sk->sk_bound_dev_if,
			sk->sk_mark, hsk->inet.tos, RT_SCOPE_UNIVERSE,
			sk->sk_protocol, 0, peer->addr, hsk->inet.inet_saddr,
			0, 0, sk->sk_uid);
	security_sk_classify_flow(sk, &peer->flow);
	rt = ip_route_output_flow(sock_net(sk), &peer->flow.u.ip4, sk);
	if (IS_ERR(rt)) {
		/* Retain the existing dst if we can't create a new one. */
		if (hsk->homa->verbose)
			printk(KERN_NOTICE "homa_refresh couldn't recreate "
					"dst: error %ld", PTR_ERR(rt));
		INC_METRIC(peer_route_errors, 1);
	} else {
		struct homa_dead_dst *dead = (struct homa_dead_dst *)
				kmalloc(sizeof(*dead), GFP_KERNEL);
		if (unlikely(!dead)) {
			/* Can't allocate memory to keep track of the
			 * dead dst; just free it immediately (a bit
			 * risky, admittedly).
			 */
			dst_release(peer->dst);
		} else {
			__u64 now = get_cycles();
			
			dead->dst = peer->dst;
			dead->gc_time = now + (cpu_khz<<7);
			list_add_tail(&dead->dst_links, &peertab->dead_dsts);
			homa_peertab_gc_dsts(peertab, now);
		}
		peer->dst = &rt->dst;
	}
	spin_unlock_bh(&peertab->write_lock);
}

/**
 * homa_peer_unsched_priority() - Returns the priority level to use for
 * unscheduled packets of a message.
 * @homa:     Overall data about the Homa protocol implementation.
 * @peer:     The destination of the message.
 * @length:   Number of bytes in the message.
 * 
 * Return:    A priority level.
 */
int homa_unsched_priority(struct homa *homa, struct homa_peer *peer,
		int length)
{
	int i;
	for (i = homa->num_priorities-1; ; i--) {
		if (peer->unsched_cutoffs[i] >= length)
			return i;
	}
	/* Can't ever get here */
}

/**
 * homa_peer_set_cutoffs() - Set the cutoffs for unscheduled priorities in
 * a peer object. This is a convenience function used primarily by unit tests.
 * @peer:   Homa_peer object whose cutoffs should be set.
 * @c0:     Largest message size that will use priority 0. 
 * @c1:     Largest message size that will use priority 1.
 * @c2:     Largest message size that will use priority 2.
 * @c3:     Largest message size that will use priority 3.
 * @c4:     Largest message size that will use priority 4.
 * @c5:     Largest message size that will use priority 5.
 * @c6:     Largest message size that will use priority 6.
 * @c7:     Largest message size that will use priority 7.
 */
void homa_peer_set_cutoffs(struct homa_peer *peer, int c0, int c1, int c2,
		int c3, int c4, int c5, int c6, int c7)
{
	peer->unsched_cutoffs[0] = c0;
	peer->unsched_cutoffs[1] = c1;
	peer->unsched_cutoffs[2] = c2;
	peer->unsched_cutoffs[3] = c3;
	peer->unsched_cutoffs[4] = c4;
	peer->unsched_cutoffs[5] = c5;
	peer->unsched_cutoffs[6] = c6;
	peer->unsched_cutoffs[7] = c7;
}

/**
 * homa_peer_lock_slow() - This function implements the slow path for
 * acquiring a peer's @unacked_lock. It is invoked when the lock isn't
 * immediately available. It waits for the lock, but also records statistics
 * about the waiting time.
 * @peer:    Peer to  lock.
 */
void homa_peer_lock_slow(struct homa_peer *peer)
{
	__u64 start = get_cycles();
	tt_record("beginning wait for peer lock");
	spin_lock_bh(&peer->ack_lock);
	tt_record("ending wait for peer lock");
	INC_METRIC(peer_lock_misses, 1);
	INC_METRIC(peer_lock_miss_cycles, get_cycles() - start);
}

/**
 * homa_peer_add_ack() - Add a given RPC to the list of unacked
 * RPCs for its server. Once this method has been invoked, it's safe
 * to delete the RPC, since it will eventually be acked to the server.
 * @rpc:    Client RPC that has now completed.
 */
void homa_peer_add_ack(struct homa_rpc *rpc)
{
	struct homa_peer *peer = rpc->peer;
	struct ack_header ack;
	
	homa_peer_lock(peer);
	if (peer->num_acks < NUM_PEER_UNACKED_IDS) {
		peer->acks[peer->num_acks].client_id = cpu_to_be64(rpc->id);
		peer->acks[peer->num_acks].client_port = htons(rpc->hsk->port);
		peer->acks[peer->num_acks].server_port = htons(rpc->dport);
		peer->num_acks++;
		homa_peer_unlock(peer);
		return;
	}
	
	/* The peer has filled up; send an ACK message to empty it. The
	 * RPC in the message header will also be considered ACKed.
	 */
	INC_METRIC(ack_overflows, 1);
	memcpy(ack.acks, peer->acks, sizeof(peer->acks));
	ack.num_acks = htons(peer->num_acks);
	peer->num_acks = 0;
	homa_peer_unlock(peer);
	homa_xmit_control(ACK, &ack, sizeof(ack), rpc);
}

/**
 * homa_peer_get_acks() - Copy acks out of a peer, and remove them from the
 * peer.
 * @peer:    Peer to check for possible unacked RPCs.
 * @count:   Maximum number of acks to return.
 * @dst:     The acks are copied to this location.
 * 
 * Return:   The number of acks extracted from the peer (<= count).
 */
int homa_peer_get_acks(struct homa_peer *peer, int count, struct homa_ack *dst)
{	
	/* Don't waste time acquiring the lock if there are no ids available. */
	if (peer->num_acks == 0)
		return 0;
	
	homa_peer_lock(peer);
	
	if (count > peer->num_acks)
		count = peer->num_acks;
	memcpy(dst, &peer->acks[peer->num_acks - count],
			count * sizeof(peer->acks[0]));
	peer->num_acks -= count;
	
	homa_peer_unlock(peer);
	return count;
}