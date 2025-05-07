// SPDX-License-Identifier: BSD-2-Clause

/* This file provides functions related to homa_peer and homa_peertab
 * objects.
 */

#include "homa_impl.h"
#include "homa_peer.h"
#include "homa_rpc.h"

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
	peertab->buckets = vmalloc(HOMA_PEERTAB_BUCKETS *
				   sizeof(*peertab->buckets));
	if (!peertab->buckets)
		return -ENOMEM;
	for (i = 0; i < HOMA_PEERTAB_BUCKETS; i++)
		INIT_HLIST_HEAD(&peertab->buckets[i]);
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
	struct hlist_node *next;
	struct homa_peer *peer;
	int i;

	if (!peertab->buckets)
		return;

	spin_lock_bh(&peertab->write_lock);
	for (i = 0; i < HOMA_PEERTAB_BUCKETS; i++) {
		hlist_for_each_entry_safe(peer, next, &peertab->buckets[i],
					  peertab_links) {
			dst_release(peer->dst);
			kfree(peer);
		}
	}
	vfree(peertab->buckets);
	homa_peertab_gc_dsts(peertab, ~0);
	spin_unlock_bh(&peertab->write_lock);
}

#ifndef __UPSTREAM__ /* See strip.py */
/**
 * homa_peertab_get_peers() - Return information about all of the peers
 * currently known
 * @peertab:    The table to search for peers.
 * @num_peers:  Modified to hold the number of peers returned.
 * Return:      kmalloced array holding pointers to all known peers. The
 *		caller must free this. If there is an error, or if there
 *	        are no peers, NULL is returned.  Note: if a large number
 *              of new peers are created while this function executes,
 *              then the results may not be complete.
 */
struct homa_peer **homa_peertab_get_peers(struct homa_peertab *peertab,
					  int *num_peers)
{
	int i, slots, next_slot;
	struct homa_peer **result;
	struct homa_peer *peer;

	/* Note: RCU must be used in the iterators below to ensure safety
	 * with concurrent insertions. Technically, rcu_read_lock and
	 * rcu_read_unlock shouldn't be necessary because we don't have to
	 * worry about concurrent deletions. But without them, some sanity
	 * checkers will complain.
	 */
	rcu_read_lock();

	/* Figure out how large an array to allocate. */
	slots = 0;
	next_slot = 0;
	result = NULL;
	if (peertab->buckets) {
		for (i = 0; i < HOMA_PEERTAB_BUCKETS; i++) {
			hlist_for_each_entry_rcu(peer, &peertab->buckets[i],
						 peertab_links)
				slots++;
		}
	}
	if (slots == 0)
		goto done;

	/* Allocate extra space in case new peers got created while we
	 * were counting.
	 */
	slots += 10;
	result = kmalloc_array(slots, sizeof(peer), GFP_ATOMIC);
	if (!result)
		goto done;
	for (i = 0; i < HOMA_PEERTAB_BUCKETS; i++) {
		hlist_for_each_entry_rcu(peer, &peertab->buckets[i],
					 peertab_links) {
			result[next_slot] = peer;
			next_slot++;

			/* We might not have allocated enough extra space. */
			if (next_slot >= slots)
				goto done;
		}
	}
done:
	rcu_read_unlock();
	*num_peers = next_slot;
	return result;
}
#endif /* See strip.py */

/**
 * homa_peertab_gc_dsts() - Invoked to free unused dst_entries, if it is
 * safe to do so.
 * @peertab:       The table in which to free entries.
 * @now:           Current time, in sched_clock() units; entries with expiration
 *                 dates no later than this will be freed. Specify ~0 to
 *                 free all entries.
 */
void homa_peertab_gc_dsts(struct homa_peertab *peertab, u64 now)
	__must_hold(&peer_tab->write_lock)
{
	while (!list_empty(&peertab->dead_dsts)) {
		struct homa_dead_dst *dead =
			list_first_entry(&peertab->dead_dsts,
					 struct homa_dead_dst, dst_links);
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
 * @addr:       Address of the desired host: IPv4 addresses are represented
 *              as IPv4-mapped IPv6 addresses.
 * @inet:       Socket that will be used for sending packets.
 *
 * Return:      The peer associated with @addr, or a negative errno if an
 *              error occurred. The caller can retain this pointer
 *              indefinitely: peer entries are never deleted except in
 *              homa_peertab_destroy.
 */
struct homa_peer *homa_peer_find(struct homa_peertab *peertab,
				 const struct in6_addr *addr,
				 struct inet_sock *inet)
{
	struct homa_peer *peer;
	struct dst_entry *dst;

	// Should use siphash or jhash here:
	u32 bucket = hash_32((__force u32)addr->in6_u.u6_addr32[0],
			       HOMA_PEERTAB_BUCKET_BITS);

	bucket ^= hash_32((__force u32)addr->in6_u.u6_addr32[1],
			  HOMA_PEERTAB_BUCKET_BITS);
	bucket ^= hash_32((__force u32)addr->in6_u.u6_addr32[2],
			  HOMA_PEERTAB_BUCKET_BITS);
	bucket ^= hash_32((__force u32)addr->in6_u.u6_addr32[3],
			  HOMA_PEERTAB_BUCKET_BITS);

	/* Use RCU operators to ensure safety even if a concurrent call is
	 * adding a new entry. The calls to rcu_read_lock and rcu_read_unlock
	 * shouldn't actually be needed, since we don't need to protect
	 * against concurrent deletion.
	 */
	rcu_read_lock();
	hlist_for_each_entry_rcu(peer, &peertab->buckets[bucket],
				 peertab_links) {
		if (ipv6_addr_equal(&peer->addr, addr)) {
			rcu_read_unlock();
			return peer;
		}
		INC_METRIC(peer_hash_links, 1);
	}
	rcu_read_unlock();

	/* No existing entry; create a new one.
	 *
	 * Note: after we acquire the lock, we have to check again to
	 * make sure the entry still doesn't exist (it might have been
	 * created by a concurrent invocation of this function).
	 */
	spin_lock_bh(&peertab->write_lock);
	hlist_for_each_entry(peer, &peertab->buckets[bucket],
			     peertab_links) {
		if (ipv6_addr_equal(&peer->addr, addr))
			goto done;
	}
	peer = kmalloc(sizeof(*peer), GFP_ATOMIC | __GFP_ZERO);
	if (!peer) {
		peer = (struct homa_peer *)ERR_PTR(-ENOMEM);
		INC_METRIC(peer_kmalloc_errors, 1);
		goto done;
	}
	peer->addr = *addr;
	dst = homa_peer_get_dst(peer, inet);
	if (IS_ERR(dst)) {
		kfree(peer);
		peer = (struct homa_peer *)PTR_ERR(dst);
		INC_METRIC(peer_route_errors, 1);
		goto done;
	}
	peer->dst = dst;
#ifndef __STRIP__ /* See strip.py */
	peer->unsched_cutoffs[HOMA_MAX_PRIORITIES - 1] = 0;
	peer->unsched_cutoffs[HOMA_MAX_PRIORITIES - 2] = INT_MAX;
	INIT_LIST_HEAD(&peer->grantable_rpcs);
	INIT_LIST_HEAD(&peer->grantable_links);
#endif /* See strip.py */
	smp_wmb();
	hlist_add_head_rcu(&peer->peertab_links, &peertab->buckets[bucket]);
	peer->current_ticks = -1;
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
	struct homa_dead_dst *save_dead;
	struct dst_entry *dst;
	u64 now;

	/* Need to keep around the current entry for a while in case
	 * someone is using it. If we can't do that, then don't update
	 * the entry.
	 */
	save_dead = kmalloc(sizeof(*save_dead), GFP_ATOMIC);
	if (unlikely(!save_dead))
		return;

	dst = homa_peer_get_dst(peer, &hsk->inet);
	if (IS_ERR(dst)) {
#ifndef __STRIP__ /* See strip.py */
		/* Retain the existing dst if we can't create a new one. */
		if (hsk->homa->verbose)
			pr_notice("%s couldn't recreate dst: error %ld",
				  __func__, PTR_ERR(dst));
		INC_METRIC(peer_route_errors, 1);
#endif /* See strip.py */
		kfree(save_dead);
		return;
	}

	spin_lock_bh(&peertab->write_lock);
	now = sched_clock();
	save_dead->dst = peer->dst;
	save_dead->gc_time = now + 100000000;   /* 100 ms */
	list_add_tail(&save_dead->dst_links, &peertab->dead_dsts);
	homa_peertab_gc_dsts(peertab, now);
	peer->dst = dst;
	spin_unlock_bh(&peertab->write_lock);
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_unsched_priority() - Returns the priority level to use for
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

	for (i = homa->num_priorities - 1; ; i--) {
		if (peer->unsched_cutoffs[i] >= length)
			return i;
	}
	/* Can't ever get here */
}
#endif /* See strip.py */

/**
 * homa_peer_get_dst() - Find an appropriate dst structure (either IPv4
 * or IPv6) for a peer.
 * @peer:   The peer for which a dst is needed. Note: this peer's flow
 *          struct will be overwritten.
 * @inet:   Socket that will be used for sending packets.
 * Return:  The dst structure (or an ERR_PTR).
 */
struct dst_entry *homa_peer_get_dst(struct homa_peer *peer,
				    struct inet_sock *inet)
{
	memset(&peer->flow, 0, sizeof(peer->flow));
	if (inet->sk.sk_family == AF_INET) {
		struct rtable *rt;

		flowi4_init_output(&peer->flow.u.ip4, inet->sk.sk_bound_dev_if,
				   inet->sk.sk_mark, inet->tos,
				   RT_SCOPE_UNIVERSE, inet->sk.sk_protocol, 0,
				   peer->addr.in6_u.u6_addr32[3],
				   inet->inet_saddr, 0, 0, inet->sk.sk_uid);
		security_sk_classify_flow(&inet->sk, &peer->flow.u.__fl_common);
		rt = ip_route_output_flow(sock_net(&inet->sk),
					  &peer->flow.u.ip4, &inet->sk);
		if (IS_ERR(rt))
			return (struct dst_entry *)(PTR_ERR(rt));
		return &rt->dst;
	}
	peer->flow.u.ip6.flowi6_oif = inet->sk.sk_bound_dev_if;
	peer->flow.u.ip6.flowi6_iif = LOOPBACK_IFINDEX;
	peer->flow.u.ip6.flowi6_mark = inet->sk.sk_mark;
	peer->flow.u.ip6.flowi6_scope = RT_SCOPE_UNIVERSE;
	peer->flow.u.ip6.flowi6_proto = inet->sk.sk_protocol;
	peer->flow.u.ip6.flowi6_flags = 0;
	peer->flow.u.ip6.flowi6_secid = 0;
	peer->flow.u.ip6.flowi6_tun_key.tun_id = 0;
	peer->flow.u.ip6.flowi6_uid = inet->sk.sk_uid;
	peer->flow.u.ip6.daddr = peer->addr;
	peer->flow.u.ip6.saddr = inet->pinet6->saddr;
	peer->flow.u.ip6.fl6_dport = 0;
	peer->flow.u.ip6.fl6_sport = 0;
	peer->flow.u.ip6.mp_hash = 0;
	peer->flow.u.ip6.__fl_common.flowic_tos = inet->tos;
	peer->flow.u.ip6.flowlabel = ip6_make_flowinfo(inet->tos, 0);
	security_sk_classify_flow(&inet->sk, &peer->flow.u.__fl_common);
	return ip6_dst_lookup_flow(sock_net(&inet->sk), &inet->sk,
			&peer->flow.u.ip6, NULL);
}

#ifndef __STRIP__ /* See strip.py */
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
 * acquiring a peer's @ack_lock. It is invoked when the lock isn't
 * immediately available. It waits for the lock, but also records statistics
 * about the waiting time.
 * @peer:    Peer to  lock.
 */
void homa_peer_lock_slow(struct homa_peer *peer)
	__acquires(&peer->ack_lock)
{
	u64 start = sched_clock();

	tt_record("beginning wait for peer lock");
	spin_lock_bh(&peer->ack_lock);
	tt_record("ending wait for peer lock");
	INC_METRIC(peer_ack_lock_misses, 1);
	INC_METRIC(peer_ack_lock_miss_ns, sched_clock() - start);
}
#endif /* See strip.py */

/**
 * homa_peer_add_ack() - Add a given RPC to the list of unacked
 * RPCs for its server. Once this method has been invoked, it's safe
 * to delete the RPC, since it will eventually be acked to the server.
 * @rpc:    Client RPC that has now completed.
 */
void homa_peer_add_ack(struct homa_rpc *rpc)
{
	struct homa_peer *peer = rpc->peer;
	struct homa_ack_hdr ack;

	homa_peer_lock(peer);
	if (peer->num_acks < HOMA_MAX_ACKS_PER_PKT) {
		peer->acks[peer->num_acks].client_id = cpu_to_be64(rpc->id);
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
