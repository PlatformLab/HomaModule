// SPDX-License-Identifier: BSD-2-Clause

/* This file provides functions related to homa_peer and homa_peertab
 * objects.
 */

#include "homa_impl.h"
#include "homa_peer.h"
#include "homa_rpc.h"

#ifdef __UNIT_TEST__
#undef rhashtable_init
#define rhashtable_init mock_rht_init

#undef rhashtable_lookup_get_insert_fast
#define rhashtable_lookup_get_insert_fast mock_rht_lookup_get_insert_fast
#endif /* __UNIT_TEST__ */

const struct rhashtable_params ht_params = {
	.key_len     = sizeof(struct homa_peer_key),
	.key_offset  = offsetof(struct homa_peer, ht_key),
	.head_offset = offsetof(struct homa_peer, ht_linkage),
	.nelem_hint = 10000,
	.hashfn = homa_peer_hash,
	.obj_cmpfn = homa_peer_compare
};

/**
 * homa_peertab_alloc() - Allocate and initialize a homa_peertab.
 *
 * Return:    A pointer to the new homa_peertab, or ERR_PTR(-errno) if there
 *            was a problem.
 */
struct homa_peertab *homa_peertab_alloc(void)
{
	struct homa_peertab *peertab;
	int err;

	peertab = kmalloc(sizeof(*peertab), GFP_KERNEL);
	if (!peertab) {
		pr_err("%s couldn't create peers: kmalloc failure", __func__);
		return ERR_PTR(-ENOMEM);
	}

	err = rhashtable_init(&peertab->ht, &ht_params);
	if (err) {
		kfree(peertab);
		return ERR_PTR(err);
	}
	return peertab;
}

/**
 * homa_peertab_free_homa() - Garbage collect all of the peer information
 * associated with a particular struct homa.
 * @homa:    Object whose peers should be freed.
 */
void homa_peertab_free_net(struct homa_net *hnet)
{
	struct homa_peertab *peertab = hnet->homa->peers;
	struct rhashtable_iter iter;
	struct homa_peer *peer;

	rhashtable_walk_enter(&peertab->ht, &iter);
	rhashtable_walk_start(&iter);
	while (1) {
		peer = rhashtable_walk_next(&iter);
		if (!peer)
			break;
		if (IS_ERR(peer))
			continue;
		if (peer->ht_key.hnet != hnet)
			continue;
		rhashtable_remove_fast(&peertab->ht, &peer->ht_linkage,
				       ht_params);
		homa_peer_free(peer);
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
}

/**
 * homa_peertab_free_fn() - This function is invoked for each entry in
 * the peer hash table by the rhashtable code when the table is being
 * deleted. It frees its argument.
 * @object:     struct homa_peer to free.
 * @dummy:      Not used.
 */
void homa_peertab_free_fn(void *object, void *dummy)
{
	struct homa_peer *peer = object;

	homa_peer_free(peer);
}

/**
 * homa_peertab_free() - Destructor for homa_peertabs. After this
 * function returns, it is unsafe to use any results from previous calls
 * to homa_peer_find, since all existing homa_peer objects will have been
 * destroyed.
 * @peertab:  The table to destroy.
 */
void homa_peertab_free(struct homa_peertab *peertab)
{
	spin_lock_init(&peertab->lock);
	rhashtable_free_and_destroy(&peertab->ht, homa_peertab_free_fn,
				    NULL);
	kfree(peertab);
}

/**
 * homa_peer_alloc() - Allocate and initialize a new homa_peer object.
 * @hsk:        Socket for which the peer will be used.
 * @addr:       Address of the desired host: IPv4 addresses are represented
 *              as IPv4-mapped IPv6 addresses.
 * Return:      The peer associated with @addr, or a negative errno if an
 *              error occurred. On a successful return the reference count
 *              will be incremented for the returned peer.
 */
struct homa_peer *homa_peer_alloc(struct homa_sock *hsk,
				  const struct in6_addr *addr)
{
	struct homa_peer *peer;
	struct dst_entry *dst;

	peer = kmalloc(sizeof(*peer), GFP_ATOMIC | __GFP_ZERO);
	if (!peer) {
		INC_METRIC(peer_kmalloc_errors, 1);
		return (struct homa_peer *)ERR_PTR(-ENOMEM);
	}
	peer->ht_key.addr = *addr;
	peer->ht_key.hnet = hsk->hnet;
	atomic_set(&peer->refs, 1);
	peer->addr = *addr;
	dst = homa_peer_get_dst(peer, hsk);
	if (IS_ERR(dst)) {
		INC_METRIC(peer_route_errors, 1);
		kfree(peer);
		return (struct homa_peer *)dst;
	}
	peer->dst = dst;
#ifndef __STRIP__ /* See strip.py */
	peer->unsched_cutoffs[HOMA_MAX_PRIORITIES - 1] = 0;
	peer->unsched_cutoffs[HOMA_MAX_PRIORITIES - 2] = INT_MAX;
	INIT_LIST_HEAD(&peer->grantable_rpcs);
	INIT_LIST_HEAD(&peer->grantable_links);
#endif /* See strip.py */
	peer->current_ticks = -1;
	spin_lock_init(&peer->ack_lock);
	INC_METRIC(peer_new_entries, 1);
	return peer;
}

/**
 * homa_peer_free() - Release any resources in a peer and free the homa_peer
 * struct.
 * @peer:       Structure to free. Must not currently be linked into
 *              peertab->ht.
 */
void homa_peer_free(struct homa_peer *peer)
{
	dst_release(peer->dst);

	if (atomic_read(&peer->refs) == 0)
		kfree(peer);
	else {
#ifdef __UNIT_TEST__
		if (!mock_peer_free_no_fail)
			FAIL(" %s found peer %s with reference count %d",
				__func__, homa_print_ipv6_addr(&peer->addr),
				atomic_read(&peer->refs));
		else
			UNIT_LOG("; ", "peer %s has reference count %d",
				 homa_print_ipv6_addr(&peer->addr),
				 atomic_read(&peer->refs));
#else /* __UNIT_TEST__ */
		WARN(1, "%s found peer with reference count %d",
		     __func__, atomic_read(&peer->refs));
#endif /* __UNIT_TEST__ */
	}
}

/**
 * homa_peer_find() - Returns the peer associated with a given host; creates
 * a new homa_peer if one doesn't already exist.
 * @hsk:        Socket where the peer will be used.
 * @addr:       Address of the desired host: IPv4 addresses are represented
 *              as IPv4-mapped IPv6 addresses.
 *
 * Return:      The peer associated with @addr, or a negative errno if an
 *              error occurred. On a successful return the reference count
 *              will be incremented for the returned peer. The caller must
 *              eventually call homa_peer_put to release the reference.
 */
struct homa_peer *homa_peer_find(struct homa_sock *hsk,
				 const struct in6_addr *addr)
{
	struct homa_peertab *peertab = hsk->homa->peers;
	struct homa_peer *peer, *other;
	struct homa_peer_key key;

	key.addr = *addr;
	key.hnet = hsk->hnet;
	rcu_read_lock();
	peer = rhashtable_lookup(&peertab->ht, &key, ht_params);
	if (peer) {
		homa_peer_hold(peer);
		rcu_read_unlock();
		return peer;
	}

	/* No existing entry, so we have to create a new one. */
	peer = homa_peer_alloc(hsk, addr);
	if (IS_ERR(peer)) {
		rcu_read_unlock();
		return peer;
	}
	spin_lock_bh(&peertab->lock);
	other = rhashtable_lookup_get_insert_fast(&peertab->ht,
						  &peer->ht_linkage, ht_params);
	spin_unlock_bh(&peertab->lock);
	if (IS_ERR(other)) {
		/* Couldn't insert; return the error info. */
		homa_peer_put(peer);
		homa_peer_free(peer);
		peer = other;
	} else if (other) {
		/* Someone else already created the desired peer; use that
		 * one instead of ours.
		 */
		homa_peer_put(peer);
		homa_peer_free(peer);
		homa_peer_hold(other);
		peer = other;
	}
	rcu_read_unlock();
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
	struct dst_entry *dst;

	dst = homa_peer_get_dst(peer, hsk);
	if (IS_ERR(dst)) {
#ifndef __STRIP__ /* See strip.py */
		/* Retain the existing dst if we can't create a new one. */
		if (hsk->homa->verbose)
			pr_notice("%s couldn't recreate dst: error %ld",
				  __func__, PTR_ERR(dst));
		INC_METRIC(peer_route_errors, 1);
#endif /* See strip.py */
		return;
	}
	dst_release(peer->dst);
	peer->dst = dst;
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
 * @hsk:    Socket that will be used for sending packets.
 * Return:  The dst structure (or an ERR_PTR); a reference has been taken.
 */
struct dst_entry *homa_peer_get_dst(struct homa_peer *peer,
				    struct homa_sock *hsk)
{
	memset(&peer->flow, 0, sizeof(peer->flow));
	if (hsk->sock.sk_family == AF_INET) {
		struct rtable *rt;

		flowi4_init_output(&peer->flow.u.ip4, hsk->sock.sk_bound_dev_if,
				   hsk->sock.sk_mark, hsk->inet.tos,
				   RT_SCOPE_UNIVERSE, hsk->sock.sk_protocol, 0,
				   peer->addr.in6_u.u6_addr32[3],
				   hsk->inet.inet_saddr, 0, 0,
				   hsk->sock.sk_uid);
		security_sk_classify_flow(&hsk->sock,
					  &peer->flow.u.__fl_common);
		rt = ip_route_output_flow(sock_net(&hsk->sock),
					  &peer->flow.u.ip4, &hsk->sock);
		if (IS_ERR(rt))
			return (struct dst_entry *)(PTR_ERR(rt));
		return &rt->dst;
	}
	peer->flow.u.ip6.flowi6_oif = hsk->sock.sk_bound_dev_if;
	peer->flow.u.ip6.flowi6_iif = LOOPBACK_IFINDEX;
	peer->flow.u.ip6.flowi6_mark = hsk->sock.sk_mark;
	peer->flow.u.ip6.flowi6_scope = RT_SCOPE_UNIVERSE;
	peer->flow.u.ip6.flowi6_proto = hsk->sock.sk_protocol;
	peer->flow.u.ip6.flowi6_flags = 0;
	peer->flow.u.ip6.flowi6_secid = 0;
	peer->flow.u.ip6.flowi6_tun_key.tun_id = 0;
	peer->flow.u.ip6.flowi6_uid = hsk->sock.sk_uid;
	peer->flow.u.ip6.daddr = peer->addr;
	peer->flow.u.ip6.saddr = hsk->inet.pinet6->saddr;
	peer->flow.u.ip6.fl6_dport = 0;
	peer->flow.u.ip6.fl6_sport = 0;
	peer->flow.u.ip6.mp_hash = 0;
	peer->flow.u.ip6.__fl_common.flowic_tos = hsk->inet.tos;
	peer->flow.u.ip6.flowlabel = ip6_make_flowinfo(hsk->inet.tos, 0);
	security_sk_classify_flow(&hsk->sock, &peer->flow.u.__fl_common);
	return ip6_dst_lookup_flow(sock_net(&hsk->sock), &hsk->sock,
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
	u64 start = homa_clock();

	tt_record("beginning wait for peer lock");
	spin_lock_bh(&peer->ack_lock);
	tt_record("ending wait for peer lock");
	INC_METRIC(peer_ack_lock_misses, 1);
	INC_METRIC(peer_ack_lock_miss_cycles, homa_clock() - start);
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
