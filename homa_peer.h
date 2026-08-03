/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */

/* This file contains definitions related to managing peers and routes
 * (homa_peer, homa_route, homa_peertab).
 */

#ifndef _HOMA_PEER_H
#define _HOMA_PEER_H

#include "homa_hijack.h"
#include "homa_wire.h"
#include "homa_sock.h"

#include <linux/rhashtable.h>

struct homa_rpc;

/**
 * struct homa_peertab - Stores homa_peer and homa_route objects. There is
 * one of these per struct homa.
 */
struct homa_peertab {
	/**
	 * @lock: Used to synchronize updates to @peer_ht, @route_ht, as well
	 * as other operations on this object.
	 */
	spinlock_t lock;

	/** @ht: Hash table that stores struct peers. */
	struct rhashtable peer_ht;

	/**
	 * @route_ht:  Hash table that stores homa_peer_flow objects.
	 * There can be multiple entries in this table for each peer.
	 */
	struct rhashtable route_ht;

	/**
	 * @ht_iter: Used to scan route_ht to find routes to garbage
	 * collect.
	 */
	struct rhashtable_iter route_ht_iter;

	/** @num_routes: Total number of objects currently in @route_ht. */
	int num_routes;

	/**
	 * @route_ht_valid: True means route_ht has been initialized and must
	 * eventually be destroyed (it also means peer_ht has been initialized).
	 */
	bool route_ht_valid;

	/**
	 * @gc_stop_count: Nonzero means that route garbage collection
	 * should not be performed (conflicting state changes are underway).
	 */
	int gc_stop_count;

	/**
	 * @gc_threshold: If @num_routes is less than this, don't bother
	 * doing any peer garbage collection. Set externally via sysctl.
	 */
	int gc_threshold;

	/**
	 * @net_max: If the number of peers for a homa_net exceeds this number,
	 * work aggressively to reclaim peers for that homa_net. Set
	 * externally via sysctl.
	 */
	int net_max;

	/**
	 * @idle_secs_min: A peer will not be considered for garbage collection
	 * under any circumstances if it has been idle less than this many
	 * seconds. Set externally via sysctl.
	 */
	int idle_secs_min;

	/**
	 * @idle_jiffies_min: Same as idle_secs_min except in units
	 * of jiffies.
	 */
	int idle_jiffies_min;

	/**
	 * @idle_secs_max: A peer that has been idle for less than
	 * this many seconds will not be considered for garbage collection
	 * unless its homa_net has more than @net_threshold peers. Set
	 * externally via sysctl.
	 */
	int idle_secs_max;

	/**
	 * @idle_jiffies_max: Same as idle_secs_max except in units
	 * of jiffies.
	 */
	int idle_jiffies_max;

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @sysctl_header: Used to remove sysctl values when this structure
	 * is destroyed.
	 */
	struct ctl_table_header *sysctl_header;
#endif /* See strip.py */

	/** @rcu_head: Holds state of a pending call_rcu invocation. */
	struct rcu_head rcu_head;
};

/**
 * struct homa_peer_key - Used to look up homa_peer structs in homa_peertab->peer_ht.
 */
struct homa_peer_key {
	/**
	 * @addr: Address of the desired host. IPv4 addresses are represented
	 * with IPv4-mapped IPv6 addresses. Must be the first variable in
	 * the struct, because of union in homa_peer.
	 */
	struct in6_addr addr;

	/** @hnet: The network namespace in which this peer is valid. */
	struct homa_net *hnet;
};

/**
 * struct homa_peer - One of these objects exists for each machine that we
 * have communicated with (either as client or server). This struct contains
 * information that is common to all uses of the peer.
 */
struct homa_peer {
	union {
		/**
		 * @addr: IPv6 address for the machine (IPv4 addresses are
		 * stored as IPv4-mapped IPv6 addresses).
		 */
		struct in6_addr addr;

		/** @ht_key: The hash table key for this peer in peertab->peer_ht. */
		struct homa_peer_key ht_key;
	};

	/**
	 * @refs: Number of outstanding references to this peer. Does *not*
	 * include a reference for the entry in peertab->peer_ht. The peer
	 * can be freed when this value becomes zero.
	 */
	refcount_t refs;

	/**
	 * @ht_linkage: Used by rashtable implement to link this peer into
	 * peertab->peer_ht.
	 */
	struct rhash_head ht_linkage;

	/**
	 * @lock: used to synchronize access to fields in this struct, such
	 * as @num_acks, @acks, @dst, and @dst_cookie.
	 */
	spinlock_t lock ____cacheline_aligned_in_smp;

	/**
	 * @num_acks: the number of (initial) entries in @acks that
	 * currently hold valid information.
	 */
	int num_acks;

	/**
	 * @acks: info about client RPCs whose results have been completely
	 * received.
	 */
	struct homa_ack acks[HOMA_MAX_ACKS_PER_PKT];

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @unsched_cutoffs: priorities to use for unscheduled packets
	 * sent to this host, as specified in the most recent CUTOFFS
	 * packet from that host. See documentation for @homa.unsched_cutoffs
	 * for the meanings of these values.
	 */
	int unsched_cutoffs[HOMA_MAX_PRIORITIES];

	/**
	 * @cutoff_version: value of cutoff_version in the most recent
	 * CUTOFFS packet received from this peer.  0 means we haven't
	 * yet received a CUTOFFS packet from the host. Note that this is
	 * stored in network byte order.
	 */
	__be16 cutoff_version;

	/**
	 * @last_update_jiffies: time in jiffies when we sent the most
	 * recent CUTOFFS packet to this peer.
	 */
	unsigned long last_update_jiffies;

	/**
	 * @active_rpcs: Number of RPCs involving this peer whose incoming
	 * messages are currently in homa->grant->active_rpcs. Managed by
	 * homa_grant.c under the grant lock.
	 */
	int active_rpcs;

	/**
	 * @grantable_rpcs: Contains homa_rpcs (both requests and responses)
	 * involving this peer that are not in homa->active_rpcs but
	 * whose msgins eventually need more grants. The list is sorted in
	 * priority order (head has fewest ungranted bytes). Managed by
	 * homa_grant.c under the grant lock. If this list is nonempty
	 * then refs will be nonzero.
	 */
	struct list_head grantable_rpcs;

	/**
	 * @grantable_links: Used to link this peer into homa->grantable_peers.
	 * If this RPC is not linked into homa->grantable_peers, this is an
	 * empty list pointing to itself. Managed by homa_grant.c under the
	 * grant lock. If this list is nonempty then refs will be nonzero.
	 */
	struct list_head grantable_links;
#endif /* See strip.py */

	/**
	 * @outstanding_resends: the number of resend requests we have
	 * sent to this server (spaced @homa.resend_interval apart) since
	 * we received a packet from this peer.
	 */
	int outstanding_resends;

	/**
	 * @most_recent_resend: @homa->timer_ticks when the most recent
	 * resend was sent to this peer.
	 */
	int most_recent_resend;

	/**
	 * @least_recent_rpc: of all the RPCs for this peer scanned at
	 * @current_ticks, this is the RPC whose @resend_timer_ticks
	 * is farthest in the past.
	 */
	struct homa_rpc *least_recent_rpc;

	/**
	 * @least_recent_ticks: the @resend_timer_ticks value for
	 * @least_recent_rpc.
	 */
	u32 least_recent_ticks;

	/**
	 * @current_ticks: the value of @homa->timer_ticks the last time
	 * that @least_recent_rpc and @least_recent_ticks were computed.
	 * Used to detect the start of a new homa_timer pass.
	 */
	u32 current_ticks;

	/**
	 * @resend_rpc: the value of @least_recent_rpc computed in the
	 * previous homa_timer pass. This RPC will be issued a RESEND
	 * in the current pass, if it still needs one.
	 */
	struct homa_rpc *resend_rpc;
};

/**
 * struct homa_route_key - Used to look up homa_route structs in
 * homa_peertab_route_ht. These fields represent all of the information
 * tha could impact the choice of a particular struct dst_entry.
 */
struct homa_route_key {
	/**
	 * @saddr: Source network address. IPv4 addresses are represented
	 * with IPv4-mapped IPv6 addresses.
	 */
	struct in6_addr saddr;
	/**
	 * @dst: Destination network address. IPv4 addresses are represented
	 * with IPv4-mapped IPv6 addresses.
	 */
	struct in6_addr daddr;

	/**
	 * @hnet: The network namespace in which this route is valid. This
	 * needs to be a homa_hnet pointer, not just struct net, in order
	 * to access homa_hnet->num_routes.
	 */
	struct homa_net *hnet;

	/**
	 * @sk_policy_out: sk->sk_policy[XFRM_POLICY_OUT]: uniquely
	 * determines IPsec policy, if any.
	 */
	struct xfrm_policy *sk_policy_out;

	/** @uid: sock->sk_sk_uid */
	kuid_t uid;

	/** @mark: sock->sk_mark */
	u32 mark;

	/** @secid flowic.secid produced by security_sk_classify_flow. */
	u32 secid;

	/** @bound_dev_if: sock->sk_bound_dev_if */
	int bound_dev_if;
};

/**
 * struct homa_route - Holds a dst_entry for communicating with a
 * particular peer, as well as information needed to cache the dst_entry
 * and share it for multiple RPCs. There can be more than one of these
 * objects per peer, which have different homa_route_keys.
 */
struct homa_route {
	/**
	 * @lock: used to synchronize uypdates to this struct.
	 */
	spinlock_t lock;

	/**
	 * @refs: Number of outstanding references to this object. Includes
	 * one reference for the entry in peertab->route_ht, plus one for each
	 * call to homa_route_get that has not been canceled by a call to
	 * homa_peer_route_release; the object will be freed (via RCU) when
	 * this count becomes zero.
	 */
	refcount_t refs;

	/**
	 * @access_jiffies: Time in jiffies of most recent access to this
	 * object; used for garbage collection.
	 */
	unsigned long access_jiffies;

	/** @key: Identifies this entry in peertab->route_ht. */
	struct homa_route_key key;

	/**
	 * @peer: Peer with which this route is associated. This object holds a
	 * reference on the peer.
	 */
	struct homa_peer *peer;

	/**
	 * @dst: Used to route packets to this peer; this object owns a
	 * reference that must eventually be released.
	 */
	struct dst_entry __rcu *dst;

	/**
	 * @dst_cookie: Used to check whether dst is still valid. This is
	 * accessed without synchronization, which is racy, but the worst
	 * that can happen is using an obsolete dst.
	 */
	u32 dst_cookie;

	/**
	 * @flow: Contains parameters used to generate @dst; must be
	 * retained and passed to ip*xmit.
	 */
	struct flowi flow;

	/**
	 * @ht_linkage: Used by rashtable to link this object into
	 * peertab->route_ht.
	 */
	struct rhash_head ht_linkage;

	/** @rcu_head: Holds state of a pending call_rcu invocation. */
	struct rcu_head rcu_head;
};

void     homa_dst_refresh(struct homa_peertab *peertab,
			  struct homa_peer *peer, struct homa_sock *hsk);
void     homa_peer_add_ack(struct homa_rpc *rpc);
struct homa_peer
	*homa_peer_alloc(struct homa_sock *hsk, const struct in6_addr *addr);
struct homa_peertab
	*homa_peer_alloc_peertab(void);
int      homa_peer_dointvec(const struct ctl_table *table, int write,
			    void *buffer, size_t *lenp, loff_t *ppos);
void     homa_peer_free(struct homa_peer *peer);
void     homa_peer_free_net(struct homa_net *hnet);
void     homa_peer_free_peertab(struct homa_peertab *peertab);
struct homa_peer
	*homa_peer_get(struct homa_sock *hsk, const struct in6_addr *addr);
int      homa_peer_get_acks(struct homa_peer *peer, int count,
			    struct homa_ack *dst);
void     homa_peer_lock_slow(struct homa_peer *peer);
void     homa_peer_release_fn(void *object, void *dummy);
void     homa_peer_update_sysctl_deps(struct homa_peertab *peertab);
void     homa_peer_set_cutoffs(struct homa_peer *peer, int c0, int c1,
			       int c2, int c3, int c4, int c5, int c6, int c7);
struct homa_route
        *homa_route_alloc(struct homa_sock *hsk,
			  const struct homa_route_key *key);
void     homa_route_delete_fn(void *object, void *dummy);
void     homa_route_free(struct rcu_head *head);
void     homa_route_gc(struct homa_peertab *peertab);
struct homa_route
        *homa_route_get(struct homa_sock *hsk,
				    const struct in6_addr *addr);
u32      homa_route_hash(const void *data, u32 len, u32 seed);
int      homa_route_pick_victims(struct homa_peertab *peertab,
				 struct homa_route *victims[], int max_victims);
int      homa_route_prefer_evict(struct homa_peertab *peertab,
				 struct homa_route *route1,
				 struct homa_route *route2);
int      homa_route_validate(struct homa_rpc *rpc);

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_peer_lock() - Acquire the lock for a peer. If the lock isn't
 * immediately available, record stats on the waiting time.
 * @peer:    Peer to lock.
 */
static inline void homa_peer_lock(struct homa_peer *peer)
	__acquires(peer->lock)
{
	if (!spin_trylock_bh(&peer->lock))
		homa_peer_lock_slow(peer);
}
#else /* See strip.py */
/**
 * homa_peer_lock() - Acquire the lock for a peer.
 * @peer:    Peer to lock.
 */
static inline void homa_peer_lock(struct homa_peer *peer)
	__acquires(peer->lock)
{
	spin_lock_bh(&peer->lock);
}
#endif /* See strip.py */

/**
 * homa_peer_unlock() - Release the lock for a peer.
 * @peer:   Peer to lock.
 */
static inline void homa_peer_unlock(struct homa_peer *peer)
	__releases(peer->lock)
{
	spin_unlock_bh(&peer->lock);
}

/**
 * homa_route_hold() - Increment the reference count on a route.
 * Caller must eventually invoke homa_route_release to decrement the
 * reference count again.
 * @route:   Route whose reference count should be incremented. Caller must
 *           already hold a reference to this.
 */
static inline void homa_route_hold(struct homa_route *route)
{
	refcount_inc(&route->refs);
}

/**
 * homa_route_release() - Release a reference on a route (cancels the effect of
 * a previous call to homa_route_hold). If the reference count becomes zero
 * then the route may be deleted at any time.
 * @peer:      Object to release.
 */
static inline void homa_route_release(struct homa_route *route)
{
	if (refcount_dec_and_test(&route->refs))
		call_rcu(&route->rcu_head, homa_route_free);
}

/**
 * homa_peer_compare() - Comparison function for entries in @peertab->peer_ht.
 * @arg:   Contains one of the keys to compare.
 * @obj:   homa_peer object containing the other key to compare.
 * Return: 0 means the keys match, 1 means mismatch.
 */
static inline int homa_peer_compare(struct rhashtable_compare_arg *arg,
				    const void *obj)
{
	const struct homa_peer_key *key = arg->key;
	const struct homa_peer *peer = obj;

	return !(ipv6_addr_equal(&key->addr, &peer->ht_key.addr) &&
		 peer->ht_key.hnet == key->hnet);
}

/**
 * homa_route_xmit() - Transmit a packet according to a given route.
 * @skb:      Packet to transmit.
 * @hsk:      Socket on which to transmit packet.
 * @route:    Route to use to transmit packet.
 * @priority: Priority for packet.
 * Return:    0 for success, otherwise a negative errno.
 */
static inline int homa_route_xmit(struct sk_buff *skb, struct homa_sock *hsk,
				  struct homa_route *route, int priority)
{
	dst_hold(route->dst);
	skb_dst_set(skb, route->dst);
	if (ipv6_addr_v4mapped(&route->peer->addr)) {
		homa_hijack_set_hdr(skb, route, false);
		hsk->inet.tos = hsk->homa->priority_map[priority] << 5;
		return ip_queue_xmit(&hsk->inet.sk, skb, &route->flow);
	} else {
		homa_hijack_set_hdr(skb, route, true);
		return ip6_xmit(&hsk->inet.sk, skb, &route->flow.u.ip6, 0,
			        NULL, hsk->homa->priority_map[priority] << 5,
				0);
	}
}

/**
 * homa_peer_unlink() - Remove the connection between a route and its peer,
 * potentially freeing the peer in the process.
 * @route:    Route to disconnect.
 */
static inline void homa_peer_unlink(struct homa_route *route)
	__must_hold(route->hnet->homa->peertab->lock)
{
	struct homa_peertab *peertab;
	extern const struct rhashtable_params peer_ht_params;

	if (!route->peer)
		return;

	/* Note: we don't need to use RCU for freeing peers because we have
	 * already used RCU for freeing routes, so we know there are no
	 * outstanding uses. By holding the peertab lock we have locked
	 * out calls to homa_peer_get.
	 */
	peertab = route->key.hnet->homa->peertab;
	if (refcount_dec_and_test(&route->peer->refs)) {
		rhashtable_remove_fast(&peertab->peer_ht,
				       &route->peer->ht_linkage,
				       peer_ht_params);
		homa_peer_free(route->peer);
	}
	route->peer = NULL;
}

/**
 * homa_route_key_init() - Initialize the fields of a key for
 * peertab->route_ht. Note: caller must hold an RCU read lock.
 * @key:      Key to initialize
 * @hsk:      Socket from which to pull fields for the key other than
 *            daddr.
 * @daddr:    Destination address for the key.
 */
static inline void homa_route_key_init(struct homa_route_key *key,
				       const struct homa_sock *hsk,
				       const struct in6_addr *daddr)
{
	struct flowi_common flowic;

	memset(key, 0, sizeof(*key));
	if (hsk->sock.sk_family == AF_INET)
		ipv6_addr_set_v4mapped(hsk->inet.inet_saddr, &key->saddr);
	else
		key->saddr = hsk->inet.pinet6->saddr;
	key->daddr = *daddr;
	key->hnet = hsk->hnet;
	key->sk_policy_out = rcu_dereference(hsk->sock.sk_policy[XFRM_POLICY_OUT]);
	key->uid = hsk->sock.sk_uid;
	key->mark = hsk->sock.sk_mark;
	flowic.flowic_secid = 0;
	security_sk_classify_flow(&hsk->sock, &flowic);
	key->secid = flowic.flowic_secid;
	key->bound_dev_if = hsk->sock.sk_bound_dev_if;

}

#endif /* _HOMA_PEER_H */
