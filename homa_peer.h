/* SPDX-License-Identifier: BSD-2-Clause */

/* This file contains definitions related to managing peers (homa_peer
 * and homa_peertab).
 */

#ifndef _HOMA_PEER_H
#define _HOMA_PEER_H

#include "homa_wire.h"
#include "homa_sock.h"

#include <linux/rhashtable.h>

struct homa_rpc;

/**
 * struct homa_peertab - Stores homa_peer objects, indexed by IPv6
 * address.
 */
struct homa_peertab {
	/**
	 * @lock: Used to synchronize updates to @ht as well as other
	 * operations on this object.
	 */
	spinlock_t lock;

	/** @ht: Hash table that stores all struct peers. */
	struct rhashtable ht;

	/** @ht_iter: Used to scan ht to find peers to garbage collect. */
	struct rhashtable_iter ht_iter;

	/** @num_peers: Total number of peers currently in @ht. */
	int num_peers;

	/**
	 * @ht_valid: True means ht and ht_iter have been initialized and must
	 * eventually be destroyed.
	 */
	bool ht_valid;

	/**
	 * @dead_peers: List of peers that have been removed from ht
	 * but can't yet be freed (because they have nonzero reference
	 * counts or an rcu sync point hasn't been reached).
	 */
	struct list_head dead_peers;

	/** @rcu_head: Holds state of a pending call_rcu invocation. */
	struct rcu_head rcu_head;

	/**
	 * @call_rcu_pending: Nonzero means that call_rcu has been
	 * invoked but it has not invoked the callback function; until the
	 * callback has been invoked we can't free peers on dead_peers or
	 * invoke call_rcu again (which means we can't add more peers to
	 * dead_peers).
	 */
	atomic_t call_rcu_pending;

	/**
	 * @gc_stop_count: Nonzero means that peer garbage collection
	 * should not be performed (conflicting state changes are underway).
	 */
	int gc_stop_count;

	/**
	 * @gc_threshold: If @num_peers is less than this, don't bother
	 * doing any peer garbage collection. Set externally via sysctl.
	 */
	int gc_threshold;

	/**
	 * @net_max: If the number of peers for a homa_net exceeds this number,
	 * work aggressivley to reclaim peers for that homa_net. Set
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
	unsigned long idle_jiffies_min;

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
	unsigned long idle_jiffies_max;

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @sysctl_header: Used to remove sysctl values when this structure
	 * is destroyed.
	 */
	struct ctl_table_header *sysctl_header;
#endif /* See strip.py */
};

/**
 * struct homa_peer_key - Used to look up homa_peer structs in an rhashtable.
 */
struct homa_peer_key {
	/**
	 * @addr: Address of the desired host. IPv4 addresses are represented
	 * with IPv4-mapped IPv6 addresses.
	 */
	struct in6_addr addr;

	/** @hnet: The network namespace in which this peer is valid. */
	struct homa_net *hnet;
};

/**
 * struct homa_peer - One of these objects exists for each machine that we
 * have communicated with (either as client or server).
 */
struct homa_peer {
	/** @ht_key: The hash table key for this peer in peertab->ht. */
	struct homa_peer_key ht_key;

	/**
	 * @ht_linkage: Used by rashtable implement to link this peer into
	 * peertab->ht.
	 */
	struct rhash_head ht_linkage;

	/** @dead_links: Used to link this peer into peertab->dead_peers. */
	struct list_head dead_links;

	/**
	 * @refs: Number of unmatched calls to homa_peer_hold; it's not safe
	 * to free this object until the reference count is zero.
	 */
	atomic_t refs ____cacheline_aligned_in_smp;

	/**
	 * @access_jiffies: Time in jiffies of most recent access to this
	 * peer.
	 */
	unsigned long access_jiffies;

	/**
	 * @addr: IPv6 address for the machine (IPv4 addresses are stored
	 * as IPv4-mapped IPv6 addresses).
	 */
	struct in6_addr addr ____cacheline_aligned_in_smp;

	/** @flow: Addressing info needed to send packets. */
	struct flowi flow;

	/**
	 * @dst: Used to route packets to this peer; we own a reference
	 * to this, which we must eventually release.
	 */
	struct dst_entry *dst;

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

	/**
	 * @ack_lock: used to synchronize access to @num_acks and @acks.
	 */
	spinlock_t ack_lock;
};

void     homa_dst_refresh(struct homa_peertab *peertab,
			  struct homa_peer *peer, struct homa_sock *hsk);
struct homa_peertab
	*homa_peertab_alloc(void);
void     homa_peertab_free(struct homa_peertab *peertab);
void     homa_peertab_free_net(struct homa_net *hnet);
void     homa_peertab_free_fn(void *object, void *dummy);
void     homa_peer_add_ack(struct homa_rpc *rpc);
struct homa_peer
	*homa_peer_alloc(struct homa_sock *hsk, const struct in6_addr *addr);
int      homa_peer_dointvec(const struct ctl_table *table, int write,
			    void *buffer, size_t *lenp, loff_t *ppos);
struct homa_peer
	*homa_peer_find(struct homa_sock *hsk, const struct in6_addr *addr);
void     homa_peer_free(struct homa_peer *peer);
void     homa_peer_free_dead(struct homa_peertab *peertab);
void     homa_peer_gc(struct homa_peertab *peertab);
int      homa_peer_get_acks(struct homa_peer *peer, int count,
			    struct homa_ack *dst);
struct dst_entry
	*homa_peer_get_dst(struct homa_peer *peer, struct homa_sock *hsk);
#ifndef __STRIP__ /* See strip.py */
void     homa_peer_lock_slow(struct homa_peer *peer);
int      homa_peer_pick_victims(struct homa_peertab *peertab,
				struct homa_peer *victims[], int max_victims);
int      homa_peer_prefer_evict(struct homa_peertab *peertab,
				struct homa_peer *peer1,
				struct homa_peer *peer2);
void     homa_peer_rcu_callback(struct rcu_head *head);
void     homa_peer_set_cutoffs(struct homa_peer *peer, int c0, int c1,
			       int c2, int c3, int c4, int c5, int c6, int c7);
void     homa_peer_update_sysctl_deps(struct homa_peertab *peertab);
void     homa_peer_wait_dead(struct homa_peertab *peertab);
#endif /* See strip.py */

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_peer_lock() - Acquire the lock for a peer's @unacked_lock. If the lock
 * isn't immediately available, record stats on the waiting time.
 * @peer:    Peer to lock.
 */
static inline void homa_peer_lock(struct homa_peer *peer)
	__acquires(&peer->ack_lock)
{
	if (!spin_trylock_bh(&peer->ack_lock))
		homa_peer_lock_slow(peer);
}
#else /* See strip.py */
/**
 * homa_peer_lock() - Acquire the lock for a peer's @ack_lock.
 * @peer:    Peer to lock.
 */
static inline void homa_peer_lock(struct homa_peer *peer)
	__acquires(&peer->ack_lock)
{
	spin_lock_bh(&peer->ack_lock);
}
#endif /* See strip.py */

/**
 * homa_peer_unlock() - Release the lock for a peer's @unacked_lock.
 * @peer:   Peer to lock.
 */
static inline void homa_peer_unlock(struct homa_peer *peer)
	__releases(&peer->ack_lock)
{
	spin_unlock_bh(&peer->ack_lock);
}

/**
 * homa_get_dst() - Returns destination information associated with a peer,
 * updating it if the cached information is stale.
 * @peer:   Peer whose destination information is desired.
 * @hsk:    Homa socket; needed by lower-level code to recreate the dst.
 * Return:  Up-to-date destination for peer; a reference has been taken
 *          on this dst_entry, which the caller must eventually release.
 */
static inline struct dst_entry *homa_get_dst(struct homa_peer *peer,
					     struct homa_sock *hsk)
{
	if (unlikely(peer->dst->obsolete > 0))
		homa_dst_refresh(hsk->homa->peertab, peer, hsk);
	dst_hold(peer->dst);
	return peer->dst;
}

/**
 * homa_peer_hold() - Increment the reference count on an RPC, which will
 * prevent it from being freed until homa_peer_put() is called.
 * @peer:      Object on which to take a reference.
 */
static inline void homa_peer_hold(struct homa_peer *peer)
{
	atomic_inc(&peer->refs);
}

/**
 * homa_peer_put() - Release a reference on a peer (cancels the effect of
 * a previous call to homa_peer_hold). If the reference count becomes zero
 * then the peer may be deleted at any time.
 * @peer:      Object to release.
 */
static inline void homa_peer_put(struct homa_peer *peer)
{
	atomic_dec(&peer->refs);
}

/**
 * homa_peer_hash() - Hash function used for @peertab->ht.
 * @data:    Pointer to key for which a hash is desired. Must actually
 *           be a struct homa_peer_key.
 * @dummy:   Not used
 * @seed:    Seed for the hash.
 * Return:   A 32-bit hash value for the given key.
 */
static inline u32 homa_peer_hash(const void *data, u32 dummy, u32 seed)
{
	/* This is MurmurHash3, used instead of the jhash default because it
	 * is faster (25 ns vs. 40 ns as of May 2025).
	 */
	BUILD_BUG_ON(sizeof(struct homa_peer_key) & 0x3);
	const u32 len = sizeof(struct homa_peer_key) >> 2;
	const u32 c1 = 0xcc9e2d51;
	const u32 c2 = 0x1b873593;
	const u32 *key = data;
	u32 h = seed;

	for (size_t i = 0; i < len; i++) {
		u32 k = key[i];

		k *= c1;
		k = (k << 15) | (k >> (32 - 15));
		k *= c2;

		h ^= k;
		h = (h << 13) | (h >> (32 - 13));
		h = h * 5 + 0xe6546b64;
	}

	h ^= len * 4;  // Total number of input bytes

	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}

/**
 * homa_peer_compare() - Comparison function for entries in @peertab->ht.
 * @arg:   Contains one of the keys to compare.
 * @obj:   homa_peer object containing the other key to compare.
 * Return: 0 means the keys match, 1 means mismatch.
 */
static inline int homa_peer_compare(struct rhashtable_compare_arg *arg,
				    const void *obj)
{
	const struct homa_peer *peer = obj;
	const struct homa_peer_key *key = arg->key;

	return !(ipv6_addr_equal(&key->addr, &peer->ht_key.addr) &&
	         peer->ht_key.hnet == key->hnet);
}

#endif /* _HOMA_PEER_H */
