/* SPDX-License-Identifier: BSD-2-Clause */

/* This file contains definitions related to managing peers (homa_peer
 * and homa_peertab).
 */

#ifndef _HOMA_PEER_H
#define _HOMA_PEER_H

#include "homa_wire.h"
#include "homa_sock.h"

struct homa_rpc;

/**
 * struct homa_dead_dst - Used to retain dst_entries that are no longer
 * needed, until it is safe to delete them (I'm not confident that the RCU
 * mechanism will be safe for these: the reference count could get incremented
 * after it's on the RCU list?).
 */
struct homa_dead_dst {
	/** @dst: Entry that is no longer used by a struct homa_peer. */
	struct dst_entry *dst;

	/**
	 * @gc_time: Time (in units of sched_clock()) when it is safe
	 * to free @dst.
	 */
	u64 gc_time;

	/** @dst_links: Used to link together entries in peertab->dead_dsts. */
	struct list_head dst_links;
};

/**
 * define HOMA_PEERTAB_BUCKET_BITS - Number of bits in the bucket index for a
 * homa_peertab.  Should be large enough to hold an entry for every server
 * in a datacenter without long hash chains.
 */
#define HOMA_PEERTAB_BUCKET_BITS 16

/** define HOME_PEERTAB_BUCKETS - Number of buckets in a homa_peertab. */
#define HOMA_PEERTAB_BUCKETS BIT(HOMA_PEERTAB_BUCKET_BITS)

/**
 * struct homa_peertab - A hash table that maps from IPv6 addresses
 * to homa_peer objects. IPv4 entries are encapsulated as IPv6 addresses.
 * Entries are gradually added to this table, but they are never removed
 * except when the entire table is deleted. We can't safely delete because
 * results returned by homa_peer_find may be retained indefinitely.
 *
 * This table is managed exclusively by homa_peertab.c, using RCU to
 * permit efficient lookups.
 */
struct homa_peertab {
	/**
	 * @write_lock: Synchronizes addition of new entries; not needed
	 * for lookups (RCU is used instead).
	 */
	spinlock_t write_lock;

	/**
	 * @dead_dsts: List of dst_entries that are waiting to be deleted.
	 * Hold @write_lock when manipulating.
	 */
	struct list_head dead_dsts;

	/**
	 * @buckets: Pointer to heads of chains of homa_peers for each bucket.
	 * Malloc-ed, and must eventually be freed. NULL means this structure
	 * has not been initialized.
	 */
	struct hlist_head *buckets;
};

/**
 * struct homa_peer - One of these objects exists for each machine that we
 * have communicated with (either as client or server).
 */
struct homa_peer {
	/**
	 * @addr: IPv6 address for the machine (IPv4 addresses are stored
	 * as IPv4-mapped IPv6 addresses).
	 */
	struct in6_addr addr;

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
	 * @grantable_rpcs: Contains all homa_rpcs (both requests and
	 * responses) involving this peer whose msgins require (or required
	 * them in the past) and have not been fully received. The list is
	 * sorted in priority order (head has fewest bytes_remaining).
	 * Locked with homa->grantable_lock.
	 */
	struct list_head grantable_rpcs;

	/**
	 * @grantable_links: Used to link this peer into homa->grantable_peers.
	 * If this RPC is not linked into homa->grantable_peers, this is an
	 * empty list pointing to itself.
	 */
	struct list_head grantable_links;
#endif /* See strip.py */

	/**
	 * @peertab_links: Links this object into a bucket of its
	 * homa_peertab.
	 */
	struct hlist_node peertab_links;

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
void     homa_peertab_destroy(struct homa_peertab *peertab);
#ifndef __STRIP__ /* See strip.py */
struct homa_peer **
		homa_peertab_get_peers(struct homa_peertab *peertab,
				       int *num_peers);
#endif /* See strip.py */
int      homa_peertab_init(struct homa_peertab *peertab);
void     homa_peer_add_ack(struct homa_rpc *rpc);
struct homa_peer
	       *homa_peer_find(struct homa_peertab *peertab,
			       const struct in6_addr *addr,
			       struct inet_sock *inet);
int      homa_peer_get_acks(struct homa_peer *peer, int count,
			    struct homa_ack *dst);
struct dst_entry
	       *homa_peer_get_dst(struct homa_peer *peer,
				  struct inet_sock *inet);
#ifndef __STRIP__ /* See strip.py */
void     homa_peer_lock_slow(struct homa_peer *peer);
void     homa_peer_set_cutoffs(struct homa_peer *peer, int c0, int c1,
			       int c2, int c3, int c4, int c5, int c6, int c7);
#endif /* See strip.py */
void     homa_peertab_gc_dsts(struct homa_peertab *peertab, u64 now);

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
 * Return:   Up-to-date destination for peer.
 */
static inline struct dst_entry *homa_get_dst(struct homa_peer *peer,
					     struct homa_sock *hsk)
{
	if (unlikely(peer->dst->obsolete > 0))
		homa_dst_refresh(hsk->homa->peers, peer, hsk);
	return peer->dst;
}

#endif /* _HOMA_PEER_H */
