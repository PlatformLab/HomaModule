/* Copyright (c) 2022, Stanford University
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

/* This file implements homa_lcache objects */

#include "homa_impl.h"

/**
 * struct homa_lcache - Used to retain the lock for an RPC so that it can
 * be reused efficiently (in particular, when processing a batch of packets,
 * we want to keep the lock for the entire batch).
 */
struct homa_lcache {
	/** @rpc: if non-NULL, this RPC is currently locked. */
	struct homa_rpc *rpc;
};

/**
 * homa_lcache_init() - Constructor for homa_lcaches.
 * @lc:  The object to initialize; previous contents are discarded.
 */
static inline void homa_lcache_init(struct homa_lcache *lc)
{
	lc->rpc = NULL;
}

/**
 * homa_lcache_save() - Store info about a locked RPC.
 * @lc:    Lock cache in which to store info. Must be properly initialized;
 *         if it currently caches a lock, that lock is released.
 * @rpc:   RPC to cache: must be locked by caller.
 */
static inline void homa_lcache_save(struct homa_lcache *lc,
		struct homa_rpc *rpc)
{
	if (lc->rpc) {
		homa_rpc_unlock(lc->rpc);
	}
	lc->rpc = rpc;
}

/**
 * homa_lcache_release() - Unlock the cached RPC, if there is one. This must
 * be invoked before abandoning the object.
 * @lc:    Lock cache.
 */
static inline void homa_lcache_release(struct homa_lcache *lc)
{
	if (lc->rpc) {
		homa_rpc_unlock(lc->rpc);
	}
	lc->rpc = NULL;
}

/**
 * homa_lcache_get_server() - Check to see if a particular server RPC is
 * locked.
 * @lc:    RPC lock cache to check
 * @id:    Id of the desired RPC
 * @addr:  Address of the peer machine for this RPC.
 * @port:  Peer's port for the RPC
 *
 * Return: if @lc has a cached lock for @id, return the corresponding
 * RPC, otherwise return NULL.
 */
static inline struct homa_rpc *homa_lcache_get(struct homa_lcache *lc,
		__u64 id, const struct in6_addr *addr, __u16 port)
{
	if ((lc->rpc != NULL) && (lc->rpc->id == id)
			&& ipv6_addr_equal(&lc->rpc->peer->addr, addr)
			&& (lc->rpc->dport == port))
		return lc->rpc;
	return NULL;
}