/* SPDX-License-Identifier: BSD-2-Clause */

/* This file defines struct homa_interest and related functions.  */

#ifndef _HOMA_INTEREST_H
#define _HOMA_INTEREST_H

#include "homa_rpc.h"
#include "homa_sock.h"

/**
 * struct homa_interest - Used by homa_wait_private and homa_wait_shared to
 * wait for incoming message data to arrive for an RPC. An interest can
 * be either private (if referenced by an rpc->private_interest) or shared
 * (if present on hsk->interests).
 */
struct homa_interest {
	/**
	 * @ready: Nonzero means the interest is ready for attention: either
	 * there is an RPC that needs attention or @hsk has been shutdown.
	 */
	atomic_t ready;

	/**
	 * @rpc: If ready is set, then this holds an RPC that needs
	 * attention, or NULL if this is a shared interest and hsk has
	 * been shutdown. If ready is not set, this will be NULL if the
	 * interest is shared; if it's private, it holds the RPC the
	 * interest is associated with.
	 */
	struct homa_rpc *rpc;

	/**
	 * @core: Core on which homa_wait_*was invoked.  This is a hint
	 * used for load balancing (see balance.txt).
	 */
	int core;

	/**
	 * @wait_queue: Used to block the thread while waiting (will never
	 * have more than one queued thread).
	 */
	struct wait_queue_head wait_queue;

	/** @hsk: Socket that the interest is associated with. */
	struct homa_sock *hsk;

	/**
	 * @links: If the interest is shared, used to link this object into
	 * @hsk->interests.
	 */
	struct list_head links;
};

/**
 * homa_interest_unlink_shared() - Remove an interest from the list for a
 * socket. Note: this can race with homa_rpc_handoff, so on return it's
 * possible that the interest is ready.
 * @interest:    Interest to remove. Must have been initialized with
 *               homa_interest_init_shared.
 */
static inline void homa_interest_unlink_shared(struct homa_interest *interest)
{
	if (!list_empty(&interest->links)) {
		homa_sock_lock(interest->hsk);
		list_del_init(&interest->links);
		homa_sock_unlock(interest->hsk);
	}
}

/**
 * homa_interest_unlink_private() - Detach a private interest from its
 * RPC. Note: this can race with homa_rpc_handoff, so on return it's
 * possible that the interest is ready.
 * @interest:    Interest to remove. Must have been initialized with
 *               homa_interest_init_private. Its RPC must be locked by
 *               the caller.
 */
static inline void homa_interest_unlink_private(struct homa_interest *interest)
	__must_hold(&interest->rpc->bucket->lock)
{
	if (interest == interest->rpc->private_interest)
		interest->rpc->private_interest = NULL;
}

void     homa_interest_init_shared(struct homa_interest *interest,
	struct homa_sock *hsk);
int      homa_interest_init_private(struct homa_interest *interest,
				    struct homa_rpc *rpc);
void     homa_interest_notify_private(struct homa_rpc *rpc);
int      homa_interest_wait(struct homa_interest *interest, int nonblocking);

#ifndef __STRIP__ /* See strip.py */
struct homa_interest
	*homa_choose_interest(struct homa_sock *hsk);
#endif /* See strip.py */

#endif /* _HOMA_INTEREST_H */