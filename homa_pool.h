/* SPDX-License-Identifier: BSD-2-Clause */

/* This file contains definitions used to manage user-space buffer pools.
 */

#ifndef _HOMA_POOL_H
#define _HOMA_POOL_H

#include <linux/percpu.h>

#include "homa_rpc.h"

/**
 * struct homa_bpage - Contains information about a single page in
 * a buffer pool.
 */
struct homa_bpage {
	/** @lock: to synchronize shared access. */
	spinlock_t lock;

	/**
	 * @refs: Counts number of distinct uses of this
	 * bpage (1 tick for each message that is using
	 * this page, plus an additional tick if the @owner
	 * field is set).
	 */
	atomic_t refs;

	/**
	 * @owner: kernel core that currently owns this page
	 * (< 0 if none).
	 */
	int owner;

	/**
	 * @expiration: homa_clock() time after which it's OK to steal this
	 * page from its current owner (if @refs is 1).
	 */
	u64 expiration;
} ____cacheline_aligned_in_smp;

/**
 * struct homa_pool_core - Holds core-specific data for a homa_pool (a bpage
 * out of which that core is allocating small chunks).
 */
struct homa_pool_core {
	/**
	 * @page_hint: Index of bpage in pool->descriptors,
	 * which may be owned by this core. If so, we'll use it
	 * for allocating partial pages.
	 */
	int page_hint;

	/**
	 * @allocated: if the page given by @page_hint is
	 * owned by this core, this variable gives the number of
	 * (initial) bytes that have already been allocated
	 * from the page.
	 */
	int allocated;

	/**
	 * @next_candidate: when searching for free bpages,
	 * check this index next.
	 */
	int next_candidate;
};

/**
 * struct homa_pool - Describes a pool of buffer space for incoming
 * messages for a particular socket; managed by homa_pool.c. The pool is
 * divided up into "bpages", which are a multiple of the hardware page size.
 * A bpage may be owned by a particular core so that it can more efficiently
 * allocate space for small messages.
 */
struct homa_pool {
	/**
	 * @hsk: the socket that this pool belongs to.
	 */
	struct homa_sock *hsk;

	/**
	 * @region: beginning of the pool's region (in the app's virtual
	 * memory). Divided into bpages. 0 means the pool hasn't yet been
	 * initialized.
	 */
	char __user *region;

	/** @num_bpages: total number of bpages in the pool. */
	int num_bpages;

	/** @descriptors: kmalloced area containing one entry for each bpage. */
	struct homa_bpage *descriptors;

	/**
	 * @free_bpages: the number of pages still available for allocation
	 * by homa_pool_get pages. This equals the number of pages with zero
	 * reference counts, minus the number of pages that have been claimed
	 * by homa_get_pool_pages but not yet allocated.
	 */
	atomic_t free_bpages;

	/**
	 * @bpages_needed: the number of free bpages required to satisfy the
	 * needs of the first RPC on @hsk->waiting_for_bufs, or INT_MAX if
	 * that queue is empty.
	 */
	int bpages_needed;

	/** @cores: core-specific info; dynamically allocated. */
	struct homa_pool_core __percpu *cores;

	/**
	 * @check_waiting_invoked: incremented during unit tests when
	 * homa_pool_check_waiting is invoked.
	 */
	int check_waiting_invoked;
};

bool     homa_bpage_available(struct homa_bpage *bpage, u64 now);
struct   homa_pool *homa_pool_alloc(struct homa_sock *hsk);
int      homa_pool_alloc_msg(struct homa_rpc *rpc);
void     homa_pool_check_waiting(struct homa_pool *pool);
void     homa_pool_free(struct homa_pool *pool);
void __user *homa_pool_get_buffer(struct homa_rpc *rpc, int offset,
				  int *available);
int      homa_pool_get_pages(struct homa_pool *pool, int num_pages,
			     u32 *pages, int leave_locked);
void     homa_pool_get_rcvbuf(struct homa_pool *pool,
			      struct homa_rcvbuf_args *args);
int      homa_pool_release_buffers(struct homa_pool *pool,
				   int num_buffers, u32 *buffers);
int      homa_pool_set_region(struct homa_sock *hsk, void __user *region,
			      u64 region_size);

#endif /* _HOMA_POOL_H */
