/* SPDX-License-Identifier: BSD-2-Clause */

/* This file contains definitions used to manage user-space buffer pools.
 */

#ifndef _HOMA_POOL_H
#define _HOMA_POOL_H

#include "homa_rpc.h"

/**
 * struct homa_bpage - Contains information about a single page in
 * a buffer pool.
 */
struct homa_bpage {
	union {
		/**
		 * @cache_line: Ensures that each homa_bpage object
		 * is exactly one cache line long.
		 */
		char cache_line[L1_CACHE_BYTES];
		struct {
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
			 * @expiration: time (in sched_clock() units) after
			 * which it's OK to steal this page from its current
			 * owner (if @refs is 1).
			 */
			__u64 expiration;
		};
	};
};

_Static_assert(sizeof(struct homa_bpage) == L1_CACHE_BYTES,
	       "homa_bpage overflowed a cache line");

/**
 * struct homa_pool_core - Holds core-specific data for a homa_pool (a bpage
 * out of which that core is allocating small chunks).
 */
struct homa_pool_core {
	union {
		/**
		 * @cache_line: Ensures that each object is exactly one
		 * cache line long.
		 */
		char cache_line[L1_CACHE_BYTES];
		struct {
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
	};
};

#if 1 /* See strip.py */
_Static_assert(sizeof(struct homa_pool_core) == L1_CACHE_BYTES,
	       "homa_pool_core overflowed a cache line");
#endif /* See strip.py */

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
	char *region;

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
	 * The number of free bpages required to satisfy the needs of the
	 * first RPC on @hsk->waiting_for_bufs, or INT_MAX if that queue
	 * is empty.
	 */
	int bpages_needed;

	/** @cores: core-specific info; dynamically allocated. */
	struct homa_pool_core *cores;

	/** @num_cores: number of elements in @cores. */
	int num_cores;

	/**
	 * @check_waiting_invoked: incremented during unit tests when
	 * homa_pool_check_waiting is invoked.
	 */
	int check_waiting_invoked;
};

int      homa_pool_allocate(struct homa_rpc *rpc);
void     homa_pool_check_waiting(struct homa_pool *pool);
void     homa_pool_destroy(struct homa_pool *pool);
void    *homa_pool_get_buffer(struct homa_rpc *rpc, int offset,
			      int *available);
int      homa_pool_get_pages(struct homa_pool *pool, int num_pages,
			     __u32 *pages, int leave_locked);
int      homa_pool_init(struct homa_sock *hsk, void *buf_region,
			__u64 region_size);
void     homa_pool_release_buffers(struct homa_pool *pool,
				   int num_buffers, __u32 *buffers);

#endif /* _HOMA_POOL_H */
