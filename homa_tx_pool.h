/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */

/* This module manages a pool of memory pages used for outgoing sk_buffs. */

#ifndef _HOMA_TX_POOL_H
#define _HOMA_TX_POOL_H

#include <linux/percpu-defs.h>

/**
 * define HOMA_TX_PAGE_ORDER - exponent (power of two) determining how
 * many pages to allocate in a high-order page for skb pages (e.g.,
 * 2 means allocate in units of 4 pages).
 */
#define HOMA_TX_PAGE_ORDER 4

/**
 * define HOMA_TX_PAGE_SIZE - number of bytes corresponding to HOMA_PAGE_ORDER.
 */
#define HOMA_TX_PAGE_SIZE (PAGE_SIZE << HOMA_TX_PAGE_ORDER)

/**
 * define HOMA_TX_PAGE_SHIFT: HOMA_PAGE_SIZE == 1 << HOMA_TX_PAGE_SHIFT
 */
#define HOMA_TX_PAGE_SHIFT (PAGE_SHIFT + HOMA_TX_PAGE_ORDER)

/**
 * struct homa_tx_pool - A cache of free pages available for use.
 * Each page is of size HOMA_TX_PAGE_SIZE, and a given pool is dedicated for
 * use by a single NUMA node.
 */
struct homa_tx_pool {
	/** @mutex: Used to synchronize access to the fields in this struct. */
	spinlock_t mutex;

	/** @avail: Number of free pages currently in the pool. */
	int avail;

	/**
	 * @low_mark: Low water mark: smallest value of avail since the
	 * last time homa_tx_pool_gc reset it.
	 */
	int low_mark;

#define HOMA_TX_POOL_LIMIT 1000

	/**
	 * @pages: Pointers to pages that are currently free; the ref count
	 * is 1 in each of these pages.
	 */
	struct page *pages[HOMA_TX_POOL_LIMIT];
};

/**
 * struct homa_tx_pool_core - Stores core-specific information related to
 * tx memory allocation. All values are assumed to be zero initially.
 */
struct homa_tx_pool_core {
	/**
	 * @pool: NUMA-specific page pool from which to allocate skb pages
	 * for this core.
	 */
	struct homa_tx_pool *pool;

	/**
	 * @page: a page of data that is "owned" by this core and used for
	 * allocation on this core (or NULL). This pointer is included in
	 * the page's reference count.
	 */
	struct page *page;

	/**
	 * @page_size: total number of bytes in @page (including any
	 * already allocated).
	 */
	int page_size;

	/**
	 * @allocated: number of (initial) bytes in @page that have already
	 * been allocated for use.
	 */
	int allocated;
};
DECLARE_PER_CPU(struct homa_tx_pool_core, homa_tx_pool_core);

/**
 * struct homa_frag_filler - Used to iterate over an array of skb_frag_t's
 * to copy data into them.
 */
struct homa_frag_filler {
	/** @frag: Fragment currently being filled (in an array of frags). */
	skb_frag_t *frag;

	/**
	 * @offset: Offset within @frag where the next byte of data should be
	 * stored.
	 */
	int offset;

	/**
	 * @num_frags: Number of fragments in the array including @frag:
	 * if this reaches zero then we have run out of space.
	 */
	int num_frags;
};

/**
 * homa_init_frag_filler() - Initialize a frag filler.
 * @filler:     Struct to initialize.
 * @num_frags:  Number of fragments available to fill.
 * @frags:      First in array of @num_frags fragments.
 */
static inline void homa_frag_filler_init(struct homa_frag_filler *filler,
					 int num_frags, skb_frag_t *frags)
{
	filler->frag = frags;
	filler->offset = 0;
	filler->num_frags = num_frags;
}

int          homa_copy_iter_to_frags(struct homa_frag_filler *filler,
				     struct iov_iter *iter, int num_bytes);
int          homa_copy_to_frags(struct homa_frag_filler *filler, void *src,
				int num_bytes);
int          homa_tx_pool_alloc(struct homa *homa, int length, int *num_frags,
			        skb_frag_t **frags);
int          __homa_tx_pool_alloc_frag(struct homa_tx_pool_core *tx_core,
				       int length, skb_frag_t *frag);
int          homa_tx_pool_alloc_frag(struct homa *homa, int length,
				     skb_frag_t *frag);
struct page *homa_tx_pool_alloc_page(struct homa_tx_pool_core *tx_core,
				     int *length);
void         homa_tx_pool_cleanup(struct homa *homa);
void         homa_tx_pool_free(struct homa *homa, int num_frags,
			       skb_frag_t *frags);
void         homa_tx_pool_gc(struct homa *homa);
int          homa_tx_pool_init(struct homa *homa);

#endif /* _HOMA_TX_POOL_H */
