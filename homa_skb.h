/* SPDX-License-Identifier: BSD-2-Clause */

/* This file contains definitions related to efficient management of
 * memory associated with transmit sk_buffs.
 */

#ifndef _HOMA_SKB_H
#define _HOMA_SKB_H

#include <linux/percpu-defs.h>

/**
 * define HOMA_PAGE_ORDER: power-of-two exponent determining how
 * many pages to allocate in a high-order page for skb pages (e.g.,
 * 2 means allocate in units of 4 pages).
 */
#define HOMA_SKB_PAGE_ORDER 4

/**
 * define HOMA_PAGE_SIZE: number of bytes corresponding to HOMA_PAGE_ORDER.
 */
#define HOMA_SKB_PAGE_SIZE (PAGE_SIZE << HOMA_SKB_PAGE_ORDER)

/**
 * struct homa_page_pool - A cache of free pages available for use in tx skbs.
 * Each page is of size HOMA_SKB_PAGE_SIZE, and a pool is dedicated for
 * use by a single NUMA node. Access to these objects is synchronized with
 * @homa->page_pool_mutex.
 */
struct homa_page_pool {
	/** @avail: Number of free pages currently in the pool. */
	int avail;

	/**
	 * @low_mark: Low water mark: smallest value of avail since the
	 * last time homa_skb_release_pages reset it.
	 */
	int low_mark;

#define HOMA_PAGE_POOL_SIZE 1000

	/**
	 * @pages: Pointers to pages that are currently free; the ref count
	 * is 1 in each of these pages.
	 */
	struct page *pages[HOMA_PAGE_POOL_SIZE];
};

/**
 * struct homa_skb_core - Stores core-specific information related to
 * sk_buff allocation. All values are assumed to be zero initially.
 */
struct homa_skb_core {
	/**
	 * @pool: NUMA-specific page pool from which to allocate skb pages
	 * for this core.
	 */
	struct homa_page_pool *pool;

	/**
	 * @skb_page: a page of data available being used for skb frags.
	 * This pointer is included in the page's reference count.
	 */
	struct page *skb_page;

	/**
	 * @page_inuse: offset of first byte in @skb_page that hasn't already
	 * been allocated.
	 */
	int page_inuse;

	/** @page_size: total number of bytes available in @skb_page. */
	int page_size;

	/**
	 * define HOMA_MAX_STASHED: maximum number of stashed pages that
	 * can be consumed by a message of a given size (assumes page_inuse
	 * is 0). This is a rough guess, since it doesn't consider all of
	 * the data_segments that will be needed for the packets.
	 */
#define HOMA_MAX_STASHED(size) (((size - 1) / HOMA_SKB_PAGE_SIZE) + 1)

	/**
	 * @num_stashed_pages: number of pages currently available in
	 * stashed_pages.
	 */
	int num_stashed_pages;

	/**
	 * @stashed_pages: use to prefetch from the cache all of the pages a
	 * message will need with a single operation, to avoid having to
	 * synchronize separately for each page. Note: these pages are all
	 * HOMA_SKB_PAGE_SIZE in length.
	 */
	struct page *stashed_pages[HOMA_MAX_STASHED(HOMA_MAX_MESSAGE_LENGTH)];
};
DECLARE_PER_CPU(struct homa_skb_core, homa_skb_core);

extern int      homa_skb_append_from_iter(struct homa *homa,
		    struct sk_buff *skb, struct iov_iter *iter, int length);
extern int      homa_skb_append_from_skb(struct homa *homa,
		    struct sk_buff *dst_skb, struct sk_buff *src_skb,
		    int offset, int length);
extern int      homa_skb_append_to_frag(struct homa *homa, struct sk_buff *skb,
		    void *buf, int length);
extern void     homa_skb_cache_pages(struct homa *homa, struct page **pages,
		    int count);
extern void     homa_skb_cleanup(struct homa *homa);
extern void    *homa_skb_extend_frags(struct homa *homa, struct sk_buff *skb,
		    int *length);
extern void     homa_skb_free_tx(struct homa *homa, struct sk_buff *skb);
extern void     homa_skb_free_many_tx(struct homa *homa, struct sk_buff **skbs,
		    int count);
extern void     homa_skb_get(struct sk_buff *skb, void *dest, int offset,
		    int length);
extern int      homa_skb_init(struct homa *homa);
extern struct sk_buff
	       *homa_skb_new_tx(int length);
extern bool     homa_skb_page_alloc(struct homa *homa,
		    struct homa_skb_core *core);
extern void     homa_skb_release_pages(struct homa *homa);
extern void     homa_skb_stash_pages(struct homa *homa, int length);

#endif /* _HOMA_SKB_H */