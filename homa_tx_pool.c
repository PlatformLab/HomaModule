// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

/* This file manages a reusable pools of pages (one per NUMA node), that
 * are used to hold the data of outgoing Homa messages. Homa uses these
 * custom pools rather than, say, page_pools because Homa can free pages
 * from its pools more agressively than in page_pool. And, this module
 * also implements a one-page cache page per core to use for allocating
 * smaller chunks of tx memory.
 */

#include "homa_impl.h"
#include "homa_tx_pool.h"

DEFINE_PER_CPU(struct homa_tx_pool_core, homa_tx_pool_core);

static void frag_page_set(skb_frag_t *frag, struct page *page)
{
	frag->netmem = page_to_netmem(page);
}

/**
 * homa_tx_pool_init() - Invoked when a struct homa is created; initializes
 * information related to this module.
 * @homa:        Shared information about the Homa transport; pool-related
 *               fields are assumed to have been initialized to zero.
 * Return:       0 for success, negative errno on error
 */
int homa_tx_pool_init(struct homa *homa)
{
	int i;
	u64 min_kb;

	homa->tx_page_pool_min_kb = 1000;
	min_kb = 3 * HOMA_MAX_MESSAGE_LENGTH;
	do_div(min_kb, 1000);
	homa->tx_page_pool_min_kb = min_kb;

	/* Initialize NUMA-specfific page pools. */
	homa->max_numa = -1;
	for (i = 0; i < nr_cpu_ids; i++) {
		struct homa_tx_pool_core *tx_core;
		int numa = cpu_to_node(i);

		BUG_ON(numa >= MAX_NUMNODES);
		if (numa > homa->max_numa)
			homa->max_numa = numa;
		if (!homa->tx_pools[numa]) {
			struct homa_tx_pool *pool;

			pool = kzalloc(sizeof(*pool), GFP_ATOMIC);
			if (!pool)
				goto error;
			homa->tx_pools[numa] = pool;
		}
		tx_core = &per_cpu(homa_tx_pool_core, i);
		tx_core->pool = homa->tx_pools[numa];
	}
	pr_notice("%s found max NUMA node %d\n", __func__, homa->max_numa);
	return 0;

error:
	homa_tx_pool_cleanup(homa);
	return -ENOMEM;
}

/**
 * homa_tx_pool_cleanup() - Invoked when a struct homa is deleted; cleans
 * up information related to this module.
 * @homa:  Overall information about the Homa transport.
 */
void homa_tx_pool_cleanup(struct homa *homa)
{
	int i, j;

	for (i = 0; i < nr_cpu_ids; i++) {
		struct homa_tx_pool_core *tx_core;

		tx_core = &per_cpu(homa_tx_pool_core, i);
		if (!tx_core)
			continue;
		if (tx_core->page) {
			put_page(tx_core->page);
			tx_core->page = NULL;
			tx_core->page_size = 0;
			tx_core->allocated = 0;
		}
		tx_core->pool = NULL;
	}

	for (i = 0; i < MAX_NUMNODES; i++) {
		struct homa_tx_pool *pool = homa->tx_pools[i];

		if (!pool)
			continue;
		for (j = pool->avail - 1; j >= 0; j--)
			put_page(pool->pages[j]);
		pool->avail = 0;
		kfree(pool);
		homa->tx_pools[i] = NULL;
	}

	kfree(homa->tx_pages_to_free);
	homa->tx_pages_to_free = NULL;
	homa->tx_pages_to_free_slots = 0;
}

/**
 * homa_tx_pool_alloc() - Allocate a block of memory in one or more
 * fragments.
 * @homa:        Shared information about the Homa transport.
 * @lenth:       Total number of bytes to allocate.
 * @num_frags:   Number of fragments of storage initially available at **frags;
 *               modified to hold the total number of fragments
 *               allocated.
 * @frags:       Pointer to pointer to space in which to store fragments;
 *               if this initial space is insufficient to hold all of the
 *               fragments needed, will be overwritten with a dynamically
 *               allocated block.
 * Return:       0 for success, negative errno on error.
 */
int homa_tx_pool_alloc(struct homa *homa, int length, int *num_frags,
			skb_frag_t **frags)
{
	struct homa_tx_pool_core *tx_core;
	skb_frag_t *cur_frags = *frags;
	int max_frags = *num_frags;
	int bytes_left = length;
	int frags_allocated = 0;
	skb_frag_t *frag;
	int err;

	/* Asssure atomicity with respect to SoftIRQ invocations or
	 * task preemption (so we can access per-core info without races).
	 */
	local_bh_disable();
	tx_core = &per_cpu(homa_tx_pool_core, smp_processor_id());

	while (bytes_left  > 0) {
		/* Expand the frag array if needed. */
		if (frags_allocated == max_frags) {
			skb_frag_t *new_frags;
			int num_new;

			num_new = ((bytes_left + HOMA_TX_PAGE_SIZE - 1) >>
			            (PAGE_SHIFT + HOMA_TX_PAGE_ORDER)) +
				    frags_allocated;
			new_frags = kvmalloc_array(num_new, sizeof(*new_frags),
						   GFP_ATOMIC);
			if (!new_frags) {
				err = -ENOMEM;
				goto error;
			}
			memcpy(new_frags, cur_frags,
			       frags_allocated * sizeof(*new_frags));
			if (cur_frags != *frags)
				kfree(cur_frags);
			cur_frags = new_frags;
			max_frags = num_new;
		}

		frag = &cur_frags[frags_allocated];
		err = __homa_tx_pool_alloc_frag(tx_core, bytes_left, frag);
		if (err != 0)
			goto error;
		frags_allocated++;
		bytes_left -= skb_frag_size(frag);
	}
	local_bh_enable();
	*frags  = cur_frags;
	*num_frags = frags_allocated;
	return 0;

error:
	homa_tx_pool_free(homa, frags_allocated, cur_frags);
	if (cur_frags != *frags)
		kfree(cur_frags);
	*num_frags = 0;
	local_bh_enable();
	return err;
}

/**
 * __homa_tx_pool_alloc_frag() - Allocate space for a single fragment.
 * Caller must have disabled interrupts.
 * @tx_core:   Core-specific information to use for the allocation.
 * @length:    Desired length: actual length of fragment may be less
 *             than this.
 * @frag:      Store information about the allocated fragment here. Its
 *             length may be less than @length. A reference will be taken
 *             on its page.
 * Return:     0 for success, otherwise a negative errno.
 */
int __homa_tx_pool_alloc_frag(struct homa_tx_pool_core *tx_core, int length,
			     skb_frag_t *frag)
{
	struct page *page;
	int page_size;

	/* See if the allocation can be handled with the core's cached page. */
	if (tx_core->page_size - tx_core->allocated >= length) {
		get_page(tx_core->page);
		frag_page_set(frag, tx_core->page);
		frag->offset = tx_core->allocated;
		skb_frag_size_set(frag, length);
		tx_core->allocated += length;
		if (tx_core->allocated == tx_core->page_size) {
			put_page(tx_core->page);
			tx_core->page = NULL;
			tx_core->page_size = 0;
			tx_core->allocated = 0;
		}
		return 0;
	}

	/* Must allocate a new page. */
	page = homa_tx_pool_alloc_page(tx_core, &page_size);
	if (!page)
		return -ENOMEM;
	frag_page_set(frag, page);
	frag->offset = 0;
	skb_frag_size_set(frag, min(page_size, length));

	/* Retain the leftover part of the page as the core's cached page,
	 * if it has more space available than the current cached page.
	 */
	if (tx_core->page == NULL ||
	    (tx_core->page_size - tx_core->allocated) <
	    (page_size - skb_frag_size(frag))) {
		if (tx_core->page)
			put_page(tx_core->page);
		get_page(page);
		tx_core->page = page;
		tx_core->page_size = page_size;
		tx_core->allocated = skb_frag_size(frag);
	}
	return 0;
}

/**
 * homa_tx_pool_alloc_frag() - Allocate space for a single fragment.
 * @homa:      Overall information about the Homa transport.
 * @length:    Desired length: actual length of fragment may be less
 *             than this.
 * @frag:      Store information about the allocated fragment here. Its
 *             length may be less than @length. A reference will be taken
 *             on its page.
 * Return:     0 for success, otherwise a negative errno.
 */
int homa_tx_pool_alloc_frag(struct homa *homa, int length, skb_frag_t *frag)
{
	struct homa_tx_pool_core *tx_core;
	int result;

	tx_core = &per_cpu(homa_tx_pool_core, smp_processor_id());
	local_bh_disable();
	result = __homa_tx_pool_alloc_frag(tx_core, length, frag);
	local_bh_enable();
	return result;
}

/**
 * homa_tx_pool_alloc_page() - Allocate a new page for skb allocation for a
 * given core. Any existing page is released.
 * @txb_core:   Core-specific info; the page will be allocated in this core.
 * @length:     The length of the allocated page (if any) will be stored here.
 * Return:      The allocated page (with reference count 1) or NULL if
 *              no page could be allocated.
 */
struct page *homa_tx_pool_alloc_page(struct homa_tx_pool_core *tx_core,
				      int *length)
{
	struct homa_tx_pool *pool;
	struct page *page;

	IF_NO_STRIP(u64 start);

	/* Step 1: can we reuse the core's cached page? */
	page = tx_core->page;
	if (page && page_ref_count(page) == 1) {
		*length = tx_core->page_size;
		tx_core->page = NULL;
		tx_core->page_size = 0;
		tx_core->allocated = 0;
		return page;
	}

	/* Step 2: can we retrieve a page from the pool for this NUMA node? */
	pool = tx_core->pool;
	if (pool->avail) {
		UNIT_HOOK("tx_pool_race");
		spin_lock_bh(&pool->mutex);

		/* Must recheck: could have changed before locked. */
		if (pool->avail) {
			pool->avail--;
			if (pool->avail < pool->low_mark)
				pool->low_mark = pool->avail;
			page = pool->pages[pool->avail];
			spin_unlock_bh(&pool->mutex);
			*length = HOMA_TX_PAGE_SIZE;
			return page;
		}
		spin_unlock_bh(&pool->mutex);
	}

	/* Step 3: can we allocate a big page? */
	INC_METRIC(tx_page_allocs, 1);
	IF_NO_STRIP(start = homa_clock());
	page = alloc_pages(GFP_ATOMIC | __GFP_COMP | __GFP_NOWARN |
			   __GFP_NORETRY, HOMA_TX_PAGE_ORDER);
	if (likely(page)) {
		INC_METRIC(tx_page_alloc_cycles, homa_clock() - start);
		*length = HOMA_TX_PAGE_SIZE;
		return page;
	}

	/* Step 4: can we allocate a normal page? */
	page = alloc_page(GFP_ATOMIC);
	INC_METRIC(tx_page_alloc_cycles, homa_clock() - start);
	if (likely(page)) {
		*length = PAGE_SIZE;
		return page;
	}
	return NULL;
}

/**
 * homa_tx_pool_free() - Release one or more fragments previously allocated
 * by homa_tx_pool_alloc.
 * @homa:        Shared information about the Homa transport.
 * @num_frags:   Number of fragments at *frags.
 * @frags:       Pointer to array of fragments to free; must not be used
 *               after this function returns.
 */
void homa_tx_pool_free(struct homa *homa, int num_frags, skb_frag_t *frags)
{
	struct homa_tx_pool *pool;
	int i;

	if (num_frags <= 0)
		return;

	pool = homa->tx_pools[page_to_nid(skb_frag_page(&frags[0]))];
	spin_lock_bh(&pool->mutex);
	for (i = 0; i < num_frags; i++) {
		struct page *page = skb_frag_page(&frags[i]);

		if (compound_order(page) == HOMA_TX_PAGE_ORDER &&
		    page_ref_count(page) == 1 &&
		    pool->avail < HOMA_TX_POOL_LIMIT) {
			pool->pages[pool->avail] = page;
			pool->avail++;
		} else {
			put_page(page);
		}
	}
	spin_unlock_bh(&pool->mutex);
}

/**
 * homa_tx_pool_gc() - This function is invoked occasionally; its
 * job is to gradually release pages from the page pools back to
 * Linux, based on sysctl parameters such as tx_page_frees_per_sec.
 * @homa:  Overall information about the Homa transport.
 */
void homa_tx_pool_gc(struct homa *homa)
{
	int i, max_low_mark, min_pages, release, release_max;
	struct homa_tx_pool *max_pool;
	u64 now = homa_clock();

	if (now < homa->tx_page_free_time)
		return;

	/* Free pages every 0.5 second. */
	homa->tx_page_free_time = now + (500 * homa_clock_khz());

	/* Make sure we have space in which to collect pages to free. */
	release_max = homa->tx_page_frees_per_sec / 2;
	if (homa->tx_pages_to_free_slots < release_max) {
		struct page **old = homa->tx_pages_to_free;

		homa->tx_pages_to_free = kmalloc_array(release_max,
						       sizeof(struct page *),
						       GFP_ATOMIC);
		if (homa->tx_pages_to_free) {
			kfree(old);
			homa->tx_pages_to_free_slots = release_max;
		} else {
			/* Couldn't allocate space; reuse existing space
			 * and reduce how many pages we'll free.
			 */
			homa->tx_pages_to_free = old;
			release_max = homa->tx_pages_to_free_slots;
		}
	}

	/* Find the pool with the largest number of pages that haven't
	 * been used recently.
	 */
	max_low_mark = -1;
	for (i = 0; i <= homa->max_numa; i++) {
		struct homa_tx_pool *pool = homa->tx_pools[i];

		if (!pool)
			continue;
		spin_lock_bh(&pool->mutex);
		if (pool->low_mark > max_low_mark) {
			max_low_mark = pool->low_mark;
			max_pool = pool;
		}
		pool->low_mark = pool->avail;
		spin_unlock_bh(&pool->mutex);
	}

	/* Collect pages to free (but don't free them until after
	 * releasing the lock, since freeing is expensive).
	 */
	spin_lock_bh(&max_pool->mutex);
	min_pages = ((homa->tx_page_pool_min_kb * 1000)
			+ (HOMA_TX_PAGE_SIZE - 1)) >> HOMA_TX_PAGE_SHIFT;

	/* Note: may need to adjust max_low_mark to reflect changes made
	 * while lock wasn't held.
	 */
	UNIT_HOOK("tx_pool_race");
	if (max_low_mark > max_pool->low_mark)
		max_low_mark = max_pool->low_mark;
	release = max_low_mark - min_pages;
	if (release > release_max)
		release = release_max;
	for (i = 0; i < release; i++) {
		max_pool->avail--;
		homa->tx_pages_to_free[i] = max_pool->pages[max_pool->avail];
	}
	max_pool->low_mark = max_pool->avail;
	spin_unlock_bh(&max_pool->mutex);

	/* Free the pages that were collected. */
	for (i = 0; i < release; i++) {
		struct page *page = homa->tx_pages_to_free[i];

		tt_record2("homa_tx_pool_gc releasing page 0x%08x%08x",
			   tt_hi(page), tt_lo(page));
		put_page(page);
	}
}

/**
 * homa_copy_to_frags() - Copy a block of data into an array of fragments.
 * @filler:    Describes the current position in the array of fragments;
 *             will be updated to reflect the copied data.
 * @src:       Copy bytes from here into the fragments.
 * @num_bytes: Number of bytes to copy.
 * Return:     0 for success; -EINVAL if there isn't enough room in the
 *             fragments for the new bytes.
 */
int homa_copy_to_frags(struct homa_frag_filler *filler, void *src,
		       int num_bytes)
{
	int p_off, copied, p_len;
	int bytes_this_frag;
	struct page *p;
	u8 *src_cur;

#ifdef __UNIT_TEST__
	if (mock_check_error(&mock_copy_to_frags_errors))
		return -EINVAL;
#endif /* __UNIT_TEST__ */

	src_cur = src;
	while (num_bytes > 0) {
		if (filler->offset >= skb_frag_size(filler->frag)) {
			filler->frag++;
			filler->num_frags--;
			if (filler->num_frags <= 0)
				return -EINVAL;
			filler->offset = 0;
		}
		bytes_this_frag = min(num_bytes,
				      skb_frag_size(filler->frag) -
				      filler->offset);
		skb_frag_foreach_page(filler->frag,
				      skb_frag_off(filler->frag) +
				      filler->offset, bytes_this_frag, p,
				      p_off, p_len, copied) {
			u8 *vaddr = kmap_local_page(p);

			memcpy(vaddr + p_off, src_cur, p_len);
			kunmap_local(vaddr);
			src_cur += p_len;
		}
		filler->offset += bytes_this_frag;
		num_bytes -= bytes_this_frag;
	}
	return 0;
}

/**
 * homa_copy_iter_to_frags() - Copy data from an iterator (presumably
 * referring to user-space data) into an array of fragments.
 * @filler:    Describes the current position in the array of fragments;
 *             will be updated to reflect the copied data.
 * @iter:      Copy bytes from here into the fragments.
 * @num_bytes: Number of bytesto copy.
 * Return:     0 for success; -EINVAL if there isn't enough room in the
 *             fragments for the new bytes.
 */
int homa_copy_iter_to_frags(struct homa_frag_filler *filler,
			    struct iov_iter *iter, int num_bytes)
{
	int p_off, copied, p_len;
	int bytes_this_frag;
	struct page *p;

	while (num_bytes > 0) {
		if (filler->offset >= skb_frag_size(filler->frag)) {
			filler->frag++;
			filler->num_frags--;
			if (filler->num_frags <= 0)
				return -EINVAL;
			filler->offset = 0;
		}
		bytes_this_frag = min(num_bytes,
				      skb_frag_size(filler->frag) -
				      filler->offset);
		skb_frag_foreach_page(filler->frag,
				      skb_frag_off(filler->frag) +
				      filler->offset, bytes_this_frag, p,
				      p_off, p_len, copied) {
			int result;
			u8 *vaddr = kmap_local_page(p);

			result = copy_from_iter(vaddr + p_off, p_len, iter);
			kunmap_local(vaddr);
			if (result != p_len)
				return -EFAULT;
		}
		filler->offset += bytes_this_frag;
		num_bytes -= bytes_this_frag;
	}
	return 0;
}