/* Copyright (c) 2024 Homa Developers
 * SPDX-License-Identifier: BSD-1-Clause
 */

/* This file contains functions for allocating and freeing sk_buffs. */

#include "homa_impl.h"

#ifdef __UNIT_TEST__
extern int mock_max_skb_frags;
#define HOMA_MAX_SKB_FRAGS mock_max_skb_frags
#else
#define HOMA_MAX_SKB_FRAGS MAX_SKB_FRAGS
#endif

/**
 * homa_skb_page_pool_init() - Invoked when a struct homa is created to
 * initialize a page pool.
 * @pool:         Pool to initialize.
 */
void homa_skb_page_pool_init(struct homa_page_pool *pool)
{
	pool->avail = 0;
	pool->low_mark = 0;
	memset(pool->pages, 0, sizeof(pool->pages));
}

/**
 * homa_skb_cleanup() - Invoked when a struct homa is deleted; cleans
 * up information related to skb allocation.
 * @homa:  Overall inforamtion about the Homa transport.
 */
void homa_skb_cleanup(struct homa *homa)
{
	int i, j;
	for (i = 0; i < nr_cpu_ids; i++) {
		struct homa_core *core = homa_cores[i];
		if (core->skb_page != NULL) {
			put_page(core->skb_page);
			core->skb_page = NULL;
			core->page_size = 0;
			core->page_inuse = 0;
		}
		for (j = 0; j < core->num_stashed_pages; j++)
			put_page(core->stashed_pages[j]);
		core->num_stashed_pages = 0;
	}

	for (i = 0; i < MAX_NUMNODES; i++) {
		struct homa_numa *numa = homa_numas[i];
		if (!numa)
			continue;
		for (j = numa->page_pool.avail - 1; j >= 0; j--)
			put_page(numa->page_pool.pages[j]);
		numa->page_pool.avail = 0;
	}

	if (homa->skb_pages_to_free != NULL) {
		kfree(homa->skb_pages_to_free);
		homa->skb_pages_to_free = NULL;
		homa->pages_to_free_slots = 0;
	}
}

/**
 * homa_skb_new_tx() - Allocate a new sk_buff for outgoing data.
 * @length:       Number of bytes of data that the caller would like to
 *                have available in the linear part of the sk_buff for
 *                the Homa header and additional data beyond that. This
 *                function will allocate additional space for IP and
 *                Ethernet headers, as well as for the homa_skb_info.
 * Return:        New sk_buff, or NULL if there was insufficient memory.
 *                The sk_buff will be configured with so that the next
 *                skb_put will be for the transport (Homa) header. The
 *                homa_skb_info is not initialized.
 */
struct sk_buff *homa_skb_new_tx(int length)
{
	struct sk_buff *skb;
	__u64 start = get_cycles();

	/* Note: allocate space for an IPv6 header, which is larger than
	 * an IPv4 header.
	 */
	skb = alloc_skb(HOMA_SKB_EXTRA + HOMA_IPV6_HEADER_LENGTH +
			sizeof(struct homa_skb_info) + length,
			GFP_KERNEL);
	if (likely(skb)) {
		skb_reserve(skb, HOMA_SKB_EXTRA + HOMA_IPV6_HEADER_LENGTH);
		skb_reset_transport_header(skb);
	}
	INC_METRIC(skb_allocs, 1);
	INC_METRIC(skb_alloc_cycles, get_cycles() - start);
	return skb;
}

/**
 * homa_skb_stash_pages() - Typically invoked at the beginning of
 * preparing an output message; will collect from the page cache enough
 * pages to meet the needs of the message and stash them locally for this
 * core, so that the global lock for the page cache only needs to be acquired
 * once.
 * @homa:      Overall data about the Homa protocol implementation.
 * @length:    Length of the message being prepared. Must be <=
 *             HOMA_MAX_MESSAGE_LENGTH.
 */
void homa_skb_stash_pages(struct homa *homa, int length)
{
	struct homa_core *core = homa_cores[raw_smp_processor_id()];
	struct homa_page_pool *pool = &core->numa->page_pool;
	int pages_needed = HOMA_MAX_STASHED(length);

	if ((pages_needed < 2) || (core->num_stashed_pages >= pages_needed))
		return;
	spin_lock_bh(&homa->page_pool_mutex);
	while (pool->avail && (core->num_stashed_pages < pages_needed)) {
		pool->avail--;
		if (pool->avail < pool->low_mark )
			pool->low_mark = pool->avail;
		core->stashed_pages[core->num_stashed_pages] =
				pool->pages[pool->avail];
		core->num_stashed_pages++;
	}
	spin_unlock_bh(&homa->page_pool_mutex);
}

/**
 * homa_skb_extend_frags() - Allocate additional space in the frags part
 * of an skb (ideally by just expanding the last fragment). Returns
 * one contiguous chunk, whose size is <= @length.
 * @homa:     Overall data about the Homa protocol implementation.
 * @skb:      Skbuff for which additional space is needed.
 * @length:   The preferred number of bytes to append; modified to hold
 *            the actual number allocated, which may be less.
 * Return:    Pointer to the new space, or NULL if space couldn't be
 *            allocated.
 */
void *homa_skb_extend_frags(struct homa *homa, struct sk_buff *skb, int *length)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	struct homa_core *core = homa_cores[raw_smp_processor_id()];
	skb_frag_t *frag = &shinfo->frags[shinfo->nr_frags - 1];
	char *result;
	int actual_size = *length;

	/* Can we just extend the skb's last fragment? */
	if ((shinfo->nr_frags > 0) && (frag->bv_page == core->skb_page)
			&& (core->page_inuse < core->page_size)
			&& ((frag->bv_offset + frag->bv_len)
			== core->page_inuse)) {
		if ((core->page_size - core->page_inuse) < actual_size)
			actual_size = core->page_size - core->page_inuse;
		*length = actual_size;
		frag->bv_len += actual_size;
		result = page_address(frag->bv_page) + core->page_inuse;
		core->page_inuse += actual_size;
		skb_len_add(skb, actual_size);
		return result;
	}

	/* Need to add a new fragment to the skb. */
	core->page_inuse = ALIGN(core->page_inuse, SMP_CACHE_BYTES);
	if (core->page_inuse >= core->page_size) {
		if (!homa_skb_page_alloc(homa, core))
			return NULL;
	}
	if ((core->page_size - core->page_inuse) < actual_size)
		actual_size = core->page_size - core->page_inuse;
	frag = &shinfo->frags[shinfo->nr_frags];
	shinfo->nr_frags++;
	frag->bv_page = core->skb_page;
	get_page(core->skb_page);
	frag->bv_offset = core->page_inuse;
	*length = actual_size;
	frag->bv_len = actual_size;
	result = page_address(frag->bv_page) + core->page_inuse;
	core->page_inuse += actual_size;
	skb_len_add(skb, actual_size);
	return result;
}

/**
 * homa_skb_page_alloc() - Allocate a new page for skb allocation for a
 * given core. Any existing page is released.
 * @homa:         Overall data about the Homa protocol implementation.
 * @core:         Allocate page in this core.
 * Return:       True if successful, false if memory not available.
 */
bool homa_skb_page_alloc(struct homa *homa, struct homa_core * core)
{
	struct homa_page_pool *pool;
	    __u64 start;
	if (core->skb_page) {
		if (page_ref_count(core->skb_page) == 1) {
			/* The existing page is no longer in use, so we can
			 * reuse it.
			 */
			core->page_inuse = 0;
			goto success;
		}
		put_page(core->skb_page);
	}

	/* Step 1: does this core have a stashed page? */
	core->page_size = HOMA_SKB_PAGE_SIZE;
	core->page_inuse = 0;
	if (core->num_stashed_pages > 0) {
		core->num_stashed_pages--;
		core->skb_page = core->stashed_pages[core->num_stashed_pages];
		goto success;
	}

	/* Step 2: can we retreive a page from the pool for this NUMA node? */
	pool = &core->numa->page_pool;
	if (pool->avail) {
		struct homa_page_pool *pool = &core->numa->page_pool;
		spin_lock_bh(&homa->page_pool_mutex);
		if (pool->avail) {
			pool->avail--;
			if (pool->avail < pool->low_mark)
				pool->low_mark = pool->avail;
			core->skb_page = pool->pages[pool->avail];
			spin_unlock_bh(&homa->page_pool_mutex);
			goto success;
		}
		spin_unlock_bh(&homa->page_pool_mutex);
	}

	/* Step 3: can we allocate a new big page? */
	INC_METRIC(skb_page_allocs, 1);
	start = get_cycles();
	core->skb_page = alloc_pages((GFP_KERNEL & ~__GFP_RECLAIM) | __GFP_COMP
			| __GFP_NOWARN | __GFP_NORETRY, HOMA_SKB_PAGE_ORDER);
	if (likely(core->skb_page)) {
		INC_METRIC(skb_page_alloc_cycles, get_cycles() - start);
		goto success;
	}

	/* Step 4: can we allocate a normal page? */
	core->skb_page = alloc_page(GFP_KERNEL);
	INC_METRIC(skb_page_alloc_cycles, get_cycles() - start);
	if (likely(core->skb_page)) {
		core->page_size = PAGE_SIZE;
		goto success;
	}
	core->page_size = core->page_inuse = 0;
	return false;

	success:
	return true;
}

/**
 * homa_skb_append_to_frag() - Append a block of data to an sk_buff
 * by allocating new space at the end of the frags area and copying the
 * data into that new space.
 * @homa:     Overall data about the Homa protocol implementation.
 * @skb:      Append to this sk_buff.
 * @buf:      Address of first byte of data to be appended.
 * @length:   Number of byte to append.
 * Return: 0 or a negative errno.
 */
int homa_skb_append_to_frag(struct homa *homa, struct sk_buff *skb, void *buf,
		int length)
{
	int chunk_length;
	char *src = (char *) buf;
	char *dst;

	while (length > 0) {
		chunk_length = length;
		dst = (char *) homa_skb_extend_frags(homa, skb, &chunk_length);
		if (!dst)
			return -ENOMEM;
		memcpy(dst, src, chunk_length);
		length -= chunk_length;
		src += chunk_length;
	}
	return 0;
}

/**
 * homa_skb_append_from_iter() - Append data to an sk_buff by allocating
 * new space at the end of the frags area and copying data into that space
 * @homa:     Overall data about the Homa protocol implementation.
 * @skb:      Append to this sk_buff.
 * @iter:     Describes location of data to append; modified to reflect
 *            copies data.
 * @length:   Number of byte to append; iter must have at least this many bytes.
 * Return: 0 or a negative errno.
 */
int homa_skb_append_from_iter(struct homa *homa, struct sk_buff *skb,
		struct iov_iter *iter, int length)
{
	int chunk_length;
	char *dst;

	while (length > 0)
	{
		chunk_length = length;
		dst = (char *) homa_skb_extend_frags(homa, skb, &chunk_length);
		if (!dst)
			return -ENOMEM;
		if (copy_from_iter(dst, chunk_length, iter) != chunk_length)
			return -EFAULT;
		length -= chunk_length;
	}
	return 0;
}

/**
 * homa_skb_append_from_skb() - Copy data from one skb to another. The
 * data is appended into new frags at the destination. The copies are done
 * virtually when possible.
 * @homa:        Overall data about the Homa protocol implementation.
 * @dst_skb:     Data gets added to the end of this skb.
 * @src_skb:     Data is copied out of this skb.
 * @offset:      Offset within @src_skb of first byte to copy, relative
 * 		 to the transport header.
 * @length:      Total number of bytes to copy; fewer bytes than this may
 *               be copied if @src_skb isn't long enough to hold all of the
 *               desired bytes.
 * Return:       0 for success or a negative errno if an error occurred.
 */
int homa_skb_append_from_skb(struct homa *homa, struct sk_buff *dst_skb,
		struct sk_buff *src_skb, int offset, int length)
{
	struct skb_shared_info *src_shinfo = skb_shinfo(src_skb);
	struct skb_shared_info *dst_shinfo = skb_shinfo(dst_skb);
	int src_frag_offset, src_frags_left, chunk_size, err, head_len;
	skb_frag_t *src_frag, *dst_frag;

	/* Copy bytes from the linear part of the source, if any. */
	head_len = skb_tail_pointer(src_skb) - skb_transport_header(src_skb);
	if (offset < head_len)
	{
		chunk_size = length;
		if (chunk_size > (head_len - offset))
			chunk_size = head_len - offset;
		err = homa_skb_append_to_frag(homa, dst_skb,
				skb_transport_header(src_skb) + offset,
				chunk_size);
		if (err)
			return err;
		offset += chunk_size;
		length -= chunk_size;
	}

        /* Virtually copy bytes from source frags, if needed. */
	src_frag_offset = head_len;
	for (src_frags_left = src_shinfo->nr_frags, src_frag = &src_shinfo->frags[0];
	    	(src_frags_left > 0) && (length > 0);
	     	src_frags_left--, src_frag_offset += src_frag->bv_len, src_frag++)
	{
		if (offset >= (src_frag_offset + src_frag->bv_len))
			continue;
		chunk_size = src_frag->bv_len - (offset - src_frag_offset);
		if (chunk_size > length)
			chunk_size = length;
		if (dst_shinfo->nr_frags == HOMA_MAX_SKB_FRAGS)
			return -EINVAL;
		dst_frag = &dst_shinfo->frags[dst_shinfo->nr_frags];
		dst_shinfo->nr_frags++;
		dst_frag->bv_page = src_frag->bv_page;
		get_page(src_frag->bv_page);
		dst_frag->bv_offset = src_frag->bv_offset
				+ (offset - src_frag_offset);
		dst_frag->bv_len = chunk_size;
		offset += chunk_size;
		length -= chunk_size;
		skb_len_add(dst_skb, chunk_size);
	}
	return 0;
}

/**
 * homa_skb_free_tx() - Release the storage for an sk_buff.
 * @homa:      Overall data about the Homa protocol implementation.
 * @skb:       sk_buff to free; should have been allocated by
 *             homa_skb_new_tx.
 */
void homa_skb_free_tx(struct homa *homa, struct sk_buff *skb)
{
	homa_skb_free_many_tx(homa, &skb, 1);
}

/**
 * homa_skb_free_many_tx() - Release the storage for multiple sk_buffs.
 * @homa:      Overall data about the Homa protocol implementation.
 * @skbs:      Pointer to first entry in array of sk_buffs to free.  All of
 *             these should have been allocated by homa_skb_new_tx.
 * @count:     Total number of sk_buffs to free.
 */
void homa_skb_free_many_tx(struct homa *homa, struct sk_buff **skbs, int count)
{
#ifdef __UNIT_TEST__
#define MAX_PAGES_AT_ONCE 3
#else
#define MAX_PAGES_AT_ONCE 50
#endif
	struct page *pages_to_cache[MAX_PAGES_AT_ONCE];
	int num_pages = 0;
	__u64 start = get_cycles();
	int i, j;

	for (i = 0; i < count; i++) {
		struct sk_buff *skb = skbs[i];
		struct skb_shared_info *shinfo = skb_shinfo(skb);

		if (refcount_read(&skb->users) != 1) {
			/* This sk_buff is still in use somewhere, so can't
			 * reclaim its pages. */
			kfree_skb(skb);
			continue;
		}

		/* Reclaim cacheable pages. */
		for (j = 0; j < shinfo->nr_frags; j++) {
			struct page *page = skb_frag_page(&shinfo->frags[j]);
			if ((compound_order(page) == HOMA_SKB_PAGE_ORDER)
					&& (page_ref_count(page) == 1)) {
				pages_to_cache[num_pages] = page;
				num_pages++;
				if (num_pages == MAX_PAGES_AT_ONCE) {
					homa_skb_cache_pages(homa, pages_to_cache,
							num_pages);
					num_pages = 0;
				}
			} else
				put_page(page);
		}
		shinfo->nr_frags = 0;
		kfree_skb(skb);
	}
	if (num_pages > 0)
		homa_skb_cache_pages(homa, pages_to_cache, num_pages);
	INC_METRIC(skb_frees, count);
	INC_METRIC(skb_free_cycles, get_cycles() - start);
}

/**
 * homa_skb_cache_pages() - Return pages to the global Homa cache of
 * pages for sk_buffs.
 * @homa:        Overall data about the Homa protocol implementation.
 * @pages:       Array of pages to cache.
 * @count:       Number of pages in @count.
 */
void homa_skb_cache_pages(struct homa *homa, struct page **pages, int count)
{
#ifdef __UNIT_TEST__
#define LIMIT 4
#else
#define LIMIT HOMA_PAGE_POOL_SIZE
#endif
	int i;
	spin_lock_bh(&homa->page_pool_mutex);
	for (i = 0; i < count; i++) {
		struct page *page = pages[i];
		struct homa_page_pool *pool =
				&homa_numas[page_to_nid(page)]->page_pool;
		if (pool->avail < LIMIT) {
			pool->pages[pool->avail] = page;
			pool->avail++;
		} else
			put_page(pages[i]);
	}
	spin_unlock_bh(&homa->page_pool_mutex);
}

/**
 * homa_skb_get() - Copy out part of the contents of a packet.
 * @skb:       sk_buff from which to copy data.
 * @dest:      Where to copy the data.
 * @offset:    Offset within skb of first byte to copy, measured
 *             relative to the transport header.
 * @length:    Total number of bytes to copy; will copy fewer bytes than
 *             this if the packet doesn't contain @length bytes at @offset.
 */
void homa_skb_get(struct sk_buff *skb, void *dest, int offset, int length)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	char *dst = (char *) dest;
	int chunk_size, frags_left, frag_offset, head_len;
	skb_frag_t *frag;

	/* Copy bytes from the linear part of the skb, if any. */
	head_len = skb_tail_pointer(skb) - skb_transport_header(skb);
	if (offset < head_len) {
		chunk_size = length;
		if (chunk_size > (head_len - offset))
			chunk_size = head_len - offset;
		memcpy(dst, skb_transport_header(skb) + offset, chunk_size);
		offset += chunk_size;
		length -= chunk_size;
		dst += chunk_size;
	}

	frag_offset = head_len;
	for (frags_left = shinfo->nr_frags, frag = &shinfo->frags[0];
			(frags_left > 0) && (length > 0);
			frags_left--, frag_offset += frag->bv_len, frag++) {
		if (offset >= (frag_offset + frag->bv_len))
			continue;
		chunk_size = frag->bv_len - (offset - frag_offset);
		if (chunk_size > length)
			chunk_size = length;
		memcpy(dst, page_address(frag->bv_page) + frag->bv_offset
				+ (offset - frag_offset),
				chunk_size);
		offset += chunk_size;
		length -= chunk_size;
		dst += chunk_size;
	}
}

/**
 * homa_skb_release_pages() - This function is invoked occasionally; it's
 * job is to gradually release pages from the sk_buff page pools back to
 * Linux, based on sysctl parameters such as skb_page_frees_per_sec.
 * @homa:  Overall information about the Homa transport.
 */
void homa_skb_release_pages(struct homa *homa)
{
	__u64 now = get_cycles();
	__s64 interval;
	int i, max_low_mark, min_pages, release, release_max;
	struct homa_page_pool *max_pool;

	if (now < homa->skb_page_free_time)
		return;

        /* Free pages every 0.5 second. */
	interval = cpu_khz*500;
	homa->skb_page_free_time = now + interval;
	release_max = homa->skb_page_frees_per_sec/2;
	if (homa->pages_to_free_slots < release_max) {
		if (homa->skb_pages_to_free != NULL)
			kfree(homa->skb_pages_to_free);
		homa->skb_pages_to_free = kmalloc(release_max *
				sizeof(struct page *), GFP_KERNEL);
		homa->pages_to_free_slots = release_max;
	}

	/* Find the pool with the largest low-water mark. */
	max_low_mark = -1;
	spin_lock_bh(&homa->page_pool_mutex);
	for (i = 0; i < homa_num_numas; i++) {
		struct homa_page_pool *pool = &homa_numas[i]->page_pool;
		if (pool->low_mark > max_low_mark) {
			max_low_mark = pool->low_mark;
			max_pool = pool;
		}
		tt_record3("NUMA node %d has %d pages in skb page pool, "
				"low mark %d", i, pool->avail, pool->low_mark);
		pool->low_mark = pool->avail;
	}

	/* Collect pages to free (but don't free them until after
	 * releasing the lock, since freeing is expensive).
	 */
	min_pages = ((homa->skb_page_pool_min_kb * 1000)
			+ (HOMA_SKB_PAGE_SIZE - 1))/ HOMA_SKB_PAGE_SIZE;
	release = max_low_mark - min_pages;
	if (release > release_max)
		release = release_max;
	for (i = 0; i < release; i++) {
		max_pool->avail--;
		homa->skb_pages_to_free[i] = max_pool->pages[max_pool->avail];
	}
	max_pool->low_mark = max_pool->avail;
	spin_unlock_bh(&homa->page_pool_mutex);

	/* Free the pages that were collected. */
	for (i = 0; i < release; i++) {
		struct page *page = homa->skb_pages_to_free[i];
		tt_record2("homa_skb_release_pages releasing page 0x%08x%08x",
				tt_hi(page), tt_lo(page));
		put_page(page);
	}
}