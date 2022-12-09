/* Copyright (c) 2022 Stanford University
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

#include "homa_impl.h"

/* Pools must always have at least this many active pages. */
#define MIN_ACTIVE 4

/* When running unit tests, allow HOMA_BPAGE_SIZE and HOMA_BPAGE_SHIFT
 * to be overriden.
 */
#ifdef __UNIT_TEST__
#include "mock.h"
#undef HOMA_BPAGE_SIZE
#define HOMA_BPAGE_SIZE mock_bpage_size
#undef HOMA_BPAGE_SHIFT
#define HOMA_BPAGE_SHIFT mock_bpage_shift
#endif

/**
 * homa_pool_init() - Initialize a homa_pool; any previous contents of the
 * objects are overwritten.
 * @pool:         Pool to initialize.
 * @homa          Overall information about Homa.
 * @region        First byte of the memory region for the pool, allocated
 *                by the application; must be page-aligned.
 * @region_size   Total number of bytes available at @buf_region.
 * Return: Either zero (for success) or a negative errno for failure.
 */
int homa_pool_init(struct homa_pool *pool, struct homa *homa,
		void *region, __u64 region_size)
{
	int i, result;

	if (((__u64) region) & ~PAGE_MASK)
		return -EINVAL;
	pool->cores = NULL;
	pool->region = (char *) region;
	pool->num_bpages = region_size >> HOMA_BPAGE_SHIFT;
	if (pool->num_bpages < MIN_ACTIVE) {
		result = -EINVAL;
		goto error;
	}
	pool->homa = homa;
	pool->descriptors = (struct homa_bpage *) kmalloc(
			pool->num_bpages * sizeof(struct homa_bpage),
			GFP_ATOMIC);
	if (!pool->descriptors) {
		result = -ENOMEM;
		goto error;
	}
	for (i = 0; i < pool->num_bpages; i++) {
		struct homa_bpage *bp = &pool->descriptors[i];
		spin_lock_init(&bp->lock);
		atomic_set(&bp->refs, 0);
		bp->owner = -1;
		bp->expiration = 0;
	}
	atomic_set(&pool->active_pages, MIN_ACTIVE);
	atomic_set(&pool->next_scan, 0);
	atomic_set(&pool->free_bpages_found, 0);

	/* Allocate and initialize core-specific data. */
	pool->cores = (struct homa_pool_core *) kmalloc(nr_cpu_ids *
			sizeof(struct homa_pool_core), GFP_ATOMIC);
	if (!pool->cores) {
		result = -ENOMEM;
		goto error;
	}
	pool->num_cores = nr_cpu_ids;
	for (i = 0; i < pool->num_cores; i++) {
		pool->cores[i].page_hint = 0;
		pool->cores[i].allocated = 0;
	}

	return 0;

	error:
	if (pool->descriptors)
		kfree(pool->descriptors);
	if (pool->cores)
		kfree(pool->cores);
	pool->region = NULL;
	return result;
}

/**
 * homa_pool_destroy() - Destructor for homa_pool. After this method
 * returns, the object should not be used unless it has been reinitialized.
 * @pool: Pool to destroy.
 */
void homa_pool_destroy(struct homa_pool *pool)
{
	if (!pool->region)
		return;
	kfree(pool->descriptors);
	kfree(pool->cores);
	pool->region = NULL;
}

/**
 * homa_pool_get_pages() - Allocate one or more full pages from the pool.
 * @pool:         Pool from which to allocate pages
 * @num_pages:    Number of pages needed
 * @pages:        The indices of the allocated pages are stored here; caller
 *                must ensure this array is big enough. Reference counts have
 *                been set to 1 on all of these pages.
 * @set_owner:    If nonzero, the current core is marked as owner of all
 *                of the allocated pages (and the expiration time is also
 *                set). Otherwises the pages are left unowned.
 * Return: 0 for success, -1 if there wasn't enough free space in the pool.
*/
int homa_pool_get_pages(struct homa_pool *pool, int num_pages, __u32 *pages,
		int set_owner)
{
	int alloced = 0;
	__u64 now = get_cycles();

	int active = atomic_read(&pool->active_pages);
	int i;

	while (1) {
		int cur = atomic_fetch_inc(&pool->next_scan);
		struct homa_bpage *bpage;

		if (cur >= active) {
			int free = atomic_read(&pool->free_bpages_found);
			if ((free == 0) && (active == pool->num_bpages)) {
				break;
			}
			if (active > 4*free) {
				/* < 25% of pages free; grow active pool. */
				active += num_pages - alloced;
				if (active > pool->num_bpages)
					active = pool->num_bpages;
				atomic_set(&pool->active_pages, active);
			} else if (2*free > active) {
				/* > 50% of pages free; shrink active
				 * pool by 10%.
				 */
				active -= active/10;
				atomic_set(&pool->active_pages,
						(active >= MIN_ACTIVE)
						? active : MIN_ACTIVE);
			}
			if (cur >= active) {
				atomic_set(&pool->free_bpages_found, 0);
				atomic_set(&pool->next_scan, 0);
				continue;
			}
		}

		bpage = &pool->descriptors[cur];
		/* Don't lock the bpage unless there is some chance we can
		 * use it. */
		if (atomic_read(&bpage->refs) || ((bpage->owner >= 0)
				&& (bpage->expiration > now)))
			continue;
		if (!spin_trylock_bh(&bpage->lock))
			continue;

		/* Must recheck after acquiring the lock (another core
		 * could have snuck in and grabbed the bpage).
		 */
		if (atomic_read(&bpage->refs) || ((bpage->owner >= 0)
				&& (bpage->expiration > now))) {
			spin_unlock_bh(&bpage->lock);
			continue;
		}
		atomic_inc(&pool->free_bpages_found);
		atomic_set(&bpage->refs, 1);
		if (set_owner) {
			bpage->owner = raw_smp_processor_id();
			bpage->expiration = now + pool->homa->bpage_lease_cycles;
		} else
			bpage->owner = -1;
		spin_unlock_bh(&bpage->lock);
		pages[alloced] = cur;
		alloced++;
		if (alloced == num_pages)
			return 0;
	}

	/* If we get here, it means we ran out of space in the pool. Free
	 * any pages already allocated. There's no need to lock the bpage
	 * before modifying it; the ref count provides sufficient protection.
	 */
	for (i = 0; i < alloced; i++) {
		struct homa_bpage *bpage = &pool->descriptors[pages[i]];
		bpage->owner = -1;
		atomic_set(&bpage->refs, 0);
	}
	return -1;
}

/**
 * homa_pool_allocate() - Allocate buffer space for an RPC.
 * @rpc:  RPC that needs space allocated for its incoming message (space must
 *        not already have been allocated). The fields @msgin->num_buffers
 *        and @msgin->buffers are filled in.
 * Return: 0 for success, -1 if space could not be allocated.
 */
int homa_pool_allocate(struct homa_rpc *rpc)
{
	struct homa_pool *pool = &rpc->hsk->buffer_pool;
	int full_pages, partial, i, core_id;
	__u32 pages[HOMA_MAX_BPAGES];
	struct homa_pool_core *core;
	struct homa_bpage *bpage;
	__u64 now = get_cycles();

	if (!pool->region)
		return -1;

	/* First allocate any full bpages that are needed. */
	full_pages = rpc->msgin.total_length >> HOMA_BPAGE_SHIFT;
	if (unlikely(full_pages)) {
		if (homa_pool_get_pages(pool, full_pages, pages, 0) != 0)
			return -1;
		for (i = 0; i < full_pages; i++)
			rpc->msgin.buffers[i] = pages[i] << HOMA_BPAGE_SHIFT;
	}
	rpc->msgin.num_buffers = full_pages;

	/* The last chunk may be less than a full bpage; for this we use
	 * a bpage that we own (and reuse for multiple messages).
	 */
	partial = rpc->msgin.total_length - (full_pages << HOMA_BPAGE_SHIFT);
	if (unlikely(partial == 0))
		return 0;
	core_id = raw_smp_processor_id();
	core = &pool->cores[core_id];
	bpage = &pool->descriptors[core->page_hint];
	if (!spin_trylock_bh(&bpage->lock)) {
		/* Someone else has the lock, which means they are stealing
		 * the bpage from us. Abandon it.
		 */
		goto new_page;
	}
	if (bpage->owner != core_id) {
		spin_unlock_bh(&bpage->lock);
		goto new_page;
	}
	if ((core->allocated + partial) > HOMA_BPAGE_SIZE) {
		if (atomic_read(&bpage->refs) > 0) {
			bpage->owner = -1;
			spin_unlock_bh(&bpage->lock);
			goto new_page;
		}
		/* Bpage is totally free, so we can reuse it. */
		core->allocated = 0;
		INC_METRIC(bpage_reuses, 1);
	}
	bpage->expiration = now + pool->homa->bpage_lease_cycles;
	atomic_inc(&bpage->refs);
	spin_unlock_bh(&bpage->lock);
	goto allocate_partial;

	/* Can't use the current page; get another one. */
	new_page:
	if (homa_pool_get_pages(pool, 1, pages, 1) != 0) {
		homa_pool_release_buffers(pool, rpc->msgin.num_buffers,
				rpc->msgin.buffers);
		rpc->msgin.num_buffers = 0;
		return -1;
	}
	core->page_hint = pages[0];
	core->allocated = 0;

	allocate_partial:
	rpc->msgin.buffers[rpc->msgin.num_buffers] = core->allocated
			+ (core->page_hint << HOMA_BPAGE_SHIFT);
	rpc->msgin.num_buffers++;
	core->allocated += partial;
	return 0;
}

/**
 * homa_pool_get_buffer() - Given an RPC, figure out where to store incoming
 * message data.
 * @rpc:        RPC for which incoming message data is being processed; its
 *              msgin must be properly initialized.
 * @offset:     Offset within @rpc's incoming message.
 * @available:  Will be filled in with the number of bytes of space available
 *              at the returned address.
 * Return:      The application's virtual address for buffer space corresponding
 *              to @offset in the incoming message for @rpc. 0 is returned if
 *              buffer space could not be allocated.
 */
void *homa_pool_get_buffer(struct homa_rpc *rpc, int offset, int *available)
{
	int bpage_index, bpage_offset;

	if (rpc->msgin.num_buffers == 0)
		if (homa_pool_allocate(rpc) != 0)
			return NULL;
	bpage_index = offset >> HOMA_BPAGE_SHIFT;
	BUG_ON(bpage_index >= rpc->msgin.num_buffers);
	bpage_offset = offset & (HOMA_BPAGE_SIZE-1);
	*available = (bpage_index < (rpc->msgin.num_buffers-1))
			? HOMA_BPAGE_SIZE - bpage_offset
			: rpc->msgin.total_length - offset;
	return rpc->hsk->buffer_pool.region + rpc->msgin.buffers[bpage_index]
			+ bpage_offset;
}

/**
 * homa_pool_release_buffers() - Release buffer space so that it can be
 * reused. This method may be invoked without holding any locks.
 * @pool:         Pool that the buffer space belongs to.
 * @num_buffers:  How many buffers to release.
 * @buffers:      Points to @num_buffers values, each of which is an offset
 *                from the start of the pool to the buffer to be released.
 */
void homa_pool_release_buffers(struct homa_pool *pool, int num_buffers,
		__u32 *buffers)
{
	int i;

	if (!pool->region)
		return;
	for (i = 0; i < num_buffers; i++) {
		__u32 bpage_index = buffers[i] >> HOMA_BPAGE_SHIFT;
		if (bpage_index < pool->num_bpages)
			 atomic_dec(&pool->descriptors[bpage_index].refs);
	}
}