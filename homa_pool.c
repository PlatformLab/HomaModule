// SPDX-License-Identifier: BSD-2-Clause

#include "homa_impl.h"
#ifndef __STRIP__ /* See strip.py */
#include "homa_grant.h"
#endif /* See strip.py */
#include "homa_pool.h"

/* This file contains functions that manage user-space buffer pools. */

/* Pools must always have at least this many bpages (no particular
 * reasoning behind this value).
 */
#define MIN_POOL_SIZE 2

/* Used when determining how many bpages to consider for allocation. */
#define MIN_EXTRA 4

#ifdef __UNIT_TEST__
/* When running unit tests, allow HOMA_BPAGE_SIZE and HOMA_BPAGE_SHIFT
 * to be overridden.
 */
#include "mock.h"
#undef HOMA_BPAGE_SIZE
#define HOMA_BPAGE_SIZE mock_bpage_size
#undef HOMA_BPAGE_SHIFT
#define HOMA_BPAGE_SHIFT mock_bpage_shift
#endif /* __UNIT_TEST__ */

/**
 * set_bpages_needed() - Set the bpages_needed field of @pool based
 * on the length of the first RPC that's waiting for buffer space.
 * The caller must own the lock for @pool->hsk.
 * @pool: Pool to update.
 */
static void set_bpages_needed(struct homa_pool *pool)
{
	struct homa_rpc *rpc = list_first_entry(&pool->hsk->waiting_for_bufs,
						struct homa_rpc, buf_links);

	pool->bpages_needed = (rpc->msgin.length + HOMA_BPAGE_SIZE - 1) >>
			      HOMA_BPAGE_SHIFT;
}

/**
 * homa_pool_alloc() - Allocate and initialize a new homa_pool (it will have
 * no region associated with it until homa_pool_set_region is invoked).
 * @hsk:          Socket the pool will be associated with.
 * Return: A pointer to the new pool or a negative errno.
 */
struct homa_pool *homa_pool_alloc(struct homa_sock *hsk)
{
	struct homa_pool *pool;

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return ERR_PTR(-ENOMEM);
	pool->hsk = hsk;
	return pool;
}

/**
 * homa_pool_set_region() - Associate a region of memory with a pool.
 * @hsk:          Socket whose pool the region will be associated with.
 *                Must not be locked, and the pool must not currently
 *                have a region associated with it.
 * @region:       First byte of the memory region for the pool, allocated
 *                by the application; must be page-aligned.
 * @region_size:  Total number of bytes available at @buf_region.
 * Return: Either zero (for success) or a negative errno for failure.
 */
int homa_pool_set_region(struct homa_sock *hsk, void __user *region,
			 u64 region_size)
{
	struct homa_pool_core __percpu *cores;
	struct homa_bpage *descriptors;
	int i, result, num_bpages;
	struct homa_pool *pool;

	if (((uintptr_t)region) & ~PAGE_MASK)
		return -EINVAL;

	/* Allocate memory before locking the socket, so we can allocate
	 * without GFP_ATOMIC.
	 */
	num_bpages = region_size >> HOMA_BPAGE_SHIFT;
	if (num_bpages < MIN_POOL_SIZE)
		return -EINVAL;
	descriptors = kmalloc_array(num_bpages, sizeof(struct homa_bpage),
				    __GFP_ZERO);
	if (!descriptors)
		return -ENOMEM;
	cores = alloc_percpu_gfp(struct homa_pool_core, __GFP_ZERO);
	if (!cores) {
		result = -ENOMEM;
		goto error;
	}

	homa_sock_lock(hsk);
	pool = hsk->buffer_pool;
	if (pool->region) {
		result = -EINVAL;
		homa_sock_unlock(hsk);
		goto error;
	}

	pool->region = (char __user *)region;
	pool->num_bpages = num_bpages;
	pool->descriptors = descriptors;
	atomic_set(&pool->free_bpages, pool->num_bpages);
	pool->bpages_needed = INT_MAX;
	pool->cores = cores;
	pool->check_waiting_invoked = 0;

	for (i = 0; i < pool->num_bpages; i++) {
		struct homa_bpage *bp = &pool->descriptors[i];

		spin_lock_init(&bp->lock);
		bp->owner = -1;
	}

	homa_sock_unlock(hsk);
	return 0;

error:
	kfree(descriptors);
	free_percpu(cores);
	return result;
}

/**
 * homa_pool_free() - Destructor for homa_pool. After this method
 * returns, the object should not be used (it will be freed here).
 * @pool: Pool to destroy.
 */
void homa_pool_free(struct homa_pool *pool)
{
	if (pool->region) {
		kfree(pool->descriptors);
		free_percpu(pool->cores);
		pool->region = NULL;
	}
	kfree(pool);
}

/**
 * homa_pool_get_rcvbuf() - Return information needed to handle getsockopt
 * for HOMA_SO_RCVBUF.
 * @pool:         Pool for which information is needed.
 * @args:         Store info here.
 */
void homa_pool_get_rcvbuf(struct homa_pool *pool,
			  struct homa_rcvbuf_args *args)
{
	args->start = (uintptr_t)pool->region;
	args->length = pool->num_bpages << HOMA_BPAGE_SHIFT;
}

/**
 * homa_bpage_available() - Check whether a bpage is available for use.
 * @bpage:      Bpage to check
 * @now:        Current time (homa_clock() units)
 * Return:      True if the bpage is free or if it can be stolen, otherwise
 *              false.
 */
bool homa_bpage_available(struct homa_bpage *bpage, u64 now)
{
	int ref_count = atomic_read(&bpage->refs);

	return ref_count == 0 || (ref_count == 1 && bpage->owner >= 0 &&
			bpage->expiration <= now);
}

/**
 * homa_pool_get_pages() - Allocate one or more full pages from the pool.
 * @pool:         Pool from which to allocate pages
 * @num_pages:    Number of pages needed
 * @pages:        The indices of the allocated pages are stored here; caller
 *                must ensure this array is big enough. Reference counts have
 *                been set to 1 on all of these pages (or 2 if set_owner
 *                was specified).
 * @set_owner:    If nonzero, the current core is marked as owner of all
 *                of the allocated pages (and the expiration time is also
 *                set). Otherwise the pages are left unowned.
 * Return: 0 for success, -1 if there wasn't enough free space in the pool.
 */
int homa_pool_get_pages(struct homa_pool *pool, int num_pages, u32 *pages,
			int set_owner)
{
	int core_num = smp_processor_id();
	struct homa_pool_core *core;
	u64 now = homa_clock();
	int alloced = 0;
	int limit = 0;

	core = this_cpu_ptr(pool->cores);
	if (atomic_sub_return(num_pages, &pool->free_bpages) < 0) {
		atomic_add(num_pages, &pool->free_bpages);
		return -1;
	}

	/* Once we get to this point we know we will be able to find
	 * enough free pages; now we just have to find them.
	 */
	while (alloced != num_pages) {
		struct homa_bpage *bpage;
		int cur;

		/* If we don't need to use all of the bpages in the pool,
		 * then try to use only the ones with low indexes. This
		 * will reduce the cache footprint for the pool by reusing
		 * a few bpages over and over. Specifically this code will
		 * not consider any candidate page whose index is >= limit.
		 * Limit is chosen to make sure there are a reasonable
		 * number of free pages in the range, so we won't have to
		 * check a huge number of pages.
		 */
		if (limit == 0) {
			int extra;

			limit = pool->num_bpages -
				atomic_read(&pool->free_bpages);
			extra = limit >> 2;
			limit += (extra < MIN_EXTRA) ? MIN_EXTRA : extra;
			if (limit > pool->num_bpages)
				limit = pool->num_bpages;
		}

		cur = core->next_candidate;
		core->next_candidate++;
		if (cur >= limit) {
			core->next_candidate = 0;

			/* Must recompute the limit for each new loop through
			 * the bpage array: we may need to consider a larger
			 * range of pages because of concurrent allocations.
			 */
			limit = 0;
			continue;
		}
		bpage = &pool->descriptors[cur];

		/* Figure out whether this candidate is free (or can be
		 * stolen). Do a quick check without locking the page, and
		 * if the page looks promising, then lock it and check again
		 * (must check again in case someone else snuck in and
		 * grabbed the page).
		 */
		if (!homa_bpage_available(bpage, now))
			continue;
		if (!spin_trylock_bh(&bpage->lock))
			/* Rather than wait for a locked page to become free,
			 * just go on to the next page. If the page is locked,
			 * it probably won't turn out to be available anyway.
			 */
			continue;
		if (!homa_bpage_available(bpage, now)) {
			spin_unlock_bh(&bpage->lock);
			continue;
		}
		if (bpage->owner >= 0)
			atomic_inc(&pool->free_bpages);
		if (set_owner) {
			atomic_set(&bpage->refs, 2);
			bpage->owner = core_num;
			bpage->expiration = now +
					    pool->hsk->homa->bpage_lease_cycles;
		} else {
			atomic_set(&bpage->refs, 1);
			bpage->owner = -1;
		}
		spin_unlock_bh(&bpage->lock);
		pages[alloced] = cur;
		alloced++;
	}
	return 0;
}

/**
 * homa_pool_alloc_msg() - Allocate buffer space for an incoming message.
 * @rpc:  RPC that needs space allocated for its incoming message (space must
 *        not already have been allocated). The fields @msgin->num_buffers
 *        and @msgin->buffers are filled in. Must be locked by caller.
 * Return: The return value is normally 0, which means either buffer space
 * was allocated or the @rpc was queued on @hsk->waiting. If a fatal error
 * occurred, such as no buffer pool present, then a negative errno is
 * returned.
 */
int homa_pool_alloc_msg(struct homa_rpc *rpc)
	__must_hold(&rpc->bucket->lock)
{
	struct homa_pool *pool = rpc->hsk->buffer_pool;
	int full_pages, partial, i, core_id;
	u32 pages[HOMA_MAX_BPAGES];
	struct homa_pool_core *core;
	struct homa_bpage *bpage;
	struct homa_rpc *other;

	if (!pool->region)
		return -ENOMEM;

	/* First allocate any full bpages that are needed. */
	full_pages = rpc->msgin.length >> HOMA_BPAGE_SHIFT;
	if (unlikely(full_pages)) {
		if (homa_pool_get_pages(pool, full_pages, pages, 0) != 0)
			goto out_of_space;
		for (i = 0; i < full_pages; i++)
			rpc->msgin.bpage_offsets[i] = pages[i] <<
					HOMA_BPAGE_SHIFT;
	}
	rpc->msgin.num_bpages = full_pages;

	/* The last chunk may be less than a full bpage; for this we use
	 * the bpage that we own (and reuse it for multiple messages).
	 */
	partial = rpc->msgin.length & (HOMA_BPAGE_SIZE - 1);
	if (unlikely(partial == 0))
		goto success;
	core_id = smp_processor_id();
	core = this_cpu_ptr(pool->cores);
	bpage = &pool->descriptors[core->page_hint];
#ifndef __STRIP__ /* See strip.py */
	if (!spin_trylock_bh(&bpage->lock)) {
		tt_record("beginning wait for bpage lock");
		spin_lock_bh(&bpage->lock);
		tt_record("ending wait for bpage lock");
	}
#else /* See strip.py */
	spin_lock_bh(&bpage->lock);
#endif /* See strip.py */
	if (bpage->owner != core_id) {
		spin_unlock_bh(&bpage->lock);
		goto new_page;
	}
	if ((core->allocated + partial) > HOMA_BPAGE_SIZE) {
#ifndef __STRIP__ /* See strip.py */
		if (atomic_read(&bpage->refs) == 1) {
			/* Bpage is totally free, so we can reuse it. */
			core->allocated = 0;
			INC_METRIC(bpage_reuses, 1);
#else /* See strip.py */
		if (atomic_read(&bpage->refs) == 1) {
			/* Bpage is totally free, so we can reuse it. */
			core->allocated = 0;
#endif /* See strip.py */
		} else {
			bpage->owner = -1;

			/* We know the reference count can't reach zero here
			 * because of check above, so we won't have to decrement
			 * pool->free_bpages.
			 */
			atomic_dec_return(&bpage->refs);
			spin_unlock_bh(&bpage->lock);
			goto new_page;
		}
	}
	bpage->expiration = homa_clock() +
			    pool->hsk->homa->bpage_lease_cycles;
	atomic_inc(&bpage->refs);
	spin_unlock_bh(&bpage->lock);
	goto allocate_partial;

	/* Can't use the current page; get another one. */
new_page:
	if (homa_pool_get_pages(pool, 1, pages, 1) != 0) {
		homa_pool_release_buffers(pool, rpc->msgin.num_bpages,
					  rpc->msgin.bpage_offsets);
		rpc->msgin.num_bpages = 0;
		goto out_of_space;
	}
	core->page_hint = pages[0];
	core->allocated = 0;

allocate_partial:
	rpc->msgin.bpage_offsets[rpc->msgin.num_bpages] = core->allocated
			+ (core->page_hint << HOMA_BPAGE_SHIFT);
	rpc->msgin.num_bpages++;
	core->allocated += partial;

success:
	tt_record4("Allocated %d bpage pointers on port %d for id %d, free_bpages now %d",
		   rpc->msgin.num_bpages, pool->hsk->port, rpc->id,
		   atomic_read(&pool->free_bpages));
	return 0;

	/* We get here if there wasn't enough buffer space for this
	 * message; add the RPC to hsk->waiting_for_bufs. The list is sorted
	 * by RPC length in order to implement SRPT.
	 */
out_of_space:
	INC_METRIC(buffer_alloc_failures, 1);
	tt_record4("Buffer allocation failed, port %d, id %d, length %d, free_bpages %d",
		   pool->hsk->port, rpc->id, rpc->msgin.length,
		   atomic_read(&pool->free_bpages));
	homa_sock_lock(pool->hsk);
	list_for_each_entry(other, &pool->hsk->waiting_for_bufs, buf_links) {
		if (other->msgin.length > rpc->msgin.length) {
			list_add_tail(&rpc->buf_links, &other->buf_links);
			goto queued;
		}
	}
	list_add_tail(&rpc->buf_links, &pool->hsk->waiting_for_bufs);

queued:
	set_bpages_needed(pool);
	homa_sock_unlock(pool->hsk);
	return 0;
}

/**
 * homa_pool_get_buffer() - Given an RPC, figure out where to store incoming
 * message data.
 * @rpc:        RPC for which incoming message data is being processed; its
 *              msgin must be properly initialized and buffer space must have
 *              been allocated for the message.
 * @offset:     Offset within @rpc's incoming message.
 * @available:  Will be filled in with the number of bytes of space available
 *              at the returned address (could be zero if offset is
 *              (erroneously) past the end of the message).
 * Return:      The application's virtual address for buffer space corresponding
 *              to @offset in the incoming message for @rpc.
 */
void __user *homa_pool_get_buffer(struct homa_rpc *rpc, int offset,
				  int *available)
{
	int bpage_index, bpage_offset;

	bpage_index = offset >> HOMA_BPAGE_SHIFT;
	if (offset >= rpc->msgin.length) {
		WARN_ONCE(true, "%s got offset %d >= message length %d\n",
			  __func__, offset, rpc->msgin.length);
		*available = 0;
		return NULL;
	}
	bpage_offset = offset & (HOMA_BPAGE_SIZE - 1);
	*available = (bpage_index < (rpc->msgin.num_bpages - 1))
			? HOMA_BPAGE_SIZE - bpage_offset
			: rpc->msgin.length - offset;
	return rpc->hsk->buffer_pool->region +
			rpc->msgin.bpage_offsets[bpage_index] + bpage_offset;
}

/**
 * homa_pool_release_buffers() - Release buffer space so that it can be
 * reused.
 * @pool:         Pool that the buffer space belongs to. Doesn't need to
 *                be locked.
 * @num_buffers:  How many buffers to release.
 * @buffers:      Points to @num_buffers values, each of which is an offset
 *                from the start of the pool to the buffer to be released.
 * Return:        0 for success, otherwise a negative errno.
 */
int homa_pool_release_buffers(struct homa_pool *pool, int num_buffers,
			      u32 *buffers)
{
	int result = 0;
	int i;

	if (!pool->region)
		return result;
	for (i = 0; i < num_buffers; i++) {
		u32 bpage_index = buffers[i] >> HOMA_BPAGE_SHIFT;
		struct homa_bpage *bpage = &pool->descriptors[bpage_index];

		if (bpage_index < pool->num_bpages) {
			if (atomic_dec_return(&bpage->refs) == 0)
				atomic_inc(&pool->free_bpages);
		} else {
			result = -EINVAL;
		}
	}
	tt_record3("Released %d bpages, free_bpages for port %d now %d",
		   num_buffers, pool->hsk->port,
		   atomic_read(&pool->free_bpages));
	return result;
}

/**
 * homa_pool_check_waiting() - Checks to see if there are enough free
 * bpages to wake up any RPCs that were blocked. Whenever
 * homa_pool_release_buffers is invoked, this function must be invoked later,
 * at a point when the caller holds no locks (homa_pool_release_buffers may
 * be invoked with locks held, so it can't safely invoke this function).
 * This is regrettably tricky, but I can't think of a better solution.
 * @pool:         Information about the buffer pool.
 */
void homa_pool_check_waiting(struct homa_pool *pool)
{
#ifdef __UNIT_TEST__
	pool->check_waiting_invoked += 1;
#endif /* __UNIT_TEST__ */
	if (!pool->region)
		return;
	while (atomic_read(&pool->free_bpages) >= pool->bpages_needed) {
		struct homa_rpc *rpc;

		homa_sock_lock(pool->hsk);
		if (list_empty(&pool->hsk->waiting_for_bufs)) {
			pool->bpages_needed = INT_MAX;
			homa_sock_unlock(pool->hsk);
			break;
		}
		rpc = list_first_entry(&pool->hsk->waiting_for_bufs,
				       struct homa_rpc, buf_links);
		if (!homa_rpc_try_lock(rpc)) {
			/* Can't just spin on the RPC lock because we're
			 * holding the socket lock and the lock order is
			 * rpc->socket (see sync.txt). Instead, release the
			 * socket lock and try the entire operation again.
			 */
			homa_sock_unlock(pool->hsk);
			UNIT_LOG("; ", "rpc lock unavailable in %s", __func__);
			continue;
		}
		list_del_init(&rpc->buf_links);
		if (list_empty(&pool->hsk->waiting_for_bufs))
			pool->bpages_needed = INT_MAX;
		else
			set_bpages_needed(pool);
		homa_sock_unlock(pool->hsk);
		tt_record4("Retrying buffer allocation for id %d, length %d, free_bpages %d, new bpages_needed %d",
			   rpc->id, rpc->msgin.length,
			   atomic_read(&pool->free_bpages),
			   pool->bpages_needed);
		homa_pool_alloc_msg(rpc);
#ifndef __STRIP__ /* See strip.py */
		if (rpc->msgin.num_bpages > 0) {
			/* Allocation succeeded; "wake up" the RPC. */
			rpc->msgin.resend_all = 1;
			homa_grant_init_rpc(rpc, 0);
			homa_grant_check_rpc(rpc);
		}
#endif /* See strip.py */
		homa_rpc_unlock(rpc);
	}
}
