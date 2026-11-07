// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

#include "homa_impl.h"
#ifndef __STRIP__ /* See strip.py */
#include "homa_grant.h"
#endif /* See strip.py */
#include "homa_pool.h"

/* This file contains functions that manage user-space buffer pools for
 * incoming messges.
 */

/**
 * homa_pool_alloc() - Allocate and initialize a new homa_pool (it will have
 * no region associated with it until homa_pool_set_region is invoked).
 * @hsk:          Socket the pool will be associated with.
 * Return: A pointer to the new pool or a negative errno.
 */
struct homa_pool *homa_pool_alloc(struct homa_sock *hsk)
{
	struct homa_pool *pool;

	pool = kzalloc(sizeof(*pool), GFP_KERNEL_ACCOUNT);
	if (!pool)
		return ERR_PTR(-ENOMEM);
	spin_lock_init(&pool->lock);
	INIT_LIST_HEAD(&pool->waiting_for_bufs);
	pool->hsk = hsk;
	INIT_WORK(&pool->wakeup_work, homa_pool_wakeup_worker);
	return pool;
}

/**
 * homa_pool_set_region() - Associate a region of memory with a pool.
 * @pool:         Buffer pool the region will be associated with. Must not
 *                currently have a region associated with it.
 * @region:       First byte of the memory region for the pool, allocated
 *                by the application; must be page-aligned.
 * @region_size:  Total number of bytes available at @buf_region.
 * Return: Either zero (for success) or a negative errno for failure.
 */
int homa_pool_set_region(struct homa_pool *pool, void __user *region,
			 u64 region_size)
{
	struct homa_pool_core __percpu *cores = NULL;
	int i, result, num_bpages, cpu;
	u32 *free_stack;
	atomic_t *refs;
	u64 min_size;

	if (((uintptr_t)region) & ~PAGE_MASK) {
		pool->hsk->error_msg = "buffer pool is not page aligned";
		return -EINVAL;
	}

	/* The region must be large enough to hold a private bpage for
	 * each core, plus enough additional space for a couple of
	 * full-size messages.
	 */
	min_size = nr_cpu_ids;
	min_size = min_size * HOMA_BPAGE_SIZE + 2 * HOMA_MAX_MESSAGE_LENGTH;
	if (region_size < min_size) {
		pool->hsk->error_msg = "buffer pool is not large enough";
		return -EINVAL;
	}

	/* The region must not be so large that offsets into the region
	 * overflow the 32-bit values used in bpage_offsets in
	 * homa_recvmsg_args.
	 */
	if (region_size > 0x100000000ULL) {
		pool->hsk->error_msg = "buffer pool cannot be larger than 4 GB";
		return -EINVAL;
	}

	/* Allocate memory before locking the pool, so we can allocate
	 * without GFP_ATOMIC.
	 */
	num_bpages = region_size >> HOMA_BPAGE_SHIFT;
	refs = kmalloc_array(num_bpages, sizeof(atomic_t),
			     GFP_KERNEL | __GFP_ZERO | __GFP_ACCOUNT |
			     __GFP_NOWARN);
	if (!refs)
		return -ENOMEM;
	free_stack = kmalloc_array(num_bpages, sizeof(*free_stack),
				   GFP_KERNEL | __GFP_ACCOUNT | __GFP_NOWARN);
	if (!free_stack) {
		result = -ENOMEM;
		goto error;
	}
	cores = alloc_percpu_gfp(struct homa_pool_core,
				 GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!cores) {
		result = -ENOMEM;
		goto error;
	}

	/* Stack the pages so that low-numbered pages are allocated first. */
	for (i = 0; i < num_bpages; i++)
		free_stack[i] = num_bpages - 1 - i;
	for_each_possible_cpu(cpu)
		per_cpu_ptr(cores, cpu)->page = -1;

	homa_pool_lock(pool);
	if (pool->region) {
		result = -EINVAL;
		homa_pool_unlock(pool);
		goto error;
	}

	pool->free_bpages = num_bpages;
	pool->free_stack = free_stack;
	pool->num_bpages = num_bpages;
	pool->refs = refs;
	pool->cores = cores;

	/* Barrier ensures that concurrent cores trying to access
	 * newly-created region will see all the region's data.
	 */
	smp_store_release(&pool->region, (char __user *)region);
	homa_pool_unlock(pool);
	return 0;

error:
	kfree(refs);
	kfree(free_stack);
	free_percpu(cores);
	return result;
}

/**
 * homa_pool_free() - Destructor for homa_pool. After this method
 * returns, the object should not be used (it will be freed here).
 * Must be called in a context that can sleep.
 * @pool: Pool to destroy.
 */
void homa_pool_free(struct homa_pool *pool)
{
#ifdef __UNIT_TEST__
	mock_free_pool(pool);
#endif /* __UNIT_TEST__ */

	/* Ensure the wakeup work isn't running and won't run again. */
	homa_pool_lock(pool);
	pool->shutdown = true;
	homa_pool_unlock(pool);
	cancel_work_sync(&pool->wakeup_work);

	if (homa_pool_exists(pool)) {
		kfree(pool->free_stack);
		kfree(pool->refs);
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
	args->length = (u64)pool->num_bpages << HOMA_BPAGE_SHIFT;
}

/**
 * homa_pool_get_pages() - Allocate one or more full pages from a pool.
 * If there isn't enough free space, @rpc is queued on @pool->waiting_for_bufs
 * instead (unless it is dead).
 * @rpc:          RPC on whose behalf the pages are being allocated. Must
 *                be locked by caller.
 * @num_pages:    Number of pages needed.
 * @pages:        The indices of the allocated pages are stored here; caller
 *                must ensure this array is large enough. The reference count
 *                of each allocated page is set to 1.
 * Return: 0 for success, -1 if there wasn't enough free space in the pool
 * (in which case @rpc has been queued).
 */
int homa_pool_get_pages(struct homa_rpc *rpc, int num_pages, u32 *pages)
	__must_hold(rpc->bucket->lock)
{
	struct homa_pool *pool = rpc->hsk->buffer_pool;
	int i, num_free;

	homa_pool_lock(pool);
	num_free = pool->free_bpages;
	if (num_free < num_pages) {
		homa_pool_enqueue(pool, rpc);
		homa_pool_unlock(pool);
		INC_METRIC(buffer_alloc_failures, 1);
		tt_record4("Buffer allocation failed, port %d, id %d, length %d, free_bpages %d",
			   pool->hsk->port, rpc->id, rpc->msgin.length,
			   num_free);
		return -1;
	}
	for (i = 0; i < num_pages; i++) {
		pool->free_bpages--;
		pages[i] = pool->free_stack[pool->free_bpages];
		atomic_set(&pool->refs[pages[i]], 1);
	}
	homa_pool_unlock(pool);
	return 0;
}

/**
 * homa_pool_enqueue() - Add an RPC to the list of those waiting for
 * buffer space, keeping the list sorted by message length (SRPT).
 * @pool:   Pool of interest. Must be locked by caller.
 * @rpc:    RPC that couldn't get buffer space. Must be locked by caller.
 */
void homa_pool_enqueue(struct homa_pool *pool, struct homa_rpc *rpc)
	__must_hold(pool->lock)
	__must_hold(rpc->bucket->lock)
{
	struct homa_rpc *other;

	if (rpc->state == RPC_DEAD || WARN_ON_ONCE(!list_empty(&rpc->buf_links)))
		return;

	/* Find the first queued RPC that is longer than @rpc. If there is
	 * none, &other->buf_links ends up pointing to the list head, so
	 * @rpc is added at the tail.
	 */
	list_for_each_entry(other, &pool->waiting_for_bufs, buf_links) {
		if (other->msgin.length > rpc->msgin.length)
			break;
	}
	list_add_tail(&rpc->buf_links, &other->buf_links);
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
	__must_hold(rpc->bucket->lock)
{
	struct homa_pool *pool = rpc->hsk->buffer_pool;
	int full_pages, partial, pages_needed, i;
	struct homa_pool_core *core = NULL;
	u32 pages[HOMA_MAX_BPAGES];

	if (!homa_pool_exists(pool))
		return -ENOMEM;

	full_pages = rpc->msgin.length >> HOMA_BPAGE_SHIFT;
	partial = rpc->msgin.length & (HOMA_BPAGE_SIZE - 1);
	pages_needed = full_pages;

	/* If there is a partial page at the end of the message, try to
	 * allocate it in this core's private page. If that isn't possible,
	 * we'll get a new private page along with any full pages, so that
	 * all of the full pages come from a single call to
	 * homa_pool_get_pages: then a failure never leaves anything to
	 * give back.
	 */
	if (partial != 0) {
		/* Note: we can't migrate to a different core because of the
		 * lock on @rpc.
		 */
		core = this_cpu_ptr(pool->cores);
		if (core->page >= 0 &&
		    core->allocated + partial > HOMA_BPAGE_SIZE) {
			/* A reference count of 1 means there are no messages
			 * using this page, so we can reuse it from the
			 * beginning.
			 */
			if (atomic_read(&pool->refs[core->page])
			    == 1) {
				core->allocated = 0;
				INC_METRIC(bpage_reuses, 1);
			} else {
				int index = core->page;

				/* Must check for a race where the other refs
				 * got dropped just after we checked.
				 */
				UNIT_HOOK("rx_pool_race");
				if (atomic_dec_if_positive(&pool->refs[index]) == 0) {
					homa_pool_lock(pool);
					homa_pool_push_free(pool, index);
					homa_pool_check_waiting(pool);
					homa_pool_unlock(pool);
				}
				core->page = -1;
			}
		}
		if (core->page < 0)
			pages_needed++;
	}

	if (pages_needed > 0 &&
	    homa_pool_get_pages(rpc, pages_needed, pages) != 0)
		return 0;

	/* Fill in the full bpages. */
	for (i = 0; i < full_pages; i++)
		rpc->msgin.bpage_offsets[i] = pages[i] << HOMA_BPAGE_SHIFT;
	rpc->msgin.num_bpages = full_pages;

	/* Fill in a partial final page, if needed. */
	if (partial != 0) {
		if (pages_needed > full_pages) {
			/* Must update the core for the new private page. */
			core->page = pages[full_pages];
			core->allocated = 0;
		}
		atomic_inc(&pool->refs[core->page]);
		rpc->msgin.bpage_offsets[rpc->msgin.num_bpages] =
				((u32)core->page << HOMA_BPAGE_SHIFT) +
				core->allocated;
		rpc->msgin.num_bpages++;
		core->allocated += partial;
	}

	tt_record4("Allocated %d bpage pointers on port %d for id %d, num_free now %d",
		   rpc->msgin.num_bpages, pool->hsk->port, rpc->id,
		   data_race(pool->free_bpages));
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
 * homa_pool_free_bufs() - Release buffer space so that it can be reused.
 * @pool:         Pool that the buffer space belongs to. Doesn't need to
 *                be locked.
 * @num_buffers:  How many buffers to release.
 * @buffers:      Points to @num_buffers values, each of which is an offset
 *                from the start of the pool to the buffer to be released.
 * Return:        0 for success, otherwise a negative errno.
 */
int homa_pool_free_bufs(struct homa_pool *pool, int num_buffers, u32 *buffers)
{
#ifndef __UPSTREAM__ /* See strip.py */
	int freed_pages = 0;
#endif /* See strip.py */
	int i, result = 0;
	bool locked = false;

	/* Note: a misbehaving application could free the same offset
	 * multiple times, which could cause buffer space to be shared
	 * across RPCs. The refs check below catches the most obvious
	 * cases, but not all of them. Fortunately, the resulting
	 * corruption affects only the misbehaving application (buffer
	 * pools are not shared across applications).
	 */

	if (!homa_pool_exists(pool))
		return -EINVAL;
	for (i = 0; i < num_buffers; i++) {
		u32 bpage_index = buffers[i] >> HOMA_BPAGE_SHIFT;
		int refs;

		if (bpage_index >= pool->num_bpages) {
			result = -EINVAL;
			break;
		}
		refs = atomic_dec_if_positive(&pool->refs[bpage_index]);
		if (refs < 0) {
			/* Page was already free. */
			result = -EINVAL;
			continue;
		}
		if (refs == 0) {
			/* Take the pool lock once, for all freed pages. */
			if (!locked) {
				homa_pool_lock(pool);
				locked = true;
			}
			homa_pool_push_free(pool, bpage_index);
#ifndef __UPSTREAM__ /* See strip.py */
			freed_pages++;
#endif /* See strip.py */
		}
	}
	if (locked) {
		homa_pool_check_waiting(pool);
		homa_pool_unlock(pool);
	}
	tt_record4("Released %d bpage refs, freed %d bpages, free_bpages now %d; port %d",
		   num_buffers, freed_pages, data_race(pool->free_bpages),
		   pool->hsk->port);
	return result;
}

/**
 * homa_pool_check_waiting() - This function is typically invoked after
 * bpages have been freed. If the pool now contains enough free pages for
 * waiting RPC(s) to restart, arrange for that to happen (asynchronously).
 * @pool:      Pool to check.
 */
void homa_pool_check_waiting(struct homa_pool *pool)
	__must_hold(pool->lock)
{
	if (pool->shutdown || !homa_pool_head_fits(pool))
		return;
	queue_work(system_bh_wq, &pool->wakeup_work);
}

/**
 * homa_pool_wakeup_worker() - This function is invoked through the worker
 * mechanism to check for RPCs waiting on a buffer pool and wakeup those
 * whose memory needs can now be met.
 * @work:   The wakeup_work field of a homa_pool.
 */
void homa_pool_wakeup_worker(struct work_struct *work)
{
	struct homa_pool *pool = container_of(work, struct homa_pool,
					      wakeup_work);
	struct homa_rpc *rpc;

	if (!homa_pool_exists(pool))
		return;

	while (1) {
		homa_pool_lock(pool);
		if (pool->shutdown || !homa_pool_head_fits(pool)) {
			homa_pool_unlock(pool);
			break;
		}
		rpc = list_first_entry(&pool->waiting_for_bufs,
				       struct homa_rpc, buf_links);
		list_del_init(&rpc->buf_links);

		/* Take a reference to keep the RPC alive after we release
		 * the pool lock (the RPCs presence on the waiting list has
		 * been keeping it alive, but once we release the pool lock
		 * homa_pool_unlink can complete and the RPC can be freed).
		 */
		homa_rpc_hold(rpc);
		homa_pool_unlock(pool);

		homa_rpc_lock(rpc);
		if (rpc->state != RPC_DEAD) {
			tt_record3("Retrying buffer allocation for id %d, port %d, length %d",
					rpc->id, rpc->hsk->port,
					rpc->msgin.length);
			homa_pool_alloc_msg(rpc);
			if (rpc->msgin.num_bpages > 0)
				homa_pool_wakeup_rpc(rpc);
		}
		homa_rpc_unlock(rpc);
		homa_rpc_put(rpc);
	}
}

/**
 * homa_pool_wakeup_rpc() - This function is invoked when an RPC that had
 * blocked waiting for buffer space finally gets the space it needs. It
 * arranges for transmission of the RPC's data to resume.
 * @rpc:    RPC to wake up
 */
void homa_pool_wakeup_rpc(struct homa_rpc *rpc)
	__must_hold(rpc->bucket->lock)
{
	struct homa_resend_hdr resend;

#ifndef __STRIP__ /* See strip.py */
	/* If the RPC is scheduled, all we have to do is issue a grant. */
	if (test_bit(RPC_GRANTABLE, &rpc->flags)) {
		homa_grant_check_rpc(rpc);
		return;
	}
#endif /* See strip.py */

	/* Unscheduled: must ask for the message to be retransmitted. */
	resend.offset = htonl(0);
	resend.length = htonl(rpc->msgin.length);

#ifndef __STRIP__ /* See strip.py */
	/* Use the next-to-highest priority level to provide a priority boost
	 * without interfering with the highest priority traffic such as
	 * control packets.
	 */
	resend.priority = homa_high_priority(rpc->hsk->homa);
#endif /* See strip.py */
	homa_xmit_control(RESEND, &resend, sizeof(resend), rpc);
}

/**
 * homa_pool_avail_bytes() - Return a count of the number of bytes currently
 * unused and available for allocation in a pool.
 * @pool:    Pool of interest.
 * Return:    See above.
 */
u64 homa_pool_avail_bytes(struct homa_pool *pool)
{
	u64 avail;
	int cpu;

	if (!homa_pool_exists(pool))
		return 0;
	avail = (u64)READ_ONCE(pool->free_bpages) << HOMA_BPAGE_SHIFT;
	for_each_possible_cpu(cpu) {
		struct homa_pool_core *core = per_cpu_ptr(pool->cores, cpu);
		int page;

		/* The code below is unsynchronized, which means it could
		 * produce inaccurate results (but it won't crash).
		 */
		page = READ_ONCE(core->page);
		if (page >= 0) {
			if (atomic_read(&pool->refs[page]) > 1)
				avail += HOMA_BPAGE_SIZE -
					 data_race(core->allocated);
			else
				avail += HOMA_BPAGE_SIZE;
		}
	}
	return avail;
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_pool_lock_slow() - This function implements the slow path for
 * acquiring the lock for a buffer pool. It is invoked when the lock isn't
 * immediately available. It waits for the lock but also records statistics
 * about the waiting time.
 * @pool:    Buffer pool to  lock.
 */
void homa_pool_lock_slow(struct homa_pool *pool)
	__acquires(pool->lock)
{
	u64 start = homa_clock();

	tt_record("beginning wait for bpool lock");
	spin_lock_bh(&pool->lock);
	tt_record("ending wait for bpool lock");
	INC_METRIC(bpool_lock_misses, 1);
	INC_METRIC(bpool_lock_miss_cycles, homa_clock() - start);
}
#endif /* See strip.py */
