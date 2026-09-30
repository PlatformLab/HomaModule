/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */

/* This file contains definitions used to manage user-space buffer pools.
 */

#ifndef _HOMA_POOL_H
#define _HOMA_POOL_H

#include <linux/percpu.h>

#include "homa_rpc.h"

/**
 * struct homa_pool_core - Holds core-specific data for a homa_pool: a
 * private bpage out of which that core allocates space for the partial
 * (final) bpages of messages. Note: we get exclusive access to the struct
 * for the current core by disabling BH (e.g., by acquiring a lock), which
 * prevents the thread from migrating to a different core.
 */
struct homa_pool_core {
	/**
	 * @page: Index of this core's private bpage, or -1 if the core
	 * doesn't currently own a bpage. While this is >= 0 the core
	 * holds one reference on the bpage.
	 */
	int page;

	/**
	 * @allocated: Number of (initial) bytes of @page that have already
	 * been allocated.
	 */
	int allocated;
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
	 * @lock: Protects @free_bpages, @free_stack, @waiting_for_bufs, and
	 * @shutdown. Always the innermost lock: no other lock may be
	 * acquired while holding it.
	 */
	spinlock_t lock;

	/** @free_bpages: Number of valid entries in @free_stack. */
	int free_bpages;

	/**
	 * @free_stack: Indices of bpages whose reference counts are zero;
	 * the first @free_bpages entries are valid. Used as a stack so
	 * that recently freed (and hence cache-warm) pages are reused first.
	 * Dynamically allocated.
	 */
	u32 *free_stack;

	/**
	 * @waiting_for_bufs: RPCs that are blocked waiting for bpages for
	 * their incoming message (linked via rpc->buf_links). Sorted in
	 * increasing order of message length. Must hold the RPC lock and
	 * @lock to add to the list; must hold @lock to remove.
	 */
	struct list_head waiting_for_bufs;

	/**
	 * @shutdown: Set by homa_pool_free; once set, @wakeup_work will not
	 * be scheduled again.
	 */
	bool shutdown;

	/**
	 * @hsk: the socket that this pool belongs to.
	 */
	struct homa_sock *hsk;

	/**
	 * @wakeup_work: used to execute homa_pool_wakeup_worker, which
	 * retries allocation for waiting RPCs in a context where no locks
	 * are held. (at the time when bpages are freed, locks may be held
	 * that conflict with the needs of homa_pool_wakeup_worker).
	 */
	struct work_struct wakeup_work;

	/**
	 * @region: beginning of the pool's region (in the app's virtual
	 * memory). Divided into bpages. 0 means the pool hasn't yet been
	 * initialized. This pointer is used for lock-free synchronization
	 * between a core creating the region and other cores attempting
	 * to use it.
	 */
	char __user *region;

	/** @num_bpages: total number of bpages in the pool. */
	int num_bpages;

	/**
	 * @refs: array of reference counts, one for each bpage. The reference
	 * count for a page includes 1 for each message that is using the page,
	 * plus 1 if the page is currently a core's private page. The page is
	 * on @free_stack if and only if its reference count is zero.
	 * Dynamically allocated.
	 */
	atomic_t *refs;

	/** @cores: core-specific info; dynamically allocated. */
	struct homa_pool_core __percpu *cores;
};

struct   homa_pool *homa_pool_alloc(struct homa_sock *hsk);
int      homa_pool_alloc_msg(struct homa_rpc *rpc);
u64      homa_pool_avail_bytes(struct homa_pool *pool);
void     homa_pool_check_waiting(struct homa_pool *pool);
void     homa_pool_enqueue(struct homa_pool *pool, struct homa_rpc *rpc);
void     homa_pool_free(struct homa_pool *pool);
void __user *homa_pool_get_buffer(struct homa_rpc *rpc, int offset,
				  int *available);
int      homa_pool_get_pages(struct homa_rpc *rpc, int num_pages, u32 *pages);
void     homa_pool_get_rcvbuf(struct homa_pool *pool,
			      struct homa_rcvbuf_args *args);
int      homa_pool_free_bufs(struct homa_pool *pool, int num_buffers,
			     u32 *buffers);
void     homa_pool_lock_slow(struct homa_pool *pool);
int      homa_pool_set_region(struct homa_pool *pool, void __user *region,
			      u64 region_size);
void     homa_pool_wakeup_rpc(struct homa_rpc *rpc);
void     homa_pool_wakeup_worker(struct work_struct *work);

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_pool_lock() - Acquire the lock for a buffer pool. If the pool
 * isn't immediately available, record stats on the waiting time.
 * @pool:     Buffer pool to lock.
 */
static inline void homa_pool_lock(struct homa_pool *pool)
	__acquires(pool->lock)
{
	if (!spin_trylock_bh(&pool->lock))
		homa_pool_lock_slow(pool);
}
#else /* See strip.py */
/**
 * homa_pool_lock() - Acquire the lock for a buffer pool.
 * @pool:     Buffer pool to lock.
 */
static inline void homa_pool_lock(struct homa_pool *pool)
	__acquires(pool->lock)
{
	spin_lock_bh(&pool->lock);
}
#endif /* See strip.py */

/**
 * homa_pool_unlock() - Release the lock for a buffer pool.
 * @hsk:   Buffer pool to unlock.
 */
static inline void homa_pool_unlock(struct homa_pool *pool)
	__releases(pool->lock)
{
	spin_unlock_bh(&pool->lock);
}

/**
 * homa_pool_unlink() - Remove an RPC from any lists related to buffer
 * pool memory, so the RPC will not be accessed by this module again.
 * @rpc:     RPC to unlink. Must be locked.
 */
static inline void homa_pool_unlink(struct homa_rpc *rpc)
	__must_hold(rpc->bucket->lock)
{
	struct homa_pool *pool;

	/* An RPC is added to waiting_for_bufs only by code that holds the
	 * RPC's lock, so this check needs no pool lock; most RPCs don't wait
	 * for buffers, so we avoid having to lock the pool.
	 */
	if (list_empty(&rpc->buf_links))
		return;
	pool = rpc->hsk->buffer_pool;
	homa_pool_lock(pool);
	list_del_init(&rpc->buf_links);
	homa_pool_unlock(pool);
}

/**
 * homa_pool_release() - Invoked when RPCs are being reaped: releases
 * pool space owned by the RPC.
 * @rpc:        RPC to clean up. Caller must ensure that no-one else can
 *              access the RPC concurrently (e.g., it is being reaped).
 */
static inline void homa_pool_release(struct homa_rpc *rpc)
{
	if (rpc->msgin.num_bpages > 0) {
		homa_pool_free_bufs(rpc->hsk->buffer_pool,
				    rpc->msgin.num_bpages,
				    rpc->msgin.bpage_offsets);
		rpc->msgin.num_bpages = 0;
	}
}

/**
 * homa_pool_exists() - Determine whether a pool has been fully initialized
 * with a memory region.
 * @pool:     Pool to check.
 * Return:    True if there is a memory region associated with the pool,
 *            false if SO_HOMA_RCVBUF hasn't been invoked for the socket.
 */
static inline bool homa_pool_exists(struct homa_pool *pool)
{
	/* This barrier allows lockless concurrent allocation of the pool:
	 * it ensures that if the pool exists we'll see all of the initialized
	 * values related to the pool.
	 */
	return smp_load_acquire(&pool->region) != NULL;
}

/**
 * homa_pool_push_free() - Return a bpage whose reference count has just
 * reached zero to the free stack.
 * @pool:   Pool containing the bpage. Must be locked by caller.
 * @index:  Index of the bpage.
 */
static inline void homa_pool_push_free(struct homa_pool *pool, u32 index)
	__must_hold(pool->lock)
{
	WARN_ON_ONCE(pool->free_bpages >= pool->num_bpages);
	pool->free_stack[pool->free_bpages] = index;
	pool->free_bpages++;
}

/**
 * homa_pool_head_fits() - Determine whether there is now enough free
 * space for the first RPC waiting for buffers.
 * @pool:   Pool of interest. Must be locked by caller.
 * Return:  True if there is a waiting RPC and its message would fit in
 *          the bpages that are currently free; false otherwise.
 */
static inline bool homa_pool_head_fits(struct homa_pool *pool)
	__must_hold(pool->lock)
{
	struct homa_rpc *rpc;
	int pages_needed;

	if (list_empty(&pool->waiting_for_bufs))
		return false;
	rpc = list_first_entry(&pool->waiting_for_bufs, struct homa_rpc,
			       buf_links);
	pages_needed = (rpc->msgin.length + HOMA_BPAGE_SIZE - 1) >>
		       HOMA_BPAGE_SHIFT;
	return pool->free_bpages >= pages_needed;
}

#endif /* _HOMA_POOL_H */
