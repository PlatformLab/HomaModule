/* SPDX-License-Identifier: BSD-2-Clause */

/* This file defines structs and other things related to Homa sockets.  */

#ifndef _HOMA_SOCK_H
#define _HOMA_SOCK_H

/* Forward declarations. */
struct homa;
struct homa_pool;

#ifndef __STRIP__ /* See strip.py */
void     homa_sock_lock_slow(struct homa_sock *hsk);
#endif /* See strip.py */

/* Number of hash buckets in a homa_socktab. Must be a power of 2. */
#define HOMA_SOCKTAB_BUCKET_BITS 10
#define HOMA_SOCKTAB_BUCKETS BIT(HOMA_SOCKTAB_BUCKET_BITS)

/**
 * struct homa_socktab - A hash table that maps from port numbers (either
 * client or server) to homa_sock objects.
 *
 * This table is managed exclusively by homa_socktab.c, using RCU to
 * minimize synchronization during lookups.
 */
struct homa_socktab {
	/**
	 * @write_lock: Controls all modifications to this object; not needed
	 * for socket lookups (RCU is used instead). Also used to
	 * synchronize port allocation.
	 */
	spinlock_t write_lock;

	/**
	 * @buckets: Heads of chains for hash table buckets. Chains
	 * consist of homa_sock objects.
	 */
	struct hlist_head buckets[HOMA_SOCKTAB_BUCKETS];
};

/**
 * struct homa_socktab_scan - Records the state of an iteration over all
 * the entries in a homa_socktab, in a way that is safe against concurrent
 * reclamation of sockets.
 */
struct homa_socktab_scan {
	/** @socktab: The table that is being scanned. */
	struct homa_socktab *socktab;

	/**
	 * @hsk: Points to the current socket in the iteration, or NULL if
	 * we're at the beginning or end of the iteration. If non-NULL then
	 * we are holding a reference to this socket.
	 */
	struct homa_sock *hsk;

	/**
	 * @current_bucket: The index of the bucket in socktab->buckets
	 * currently being scanned (-1 if @hsk == NULL).
	 */
	int current_bucket;
};

/**
 * struct homa_rpc_bucket - One bucket in a hash table of RPCs.
 */

struct homa_rpc_bucket {
	/**
	 * @lock: serves as a lock both for this bucket (e.g., when
	 * adding and removing RPCs) and also for all of the RPCs in
	 * the bucket. Must be held whenever looking up an RPC in
	 * this bucket or manipulating an RPC in the bucket. This approach
	 * has the following properties:
	 * 1. An RPC can be looked up and locked (a common operation) with
	 *    a single lock acquisition.
	 * 2. Looking up and locking are atomic: there is no window of
	 *    vulnerability where someone else could delete an RPC after
	 *    it has been looked up and before it has been locked.
	 * 3. The lookup mechanism does not use RCU.  This is important because
	 *    RPCs are created rapidly and typically live only a few tens of
	 *    microseconds.  As of May 2027 RCU introduces a lag of about
	 *    25 ms before objects can be deleted; for RPCs this would result
	 *    in hundreds or thousands of RPCs accumulating before RCU allows
	 *    them to be deleted.
	 * This approach has the disadvantage that RPCs within a bucket share
	 * locks and thus may not be able to work concurrently, but there are
	 * enough buckets in the table to make such colllisions rare.
	 *
	 * See "Homa Locking Strategy" in homa_impl.h for more info about
	 * locking.
	 */
	spinlock_t lock __context__(rpc_bucket_lock, 1, 1);

	/**
	 * @id: identifier for this bucket, used in error messages etc.
	 * It's the index of the bucket within its hash table bucket
	 * array, with an additional offset to separate server and
	 * client RPCs.
	 */
	int id;

	/** @rpcs: list of RPCs that hash to this bucket. */
	struct hlist_head rpcs;
};

/**
 * define HOMA_CLIENT_RPC_BUCKETS - Number of buckets in hash tables for
 * client RPCs. Must be a power of 2.
 */
#define HOMA_CLIENT_RPC_BUCKETS 1024

/**
 * define HOMA_SERVER_RPC_BUCKETS - Number of buckets in hash tables for
 * server RPCs. Must be a power of 2.
 */
#define HOMA_SERVER_RPC_BUCKETS 1024

/**
 * struct homa_sock - Information about an open socket.
 */
struct homa_sock {
	/* Info for other network layers. Note: IPv6 info (struct ipv6_pinfo
	 * comes at the very end of the struct, *after* Homa's data, if this
	 * socket uses IPv6).
	 */
	union {
		/** @sock: generic socket data; must be the first field. */
		struct sock sock;

		/**
		 * @inet: generic Internet socket data; must also be the
		 first field (contains sock as its first member).
		 */
		struct inet_sock inet;
	};

	/**
	 * @homa: Overall state about the Homa implementation. NULL
	 * means this socket was never initialized or has been deleted.
	 */
	struct homa *homa;

	/**
	 * @hnet: Overall state specific to the network namespace for
	 * this socket.
	 */
	struct homa_net *hnet;

	/**
	 * @buffer_pool: used to allocate buffer space for incoming messages.
	 * Storage is dynamically allocated.
	 */
	struct homa_pool *buffer_pool;

	/**
	 * @port: Port number: identifies this socket uniquely among all
	 * those on this node.
	 */
	u16 port;

	/**
	 * @is_server: True means that this socket can act as both client
	 * and server; false means the socket is client-only.
	 */
	bool is_server;

	/**
	 * @shutdown: True means the socket is no longer usable (either
	 * shutdown has already been invoked, or the socket was never
	 * properly initialized).
	 */
	bool shutdown;

	/**
	 * @ip_header_length: Length of IP headers for this socket (depends
	 * on IPv4 vs. IPv6).
	 */
	int ip_header_length;

	/** @socktab_links: Links this socket into a homa_socktab bucket. */
	struct hlist_node socktab_links;

	/* Information above is (almost) never modified; start a new
	 * cache line below for info that is modified frequently.
	 */

	/**
	 * @lock: Must be held when modifying fields such as interests
	 * and lists of RPCs. This lock is used in place of sk->sk_lock
	 * because it's used differently (it's always used as a simple
	 * spin lock).  See "Homa Locking Strategy" in homa_impl.h
	 * for more on Homa's synchronization strategy.
	 */
	spinlock_t lock ____cacheline_aligned_in_smp;

	/**
	 * @protect_count: counts the number of calls to homa_protect_rpcs
	 * for which there have not yet been calls to homa_unprotect_rpcs.
	 */
	atomic_t protect_count;

	/**
	 * @active_rpcs: List of all existing RPCs related to this socket,
	 * including both client and server RPCs. This list isn't strictly
	 * needed, since RPCs are already in one of the hash tables below,
	 * but it's more efficient for homa_timer to have this list
	 * (so it doesn't have to scan large numbers of hash buckets).
	 * The list is sorted, with the oldest RPC first. Manipulate with
	 * RCU so timer can access without locking.
	 */
	struct list_head active_rpcs;

	/**
	 * @dead_rpcs: Contains RPCs for which homa_rpc_end has been
	 * called, but their packet buffers haven't yet been freed.
	 */
	struct list_head dead_rpcs;

	/** @dead_skbs: Total number of socket buffers in RPCs on dead_rpcs. */
	int dead_skbs;

	/**
	 * @waiting_for_bufs: Contains RPCs that are blocked because there
	 * wasn't enough space in the buffer pool region for their incoming
	 * messages. Sorted in increasing order of message length.
	 */
	struct list_head waiting_for_bufs;

	/**
	 * @ready_rpcs: List of all RPCs that are ready for attention from
	 * an application thread.
	 */
	struct list_head ready_rpcs;

	/**
	 * @interests: List of threads that are currently waiting for
	 * incoming messages via homa_wait_shared.
	 */
	struct list_head interests;

	/**
	 * @client_rpc_buckets: Hash table for fast lookup of client RPCs.
	 * Modifications are synchronized with bucket locks, not
	 * the socket lock.
	 */
	struct homa_rpc_bucket client_rpc_buckets[HOMA_CLIENT_RPC_BUCKETS];

	/**
	 * @server_rpc_buckets: Hash table for fast lookup of server RPCs.
	 * Modifications are synchronized with bucket locks, not
	 * the socket lock.
	 */
	struct homa_rpc_bucket server_rpc_buckets[HOMA_SERVER_RPC_BUCKETS];
};

/**
 * struct homa_v6_sock - For IPv6, additional IPv6-specific information
 * is present in the socket struct after Homa-specific information.
 */
struct homa_v6_sock {
	/** @homa: All socket info except for IPv6-specific stuff. */
	struct homa_sock homa;

	/** @inet6: Socket info specific to IPv6. */
	struct ipv6_pinfo inet6;
};

#ifndef __STRIP__ /* See strip.py */
void               homa_bucket_lock_slow(struct homa_rpc_bucket *bucket,
					 u64 id);
#endif /* See strip.py */
int                homa_sock_bind(struct homa_net *hnet, struct homa_sock *hsk,
				  u16 port);
void               homa_sock_destroy(struct sock *sk);
struct homa_sock  *homa_sock_find(struct homa_net *hnet, u16 port);
int                homa_sock_init(struct homa_sock *hsk);
void               homa_sock_shutdown(struct homa_sock *hsk);
void               homa_sock_unlink(struct homa_sock *hsk);
int                homa_sock_wait_wmem(struct homa_sock *hsk, int nonblocking);
void               homa_socktab_destroy(struct homa_socktab *socktab,
					struct homa_net *hnet);
void               homa_socktab_end_scan(struct homa_socktab_scan *scan);
void               homa_socktab_init(struct homa_socktab *socktab);
struct homa_sock  *homa_socktab_next(struct homa_socktab_scan *scan);
struct homa_sock  *homa_socktab_start_scan(struct homa_socktab *socktab,
					   struct homa_socktab_scan *scan);

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_sock_lock() - Acquire the lock for a socket. If the socket
 * isn't immediately available, record stats on the waiting time.
 * @hsk:     Socket to lock.
 */
static inline void homa_sock_lock(struct homa_sock *hsk)
	__acquires(&hsk->lock)
{
	if (!spin_trylock_bh(&hsk->lock))
		homa_sock_lock_slow(hsk);
}
#else /* See strip.py */
/**
 * homa_sock_lock() - Acquire the lock for a socket.
 * @hsk:     Socket to lock.
 */
static inline void homa_sock_lock(struct homa_sock *hsk)
	__acquires(&hsk->lock)
{
	spin_lock_bh(&hsk->lock);
}
#endif /* See strip.py */

/**
 * homa_sock_unlock() - Release the lock for a socket.
 * @hsk:   Socket to lock.
 */
static inline void homa_sock_unlock(struct homa_sock *hsk)
	__releases(&hsk->lock)
{
	spin_unlock_bh(&hsk->lock);
}

/**
 * homa_socktab_bucket() - Compute the bucket number in a homa_socktab
 * that will contain a particular socket.
 * @hnet:   Network namespace of the desired socket.
 * @port:   Port number of the socket.
 *
 * Return:  The index of the bucket in which a socket matching @hnet and
 *          @port will be found (if it exists).
 */
static inline int homa_socktab_bucket(struct homa_net *hnet, u16 port)
{
#ifdef __UNIT_TEST__
	return port & (HOMA_SOCKTAB_BUCKETS - 1);
#else /* __UNIT_TEST__ */
	return hash_32((uintptr_t)hnet ^ port, HOMA_SOCKTAB_BUCKET_BITS);
#endif /* __UNIT_TEST__ */
}

/**
 * homa_client_rpc_bucket() - Find the bucket containing a given
 * client RPC.
 * @hsk:      Socket associated with the RPC.
 * @id:       Id of the desired RPC.
 *
 * Return:    The bucket in which this RPC will appear, if the RPC exists.
 */
static inline struct homa_rpc_bucket
		*homa_client_rpc_bucket(struct homa_sock *hsk, u64 id)
{
	/* We can use a really simple hash function here because RPC ids
	 * are allocated sequentially.
	 */
	return &hsk->client_rpc_buckets[(id >> 1)
			& (HOMA_CLIENT_RPC_BUCKETS - 1)];
}

/**
 * homa_server_rpc_bucket() - Find the bucket containing a given
 * server RPC.
 * @hsk:         Socket associated with the RPC.
 * @id:          Id of the desired RPC.
 *
 * Return:    The bucket in which this RPC will appear, if the RPC exists.
 */
static inline struct homa_rpc_bucket
		*homa_server_rpc_bucket(struct homa_sock *hsk, u64 id)
{
	/* Each client allocates RPC ids sequentially, so they will
	 * naturally distribute themselves across the hash space.
	 * Thus we can use the id directly as hash.
	 */
	return &hsk->server_rpc_buckets[(id >> 1)
			& (HOMA_SERVER_RPC_BUCKETS - 1)];
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_bucket_lock() - Acquire the lock for an RPC hash table bucket.
 * @bucket:    Bucket to lock.
 * @id:        Id of the RPC on whose behalf the bucket is being locked.
 *             Used only for metrics.
 */
static inline void homa_bucket_lock(struct homa_rpc_bucket *bucket, u64 id)
	__acquires(rpc_bucket_lock)
{
	if (!spin_trylock_bh(&bucket->lock))
		homa_bucket_lock_slow(bucket, id);
}
#else /* See strip.py */
/**
 * homa_bucket_lock() - Acquire the lock for an RPC hash table bucket.
 * @bucket:    Bucket to lock.
 * @id:        Id of the RPC on whose behalf the bucket is being locked.
 *             Used only for metrics.
 */
static inline void homa_bucket_lock(struct homa_rpc_bucket *bucket, u64 id)
	__acquires(rpc_bucket_lock)
{
	spin_lock_bh(&bucket->lock);
}
#endif /* See strip.py */

/**
 * homa_bucket_unlock() - Release the lock for an RPC hash table bucket.
 * @bucket:   Bucket to unlock.
 * @id:       ID of the RPC that was using the lock.
 */
static inline void homa_bucket_unlock(struct homa_rpc_bucket *bucket, u64 id)
	__releases(rpc_bucket_lock)
{
	spin_unlock_bh(&bucket->lock);
}

static inline struct homa_sock *homa_sk(const struct sock *sk)
{
	return (struct homa_sock *)sk;
}

/**
 * homa_sock_wmem_avl() - Returns true if the socket is within its limit
 * for output memory usage. False means that no new messages should be sent
 * until memory is freed.
 * @hsk:   Socket of interest.
 * Return: See above.
 */
static inline bool homa_sock_wmem_avl(struct homa_sock *hsk)
{
	return refcount_read(&hsk->sock.sk_wmem_alloc) < hsk->sock.sk_sndbuf;
}

/**
 * homa_sock_wakeup_wmem() - Invoked when tx packet memory has been freed;
 * if memory usage is below the limit and there are tasks waiting for memory,
 * wake them up.
 * @hsk:   Socket of interest.
 */
static inline void homa_sock_wakeup_wmem(struct homa_sock *hsk)
{
	if (test_bit(SOCK_NOSPACE, &hsk->sock.sk_socket->flags) &&
	    homa_sock_wmem_avl(hsk)) {
		tt_record2("homa_sock_wakeup_wmem waking up port %d, wmem %d",
			   hsk->port, refcount_read(&hsk->sock.sk_wmem_alloc));
		clear_bit(SOCK_NOSPACE, &hsk->sock.sk_socket->flags);
		wake_up_interruptible_poll(sk_sleep(&hsk->sock), EPOLLOUT);
	}
}

#endif /* _HOMA_SOCK_H */
