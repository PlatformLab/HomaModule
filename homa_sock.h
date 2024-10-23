/* SPDX-License-Identifier: BSD-2-Clause */

/* This file defines structs and other things related to Homa sockets.  */

#ifndef _HOMA_SOCK_H
#define _HOMA_SOCK_H

/* Forward declarations. */
struct homa;
struct homa_pool;

void     homa_sock_lock_slow(struct homa_sock *hsk);

/**
 * define HOMA_SOCKTAB_BUCKETS - Number of hash buckets in a homa_socktab.
 * Must be a power of 2.
 */
#define HOMA_SOCKTAB_BUCKETS 1024

/**
 * struct homa_socktab - A hash table that maps from port numbers (either
 * client or server) to homa_sock objects.
 *
 * This table is managed exclusively by homa_socktab.c, using RCU to
 * minimize synchronization during lookups.
 */
struct homa_socktab {
	/**
	 * @mutex: Controls all modifications to this object; not needed
	 * for socket lookups (RCU is used instead). Also used to
	 * synchronize port allocation.
	 */
	spinlock_t write_lock;

	/**
	 * @buckets: Heads of chains for hash table buckets. Chains
	 * consist of homa_socktab_link objects.
	 */
	struct hlist_head buckets[HOMA_SOCKTAB_BUCKETS];
};

/**
 * struct homa_socktab_links - Used to link homa_socks into the hash chains
 * of a homa_socktab.
 */
struct homa_socktab_links {
	/* Must be the first element of the struct! */
	struct hlist_node hash_links;
	struct homa_sock *sock;
};

/**
 * struct homa_socktab_scan - Records the state of an iteration over all
 * the entries in a homa_socktab, in a way that permits RCU-safe deletion
 * of entries.
 */
struct homa_socktab_scan {
	/** @socktab: The table that is being scanned. */
	struct homa_socktab *socktab;

	/**
	 * @current_bucket: the index of the bucket in socktab->buckets
	 * currently being scanned. If >= HOMA_SOCKTAB_BUCKETS, the scan
	 * is complete.
	 */
	int current_bucket;

	/**
	 * @next: the next socket to return from homa_socktab_next (this
	 * socket has not yet been returned). NULL means there are no
	 * more sockets in the current bucket.
	 */
	struct homa_socktab_links *next;
};

/**
 * struct homa_rpc_bucket - One bucket in a hash table of RPCs.
 */

struct homa_rpc_bucket {
	/**
	 * @lock: serves as a lock both for this bucket (e.g., when
	 * adding and removing RPCs) and also for all of the RPCs in
	 * the bucket. Must be held whenever manipulating an RPC in
	 * this bucket. This dual purpose permits clean and safe
	 * deletion and garbage collection of RPCs.
	 */
	spinlock_t lock;

	/** @rpcs: list of RPCs that hash to this bucket. */
	struct hlist_head rpcs;

	/** @id: identifier for this bucket, used in error messages etc.
	 * It's the index of the bucket within its hash table bucket
	 * array, with an additional offset to separate server and
	 * client RPCs.
	 */
	int id;
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
	 * @lock: Must be held when modifying fields such as interests
	 * and lists of RPCs. This lock is used in place of sk->sk_lock
	 * because it's used differently (it's always used as a simple
	 * spin lock).  See sync.txt for more on Homa's synchronization
	 * strategy.
	 */
	spinlock_t lock;

	/**
	 * @last_locker: identifies the code that most recently acquired
	 * @lock successfully. Occasionally used for debugging.
	 */
	char *last_locker;

	/**
	 * @protect_count: counts the number of calls to homa_protect_rpcs
	 * for which there have not yet been calls to homa_unprotect_rpcs.
	 * See sync.txt for more info.
	 */
	atomic_t protect_count;

	/**
	 * @homa: Overall state about the Homa implementation. NULL
	 * means this socket has been deleted.
	 */
	struct homa *homa;

	/** @shutdown: True means the socket is no longer usable. */
	bool shutdown;

	/**
	 * @port: Port number: identifies this socket uniquely among all
	 * those on this node.
	 */
	__u16 port;

	/**
	 * @ip_header_length: Length of IP headers for this socket (depends
	 * on IPv4 vs. IPv6).
	 */
	int ip_header_length;

	/**
	 * @client_socktab_links: Links this socket into the homa_socktab
	 * based on @port.
	 */
	struct homa_socktab_links socktab_links;

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
	 * @dead_rpcs: Contains RPCs for which homa_rpc_free has been
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
	 * @ready_requests: Contains server RPCs whose request message is
	 * in a state requiring attention from  a user process. The head is
	 * oldest, i.e. next to return.
	 */
	struct list_head ready_requests;

	/**
	 * @ready_responses: Contains client RPCs whose response message is
	 * in a state requiring attention from a user process. The head is
	 * oldest, i.e. next to return.
	 */
	struct list_head ready_responses;

	/**
	 * @request_interests: List of threads that want to receive incoming
	 * request messages.
	 */
	struct list_head request_interests;

	/**
	 * @response_interests: List of threads that want to receive incoming
	 * response messages.
	 */
	struct list_head response_interests;

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

	/**
	 * @buffer_pool: used to allocate buffer space for incoming messages.
	 * Storage is dynamically allocated.
	 */
	struct homa_pool *buffer_pool;
};

void     homa_bucket_lock_slow(struct homa_rpc_bucket *bucket, __u64 id);
int      homa_sock_bind(struct homa_socktab *socktab,
			struct homa_sock *hsk, __u16 port);
void     homa_sock_destroy(struct homa_sock *hsk);
struct homa_sock *
		    homa_sock_find(struct homa_socktab *socktab, __u16 port);
void     homa_sock_init(struct homa_sock *hsk, struct homa *homa);
void     homa_sock_shutdown(struct homa_sock *hsk);
int      homa_socket(struct sock *sk);
void     homa_socktab_destroy(struct homa_socktab *socktab);
void     homa_socktab_init(struct homa_socktab *socktab);
struct homa_sock
	       *homa_socktab_next(struct homa_socktab_scan *scan);
struct homa_sock
	       *homa_socktab_start_scan(struct homa_socktab *socktab,
		    struct homa_socktab_scan *scan);

/**
 * homa_sock_lock() - Acquire the lock for a socket. If the socket
 * isn't immediately available, record stats on the waiting time.
 * @hsk:     Socket to lock.
 * @locker:  Static string identifying where the socket was locked;
 *           used to track down deadlocks.
 */
static inline void homa_sock_lock(struct homa_sock *hsk, const char *locker)
{
	if (!spin_trylock_bh(&hsk->lock)) {
//		printk(KERN_NOTICE "Slow path for socket %d, last locker %s",
//				hsk->client_port, hsk->last_locker);
		homa_sock_lock_slow(hsk);
	}
//	hsk->last_locker = locker;
}

/**
 * homa_sock_unlock() - Release the lock for a socket.
 * @hsk:   Socket to lock.
 */
static inline void homa_sock_unlock(struct homa_sock *hsk)
{
	spin_unlock_bh(&hsk->lock);
}

/**
 * port_hash() - Hash function for port numbers.
 * @port:   Port number being looked up.
 *
 * Return:  The index of the bucket in which this port will be found (if
 *          it exists.
 */
static inline int homa_port_hash(__u16 port)
{
	/* We can use a really simple hash function here because client
	 * port numbers are allocated sequentially and server port numbers
	 * are unpredictable.
	 */
	return port & (HOMA_SOCKTAB_BUCKETS - 1);
}

/**
 * homa_client_rpc_bucket() - Find the bucket containing a given
 * client RPC.
 * @hsk:      Socket associated with the RPC.
 * @id:       Id of the desired RPC.
 *
 * Return:    The bucket in which this RPC will appear, if the RPC exists.
 */
static inline struct homa_rpc_bucket *homa_client_rpc_bucket(struct homa_sock *hsk,
							     __u64 id)
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
static inline struct homa_rpc_bucket *homa_server_rpc_bucket(struct homa_sock *hsk,
							     __u64 id)
{
	/* Each client allocates RPC ids sequentially, so they will
	 * naturally distribute themselves across the hash space.
	 * Thus we can use the id directly as hash.
	 */
	return &hsk->server_rpc_buckets[(id >> 1)
			& (HOMA_SERVER_RPC_BUCKETS - 1)];
}

/**
 * homa_bucket_lock() - Acquire the lock for an RPC hash table bucket.
 * @bucket:    Bucket to lock
 * @id:        ID of the RPC that is requesting the lock. Normally ignored,
 *             but used occasionally for diagnostics and debugging.
 * @locker:    Static string identifying the locking code. Normally ignored,
 *             but used occasionally for diagnostics and debugging.
 */
static inline void homa_bucket_lock(struct homa_rpc_bucket *bucket,
				    __u64 id, const char *locker)
{
	if (!spin_trylock_bh(&bucket->lock))
		homa_bucket_lock_slow(bucket, id);
}

/**
 * homa_bucket_try_lock() - Acquire the lock for an RPC hash table bucket if
 * it is available.
 * @bucket:    Bucket to lock
 * @id:        ID of the RPC that is requesting the lock.
 * @locker:    Static string identifying the locking code. Normally ignored,
 *             but used when debugging deadlocks.
 * Return:     Nonzero if lock was successfully acquired, zero if it is
 *             currently owned by someone else.
 */
static inline int homa_bucket_try_lock(struct homa_rpc_bucket *bucket,
				       __u64 id, const char *locker)
{
	if (!spin_trylock_bh(&bucket->lock))
		return 0;
	return 1;
}

/**
 * homa_bucket_unlock() - Release the lock for an RPC hash table bucket.
 * @bucket:   Bucket to unlock.
 * @id:       ID of the RPC that was using the lock.
 */
static inline void homa_bucket_unlock(struct homa_rpc_bucket *bucket, __u64 id)
{
	spin_unlock_bh(&bucket->lock);
}

static inline struct homa_sock *homa_sk(const struct sock *sk)
{
	return (struct homa_sock *)sk;
}

#endif /* _HOMA_SOCK_H */
