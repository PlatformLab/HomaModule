// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

/* This file manages homa_sock and homa_socktab objects. */

#include "homa_impl.h"
#include "homa_interest.h"
#include "homa_peer.h"
#include "homa_pool.h"

#ifndef __STRIP__ /* See strip.py */
#include "homa_grant.h"
#include "homa_hijack.h"
#endif /* See strip.py */

/**
 * homa_socktab_init() - Constructor for homa_socktabs.
 * @socktab:  The object to initialize; previous contents are discarded.
 */
void homa_socktab_init(struct homa_socktab *socktab)
{
	int i;

	spin_lock_init(&socktab->write_lock);
	socktab->next_sequence = 1;
	for (i = 0; i < HOMA_SOCKTAB_BUCKETS; i++)
		INIT_HLIST_HEAD(&socktab->buckets[i]);
}

/**
 * homa_socktab_destroy() - Destructor for homa_socktabs: deletes all
 * existing sockets.
 * @socktab:  The object to destroy.
 * @hnet:     If non-NULL, only sockets for this namespace are deleted.
 */
void homa_socktab_destroy(struct homa_socktab *socktab, struct homa_net *hnet)
{
	struct homa_socktab_scan scan;
	struct homa_sock *hsk;

	for (hsk = homa_socktab_start_scan(socktab, &scan); hsk;
			hsk = homa_socktab_next(&scan)) {
		if (hnet && hnet != hsk->hnet)
			continue;

		/* In actual use there should be no sockets left when this
		 * function is invoked, so the code below will never be
		 * invoked. However, it is useful during unit tests.
		 */
		homa_sock_shutdown(hsk);
		homa_sock_destroy(&hsk->sock);
	}
	homa_socktab_end_scan(&scan);
}

/**
 * homa_socktab_start_scan() - Begin an iteration over all of the sockets
 * in a socktab.
 * @socktab:   Socktab to scan.
 * @scan:      Will hold the current state of the scan; any existing
 *             contents are discarded. The caller must eventually pass this
 *             to homa_socktab_end_scan.
 *
 * Return:     The first socket in the table, or NULL if the table is
 *             empty. If non-NULL, a reference is held on the socket to
 *             prevent its deletion.
 *
 * Each call to homa_socktab_next will return the next socket in the table.
 * All sockets that are present in the table at the time this function is
 * invoked will eventually be returned, as long as they are not removed
 * from the table. It is safe to remove sockets from the table while the
 * scan is in progress. If a socket is removed from the table during the scan,
 * it may or may not be returned by homa_socktab_next. New entries added
 * during the scan may or may not be returned.
 */
struct homa_sock *homa_socktab_start_scan(struct homa_socktab *socktab,
					  struct homa_socktab_scan *scan)
{
	scan->socktab = socktab;
	scan->hsk = NULL;
	scan->current_bucket = 0;
	scan->avail = 0;
	scan->sequence = U64_MAX;

	return homa_socktab_next(scan);
}


/**
 * homa_socktab_fill_scan() - Refill the @socks array for a homa_socktab_scan.
 * On return, if its @avail member is zero it means all of the sockets in
 * the socktab have been scanned.
 * @scan:      State of the scan. Normally the @avail member will be zero,
 *             but this is not necessary.
 */
void homa_socktab_fill_scan(struct homa_socktab_scan *scan)
{
	struct homa_sock_link *slink;
	struct hlist_head *bucket;
	struct hlist_node *next;

	rcu_read_lock();
	bucket = &scan->socktab->buckets[scan->current_bucket];
	next = rcu_dereference(hlist_first_rcu(bucket));
	while (scan->avail < HOMA_MAX_SCANNED_SOCKS) {
		if (next == NULL) {
			if (scan->current_bucket >= HOMA_SOCKTAB_BUCKETS - 1)
				break;
			scan->current_bucket++;
			scan->sequence = U64_MAX;
			bucket = &scan->socktab->buckets[scan->current_bucket];
			next = rcu_dereference(hlist_first_rcu(bucket));
			continue;
		}
		slink = hlist_entry(next, struct homa_sock_link, links);
		next = rcu_dereference(hlist_next_rcu(next));
		if (slink->sequence < scan->sequence) {
			scan->sequence = slink->sequence;
			scan->socks[scan->avail] = slink->hsk;
		    	if (refcount_inc_not_zero(&slink->hsk->sock.sk_refcnt))
				scan->avail++;
		}
	}
	rcu_read_unlock();
}

/**
 * homa_socktab_next() - Return the next socket in an iteration over a socktab.
 * @scan:      State of the scan.
 *
 * Return:     The next socket in the table, or NULL if the iteration has
 *             returned all of the sockets in the table.  If non-NULL, a
 *             reference is held on the socket to prevent its deletion (this
 *             module will release the reference in the next call to
 *             homa_socktab_next or homa_socktab_end). Sockets are not returned
 *             in any particular order. It's possible that the returned socket
 *             has been shutdown.
 */
struct homa_sock *homa_socktab_next(struct homa_socktab_scan *scan)
{
	if (scan->hsk) {
		sock_put(&scan->hsk->sock);
		scan->hsk = NULL;
	}

	if (scan->avail == 0) {
		homa_socktab_fill_scan(scan);
		if (scan->avail == 0)
			return NULL;
	}

	scan->hsk = scan->socks[scan->avail - 1];
	scan->avail--;
	return scan->hsk;
}

/**
 * homa_socktab_end_scan() - Must be invoked on completion of each scan
 * to clean up state associated with the scan.
 * @scan:      State of the scan.
 */
void homa_socktab_end_scan(struct homa_socktab_scan *scan)
{
	if (scan->hsk) {
		sock_put(&scan->hsk->sock);
		scan->hsk = NULL;
	}
	while (scan->avail > 0) {
		sock_put(&scan->socks[scan->avail - 1]->sock);
		scan->avail--;
	}
}

/**
 * homa_sock_init() - Constructor for homa_sock objects. This function
 * handles Homa-specific initialization.
 * @hsk:    Object to initialize. The Homa-specific parts must have been
 *          initialized to zeroes by the caller.
 *
 * Return:  0 for success, otherwise a negative errno.
 */
int homa_sock_init(struct homa_sock *hsk)
{
	struct homa_pool *buffer_pool;
	struct homa_socktab *socktab;
	struct homa_sock *other;
	struct homa_net *hnet;
	struct homa *homa;
	int starting_port;
	int result = 0;
	int i;

	hnet = (struct homa_net *)net_generic(sock_net(&hsk->sock),
					      homa_net_id);
	homa = hnet->homa;
	socktab = homa->socktab;

	/* Do things requiring memory allocation before locking the socket,
	 * so that GFP_ATOMIC is not needed.
	 */
	buffer_pool = homa_pool_alloc(hsk);
	if (IS_ERR(buffer_pool))
		return PTR_ERR(buffer_pool);

	/* Initialize the fields private to Homa. We can initialize
	 * everything except the port and hash table links without acquiring
	 * the socket table lock.
	 */
	hsk->homa = homa;
	hsk->hnet = hnet;
	hsk->buffer_pool = buffer_pool;

	hsk->is_server = false;
	hsk->shutdown = false;
	hsk->ip_header_length = (hsk->inet.sk.sk_family == AF_INET) ?
				sizeof(struct iphdr) : sizeof(struct ipv6hdr);
	spin_lock_init(&hsk->lock);
	atomic_set(&hsk->protect_count, 0);
	INIT_LIST_HEAD(&hsk->active_rpcs);
	INIT_LIST_HEAD(&hsk->dead_rpcs);
	hsk->dead_skbs = 0;
	INIT_LIST_HEAD(&hsk->waiting_for_bufs);
	INIT_LIST_HEAD(&hsk->ready_rpcs);
	INIT_LIST_HEAD(&hsk->interests);
	for (i = 0; i < HOMA_CLIENT_RPC_BUCKETS; i++) {
		struct homa_rpc_bucket *bucket = &hsk->client_rpc_buckets[i];

		spin_lock_init(&bucket->lock);
		bucket->id = i;
		INIT_HLIST_HEAD(&bucket->rpcs);
	}
	for (i = 0; i < HOMA_SERVER_RPC_BUCKETS; i++) {
		struct homa_rpc_bucket *bucket = &hsk->server_rpc_buckets[i];

		spin_lock_init(&bucket->lock);
		bucket->id = i + 1000000;
		INIT_HLIST_HEAD(&bucket->rpcs);
	}

	/* Initialize fields outside the Homa part. */
	hsk->sock.sk_sndbuf = homa->wmem_max;
	sock_set_flag(&hsk->inet.sk, SOCK_RCU_FREE);
	IF_NO_STRIP(homa_hijack_sock_init(hsk));

	/* This is needed to prevent blocking when allocating memory in
	 * functions like ip_route_output_flow, which could be invoked
	 * while atomic.
	 */
	hsk->sock.sk_allocation = GFP_ATOMIC;

	/* Pick a default port. Must keep the socktab locked from now
	 * until the new socket is added to the socktab, to ensure that
	 * no other socket chooses the same port.
	 */
	spin_lock_bh(&socktab->write_lock);
	starting_port = hnet->prev_default_port;
	while (1) {
		hnet->prev_default_port++;
		if (hnet->prev_default_port < HOMA_MIN_DEFAULT_PORT)
			hnet->prev_default_port = HOMA_MIN_DEFAULT_PORT;
		other = homa_sock_find(hnet, hnet->prev_default_port);
		if (!other)
			break;
		sock_put(&other->sock);
		if (hnet->prev_default_port == starting_port) {
			spin_unlock_bh(&socktab->write_lock);
			result = -EADDRNOTAVAIL;
			goto error;
		}
		spin_unlock_bh(&socktab->write_lock);
		cond_resched();
		spin_lock_bh(&socktab->write_lock);
	}
	result = homa_sock_link(hsk, hnet->prev_default_port);
	spin_unlock_bh(&socktab->write_lock);
	if (result == 0)
		return result;

error:
	hsk->shutdown = true;
	hsk->homa = NULL;
	homa_pool_free(buffer_pool);
	return result;
}

/**
 * homa_sock_link() - Add a socket to the hash table for its socktab,
 * so that it will be discoverable through homa_sock_find. If the socket
 * is already linked, the current link will be removed.
 * @hsk:    Socket to link in; hsk->port will be used to determine
 *          where the socket is linked in it socktab. Caller must hold
 *          the lock for the socket's socktab.
 * @port:   Port to use for the socket; if this function succeeds, this
 *          number will be stored in hsk.
 *
 * Return:  0 for success, otherwise a negative errno.
 */
int homa_sock_link(struct homa_sock *hsk, int port)
	__must_hold(hsk->homa->socktab->write_lock)
{
	struct homa_socktab *socktab = hsk->homa->socktab;
	struct homa_sock_link *slink;

	slink = kmalloc(sizeof(*slink), GFP_ATOMIC);
	if (!slink)
		return -ENOMEM;
	homa_sock_unlink(hsk);
	slink->hsk = hsk;
	slink->sequence = socktab->next_sequence;
	socktab->next_sequence++;
	hlist_add_head_rcu(&slink->links,
			   &socktab->buckets[homa_socktab_bucket(hsk->hnet,
								 port)]);
	hsk->port = port;
	hsk->inet.inet_num = port;
	hsk->inet.inet_sport = htons(port);
	hsk->slink = slink;
	return 0;
}

/*
 * homa_sock_unlink() - Unlinks a socket from its socktab. Once this method
 * returns, the socket will not be discoverable through the socktab.
 * @hsk:  Socket to unlink. Caller must hold the lock for the socket's
 *        socktab.
 */
void homa_sock_unlink(struct homa_sock *hsk)
	__must_hold(hsk->homa->socktab->write_lock)
{
	struct homa_sock_link *slink;

	slink = hsk->slink;
	if (!slink)
		return;
	hsk->slink = NULL;
	hlist_del_rcu(&slink->links);
	kfree_rcu(slink, rcu_head);
}

/**
 * homa_sock_shutdown() - Disable a socket so that it can no longer
 * be used for either sending or receiving messages. Any system calls
 * currently waiting to send or receive messages will be aborted. This
 * function will terminate any existing use of the socket, but it does
 * not free up socket resources: that happens in homa_sock_destroy.
 * @hsk:       Socket to shut down.
 */
void homa_sock_shutdown(struct homa_sock *hsk)
{
	struct homa_socktab *socktab;
	struct homa_rpc *rpc;

	tt_record1("Starting shutdown for socket %d", hsk->port);
	homa_sock_lock(hsk);
	if (hsk->shutdown || !hsk->homa) {
		homa_sock_unlock(hsk);
		return;
	}

	/* The order of cleanup is very important, because there could be
	 * active operations that hold RPC locks but not the socket lock.
	 * 1. Set @shutdown; this ensures that no new RPCs will be created for
	 *    this socket (though some creations might already be in progress)
	 *    and incoming packets will be dropped.
	 * 2. Remove the socket from its socktab, so no-one will ever find
	 *    it again.
	 * 3. Go through all of the RPCs and delete them; this will
	 *    synchronize with any operations in progress.
	 * 4. Perform other socket cleanup: at this point we know that
	 *    there will be no concurrent activities on individual RPCs.
	 * 5. Don't delete the buffer pool until after all of the RPCs
	 *    have been reaped.
	 * See "Homa Locking Strategy" in homa_impl.h for additional information
	 * about locking.
	 */
	hsk->shutdown = true;
	homa_sock_unlock(hsk);

	socktab = hsk->homa->socktab;
	spin_lock_bh(&socktab->write_lock);
	homa_sock_unlink(hsk);
	spin_unlock_bh(&socktab->write_lock);

	rcu_read_lock();
	list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
		homa_rpc_lock(rpc);
		homa_rpc_end(rpc);
		homa_rpc_unlock(rpc);
	}
	wake_up_interruptible_poll(sk_sleep(&hsk->sock), EPOLLOUT);
	rcu_read_unlock();

	homa_sock_lock(hsk);
	while (!list_empty(&hsk->interests))
		homa_interest_notify_shared(hsk, NULL);
	homa_sock_unlock(hsk);
	tt_record1("Finished shutdown for socket %d", hsk->port);
}

/**
 * homa_sock_destroy() - Release all of the internal resources associated
 * with a socket; is invoked at time when that is safe (i.e., all references
 * on the socket have been dropped).
 * @sk:       Socket to destroy.
 */
void homa_sock_destroy(struct sock *sk)
{
	struct homa_sock *hsk = homa_sk(sk);

	IF_NO_STRIP(int i = 0);

	if (!hsk->homa)
		return;

	tt_record1("Starting to destroy socket %d", hsk->port);
	while (!list_empty(&hsk->dead_rpcs)) {
		homa_rpc_reap(hsk, true);
#ifndef __STRIP__ /* See strip.py */
		i++;
		if (i == 5) {
			tt_record("Freezing because reap seems hung");
			tt_freeze();
		}
#endif /* See strip.py */
	}

	WARN_ON_ONCE(refcount_read(&hsk->sock.sk_wmem_alloc) != 1);
#ifdef __UNIT_TEST__
	{
		u64 tx_memory = refcount_read(&hsk->sock.sk_wmem_alloc);

		if (tx_memory != 1)
			FAIL(" sk_wmem_alloc %llu after shutdown for port %d",
			     tx_memory, hsk->port);
	}
#endif /* __UNIT_TEST__ */

	if (hsk->buffer_pool) {
		homa_pool_free(hsk->buffer_pool);
		hsk->buffer_pool = NULL;
	}
	tt_record1("Finished destroying socket %d", hsk->port);
}

/**
 * homa_sock_bind() - Associates a server port with a socket; if there
 * was a previous server port assignment for @hsk, it is abandoned.
 * @hnet:      Network namespace with which port is associated.
 * @hsk:       Homa socket.
 * @port:      Desired server port for @hsk. If 0, then this call
 *             becomes a no-op: the socket will continue to use
 *             its randomly assigned client port.
 *
 * Return:  0 for success, otherwise a negative errno. If an error is
 *          returned, hsk->error_msg is set.
 */
int homa_sock_bind(struct homa_net *hnet, struct homa_sock *hsk,
		   u16 port)
{
	struct homa_socktab *socktab = hnet->homa->socktab;
	struct homa_sock *owner;
	int result = 0;

	if (port == 0)
		return result;
	if (port >= HOMA_MIN_DEFAULT_PORT) {
		hsk->error_msg = "port number invalid: in the automatically assigned range";
		return -EINVAL;
	}
	homa_sock_lock(hsk);
	spin_lock_bh(&socktab->write_lock);
	if (hsk->shutdown) {
		hsk->error_msg = "socket has been shut down";
		result = -ESHUTDOWN;
		goto done;
	}

	owner = homa_sock_find(hnet, port);
	if (owner) {
		sock_put(&owner->sock);
		if (owner != hsk) {
			hsk->error_msg = "requested port number is already in use";
			result = -EADDRINUSE;
		}
		goto done;
	}
	result = homa_sock_link(hsk, port);
	if (result == 0)
		hsk->is_server = true;
done:
	spin_unlock_bh(&socktab->write_lock);
	homa_sock_unlock(hsk);
	return result;
}

/**
 * homa_sock_find() - Returns the socket associated with a given port.
 * @hnet:       Network namespace where the socket will be used.
 * @port:       The port of interest.
 * Return:      The socket that owns @port, or NULL if none. If non-NULL
 *              then this method has taken a reference on the socket and
 *              the caller must call sock_put to release it.
 */
struct homa_sock *homa_sock_find(struct homa_net *hnet, u16 port)
{
	int bucket = homa_socktab_bucket(hnet, port);
	struct homa_sock *result = NULL;
	struct homa_sock_link *slink;
	struct homa_sock *hsk;

	rcu_read_lock();
	hlist_for_each_entry_rcu(slink, &hnet->homa->socktab->buckets[bucket],
				 links) {
		hsk = slink->hsk;
		if (hsk && hsk->port == port && hsk->hnet == hnet &&
		    !hsk->shutdown &&
		    refcount_inc_not_zero(&hsk->sock.sk_refcnt)) {
			result = hsk;
			break;
		}
	}
	rcu_read_unlock();
	return result;
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_sock_lock_slow() - This function implements the slow path for
 * acquiring a socketC lock. It is invoked when a socket lock isn't immediately
 * available. It waits for the lock, but also records statistics about
 * the waiting time.
 * @hsk:    socket to  lock.
 */
void homa_sock_lock_slow(struct homa_sock *hsk)
	__acquires(hsk->lock)
{
	u64 start = homa_clock();

	tt_record("beginning wait for socket lock");
	spin_lock_bh(&hsk->lock);
	tt_record("ending wait for socket lock");
	INC_METRIC(socket_lock_misses, 1);
	INC_METRIC(socket_lock_miss_cycles, homa_clock() - start);
}

/**
 * homa_bucket_lock_slow() - This function implements the slow path for
 * locking a bucket in one of the hash tables of RPCs. It is invoked when a
 * lock isn't immediately available. It waits for the lock, but also records
 * statistics about the waiting time.
 * @bucket:    The hash table bucket to lock.
 * @id:        Id of the RPC on whose behalf the bucket is being locked.
 *             Used only for metrics.
 */
void homa_bucket_lock_slow(struct homa_rpc_bucket *bucket, u64 id)
	__acquires(bucket->lock)
{
	u64 start = homa_clock();

	tt_record2("beginning wait for rpc lock, id %d, (bucket %d)",
		   id, bucket->id);
	spin_lock_bh(&bucket->lock);
	tt_record2("ending wait for rpc lock, id %d, (bucket %d)",
		   id, bucket->id);
	if (homa_is_client(id)) {
		INC_METRIC(client_lock_misses, 1);
		INC_METRIC(client_lock_miss_cycles, homa_clock() - start);
	} else {
		INC_METRIC(server_lock_misses, 1);
		INC_METRIC(server_lock_miss_cycles, homa_clock() - start);
	}
}
#endif /* See strip.py */

/**
 * homa_sock_wait_wmem() - Block the thread until @hsk's usage of tx
 * packet memory drops below the socket's limit.
 * @hsk:          Socket of interest.
 * @nonblocking:  If there's not enough memory, return -EWOLDBLOCK instead
 *                of blocking.
 * Return: 0 for success, otherwise a negative errno.
 */
int homa_sock_wait_wmem(struct homa_sock *hsk, int nonblocking)
{
	long timeo = hsk->sock.sk_sndtimeo;
	int result;

	/* Note: we can't use sock_wait_for_wmem because that function
	 * is not available to modules (as of August 2025 it's static).
	 */

	if (nonblocking)
		timeo = 0;
	set_bit(HOMA_SOCK_NOSPACE, &hsk->flags);
	tt_record2("homa_sock_wait_wmem waiting on port %d, wmem %d",
		   hsk->port, refcount_read(&hsk->sock.sk_wmem_alloc));
	result = wait_event_interruptible_timeout(*sk_sleep(&hsk->sock),
						  homa_sock_wmem_avl(hsk) ||
						  hsk->shutdown, timeo);
	tt_record4("homa_sock_wait_wmem woke up on port %d with result %d, wmem %d, signal pending %d",
		   hsk->port, result, refcount_read(&hsk->sock.sk_wmem_alloc),
		   signal_pending(current));
	if (hsk->shutdown)
		return -ESHUTDOWN;
	if (signal_pending(current))
		return -EINTR;
	if (result == 0)
		return -EWOULDBLOCK;
	return 0;
}
