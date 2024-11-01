// SPDX-License-Identifier: BSD-2-Clause

/* This file manages homa_sock and homa_socktab objects. */

#include "homa_impl.h"
#include "homa_peer.h"
#include "homa_pool.h"

/**
 * homa_socktab_init() - Constructor for homa_socktabs.
 * @socktab:  The object to initialize; previous contents are discarded.
 */
void homa_socktab_init(struct homa_socktab *socktab)
{
	int i;

	spin_lock_init(&socktab->write_lock);
	for (i = 0; i < HOMA_SOCKTAB_BUCKETS; i++)
		INIT_HLIST_HEAD(&socktab->buckets[i]);
	INIT_LIST_HEAD(&socktab->active_scans);
}

/**
 * homa_socktab_destroy() - Destructor for homa_socktabs.
 * @socktab:  The object to destroy.
 */
void homa_socktab_destroy(struct homa_socktab *socktab)
{
	struct homa_socktab_scan scan;
	struct homa_sock *hsk;

	for (hsk = homa_socktab_start_scan(socktab, &scan); hsk;
			hsk = homa_socktab_next(&scan)) {
		homa_sock_destroy(hsk);
	}
	homa_socktab_end_scan(&scan);
}

/**
 * homa_socktab_start_scan() - Begin an iteration over all of the sockets
 * in a socktab.
 * @socktab:   Socktab to scan.
 * @scan:      Will hold the current state of the scan; any existing
 *             contents are discarded.
 *
 * Return:     The first socket in the table, or NULL if the table is
 *             empty.
 *
 * Each call to homa_socktab_next will return the next socket in the table.
 * All sockets that are present in the table at the time this function is
 * invoked will eventually be returned, as long as they are not removed
 * from the table. It is safe to remove sockets from the table and/or
 * delete them while the scan is in progress. If a socket is removed from
 * the table during the scan, it may or may not be returned by
 * homa_socktab_next. New entries added during the scan may or may not be
 * returned. The caller must hold an RCU read lock when invoking the
 * scan-related methods here, as well as when manipulating sockets returned
 * during the scan. It is safe to release and reacquire the RCU read lock
 * during a scan, as long as no socket is held when the read lock is
 * released and homa_socktab_next isn't invoked until the RCU read lock
 * is reacquired.
 */
struct homa_sock *homa_socktab_start_scan(struct homa_socktab *socktab,
					  struct homa_socktab_scan *scan)
{
	scan->socktab = socktab;
	scan->current_bucket = -1;
	scan->next = NULL;

	spin_lock_bh(&socktab->write_lock);
	list_add_tail_rcu(&scan->scan_links, &socktab->active_scans);
	spin_unlock_bh(&socktab->write_lock);

	return homa_socktab_next(scan);
}

/**
 * homa_socktab_next() - Return the next socket in an iteration over a socktab.
 * @scan:      State of the scan.
 *
 * Return:     The next socket in the table, or NULL if the iteration has
 *             returned all of the sockets in the table. Sockets are not
 *             returned in any particular order. It's possible that the
 *             returned socket has been destroyed.
 */
struct homa_sock *homa_socktab_next(struct homa_socktab_scan *scan)
{
	struct homa_socktab_links *links;
	struct homa_sock *hsk;

	while (1) {
		while (!scan->next) {
			scan->current_bucket++;
			if (scan->current_bucket >= HOMA_SOCKTAB_BUCKETS)
				return NULL;
			scan->next = (struct homa_socktab_links *)
				      hlist_first_rcu(&scan->socktab->buckets
				      		      [scan->current_bucket]);
		}
		links = scan->next;
		hsk = links->sock;
		scan->next = (struct homa_socktab_links *)hlist_next_rcu(&links
				->hash_links);
		return hsk;
	}
}

/**
 * homa_socktab_end_scan() - Must be invoked on completion of each scan
 * to clean up state associated with the scan.
 * @scan:      State of the scan.
 */
void homa_socktab_end_scan(struct homa_socktab_scan *scan)
{
	spin_lock_bh(&scan->socktab->write_lock);
	list_del(&scan->scan_links);
	spin_unlock_bh(&scan->socktab->write_lock);
}
/**
 * homa_sock_init() - Constructor for homa_sock objects. This function
 * initializes only the parts of the socket that are owned by Homa.
 * @hsk:    Object to initialize.
 * @homa:   Homa implementation that will manage the socket.
 *
 * Return: always 0 (success).
 */
void homa_sock_init(struct homa_sock *hsk, struct homa *homa)
{
	struct homa_socktab *socktab = homa->port_map;
	int i;

	spin_lock_bh(&socktab->write_lock);
	atomic_set(&hsk->protect_count, 0);
	spin_lock_init(&hsk->lock);
	hsk->last_locker = "none";
	atomic_set(&hsk->protect_count, 0);
	hsk->homa = homa;
	hsk->ip_header_length = (hsk->inet.sk.sk_family == AF_INET)
			? HOMA_IPV4_HEADER_LENGTH : HOMA_IPV6_HEADER_LENGTH;
	hsk->shutdown = false;
	while (1) {
		if (homa->next_client_port < HOMA_MIN_DEFAULT_PORT)
			homa->next_client_port = HOMA_MIN_DEFAULT_PORT;
		if (!homa_sock_find(socktab, homa->next_client_port))
			break;
		homa->next_client_port++;
	}
	hsk->port = homa->next_client_port;
	hsk->inet.inet_num = hsk->port;
	hsk->inet.inet_sport = htons(hsk->port);
	homa->next_client_port++;
	hsk->socktab_links.sock = hsk;
	hlist_add_head_rcu(&hsk->socktab_links.hash_links,
			   &socktab->buckets[homa_port_hash(hsk->port)]);
	INIT_LIST_HEAD(&hsk->active_rpcs);
	INIT_LIST_HEAD(&hsk->dead_rpcs);
	hsk->dead_skbs = 0;
	INIT_LIST_HEAD(&hsk->waiting_for_bufs);
	INIT_LIST_HEAD(&hsk->ready_requests);
	INIT_LIST_HEAD(&hsk->ready_responses);
	INIT_LIST_HEAD(&hsk->request_interests);
	INIT_LIST_HEAD(&hsk->response_interests);
	for (i = 0; i < HOMA_CLIENT_RPC_BUCKETS; i++) {
		struct homa_rpc_bucket *bucket = &hsk->client_rpc_buckets[i];

		spin_lock_init(&bucket->lock);
		INIT_HLIST_HEAD(&bucket->rpcs);
		bucket->id = i;
	}
	for (i = 0; i < HOMA_SERVER_RPC_BUCKETS; i++) {
		struct homa_rpc_bucket *bucket = &hsk->server_rpc_buckets[i];

		spin_lock_init(&bucket->lock);
		INIT_HLIST_HEAD(&bucket->rpcs);
		bucket->id = i + 1000000;
	}
	hsk->buffer_pool = kzalloc(sizeof(*hsk->buffer_pool), GFP_KERNEL);
	if (homa->hijack_tcp)
		hsk->sock.sk_protocol = IPPROTO_TCP;
	spin_unlock_bh(&socktab->write_lock);
}

/*
 * homa_sock_unlink() - Unlinks a socket from its socktab and does
 * related cleanups. Once this method returns, the socket will not be
 * discoverable through the socktab.
 */
void homa_sock_unlink(struct homa_sock *hsk)
{
	struct homa_socktab *socktab = hsk->homa->port_map;
	struct homa_socktab_scan *scan;

	/* If any scans refer to this socket, advance them to refer to
	 * the next socket instead.
	 */
	spin_lock_bh(&socktab->write_lock);
	list_for_each_entry(scan, &socktab->active_scans, scan_links) {
		if (!scan->next || (scan->next->sock != hsk))
			continue;
		scan->next = (struct homa_socktab_links *)hlist_next_rcu(
			      &scan->next->hash_links);
	}
	hlist_del_rcu(&hsk->socktab_links.hash_links);
	spin_unlock_bh(&socktab->write_lock);
}

/**
 * homa_sock_shutdown() - Disable a socket so that it can no longer
 * be used for either sending or receiving messages. Any system calls
 * currently waiting to send or receive messages will be aborted.
 * @hsk:       Socket to shut down.
 */
void homa_sock_shutdown(struct homa_sock *hsk)
{
	struct homa_interest *interest;
	struct homa_rpc *rpc;
	int i;

	homa_sock_lock(hsk, "homa_socket_shutdown");
	if (hsk->shutdown) {
		homa_sock_unlock(hsk);
		return;
	}

	/* The order of cleanup is very important, because there could be
	 * active operations that hold RPC locks but not the socket lock.
	 * 1. Set @shutdown; this ensures that no new RPCs will be created for
	 *    this socket (though some creations might already be in progress).
	 * 2. Remove the socket from its socktab: this ensures that
	 *    incoming packets for the socket will be dropped.
	 * 3. Go through all of the RPCs and delete them; this will
	 *    synchronize with any operations in progress.
	 * 4. Perform other socket cleanup: at this point we know that
	 *    there will be no concurrent activities on individual RPCs.
	 * 5. Don't delete the buffer pool until after all of the RPCs
	 *    have been reaped.
	 * See sync.txt for additional information about locking.
	 */
	hsk->shutdown = true;
	homa_sock_unlink(hsk);
	homa_sock_unlock(hsk);

	list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
		homa_rpc_lock(rpc, "homa_sock_shutdown");
		homa_rpc_free(rpc);
		homa_rpc_unlock(rpc);
	}

	homa_sock_lock(hsk, "homa_socket_shutdown #2");
	list_for_each_entry(interest, &hsk->request_interests, request_links)
		wake_up_process(interest->thread);
	list_for_each_entry(interest, &hsk->response_interests, response_links)
		wake_up_process(interest->thread);
	homa_sock_unlock(hsk);

	i = 0;
	while (!list_empty(&hsk->dead_rpcs)) {
		homa_rpc_reap(hsk, 1000);
		i++;
#if 1 /* See strip.py */
		if (i == 5) {
			tt_record("Freezing because reap seems hung");
			tt_freeze();
		}
#endif /* See strip.py */
	}

	homa_pool_destroy(hsk->buffer_pool);
	kfree(hsk->buffer_pool);
	hsk->buffer_pool = NULL;
}

/**
 * homa_sock_destroy() - Destructor for homa_sock objects. This function
 * only cleans up the parts of the object that are owned by Homa.
 * @hsk:       Socket to destroy.
 */
void homa_sock_destroy(struct homa_sock *hsk)
{
	homa_sock_shutdown(hsk);
	sock_set_flag(&hsk->inet.sk, SOCK_RCU_FREE);
}

/**
 * homa_sock_bind() - Associates a server port with a socket; if there
 * was a previous server port assignment for @hsk, it is abandoned.
 * @socktab:   Hash table in which the binding will be recorded.
 * @hsk:       Homa socket.
 * @port:      Desired server port for @hsk. If 0, then this call
 *             becomes a no-op: the socket will continue to use
 *             its randomly assigned client port.
 *
 * Return:  0 for success, otherwise a negative errno.
 */
int homa_sock_bind(struct homa_socktab *socktab, struct homa_sock *hsk,
		   __u16 port)
{
	struct homa_sock *owner;
	int result = 0;

	if (port == 0)
		return result;
	if (port >= HOMA_MIN_DEFAULT_PORT)
		return -EINVAL;
	homa_sock_lock(hsk, "homa_sock_bind");
	spin_lock_bh(&socktab->write_lock);
	if (hsk->shutdown) {
		result = -ESHUTDOWN;
		goto done;
	}

	owner = homa_sock_find(socktab, port);
	if (owner) {
		if (owner != hsk)
			result = -EADDRINUSE;
		goto done;
	}
	hlist_del_rcu(&hsk->socktab_links.hash_links);
	hsk->port = port;
	hsk->inet.inet_num = port;
	hsk->inet.inet_sport = htons(hsk->port);
	hlist_add_head_rcu(&hsk->socktab_links.hash_links,
			   &socktab->buckets[homa_port_hash(port)]);
done:
	spin_unlock_bh(&socktab->write_lock);
	homa_sock_unlock(hsk);
	return result;
}

/**
 * homa_sock_find() - Returns the socket associated with a given port.
 * @socktab:    Hash table in which to perform lookup.
 * @port:       The port of interest.
 * Return:      The socket that owns @port, or NULL if none.
 *
 * Note: this function uses RCU list-searching facilities, but it doesn't
 * call rcu_read_lock. The caller should do that, if the caller cares (this
 * way, the caller's use of the socket will also be protected).
 */
struct homa_sock *homa_sock_find(struct homa_socktab *socktab,  __u16 port)
{
	struct homa_socktab_links *link;
	struct homa_sock *result = NULL;

	hlist_for_each_entry_rcu(link, &socktab->buckets[homa_port_hash(port)],
				 hash_links) {
		struct homa_sock *hsk = link->sock;

		if (hsk->port == port) {
			result = hsk;
			break;
		}
	}
	return result;
}

/**
 * homa_sock_lock_slow() - This function implements the slow path for
 * acquiring a socketC lock. It is invoked when a socket lock isn't immediately
 * available. It waits for the lock, but also records statistics about
 * the waiting time.
 * @hsk:    socket to  lock.
 */
void homa_sock_lock_slow(struct homa_sock *hsk)
{
	__u64 start = sched_clock();

	tt_record("beginning wait for socket lock");
	spin_lock_bh(&hsk->lock);
	tt_record("ending wait for socket lock");
	INC_METRIC(socket_lock_misses, 1);
	INC_METRIC(socket_lock_miss_ns, sched_clock() - start);
}

/**
 * homa_bucket_lock_slow() - This function implements the slow path for
 * locking a bucket in one of the hash tables of RPCs. It is invoked when a
 * lock isn't immediately available. It waits for the lock, but also records
 * statistics about the waiting time.
 * @bucket:    The hash table bucket to lock.
 * @id:        ID of the particular RPC being locked (multiple RPCs may
 *             share a single bucket lock).
 */
void homa_bucket_lock_slow(struct homa_rpc_bucket *bucket, __u64 id)
{
	__u64 start = sched_clock();

	tt_record2("beginning wait for rpc lock, id %d (bucket %d)",
		   id, bucket->id);
	spin_lock_bh(&bucket->lock);
	tt_record2("ending wait for bucket lock, id %d (bucket %d)",
		   id, bucket->id);
	if (homa_is_client(id)) {
		INC_METRIC(client_lock_misses, 1);
		INC_METRIC(client_lock_miss_ns, sched_clock() - start);
	} else {
		INC_METRIC(server_lock_misses, 1);
		INC_METRIC(server_lock_miss_ns, sched_clock() - start);
	}
}
