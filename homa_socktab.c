/* Copyright (c) 2019, Stanford University
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

/* This file manages homa_socktab objects; it also implements several
 * operations on homa_sock objects, such as construction and destruction.
 */

#include "homa_impl.h"

/**
 * homa_socktab_init() - Constructor for homa_socktabs.
 * @socktab:  The object to initialize; previous contents are discarded.
 */
void homa_socktab_init(struct homa_socktab *socktab)
{
	int i;
	mutex_init(&socktab->write_lock);
	for (i = 0; i < HOMA_SOCKTAB_BUCKETS; i++) {
		INIT_HLIST_HEAD(&socktab->buckets[i]);
	}
}

/**
 * homa_socktab_destroy() - Destructor for homa_socktabs.
 * @socktab:  The object to destroy.
 */
void homa_socktab_destroy(struct homa_socktab *socktab)
{
	struct homa_socktab_scan scan;
	struct homa_sock *hsk;

	for (hsk = homa_socktab_start_scan(socktab, &scan); hsk !=  NULL;
			hsk = homa_socktab_next(&scan)) {
		homa_sock_destroy(hsk);
	}
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
 * returned. The caller should use RCU to prevent socket storage from
 * being reclaimed during the scan.
 */
struct homa_sock *homa_socktab_start_scan(struct homa_socktab *socktab,
	struct homa_socktab_scan *scan)
{
	scan->socktab = socktab;
	scan->current_bucket = -1;
	scan->next = NULL;
	return homa_socktab_next(scan);
}

/**
 * homa_starttab_next() - Return the next socket in an iteration over a socktab.
 * @scan:      State of the scan.
 *
 * Return:     The next socket in the table, or NULL if the iteration has
 *             returned all of the sockets in the table. Sockets are not
 *             returned in any particular order. It's possible that the
 *             returned socket has been destroyed.
 */
struct homa_sock *homa_socktab_next(struct homa_socktab_scan *scan)
{
	struct homa_sock *hsk;
	struct homa_socktab_links *links;
	while (1) {
		while (scan->next == NULL) {
			scan->current_bucket++;
			if (scan->current_bucket >= HOMA_SOCKTAB_BUCKETS)
				return NULL;
			scan->next = (struct homa_socktab_links *)
				hlist_first_rcu(
				&scan->socktab->buckets[scan->current_bucket]);
		}
		links = scan->next;
		hsk = links->sock;
		scan->next = (struct homa_socktab_links *) hlist_next_rcu(
				&links->hash_links);
		return hsk;
	}
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
	struct homa_socktab *socktab = &homa->port_map;
	int i;

	mutex_lock(&socktab->write_lock);
	atomic_set(&hsk->protect_count, 0);
	spin_lock_init(&hsk->lock);
	hsk->last_locker = "none";
	atomic_set(&hsk->protect_count, 0);
	hsk->homa = homa;
	hsk->shutdown = false;
	while (1) {
		if (homa->next_client_port < HOMA_MIN_DEFAULT_PORT) {
			homa->next_client_port = HOMA_MIN_DEFAULT_PORT;
		}
		if (!homa_sock_find(socktab, homa->next_client_port)) {
			break;
		}
		homa->next_client_port++;
	}
	hsk->port = homa->next_client_port;
	hsk->inet.inet_sport = htons(hsk->port);
	homa->next_client_port++;
	hsk->socktab_links.sock = hsk;
	hlist_add_head_rcu(&hsk->socktab_links.hash_links,
			&socktab->buckets[homa_port_hash(hsk->port)]);
	INIT_LIST_HEAD(&hsk->active_rpcs);
	INIT_LIST_HEAD(&hsk->dead_rpcs);
	hsk->dead_skbs = 0;
	INIT_LIST_HEAD(&hsk->ready_requests);
	INIT_LIST_HEAD(&hsk->ready_responses);
	INIT_LIST_HEAD(&hsk->request_interests);
	INIT_LIST_HEAD(&hsk->response_interests);
	for (i = 0; i < HOMA_CLIENT_RPC_BUCKETS; i++) {
		struct homa_rpc_bucket *bucket = &hsk->client_rpc_buckets[i];
		spin_lock_init(&bucket->lock);
		INIT_HLIST_HEAD(&bucket->rpcs);
	}
	for (i = 0; i < HOMA_SERVER_RPC_BUCKETS; i++) {
		struct homa_rpc_bucket *bucket = &hsk->server_rpc_buckets[i];
		spin_lock_init(&bucket->lock);
		INIT_HLIST_HEAD(&bucket->rpcs);
	}
	mutex_unlock(&socktab->write_lock);
}

/**
 * homa_sock_shutdown() - Disable a socket so that it can no longer
 * be used for either sending or receiving messages. Any system calls
 * currently waiting to send or receive messages will be aborted.
 * @hsk:       Socket to shut down. Must be locked by caller.
 */
void homa_sock_shutdown(struct homa_sock *hsk)
{
	struct homa_interest *interest;
	struct homa_rpc *rpc;

	homa_sock_lock(hsk, "homa_socket_shutdown");
	if (hsk->shutdown) {
		homa_sock_unlock(hsk);
		return;
	}
	printk(KERN_NOTICE "Shutting down socket %d", hsk->port);

	/* The order of cleanup is very important, because there could be
	 * active operations that hold RPC locks but not the socket lock.
	 * 1. Set @shutdown; this ensures that no new RPCs will be created for
	 *    this socket (though some creations might already be in progress).
	 * 2. Remove the socket from the port map: this ensures that
	 *    incoming packets for the socket will be dropped.
	 * 3. Go through all of the RPCs and delete them; this will
	 *    synchronize with any operations in progress.
	 * 4. Perform other socket cleanup: at this point we know that
	 *    there will be no concurrent activities on individual RPCs.
	 * See sync.txt for additional information about locking.
	 */
	hsk->shutdown = true;
	mutex_lock(&hsk->homa->port_map.write_lock);
	hlist_del_rcu(&hsk->socktab_links.hash_links);
	mutex_unlock(&hsk->homa->port_map.write_lock);
	homa_sock_unlock(hsk);

	list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
		homa_rpc_lock(rpc);
		homa_rpc_free(rpc);
		homa_rpc_unlock(rpc);
	}

	homa_sock_lock(hsk, "homa_socket_shutdown #2");
	list_for_each_entry(interest, &hsk->request_interests, request_links)
		wake_up_process(interest->thread);
	list_for_each_entry(interest, &hsk->response_interests, response_links)
		wake_up_process(interest->thread);
	homa_sock_unlock(hsk);

	while (!list_empty(&hsk->dead_rpcs))
		homa_rpc_reap(hsk, 1000);
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
	int result = 0;
	struct homa_sock *owner;

	if (port == 0)
		return result;
	if (port >= HOMA_MIN_DEFAULT_PORT) {
		return -EINVAL;
	}
	mutex_lock(&socktab->write_lock);

	owner = homa_sock_find(socktab, port);
	if (owner != NULL) {
		if (owner != hsk)
			result = -EADDRINUSE;
		goto done;
	}
	hlist_del_rcu(&hsk->socktab_links.hash_links);
	hsk->port = port;
	hsk->inet.inet_sport = htons(hsk->port);
	hlist_add_head_rcu(&hsk->socktab_links.hash_links,
			&socktab->buckets[homa_port_hash(port)]);
    done:
	mutex_unlock(&socktab->write_lock);
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
	__u64 start = get_cycles();
	tt_record("beginning wait for socket lock");
	spin_lock_bh(&hsk->lock);
	tt_record("ending wait for socket lock");
	INC_METRIC(socket_lock_misses, 1);
	INC_METRIC(socket_lock_miss_cycles, get_cycles() - start);
}
