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
	mutex_init(&socktab->writeLock);
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
	/* Currently don't need to do anything. */
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
	mutex_lock(&socktab->writeLock);
	hsk->homa = homa;
	hsk->server_port = 0;
	while (1) {
		if (homa->next_client_port < HOMA_MIN_CLIENT_PORT) {
			homa->next_client_port = HOMA_MIN_CLIENT_PORT;
		}
		if (!homa_sock_find(socktab, homa->next_client_port)) {
			break;
		}
		homa->next_client_port++;
	}
	hsk->client_port = homa->next_client_port;
	homa->next_client_port++;
	hsk->next_outgoing_id = 1;
	hsk->client_links.sock = hsk;
	hlist_add_head_rcu(&hsk->client_links.hash_links,
			&socktab->buckets[homa_port_hash(hsk->client_port)]);
	INIT_LIST_HEAD(&hsk->client_rpcs);
	INIT_LIST_HEAD(&hsk->server_rpcs);
	INIT_LIST_HEAD(&hsk->ready_rpcs);
	mutex_unlock(&socktab->writeLock);
}

/**
 * homa_sock_destroy() - Destructor for home_sock objects. This function
 * only cleans up the parts of the object that are owned by Homa.
 * @hsk:       Object to destroy.
 * @socktab:  Socktab in which @hsk has been registered.
 */
void homa_sock_destroy(struct homa_sock *hsk, struct homa_socktab *socktab)
{
	struct list_head *pos, *next;

	mutex_lock(&socktab->writeLock);
	hlist_del_rcu(&hsk->client_links.hash_links);
	if (hsk->server_port != 0) 
		hlist_del_rcu(&hsk->server_links.hash_links);
	mutex_unlock(&socktab->writeLock);
		
	list_for_each_safe(pos, next, &hsk->client_rpcs) {
		struct homa_rpc *crpc = list_entry(pos,
				struct homa_rpc, rpc_links);
		homa_rpc_free(crpc);
	}
	list_for_each_safe(pos, next, &hsk->server_rpcs) {
		struct homa_rpc *srpc = list_entry(pos, struct homa_rpc,
				rpc_links);
		homa_rpc_free(srpc);
	}
	sock_set_flag(&hsk->inet.sk, SOCK_RCU_FREE);
}

/**
 * homa_sock_bind() - Associates a server port with a socket; if there
 * was a previous server port assignment for @hsk, it is abandoned.
 * @socktab:   Hash table in which the binding will be recorded.
 * @hsk:       Homa socket.
 * @port:      Desired server port for @hsk.
 * 
 * Return:  0 for success, otherwise a negative errno.
 */
int homa_sock_bind(struct homa_socktab *socktab, struct homa_sock *hsk,
		__u16 port)
{
	int result = 0;
	struct homa_sock *owner;
	
	if ((port == 0) || (port >= HOMA_MIN_CLIENT_PORT)) {
		return -EINVAL;
	}
	mutex_lock(&socktab->writeLock);
	owner = homa_sock_find(socktab, port);
	if (owner != NULL) {
		if (owner != hsk)
			result = -EADDRINUSE;
		goto done;
	}
	if (hsk->server_port) {
		hlist_del_rcu(&hsk->server_links.hash_links);
	}
	hsk->server_port = port;
	hsk->server_links.sock = hsk;
	hlist_add_head_rcu(&hsk->server_links.hash_links,
			&socktab->buckets[homa_port_hash(port)]);
    done:
	mutex_unlock(&socktab->writeLock);
	return result;
}

/**
 * homa_sock_find() - Returns the socket associated with a given port.
 * @socktab:    Hash table in which to perform lookup.
 * @port:       The port of interest; may be either a &homa_sock.client_port
 *              or a &homa_sock.server_port. Must not be 0.
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
		if ((hsk->client_port == port) || (hsk->server_port == port)) {
			result = hsk;
			break;
		}
	}
	return result;
}