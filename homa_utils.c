/* Copyright (c) 2019-2020, Stanford University
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

/* This file contains miscellaneous utility functions for the Homa protocol. */

#include "homa_impl.h"

/* Separate performance counters for each core. NR_CPUS is an overestimate
 * of the actual number, but allows us to allocate the array statically.
 */
struct homa_metrics *homa_metrics[NR_CPUS];

/* Points to block of memory holding all homa_metrics; used to free it. */
char *metrics_memory;

/**
 * homa_init() - Constructor for homa objects.
 * @homa:   Object to initialize.
 * 
 * Return:  0 on success, or a negative errno if there was an error. Even
 *          if an error occurs, it is safe (and necessary) to call
 *          homa_destroy at some point.
 */
int homa_init(struct homa *homa)
{
	size_t aligned_size;
	char *first;
	int i, err;
	_Static_assert(HOMA_MAX_PRIORITIES >= 8,
			"homa_init assumes at least 8 priority levels");
	
	/* Initialize Homa metrics (if no-one else has already done it),
	 * making sure that each core has private cache lines for its metrics.
	 */
	if (!metrics_memory) {
		aligned_size = (sizeof(struct homa_metrics) + 0x3f) & ~0x3f;
		metrics_memory = vmalloc(0x3f + (nr_cpu_ids*aligned_size));
		if (!metrics_memory) {
			printk(KERN_ERR "Homa couldn't allocate memory "
					"for metrics\n");
			return -ENOMEM;
		}
		first = (char *) (((__u64) metrics_memory + 0x3f) & ~0x3f);
		for (i = 0; i < nr_cpu_ids; i++) {
			homa_metrics[i] = (struct homa_metrics *)
					(first + i*aligned_size);
			memset(homa_metrics[i], 0, aligned_size);
		}
	}
	
	homa->pacer_kthread = NULL;
	homa->next_client_port = HOMA_MIN_CLIENT_PORT;
	atomic64_set(&homa->next_outgoing_id, 1);
	homa_socktab_init(&homa->port_map);
	err = homa_peertab_init(&homa->peers);
	if (err) {
		printk(KERN_ERR "Couldn't initialize peer table (errno %d)\n",
			-err);
		return err;
	}
	
	/* Wild guesses to initialize configuration values... */
	homa->rtt_bytes = 10000;
	homa->link_mbps = 10000;
	homa->num_priorities = HOMA_MAX_PRIORITIES;
	homa->base_priority = 0;
	homa->max_sched_prio = HOMA_MAX_PRIORITIES - 5;
	homa->unsched_cutoffs[HOMA_MAX_PRIORITIES-1] = 200;
	homa->unsched_cutoffs[HOMA_MAX_PRIORITIES-2] = 2800;
	homa->unsched_cutoffs[HOMA_MAX_PRIORITIES-3] = 15000;
	homa->unsched_cutoffs[HOMA_MAX_PRIORITIES-4] = HOMA_MAX_MESSAGE_SIZE;
#ifdef __UNIT_TEST__
	/* Unit tests won't send CUTOFFS messages unless the test changes
	 * this variable.
	 */
	homa->cutoff_version = 0;
#else
	homa->cutoff_version = 1;
#endif
	homa->grant_increment = 0;
	homa->max_overcommit = 8;
	homa->resend_ticks = 2;
	homa->resend_interval = 5;
	homa->abort_resends = 10;
	homa->reap_limit = 10;
	homa->max_dead_buffs = 10000;
	spin_lock_init(&homa->grantable_lock);
	INIT_LIST_HEAD(&homa->grantable_rpcs);
	homa->num_grantable = 0;
	spin_lock_init(&homa->throttle_lock);
	INIT_LIST_HEAD_RCU(&homa->throttled_rpcs);
	homa->throttle_min_bytes = 300;
	homa->pacer_kthread = kthread_run(homa_pacer_main, homa,
			"homa_pacer");
	if (IS_ERR(homa->pacer_kthread)) {
		err = PTR_ERR(homa->pacer_kthread);
		homa->pacer_kthread = NULL;
		printk(KERN_ERR "couldn't create homa pacer thread: error %d\n",
			err);
		return err;
	}
	homa->pacer_exit = false;
	atomic_set(&homa->pacer_active, 0);
	atomic64_set(&homa->link_idle_time, get_cycles());
	homa->max_nic_queue_ns = 2000;
	homa->cycles_per_kbyte = 0;
	homa->verbose = 0;
	homa->max_gso_size = 1000000;
	homa->max_gro_skbs = 20;
	homa->timer_ticks = 0;
	spin_lock_init(&homa->metrics_lock);
	homa->metrics = NULL;
	homa->metrics_capacity = 0;
	homa->metrics_length = 0;
	homa->metrics_active_opens = 0;
	homa_outgoing_sysctl_changed(homa);
	return 0;
}

/**
 * homa_destroy() -  Destructor for homa objects.
 * @homa:      Object to destroy.
 */
void homa_destroy(struct homa *homa)
{
	int i;
	if (homa->pacer_kthread) {
		homa_pacer_stop(homa);
	}
	
	/* The order of the following 2 statements matters! */
	homa_socktab_destroy(&homa->port_map);
	homa_peertab_destroy(&homa->peers);
	if (metrics_memory) {
		vfree(metrics_memory);
		metrics_memory = NULL;
		for (i = 0; i < nr_cpu_ids; i++) {
			homa_metrics[i] = NULL;
		}
	}
	if (homa->metrics)
		kfree(homa->metrics);
}

/**
 * homa_rpc_new_client() - Allocate and construct a client RPC (one that is used
 * to issue an outgoing request). Doesn't send any packets. Invoked with no
 * locks held.
 * @hsk:      Socket to which the RPC belongs.
 * @dest:     Address of host (ip and port) to which the RPC will be sent.
 * @buffer:   Address (in user space) of the first byte of the request message.
 * @len:      Number of bytes in the request message.
 * 
 * Return:    A printer to the newly allocated object, or a negative
 *            errno if an error occurred. The RPC will be locked; the
 *            caller must eventually unlock it. 
 */
struct homa_rpc *homa_rpc_new_client(struct homa_sock *hsk,
		struct sockaddr_in *dest, void __user *buffer, size_t len)
{
	int err;
	struct homa_rpc *crpc;
	struct homa_rpc_bucket *bucket;
	struct sk_buff *skb = NULL;
	
	crpc = (struct homa_rpc *) kmalloc(sizeof(*crpc), GFP_KERNEL);
	if (unlikely(!crpc))
		return ERR_PTR(-ENOMEM);
	
	/* Initialize fields that don't require the socket lock. */
	crpc->hsk = hsk;
	crpc->id = atomic64_fetch_add(1, &hsk->homa->next_outgoing_id);
	bucket = homa_client_rpc_bucket(hsk, crpc->id);
	crpc->lock = &bucket->lock;
	crpc->state = RPC_OUTGOING;
	crpc->is_client = true;
	crpc->dont_reap = false;
	crpc->peer = homa_peer_find(&hsk->homa->peers,
			dest->sin_addr.s_addr, &hsk->inet);
	if (unlikely(IS_ERR(crpc->peer))) {
		err = PTR_ERR(crpc->peer);
		goto error;
	}
	crpc->dport = ntohs(dest->sin_port);
	crpc->error = 0;
	crpc->msgin.total_length = -1;
	crpc->msgin.num_skbs = 0;
	skb = homa_fill_packets(hsk->homa, crpc->peer, buffer, len);
	if (IS_ERR(skb)) {
		err = PTR_ERR(skb);
		skb = NULL;
		goto error;
	}
	homa_message_out_init(crpc, hsk->client_port, skb, len);
	INIT_LIST_HEAD(&crpc->dead_links);
	crpc->interest = NULL;
	INIT_LIST_HEAD(&crpc->ready_links);
	INIT_LIST_HEAD(&crpc->grantable_links);
	INIT_LIST_HEAD(&crpc->throttled_links);
	crpc->silent_ticks = 0;
	crpc->num_resends = 0;
	
	/* Initialize fields that require locking. This allows the most
	 * expensive work, such as copying in the message from user space,
	 * to be performed without holding locks. Also, can't hold spin
	 * locks while doing things that could block, such as memory allocation.
	 */
	homa_bucket_lock(bucket, client);
	homa_sock_lock(hsk, "homa_rpc_new_client");
	if (hsk->shutdown) {
		homa_sock_unlock(hsk);
		homa_rpc_unlock(crpc);
		err = -ESHUTDOWN;
		goto error;
	}
	hlist_add_head(&crpc->hash_links, &bucket->rpcs);
	list_add_tail_rcu(&crpc->active_links, &hsk->active_rpcs);
	homa_sock_unlock(hsk);
	
	return crpc;
	
error:
	homa_free_skbs(skb);
	kfree(crpc);
	return ERR_PTR(err);
}

/**
 * homa_rpc_new_server() - Allocate and construct a server RPC (one that is
 * used to manage an incoming request).
 * @hsk:    Socket that owns this RPC.
 * @source: IP address (network byte order) of the RPC's client.
 * @h:      Header for the first data packet received for this RPC; used
 *          to initialize the RPC.
 * 
 * Return:  A pointer to a new RPC, which is locked, or a negative errno
 *          if an error occurred. If there is already an RPC corresponding
 *          to h, then it is returned instead of creating a new RPC.
 *          If a new RPC is created, it is not yet linked into
 *          @hsk->active_rpcs.
 */
struct homa_rpc *homa_rpc_new_server(struct homa_sock *hsk,
		__be32 source, struct data_header *h)
{
	int err;
	struct homa_rpc *srpc;
	struct homa_rpc_bucket *bucket = homa_server_rpc_bucket(hsk,
			h->common.id);
	
	/* Lock the bucket, and make sure no-one else has already created
	 * the desired RPC.
	 */
	homa_bucket_lock(bucket, server);
	hlist_for_each_entry_rcu(srpc, &bucket->rpcs, hash_links) {
		if ((srpc->id == h->common.id) && 
				(srpc->dport == ntohs(h->common.sport)) &&
				(srpc->peer->addr == source)) {
			/* RPC already exists; just return it instead
			 * of creating a new RPC.
			 */
			return srpc;
		}
	}
	
	/* Initialize fields that don't require the socket lock. */
	srpc = (struct homa_rpc *) kmalloc(sizeof(*srpc), GFP_KERNEL);
	if (!srpc) {
		err = -ENOMEM;
		goto error;
	}
	srpc->hsk = hsk;
	srpc->lock = &bucket->lock;
	srpc->state = RPC_INCOMING;
	srpc->is_client = false;
	srpc->dont_reap = false;
	srpc->peer = homa_peer_find(&hsk->homa->peers, source, &hsk->inet);
	if (unlikely(IS_ERR(srpc->peer))) {
		err = PTR_ERR(srpc->peer);
		kfree(srpc);
		goto error;
	}
	srpc->dport = ntohs(h->common.sport);
	srpc->id = h->common.id;
	srpc->error = 0;
	homa_message_in_init(&srpc->msgin, ntohl(h->message_length),
			ntohl(h->incoming));
	srpc->msgout.length = -1;
	srpc->msgout.num_skbs = 0;
	srpc->active_links.next = LIST_POISON1;
	srpc->interest = NULL;
	INIT_LIST_HEAD(&srpc->ready_links);
	INIT_LIST_HEAD(&srpc->grantable_links);
	INIT_LIST_HEAD(&srpc->throttled_links);
	srpc->silent_ticks = 0;
	srpc->num_resends = 0;

	hlist_add_head(&srpc->hash_links, &bucket->rpcs);
	return srpc;

error:
	spin_unlock_bh(&bucket->lock);
	return ERR_PTR(err);
}

/**
 * homa_rpc_lock_slow() - This function implements the slow path for
 * acquiring an RPC lock. It is invoked when an RPC lock isn't immediately
 * available. It waits for the lock, but also records statistics about
 * the waiting time.
 * @rpc:    RPC to  lock.
 */
void homa_rpc_lock_slow(struct homa_rpc *rpc)
{
	__u64 start = get_cycles();
	spin_lock_bh(rpc->lock);
	if (rpc->is_client) {
		INC_METRIC(client_lock_misses, 1);
		INC_METRIC(client_lock_miss_cycles, get_cycles() - start);
	} else {
		INC_METRIC(server_lock_misses, 1);
		INC_METRIC(server_lock_miss_cycles, get_cycles() - start);
	}
}

/**
 * homa_rpc_free() - Destructor for homa_rpc; will arrange for all resources
 * associated with the RPC to be released (eventually).
 * @rpc:  Structure to clean up, or NULL. Must be locked. Its socket must
 *        not be locked.
 */
void homa_rpc_free(struct homa_rpc *rpc)
{
	if (!rpc || (rpc->state == RPC_DEAD))
		return;
	tt_record3("Freeing rpc id %d, total_length %d, lock 0x%x", rpc->id,
			rpc->msgin.total_length,
			*(int *) &rpc->msgin.packets.lock);
	
	/* Before doing anything else, unlink the input message from
	 * homa->grantable_msgs. This will synchronize to ensure that
	 * homa_manage_grants doesn't access this RPC after destruction
	 * begins.
	 */
	homa_remove_from_grantable(rpc->hsk->homa, rpc);
	
	/* Unlink from all lists, so no-one will ever find this RPC again. */
	homa_sock_lock(rpc->hsk, "homa_rpc_free");
	__hlist_del(&rpc->hash_links);
	list_del_rcu(&rpc->active_links);
	__list_del_entry(&rpc->ready_links);
	if (rpc->interest != NULL) {
		rpc->interest->reg_rpc = NULL;
		wake_up_process(rpc->interest->thread);
		rpc->interest = NULL;
	}
	list_add_tail_rcu(&rpc->dead_links, &rpc->hsk->dead_rpcs);
	rpc->hsk->dead_skbs += rpc->msgin.num_skbs + rpc->msgout.num_skbs;
	rpc->state = RPC_DEAD;
	homa_sock_unlock(rpc->hsk);
	
	if (unlikely(!list_empty(&rpc->throttled_links))) {
		homa_throttle_lock(rpc->hsk->homa);
		list_del(&rpc->throttled_links);
		INIT_LIST_HEAD(&rpc->throttled_links);
		homa_throttle_unlock(rpc->hsk->homa);
	}
}

/**
 * homa_rpc_reap() - Invoked to release resources associated with dead
 * RPCs for a given socket. For a large RPC, it can take a long time to
 * free all of its packet buffers, so we try to perform this work
 * off the critical path where it won't delay applications. Each call to
 * this function does a small chunk of work.
 * @hsk:   Homa socket that may contain dead RPCs. Must be locked by the
 *         caller. The lock may be released and then reacquired by this
 *         function.
 * 
 * Return: A value greater than 0 means the function found work to do;
 *         there may be additional RPCs that haven't yet been reaped.
 *         A value of zero means that there are no RPCs ready to be
 *         reaped. A value less than zero means that reaping was disabled,
 *         so the method didn't do anything; there may or may not be
 *         RPCs available to reap.
 */
int homa_rpc_reap(struct homa_sock *hsk)
{
	struct sk_buff *skbs[hsk->homa->reap_limit];
	struct homa_rpc *rpcs[hsk->homa->reap_limit];
	int num_skbs = 0;
	int num_rpcs = 0;
	struct homa_rpc *rpc;
	static int instance = 0;
	int i;
	
	if (atomic_read(&hsk->reap_disable)) {
		INC_METRIC(disabled_reaps, 1);
		return -1;
	}
	INC_METRIC(reaper_calls, 1);
	INC_METRIC(reaper_dead_skbs, hsk->dead_skbs);
	
	/* Collect buffers and freeable RPCs until either we hit our limit
	 * or run out of RPCs.
	 */
	instance++;
	tt_record3("Starting homa_rpc_reap, dead_skbs %d, instance %d, port %d",
			hsk->dead_skbs, instance, hsk->client_port);
	list_for_each_entry_rcu(rpc, &hsk->dead_rpcs, dead_links) {
		if (rpc->dont_reap) {
			INC_METRIC(disabled_rpc_reaps, 1);
			continue;
		}
		if (rpc->msgout.length >= 0) {
			while (rpc->msgout.packets) {
				skbs[num_skbs] = rpc->msgout.packets;
				rpc->msgout.packets = *homa_next_skb(
						rpc->msgout.packets);
				num_skbs++;
				rpc->msgout.num_skbs--;
				if (num_skbs >= hsk->homa->reap_limit)
					goto release;
			}
		}
		i = 0;
		if (rpc->msgin.total_length >= 0) {
			while (1) {
				struct sk_buff *skb = skb_dequeue(
						&rpc->msgin.packets);
				if (!skb)
					break;
				skbs[num_skbs] = skb;
				num_skbs++;
				rpc->msgin.num_skbs--;
				if (num_skbs >= hsk->homa->reap_limit)
					goto release;
			}
		}
		
		/* If we get here, it means all packets have been removed
		 * from the RPC.
		 */
		rpcs[num_rpcs] = rpc;
		num_rpcs++;
		list_del_rcu(&rpc->dead_links);
	}
	
	/* Free all of the collected resources; release the socket
	 * lock while doing this.
	 */
release:
	tt_record2("reaping %d skbs, %d rpcs", num_skbs, num_rpcs);
        
	if ((num_skbs == 0) && (num_rpcs == 0))
		return 0;
	hsk->dead_skbs -= num_skbs;
	homa_sock_unlock(hsk);
	for (i = 0; i < num_skbs; i++) {
		kfree_skb(skbs[i]);
	}
	for (i = 0; i < num_rpcs; i++) {
		UNIT_LOG("; ", "reaped %llu", rpcs[i]->id);
		/* Lock and unlock the RPC before freeing it. This is needed
		 * to deal with races where the last user of the RPC (such
		 * as homa_ioc_reply) hasn't unlocked it yet.
		 */
		homa_rpc_lock(rpcs[i]);
		homa_rpc_unlock(rpcs[i]);
		kfree(rpcs[i]);
	}
	homa_sock_lock(hsk, "homa_rpc_reap");
	return 1;
}

/**
 * homa_find_client_rpc() - Locate client-side information about the RPC that
 * a packet belongs to, if there is any. Thread-safe without socket lock.
 * @hsk:      Socket via which packet was received.
 * @id:       Unique identifier for the RPC.
 * 
 * Return:    A pointer to the homa_rpc for this id, or NULL if none.
 *            The RPC will be locked; the caller must eventually unlock it
 *            by invoking homa_unlock_client_rpc.
 */
struct homa_rpc *homa_find_client_rpc(struct homa_sock *hsk, __u64 id)
{
	struct homa_rpc *crpc;
	struct homa_rpc_bucket *bucket = homa_client_rpc_bucket(hsk, id);
	homa_bucket_lock(bucket, client);
	hlist_for_each_entry_rcu(crpc, &bucket->rpcs, hash_links) {
		if (crpc->id == id) {
			return crpc;
		}
	}
	spin_unlock_bh(&bucket->lock);
	return NULL;
}

/**
 * homa_find_server_rpc() - Locate server-side information about the RPC that
 * a packet belongs to, if there is any. Thread-safe without socket lock.
 * @hsk:      Socket via which packet was received.
 * @saddr:    Address from which the packet was sent.
 * @sport:    Port at @saddr from which the packet was sent.
 * @id:       Unique identifier for the RPC.
 * 
 * Return:    A pointer to the homa_rpc matching the arguments, or NULL
 *            if none. The RPC will be locked; the caller must eventually
 *            unlock it by invoking homa_unlock_server_rpc.
 */
struct homa_rpc *homa_find_server_rpc(struct homa_sock *hsk,
		__be32 saddr, __u16 sport, __u64 id)
{
	struct homa_rpc *srpc;
	struct homa_rpc_bucket *bucket = homa_server_rpc_bucket(hsk, id);
	homa_bucket_lock(bucket, server);
	hlist_for_each_entry_rcu(srpc, &bucket->rpcs, hash_links) {
		if ((srpc->id == id) && (srpc->dport == sport) &&
				(srpc->peer->addr == saddr)) {
			return srpc;
		}
	}
	spin_unlock_bh(&bucket->lock);
	return NULL;
}

/**
 * homa_print_ipv4_addr() - Convert an IPV4 address to the standard string
 * representation.
 * @addr:    Address to convert, in network byte order.
 * 
 * Return:   The converted value. Values are stored in static memory, so
 *           the caller need not free. This also means that storage is
 *           eventually reused (there are enough buffers to accommodate
 *           multiple "active" values).
 * 
 * Note: Homa uses this function, rather than the %pI4 format specifier
 * for snprintf et al., because the kernel's version of snprintf isn't
 * available in Homa's unit test environment.
 */
char *homa_print_ipv4_addr(__be32 addr)
{
#define NUM_BUFS 4
#define BUF_SIZE 30
	static char buffers[NUM_BUFS][BUF_SIZE];
	static int next_buf = 0;
	__u32 a2 = ntohl(addr);
	char *buffer = buffers[next_buf];
	next_buf++;
	if (next_buf >= NUM_BUFS)
		next_buf = 0;
	snprintf(buffer, BUF_SIZE, "%u.%u.%u.%u", (a2 >> 24) & 0xff,
			(a2 >> 16) & 0xff, (a2 >> 8) & 0xff, a2 & 0xff);
	return buffer;
}

/**
 * homa_print_packet() - Print a human-readable string describing the
 * information in a Homa packet.
 * @skb:     Packet whose information should be printed.
 * @buffer:  Buffer in which to generate the string.
 * @buf_len: Number of bytes available at @buffer.
 * 
 * Return:   @buffer
 */
char *homa_print_packet(struct sk_buff *skb, char *buffer, int buf_len)
{
	int used = 0;
	struct common_header *common = (struct common_header *) skb->data;
	
	used = homa_snprintf(buffer, buf_len, used,
		"%s from %s:%u, dport %d, id %llu",
		homa_symbol_for_type(common->type),
		homa_print_ipv4_addr(ip_hdr(skb)->saddr),
		ntohs(common->sport), ntohs(common->dport), common->id);
	switch (common->type) {
	case DATA: {
		struct data_header *h = (struct data_header *)
				skb->data;
		struct data_segment *seg;
		int seg_length = ntohl(h->seg.segment_length);
		int bytes_left, i;
		used = homa_snprintf(buffer, buf_len, used,
				", message_length %d, offset %d, "
				"data_length %d, incoming %d, "
				"cutoff_version %d%s",
				ntohl(h->message_length),
				ntohl(h->seg.offset), seg_length,
				ntohl(h->incoming),
				ntohs(h->cutoff_version),
				h->retransmit ? ", RETRANSMIT" : "");
		bytes_left = skb->len - sizeof32(*h) - seg_length;
		if (skb_shinfo(skb)->gso_segs <= 1)
			break;
		used = homa_snprintf(buffer, buf_len, used, ", extra segs");
		for (i = skb_shinfo(skb)->gso_segs - 1; i > 0; i--) {
			seg = (struct data_segment *) (skb->data + skb->len
					- bytes_left);
			seg_length = ntohl(seg->segment_length);
			used = homa_snprintf(buffer, buf_len, used,
					" %d@%d", seg_length,
					ntohl(seg->offset));
			bytes_left -= sizeof32(*seg) + seg_length;
		};
		break;
	}
	case GRANT: {
		struct grant_header *h = (struct grant_header *) skb->data;
		used = homa_snprintf(buffer, buf_len, used,
				", offset %d, grant_prio %u",
				ntohl(h->offset), h->priority);
		break;
	}
	case RESEND: {
		struct resend_header *h = (struct resend_header *) skb->data;
		used = homa_snprintf(buffer, buf_len, used,
				", offset %d, length %d, resend_prio %u",
				ntohl(h->offset), ntohl(h->length),
				h->priority);
		break;
	}
	case RESTART:
		/* Nothing to add here. */
		break;
	case BUSY:
		/* Nothing to add here. */
		break;
	case CUTOFFS: {
		struct cutoffs_header *h = (struct cutoffs_header *) skb->data;
		used = homa_snprintf(buffer, buf_len, used,
				", cutoffs %d %d %d %d %d %d %d %d, version %u",
				ntohl(h->unsched_cutoffs[0]),
				ntohl(h->unsched_cutoffs[1]),
				ntohl(h->unsched_cutoffs[2]),
				ntohl(h->unsched_cutoffs[3]),
				ntohl(h->unsched_cutoffs[4]),
				ntohl(h->unsched_cutoffs[5]),
				ntohl(h->unsched_cutoffs[6]),
				ntohl(h->unsched_cutoffs[7]),
				ntohs(h->cutoff_version));
		break;
	}
	case FREEZE:
		/* Nothing to add here. */
		break;
	}
	buffer[buf_len-1] = 0;
	return buffer;
}

/**
 * homa_print_packet_short() - Print a human-readable string describing the
 * information in a Homa packet. This function generates a shorter
 * description than homa_print_packet.
 * @skb:     Packet whose information should be printed.
 * @buffer:  Buffer in which to generate the string.
 * @buf_len: Number of bytes available at @buffer.
 * 
 * Return:   @buffer
 */
char *homa_print_packet_short(struct sk_buff *skb, char *buffer, int buf_len)
{
	struct common_header *common =
			(struct common_header *) skb_transport_header(skb);
	switch (common->type) {
	case DATA: {
		struct data_header *h = (struct data_header *) common;
		struct data_segment *seg;
		int bytes_left, used, i;
		int seg_length = ntohl(h->seg.segment_length);
		
		used = homa_snprintf(buffer, buf_len, 0, "DATA%s %d@%d",
				h->retransmit ? " retrans" : "",
				seg_length, ntohl(h->seg.offset));
		bytes_left = skb->len - sizeof32(*h) - seg_length;
		for (i = skb_shinfo(skb)->gso_segs - 1; i > 0; i--) {
			seg = (struct data_segment *) (skb->data + skb->len
					- bytes_left);
			seg_length = ntohl(seg->segment_length);
			used = homa_snprintf(buffer, buf_len, used,
					" %d@%d", seg_length,
					ntohl(seg->offset));
			bytes_left -= sizeof32(*seg) + seg_length;
		}
		break;
	}
	case GRANT: {
		struct grant_header *h = (struct grant_header *) common;
		snprintf(buffer, buf_len, "GRANT %d@%d", ntohl(h->offset),
				h->priority);
		break;
	}
	case RESEND: {
		struct resend_header *h = (struct resend_header *) common;
		snprintf(buffer, buf_len, "RESEND %d-%d@%d", ntohl(h->offset),
				ntohl(h->offset) + ntohl(h->length) - 1,
				h->priority);
		break;
	}
	case RESTART:
		snprintf(buffer, buf_len, "RESTART");
		break;
	case BUSY:
		snprintf(buffer, buf_len, "BUSY");
		break;
	case CUTOFFS: 
		snprintf(buffer, buf_len, "CUTOFFS");
		break;
	case FREEZE:
		snprintf(buffer, buf_len, "FREEZE");
		break;
	default:
		snprintf(buffer, buf_len, "unknown packet type %d",
				common->type);
		break;
	}
	return buffer;
}

/**
 * homa_snprintf() - This function makes it easy to use a series of calls
 * to snprintf to gradually append information to a fixed-size buffer.
 * If the buffer fills, the function can continue to be called, but nothing
 * more will get added to the buffer.
 * @buffer:   Characters accumulate here.
 * @size:     Total space available in @buffer.
 * @used:     Number of bytes currently occupied in the buffer, not including
 *            a terminating null character; this is typically the result of
 *            the previous call to this function.
 * @format:   Format string suitable for passing to printf-like functions,
 *            followed by values for the various substitutions requested
 *            in @format
 * @ ...
 * 
 * Return:    The number of characters now occupied in @buffer, not
 *            including the terminating null character. 
 */
int homa_snprintf(char *buffer, int size, int used, const char* format, ...)
{
	int new_chars;
	
	va_list ap;
	va_start(ap, format);
	
	if (used >= (size-1))
		return used;
	
	new_chars = vsnprintf(buffer + used, size - used, format, ap);
	if (new_chars < 0)
		return used;
	if (new_chars >= (size - used))
		return size - 1;
	return used + new_chars;
}

/**
 * homa_symbol_for_state() - Returns a printable string describing an
 * RPC state.
 * @rpc:  RPC whose state should be returned in printable form.
 * 
 * Return: A static string holding the current state of @rpc.
 */
char *homa_symbol_for_state(struct homa_rpc *rpc)
{
	static char buffer[20];
	switch (rpc->state) {
	case RPC_OUTGOING:
		return "OUTGOING";
	case RPC_INCOMING:
		return "INCOMING";
	case RPC_READY:
		return "READY";
	case RPC_IN_SERVICE:
		return "IN_SERVICE";
	case RPC_DEAD:
		return "DEAD";
	}
	
	/* See safety comment in homa_symbol_for_type. */
	snprintf(buffer, sizeof(buffer)-1, "UNKNOWN(%u)", rpc->state);
	buffer[sizeof(buffer)-1] = 0;
	return buffer;
}

/**
 * homa_symbol_for_type() - Returns a printable string describing a packet type.
 * @type:  A value from those defined by &homa_packet_type.
 * 
 * Return: A static string holding the packet type corresponding to @type.
 */
char *homa_symbol_for_type(uint8_t type)
{
	static char buffer[20];
	switch (type) {
	case DATA:
		return "DATA";
	case GRANT:
		return "GRANT";
	case RESEND:
		return "RESEND";
	case RESTART:
		return "RESTART";
	case BUSY:
		return "BUSY";
	case CUTOFFS:
		return "CUTOFFS";
	case FREEZE:
		return "FREEZE";
	}
	
	/* Using a static buffer can produce garbled text under concurrency,
	 * but (a) it's unlikely (this code only executes if the opcode is
	 * bogus), (b) this is mostly for testing and debugging, and (c) the
	 * code below ensures that the string cannot run past the end of the
	 * buffer, so the code is safe. */
	snprintf(buffer, sizeof(buffer)-1, "UNKNOWN(%u)", type);
	buffer[sizeof(buffer)-1] = 0;
	return buffer;
}

/**
 * homa_append_metric() - Formats a new metric and appends it to homa->metrics.
 * @homa:        The new data will appended to the @metrics field of
 *               this structure.
 * @format:      Standard printf-style format string describing the
 *               new metric. Arguments after this provide the usual
 *               values expected for printf-like functions.
 */
void homa_append_metric(struct homa *homa, const char* format, ...)
{
	char *new_buffer;
	size_t new_chars;
	va_list ap;
	
	if (!homa->metrics) {
#ifdef __UNIT_TEST__
		homa->metrics_capacity =  30;
#else
		homa->metrics_capacity =  4096;
#endif
		homa->metrics =  kmalloc(homa->metrics_capacity, GFP_KERNEL);
		if (!homa->metrics) {
			printk(KERN_WARNING "homa_append_metric couldn't "
				"allocate memory\n");
			return;
		}
		homa->metrics_length = 0;
	}
	
	/* May have to execute this loop multiple times if we run out
	 * of space in homa->metrics; each iteration expands the storage,
	 * until eventually it is large enough.
	 */
	while (true) {
		va_start(ap, format);
		new_chars = vsnprintf(homa->metrics + homa->metrics_length,
				homa->metrics_capacity - homa->metrics_length,
				format, ap);
		va_end(ap);
		if ((homa->metrics_length + new_chars) < homa->metrics_capacity)
			break;
		
		/* Not enough room; expand buffer capacity. */
		homa->metrics_capacity *= 2;
		new_buffer = kmalloc(homa->metrics_capacity, GFP_KERNEL);
		if (!new_buffer) {
			printk(KERN_WARNING "homa_append_metric couldn't "
				"allocate memory\n");
			return;
		}
		memcpy(new_buffer, homa->metrics, homa->metrics_length);
		kfree(homa->metrics);
		homa->metrics = new_buffer;
	}
	homa->metrics_length += new_chars;
}

/**
 * homa_print_metrics() - Sample all of the Homa performance metrics and
 * generate a human-readable string describing all of them.
 * @homa:    Overall data about the Homa protocol implementation;
 *           the formatted string will be stored in homa->metrics.
 * 
 * Return:   The formatted string. 
 */
char *homa_print_metrics(struct homa *homa)
{
	int core, i, lower = 0;
	
	homa->metrics_length = 0;
	homa_append_metric(homa,
			"rdtsc_cycles         %20llu  "
			"RDTSC cycle counter when metrics were gathered\n",
			get_cycles());
	homa_append_metric(homa,
			"cpu_khz                   %15llu  "
			"Clock rate for RDTSC counter, in khz\n",
			cpu_khz);
	for (core = 0; core < nr_cpu_ids; core++) {
		struct homa_metrics *m = homa_metrics[core];
		homa_append_metric(homa,
				"core                      %15d  "
				"Core id for following metrics\n",
				core);
		for (i = 0; i < HOMA_NUM_SMALL_COUNTS; i++) {
			homa_append_metric(homa,
				"msg_bytes_%-9d       %15llu  "
				"Bytes in incoming messages containing "
				"%d-%d bytes\n",
				(i+1)*64, m->small_msg_bytes[i], lower,
				(i+1)*64);
			lower = (i+1)*64 + 1;
		}
		for (i = (HOMA_NUM_SMALL_COUNTS*64)/1024;
				i < HOMA_NUM_MEDIUM_COUNTS; i++) {
			homa_append_metric(homa,
				"msg_bytes_%-9d       %15llu  "
				"Bytes in incoming messages containing "
				"%d-%d bytes\n",
				(i+1)*1024, m->medium_msg_bytes[i], lower,
				(i+1)*1024);
			lower = (i+1)*1024 + 1;
		}
		homa_append_metric(homa,
				"large_msg_count           %15llu  "
				"# of incoming messages >= %d bytes\n",
				m->large_msg_count, lower);
		homa_append_metric(homa,
				"large_msg_bytes           %15llu  "
				"Bytes in incoming messages >= %d bytes\n",
				m->large_msg_bytes, lower);
		for (i = DATA; i < BOGUS;  i++) {
			char *symbol = homa_symbol_for_type(i);
			homa_append_metric(homa,
					"packets_sent_%-7s      %15llu  "
					"%s packets sent\n",
					symbol, m->packets_sent[i-DATA],
					symbol);
		}
		for (i = DATA; i < BOGUS;  i++) {
			char *symbol = homa_symbol_for_type(i);
			homa_append_metric(homa,
					"packets_rcvd_%-7s      %15llu  "
					"%s packets received\n",
					symbol, m->packets_received[i-DATA],
					symbol);
		}
		homa_append_metric(homa,
				"requests_received         %15llu  "
				"Incoming request messages\n",
				m->requests_received);
		homa_append_metric(homa,
				"responses_received        %15llu  "
				"Incoming response messages\n",
				m->responses_received);
		homa_append_metric(homa,
				"softirq_calls             %15llu  "
				"Calls to homa_softirq (i.e. # GRO pkts "
				"received)\n",
				m->softirq_calls);
		homa_append_metric(homa,
				"softirq_cycles            %15llu  "
				"Time spent in homa_softirq\n",
				m->softirq_cycles);
		homa_append_metric(homa,
				"napi_cycles               %15llu  "
				"Time spent in NAPI-level packet handlng\n",
				m->napi_cycles);
		homa_append_metric(homa,
				"send_cycles               %15llu  "
				"Time spent in homa_ioc_send kernel call\n",
				m->send_cycles);
		homa_append_metric(homa,
				"recv_cycles               %15llu  "
				"Time spent in homa_ioc_recv kernel call\n",
				m->recv_cycles - m->blocked_cycles);
		homa_append_metric(homa,
				"blocked_cycles            %15llu  "
				"Time spent blocked in homa_ioc_recv\n",
				m->blocked_cycles);
		homa_append_metric(homa,
				"reply_cycles              %15llu  "
				"Time spent in homa_ioc_reply kernel call\n",
				m->reply_cycles);
		homa_append_metric(homa,
				"manage_grants_cycles      %15llu  "
				"Time spent in manage_grants\n",
				m->manage_grants_cycles);
		homa_append_metric(homa,
				"timer_cycles              %15llu  "
				"Time spent in homa_timer\n",
				m->timer_cycles);
		homa_append_metric(homa,
				"pacer_cycles              %15llu  "
				"Time spent in homa_pacer\n",
				m->pacer_cycles);
		homa_append_metric(homa,
				"homa_cycles               %15llu  "
				"Total time in all Homa-related functions\n",
				m->softirq_cycles + m->napi_cycles +
				m->send_cycles + m->recv_cycles +
				m->reply_cycles - m->blocked_cycles +
				m->timer_cycles + m->pacer_cycles);
		homa_append_metric(homa,
				"pacer_lost_cycles         %15llu  "
				"Lost transmission time because pacer was "
				"slow\n",
				m->pacer_lost_cycles);
		homa_append_metric(homa,
				"pacer_skipped_rpcs        %15llu  "
				"Pacer aborts because of locked RPCs\n",
				m->pacer_skipped_rpcs);
		homa_append_metric(homa,
				"resent_packets            %15llu  "
				"DATA packets sent in response to RESENDs\n",
				m->resent_packets);
		homa_append_metric(homa,
				"peer_hash_links           %15llu  "
				"Hash chain link traversals in peer table\n",
				m->peer_hash_links);
		homa_append_metric(homa,
				"peer_new_entries          %15llu  "
				"New entries created in peer table\n",
				m->peer_new_entries);
		homa_append_metric(homa,
				"peer_kmalloc_errors       %15llu  "
				"kmalloc failures creating peer table "
				"entries\n",
				m->peer_kmalloc_errors);
		homa_append_metric(homa,
				"peer_route_errors         %15llu  "
				"Routing failures creating peer table "
				"entries\n",
				m->peer_route_errors);
		homa_append_metric(homa,
				"control_xmit_errors       %15llu  "
				"Errors sending control packets\n",
				m->control_xmit_errors);
		homa_append_metric(homa,
				"data_xmit_errors          %15llu  "
				"Errors sending data packets\n",
				m->data_xmit_errors);
		homa_append_metric(homa,
				"unknown_rpcs              %15llu  "
				"Packets discarded because RPC is unknown\n",
				m->unknown_rpcs);
		homa_append_metric(homa,
				"server_cant_create_rpcs   %15llu  "
				"Packets discarded because server "
				"couldn't create RPC\n",
				m->server_cant_create_rpcs);
		homa_append_metric(homa,
				"unknown_packet_types      %15llu  "
				"Packets discarded because of unsupported "
				"type\n",
				m->unknown_packet_types);
		homa_append_metric(homa,
				"short_packets             %15llu  "
				"Packets discarded because too short\n",
				m->short_packets);
		homa_append_metric(homa,
				"redundant_packets         %15llu  "
				"Packets discarded because data already "
				"received\n",
				m->redundant_packets);
		homa_append_metric(homa,
				"client_rpc_timeouts       %15llu  "
				"RPCs aborted by client because of timeout\n",
				m->client_rpc_timeouts);
		homa_append_metric(homa,
				"server_rpc_timeouts       %15llu  "
				"RPCs aborted by server because of timeout\n",
				m->server_rpc_timeouts);
		homa_append_metric(homa,
				"client_lock_misses        %15llu  "
				"Bucket lock misses for client RPCs\n",
				m->client_lock_misses);
		homa_append_metric(homa,
				"client_lock_miss_cycles   %15llu  "
				"Time lost waiting for client bucket locks\n",
				m->client_lock_miss_cycles);
		homa_append_metric(homa,
				"server_lock_misses        %15llu  "
				"Bucket lock misses for server RPCs\n",
				m->server_lock_misses);
		homa_append_metric(homa,
				"server_lock_miss_cycles   %15llu  "
				"Time lost waiting for server bucket locks\n",
				m->server_lock_miss_cycles);
		homa_append_metric(homa,
				"socket_lock_misses        %15llu  "
				"Socket lock misses\n",
				m->socket_lock_misses);
		homa_append_metric(homa,
				"socket_lock_miss_cycles   %15llu  "
				"Time lost waiting for socket locks\n",
				m->socket_lock_miss_cycles);
		homa_append_metric(homa,
				"grantable_lock_misses     %15llu  "
				"Grantable lock misses\n",
				m->grantable_lock_misses);
		homa_append_metric(homa,
				"grantable_lock_miss_cycles%15llu  "
				"Time lost waiting for grantable lock\n",
				m->grantable_lock_miss_cycles);
		homa_append_metric(homa,
				"throttle_lock_misses      %15llu  "
				"Throttle lock misses\n",
				m->throttle_lock_misses);
		homa_append_metric(homa,
				"throttle_lock_miss_cycles %15llu  "
				"Time lost waiting for throttle locks\n",
				m->throttle_lock_miss_cycles);
		homa_append_metric(homa,
				"disabled_reaps            %15llu  "
				"Reaper invocations that were disabled\n",
				m->disabled_reaps);
		homa_append_metric(homa,
				"disabled_rpc_reaps        %15llu  "
				"Disabled RPCs skipped by reaper\n",
				m->disabled_rpc_reaps);
		homa_append_metric(homa,
				"reaper_calls              %15llu  "
				"Reaper invocations that were not disabled\n",
				m->reaper_calls);
		homa_append_metric(homa,
				"reaper_dead_skbs          %15llu  "
				"Sum of hsk->dead_skbs across all reaper "
				"calls\n",
				m->reaper_dead_skbs);
		homa_append_metric(homa,
				"temp1                     %15llu  "
				"Temporary use in testing\n",
				m->temp1);
		homa_append_metric(homa,
				"temp2                     %15llu  "
				"Temporary use in testing\n",
				m->temp2);
		homa_append_metric(homa,
				"temp3                     %15llu  "
				"Temporary use in testing\n",
				m->temp3);
		homa_append_metric(homa,
				"temp4                     %15llu  "
				"Temporary use in testing\n",
				m->temp4);
	}

	return homa->metrics;
}

/**
 * homa_prios_changed() - This function is called whenever configuration
 * information related to priorities, such as @homa->unsched_cutoffs or
 * @homa->num_priorities, is modified. It adjusts the cutoffs if needed
 * to maintain consistency, and it updates other values that depend on
 * this information.
 * @homa: Contains the priority info to be checked and updated.
 */
void homa_prios_changed(struct homa *homa)
{
	int i;
	
	if (homa->num_priorities > HOMA_MAX_PRIORITIES)
		homa->num_priorities = HOMA_MAX_PRIORITIES;
	
	/* This guarantees that we will choose priority 0 if nothing else
	 * in the cutoff array matches.
	 */
	homa->unsched_cutoffs[0] = INT_MAX;
	
	for (i = HOMA_MAX_PRIORITIES-1; ; i--) {
		if (i >= homa->num_priorities) {
			homa->unsched_cutoffs[i] = 0;
			continue;
		}
		if (i == 0) {
			homa->unsched_cutoffs[i] = INT_MAX;
			homa->max_sched_prio = 0;
			break;
		}
		if ((homa->unsched_cutoffs[i] >= HOMA_MAX_MESSAGE_SIZE)) {
			homa->max_sched_prio = i-1;
			break;
		}
	}
	homa->cutoff_version++;
}

/**
 * homa_spin() - Delay (without sleeping) for a given time interval.
 * @usecs:   How long to delay (in microseconds)
 */
void homa_spin(int usecs)
{
	__u64 end;
	end = get_cycles() + (usecs*cpu_khz)/1000;
	while (get_cycles() < end) {
		/* Empty loop body.*/
	}
}

/**
 * homa_free_skbs() - Free all of the skbs in a list.
 * @head:    First in a list of socket buffers linked through homa_next_skb.
 */
void homa_free_skbs(struct sk_buff *head)
{
	while (head) {
		struct sk_buff *next = *homa_next_skb(head);
		kfree_skb(head);
		head = next;
	}
}

/**
 * homa_grantable_lock_slow() - This function implements the slow path for
 * acquiring the grantable lock. It is invoked when the lock isn't immediately
 * available. It waits for the lock, but also records statistics about
 * the waiting time.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_grantable_lock_slow(struct homa *homa)
{
	__u64 start = get_cycles();
	tt_record("beginning wait for grantable lock");
	spin_lock_bh(&homa->grantable_lock);
	tt_record("ending wait for grantable lock");
	INC_METRIC(grantable_lock_misses, 1);
	INC_METRIC(grantable_lock_miss_cycles, get_cycles() - start);
}

/**
 * homa_throttle_lock_slow() - This function implements the slow path for
 * acquiring the throttle lock. It is invoked when the lock isn't immediately
 * available. It waits for the lock, but also records statistics about
 * the waiting time.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_throttle_lock_slow(struct homa *homa)
{
	__u64 start = get_cycles();
	tt_record("beginning wait for throttle lock");
	spin_lock_bh(&homa->throttle_lock);
	tt_record("ending wait for throttle lock");
	INC_METRIC(throttle_lock_misses, 1);
	INC_METRIC(throttle_lock_miss_cycles, get_cycles() - start);
}