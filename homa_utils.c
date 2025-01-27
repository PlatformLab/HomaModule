// SPDX-License-Identifier: BSD-2-Clause

/* This file contains miscellaneous utility functions for Homa, such
 * as initializing and destroying homa structs.
 */

#include "homa_impl.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#include "homa_skb.h"

struct completion homa_pacer_kthread_done;

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
	int i, err;

	_Static_assert(HOMA_MAX_PRIORITIES >= 8,
		       "homa_init assumes at least 8 priority levels");

	homa->pacer_kthread = NULL;
	init_completion(&homa_pacer_kthread_done);
	atomic64_set(&homa->next_outgoing_id, 2);
	atomic64_set(&homa->link_idle_time, sched_clock());
	spin_lock_init(&homa->grantable_lock);
	homa->grantable_lock_time = 0;
	atomic_set(&homa->grant_recalc_count, 0);
	INIT_LIST_HEAD(&homa->grantable_peers);
	INIT_LIST_HEAD(&homa->grantable_rpcs);
	homa->num_grantable_rpcs = 0;
	homa->last_grantable_change = sched_clock();
	homa->max_grantable_rpcs = 0;
	homa->oldest_rpc = NULL;
	homa->num_active_rpcs = 0;
	for (i = 0; i < HOMA_MAX_GRANTS; i++) {
		homa->active_rpcs[i] = NULL;
		atomic_set(&homa->active_remaining[i], 0);
	}
	homa->grant_nonfifo = 0;
	homa->grant_nonfifo_left = 0;
	spin_lock_init(&homa->pacer_mutex);
	homa->pacer_fifo_fraction = 50;
	homa->pacer_fifo_count = 1;
	homa->pacer_wake_time = 0;
	spin_lock_init(&homa->throttle_lock);
	INIT_LIST_HEAD_RCU(&homa->throttled_rpcs);
	homa->throttle_add = 0;
	homa->throttle_min_bytes = 200;
	atomic_set(&homa->total_incoming, 0);
	homa->prev_default_port = HOMA_MIN_DEFAULT_PORT - 1;
	homa->port_map = kmalloc(sizeof(*homa->port_map), GFP_KERNEL);
	if (!homa->port_map) {
		pr_err("%s couldn't create port_map: kmalloc failure",
		       __func__);
		return -ENOMEM;
	}
	homa_socktab_init(homa->port_map);
	homa->peers = kmalloc(sizeof(*homa->peers), GFP_KERNEL);
	if (!homa->peers) {
		pr_err("%s couldn't create peers: kmalloc failure", __func__);
		return -ENOMEM;
	}
	err = homa_peertab_init(homa->peers);
	if (err) {
		pr_err("%s couldn't initialize peer table (errno %d)\n",
		       __func__, -err);
		return err;
	}
	err = homa_skb_init(homa);
	if (err) {
		pr_err("Couldn't initialize skb management (errno %d)\n",
		       -err);
		return err;
	}

	/* Wild guesses to initialize configuration values... */
	homa->unsched_bytes = 40000;
	homa->window_param = 100000;
	homa->link_mbps = 25000;
	homa->poll_usecs = 50;
	homa->num_priorities = HOMA_MAX_PRIORITIES;
	for (i = 0; i < HOMA_MAX_PRIORITIES; i++)
		homa->priority_map[i] = i;
	homa->max_sched_prio = HOMA_MAX_PRIORITIES - 5;
	homa->unsched_cutoffs[HOMA_MAX_PRIORITIES - 1] = 200;
	homa->unsched_cutoffs[HOMA_MAX_PRIORITIES - 2] = 2800;
	homa->unsched_cutoffs[HOMA_MAX_PRIORITIES - 3] = 15000;
	homa->unsched_cutoffs[HOMA_MAX_PRIORITIES - 4] = HOMA_MAX_MESSAGE_LENGTH;
#ifdef __UNIT_TEST__
	/* Unit tests won't send CUTOFFS messages unless the test changes
	 * this variable.
	 */
	homa->cutoff_version = 0;
#else
	homa->cutoff_version = 1;
#endif
	homa->fifo_grant_increment = 10000;
	homa->grant_fifo_fraction = 50;
	homa->max_overcommit = 8;
	homa->max_incoming = 400000;
	homa->max_rpcs_per_peer = 1;
	homa->resend_ticks = 5;
	homa->resend_interval = 5;
	homa->timeout_ticks = 100;
	homa->timeout_resends = 5;
	homa->request_ack_ticks = 2;
	homa->reap_limit = 10;
	homa->dead_buffs_limit = 5000;
	homa->max_dead_buffs = 0;
	homa->pacer_kthread = kthread_run(homa_pacer_main, homa,
					  "homa_pacer");
	if (IS_ERR(homa->pacer_kthread)) {
		err = PTR_ERR(homa->pacer_kthread);
		homa->pacer_kthread = NULL;
		pr_err("couldn't create homa pacer thread: error %d\n", err);
		return err;
	}
	homa->pacer_exit = false;
	homa->max_nic_queue_ns = 5000;
	homa->ns_per_mbyte = 0;
	homa->verbose = 0;
	homa->max_gso_size = 10000;
	homa->gso_force_software = 0;
	homa->hijack_tcp = 0;
	homa->max_gro_skbs = 20;
	homa->gro_policy = HOMA_GRO_NORMAL;
	homa->busy_usecs = 100;
	homa->gro_busy_usecs = 5;
	homa->timer_ticks = 0;
	mutex_init(&homa->metrics_mutex);
	homa->metrics = NULL;
	homa->metrics_capacity = 0;
	homa->metrics_length = 0;
	homa->metrics_active_opens = 0;
	homa->flags = 0;
	homa->freeze_type = 0;
	homa->bpage_lease_usecs = 10000;
	homa->next_id = 0;
	homa_outgoing_sysctl_changed(homa);
	homa_incoming_sysctl_changed(homa);
	return 0;
}

/**
 * homa_destroy() -  Destructor for homa objects.
 * @homa:      Object to destroy.
 */
void homa_destroy(struct homa *homa)
{
#ifdef __UNIT_TEST__
#include "utils.h"
	unit_homa_destroy(homa);
#endif /* __UNIT_TEST__ */
	if (homa->pacer_kthread) {
		homa_pacer_stop(homa);
		wait_for_completion(&homa_pacer_kthread_done);
	}

	/* The order of the following statements matters! */
	if (homa->port_map) {
		homa_socktab_destroy(homa->port_map);
		kfree(homa->port_map);
		homa->port_map = NULL;
	}
	if (homa->peers) {
		homa_peertab_destroy(homa->peers);
		kfree(homa->peers);
		homa->peers = NULL;
	}
	homa_skb_cleanup(homa);
	kfree(homa->metrics);
	homa->metrics = NULL;
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
#define NUM_BUFS_IPV4 4
#define BUF_SIZE_IPV4 30
	static char buffers[NUM_BUFS_IPV4][BUF_SIZE_IPV4];
	u32 a2 = ntohl(addr);
	static int next_buf;
	char *buffer;

	buffer = buffers[next_buf];
	next_buf++;
	if (next_buf >= NUM_BUFS_IPV4)
		next_buf = 0;
	snprintf(buffer, BUF_SIZE_IPV4, "%u.%u.%u.%u", (a2 >> 24) & 0xff,
		 (a2 >> 16) & 0xff, (a2 >> 8) & 0xff, a2 & 0xff);
	return buffer;
}

/**
 * homa_print_ipv6_addr() - Convert an IPv6 address to a human-readable string
 * representation. IPv4-mapped addresses are printed in IPv4 syntax.
 * @addr:    Address to convert, in network byte order.
 *
 * Return:   The converted value. Values are stored in static memory, so
 *           the caller need not free. This also means that storage is
 *           eventually reused (there are enough buffers to accommodate
 *           multiple "active" values).
 */
char *homa_print_ipv6_addr(const struct in6_addr *addr)
{
#define NUM_BUFS BIT(2)
#define BUF_SIZE 64
	static char buffers[NUM_BUFS][BUF_SIZE];
	static int next_buf;
	char *buffer;

	buffer = buffers[next_buf];
	next_buf++;
	if (next_buf >= NUM_BUFS)
		next_buf = 0;
#ifdef __UNIT_TEST__
	struct in6_addr zero = {};

	if (ipv6_addr_equal(addr, &zero)) {
		snprintf(buffer, BUF_SIZE, "0.0.0.0");
	} else if ((addr->s6_addr32[0] == 0) &&
		(addr->s6_addr32[1] == 0) &&
		(addr->s6_addr32[2] == htonl(0x0000ffff))) {
		u32 a2 = ntohl(addr->s6_addr32[3]);

		snprintf(buffer, BUF_SIZE, "%u.%u.%u.%u", (a2 >> 24) & 0xff,
			 (a2 >> 16) & 0xff, (a2 >> 8) & 0xff, a2 & 0xff);
	} else {
		const char *inet_ntop(int af, const void *src, char *dst,
				      size_t size);
		inet_ntop(AF_INET6, addr, buffer + 1, BUF_SIZE);
		buffer[0] = '[';
		strcat(buffer, "]");
	}
#else
	snprintf(buffer, BUF_SIZE, "%pI6", addr);
#endif
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
	struct homa_common_hdr *common;
	char header[HOMA_MAX_HEADER];
	struct in6_addr saddr;
	int used = 0;

	if (!skb) {
		snprintf(buffer, buf_len, "skb is NULL!");
		buffer[buf_len - 1] = 0;
		return buffer;
	}

	homa_skb_get(skb, &header, 0, sizeof(header));
	common = (struct homa_common_hdr *)header;
	saddr = skb_canonical_ipv6_saddr(skb);
	used = homa_snprintf(buffer, buf_len, used,
			     "%s from %s:%u, dport %d, id %llu",
			     homa_symbol_for_type(common->type),
			     homa_print_ipv6_addr(&saddr),
			     ntohs(common->sport), ntohs(common->dport),
			     be64_to_cpu(common->sender_id));
	switch (common->type) {
	case DATA: {
		struct homa_skb_info *homa_info = homa_get_skb_info(skb);
		struct homa_data_hdr *h = (struct homa_data_hdr *)header;
		int data_left, i, seg_length, pos, offset;

		if (skb_shinfo(skb)->gso_segs == 0) {
			seg_length = homa_data_len(skb);
			data_left = 0;
		} else {
			seg_length = homa_info->seg_length;
			if (seg_length > homa_info->data_bytes)
				seg_length = homa_info->data_bytes;
			data_left = homa_info->data_bytes - seg_length;
		}
		offset = ntohl(h->seg.offset);
		if (offset == -1)
			offset = ntohl(h->common.sequence);
		used = homa_snprintf(buffer, buf_len, used,
				     ", message_length %d, offset %d, data_length %d, incoming %d",
				     ntohl(h->message_length), offset,
				     seg_length, ntohl(h->incoming));
		if (ntohs(h->cutoff_version) != 0)
			used = homa_snprintf(buffer, buf_len, used,
					     ", cutoff_version %d",
					     ntohs(h->cutoff_version));
		if (h->retransmit)
			used = homa_snprintf(buffer, buf_len, used,
					     ", RETRANSMIT");
		if (skb_shinfo(skb)->gso_type == 0xd)
			used = homa_snprintf(buffer, buf_len, used,
					     ", TSO disabled");
		if (skb_shinfo(skb)->gso_segs <= 1)
			break;
		pos = skb_transport_offset(skb) + sizeof32(*h) + seg_length;
		used = homa_snprintf(buffer, buf_len, used, ", extra segs");
		for (i = skb_shinfo(skb)->gso_segs - 1; i > 0; i--) {
			if (homa_info->seg_length < skb_shinfo(skb)->gso_size) {
				struct homa_seg_hdr seg;

				homa_skb_get(skb, &seg, pos, sizeof(seg));
				offset = ntohl(seg.offset);
			} else {
				offset += seg_length;
			}
			if (seg_length > data_left)
				seg_length = data_left;
			used = homa_snprintf(buffer, buf_len, used,
					     " %d@%d", seg_length, offset);
			data_left -= seg_length;
			pos += skb_shinfo(skb)->gso_size;
		};
		break;
	}
	case GRANT: {
		struct homa_grant_hdr *h = (struct homa_grant_hdr *)header;
		char *resend = (h->resend_all) ? ", resend_all" : "";

		used = homa_snprintf(buffer, buf_len, used,
				     ", offset %d, grant_prio %u%s",
				     ntohl(h->offset), h->priority, resend);
		break;
	}
	case RESEND: {
		struct homa_resend_hdr *h = (struct homa_resend_hdr *)header;

		used = homa_snprintf(buffer, buf_len, used,
				     ", offset %d, length %d, resend_prio %u",
				     ntohl(h->offset), ntohl(h->length),
				     h->priority);
		break;
	}
	case UNKNOWN:
		/* Nothing to add here. */
		break;
	case BUSY:
		/* Nothing to add here. */
		break;
	case CUTOFFS: {
		struct homa_cutoffs_hdr *h = (struct homa_cutoffs_hdr *)header;

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
	case NEED_ACK:
		/* Nothing to add here. */
		break;
	case ACK: {
		struct homa_ack_hdr *h = (struct homa_ack_hdr *)header;
		int i, count;

		count = ntohs(h->num_acks);
		used = homa_snprintf(buffer, buf_len, used, ", acks");
		for (i = 0; i < count; i++) {
			used = homa_snprintf(buffer, buf_len, used,
					     " [sp %d, id %llu]",
					     ntohs(h->acks[i].server_port),
					     be64_to_cpu(h->acks[i].client_id));
		}
		break;
	}
	}

	buffer[buf_len - 1] = 0;
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
	struct homa_common_hdr *common;
	char header[HOMA_MAX_HEADER];

	common = (struct homa_common_hdr *)header;
	homa_skb_get(skb, header, 0, HOMA_MAX_HEADER);
	switch (common->type) {
	case DATA: {
		struct homa_data_hdr *h = (struct homa_data_hdr *)header;
		struct homa_skb_info *homa_info = homa_get_skb_info(skb);
		int data_left, used, i, seg_length, pos, offset;

		if (skb_shinfo(skb)->gso_segs == 0) {
			seg_length = homa_data_len(skb);
			data_left = 0;
		} else {
			seg_length = homa_info->seg_length;
			data_left = homa_info->data_bytes - seg_length;
		}
		offset = ntohl(h->seg.offset);
		if (offset == -1)
			offset = ntohl(h->common.sequence);

		pos = skb_transport_offset(skb) + sizeof32(*h) + seg_length;
		used = homa_snprintf(buffer, buf_len, 0, "DATA%s %d@%d",
				     h->retransmit ? " retrans" : "",
				     seg_length, offset);
		for (i = skb_shinfo(skb)->gso_segs - 1; i > 0; i--) {
			if (homa_info->seg_length < skb_shinfo(skb)->gso_size) {
				struct homa_seg_hdr seg;

				homa_skb_get(skb, &seg, pos, sizeof(seg));
				offset = ntohl(seg.offset);
			} else {
				offset += seg_length;
			}
			if (seg_length > data_left)
				seg_length = data_left;
			used = homa_snprintf(buffer, buf_len, used,
					     " %d@%d", seg_length, offset);
			data_left -= seg_length;
			pos += skb_shinfo(skb)->gso_size;
		}
		break;
	}
	case GRANT: {
		struct homa_grant_hdr *h = (struct homa_grant_hdr *)header;
		char *resend = h->resend_all ? " resend_all" : "";

		snprintf(buffer, buf_len, "GRANT %d@%d%s", ntohl(h->offset),
			 h->priority, resend);
		break;
	}
	case RESEND: {
		struct homa_resend_hdr *h = (struct homa_resend_hdr *)header;

		snprintf(buffer, buf_len, "RESEND %d-%d@%d", ntohl(h->offset),
			 ntohl(h->offset) + ntohl(h->length) - 1,
			 h->priority);
		break;
	}
	case UNKNOWN:
		snprintf(buffer, buf_len, "UNKNOWN");
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
	case NEED_ACK:
		snprintf(buffer, buf_len, "NEED_ACK");
		break;
	case ACK:
		snprintf(buffer, buf_len, "ACK");
		break;
	default:
		snprintf(buffer, buf_len, "unknown packet type 0x%x",
			 common->type);
		break;
	}
	return buffer;
}

/**
 * homa_freeze_peers() - Send FREEZE packets to all known peers.
 * @homa:   Provides info about peers.
 */
void homa_freeze_peers(struct homa *homa)
{
	struct homa_socktab_scan scan;
	struct homa_freeze_hdr freeze;
	struct homa_peer **peers;
	int num_peers, i, err;
	struct homa_sock *hsk;

	/* Find a socket to use (any will do). */
	rcu_read_lock();
	hsk = homa_socktab_start_scan(homa->port_map, &scan);
	homa_socktab_end_scan(&scan);
	if (!hsk) {
		tt_record("homa_freeze_peers couldn't find a socket");
		goto done;
	}

	peers = homa_peertab_get_peers(homa->peers, &num_peers);
	if (!peers) {
		tt_record("homa_freeze_peers couldn't find peers to freeze");
		goto done;
	}
	freeze.common.type = FREEZE;
	freeze.common.sport = htons(hsk->port);
	freeze.common.dport = 0;
	freeze.common.flags = HOMA_TCP_FLAGS;
	freeze.common.urgent = htons(HOMA_TCP_URGENT);
	freeze.common.sender_id = 0;
	for (i = 0; i < num_peers; i++) {
		tt_record1("Sending freeze to 0x%x", tt_addr(peers[i]->addr));
		err = __homa_xmit_control(&freeze, sizeof(freeze), peers[i], hsk);
		if (err != 0)
			tt_record2("homa_freeze_peers got error %d in xmit to 0x%x\n",
				   err, tt_addr(peers[i]->addr));
	}
	kfree(peers);

done:
	rcu_read_unlock();
	return;
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
int homa_snprintf(char *buffer, int size, int used, const char *format, ...)
{
	int new_chars;
	va_list ap;

	va_start(ap, format);

	if (used >= (size - 1))
		return used;

	new_chars = vsnprintf(buffer + used, size - used, format, ap);
	if (new_chars < 0)
		return used;
	if (new_chars >= (size - used))
		return size - 1;
	return used + new_chars;
}

/**
 * homa_symbol_for_type() - Returns a printable string describing a packet type.
 * @type:  A value from those defined by &homa_packet_type.
 *
 * Return: A static string holding the packet type corresponding to @type.
 */
char *homa_symbol_for_type(uint8_t type)
{
	switch (type) {
	case DATA:
		return "DATA";
	case GRANT:
		return "GRANT";
	case RESEND:
		return "RESEND";
	case UNKNOWN:
		return "UNKNOWN";
	case BUSY:
		return "BUSY";
	case CUTOFFS:
		return "CUTOFFS";
	case FREEZE:
		return "FREEZE";
	case NEED_ACK:
		return "NEED_ACK";
	case ACK:
		return "ACK";
	}
	return "??";
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

	for (i = HOMA_MAX_PRIORITIES - 1; ; i--) {
		if (i >= homa->num_priorities) {
			homa->unsched_cutoffs[i] = 0;
			continue;
		}
		if (i == 0) {
			homa->unsched_cutoffs[i] = INT_MAX;
			homa->max_sched_prio = 0;
			break;
		}
		if (homa->unsched_cutoffs[i] >= HOMA_MAX_MESSAGE_LENGTH) {
			homa->max_sched_prio = i - 1;
			break;
		}
	}
	homa->cutoff_version++;
}

/**
 * homa_spin() - Delay (without sleeping) for a given time interval.
 * @ns:   How long to delay (in nanoseconds)
 */
void homa_spin(int ns)
{
	u64 end;

	end = sched_clock() + ns;
	while (sched_clock() < end)
		/* Empty loop body.*/
		;
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_throttle_lock_slow() - This function implements the slow path for
 * acquiring the throttle lock. It is invoked when the lock isn't immediately
 * available. It waits for the lock, but also records statistics about
 * the waiting time.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_throttle_lock_slow(struct homa *homa)
	__acquires(&homa->throttle_lock)
{
	u64 start = sched_clock();

	tt_record("beginning wait for throttle lock");
	spin_lock_bh(&homa->throttle_lock);
	tt_record("ending wait for throttle lock");
	INC_METRIC(throttle_lock_misses, 1);
	INC_METRIC(throttle_lock_miss_ns, sched_clock() - start);
}

/**
 * homa_freeze() - Freezes the timetrace if a particular kind of freeze
 * has been requested through sysctl.
 * @rpc:      If we freeze our timetrace, we'll also send a freeze request
 *            to the peer for this RPC.
 * @type:     Condition that just occurred. If this doesn't match the
 *            externally set "freeze_type" value, then we don't freeze.
 * @format:   Format string used to generate a time trace record describing
 *            the reason for the freeze; must include "id %d, peer 0x%x"
 */
void homa_freeze(struct homa_rpc *rpc, enum homa_freeze_type type, char *format)
{
	if (type != rpc->hsk->homa->freeze_type)
		return;
	rpc->hsk->homa->freeze_type = 0;
	if (!atomic_read(&tt_frozen)) {
//		struct homa_freeze_hdr freeze;
		int dummy;

		pr_notice("freezing in %s with freeze_type %d\n", __func__,
			  type);
		tt_record1("homa_freeze calling homa_rpc_log_active with freeze_type %d", type);
		homa_rpc_log_active_tt(rpc->hsk->homa, 0);
		homa_validate_incoming(rpc->hsk->homa, 1, &dummy);
		pr_notice("%s\n", format);
		tt_record2(format, rpc->id, tt_addr(rpc->peer->addr));
		tt_freeze();
//		homa_xmit_control(FREEZE, &freeze, sizeof(freeze), rpc);
		homa_freeze_peers(rpc->hsk->homa);
	}
}
#endif /* See strip.py */
