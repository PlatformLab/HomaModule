// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

/* This file contains functions that are useful to have in Homa during
 * development, but aren't needed in production versions.
 */

#include "homa_impl.h"
#include "homa_devel.h"
#include "homa_grant.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#ifndef __STRIP__ /* See strip.py */
#include "homa_skb.h"
#else /* See strip.py */
#include "homa_stub.h"
#endif /* See strip.py */
#include "homa_wire.h"

#ifndef __STRIP__ /* See strip.py */
/* homa_drop_packet will accept this many more packets before it drops some. */
static int accept_count;

/* If accept_count <= 0, homa_drop_packet will drop this many packets
 * before it starts accepting again.
 */
static int drop_count;

/* Used for random-number generation. */
static u32 seed;
#endif /* See strip.py */

/* Used to record a history of rx state. */
#define MAX_RX_SNAPSHOTS 1000
static struct homa_rpc_snapshot rpc_snapshots[MAX_RX_SNAPSHOTS];
static int next_snapshot;

/* homa_clock() time when most recent rx snapshot was taken. */
u64 snapshot_time;

/* Interval between rx snapshots in ms. */
#define RX_SNAPSHOT_INTERVAL 20

/* Interval between rx snapshots, in homa_clock() units. */
u64 snapshot_interval;

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
#ifndef __STRIP__ /* See strip.py */
		used = homa_snprintf(buffer, buf_len, used,
				     ", message_length %d, offset %d, data_length %d, incoming %d",
				     ntohl(h->message_length), offset,
				     seg_length, ntohl(h->incoming));
		if (ntohs(h->cutoff_version) != 0)
			used = homa_snprintf(buffer, buf_len, used,
					     ", cutoff_version %d",
					     ntohs(h->cutoff_version));
#else /* See strip.py */
		used = homa_snprintf(buffer, buf_len, used,
				     ", message_length %d, offset %d, data_length %d",
				     ntohl(h->message_length), offset,
				     seg_length);
#endif /* See strip.py */
		if (h->retransmit)
			used = homa_snprintf(buffer, buf_len, used,
					     ", RETRANSMIT");
		if (skb_shinfo(skb)->gso_type == 0xd)
			used = homa_snprintf(buffer, buf_len, used,
					     ", TSO disabled");
		if (skb_shinfo(skb)->gso_segs <= 1)
			break;
		pos = skb_transport_offset(skb) + sizeof(*h) + seg_length;
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
#ifndef __STRIP__ /* See strip.py */
	case GRANT: {
		struct homa_grant_hdr *h = (struct homa_grant_hdr *)header;

		used = homa_snprintf(buffer, buf_len, used,
				     ", offset %d, grant_prio %u",
				     ntohl(h->offset), h->priority);
		break;
	}
#endif /* See strip.py */
	case RESEND: {
		struct homa_resend_hdr *h = (struct homa_resend_hdr *)header;

#ifndef __STRIP__ /* See strip.py */
		used = homa_snprintf(buffer, buf_len, used,
				     ", offset %d, length %d, resend_prio %u",
				     ntohl(h->offset), ntohl(h->length),
				     h->priority);
#else /* See strip.py */
		used = homa_snprintf(buffer, buf_len, used,
				     ", offset %d, length %d",
				     ntohl(h->offset), ntohl(h->length));
#endif /* See strip.py */
		break;
	}
	case RPC_UNKNOWN:
		/* Nothing to add here. */
		break;
	case BUSY:
		/* Nothing to add here. */
		break;
#ifndef __STRIP__ /* See strip.py */
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
#endif /* See strip.py */
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

		pos = skb_transport_offset(skb) + sizeof(*h) + seg_length;
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
#ifndef __STRIP__ /* See strip.py */
	case GRANT: {
		struct homa_grant_hdr *h = (struct homa_grant_hdr *)header;

		snprintf(buffer, buf_len, "GRANT %d@%d", ntohl(h->offset),
			 h->priority);
		break;
	}
#endif /* See strip.py */
	case RESEND: {
		struct homa_resend_hdr *h = (struct homa_resend_hdr *)header;

#ifndef __STRIP__ /* See strip.py */
		snprintf(buffer, buf_len, "RESEND %d-%d@%d", ntohl(h->offset),
			 ntohl(h->offset) + ntohl(h->length) - 1,
			 h->priority);
#else /* See strip.py */
		snprintf(buffer, buf_len, "RESEND %d-%d", ntohl(h->offset),
			 ntohl(h->offset) + ntohl(h->length) - 1);
#endif /* See strip.py */
		break;
	}
	case RPC_UNKNOWN:
		snprintf(buffer, buf_len, "RPC_UNKNOWN");
		break;
	case BUSY:
		snprintf(buffer, buf_len, "BUSY");
		break;
#ifndef __STRIP__ /* See strip.py */
	case CUTOFFS:
		snprintf(buffer, buf_len, "CUTOFFS");
		break;
	case FREEZE:
		snprintf(buffer, buf_len, "FREEZE");
		break;
#endif /* See strip.py */
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
 * homa_freeze_peers() - Send FREEZE packets to all known peers in the
 * root network namespace.
 */
void homa_freeze_peers(void)
{
	struct homa_socktab_scan scan;
	struct homa_freeze_hdr freeze;
	struct rhashtable_iter iter;
	struct homa_peer *peer;
	struct homa_sock *hsk;
	struct homa_net *hnet;
	int err;

	/* Find a socket to use (any socket for the namespace will do). */
	hnet = homa_net(&init_net);
	rcu_read_lock();
	hsk = homa_socktab_start_scan(hnet->homa->socktab, &scan);
	while (hsk && hsk->hnet != hnet)
		hsk = homa_socktab_next(&scan);
	homa_socktab_end_scan(&scan);
	if (!hsk) {
		tt_record("homa_freeze_peers couldn't find a socket");
		goto done;
	}

	freeze.common.type = FREEZE;
	freeze.common.sport = htons(hsk->port);
	freeze.common.dport = 0;
	IF_NO_STRIP(freeze.common.flags = HOMA_TCP_FLAGS);
	IF_NO_STRIP(freeze.common.urgent = htons(HOMA_TCP_URGENT));
	freeze.common.sender_id = 0;

	rhashtable_walk_enter(&hnet->homa->peertab->ht, &iter);
	rhashtable_walk_start(&iter);
	while (true) {
		peer = rhashtable_walk_next(&iter);
		if (!peer)
			break;
		if (IS_ERR(peer))
			/* Resize event occurred and walk will restart;
			 * that could result in duplicate freezes, but
			 * that's OK.
			 */
			continue;
		if (peer->ht_key.hnet != hnet)
			continue;
		tt_record1("Sending freeze to 0x%x", tt_addr(peer->addr));
		err = __homa_xmit_control(&freeze, sizeof(freeze), peer, hsk);
		if (err != 0)
			tt_record2("homa_freeze_peers got error %d in xmit to 0x%x\n",
				   err, tt_addr(peer->addr));
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

done:
	rcu_read_unlock();
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
	case RPC_IN_SERVICE:
		return "IN_SERVICE";
	case RPC_DEAD:
		return "DEAD";
	}

	/* See safety comment in homa_symbol_for_type. */
	snprintf(buffer, sizeof(buffer) - 1, "unknown(%u)", rpc->state);
	buffer[sizeof(buffer) - 1] = 0;
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
	switch (type) {
	case DATA:
		return "DATA";
#ifndef __STRIP__ /* See strip.py */
	case GRANT:
		return "GRANT";
#endif /* See strip.py */
	case RESEND:
		return "RESEND";
	case RPC_UNKNOWN:
		return "RPC_UNKNOWN";
	case BUSY:
		return "BUSY";
#ifndef __STRIP__ /* See strip.py */
	case CUTOFFS:
		return "CUTOFFS";
	case FREEZE:
		return "FREEZE";
#endif /* See strip.py */
	case NEED_ACK:
		return "NEED_ACK";
	case ACK:
		return "ACK";
	}
	return "??";
}

#ifndef __STRIP__ /* See strip.py */
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
		homa_freeze_peers();
	}
}
#endif /* See strip.py */

/**
 * homa_check_addr() - Verify that an address falls within the allowable
 * range for kernel data. If not, crash the kernel.
 * @p:  Address to check.
 */
void homa_check_addr(void *p)
{
	uintptr_t addr = (uintptr_t)p;

	if ((addr & 0xffff800000000000) != 0xffff800000000000) {
		pr_err("homa_check_addr received bogus address 0x%lx\n", addr);
		tt_dbg1("foo");
		BUG_ON(1);
	}
}

/**
 * homa_check_list() - Scan a list to make sure its pointer structure is
 * not corrupted and that its length is bounded. Crashes the kernel if
 * a problem is found.
 * @list:        Head of list to scan.
 * @max_length:  If the list has more than this many elements, it is
 *               assumed to have an internal loop.
 */
void homa_check_list(struct list_head *list, int max_length)
{
	struct list_head *p, *prev;
	int num_elems;

	homa_check_addr(list->next);
	homa_check_addr(list->prev);
	prev = list;
	for (p = list->next, num_elems = 0; ; p = p->next, num_elems++) {
		if (p->prev != prev) {
			pr_err("homa_check_list found bogus list structure: p->prev 0x%px, prev 0x%px\n",
			       p->prev, prev);
			tt_dbg1("foo");
			BUG_ON(1);
		}
		if (p == list)
			break;
		if (num_elems > max_length) {
			pr_err("homa_check_list found list with > %d elements\n",
			       max_length);
			tt_dbg1("foo");
			BUG_ON(1);
		}
		homa_check_addr(p->next);
		homa_check_addr(p->prev);
		prev = p;
	}
}

/**
 * homa_rpc_log() - Log info about a particular RPC; this is functionality
 * pulled out of homa_rpc_log_active because its indentation got too deep.
 * @rpc:  RPC for which key info should be written to the system log.
 */
void homa_rpc_log(struct homa_rpc *rpc)
{
	char *type = homa_is_client(rpc->id) ? "Client" : "Server";
	char *peer = homa_print_ipv6_addr(&rpc->peer->addr);

	if (rpc->state == RPC_INCOMING)
		pr_notice("%s RPC INCOMING, id %llu, peer %s:%d, %d/%d bytes received, incoming %d\n",
			  type, rpc->id, peer, rpc->dport,
			  rpc->msgin.length - rpc->msgin.bytes_remaining,
#ifndef __STRIP__
			  rpc->msgin.length, rpc->msgin.granted);
#else
			  rpc->msgin.length, 0);
#endif /* __STRIP__ */
	else if (rpc->state == RPC_OUTGOING) {
		pr_notice("%s RPC OUTGOING, id %llu, peer %s:%d, out length %d, left %d, granted %d, in left %d, resend_ticks %u, silent_ticks %d\n",
			  type, rpc->id, peer, rpc->dport, rpc->msgout.length,
			  rpc->msgout.length - rpc->msgout.next_xmit_offset,
#ifndef __STRIP__
			  rpc->msgout.granted, rpc->msgin.bytes_remaining,
#else
			  0, rpc->msgin.bytes_remaining,
#endif /* __STRIP__ */
			  rpc->resend_timer_ticks, rpc->silent_ticks);
	} else {
		pr_notice("%s RPC %s, id %llu, peer %s:%d, incoming length %d, outgoing length %d\n",
			  type, homa_symbol_for_state(rpc), rpc->id, peer,
			  rpc->dport, rpc->msgin.length, rpc->msgout.length);
	}
}

/**
 * homa_rpc_log_active() - Print information to the system log about all
 * active RPCs. Intended primarily for debugging.
 * @homa:    Overall data about the Homa protocol implementation.
 * @id:      An RPC id: if nonzero, then only RPCs with this id will be
 *           logged.
 */
void homa_rpc_log_active(struct homa *homa, uint64_t id)
{
	struct homa_socktab_scan scan;
	struct homa_sock *hsk;
	struct homa_rpc *rpc;
	int count = 0;

	pr_notice("Logging active Homa RPCs:\n");
	rcu_read_lock();
	for (hsk = homa_socktab_start_scan(homa->socktab, &scan);
	     hsk; hsk = homa_socktab_next(&scan)) {
		if (list_empty(&hsk->active_rpcs) || hsk->shutdown)
			continue;

		if (!homa_protect_rpcs(hsk))
			continue;
		list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
			count++;
			if (id != 0 && id != rpc->id)
				continue;
			homa_rpc_log(rpc);
					}
		homa_unprotect_rpcs(hsk);
	}
	homa_socktab_end_scan(&scan);
	rcu_read_unlock();
	pr_notice("Finished logging active Homa RPCs: %d active RPCs\n", count);
}

/**
 * homa_rpc_log_tt() - Log info about a particular RPC using timetraces.
 * @rpc:  RPC for which key info should be written to the system log.
 */
void homa_rpc_log_tt(struct homa_rpc *rpc)
{
	if (rpc->state == RPC_INCOMING) {
		int received = rpc->msgin.length
				- rpc->msgin.bytes_remaining;
		int rank;

		tt_record4("Incoming RPC id %d, peer 0x%x, %d/%d bytes received",
			   rpc->id, tt_addr(rpc->peer->addr),
			   received, rpc->msgin.length);
#ifndef __STRIP__
		tt_record3("RPC id %d has incoming %d, granted %d", rpc->id,
			   rpc->msgin.granted - received, rpc->msgin.granted);
		rank = rpc->msgin.rank;
#else /* __STRIP__ */
		rank = -1;
#endif /* __STRIP__ */
		tt_record4("RPC id %d: length %d, remaining %d, rank %d",
			   rpc->id, rpc->msgin.length,
			   rpc->msgin.bytes_remaining, rank);
		if (rpc->msgin.num_bpages == 0) {
			tt_record1("RPC id %d is blocked waiting for buffers",
				   rpc->id);
		} else {
			struct sk_buff *skb = skb_peek(&rpc->msgin.packets);

			if (!skb) {
				tt_record2("RPC id %d has %d bpages allocated, no uncopied bytes",
					rpc->id, rpc->msgin.num_bpages);
			} else {
				struct homa_data_hdr *h;

				h = (struct homa_data_hdr *) skb->data;
				tt_record3("RPC id %d has %d bpages allocated, first uncopied offset %d",
					rpc->id, rpc->msgin.num_bpages,
					ntohl(h->seg.offset));
			}
		}
	} else if (rpc->state == RPC_OUTGOING) {
		tt_record4("Outgoing RPC id %d, peer 0x%x, %d/%d bytes sent",
			   rpc->id, tt_addr(rpc->peer->addr),
			   rpc->msgout.next_xmit_offset,
			   rpc->msgout.length);
#ifndef __STRIP__
		if (rpc->msgout.granted > rpc->msgout.next_xmit_offset)
			tt_record3("RPC id %d has %d unsent grants (granted %d)",
				   rpc->id, rpc->msgout.granted -
				   rpc->msgout.next_xmit_offset,
				   rpc->msgout.granted);
#endif /* __STRIP__ */
	} else {
		tt_record2("RPC id %d is in state %d", rpc->id, rpc->state);
	}
}

/**
 * homa_rpc_log_active_tt() - Log information about all active RPCs using
 * timetraces.
 * @homa:    Overall data about the Homa protocol implementation.
 * @freeze_count:  If nonzero, FREEZE requests will be sent for this many
 *                 incoming RPCs with outstanding grants
 */
void homa_rpc_log_active_tt(struct homa *homa, int freeze_count)
{
	struct homa_socktab_scan scan;
	struct homa_sock *hsk;
	struct homa_rpc *rpc;
	int count = 0;

	tt_record("Logging Homa RPCs:");
	rcu_read_lock();
	for (hsk = homa_socktab_start_scan(homa->socktab, &scan);
			hsk; hsk = homa_socktab_next(&scan)) {
		if (list_empty(&hsk->active_rpcs) || hsk->shutdown)
			continue;

		if (!homa_protect_rpcs(hsk))
			continue;
		list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
			struct homa_freeze_hdr freeze;

			count++;
			homa_rpc_log_tt(rpc);
			if (freeze_count == 0)
				continue;
			if (rpc->state != RPC_INCOMING)
				continue;
#ifndef __STRIP__
			if (rpc->msgin.granted <= (rpc->msgin.length
					- rpc->msgin.bytes_remaining))
				continue;
#endif /* __STRIP__ */
			freeze_count--;
			pr_notice("Emitting FREEZE in %s\n", __func__);
			homa_xmit_control(FREEZE, &freeze, sizeof(freeze), rpc);
		}
		homa_unprotect_rpcs(hsk);
	}
	homa_socktab_end_scan(&scan);
	rcu_read_unlock();
	tt_record1("Finished logging (%d active Homa RPCs)", count);
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_validate_incoming() - Scan all of the active RPCs to compute what
 * homa_total_incoming should be, and see if it actually matches.
 * @homa:         Overall data about the Homa protocol implementation.
 * @verbose:      Print incoming info for each individual RPC.
 * @link_errors:  Set to 1 if one or more grantable RPCs don't seem to
 *                be linked into the grantable lists.
 * Return:   The difference between the actual value of homa->total_incoming
 *           and the expected value computed from the individual RPCs (positive
 *           means homa->total_incoming is higher than expected).
 */
int homa_validate_incoming(struct homa *homa, int verbose, int *link_errors)
{
	struct homa_socktab_scan scan;
	int total_incoming = 0;
	struct homa_sock *hsk;
	struct homa_rpc *rpc;
	int actual;

	tt_record1("homa_validate_incoming starting, total_incoming %d",
		   atomic_read(&homa->grant->total_incoming));
	*link_errors = 0;
	rcu_read_lock();
	for (hsk = homa_socktab_start_scan(homa->socktab, &scan);
			hsk; hsk = homa_socktab_next(&scan)) {
		if (list_empty(&hsk->active_rpcs) || hsk->shutdown)
			continue;

		if (!homa_protect_rpcs(hsk))
			continue;
		list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
			int incoming;

			if (rpc->state != RPC_INCOMING)
				continue;
			incoming = rpc->msgin.granted -
					(rpc->msgin.length
					- rpc->msgin.bytes_remaining);
			if (incoming < 0)
				incoming = 0;
			if (rpc->msgin.rec_incoming == 0)
				continue;
			total_incoming += rpc->msgin.rec_incoming;
			if (verbose)
				tt_record3("homa_validate_incoming: RPC id %d, incoming %d, rec_incoming %d",
					   rpc->id, incoming,
					   rpc->msgin.rec_incoming);
			if (rpc->msgin.granted >= rpc->msgin.length)
				continue;
			if (list_empty(&rpc->grantable_links)) {
				tt_record1("homa_validate_incoming: RPC id %d not linked in grantable list",
					   rpc->id);
				*link_errors = 1;
			}
			if (list_empty(&rpc->grantable_links)) {
				tt_record1("homa_validate_incoming: RPC id %d peer not linked in grantable list",
					   rpc->id);
				*link_errors = 1;
			}
		}
		homa_unprotect_rpcs(hsk);
	}
	homa_socktab_end_scan(&scan);
	rcu_read_unlock();
	actual = atomic_read(&homa->grant->total_incoming);
	tt_record3("homa_validate_incoming diff %d (expected %d, got %d)",
		   actual - total_incoming, total_incoming, actual);
	return actual - total_incoming;
}

/**
 * homa_drop_packet() - Invoked for each incoming packet to determine
 * (stochastically) whether that packet should be dropped. Used during
 * development to exercise retry code.
 * to
 * @homa:     Overall information about the Homa transport
 * Return:    Nonzero means drop the packet, zero means process normally.
 */
int homa_drop_packet(struct homa *homa)
{
	/* This code is full of races, but they don't matter (better fast
	 * than precise).
	 */
	if (homa->accept_bits == 0)
		return 0;
	while (1) {
		if (accept_count > 0) {
			accept_count--;
			return 0;
		}
		if (drop_count > 0) {
			drop_count--;
			return 1;
		}
		if (seed == 0)
			seed = homa_clock();
		seed = seed * 1664525 + 1013904223;
		accept_count = (seed >> 4) & ((1 << homa->accept_bits) - 1);
		seed = seed * 1664525 + 1013904223;
		drop_count = 1 + ((seed >> 4) & ((1 << homa->drop_bits) - 1));
		tt_record2("homa_drop_packet set accept_count %d, drop_count 0x%x",
			   accept_count, drop_count);
	}
}
#endif /* See strip.py */

/**
 * homa_snapshot_get_stats() - Fill in a homa_rpc_snapshot with the latest
 * statistics.
 * @snap:    Structure to fill in.
 */
void homa_snapshot_get_stats(struct homa_rpc_snapshot *snap)
{
	IF_NO_STRIP(int core);

	memset(snap, 0, sizeof(*snap));
	snap->clock = homa_clock();
#ifndef __STRIP__ /* See strip.py */
	for (core = 0; core < nr_cpu_ids; core++) {
		struct homa_metrics *m = &per_cpu(homa_metrics, core);

		snap->client_requests_started += m->client_requests_started;
		snap->client_request_bytes_started +=
				m->client_request_bytes_started;
		snap->client_request_bytes_done += m->client_request_bytes_done;
		snap->client_requests_done += m->client_requests_done;

		snap->client_responses_started += m->client_responses_started;
		snap->client_response_bytes_started +=
				m->client_response_bytes_started;
		snap->client_response_bytes_done +=
				m->client_response_bytes_done;
		snap->client_responses_done += m->client_responses_done;

		snap->server_requests_started += m->server_requests_started;
		snap->server_request_bytes_started +=
				m->server_request_bytes_started;
		snap->server_request_bytes_done += m->server_request_bytes_done;
		snap->server_requests_done += m->server_requests_done;

		snap->server_responses_started += m->server_responses_started;
		snap->server_response_bytes_started +=
				m->server_response_bytes_started;
		snap->server_response_bytes_done +=
				m->server_response_bytes_done;
		snap->server_responses_done += m->server_responses_done;
	}
#endif /* See strip.py */
}

/**
 * homa_snapshot_rpcs() - This function is called by homa_timer; it collects
 * data about overall progress of client and server RPCs.
 */
void homa_snapshot_rpcs(void)
{
	struct homa_rpc_snapshot *snap;
	u64 now = homa_clock();

	if (snapshot_interval == 0)
		snapshot_interval = homa_clock_khz() * RX_SNAPSHOT_INTERVAL;

	if (now < snapshot_time + snapshot_interval)
		return;
	snapshot_time = now;
	snap = &rpc_snapshots[next_snapshot];
	homa_snapshot_get_stats(snap);
	next_snapshot++;
	if (next_snapshot >= MAX_RX_SNAPSHOTS)
		next_snapshot = 0;
}

/**
 * homa_rpc_snapshot_log_tt() - Dump all of the RPC snapshot data to the
 * timetrace.
 */
void homa_rpc_snapshot_log_tt(void)
{
	u64 creq_base, creq_bbase, cresp_base, cresp_bbase;
	u64 sreq_base, sreq_bbase, sresp_base, sresp_bbase;
	struct homa_rpc_snapshot *snap;
	u64 now = homa_clock();
	u64 usecs;
	int i;

	i = next_snapshot;

	/* Offset all the output values to start at 0, in order to avoid
	 * wraparound in 32-bit timetrace values.
	 */
	creq_base = rpc_snapshots[i].client_requests_done;
	creq_bbase = rpc_snapshots[i].client_request_bytes_done;
	cresp_base = rpc_snapshots[i].client_responses_done;
	cresp_bbase = rpc_snapshots[i].client_response_bytes_done;
	sreq_base = rpc_snapshots[i].server_requests_done;
	sreq_bbase = rpc_snapshots[i].server_request_bytes_done;
	sresp_base = rpc_snapshots[i].server_responses_done;
	sresp_bbase = rpc_snapshots[i].server_response_bytes_done;
	do {
		snap = &rpc_snapshots[i];

		/* Compute how many microseconds before now this snapshot
		 * was taken.
		 */
		usecs = 1000*(now - snap->clock);
		do_div(usecs, homa_clock_khz());

		tt_record1("rpc snapshot usecs %d", -usecs);
		tt_record4("rpc snapshot client requests started %d, kbytes_started %d, kbytes_done %d, done %d",
			   snap->client_requests_started - creq_base,
			   (snap->client_request_bytes_started -
			    creq_bbase) >> 10,
			   (snap->client_request_bytes_done -
			    creq_bbase) >> 10,
			   snap->client_requests_done - creq_base);
		tt_record4("rpc snapshot client responses started %d, kbytes_started %d, kbytes_done %d, done %d",
			   snap->client_responses_started - cresp_base,
			   (snap->client_response_bytes_started -
			    cresp_bbase) >> 10,
			   (snap->client_response_bytes_done -
			    cresp_bbase) >> 10,
			   snap->client_responses_done - cresp_base);
		tt_record4("rpc snapshot server requests started %d, kbytes_started %d, kbytes_done %d, done %d",
			   snap->server_requests_started - sreq_base,
			   (snap->server_request_bytes_started -
			    sreq_bbase) >> 10,
			   (snap->server_request_bytes_done -
			    sreq_bbase) >> 10,
			   snap->server_requests_done - sreq_base);
		tt_record4("rpc snapshot server responses started %d, kbytes_started %d, kbytes_done %d, done %d",
			   snap->server_responses_started - sresp_base,
			   (snap->server_response_bytes_started -
			    sresp_bbase) >> 10,
			   (snap->server_response_bytes_done -
			    sresp_bbase) >> 10,
			   snap->server_responses_done - sresp_base);

		i++;
		if (i >= MAX_RX_SNAPSHOTS)
			i = 0;
	} while (i != next_snapshot);
}
/**
 * homa_rpc_stats_log() - Print statistics on RPC progress to the system log.
 */
void homa_rpc_stats_log(void)
{
	struct homa_rpc_snapshot snap;

	homa_snapshot_get_stats(&snap);
	pr_notice("Client requests: started %llu, done %llu, delta %llu\n",
		  snap.client_requests_started, snap.client_requests_done,
		  snap.client_requests_started - snap.client_requests_done);
	pr_notice("Client request bytes: started %llu, bytes_done %llu, delta %llu\n",
		  snap.client_request_bytes_started,
		  snap.client_request_bytes_done,
		  snap.client_request_bytes_started -
		  snap.client_request_bytes_done);
	pr_notice("Client responses: started %llu, done %llu, delta %llu\n",
		  snap.client_responses_started, snap.client_responses_done,
		  snap.client_responses_started - snap.client_responses_done);
	pr_notice("Client response bytes: started %llu, bytes_done %llu, delta %llu\n",
		  snap.client_response_bytes_started,
		  snap.client_response_bytes_done,
		  snap.client_response_bytes_started -
		  snap.client_response_bytes_done);
	pr_notice("Server requests: started %llu, done %llu, delta %llu\n",
		  snap.server_requests_started, snap.server_requests_done,
		  snap.server_requests_started - snap.server_requests_done);
	pr_notice("Server request bytes: started %llu, bytes_done %llu, delta %llu\n",
		  snap.server_request_bytes_started,
		  snap.server_request_bytes_done,
		  snap.server_request_bytes_started -
		  snap.server_request_bytes_done);
	pr_notice("Server responses: started %llu, done %llu, delta %llu\n",
		  snap.server_responses_started, snap.server_responses_done,
		  snap.server_responses_started - snap.server_responses_done);
	pr_notice("Server response bytes: started %llu, bytes_done %llu, delta %llu\n",
		  snap.server_response_bytes_started,
		  snap.server_response_bytes_done,
		  snap.server_response_bytes_started -
		  snap.server_response_bytes_done);
}
