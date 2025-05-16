// SPDX-License-Identifier: BSD-2-Clause

/* This file contains functions that are useful to have in Homa during
 * development, but aren't needed in production versions.
 */

#include "homa_impl.h"
#include "homa_devel.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#ifndef __STRIP__ /* See strip.py */
#include "homa_skb.h"
#else /* See strip.py */
#include "homa_stub.h"
#endif /* See strip.py */
#include "homa_wire.h"

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
		char *resend = (h->resend_all) ? ", resend_all" : "";

		used = homa_snprintf(buffer, buf_len, used,
				     ", offset %d, grant_prio %u%s",
				     ntohl(h->offset), h->priority, resend);
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
		char *resend = h->resend_all ? " resend_all" : "";

		snprintf(buffer, buf_len, "GRANT %d@%d%s", ntohl(h->offset),
			 h->priority, resend);
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
void homa_freeze_peers()
{
	struct homa_socktab_scan scan;
	struct homa_freeze_hdr freeze;
	struct rhashtable_iter iter;
	struct homa_peer *peer;
	struct homa_sock *hsk;
	struct homa_net *hnet;
	int err;

	/* Find a socket to use (any socket for the namespace will do). */
	hnet = homa_net_from_net(&init_net);
	rcu_read_lock();
	hsk = homa_socktab_start_scan(hnet->homa->port_map, &scan);
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

	rhashtable_walk_enter(&hnet->homa->peers->ht, &iter);
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
