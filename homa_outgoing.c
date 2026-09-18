// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

/* This file contains functions related to the sender side of message
 * transmission. It also contains utility functions for sending packets.
 */

#include "homa_impl.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#include "homa_tx_pool.h"
#include "homa_wire.h"

#ifndef __STRIP__ /* See strip.py */
#include "homa_hijack.h"
#include "homa_qdisc.h"
#endif /* See strip.py */

/**
 * homa_message_out_init() - Initialize rpc->msgout. This function doesn't
 * read data from user space or create sk_buffs, but it sets up information
 * such as the message geometry.
 * @rpc:       RPC whose output message should be initialized. Must be
 *             locked by caller. Fields in rpc->msgout should have been
 *             zeroed by the caller.
 * @length:    Number of bytes that will eventually be in rpc->msgout.
 */
void homa_message_out_init(struct homa_rpc *rpc, int length)
	__must_hold(rpc->bucket->lock)
{
	struct dst_entry *dst;
	u64 max_segs;
	int mtu;

	memset(&rpc->msgout, 0, sizeof(rpc->msgout));
	rpc->msgout.length = length;
#ifndef __STRIP__ /* See strip.py */
	rpc->msgout.unscheduled = rpc->hsk->homa->unsched_bytes;
	if (rpc->msgout.unscheduled > length)
		rpc->msgout.unscheduled = length;
	rpc->msgout.granted = rpc->msgout.unscheduled;
#endif /* See strip.py */
	rpc->msgout.init_time = homa_clock();

	/* Compute the geometry of packets. */
	dst = homa_get_dst(rpc->peer, rpc->hsk);
	mtu = dst_mtu(dst);
	rpc->msgout.max_seg_data = mtu - rpc->hsk->ip_header_length -
				   sizeof(struct homa_data_hdr);
	max_segs = min_t(u32, rpc->hsk->homa->max_gso_size,
			 dst->dev->gso_max_size) -
		   (sizeof(struct homa_data_hdr) + HOMA_SKB_EXTRA);
	do_div(max_segs, rpc->msgout.max_seg_data +
			 sizeof(struct homa_seg_hdr));
	if (max_segs > dst->dev->gso_max_segs)
		max_segs = dst->dev->gso_max_segs;
	if (max_segs < 1)
		max_segs = 1;
	rpc->msgout.max_gso_segs = max_segs;
	rpc->msgout.max_gso_data = max_segs * rpc->msgout.max_seg_data;
	dst_release(dst);
}

/**
 * homa_tx_copy_from_user() - Copy outbound message data for an RPC from
 * user space into kernel memory and (possibly) start transmitting packets.
 * @rpc:      RPC whose tx message is to be copied.
 * @iter:     Describes the location in user space of the message
 *            data.
 * @xmit:     True means this function should also start transmitting packets.
 *            False means only copy data; don't transmit packets.
 * Return:    Zero for success, otherwise a negative errno.
 */
int homa_tx_copy_from_user(struct homa_rpc *rpc, struct iov_iter *iter,
			   bool xmit)
	__must_hold(rpc->bucket->lock)
{
	struct homa_frag_filler filler;
	int err, hdr_space;
	u64 num_segs;
	int offset;

	homa_message_out_init(rpc, iter->count);

	/* Allocate kernel memory to hold the message data (note that we
	 * need to allocate extra space for homa_seg_hdrs).
	 */
	num_segs = rpc->msgout.length + rpc->msgout.max_seg_data - 1;
	do_div(num_segs, rpc->msgout.max_seg_data);
	hdr_space = num_segs * sizeof(struct homa_seg_hdr);
	rpc->msgout.frags = &rpc->msgout.frag;
	rpc->msgout.num_frags = 1;
	err = homa_tx_pool_alloc(rpc->hsk->homa, rpc->msgout.length + hdr_space,
				 &rpc->msgout.num_frags, &rpc->msgout.frags);
	if (err != 0)
		return err;
	rpc->msgout.frag_bytes = rpc->msgout.length + hdr_space;
	refcount_add(rpc->msgout.frag_bytes, &rpc->hsk->sock.sk_wmem_alloc);

	/* Copy the data in from user space, preceding each segment of data
	 * with its homa_seg_hdr.
	 */
	homa_rpc_unlock(rpc);
#ifndef __STRIP__ /* See strip.py */
	tt_record3("starting copy from user space for id %d, length %d, unscheduled %d",
		   rpc->id, rpc->msgout.length, rpc->msgout.unscheduled);
#else /* See strip.py */
	tt_record2("starting copy from user space for id %d, length %d",
		   rpc->id, rpc->msgout.length);
#endif /* See strip.py */
	homa_frag_filler_init(&filler, rpc->msgout.num_frags,
			      rpc->msgout.frags);
	offset = 0;
	while (offset < rpc->msgout.length) {
		int seg_size = min(rpc->msgout.length - offset,
				   rpc->msgout.max_seg_data);
		struct homa_seg_hdr seg_hdr;

		seg_hdr.offset = htonl(offset);
		err = homa_copy_to_frags(&filler, &seg_hdr, sizeof(seg_hdr));
		if (unlikely(err != 0))
			goto done;
		err = homa_copy_iter_to_frags(&filler, iter, seg_size);
		if (unlikely(err != 0))
			goto done;
		offset += seg_size;
		smp_store_release(&rpc->msgout.copied_from_user, offset);

#ifndef __STRIP__ /* See strip.py */
		/* Transmit unscheduled data if requested. We only transmit
		 * unscheduled data now, under the assumption that a
		 * SoftIRQ thread will transmit the remaining data as grants
		 * come in. That way we get parallelism between 2 threads:
		 * this thread copies and the SoftIRQ thread transmits.
		 * Parallelism is important on networks of 100 Gbps and more
		 * because copying data is the bottleneck; we don't want to
		 * use cycles in this thread sending packets. It is important
		 * to send all the unscheduled data here in order to keep the
		 * network busy until the first grant arrives.
		 */
		if (xmit && rpc->msgout.next_xmit_offset <
			    rpc->msgout.unscheduled &&
		    offset >= rpc->msgout.next_xmit_offset +
		              rpc->msgout.max_gso_data) {
			homa_rpc_lock(rpc);
			homa_xmit_data(rpc);
			homa_rpc_unlock(rpc);
		}
#endif /* See strip.py */
	}
	tt_record2("finished copy from user space for id %d, length %d",
		   rpc->id, rpc->msgout.length);
	INC_METRIC(sent_msg_bytes, rpc->msgout.length);

done:
	UNIT_LOG("; ", "homa_tx_copy_to_user done");
	homa_rpc_lock(rpc);
#ifndef __STRIP__ /* See strip.py */
	/* Must make one more attempt to transmit data (e.g. the message is
	 * entirely unscheduled, so no other thread helped out as described
	 * above).
	 */
#endif /* See strip.py */
	if (xmit && err == 0)
		homa_xmit_data(rpc);
	return err;
}

/**
 * __homa_skb_alloc() - Allocate a new (empty) sk_buff for use in transmitting
 * data or control info.
 * @length:       Number of bytes of data that the caller would like to
 *                have available in the linear part of the sk_buff for
 *                the Homa header and additional data beyond that. This
 *                function will allocate additional space for IP and
 *                Ethernet headers, as well as for the homa_skb_info.
 * Return:        New sk_buff, or NULL if there was insufficient memory.
 *                The sk_buff will be configured so that the next
 *                skb_put will be for the transport (Homa) header. The
 *                homa_skb_info is not initialized.
 */
struct sk_buff *__homa_skb_alloc(int length)
{
	struct sk_buff *skb;

	IF_NO_STRIP(u64 start = homa_clock());

	skb = alloc_skb(HOMA_SKB_EXTRA + sizeof(struct homa_skb_info) + length,
			GFP_ATOMIC);
	if (likely(skb)) {
		skb_reserve(skb, HOMA_SKB_EXTRA);
		skb_reset_transport_header(skb);
	}
	INC_METRIC(skb_allocs, 1);
	INC_METRIC(skb_alloc_cycles, homa_clock() - start);
	return skb;
}

/**
 * homa_tx_skb_alloc() - Create an outgoing data packet for a Homa message.
 * @rpc:      RPC for the message. Its @msgout must have been initialized
 *            (e.g. the packet geometry will be determined by information
 *            in @rpc->msgout).
 * @offset:   Offset within the message of the first byte of data for
 *            this packet.
 * @end:      Offset within the message of the byte just after the last
 *            one to include in this packet. The skb may actually end either
 *            before or after this offset; this value is modified to hold
 *            the actual end.
 * Return:    A pointer to the sk_buff, or a negative errno for error.
 */
struct sk_buff *homa_tx_skb_alloc(struct homa_rpc *rpc, u32 offset, u32 *end)
	__must_hold(rpc->bucket->lock)
{
	int msg_frags_left, bytes_left, bytes_to_skip, rem;
	struct homa_sock *hsk = rpc->hsk;
	struct homa_skb_info *homa_info;
	skb_frag_t *msg_frag, *skb_frag;
	struct skb_shared_info *shinfo;
	u64 seg_index, num_segs;
	struct homa_data_hdr *h;
	struct sk_buff *skb;
	int err;

	if (offset >= rpc->msgout.length)
		return ERR_PTR(-EINVAL);
	if (*end > rpc->msgout.length)
		*end = rpc->msgout.length;

	/* Find the location within rpc->msgin.frags of the data for the
	 * first segment to output (skipping its homa_seg_hdr, since that
	 * will be in the linear part of the skb). Also, round offset down
	 * to the start of its segment.
	 */
	seg_index = offset;
	rem = do_div(seg_index, rpc->msgout.max_seg_data);
	offset -= rem;
	bytes_to_skip = seg_index * (rpc->msgout.max_seg_data +
				     sizeof(struct homa_seg_hdr)) +
			sizeof(struct homa_seg_hdr);
	for (msg_frags_left = rpc->msgout.num_frags,
	     msg_frag = rpc->msgout.frags; ; msg_frags_left--, msg_frag++) {
		if (bytes_to_skip < skb_frag_size(msg_frag))
			break;
		bytes_to_skip -= skb_frag_size(msg_frag);
	}

	/* Compute how much data from rpc->msgout.frags to include in the
	 * packet.
	 */
	num_segs = *end - offset + rpc->msgout.max_seg_data - 1;
	do_div(num_segs, rpc->msgout.max_seg_data);
	if (num_segs > rpc->msgout.max_gso_segs)
		num_segs = rpc->msgout.max_gso_segs;
	bytes_left = num_segs * (rpc->msgout.max_seg_data +
				 sizeof(struct homa_seg_hdr)) -
		     sizeof(struct homa_seg_hdr);

	skb = __homa_skb_alloc(sizeof(struct homa_data_hdr));
	if (unlikely(!skb))
		return ERR_PTR(-ENOMEM);
	skb_dst_set(skb, homa_get_dst(rpc->peer, hsk));
	skb->ooo_okay = 1;
	shinfo = skb_shinfo(skb);

	/* Fill in the Homa header (which will be replicated in every
	 * segment by GSO). The header in the linear portion contains the
	 * homa_seg_hdr for the first fragment.
	 */
	h = (struct homa_data_hdr *)skb_put(skb, sizeof(struct homa_data_hdr));
	memset(h, 0, sizeof(*h));
	h->common.sport = htons(hsk->port);
	h->common.dport = htons(rpc->dport);
	h->common.type = DATA;
	homa_set_doff(skb, sizeof(struct homa_data_hdr) -
			   sizeof(struct homa_seg_hdr));
	h->common.sender_id = cpu_to_be64(rpc->id);
	h->message_length = htonl(rpc->msgout.length);
	IF_NO_STRIP(h->incoming = htonl(rpc->msgout.unscheduled));
	homa_peer_get_acks(rpc->peer, 1, &h->ack);
	IF_NO_STRIP(h->cutoff_version = rpc->peer->cutoff_version);
	if (offset < rpc->msgout.next_xmit_offset)
		h->retransmit = 1;
	h->seg.offset = ntohl(offset);

	/* Virtually copy data from rpc->msgout.frags to the skb; each
	 * iteration of the following loop copies one frag.
	 */
	while (bytes_left > 0 && shinfo->nr_frags < MAX_SKB_FRAGS &&
	       msg_frags_left > 0) {
		skb_frag_t *skb_frag = &shinfo->frags[shinfo->nr_frags];
		struct page *page;
		int frag_avail, frag_bytes;

		/* skb_frag_size() is unsigned; keep the min() operands signed
		 * (matching bytes_left and frag_bytes) so a mixed-sign compare
		 * can't turn an underflow into a huge positive length.
		 */
		frag_avail = (int)skb_frag_size(msg_frag) - bytes_to_skip;
		frag_bytes = min(frag_avail, bytes_left);
		page = skb_frag_page(msg_frag);
		get_page(page);
		skb_frag->netmem = page_to_netmem(page);
		skb_frag->offset = msg_frag->offset + bytes_to_skip;
		skb_frag_size_set(skb_frag, frag_bytes);
		skb_len_add(skb, frag_bytes);

		bytes_left -= frag_bytes;
		bytes_to_skip = 0;
		msg_frag++;
		msg_frags_left--;
		shinfo->nr_frags++;
	}

	if (bytes_left > 0 && msg_frags_left > 0 &&
	    shinfo->nr_frags >= MAX_SKB_FRAGS) {
		/* There wasn't enough fragment space in skb to store all the
		 * desired segments. Round the skb back to the nearest segment
		 * boundary.
		 */
		while (bytes_left > 0) {
			bytes_left -= rpc->msgout.max_seg_data +
				      sizeof(struct homa_seg_hdr);
			num_segs--;
		}
		if (num_segs == 0) {
			err = -EINVAL;
			goto error;
		}
		while (bytes_left < 0) {
			skb_frag = &shinfo->frags[shinfo->nr_frags - 1];
			if (-bytes_left < skb_frag_size(skb_frag)) {
				skb_frag_size_sub(skb_frag, -bytes_left);
				skb_len_add(skb, bytes_left);
				break;
			}
			bytes_left += skb_frag_size(skb_frag);
			skb_len_add(skb, -skb_frag_size(skb_frag));
			put_page(skb_frag_page(skb_frag));
			shinfo->nr_frags--;
		}
	}
	*end = min_t(u32, offset + num_segs * rpc->msgout.max_seg_data,
		   rpc->msgout.length);

	/* Fill in fields in shinfo. */
	if (num_segs > 1) {
		shinfo->gso_segs = num_segs;
		shinfo->gso_size = rpc->msgout.max_seg_data +
				   sizeof(struct homa_seg_hdr);
		shinfo->gso_type = (hsk->inet.sk.sk_family ==
				    AF_INET6) ? SKB_GSO_TCPV6 :
				    SKB_GSO_TCPV4;
	}

	/* Initialize homa_skb_info for the packet. */
	homa_info = homa_get_skb_info(skb);
	memset(homa_info, 0, sizeof(*homa_info));
	homa_info->data_bytes = *end - offset;
	homa_info->dont_defer = false;
	return skb;

error:
	kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
	return ERR_PTR(err);
}

/**
 * homa_tx_skb_send() - Create and send one (GSO) data packet for an RPC. The
 * dimensions of the packet transmitted may change from those specified
 * in the argument depending on factors such as availability of GSO,
 * MTU, etc.
 * @rpc:         RPC for which to send the packet. This function releases
 *               and then re-requires rpc's lock, so the RPC could be
 *               dead when this function returns.
 * @offset:      The packet must contain this offset.
 * @end:         Offset of the message byte just after the last one
 *               the caller would like included in the packet. Modified
 *               to hold the offset just after the last byte actually
 *               included in the packet.
 * Return:       0 for success, otherwise a negative errno.
 */
int homa_tx_skb_send(struct homa_rpc *rpc, u32 offset, u32 *end)
	__must_hold(rpc->bucket->lock)
{
	struct sk_buff *skb;

	IF_NO_STRIP(int err);
	IF_NO_STRIP(int priority, skb_offset, data_bytes, queue);
	IF_NO_STRIP(struct homa_data_hdr *h);

	skb = homa_tx_skb_alloc(rpc, offset, end);
	if (IS_ERR(skb))
		return PTR_ERR(skb);

#ifndef __STRIP__ /* See strip.py */
	if (offset < rpc->msgout.next_xmit_offset) {
		tt_record3("retransmitting offset %d, length %d, id %d",
			   offset, *end - offset, rpc->id);
		priority = rpc->msgout.retrans_priority;
	} else if (offset < rpc->msgout.unscheduled)
		priority = homa_unsched_priority(rpc->hsk->homa, rpc->peer,
						 rpc->msgout.length);
	else
		priority = rpc->msgout.sched_priority;
	priority = rpc->hsk->homa->priority_map[priority];
	h = (struct homa_data_hdr *)skb_transport_header(skb);
	skb_offset = ntohl(h->seg.offset);
	data_bytes = homa_get_skb_info(skb)->data_bytes;
	queue = skb->queue_mapping;
#endif /* See strip.py */

	/* Note: must update next_xmit_offset here, before releasing the
	 * RPC lock below; otherwise some other thread might decide to
	 * transmit the same bytes.
	 */
	if (*end > rpc->msgout.next_xmit_offset)
		rpc->msgout.next_xmit_offset = *end;

	INC_METRIC(packets_sent[0], 1);
	INC_METRIC(priority_bytes[priority], skb->len);
	INC_METRIC(priority_packets[priority], 1);
	if (ipv6_addr_v4mapped(&rpc->peer->addr)) {
		tt_record4("calling ip_queue_xmit: peer 0x%x, id %d, offset %d, length %d",
			   tt_addr(rpc->peer->addr), rpc->id, skb_offset,
			   data_bytes);

#ifndef __STRIP__ /* See strip.py */
		homa_hijack_set_hdr(skb, rpc->peer, false);
		rpc->hsk->inet.tos = priority << 5;
		homa_rpc_unlock(rpc);
		err = ip_queue_xmit(&rpc->hsk->inet.sk, skb, &rpc->peer->flow);
#else /* See strip.py */
		homa_rpc_unlock(rpc);
		ip_queue_xmit(&rpc->hsk->inet.sk, skb, &rpc->peer->flow);
#endif /* See strip.py */
	} else {
		tt_record4("calling ip6_xmit: peer 0x%x, id %d, offset %d, length %d",
			   tt_addr(rpc->peer->addr), rpc->id, skb_offset,
			   data_bytes);
#ifndef __STRIP__ /* See strip.py */
		homa_hijack_set_hdr(skb, rpc->peer, true);
		homa_rpc_unlock(rpc);
		err = ip6_xmit(&rpc->hsk->inet.sk, skb, &rpc->peer->flow.u.ip6,
			       0, NULL, priority << 5, 0);
#else /* See strip.py */
		homa_rpc_unlock(rpc);
		ip6_xmit(&rpc->hsk->inet.sk, skb, &rpc->peer->flow.u.ip6,
			 0, NULL, 0, 0);
#endif /* See strip.py */
	}
	homa_rpc_lock(rpc);
#ifndef __STRIP__ /* See strip.py */
	tt_record4("Finished queueing packet: rpc id %llu, offset %d, len %d, qid %d",
		   rpc->id, skb_offset, data_bytes, queue);
	if (err)
		INC_METRIC(data_xmit_errors, 1);
	return err;
#else /* See strip.py */
	return 0;
#endif /* See strip.py */
}

/**
 * homa_xmit_control() - Send a control packet to the other end of an RPC.
 * @type:      Packet type, such as DATA.
 * @contents:  Address of buffer containing the contents of the packet.
 *             Only information after the common header must be valid;
 *             the common header will be filled in by this function.
 * @length:    Length of @contents (including the common header).
 * @rpc:       The packet will go to the socket that handles the other end
 *             of this RPC. Addressing info for the packet, including all of
 *             the fields of homa_common_hdr except type, will be set from this.
 *             Caller must not hold any locks (see "Homa Locking Strategy"
 *             in homa_impl.h).
 *
 * Return:     Either zero (for success), or a negative errno value if there
 *             was a problem.
 */
int homa_xmit_control(enum homa_packet_type type, void *contents,
		      size_t length, struct homa_rpc *rpc)
{
	struct homa_common_hdr *h = contents;

	memset(h, 0, sizeof(*h));
	h->type = type;
	h->sport = htons(rpc->hsk->port);
	h->dport = htons(rpc->dport);
	h->sender_id = cpu_to_be64(rpc->id);
	return __homa_xmit_control(contents, length, rpc->peer, rpc->hsk);
}

/**
 * __homa_xmit_control() - Lower-level version of homa_xmit_control: sends
 * a control packet.
 * @contents:  Address of buffer containing the contents of the packet.
 *             The caller must have filled in all of the information,
 *             including the common header.
 * @length:    Length of @contents.
 * @peer:      Destination to which the packet will be sent.
 * @hsk:       Socket via which the packet will be sent.
 *
 * Return:     Either zero (for success), or a negative errno value if there
 *             was a problem.
 */
int __homa_xmit_control(void *contents, size_t length, struct homa_peer *peer,
			struct homa_sock *hsk)
{
	struct homa_common_hdr *h;
	struct sk_buff *skb;
	int extra_bytes;
	int result;

	IF_NO_STRIP(int priority);

	skb = __homa_skb_alloc(HOMA_MAX_HEADER);
	if (unlikely(!skb))
		return -ENOBUFS;
	skb_dst_set(skb, homa_get_dst(peer, hsk));

	h = skb_put(skb, length);
	memcpy(h, contents, length);
	extra_bytes = HOMA_MIN_PKT_LENGTH - length;
	if (extra_bytes > 0) {
		memset(skb_put(skb, extra_bytes), 0, extra_bytes);
		UNIT_LOG(",", "padded control packet with %d bytes",
			 extra_bytes);
	}
#ifndef __STRIP__ /* See strip.py */
	priority = hsk->homa->num_priorities - 1;
#endif /* See strip.py */
	skb->ooo_okay = 1;
	homa_set_doff(skb, 20);
	INC_METRIC(packets_sent[h->type - DATA], 1);
	INC_METRIC(priority_bytes[priority], skb->len);
	INC_METRIC(priority_packets[priority], 1);
#ifndef __STRIP__ /* See strip.py */
	if (ipv6_addr_v4mapped(&peer->addr)) {
		homa_hijack_set_hdr(skb, peer, false);

		/* This will find its way to the DSCP field in the IPv4 hdr. */
		hsk->inet.tos = hsk->homa->priority_map[priority] << 5;
		result = ip_queue_xmit(&hsk->inet.sk, skb, &peer->flow);
	} else {
		homa_hijack_set_hdr(skb, peer, true);
		result = ip6_xmit(&hsk->inet.sk, skb, &peer->flow.u.ip6, 0,
				  NULL, hsk->homa->priority_map[priority] << 5,
				  0);
	}
	if (unlikely(result != 0))
		INC_METRIC(control_xmit_errors, 1);
#else /* See strip.py */
	if (hsk->inet.sk.sk_family == AF_INET6)
		result = ip6_xmit(&hsk->inet.sk, skb, &peer->flow.u.ip6, 0,
				  NULL, 0, 0);
	else
		result = ip_queue_xmit(&hsk->inet.sk, skb, &peer->flow);
#endif /* See strip.py */
	return result;
}

/**
 * homa_xmit_unknown() - Send an RPC_UNKNOWN packet to a peer.
 * @skb:         Buffer containing an incoming packet; identifies the peer to
 *               which the RPC_UNKNOWN packet should be sent.
 * @hsk:         Socket that should be used to send the RPC_UNKNOWN packet.
 */
void homa_xmit_unknown(struct sk_buff *skb, struct homa_sock *hsk)
{
	struct homa_common_hdr *h = (struct homa_common_hdr *)skb->data;
	struct in6_addr saddr = skb_canonical_ipv6_saddr(skb);
	struct homa_rpc_unknown_hdr unknown;
	struct homa_peer *peer;

#ifndef __STRIP__ /* See strip.py */
	if (hsk->homa->verbose)
		pr_notice("sending RPC_UNKNOWN to peer %s:%d for id %llu",
			  homa_print_ipv6_addr(&saddr),
			  ntohs(h->sport), homa_local_id(h->sender_id));
#endif /* See strip.py */
	tt_record3("sending unknown to 0x%x:%d for id %llu",
		   tt_addr(saddr), ntohs(h->sport),
		   homa_local_id(h->sender_id));
	memset(&unknown, 0, sizeof(unknown));
	unknown.common.sport = h->dport;
	unknown.common.dport = h->sport;
	unknown.common.type = RPC_UNKNOWN;
	unknown.common.sender_id = cpu_to_be64(homa_local_id(h->sender_id));
	peer = homa_peer_get(hsk, &saddr);
	if (!IS_ERR(peer)) {
		__homa_xmit_control(&unknown, sizeof(unknown), peer, hsk);
		homa_peer_release(peer);
	}
}

/**
 * homa_xmit_data() - If an RPC has outbound data packets that are permitted
 * to be transmitted according to the scheduling mechanism, arrange for
 * them to be sent.
 * @rpc:       RPC to check for transmittable packets. Must be locked by
 *             caller.
 */
void homa_xmit_data(struct homa_rpc *rpc)
	__must_hold(rpc->bucket->lock)
{
	u32 xmit_offset, end;

	while (rpc->state != RPC_DEAD) {
		xmit_offset = rpc->msgout.next_xmit_offset;
#ifndef __STRIP__ /* See strip.py */
		if (xmit_offset >= rpc->msgout.granted) {
			tt_record3("homa_xmit_data stopping at offset %d for id %u: granted is %d",
				   xmit_offset, rpc->id, rpc->msgout.granted);
			break;
		}
#endif /* See strip.py */

		/* Don't transmit unless enough data has been copied from user
		 * space for a maximum-size packet.
		 */
		if (xmit_offset + rpc->msgout.max_gso_data >
		    rpc->msgout.copied_from_user &&
		    rpc->msgout.copied_from_user < rpc->msgout.length)
			break;

#ifndef __STRIP__ /* See strip.py */
		if (xmit_offset < rpc->msgout.unscheduled)
			end = rpc->msgout.unscheduled;
		else
			end = rpc->msgout.length;
#else /* See strip.py */
		if (xmit_offset >= rpc->msgout.length)
			break;
		end = rpc->msgout.length;
#endif /* See strip.py */
		homa_tx_skb_send(rpc, xmit_offset, &end);
#ifndef __STRIP__ /* See strip.py */
		if (homa_is_client(rpc->id)) {
			INC_METRIC(client_request_bytes_done, end - xmit_offset);
			INC_METRIC(client_requests_done,
				   rpc->msgout.next_xmit_offset ==
				   rpc->msgout.length);
		} else {
			INC_METRIC(server_response_bytes_done,
				   end - xmit_offset);
			INC_METRIC(server_responses_done,
				   rpc->msgout.next_xmit_offset ==
				   rpc->msgout.length);
		}
#endif /* See strip.py */
	}
}

/**
 * homa_resend_data() - This function is invoked as part of handling RESEND
 * requests. It retransmits the packet(s) containing a given range of bytes
 * from a message.
 * @rpc:      RPC for which data should be resent. Must be locked by caller.
 * @start:    Offset within @rpc->msgout of the first byte to retransmit.
 * @end:      Offset within @rpc->msgout of the byte just after the last one
 *            to retransmit.
 * Return:    0 for success, otherwise a negative errno.
 */
int homa_resend_data(struct homa_rpc *rpc, int start, int end)
	__must_hold(rpc->bucket->lock)
{
	u32 offset, pkt_end;
	int err = 0;

	for (offset = start; offset < end; offset = pkt_end) {
		pkt_end = end;
		err = homa_tx_skb_send(rpc, offset, &pkt_end);
		if (err != 0)
			break;
		INC_METRIC(resent_packets, 1);
		if (rpc->state == RPC_DEAD)
			break;
	}
	return err;
}

/**
 * homa_rpc_tx_end() - Return the offset of the first byte in an
 * RPC's outgoing message that has not (with high probability) been
 * passed to the NIC (i.e. offsets beyond this point have not been
 * passed to ip*xmit or are deferred in homa_qdisc).
 * @rpc:    RPC to check
 * Return:  See above. If the message has been fully transmitted then
 *          rpc->msgout.length is returned.
 */
int homa_rpc_tx_end(struct homa_rpc *rpc)
{
#ifndef __STRIP__ /* See strip.py */
	int deferred;

	deferred = homa_qdisc_deferred_offset(rpc);
	if (deferred >= 0)
		return deferred;
#endif /* See strip.py */
	return rpc->msgout.next_xmit_offset;
}
