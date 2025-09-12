// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

/* This file contains functions related to the sender side of message
 * transmission. It also contains utility functions for sending packets.
 */

#include "homa_impl.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#include "homa_wire.h"

#ifndef __STRIP__ /* See strip.py */
#include "homa_pacer.h"
#include "homa_qdisc.h"
#include "homa_skb.h"
#else /* See strip.py */
#include "homa_stub.h"
#endif /* See strip.py */

/**
 * homa_message_out_init() - Initialize rpc->msgout.
 * @rpc:       RPC whose output message should be initialized. Must be
 *             locked by caller.
 * @length:    Number of bytes that will eventually be in rpc->msgout.
 */
void homa_message_out_init(struct homa_rpc *rpc, int length)
	__must_hold(rpc->bucket->lock)
{
	memset(&rpc->msgout, 0, sizeof(rpc->msgout));
	rpc->msgout.length = length;
	rpc->msgout.next_xmit = &rpc->msgout.packets;
#ifndef __STRIP__ /* See strip.py */
	rpc->msgout.unscheduled = rpc->hsk->homa->unsched_bytes;
	if (rpc->msgout.unscheduled > length)
		rpc->msgout.unscheduled = length;
#endif /* See strip.py */
	rpc->msgout.init_time = homa_clock();
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_fill_data_interleaved() - This function is invoked to fill in the
 * part of a data packet after the initial header, when GSO is being used
 * but TCP hijacking is not. As result, homa_seg_hdrs must be interleaved
 * with the data to provide the correct offset for each segment.
 * @rpc:            RPC whose output message is being created. Must be
 *                  locked by caller.
 * @skb:            The packet being filled. The initial homa_data_hdr was
 *                  created and initialized by the caller and the
 *                  homa_skb_info has been filled in with the packet geometry.
 * @iter:           Describes location(s) of (remaining) message data in user
 *                  space.
 * Return:          Either a negative errno or 0 (for success).
 */
#else /* See strip.py */
/**
 * homa_fill_data_interleaved() - This function is invoked to fill in the
 * part of a data packet after the initial header, when GSO is being used.
 * homa_seg_hdrs must be interleaved with the data to provide the correct
 * offset for each segment.
 * @rpc:            RPC whose output message is being created. Must be
 *                  locked by caller.
 * @skb:            The packet being filled. The initial homa_data_hdr was
 *                  created and initialized by the caller and the
 *                  homa_skb_info has been filled in with the packet geometry.
 * @iter:           Describes location(s) of (remaining) message data in user
 *                  space.
 * Return:          Either a negative errno or 0 (for success).
 */
#endif /* See strip.py */
int homa_fill_data_interleaved(struct homa_rpc *rpc, struct sk_buff *skb,
			       struct iov_iter *iter)
	__must_hold(rpc->bucket->lock)
{
	struct homa_skb_info *homa_info = homa_get_skb_info(skb);
	int seg_length = homa_info->seg_length;
	int bytes_left = homa_info->data_bytes;
	int offset = homa_info->offset;
	int err;

	/* Each iteration of the following loop adds info for one packet,
	 * which includes a homa_seg_hdr followed by the data for that
	 * segment. The first homa_seg_hdr was already added by the caller.
	 */
	while (1) {
		struct homa_seg_hdr seg;

		if (bytes_left < seg_length)
			seg_length = bytes_left;
		err = homa_skb_append_from_iter(rpc->hsk->homa, skb, iter,
						seg_length);
		if (err != 0)
			return err;
		bytes_left -= seg_length;
		offset += seg_length;

		if (bytes_left == 0)
			break;

		seg.offset = htonl(offset);
		err = homa_skb_append_to_frag(rpc->hsk->homa, skb, &seg,
					      sizeof(seg));
		if (err != 0)
			return err;
	}
	return 0;
}

/**
 * homa_tx_data_pkt_alloc() - Allocate a new sk_buff and fill it with an
 * outgoing Homa data packet. The resulting packet will be a GSO packet
 * that will eventually be segmented by the NIC.
 * @rpc:          RPC that packet will belong to (msgout must have been
 *                initialized). Must be locked by caller.
 * @iter:         Describes location(s) of (remaining) message data in user
 *                space.
 * @offset:       Offset in the message of the first byte of data in this
 *                packet.
 * @length:       How many bytes of data to include in the skb. Caller must
 *                ensure that this amount of data isn't too much for a
 *                well-formed GSO packet, and that iter has at least this
 *                much data.
 * @max_seg_data: Maximum number of bytes of message data that can go in
 *                a single segment of the GSO packet.
 * Return: A pointer to the new packet, or a negative errno.
 */
struct sk_buff *homa_tx_data_pkt_alloc(struct homa_rpc *rpc,
				       struct iov_iter *iter, int offset,
				       int length, int max_seg_data)
	__must_hold(rpc->bucket->lock)
{
	struct homa_skb_info *homa_info;
	struct homa_data_hdr *h;
	struct sk_buff *skb;
	int err, gso_size;
	u64 segs;

	segs = length + max_seg_data - 1;
	do_div(segs, max_seg_data);

	/* Initialize the overall skb. */
#ifndef __STRIP__ /* See strip.py */
	skb = homa_skb_alloc_tx(sizeof(struct homa_data_hdr));
#else /* See strip.py */
	skb = homa_skb_alloc_tx(sizeof(struct homa_data_hdr) + length +
			      (segs - 1) * sizeof(struct homa_seg_hdr));
#endif /* See strip.py */
	if (!skb)
		return ERR_PTR(-ENOMEM);

	/* Fill in the Homa header (which will be replicated in every
	 * network packet by GSO).
	 */
	h = (struct homa_data_hdr *)skb_put(skb, sizeof(struct homa_data_hdr));
	h->common.sport = htons(rpc->hsk->port);
	h->common.dport = htons(rpc->dport);
	h->common.sequence = htonl(offset);
	h->common.type = DATA;
	homa_set_doff(h, sizeof(struct homa_data_hdr));
#ifndef __STRIP__ /* See strip.py */
	h->common.flags = HOMA_TCP_FLAGS;
#endif /* See strip.py */
	h->common.checksum = 0;
#ifndef __STRIP__ /* See strip.py */
	h->common.urgent = htons(HOMA_TCP_URGENT);
#endif /* See strip.py */
	h->common.sender_id = cpu_to_be64(rpc->id);
	h->message_length = htonl(rpc->msgout.length);
#ifndef __STRIP__ /* See strip.py */
	h->incoming = htonl(rpc->msgout.unscheduled);
#endif /* See strip.py */
	h->ack.client_id = 0;
	homa_peer_get_acks(rpc->peer, 1, &h->ack);
#ifndef __STRIP__ /* See strip.py */
	h->cutoff_version = rpc->peer->cutoff_version;
#endif /* See strip.py */
	h->retransmit = 0;
#ifndef __STRIP__ /* See strip.py */
	h->seg.offset = htonl(-1);
#else /* See strip.py */
	h->seg.offset = htonl(offset);
#endif /* See strip.py */

	homa_info = homa_get_skb_info(skb);
	homa_info->next_skb = NULL;
	homa_info->wire_bytes = length + segs * (sizeof(struct homa_data_hdr)
			+  rpc->hsk->ip_header_length + HOMA_ETH_OVERHEAD);
	homa_info->data_bytes = length;
	homa_info->seg_length = max_seg_data;
	homa_info->offset = offset;
	homa_info->rpc = rpc;

#ifndef __STRIP__ /* See strip.py */
	if (segs > 1 && rpc->hsk->sock.sk_protocol != IPPROTO_TCP) {
#else /* See strip.py */
	if (segs > 1) {
#endif /* See strip.py */
		homa_set_doff(h, sizeof(struct homa_data_hdr)  -
				sizeof(struct homa_seg_hdr));
#ifndef __STRIP__ /* See strip.py */
		h->seg.offset = htonl(offset);
#endif /* See strip.py */
		gso_size = max_seg_data + sizeof(struct homa_seg_hdr);
		err = homa_fill_data_interleaved(rpc, skb, iter);
	} else {
		gso_size = max_seg_data;
		err = homa_skb_append_from_iter(rpc->hsk->homa, skb, iter,
						length);
	}
	if (err)
		goto error;

	if (segs > 1) {
		skb_shinfo(skb)->gso_segs = segs;
		skb_shinfo(skb)->gso_size = gso_size;

		/* It's unclear what gso_type should be used to force software
		 * GSO; the value below seems to work...
		 */
		skb_shinfo(skb)->gso_type =
		    rpc->hsk->homa->gso_force_software ? 0xd : SKB_GSO_TCPV6;
	}
	return skb;

error:
	homa_skb_free_tx(rpc->hsk->homa, skb);
	return ERR_PTR(err);
}

/**
 * homa_message_out_fill() - Initializes information for sending a message
 * for an RPC (either request or response); copies the message data from
 * user space and (possibly) begins transmitting the message.
 * @rpc:     RPC for which to send message; this function must not
 *           previously have been called for the RPC. Must be locked. The RPC
 *           will be unlocked while copying data, but will be locked again
 *           before returning.
 * @iter:    Describes location(s) of message data in user space.
 * @xmit:    Nonzero means this method should start transmitting packets;
 *           transmission will be overlapped with copying from user space.
 *           Zero means the caller will initiate transmission after this
 *           function returns.
 *
 * Return:   0 for success, or a negative errno for failure. It is possible
 *           for the RPC to be freed while this function is active. If that
 *           happens, copying will cease, -EINVAL will be returned, and
 *           rpc->state will be RPC_DEAD.
 */
int homa_message_out_fill(struct homa_rpc *rpc, struct iov_iter *iter, int xmit)
	__must_hold(rpc->bucket->lock)
{
	/* Geometry information for packets:
	 * mtu:              largest size for an on-the-wire packet (including
	 *                   all headers through IP header, but not Ethernet
	 *                   header).
	 * max_seg_data:     largest amount of Homa message data that fits
	 *                   in an on-the-wire packet (after segmentation).
	 * max_gso_data:     largest amount of Homa message data that fits
	 *                   in a GSO packet (before segmentation).
	 */
	int mtu, max_seg_data, max_gso_data;
	struct sk_buff **last_link;
	struct dst_entry *dst;
	u64 segs_per_gso;
	IF_NO_STRIP(int overlap_xmit);
	/* Bytes of the message that haven't yet been copied into skbs. */
	int bytes_left;
	int gso_size;
	int err;

	if (unlikely(iter->count > HOMA_MAX_MESSAGE_LENGTH ||
		     iter->count == 0)) {
		tt_record2("homa_message_out_fill found bad length %d for id %d",
			   iter->count, rpc->id);
		err = -EINVAL;
		goto error;
	}
	homa_message_out_init(rpc, iter->count);

	/* Compute the geometry of packets. */
	dst = homa_get_dst(rpc->peer, rpc->hsk);
	mtu = dst_mtu(dst);
	max_seg_data = mtu - rpc->hsk->ip_header_length
			- sizeof(struct homa_data_hdr);
	gso_size = dst->dev->gso_max_size;
	if (gso_size > rpc->hsk->homa->max_gso_size)
		gso_size = rpc->hsk->homa->max_gso_size;
	dst_release(dst);

#ifndef __STRIP__ /* See strip.py */
	/* Round gso_size down to an even # of mtus; calculation depends
	 * on whether we're doing TCP hijacking (need more space in TSO packet
	 * if no hijacking).
	 */
	if (rpc->hsk->sock.sk_protocol == IPPROTO_TCP) {
		/* Hijacking */
		segs_per_gso = gso_size - rpc->hsk->ip_header_length
				- sizeof(struct homa_data_hdr);
		do_div(segs_per_gso, max_seg_data);
	} else {
		/* No hijacking */
		segs_per_gso = gso_size - rpc->hsk->ip_header_length -
				sizeof(struct homa_data_hdr) +
				sizeof(struct homa_seg_hdr);
		do_div(segs_per_gso, max_seg_data +
				sizeof(struct homa_seg_hdr));
	}
#else /* See strip.py */
	/* Round gso_size down to an even # of mtus. */
	segs_per_gso = gso_size - rpc->hsk->ip_header_length -
			sizeof(struct homa_data_hdr) +
			sizeof(struct homa_seg_hdr);
	do_div(segs_per_gso, max_seg_data +
			sizeof(struct homa_seg_hdr));
#endif /* See strip.py */
	if (segs_per_gso == 0)
		segs_per_gso = 1;
	max_gso_data = segs_per_gso * max_seg_data;
	UNIT_LOG("; ", "mtu %d, max_seg_data %d, max_gso_data %d",
		 mtu, max_seg_data, max_gso_data);

#ifndef __STRIP__ /* See strip.py */
	overlap_xmit = rpc->msgout.length > 2 * max_gso_data;
	if (homa_qdisc_active(rpc->hsk->hnet))
		overlap_xmit = 0;
	rpc->msgout.granted = rpc->msgout.unscheduled;
#endif /* See strip.py */
	homa_skb_stash_pages(rpc->hsk->homa, rpc->msgout.length);

	/* Each iteration of the loop below creates one GSO packet. */
#ifndef __STRIP__ /* See strip.py */
	tt_record3("starting copy from user space for id %d, length %d, unscheduled %d",
		   rpc->id, rpc->msgout.length, rpc->msgout.unscheduled);
#else /* See strip.py */
	tt_record2("starting copy from user space for id %d, length %d",
		   rpc->id, rpc->msgout.length);
#endif /* See strip.py */
	last_link = &rpc->msgout.packets;
	for (bytes_left = rpc->msgout.length; bytes_left > 0; ) {
		int skb_data_bytes, offset;
		struct sk_buff *skb;

		homa_rpc_unlock(rpc);
		skb_data_bytes = max_gso_data;
		offset = rpc->msgout.length - bytes_left;
#ifndef __STRIP__ /* See strip.py */
		if (offset < rpc->msgout.unscheduled &&
		    (offset + skb_data_bytes) > rpc->msgout.unscheduled) {
			/* Insert a packet boundary at the unscheduled limit,
			 * so we don't transmit extra data.
			 */
			skb_data_bytes = rpc->msgout.unscheduled - offset;
		}
#endif /* See strip.py */
		if (skb_data_bytes > bytes_left)
			skb_data_bytes = bytes_left;
		skb = homa_tx_data_pkt_alloc(rpc, iter, offset, skb_data_bytes,
					     max_seg_data);
		if (IS_ERR(skb)) {
			err = PTR_ERR(skb);
			homa_rpc_lock(rpc);
			goto error;
		}
		bytes_left -= skb_data_bytes;

		homa_rpc_lock(rpc);
		if (rpc->state == RPC_DEAD) {
			/* RPC was freed while we were copying. */
			err = -EINVAL;
			homa_skb_free_tx(rpc->hsk->homa, skb);
			goto error;
		}
		*last_link = skb;
		last_link = &(homa_get_skb_info(skb)->next_skb);
		*last_link = NULL;
		rpc->msgout.num_skbs++;
		rpc->msgout.skb_memory += skb->truesize;
		rpc->msgout.copied_from_user = rpc->msgout.length - bytes_left;
		rpc->msgout.first_not_tx = rpc->msgout.packets;
#ifndef __STRIP__ /* See strip.py */
		if (overlap_xmit && list_empty(&rpc->throttled_links) &&
		    xmit && offset < rpc->msgout.granted) {
			tt_record1("waking up pacer for id %d", rpc->id);
			homa_pacer_manage_rpc(rpc);
		}
#endif /* See strip.py */
	}
	tt_record2("finished copy from user space for id %d, length %d",
		   rpc->id, rpc->msgout.length);
	INC_METRIC(sent_msg_bytes, rpc->msgout.length);
	refcount_add(rpc->msgout.skb_memory, &rpc->hsk->sock.sk_wmem_alloc);
#ifndef __STRIP__ /* See strip.py */
	if (!overlap_xmit && xmit)
		homa_xmit_data(rpc, false);
#else /* See strip.py */
	homa_xmit_data(rpc);
#endif /* See strip.py */
	return 0;

error:
	refcount_add(rpc->msgout.skb_memory, &rpc->hsk->sock.sk_wmem_alloc);
	return err;
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
 *             Caller must hold either the lock or a reference.
 *
 * Return:     Either zero (for success), or a negative errno value if there
 *             was a problem.
 */
int homa_xmit_control(enum homa_packet_type type, void *contents,
		      size_t length, struct homa_rpc *rpc)
{
	struct homa_common_hdr *h = contents;

	h->type = type;
	h->sport = htons(rpc->hsk->port);
	h->dport = htons(rpc->dport);
#ifndef __STRIP__ /* See strip.py */
	h->flags = HOMA_TCP_FLAGS;
	h->urgent = htons(HOMA_TCP_URGENT);
#endif /* See strip.py */
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

	skb = homa_skb_alloc_tx(HOMA_MAX_HEADER);
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
#ifndef __STRIP__ /* See strip.py */
	if (hsk->inet.sk.sk_family == AF_INET6) {
		result = ip6_xmit(&hsk->inet.sk, skb, &peer->flow.u.ip6, 0,
				  NULL, hsk->homa->priority_map[priority] << 4,
				  0);
	} else {
		/* This will find its way to the DSCP field in the IPv4 hdr. */
		hsk->inet.tos = hsk->homa->priority_map[priority] << 5;
		result = ip_queue_xmit(&hsk->inet.sk, skb, &peer->flow);
	}
#else /* See strip.py */
	if (hsk->inet.sk.sk_family == AF_INET6)
		result = ip6_xmit(&hsk->inet.sk, skb, &peer->flow.u.ip6, 0,
				  NULL, 0, 0);
	else
		result = ip_queue_xmit(&hsk->inet.sk, skb, &peer->flow);
#endif /* See strip.py */
	if (unlikely(result != 0))
		INC_METRIC(control_xmit_errors, 1);
#ifndef __STRIP__ /* See strip.py */
	if (skb->dev) {
		struct netdev_queue *txq;

		txq = netdev_get_tx_queue(skb->dev, skb->queue_mapping);
		if (netif_tx_queue_stopped(txq))
			tt_record4("__homa_xmit_control found stopped txq for id %d, qid %u, num_queued %u, limit %d",
				be64_to_cpu(h->sender_id), skb->queue_mapping,
				txq->dql.num_queued, txq->dql.adj_limit);
	}
#endif /* See strip.py */
	INC_METRIC(packets_sent[h->type - DATA], 1);
	INC_METRIC(priority_bytes[priority], skb->len);
	INC_METRIC(priority_packets[priority], 1);
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
	unknown.common.sport = h->dport;
	unknown.common.dport = h->sport;
	unknown.common.type = RPC_UNKNOWN;
#ifndef __STRIP__ /* See strip.py */
	unknown.common.flags = HOMA_TCP_FLAGS;
	unknown.common.urgent = htons(HOMA_TCP_URGENT);
#endif /* See strip.py */
	unknown.common.sender_id = cpu_to_be64(homa_local_id(h->sender_id));
	peer = homa_peer_get(hsk, &saddr);
	if (!IS_ERR(peer))
		__homa_xmit_control(&unknown, sizeof(unknown), peer, hsk);
	homa_peer_release(peer);
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_xmit_data() - If an RPC has outbound data packets that are permitted
 * to be transmitted according to the scheduling mechanism, arrange for
 * them to be sent (some may be sent immediately; others may be sent
 * later by the pacer thread).
 * @rpc:       RPC to check for transmittable packets. Must be locked by
 *             caller. Note: this function will release the RPC lock while
 *             passing packets through the RPC stack, then reacquire it
 *             before returning. It is possible that the RPC gets terminated
 *             when the lock isn't held, in which case the state will
 *             be RPC_DEAD on return.
 * @force:     True means send at least one packet, even if the NIC queue
 *             is too long. False means that zero packets may be sent, if
 *             the NIC queue is sufficiently long.
 */
void homa_xmit_data(struct homa_rpc *rpc, bool force)
#else /* See strip.py */
/**
 * homa_xmit_data() - If an RPC has outbound data packets that are permitted
 * to be transmitted according to the scheduling mechanism, arrange for
 * them to be sent.
 * @rpc:       RPC to check for transmittable packets. Must be locked by
 *             caller. Note: this function will release the RPC lock while
 *             passing packets through the RPC stack, then reacquire it
 *             before returning. It is possible that the RPC gets terminated
 *             when the lock isn't held, in which case the state will
 *             be RPC_DEAD on return.
 */
void homa_xmit_data(struct homa_rpc *rpc)
#endif /* See strip.py */
	__must_hold(rpc->bucket->lock)
{
	int length;

	IF_NO_STRIP(struct homa *homa = rpc->hsk->homa);
	IF_NO_STRIP(struct netdev_queue *txq);

	while (*rpc->msgout.next_xmit && rpc->state != RPC_DEAD) {
		struct sk_buff *skb = *rpc->msgout.next_xmit;

		IF_NO_STRIP(int priority);

#ifndef __STRIP__ /* See strip.py */
		if (rpc->msgout.next_xmit_offset >= rpc->msgout.granted) {
			tt_record3("homa_xmit_data stopping at offset %d for id %u: granted is %d",
				   rpc->msgout.next_xmit_offset, rpc->id,
				   rpc->msgout.granted);
			break;
		}

		if (rpc->msgout.length - rpc->msgout.next_xmit_offset >
		    homa->pacer->throttle_min_bytes &&
		    !homa_qdisc_active(rpc->hsk->hnet)) {
			if (!homa_pacer_check_nic_q(homa->pacer, skb, force)) {
				tt_record1("homa_xmit_data adding id %u to throttle queue",
					   rpc->id);
				homa_pacer_manage_rpc(rpc);
				break;
			}
		}

		if (rpc->msgout.next_xmit_offset < rpc->msgout.unscheduled)
			priority = homa_unsched_priority(homa, rpc->peer,
							 rpc->msgout.length);
		else
			priority = rpc->msgout.sched_priority;
#endif /* See strip.py */
		rpc->msgout.next_xmit = &(homa_get_skb_info(skb)->next_skb);
		length = homa_get_skb_info(skb)->data_bytes;
		rpc->msgout.next_xmit_offset += length;
#ifndef __STRIP__ /* See strip.py */
		if (homa_is_client(rpc->id)) {
			INC_METRIC(client_request_bytes_done, length);
			INC_METRIC(client_requests_done,
				   rpc->msgout.next_xmit_offset ==
				   rpc->msgout.length);
		} else {
			INC_METRIC(server_response_bytes_done, length);
			INC_METRIC(server_responses_done,
				   rpc->msgout.next_xmit_offset ==
				   rpc->msgout.length);
		}
#endif /* See strip.py */

		homa_rpc_unlock(rpc);
		skb_get(skb);
#ifndef __STRIP__ /* See strip.py */
		__homa_xmit_data(skb, rpc, priority);
		txq = netdev_get_tx_queue(skb->dev, skb->queue_mapping);
		if (netif_tx_queue_stopped(txq))
			tt_record4("homa_xmit_data found stopped txq for id %d, qid %d, num_queued %d, limit %d",
				   rpc->id, skb->queue_mapping,
				   txq->dql.num_queued, txq->dql.adj_limit);
		force = false;
#else /* See strip.py */
		__homa_xmit_data(skb, rpc);
#endif /* See strip.py */
		homa_rpc_lock(rpc);
	}
}

#ifndef __STRIP__ /* See strip.py */
/**
 * __homa_xmit_data() - Handles packet transmission stuff that is common
 * to homa_xmit_data and homa_resend_data.
 * @skb:      Packet to be sent. The packet will be freed after transmission
 *            (and also if errors prevented transmission).
 * @rpc:      Information about the RPC that the packet belongs to.
 * @priority: Priority level at which to transmit the packet.
 */
void __homa_xmit_data(struct sk_buff *skb, struct homa_rpc *rpc, int priority)
#else /* See strip.py */
/**
 * __homa_xmit_data() - Handles packet transmission stuff that is common
 * to homa_xmit_data and homa_resend_data.
 * @skb:      Packet to be sent. The packet will be freed after transmission
 *            (and also if errors prevented transmission).
 * @rpc:      Information about the RPC that the packet belongs to.
 */
void __homa_xmit_data(struct sk_buff *skb, struct homa_rpc *rpc)
#endif /* See strip.py */
{
#ifndef __STRIP__ /* See strip.py */
	int err;

	/* Update info that may have changed since the message was initially
	 * created.
	 */
	((struct homa_data_hdr *)skb_transport_header(skb))->cutoff_version =
			rpc->peer->cutoff_version;
#endif /* See strip.py */

	skb_dst_set(skb, homa_get_dst(rpc->peer, rpc->hsk));

	skb->ooo_okay = 1;
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct homa_common_hdr, checksum);
	if (rpc->hsk->inet.sk.sk_family == AF_INET6) {
		tt_record4("calling ip6_xmit: wire_bytes %d, peer 0x%x, id %d, offset %d",
			   homa_get_skb_info(skb)->wire_bytes,
			   tt_addr(rpc->peer->addr), rpc->id,
			   homa_get_skb_info(skb)->offset);
#ifndef __STRIP__ /* See strip.py */
		err = ip6_xmit(&rpc->hsk->inet.sk, skb, &rpc->peer->flow.u.ip6,
			       0, NULL,
			       rpc->hsk->homa->priority_map[priority] << 4, 0);
#else /* See strip.py */
		ip6_xmit(&rpc->hsk->inet.sk, skb, &rpc->peer->flow.u.ip6,
			 0, NULL, 0, 0);
#endif /* See strip.py */
	} else {
		tt_record4("calling ip_queue_xmit: wire_bytes %d, peer 0x%x, id %d, offset %d",
			   homa_get_skb_info(skb)->wire_bytes,
			   tt_addr(rpc->peer->addr), rpc->id,
			   homa_get_skb_info(skb)->offset);

#ifndef __STRIP__ /* See strip.py */
		rpc->hsk->inet.tos =
				rpc->hsk->homa->priority_map[priority] << 5;
		err = ip_queue_xmit(&rpc->hsk->inet.sk, skb, &rpc->peer->flow);
#else /* See strip.py */
		ip_queue_xmit(&rpc->hsk->inet.sk, skb, &rpc->peer->flow);
#endif /* See strip.py */
	}
	tt_record4("Finished queueing packet: rpc id %llu, offset %d, len %d, qid %d",
		   rpc->id, homa_get_skb_info(skb)->offset,
		   homa_get_skb_info(skb)->data_bytes, skb->queue_mapping);
#ifndef __STRIP__ /* See strip.py */
	if (err)
		INC_METRIC(data_xmit_errors, 1);
#endif /* See strip.py */
	INC_METRIC(packets_sent[0], 1);
	INC_METRIC(priority_bytes[priority], skb->len);
	INC_METRIC(priority_packets[priority], 1);
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_resend_data() - This function is invoked as part of handling RESEND
 * requests. It retransmits the packet(s) containing a given range of bytes
 * from a message.
 * @rpc:      RPC for which data should be resent. Must be locked by caller.
 * @start:    Offset within @rpc->msgout of the first byte to retransmit.
 * @end:      Offset within @rpc->msgout of the byte just after the last one
 *            to retransmit.
 * @priority: Priority level to use for the retransmitted data packets.
 */
void homa_resend_data(struct homa_rpc *rpc, int start, int end,
		      int priority)
#else /* See strip.py */
/**
 * homa_resend_data() - This function is invoked as part of handling RESEND
 * requests. It retransmits the packet(s) containing a given range of bytes
 * from a message.
 * @rpc:      RPC for which data should be resent.
 * @start:    Offset within @rpc->msgout of the first byte to retransmit.
 * @end:      Offset within @rpc->msgout of the byte just after the last one
 *            to retransmit.
 */
void homa_resend_data(struct homa_rpc *rpc, int start, int end)
#endif /* See strip.py */
	__must_hold(rpc->bucket->lock)
{
	struct homa_skb_info *homa_info;
	struct sk_buff *skb;

	if (end <= start)
		return;

	/* Each iteration of this loop checks one packet in the message
	 * to see if it contains segments that need to be retransmitted.
	 */
	for (skb = rpc->msgout.packets; skb; skb = homa_info->next_skb) {
		int seg_offset, offset, seg_length, data_left;
		struct homa_data_hdr *h;

		homa_info = homa_get_skb_info(skb);
		offset = homa_info->offset;
		if (offset >= end)
			break;
		if (start >= (offset + homa_info->data_bytes))
			continue;

		offset = homa_info->offset;
		seg_offset = sizeof(struct homa_data_hdr);
		data_left = homa_info->data_bytes;
		if (skb_shinfo(skb)->gso_segs <= 1) {
			seg_length = data_left;
		} else {
			seg_length = homa_info->seg_length;
			h = (struct homa_data_hdr *)skb_transport_header(skb);
		}
		for ( ; data_left > 0; data_left -= seg_length,
		     offset += seg_length,
		     seg_offset += skb_shinfo(skb)->gso_size) {
			struct homa_skb_info *new_homa_info;
			struct sk_buff *new_skb;
			int err;

			if (seg_length > data_left)
				seg_length = data_left;

			if (end <= offset)
				goto resend_done;
			if ((offset + seg_length) <= start)
				continue;

			/* This segment must be retransmitted. */
#ifndef __STRIP__ /* See strip.py */
			new_skb = homa_skb_alloc_tx(sizeof(struct homa_data_hdr));
#else /* See strip.py */
			new_skb = homa_skb_alloc_tx(sizeof(struct homa_data_hdr) +
						    seg_length);
#endif /* See strip.py */
			if (unlikely(!new_skb)) {
				UNIT_LOG("; ", "skb allocation error");
				goto resend_done;
			}
			h = __skb_put_data(new_skb, skb_transport_header(skb),
					   sizeof(struct homa_data_hdr));
			h->common.sequence = htonl(offset);
			h->seg.offset = htonl(offset);
			h->retransmit = 1;
			IF_NO_STRIP(h->incoming = htonl(end));
			err = homa_skb_append_from_skb(rpc->hsk->homa, new_skb,
						       skb, seg_offset,
						       seg_length);
			if (err != 0) {
				pr_err("%s got error %d from homa_skb_append_from_skb\n",
				       __func__, err);
				UNIT_LOG("; ", "%s got error %d while copying data",
					 __func__, -err);
				kfree_skb(new_skb);
				goto resend_done;
			}

			new_homa_info = homa_get_skb_info(new_skb);
			new_homa_info->next_skb = NULL;
			new_homa_info->wire_bytes = rpc->hsk->ip_header_length
					+ sizeof(struct homa_data_hdr)
					+ seg_length + HOMA_ETH_OVERHEAD;
			new_homa_info->data_bytes = seg_length;
			new_homa_info->seg_length = seg_length;
			new_homa_info->offset = offset;
			new_homa_info->rpc = rpc;
			tt_record3("retransmitting offset %d, length %d, id %d",
				   offset, seg_length, rpc->id);
#ifndef __STRIP__ /* See strip.py */
			homa_pacer_check_nic_q(rpc->hsk->homa->pacer, new_skb,
					       true);
			__homa_xmit_data(new_skb, rpc, priority);
#else /* See strip.py */
			__homa_xmit_data(new_skb, rpc);
#endif /* See strip.py */
			INC_METRIC(resent_packets, 1);
		}
	}

resend_done:
	return;
}

/**
 * homa_rpc_tx_end() - Return the offset of the first byte in an
 * RPC's outgoing message that has not yet been fully transmitted.
 * "Fully transmitted" means the message has been transmitted by the
 * NIC and the skb has been released by the driver. This is different from
 * rpc->msgout.next_xmit_offset, which computes the first offset that
 * hasn't yet been passed to the IP stack.
 * @rpc:    RPC to check
 * Return:  See above. If the message has been fully transmitted then
 *          rpc->msgout.length is returned.
 */
int homa_rpc_tx_end(struct homa_rpc *rpc)
{
	struct sk_buff *skb = rpc->msgout.first_not_tx;

	while (skb) {
		struct homa_skb_info *homa_info = homa_get_skb_info(skb);

		/* next_xmit_offset tells us whether the packet has been
		 * passed to the IP stack. Checking the reference count tells
		 * us whether the packet has been released by the driver
		 * (which only happens after notification from the NIC that
		 * transmission is complete).
		 */
		if (homa_info->offset >= rpc->msgout.next_xmit_offset ||
		    refcount_read(&skb->users) > 1)
			return homa_info->offset;
		skb = homa_info->next_skb;
		rpc->msgout.first_not_tx = skb;
	}
	return rpc->msgout.length;
}
