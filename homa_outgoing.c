/* Copyright (c) 2019-2023 Homa Developers
 * SPDX-License-Identifier: BSD-1-Clause
 */

/* This file contains functions related to the sender side of message
 * transmission. It also contains utility functions for sending packets.
 */

#include "homa_impl.h"

/**
 * set_priority() - Arrange for an outgoing packet to have a particular
 * priority level.
 * @skb:        The packet was priority should be set.
 * @hsk:        Socket on which the packet will be sent.
 * @priority:   Priority level for the packet; must be less than
 *              HOMA_MAX_PRIORITIES.
 */
inline static void set_priority(struct sk_buff *skb, struct homa_sock *hsk,
		int priority)
{
	/* Note: this code initially specified the priority in the VLAN
	 * header, but as of 3/2020, this performed badly on the CloudLab
	 * cluster being used for testing: 100 us of extra delay occurred
	 * whenever a packet's VLAN priority differed from the previous
	 * packet. So, now we use the DSCP field in the IP header instead.
	 */
	hsk->inet.tos = hsk->homa->priority_map[priority]<<5;
}

/**
 * homa_message_out_init() - Initialize rpc->msgout.
 * @rpc:       RPC whose output message should be initialized.
 * @length:    Number of bytes that will eventually be in rpc->msgout.
 */
void homa_message_out_init(struct homa_rpc *rpc, int length)
{
	rpc->msgout.length = length;
	rpc->msgout.num_skbs = 0;
	rpc->msgout.copied_from_user = 0;
	rpc->msgout.packets = NULL;
	rpc->msgout.next_xmit = &rpc->msgout.packets;
	rpc->msgout.next_xmit_offset = 0;
	atomic_set(&rpc->msgout.active_xmits, 0);
	rpc->msgout.unscheduled = rpc->hsk->homa->unsched_bytes;
	if (rpc->msgout.unscheduled > length)
		rpc->msgout.unscheduled = length;
	rpc->msgout.sched_priority = 0;
	rpc->msgout.init_cycles = get_cycles();
}

/**
 * homa_new_data_packet() - Allocate a new sk_buff and fill it with a Homa
 * data packet. The resulting packet will be a TSO packet that will eventually
 * be segmented by the NIC.
 * @rpc:          RPC that packet will belong to (msgout must have been
 *                initialized).
 * @iter:         Describes location(s) of (remaining) message data in user
 *                space.
 * @offset:       Offset in the message of the first byte of data in this
 *                packet.
 * @length:       How many bytes of data to include in the skb. Caller must
 *                ensure that this amount of data isn't too much for a
 *                well-formed TSO packet, and that iter has at least this
 *                much data.
 * @max_seg_data: Maximum number of bytes of message data that can go in
 *                a single segment of the TSO packet.
 * Return: A pointer to the new packet, or a negative errno.
 */
struct sk_buff *homa_new_data_packet(struct homa_rpc *rpc,
		struct iov_iter *iter, int offset, int length,
		int max_seg_data)
{
	struct data_header *h;
	struct sk_buff *skb;
	struct homa_skb_info *homa_info;
	int segs, bytes_left, err;

	/* Initialize the overall skb. */
	skb = homa_skb_new_tx(sizeof32(struct data_header)
			- sizeof32(struct data_segment));
	if (!skb)
		return ERR_PTR(-ENOMEM);

	/* Fill in the Homa header (which will be replicated in every
	 * network packet by GSO/TSO).
	 */
	h = (struct data_header *) skb_put(skb,
			sizeof(*h) - sizeof(struct data_segment));
	h->common.sport = htons(rpc->hsk->port);
	h->common.dport = htons(rpc->dport);
	homa_set_doff(h);
	h->common.type = DATA;
	h->common.sender_id = cpu_to_be64(rpc->id);
	h->message_length = htonl(rpc->msgout.length);
	h->incoming = htonl(rpc->msgout.unscheduled);
	h->cutoff_version = rpc->peer->cutoff_version;
	h->retransmit = 0;
	homa_info = homa_get_skb_info(skb);
	homa_info->next_skb = NULL;
	homa_info->wire_bytes = 0;
	homa_info->data_bytes = 0;
	homa_info->offset = offset;

	/* Each iteration of the following loop adds one segment
	 * (which will become a separate packet after GSO) to the skb.
	 */
	bytes_left = length;
	segs = 0;
	do {
		int seg_size;
		struct data_segment seg;
		seg.offset = htonl(offset);
		if (bytes_left <= max_seg_data)
			seg_size = bytes_left;
		else
			seg_size = max_seg_data;
		seg.segment_length = htonl(seg_size);
		seg.ack.client_id = 0;
		homa_peer_get_acks(rpc->peer, 1, &seg.ack);
		err = homa_skb_append_to_frag(rpc->hsk->homa, skb, &seg,
				sizeof(seg));
		if (err != 0)
			goto error;
		err = homa_skb_append_from_iter(rpc->hsk->homa, skb, iter,
				seg_size);
		if (err != 0)
			goto error;
		bytes_left -= seg_size;
		segs++;
		homa_info->wire_bytes += seg_size + sizeof(struct data_segment)
				+ sizeof(struct data_header)
				+  rpc->hsk->ip_header_length
				+ HOMA_ETH_OVERHEAD;
		homa_info->data_bytes += seg_size;
		offset += seg_size;
	} while (bytes_left > 0);

	if (segs > 1)
	{
		skb_shinfo(skb)->gso_segs = segs;
		skb_shinfo(skb)->gso_size = sizeof(struct data_segment)
				+ max_seg_data;

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
 * Return:   0 for success, or a negative errno for failure. It is is possible
 *           for the RPC to be freed while this function is active. If that
 *           happens, copying will cease, -EINVAL will be returned, and
 *           rpc->state will be RPC_DEAD.
 */
int homa_message_out_fill(struct homa_rpc *rpc, struct iov_iter *iter, int xmit)
{
	/* Geometry information for packets:
	 * mtu:              largest size for an on-the-wire packet (including
	 *                   all headers through IP header, but not Ethernet
	 *                   header).
	 * max_seg_data:     largest amount of Homa message data that fits
	 *                   in an on-the-wire packet (after segmentation).
	 * max_gso_data:     largest amount of  Homa message data that fits
	 *                   in a GSO packet (before segmentation).
	 */
	int mtu, max_seg_data, max_gso_data;

	/* Bytes of the message that haven't yet been copied into skbs. */
	int bytes_left;

	int err;
	struct sk_buff **last_link;
	struct dst_entry *dst;
	int overlap_xmit, segs_per_gso;
	int gso_size;

	homa_message_out_init(rpc, iter->count);
	if (unlikely((rpc->msgout.length > HOMA_MAX_MESSAGE_LENGTH)
			|| (rpc->msgout.length == 0))) {
		tt_record2("homa_message_out_fill found bad length %d for id %d",
				rpc->msgout.length, rpc->id);
		err = -EINVAL;
		goto error;
	}

	/* Compute the geometry of packets. */
	dst = homa_get_dst(rpc->peer, rpc->hsk);
	mtu = dst_mtu(dst);
	max_seg_data = mtu - rpc->hsk->ip_header_length
			- sizeof(struct data_header);
	gso_size = dst->dev->gso_max_size;
	if (gso_size > rpc->hsk->homa->max_gso_size)
		gso_size = rpc->hsk->homa->max_gso_size;

	/* Round gso_size down to an even # of mtus. */
	segs_per_gso = (gso_size - rpc->hsk->ip_header_length
			- sizeof(struct data_header))/max_seg_data;
	if (segs_per_gso == 0)
		segs_per_gso = 1;
	max_gso_data = segs_per_gso * max_seg_data;
	UNIT_LOG("; ", "mtu %d, max_seg_data %d, max_gso_data %d",
			mtu, max_seg_data, max_gso_data);

	overlap_xmit = rpc->msgout.length > 2*max_gso_data;
	rpc->msgout.granted = rpc->msgout.unscheduled;
	atomic_or(RPC_COPYING_FROM_USER, &rpc->flags);

	/* Each iteration of the loop below creates one GSO packet. */
	tt_record3("starting copy from user space for id %d, length %d, "
			"unscheduled %d",
			rpc->id, rpc->msgout.length, rpc->msgout.unscheduled);
	last_link = &rpc->msgout.packets;
	for (bytes_left = rpc->msgout.length; bytes_left > 0; ) {
		int skb_data_bytes, offset;
		struct sk_buff *skb;

		homa_rpc_unlock(rpc);
		skb_data_bytes = max_gso_data;
		offset = rpc->msgout.length - bytes_left;
		if ((offset < rpc->msgout.unscheduled) &&
				((offset + skb_data_bytes)
				> rpc->msgout.unscheduled)) {
			/* Insert a packet boundary at the unscheduled limit,
			 * so we don't transmit extra data.
			 */
			skb_data_bytes = rpc->msgout.unscheduled - offset;
		}
		if (skb_data_bytes > bytes_left)
			skb_data_bytes = bytes_left;
		skb = homa_new_data_packet(rpc, iter, offset, skb_data_bytes,
				max_seg_data);
		if (unlikely(!skb)) {
			err = PTR_ERR(skb);
			homa_rpc_lock(rpc, "homa_message_out_fill");
			goto error;
		}
		bytes_left -= skb_data_bytes;

		homa_rpc_lock(rpc, "homa_message_out_fill2");
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
		rpc->msgout.copied_from_user = rpc->msgout.length - bytes_left;
		if (overlap_xmit && list_empty(&rpc->throttled_links) && xmit
				&& (offset < rpc->msgout.granted)) {
			tt_record1("waking up pacer for id %d", rpc->id);
			homa_add_to_throttled(rpc);
		}
	}
	tt_record2("finished copy from user space for id %d, length %d",
			rpc->id, rpc->msgout.length);
	atomic_andnot(RPC_COPYING_FROM_USER, &rpc->flags);
	INC_METRIC(sent_msg_bytes, rpc->msgout.length);
	if (!overlap_xmit && xmit)
		homa_xmit_data(rpc, false);
	return 0;

    error:
	atomic_andnot(RPC_COPYING_FROM_USER, &rpc->flags);
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
 *             the fields of common_header except type, will be set from this.
 *
 * Return:     Either zero (for success), or a negative errno value if there
 *             was a problem.
 */
int homa_xmit_control(enum homa_packet_type type, void *contents,
	size_t length, struct homa_rpc *rpc)
{
	struct common_header *h = (struct common_header *) contents;
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
	struct common_header *h;
	int extra_bytes;
	int result, priority;
	struct dst_entry *dst;
	struct sk_buff *skb;

	/* Allocate the same size sk_buffs as for the smallest data
         * packets (better reuse of sk_buffs?).
	 */
	dst = homa_get_dst(peer, hsk);
	skb = homa_skb_new_tx(HOMA_MAX_HEADER);
	if (unlikely(!skb))
		return -ENOBUFS;
	dst_hold(dst);
	skb_dst_set(skb, dst);

	h = (struct common_header *) skb_put(skb, length);
	memcpy(h, contents, length);
	extra_bytes = HOMA_MIN_PKT_LENGTH - length;
	if (extra_bytes > 0) {
		memset(skb_put(skb, extra_bytes), 0, extra_bytes);
		UNIT_LOG(",", "padded control packet with %d bytes",
				extra_bytes);
	}
	priority = hsk->homa->num_priorities-1;
	skb->ooo_okay = 1;
	skb_get(skb);
	if (hsk->inet.sk.sk_family == AF_INET6) {
		result = ip6_xmit(&hsk->inet.sk, skb, &peer->flow.u.ip6, 0,
				NULL, hsk->homa->priority_map[priority] << 4, 0);
	} else {
		/* This will find its way to the DSCP field in the IPv4 hdr. */
		hsk->inet.tos = hsk->homa->priority_map[priority]<<5;
		result = ip_queue_xmit(&hsk->inet.sk, skb, &peer->flow);
	}
	if (unlikely(result != 0)) {
		INC_METRIC(control_xmit_errors, 1);

		/* It appears that ip*_xmit frees skbuffs after
		 * errors; the following code is to raise an alert if
		 * this isn't actually the case. The extra skb_get above
		 * and kfree_skb call below are needed to do the check
		 * accurately (otherwise the buffer could be freed and
		 * its memory used for some other purpose, resulting in
		 * a bogus "reference count").
		 */
		if (refcount_read(&skb->users) > 1) {
			if (hsk->inet.sk.sk_family == AF_INET6) {
				printk(KERN_NOTICE "ip6_xmit didn't free "
						"Homa control packet (type %d) "
						"after error %d\n",
						h->type, result);
			} else {
				printk(KERN_NOTICE "ip_queue_xmit didn't free "
						"Homa control packet (type %d) "
						"after error %d\n",
						h->type, result);
				tt_record2("ip_queue_xmit didn't free Homa "
						"control packet (type %d) "
						"after error %d\n",
						h->type, result);
			}
		}
	}
	INC_METRIC(packets_sent[h->type - DATA], 1);
	INC_METRIC(priority_bytes[priority], skb->len);
	INC_METRIC(priority_packets[priority], 1);
	kfree_skb(skb);
	return result;
}

/**
 * homa_xmit_unknown() - Send an UNKNOWN packet to a peer.
 * @skb:         Buffer containing an incoming packet; identifies the peer to
 *               which the UNKNOWN packet should be sent.
 * @hsk:         Socket that should be used to send the UNKNOWN packet.
 */
void homa_xmit_unknown(struct sk_buff *skb, struct homa_sock *hsk)
{
	struct common_header *h = (struct common_header *) skb->data;
	struct unknown_header unknown;
	struct homa_peer *peer;
	struct in6_addr saddr = skb_canonical_ipv6_saddr(skb);

	if (hsk->homa->verbose)
		printk(KERN_NOTICE "sending UNKNOWN to peer "
				"%s:%d for id %llu",
				homa_print_ipv6_addr(&saddr),
				ntohs(h->sport), homa_local_id(h->sender_id));
	tt_record3("sending unknown to 0x%x:%d for id %llu",
			tt_addr(saddr), ntohs(h->sport),
			homa_local_id(h->sender_id));
	unknown.common.sport = h->dport;
	unknown.common.dport = h->sport;
	unknown.common.sender_id = cpu_to_be64(homa_local_id(h->sender_id));
	unknown.common.type = UNKNOWN;
	peer = homa_peer_find(&hsk->homa->peers, &saddr, &hsk->inet);
	if (!IS_ERR(peer))
		 __homa_xmit_control(&unknown, sizeof(unknown), peer, hsk);
}

/**
 * homa_xmit_data() - If an RPC has outbound data packets that are permitted
 * to be transmitted according to the scheduling mechanism, arrange for
 * them to be sent (some may be sent immediately; others may be sent
 * later by the pacer thread).
 * @rpc:       RPC to check for transmittable packets. Must be locked by
 *             caller. Note: this function will release the RPC lock while
 *             passing packets through the RPC stack, then reacquire it
 *             before returning.
 * @force:     True means send at least one packet, even if the NIC queue
 *             is too long. False means that zero packets may be sent, if
 *             the NIC queue is sufficiently long.
 */
void homa_xmit_data(struct homa_rpc *rpc, bool force)
{
	struct homa *homa = rpc->hsk->homa;

	tt_record("homa_xmit_data starting");

	atomic_inc(&rpc->msgout.active_xmits);
	while (*rpc->msgout.next_xmit) {
		int priority;
		struct sk_buff *skb = *rpc->msgout.next_xmit;

		if (rpc->msgout.next_xmit_offset >= rpc->msgout.granted) {
			tt_record3("homa_xmit_data stopping at offset %d "
					"for id %u: granted is %d",
					rpc->msgout.next_xmit_offset, rpc->id,
					rpc->msgout.granted);
			break;
		}

		if ((rpc->msgout.length - rpc->msgout.next_xmit_offset)
				>= homa->throttle_min_bytes) {
			if (!homa_check_nic_queue(homa, skb, force)) {
				tt_record1("homa_xmit_data adding id %u to "
						"throttle queue", rpc->id);
				homa_add_to_throttled(rpc);
				break;
			}
		}

		if (rpc->msgout.next_xmit_offset < rpc->msgout.unscheduled) {
			priority = homa_unsched_priority(homa, rpc->peer,
					rpc->msgout.length);
		} else {
			priority = rpc->msgout.sched_priority;
		}
		rpc->msgout.next_xmit = &(homa_get_skb_info(skb)->next_skb);
		rpc->msgout.next_xmit_offset +=
				homa_get_skb_info(skb)->data_bytes;

		homa_rpc_unlock(rpc);
		skb_get(skb);
		__homa_xmit_data(skb, rpc, priority);
		force = false;
		homa_rpc_lock(rpc, "homa_xmit_data");
	}
	atomic_dec(&rpc->msgout.active_xmits);
}

/**
 * __homa_xmit_data() - Handles packet transmission stuff that is common
 * to homa_xmit_data and homa_resend_data.
 * @skb:      Packet to be sent. The packet will be freed after transmission
 *            (and also if errors prevented transmission).
 * @rpc:      Information about the RPC that the packet belongs to.
 * @priority: Priority level at which to transmit the packet.
 */
void __homa_xmit_data(struct sk_buff *skb, struct homa_rpc *rpc, int priority)
{
	int err;
	struct homa_skb_info *homa_info = homa_get_skb_info(skb);
	struct dst_entry *dst;

	/* Update info that may have changed since the message was initially
	 * created.
	 */
	((struct data_header *) skb_transport_header(skb))->cutoff_version
			= rpc->peer->cutoff_version;

	dst = homa_get_dst(rpc->peer, rpc->hsk);
	dst_hold(dst);
	skb_dst_set(skb, dst);

	skb->ooo_okay = 1;
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct common_header, checksum);
	if (rpc->hsk->inet.sk.sk_family == AF_INET6) {
		tt_record4("calling ip6_xmit: wire_bytes %d, peer 0x%x, id %d, "
				"offset %d",
				homa_get_skb_info(skb)->wire_bytes,
				tt_addr(rpc->peer->addr), rpc->id,
				homa_info->offset);
		err = ip6_xmit(&rpc->hsk->inet.sk, skb, &rpc->peer->flow.u.ip6,
				0, NULL,
				rpc->hsk->homa->priority_map[priority] << 4, 0);
	} else {
		tt_record4("calling ip_queue_xmit: wire_bytes %d, peer 0x%x, "
				"id %d, offset %d",
				homa_get_skb_info(skb)->wire_bytes,
				tt_addr(rpc->peer->addr), rpc->id,
				homa_info->offset);

		rpc->hsk->inet.tos = rpc->hsk->homa->priority_map[priority]<<5;
		err = ip_queue_xmit(&rpc->hsk->inet.sk, skb, &rpc->peer->flow);
	}
	tt_record4("Finished queueing packet: rpc id %llu, offset %d, len %d, "
			"granted %d",
			rpc->id, homa_info->offset,
			homa_get_skb_info(skb)->data_bytes,
			rpc->msgout.granted);
	if (err) {
		INC_METRIC(data_xmit_errors, 1);
	}
	INC_METRIC(packets_sent[0], 1);
	INC_METRIC(priority_bytes[priority], skb->len);
	INC_METRIC(priority_packets[priority], 1);
}

/**
 * homa_resend_data() - This function is invoked as part of handling RESEND
 * requests. It retransmits the packet(s) containing a given range of bytes
 * from a message.
 * @rpc:      RPC for which data should be resent.
 * @start:    Offset within @rpc->msgout of the first byte to retransmit.
 * @end:      Offset within @rpc->msgout of the byte just after the last one
 *            to retransmit.
 * @priority: Priority level to use for the retransmitted data packets.
 */
void homa_resend_data(struct homa_rpc *rpc, int start, int end,
		int priority)
{
	struct sk_buff *skb;
	struct homa_skb_info *homa_info;

	if (end <= start)
		return;

	/* Each iteration of this loop checks one packet in the message
	 * to see if it contains segments that need to be retransmitted.
	 */
	for (skb = rpc->msgout.packets; skb !=  NULL;
			skb = homa_info->next_skb) {
		int seg_offset, offset, length, segs_left;
		struct data_segment seg;
		struct data_header *h;

		homa_info = homa_get_skb_info(skb);
		if ((homa_info->offset >= end) || (start >=
				(homa_info->offset + homa_info->data_bytes)))
			continue;

		seg_offset = (skb_transport_header(skb) - skb->data)
				+ sizeof32(struct data_header)
				- sizeof32(struct data_segment);
		segs_left = skb_shinfo(skb)->gso_segs;
		if (segs_left < 1)
			segs_left = 1;
		for ( ; segs_left > 0; segs_left--,
				seg_offset += sizeof32(seg) + length) {
			struct sk_buff *new_skb;
			struct homa_skb_info *new_homa_info;
			int err;

			homa_skb_get(skb, &seg, seg_offset, sizeof(seg));
			offset = ntohl(seg.offset);
			length = ntohl(seg.segment_length);

			if (end <= offset)
				goto resend_done;
			if ((offset + length) <= start)
				continue;

			/* This segment must be retransmitted. */
			new_skb = homa_skb_new_tx(sizeof(struct data_header)
					- sizeof(struct data_segment));
			if (unlikely(!new_skb)) {
				if (rpc->hsk->homa->verbose)
					printk(KERN_NOTICE "homa_resend_data "
						"couldn't allocate skb\n");
				UNIT_LOG("; ", "skb allocation error");
				goto resend_done;
			}
			h = (struct data_header *) __skb_put_data(new_skb,
					skb_transport_header(skb),
					sizeof32(struct data_header)
					- sizeof32(struct data_segment));
			h->retransmit = 1;
			if ((offset + length) <= rpc->msgout.granted)
				h->incoming = htonl(rpc->msgout.granted);
			else if ((offset + length) > rpc->msgout.length)
				h->incoming = htonl(rpc->msgout.length);
			else
				h->incoming = htonl(offset + length);
			err = homa_skb_append_from_skb(rpc->hsk->homa, new_skb,
					skb, seg_offset, sizeof32(seg) + length);
			if (err != 0) {
				printk(KERN_ERR "homa_resend_data got error %d "
						"from homa_skb_append_from_skb\n",
						err);
				UNIT_LOG("; ", "homa_resend_data got error %d "
						"while copying data", -err);
				kfree_skb(new_skb);
				goto resend_done;
			}

			new_homa_info = homa_get_skb_info(new_skb);
			new_homa_info->wire_bytes = rpc->hsk->ip_header_length
					+ sizeof(struct data_header) + length
					+ HOMA_ETH_OVERHEAD;
			new_homa_info->data_bytes = length;
			new_homa_info->offset = offset;
			tt_record3("retransmitting offset %d, length %d, id %d",
					offset, length, rpc->id);
			homa_check_nic_queue(rpc->hsk->homa, new_skb, true);
			__homa_xmit_data(new_skb, rpc, priority);
			INC_METRIC(resent_packets, 1);
		}
	}

resend_done:
}

/**
 * homa_outgoing_sysctl_changed() - Invoked whenever a sysctl value is changed;
 * any output-related parameters that depend on sysctl-settable values.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_outgoing_sysctl_changed(struct homa *homa)
{
	__u64 tmp;

	/* Code below is written carefully to avoid integer underflow or
	 * overflow under expected usage patterns. Be careful when changing!
	 */
	homa->cycles_per_kbyte = (8*(__u64) cpu_khz)/homa->link_mbps;
	homa->cycles_per_kbyte = (101*homa->cycles_per_kbyte)/100;
	tmp = homa->max_nic_queue_ns;
	tmp = (tmp*cpu_khz)/1000000;
	homa->max_nic_queue_cycles = tmp;
}

/**
 * homa_check_nic_queue() - This function is invoked before passing a packet
 * to the NIC for transmission. It serves two purposes. First, it maintains
 * an estimate of the NIC queue length. Second, it indicates to the caller
 * whether the NIC queue is so full that no new packets should be queued
 * (Homa's SRPT depends on keeping the NIC queue short).
 * @homa:     Overall data about the Homa protocol implementation.
 * @skb:      Packet that is about to be transmitted.
 * @force:    True means this packet is going to be transmitted
 *            regardless of the queue length.
 * Return:    Nonzero is returned if either the NIC queue length is
 *            acceptably short or @force was specified. 0 means that the
 *            NIC queue is at capacity or beyond, so the caller should delay
 *            the transmission of @skb. If nonzero is returned, then the
 *            queue estimate is updated to reflect the transmission of @skb.
 */
int homa_check_nic_queue(struct homa *homa, struct sk_buff *skb, bool force)
{
	__u64 idle, new_idle, clock;
	int cycles_for_packet, bytes;

	bytes = homa_get_skb_info(skb)->wire_bytes;
	cycles_for_packet = (bytes * homa->cycles_per_kbyte)/1000;
	while (1) {
		clock = get_cycles();
		idle = atomic64_read(&homa->link_idle_time);
		if (((clock + homa->max_nic_queue_cycles) < idle) && !force
				&& !(homa->flags & HOMA_FLAG_DONT_THROTTLE))
			return 0;
		if (!list_empty(&homa->throttled_rpcs))
			INC_METRIC(pacer_bytes, bytes);
		if (idle < clock) {
			if (homa->pacer_wake_time) {
				__u64 lost = (homa->pacer_wake_time > idle)
						? clock - homa->pacer_wake_time
						: clock - idle;
				INC_METRIC(pacer_lost_cycles, lost);
				tt_record1("pacer lost %d cycles", lost);
			}
			new_idle = clock + cycles_for_packet;
		} else
			new_idle = idle + cycles_for_packet;

		/* This method must be thread-safe. */
		if (atomic64_cmpxchg_relaxed(&homa->link_idle_time, idle,
				new_idle) == idle)
			break;
	}
	return 1;
}

/**
 * homa_pacer_main() - Top-level function for the pacer thread.
 * @transportInfo:  Pointer to struct homa.
 *
 * Return:         Always 0.
 */
int homa_pacer_main(void *transportInfo)
{
	struct homa *homa = (struct homa *) transportInfo;

	homa->pacer_wake_time = get_cycles();
	while (1) {
		if (homa->pacer_exit) {
			homa->pacer_wake_time = 0;
			break;
		}
		homa_pacer_xmit(homa);

		/* Sleep this thread if the throttled list is empty. Even
		 * if the throttled list isn't empty, call the scheduler
		 * to give other processes a chance to run (if we don't,
		 * softirq handlers can get locked out, which prevents
		 * incoming packets from being handled).
		 */
		set_current_state(TASK_INTERRUPTIBLE);
		if (list_first_or_null_rcu(&homa->throttled_rpcs,
				struct homa_rpc, throttled_links) == NULL)
			tt_record("pacer sleeping");
		else
			__set_current_state(TASK_RUNNING);
		INC_METRIC(pacer_cycles, get_cycles() - homa->pacer_wake_time);
		homa->pacer_wake_time = 0;
		schedule();
		homa->pacer_wake_time = get_cycles();
		__set_current_state(TASK_RUNNING);
	}
	kthread_complete_and_exit(&homa_pacer_kthread_done, 0);
	return 0;
}

/**
 * homa_pacer_xmit() - Transmit packets from  the throttled list. Note:
 * this function may be invoked from either process context or softirq (BH)
 * level. This function is invoked from multiple places, not just in the
 * pacer thread. The reason for this is that (as of 10/2019) Linux's scheduling
 * of the pacer thread is unpredictable: the thread may block for long periods
 * of time (e.g., because it is assigned to the same CPU as a busy interrupt
 * handler). This can result in poor utilization of the network link. So,
 * this method gets invoked from other places as well, to increase the
 * likelihood that we keep the link busy. Those other invocations are not
 * guaranteed to happen, so the pacer thread provides a backstop.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_pacer_xmit(struct homa *homa)
{
	struct homa_rpc *rpc;
        int i;

	/* Make sure only one instance of this function executes at a
	 * time.
	 */
	if (!spin_trylock_bh(&homa->pacer_mutex))
		return;

	/* Each iteration through the following loop sends one packet. We
	 * limit the number of passes through this loop in order to cap the
	 * time spent in one call to this function (see note in
	 * homa_pacer_main about interfering with softirq handlers).
	 */
	for (i = 0; i < 5; i++) {
		__u64 idle_time, now;

		/* If the NIC queue is too long, wait until it gets shorter. */
		now = get_cycles();
		idle_time = atomic64_read(&homa->link_idle_time);
		while ((now + homa->max_nic_queue_cycles) < idle_time) {
			/* If we've xmitted at least one packet then
			 * return (this helps with testing and also
			 * allows homa_pacer_main to yield the core).
			 */
			if (i != 0)
				goto done;
			now = get_cycles();
		}
		/* Note: when we get here, it's possible that the NIC queue is
		 * still too long because other threads have queued packets,
		 * but we transmit anyway so we don't starve (see perf.text
		 * for more info).
		 */

		/* Lock the first throttled RPC. This may not be possible
		 * because we have to hold throttle_lock while locking
		 * the RPC; that means we can't wait for the RPC lock because
		 * of lock ordering constraints (see sync.txt). Thus, if
		 * the RPC lock isn't available, do nothing. Holding the
		 * throttle lock while locking the RPC is important because
		 * it keeps the RPC from being deleted before it can be locked.
		 */
		homa_throttle_lock(homa);
		homa->pacer_fifo_count -= homa->pacer_fifo_fraction;
		if (homa->pacer_fifo_count <= 0) {
			__u64 oldest = ~0;
			struct homa_rpc *cur;

			homa->pacer_fifo_count += 1000;
			rpc = NULL;
			list_for_each_entry_rcu(cur, &homa->throttled_rpcs,
					throttled_links) {
				if (cur->msgout.init_cycles < oldest) {
					rpc = cur;
					oldest = cur->msgout.init_cycles;
				}
			}
		} else
			rpc = list_first_or_null_rcu(&homa->throttled_rpcs,
					struct homa_rpc, throttled_links);
		if (rpc == NULL) {
			homa_throttle_unlock(homa);
			break;
		}
		if (!homa_bucket_try_lock(rpc->bucket, rpc->id,
				"homa_pacer_xmit")) {
			homa_throttle_unlock(homa);
			INC_METRIC(pacer_skipped_rpcs, 1);
			break;
		}
		homa_throttle_unlock(homa);

		tt_record4("pacer calling homa_xmit_data for rpc id %llu, "
				"port %d, offset %d, bytes_left %d",
				rpc->id, rpc->hsk->port,
				rpc->msgout.next_xmit_offset,
				rpc->msgout.length - rpc->msgout.next_xmit_offset);
		homa_xmit_data(rpc, true);
		if (!*rpc->msgout.next_xmit || (rpc->msgout.next_xmit_offset
				>= rpc->msgout.granted)) {
			/* Nothing more to transmit from this message (right now),
			 * so remove it from the throttled list.
			 */
			homa_throttle_lock(homa);
			if (!list_empty(&rpc->throttled_links)) {
				tt_record2("pacer removing id %d from "
						"throttled list, offset %d",
						rpc->id,
						rpc->msgout.next_xmit_offset);
				list_del_rcu(&rpc->throttled_links);
				if (list_empty(&homa->throttled_rpcs))
					INC_METRIC(throttled_cycles, get_cycles()
							- homa->throttle_add);

				/* Note: this reinitialization is only safe
				 * because the pacer only looks at the first
				 * element of the list, rather than traversing
				 * it (and besides, we know the pacer isn't
				 * active concurrently, since this code *is*
				 * the pacer). It would not be safe under more
				 * general usage patterns.
				 */
				INIT_LIST_HEAD_RCU(&rpc->throttled_links);
			}
			homa_throttle_unlock(homa);
		}
		homa_rpc_unlock(rpc);
	}
    done:
	spin_unlock_bh(&homa->pacer_mutex);
}

/**
 * homa_pacer_stop() - Will cause the pacer thread to exit (waking it up
 * if necessary); doesn't return until after the pacer thread has exited.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_pacer_stop(struct homa *homa)
{
	homa->pacer_exit = true;
	wake_up_process(homa->pacer_kthread);
	kthread_stop(homa->pacer_kthread);
	homa->pacer_kthread = NULL;
}

/**
 * homa_add_to_throttled() - Make sure that an RPC is on the throttled list
 * and wake up the pacer thread if necessary.
 * @rpc:     RPC with outbound packets that have been granted but can't be
 *           sent because of NIC queue restrictions.
 */
void homa_add_to_throttled(struct homa_rpc *rpc)
{
	struct homa *homa = rpc->hsk->homa;
	struct homa_rpc *candidate;
	int bytes_left;
	int checks = 0;
	__u64 now;

	if (!list_empty(&rpc->throttled_links)) {
		return;
	}
	now = get_cycles();
	if (!list_empty(&homa->throttled_rpcs))
		INC_METRIC(throttled_cycles, now - homa->throttle_add);
	homa->throttle_add = now;
	bytes_left = rpc->msgout.length - rpc->msgout.next_xmit_offset;
	homa_throttle_lock(homa);
	list_for_each_entry_rcu(candidate, &homa->throttled_rpcs,
			throttled_links) {
		int bytes_left_cand;
		checks++;

		/* Watch out: the pacer might have just transmitted the last
		 * packet from candidate.
		 */
		bytes_left_cand = candidate->msgout.length -
				candidate->msgout.next_xmit_offset;
		if (bytes_left_cand > bytes_left) {
			list_add_tail_rcu(&rpc->throttled_links,
					&candidate->throttled_links);
			goto done;
		}
	}
	list_add_tail_rcu(&rpc->throttled_links, &homa->throttled_rpcs);
done:
	homa_throttle_unlock(homa);
	wake_up_process(homa->pacer_kthread);
	INC_METRIC(throttle_list_adds, 1);
	INC_METRIC(throttle_list_checks, checks);
//	tt_record("woke up pacer thread");
}

/**
 * homa_remove_from_throttled() - Make sure that an RPC is not on the
 * throttled list.
 * @rpc:     RPC of interest.
 */
void homa_remove_from_throttled(struct homa_rpc *rpc)
{
	if (unlikely(!list_empty(&rpc->throttled_links))) {
		UNIT_LOG("; ", "removing id %llu from throttled list", rpc->id);
		homa_throttle_lock(rpc->hsk->homa);
		list_del(&rpc->throttled_links);
		if (list_empty(&rpc->hsk->homa->throttled_rpcs))
			INC_METRIC(throttled_cycles, get_cycles()
					- rpc->hsk->homa->throttle_add);
		homa_throttle_unlock(rpc->hsk->homa);
		INIT_LIST_HEAD(&rpc->throttled_links);
	}
}

/**
 * homa_log_throttled() - Print information to the system log about the
 * RPCs on the throttled list.
 * @homa:   Overall information about the Homa transport.
 */
void homa_log_throttled(struct homa *homa)
{
	struct homa_rpc *rpc;
	int rpcs = 0;
	int64_t bytes = 0;

	printk(KERN_NOTICE "Printing throttled list\n");
	homa_throttle_lock(homa);
	list_for_each_entry_rcu(rpc, &homa->throttled_rpcs, throttled_links) {
		rpcs++;
		if (!homa_bucket_try_lock(rpc->bucket, rpc->id,
				"homa_log_throttled")) {
			printk(KERN_NOTICE "Skipping throttled RPC: locked\n");
			continue;
		}
		if (*rpc->msgout.next_xmit != NULL)
			bytes += rpc->msgout.length
					- rpc->msgout.next_xmit_offset;
		if (rpcs <= 20)
			homa_rpc_log(rpc);
		homa_rpc_unlock(rpc);
	}
	homa_throttle_unlock(homa);
	printk(KERN_NOTICE "Finished printing throttle list: %d rpcs, "
			"%lld bytes\n", rpcs, bytes);
}
