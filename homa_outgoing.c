/* Copyright (c) 2019-2022 Stanford University
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
	((struct inet_sock *) hsk)->tos =
			hsk->homa->priority_map[priority]<<5;
}

/**
 * homa_fill_packets() - Create one or more packets and fill them with
 * data from user space.
 * @hsk:       Socket via which these packets will be sent.
 * @peer:      Peer to which the packets will be sent (needed for things like
 *             the MTU).
 * @iter:      Describes the location(s) of message data in user space.
 *
 * Return:   Address of the first packet in a list of packets linked through
 *           homa_next_skb, or a negative errno if there was an error. No
 *           fields are set in the packet headers except for type, incoming,
 *           offset, and length information. homa_message_out_init will fill
 *           in the other fields.
 */
struct sk_buff *homa_fill_packets(struct homa_sock *hsk, struct homa_peer *peer,
		struct iov_iter *iter)
{
	/* Note: this function is separate from homa_message_out_init
	 * because it must be invoked without holding an RPC lock, and
	 * homa_message_out_init must sometimes be called with the lock
	 * held.
	 */
	int bytes_left, unsched;
	struct sk_buff *skb;
	struct sk_buff *first = NULL;
	int err, mtu, max_pkt_data, gso_size, max_gso_data;
	struct sk_buff **last_link;
	struct dst_entry *dst;
	size_t len = iter->count;

	if (unlikely((iter->count > HOMA_MAX_MESSAGE_LENGTH)
			|| (iter->count == 0))) {
		err = -EINVAL;
		goto error;
	}

	dst = homa_get_dst(peer, hsk);
	mtu = dst_mtu(dst);

	max_pkt_data = mtu - hsk->ip_header_length - sizeof(struct data_header);
	if (len <= max_pkt_data) {
		unsched = max_gso_data = len;
		gso_size = mtu;
	} else {
		int bufs_per_gso;

		gso_size = peer->dst->dev->gso_max_size;
		if (gso_size > hsk->homa->max_gso_size)
			gso_size = hsk->homa->max_gso_size;

		/* Round gso_size down to an even # of mtus. */
		bufs_per_gso = gso_size/mtu;
		if (bufs_per_gso == 0) {
			bufs_per_gso = 1;
			mtu = gso_size;
			max_pkt_data = mtu - hsk->ip_header_length
					- sizeof(struct data_header);
		}
		max_gso_data = bufs_per_gso * max_pkt_data;
		gso_size = bufs_per_gso * mtu;

		/* Round unscheduled bytes *up* to an even number of gsos. */
		unsched = hsk->homa->rtt_bytes + max_gso_data - 1;
		unsched -= unsched % max_gso_data;
		if (unsched > len)
			unsched = len;
	}

	/* Copy message data from user space and form sk_buffs. Each
	 * sk_buff may contain multiple data_segments, each of which will
	 * turn into a separate packet, using either TSO in the NIC or
	 * GSO in software.
	 */
	for (bytes_left = len, last_link = &first; bytes_left > 0; ) {
		struct data_header *h;
		struct data_segment *seg;
		int available;

		/* The sizeof32(void*) creates extra space for homa_next_skb. */
		skb = alloc_skb(gso_size + HOMA_SKB_EXTRA + sizeof32(void*),
				GFP_KERNEL);
		if (unlikely(!skb)) {
			err = -ENOMEM;
			goto error;
		}
		if (unlikely((bytes_left > max_pkt_data)
				&& (max_gso_data > max_pkt_data))) {
			skb_shinfo(skb)->gso_size = sizeof(struct data_segment)
					+ max_pkt_data;
			skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
		}
		skb_shinfo(skb)->gso_segs = 0;

		skb_reserve(skb, hsk->ip_header_length + HOMA_SKB_EXTRA);
		skb_reset_transport_header(skb);
		h = (struct data_header *) skb_put(skb,
				sizeof(*h) - sizeof(struct data_segment));
		h->common.type = DATA;
		h->message_length = htonl(len);
		available = max_gso_data;

		/* Each iteration of the following loop adds one segment
		 * to the buffer.
		 */
		do {
			int seg_size;
			seg = (struct data_segment *) skb_put(skb, sizeof(*seg));
			seg->offset = htonl(len - bytes_left);
			if (bytes_left <= max_pkt_data)
				seg_size = bytes_left;
			else
				seg_size = max_pkt_data;
			seg->segment_length = htonl(seg_size);
			seg->ack.client_id = 0;
			homa_peer_get_acks(peer, 1, &seg->ack);
			if (copy_from_iter(skb_put(skb, seg_size), seg_size,
					iter) != seg_size) {
				err = -EFAULT;
				kfree_skb(skb);
				goto error;
			}
			bytes_left -= seg_size;
			(skb_shinfo(skb)->gso_segs)++;
			available -= seg_size;
		} while ((available > 0) && (bytes_left > 0));
		h->incoming = htonl(((len - bytes_left) > unsched) ?
				(len - bytes_left) : unsched);
		*last_link = skb;
		last_link = homa_next_skb(skb);
		*last_link = NULL;
	}
	return first;

    error:
	homa_free_skbs(first);
	return ERR_PTR(err);
}

/**
 * homa_message_out_init() - Initializes an RPC's msgout. Doesn't actually
 * send any packets.
 * @rpc:     RPC whose msgout is to be initialized; current contents of
 *           msgout are assumed to be garbage.
 * @sport:   Source port number to use for the message.
 * @skb:     First in a list of packets returned by homa_fill_packets
 * @len:     Total length of the message.
 */
void homa_message_out_init(struct homa_rpc *rpc, int sport, struct sk_buff *skb,
		int len)
{
	rpc->msgout.length = len;
	rpc->msgout.packets = skb;
	rpc->msgout.num_skbs = 0;
	rpc->msgout.next_packet = skb;
	rpc->msgout.unscheduled = rpc->hsk->homa->rtt_bytes;
	rpc->msgout.granted = rpc->msgout.unscheduled;
	if (rpc->msgout.granted > rpc->msgout.length)
		rpc->msgout.granted = rpc->msgout.length;
	rpc->msgout.sched_priority = 0;
	rpc->msgout.init_cycles = get_cycles();

	/* Must scan the packets to fill in header fields that weren't
	 * known when the packets were allocated.
	 */
	while (skb) {
		struct data_header *h = (struct data_header *)
				skb_transport_header(skb);
		rpc->msgout.num_skbs++;
		h->common.sport = htons(sport);
		h->common.dport = htons(rpc->dport);
		homa_set_doff(h);
		h->common.sender_id = cpu_to_be64(rpc->id);
		h->message_length = htonl(len);
		h->cutoff_version = rpc->peer->cutoff_version;
		h->retransmit = 0;
		skb = *homa_next_skb(skb);
	}
	INC_METRIC(sent_msg_bytes, len);
}

/**
 * homa_message_out_destroy() - Destructor for homa_message_out.
 * @msgout:       Structure to clean up.
 */
void homa_message_out_destroy(struct homa_message_out *msgout)
{
	struct sk_buff *skb, *next;
	if (msgout->length < 0)
		return;
	for (skb = msgout->packets; skb !=  NULL; skb = next) {
		next = *homa_next_skb(skb);
		kfree_skb(skb);
	}
	msgout->packets = NULL;
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
	skb = alloc_skb(dst_mtu(dst) + HOMA_SKB_EXTRA + sizeof32(void*),
			GFP_KERNEL);
	if (unlikely(!skb))
		return -ENOBUFS;
	dst_hold(dst);
	skb_dst_set(skb, dst);

	skb_reserve(skb, hsk->ip_header_length + HOMA_SKB_EXTRA);
	skb_reset_transport_header(skb);
	h = (struct common_header *) skb_put(skb, length);
	memcpy(h, contents, length);
	extra_bytes = HOMA_MIN_PKT_LENGTH - length;
	if (extra_bytes > 0) {
		memset(skb_put(skb, extra_bytes), 0, extra_bytes);
		UNIT_LOG(",", "padded control packet with %d bytes",
				extra_bytes);
	}
	priority = hsk->homa->num_priorities-1;
	set_priority(skb, hsk, priority);
	skb->ooo_okay = 1;
	skb_get(skb);
	if (hsk->inet.sk.sk_family == AF_INET6) {
		result = ip6_xmit(&hsk->inet.sk, skb, &peer->flow.u.ip6, 0,
				NULL, 0, priority);
	} else {
		result = ip_queue_xmit(&hsk->inet.sk, skb, &peer->flow);
	}
	if (unlikely(result != 0)) {
		INC_METRIC(control_xmit_errors, 1);

		/* It appears that ip*_xmit frees skbuffs after
		 * errors; the following code is to raise an alert if
		 * this isn't actually the case. The extra skb_get above
		 * and kfree_skb below are needed to do the check
		 * accurately (otherwise the buffer could be freed and
		 * its memory used for some other purpose, resulting in
		 * a bogus "reference count").
		 */
		if (refcount_read(&skb->users) > 1) {
			if (hsk->inet.sk.sk_family == AF_INET6) {
				printk(KERN_NOTICE "ip6_xmit didn't free "
						"Homa control packet after "
						"error\n");
			} else {
				printk(KERN_NOTICE "ip_queue_xmit didn't free "
						"Homa  control packet after "
						"error\n");
			}
		}
	}
	kfree_skb(skb);
	INC_METRIC(packets_sent[h->type - DATA], 1);
	INC_METRIC(priority_bytes[priority], skb->len);
	INC_METRIC(priority_packets[priority], 1);
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
 *             caller.
 * @force:     True means send at least one packet, even if the NIC queue
 *             is too long. False means that zero packets may be sent, if
 *             the NIC queue is sufficiently long.
 */
void homa_xmit_data(struct homa_rpc *rpc, bool force)
{
	while (rpc->msgout.next_packet) {
		int priority;
		struct sk_buff *skb = rpc->msgout.next_packet;
		struct homa *homa = rpc->hsk->homa;
		int offset = homa_data_offset(skb);

		if (homa == NULL) {
			printk(KERN_ERR "NULL homa pointer in homa_xmit_"
				"data, state %d, shutdown %d, id %llu, socket %d",
				rpc->state, rpc->hsk->shutdown, rpc->id,
				rpc->hsk->port);
			BUG();
		}

		if (offset >= rpc->msgout.granted) {
			tt_record3("homa_xmit_data stopping at offset %d "
					"for id %u: granted is %d",
					offset, rpc->id, rpc->msgout.granted);
			break;
		}

		if ((rpc->msgout.length - offset) >= homa->throttle_min_bytes) {
			if (!homa_check_nic_queue(homa, skb, force)) {
				tt_record1("homa_xmit_data adding id %u to "
						"throttle queue", rpc->id);
				homa_add_to_throttled(rpc);
				break;
			}
		}

		if (offset < rpc->msgout.unscheduled) {
			priority = homa_unsched_priority(homa, rpc->peer,
					rpc->msgout.length);
		} else {
			priority = rpc->msgout.sched_priority;
		}
		rpc->msgout.next_packet = *homa_next_skb(skb);

		skb_get(skb);
		__homa_xmit_data(skb, rpc, priority);
		force = false;
	}
	tt_record("homa_xmit_data returning");
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
	struct data_header *h = (struct data_header *)
			skb_transport_header(skb);
	struct dst_entry *dst;

	set_priority(skb, rpc->hsk, priority);

	/* Update info that may have changed since the message was initially
	 * created.
	 */
	h->cutoff_version = rpc->peer->cutoff_version;

	dst = homa_get_dst(rpc->peer, rpc->hsk);
	dst_hold(dst);
	skb_dst_set(skb, dst);

	skb->ooo_okay = 1;
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct common_header, checksum);
	if (rpc->hsk->inet.sk.sk_family == AF_INET6) {
		tt_record4("calling ip6_xmit: skb->len %d, peer 0x%x, id %d, "
				"offset %d",
				skb->len, tt_addr(rpc->peer->addr), rpc->id,
				ntohl(h->seg.offset));

		err = ip6_xmit(&rpc->hsk->inet.sk, skb, &rpc->peer->flow.u.ip6,
				0, NULL, 0, priority);
	} else {
		tt_record4("calling ip_queue_xmit: skb->len %d, peer 0x%x, "
				"id %d, offset %d",
				skb->len, tt_addr(rpc->peer->addr), rpc->id,
				htonl(h->seg.offset));

		err = ip_queue_xmit(&rpc->hsk->inet.sk, skb, &rpc->peer->flow);
	}
	tt_record4("Finished queueing packet: rpc id %llu, offset %d, len %d, "
			"granted %d",
			rpc->id, ntohl(h->seg.offset), skb->len,
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
 * requests. It retransmits the packets containing a given range of bytes
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

	if (end <= start)
		return;

	/* The nested loop below scans each data_segment in each
	 * packet, looking for those that overlap the range of
	 * interest.
	 */
	for (skb = rpc->msgout.packets; skb !=  NULL; skb = *homa_next_skb(skb)) {
		int seg_offset = (skb_transport_header(skb) - skb->head)
				+ sizeof32(struct data_header)
				- sizeof32(struct data_segment);
		int offset, length, count;
		struct data_segment *seg;
		struct data_header *h;

		count = skb_shinfo(skb)->gso_segs;
		if (count < 1)
			count = 1;
		for ( ; count > 0; count--,
				seg_offset += sizeof32(*seg) + length) {
			struct sk_buff *new_skb;
			seg = (struct data_segment *) (skb->head + seg_offset);
			offset = ntohl(seg->offset);
			length = ntohl(seg->segment_length);

			if (end <= offset)
				return;
			if ((offset + length) <= start)
				continue;

			/* This segment must be retransmitted. Copy it into
			 * a clean sk_buff.
			 */
			new_skb = alloc_skb(length + sizeof(struct data_header)
					+ rpc->hsk->ip_header_length
					+ HOMA_SKB_EXTRA, GFP_KERNEL);
			if (unlikely(!new_skb)) {
				if (rpc->hsk->homa->verbose)
					printk(KERN_NOTICE "homa_resend_data "
						"couldn't allocate skb\n");
				continue;
			}
			skb_reserve(new_skb, rpc->hsk->ip_header_length
				+ HOMA_SKB_EXTRA);
			skb_reset_transport_header(new_skb);
			__skb_put_data(new_skb, skb_transport_header(skb),
					sizeof32(struct data_header)
					- sizeof32(struct data_segment));
			__skb_put_data(new_skb, seg, sizeof32(*seg) + length);
			h = ((struct data_header *) skb_transport_header(new_skb));
			h->retransmit = 1;
			if ((offset + length) <= rpc->msgout.granted)
				h->incoming = htonl(rpc->msgout.granted);
			else if ((offset + length) > rpc->msgout.length)
				h->incoming = htonl(rpc->msgout.length);
			else
				h->incoming = htonl(offset + length);
			tt_record3("retransmitting offset %d, length %d, id %d",
					offset, length, rpc->id);
			homa_check_nic_queue(rpc->hsk->homa, new_skb, true);
			__homa_xmit_data(new_skb, rpc, priority);
			INC_METRIC(resent_packets, 1);
		}
	}
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
	int cycles_for_packet, segs, bytes;

	segs = skb_shinfo(skb)->gso_segs;
	bytes = skb->tail - skb->transport_header;
	bytes += HOMA_IPV6_HEADER_LENGTH + HOMA_ETH_OVERHEAD;
	if (segs > 0)
		bytes += (segs - 1) * (sizeof32(struct data_header)
				- sizeof32(struct data_segment)
				+ HOMA_IPV6_HEADER_LENGTH + HOMA_ETH_OVERHEAD);
	cycles_for_packet = (bytes*homa->cycles_per_kbyte)/1000;
	while (1) {
		clock = get_cycles();
		idle = atomic64_read(&homa->link_idle_time);
		if (((clock + homa->max_nic_queue_cycles) < idle) && !force
				&& !(homa->flags & HOMA_FLAG_DONT_THROTTLE))
			return 0;
		if (!list_empty(&homa->throttled_rpcs))
			INC_METRIC(pacer_bytes, bytes);
		if (idle < clock) {
			if (!list_empty(&homa->throttled_rpcs)) {
				INC_METRIC(pacer_lost_cycles, clock - idle);
				tt_record1("pacer lost %d cycles",
						clock - idle);
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
	cycles_t start;
	struct homa *homa = (struct homa *) transportInfo;

	while (1) {
		if (homa->pacer_exit) {
			break;
		}

		start = get_cycles();
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
		INC_METRIC(pacer_cycles, get_cycles() - start);
		schedule();
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
		int offset;

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
		if (!(spin_trylock_bh(rpc->lock))) {
			homa_throttle_unlock(homa);
			INC_METRIC(pacer_skipped_rpcs, 1);
			break;
		}
		homa_throttle_unlock(homa);

		offset = homa_rpc_send_offset(rpc);
		tt_record4("pacer calling homa_xmit_data for rpc id %llu, "
				"port %d, offset %d, bytes_left %d",
				rpc->id, rpc->hsk->port, offset,
				rpc->msgout.length - offset);
		homa_xmit_data(rpc, true);
		if (!rpc->msgout.next_packet
				|| (homa_data_offset(rpc->msgout.next_packet)
				>= rpc->msgout.granted)) {
			/* Nothing more to transmit from this message (right now),
			 * so remove it from the throttled list.
			 */
			homa_throttle_lock(homa);
			if (!list_empty(&rpc->throttled_links)) {
				tt_record2("pacer removing id %d from "
						"throttled list, offset %d",
						rpc->id, offset);
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
	bytes_left = rpc->msgout.length - homa_data_offset(
			rpc->msgout.next_packet);
	homa_throttle_lock(homa);
	list_for_each_entry_rcu(candidate, &homa->throttled_rpcs,
			throttled_links) {
		int bytes_left_cand;
		checks++;

		/* Watch out: the pacer might have just transmitted the last
		 * packet from candidate.
		 */
		bytes_left_cand = candidate->msgout.length -
				homa_rpc_send_offset(candidate);
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
		if (!(spin_trylock_bh(rpc->lock))) {
			printk(KERN_NOTICE "Skipping throttled RPC: locked\n");
			continue;
		}
		if (rpc->msgout.next_packet != NULL)
			bytes += rpc->msgout.length - homa_rpc_send_offset(rpc);
		if (rpcs <= 20)
			homa_rpc_log(rpc);
		homa_rpc_unlock(rpc);
	}
	homa_throttle_unlock(homa);
	printk(KERN_NOTICE "Finished printing throttle list: %d rpcs, "
			"%lld bytes\n", rpcs, bytes);
}
