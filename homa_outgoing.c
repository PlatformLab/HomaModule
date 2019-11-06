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

/* This file contains functions related to the sender side of message
 * transmission. It also contains utility functions for sending packets.
 */

#include "homa_impl.h"

/**
 * set_priority() - Arrange for a packet to have a VLAN header that
 * specifies a priority for the packet.
 * @skb:        The packet was priority should be set.
 * @priority:   Priority level for the packet, in the range 0 (for lowest
 *              priority) to 7 ( for highest priority).
 */
inline static void set_priority(struct sk_buff *skb, int priority)
{
	/* The priority values stored in the VLAN header are weird, in that
	 * the value 0 is not the lowest priority; this table maps from
	 * "sensible" values as provided by the @priority argument to the
	 * corresponding value for the VLAN header. See the IEEE P802.1
	 * standard for details.
	 */
	static int tci[] = {
		(1 << VLAN_PRIO_SHIFT) | VLAN_TAG_PRESENT,
		(0 << VLAN_PRIO_SHIFT) | VLAN_TAG_PRESENT,
		(2 << VLAN_PRIO_SHIFT) | VLAN_TAG_PRESENT,
		(3 << VLAN_PRIO_SHIFT) | VLAN_TAG_PRESENT,
		(4 << VLAN_PRIO_SHIFT) | VLAN_TAG_PRESENT,
		(5 << VLAN_PRIO_SHIFT) | VLAN_TAG_PRESENT,
		(6 << VLAN_PRIO_SHIFT) | VLAN_TAG_PRESENT,
		(7 << VLAN_PRIO_SHIFT) | VLAN_TAG_PRESENT
	};
#ifndef __UNIT_TEST__
	return;
#endif
#if 0
	static int count = 0;
	static int prio = 4;
	count++;
	if ((count & 7) == 0) {
		/* Change priority levels every eighth packet. */
		prio ^= 1;
		tt_record1("Changed priority to %d", prio);
	}
	priority = prio;
#endif
	skb->vlan_proto = htons(0x8100);
	skb->vlan_tci = tci[priority];
}

/**
 * homa_message_out_init() - Initializes an RPC's msgout, loads packet data
 * from a user-space buffer. Doesn't actually send any packets.
 * @rpc:     RPC whose msgout is to be initialized; current contents are
 *           assumed to be garbage.
 * @sport:   Source port number to use for the message.
 * @len:     Total length of the message.
 * @iter:    Info about the request buffer in user space.
 * 
 * Return:   Either 0 (for success) or a negative errno value.
 */
int homa_message_out_init(struct homa_rpc *rpc, int sport, size_t len,
		struct iov_iter *iter)
{
	int bytes_left;
	struct sk_buff *skb;
	int err, mtu, max_pkt_data, gso_max;
	struct sk_buff **last_link;
	
	rpc->msgout.length = len;
	rpc->msgout.packets = NULL;
	rpc->msgout.next_packet = NULL;
	rpc->msgout.unscheduled = rpc->hsk->homa->rtt_bytes;
	rpc->msgout.granted = rpc->msgout.unscheduled;
	if (rpc->msgout.granted > rpc->msgout.length)
		rpc->msgout.granted = rpc->msgout.length;
	rpc->msgout.sched_priority = 0;
	
	/* Do the check here so the struct is cleanly initialized after
	 * an error.
	 */
	if (unlikely(len > HOMA_MAX_MESSAGE_LENGTH)) {
		err = -EINVAL;
		goto error;
	}
	
	mtu = dst_mtu(rpc->peer->dst);
	max_pkt_data = mtu - HOMA_IPV4_HEADER_LENGTH - sizeof(struct data_header);
	gso_max = rpc->peer->dst->dev->gso_max_size;
	if (gso_max > rpc->hsk->homa->max_gso_size)
		gso_max = rpc->hsk->homa->max_gso_size;
	
	/* Copy message data from user space and form sk_buffs. Each
	 * sk_buff may contain multiple data_segments, each of which will
	 * turn into a separate packet, using either TSO in the NIC or
	 * GSO in software.
	 */
	for (bytes_left = len, last_link = &rpc->msgout.packets;
			bytes_left > 0; ) {
		struct data_header *h;
		struct data_segment *seg;
		int skb_size, available, last_pkt_length;
		
		if (likely(bytes_left <= max_pkt_data))
			skb_size = mtu + HOMA_SKB_EXTRA;
		else
			skb_size = gso_max + HOMA_SKB_EXTRA;
		
		/* The sizeof32(void*) creates extra space for homa_next_skb. */
		skb = alloc_skb(skb_size + sizeof32(void*), GFP_KERNEL);
		if (unlikely(!skb)) {
			err = -ENOMEM;
			goto error;
		}
		if (unlikely(bytes_left > max_pkt_data)) {
			skb_shinfo(skb)->gso_size = sizeof(struct data_segment)
					+ max_pkt_data;
			skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
		}
		skb_shinfo(skb)->gso_segs = 0;
			
		skb_reserve(skb, HOMA_IPV4_HEADER_LENGTH + HOMA_SKB_EXTRA);
		skb_reset_transport_header(skb);
		h = (struct data_header *) skb_put(skb,
				sizeof(*h) - sizeof(struct data_segment));
		h->common.sport = htons(sport);
		h->common.dport = htons(rpc->dport);
		homa_set_doff(h);
		h->common.type = DATA;
		h->common.id = rpc->id;
		h->message_length = htonl(rpc->msgout.length);
		h->incoming = htonl(rpc->msgout.unscheduled);
		h->cutoff_version = rpc->peer->cutoff_version;
		h->retransmit = 0;
		available = skb_size - HOMA_IPV4_HEADER_LENGTH - HOMA_SKB_EXTRA
			- (sizeof(*h) - sizeof(struct data_segment));
		
		/* Each iteration of the following loop adds one segment
		 * to the buffer.
		 */
		do {
			int seg_size;
			seg = (struct data_segment *) skb_put(skb, sizeof(*seg));
			seg->offset = htonl(rpc->msgout.length - bytes_left);
			if (bytes_left <= max_pkt_data)
				seg_size = bytes_left;
			else
				seg_size = max_pkt_data;
			seg->segment_length = htonl(seg_size);
			err = skb_add_data_nocache((struct sock *) rpc->hsk,
					skb, iter, seg_size);
			if (unlikely(err != 0)) {
				kfree_skb(skb);
				goto error;
			}
			bytes_left -= seg_size;
			(skb_shinfo(skb)->gso_segs)++;
			available -= sizeof32(*seg) + seg_size;
		} while ((bytes_left > 0) && (((available - sizeof32(*seg))
				>= max_pkt_data)
				|| (available - sizeof32(*seg))
				>= bytes_left));
		if ((rpc->msgout.length - bytes_left) > rpc->msgout.unscheduled)
			h->incoming = htonl(rpc->msgout.length - bytes_left);
		
		/* Make sure that the last segment won't result in a
		 * packet that's too small.
		 */
		last_pkt_length = htonl(seg->segment_length) + sizeof32(*h);
		if (unlikely(last_pkt_length < HOMA_MAX_HEADER))
			skb_put(skb, HOMA_MAX_HEADER - last_pkt_length);
		*last_link = skb;
		last_link = homa_next_skb(skb);
		*last_link = NULL;
		if (!rpc->msgout.next_packet)
			rpc->msgout.next_packet = skb;
		rpc->num_skbuffs++;
	}
//	tt_record1("Output message initialized for id %u", rpc->id & 0xffffffff);
	return 0;
	
    error:
	homa_message_out_destroy(&rpc->msgout);
	return err;
}

/**
 * homa_message_out_reset() - Reset a homa_message_out to its initial state,
 * as if no packets had been sent. Data for the message is preserved.
 * @rpc:    RPC whose msgout must be reset. Must be a client RPC that was
 *          successfully initialized in the past, and some packets may have
 *          been transmitted since then.
 * 
 * Return:  Zero for success, or a negative error status.
 */
int homa_message_out_reset(struct homa_rpc *rpc)
{
	struct sk_buff *skb, *next;
	struct sk_buff **last_link;
	int err = 0;
	struct homa_message_out *msgout = &rpc->msgout;
	struct data_header *h;
	
	/* Copy all of the sk_buffs in the message. This is necessary because
	 * some of the sk_buffs may already have been transmitted once;
	 * retransmitting these is risky, because the underlying stack
	 * layers make modifications that aren't idempotent (such as adding
	 * additional headers).
	 */
	last_link = &msgout->packets;
	for (skb = msgout->packets; skb != NULL; skb = next) {
		struct sk_buff *new_skb;
		int length = skb_tail_pointer(skb) - skb_transport_header(skb);
		new_skb = alloc_skb(length + HOMA_IPV4_HEADER_LENGTH
				+ HOMA_SKB_EXTRA, GFP_KERNEL);
		if (unlikely(!new_skb)) {
			err = -ENOMEM;
			if (rpc->hsk->homa->verbose)
				printk(KERN_NOTICE "homa_message_out_reset "
					"couldn't allocate new skb");
		} else {
			skb_reserve(new_skb, HOMA_IPV4_HEADER_LENGTH
				+ HOMA_SKB_EXTRA);
			skb_reset_transport_header(new_skb);
			__skb_put_data(new_skb, skb_transport_header(skb),
					length);
			skb_shinfo(new_skb)->gso_size =
					skb_shinfo(skb)->gso_size;
			skb_shinfo(new_skb)->gso_segs =
					skb_shinfo(skb)->gso_segs;
			skb_shinfo(new_skb)->gso_type =
					skb_shinfo(skb)->gso_type;
			h = ((struct data_header *)
					skb_transport_header(new_skb));
			h->retransmit = 0;
			*last_link = new_skb;
			last_link = homa_next_skb(new_skb);
		}
		next = *homa_next_skb(skb);
		kfree_skb(skb);
	}
	*last_link = NULL;
	
	msgout->next_packet = msgout->packets;
	msgout->granted = msgout->unscheduled;
	if (msgout->granted > msgout->length)
		msgout->granted = msgout->length;
	
	return err;
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
 * homa_set_priority() - Arrange for a packet to have a VLAN header that
 * specifies a priority for the packet.
 * @skb:        The packet was priority should be set.
 * @priority:   Priority level for the packet, in the range 0 (for lowest
 *              priority) to 7 ( for highest priority).
 */
void homa_set_priority(struct sk_buff *skb, int priority)
{
	set_priority(skb, priority);
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
	if (rpc->is_client) {
		h->sport = htons(rpc->hsk->client_port);
	} else {
		h->sport = htons(rpc->hsk->server_port);
	}
	h->dport = htons(rpc->dport);
	h->id = rpc->id;
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
	int result;
	
	/* Allocate the same size sk_buffs as for the smallest data
         * packets (better reuse of sk_buffs?).
	 */
	struct sk_buff *skb = alloc_skb(dst_mtu(peer->dst) + HOMA_SKB_EXTRA
			+ sizeof32(void*), GFP_KERNEL);
	if (unlikely(!skb))
		return -ENOBUFS;
	skb_reserve(skb, HOMA_IPV4_HEADER_LENGTH + HOMA_SKB_EXTRA);
	skb_reset_transport_header(skb);
	h = (struct common_header *) skb_put(skb, length);
	memcpy(h, contents, length);
	extra_bytes = HOMA_MAX_HEADER - length;
	if (extra_bytes > 0)
		memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	set_priority(skb, hsk->homa->max_prio);
	dst_hold(peer->dst);
	skb_dst_set(skb, peer->dst);
	skb_get(skb);
	result = ip_queue_xmit((struct sock *) hsk, skb, &peer->flow);
	if (unlikely(result != 0)) {
		INC_METRIC(control_xmit_errors, 1);
		
		/* It appears that ip_queue_xmit frees skbuffs after
		 * errors; the following code is to raise an alert if
		 * this isn't actually the case. The extra skb_get above
		 * and kfree_skb below are needed to do the check
		 * accurately (otherwise the buffer could be freed and
		 * its memory used for some other purpose, resulting in
		 * a bogus "reference count").
		 */
		if (refcount_read(&skb->users) > 1)
			printk(KERN_NOTICE "ip_queue_xmit didn't free "
					"Homa control packet after error\n");
	}
	kfree_skb(skb);
	INC_METRIC(packets_sent[h->type - DATA], 1);
	return result;
}

/**
 * homa_xmit_data() - If an RPC has outbound data packets that are permitted
 * to be transmitted according to the scheduling mechanism, arrange for
 * them to be sent (some may be sent immediately; others may be sent
 * later by the pacer thread).
 * @rpc:       RPC to check for transmittable packets.
 * @pacer:     True means we were invoked from the pacer, which changes the
 *             behavior a bit.
 */
void homa_xmit_data(struct homa_rpc *rpc, bool pacer)
{
	while (rpc->msgout.next_packet) {
		int priority;
		struct sk_buff *skb = rpc->msgout.next_packet;
		struct homa *homa = rpc->hsk->homa;
		int offset = homa_data_offset(skb);
		
		if (offset >= rpc->msgout.granted)
			break;
		
		if ((rpc->msgout.length - offset) >= homa->throttle_min_bytes) {
			if (list_first_or_null_rcu(&homa->throttled_rpcs,
					struct homa_rpc, throttled_links)
					&& !pacer) {
				/* Since there are other throttled messages,
				 * add this one to the throttled list and
				 * let the pacer handle it. */
				homa_add_to_throttled(rpc);
				break;
			}
			if (!homa_check_nic_queue(homa, skb, false)) {
				if (!pacer)
					homa_add_to_throttled(rpc);
				break;
			}
		}
		
		if (offset < rpc->msgout.unscheduled) {
			priority = homa_unsched_priority(rpc->peer,
					rpc->msgout.length);
		} else {
			priority = rpc->msgout.sched_priority;
		}
		rpc->msgout.next_packet = *homa_next_skb(skb);
		
		skb_get(skb);
		__homa_xmit_data(skb, rpc, priority);
	}
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

	set_priority(skb, priority);

	/* Update cutoff_version in case it has changed since the
	 * message was initially created.
	 */
	h->cutoff_version = rpc->peer->cutoff_version;
	
	dst_hold(rpc->peer->dst);
	skb_dst_set(skb, rpc->peer->dst);
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct common_header, checksum);

	err = ip_queue_xmit((struct sock *) rpc->hsk, skb, &rpc->peer->flow);
//	tt_record4("Finished queueing packet: rpc id %llu, offset %d, len %d, "
//			"next_offset %d",
//			h->common.id, ntohl(h->seg.offset), skb->len,
//			rpc->msgout.next_offset);
	if (err) {
		INC_METRIC(data_xmit_errors, 1);
		
		/* It appears that ip_queue_xmit frees skbuffs after
		 * errors; the following code raises an alert if this
		 * isn't actually the case.
		 */
		if (refcount_read(&skb->users) > 1) {
			printk(KERN_NOTICE "ip_queue_xmit didn't free "
					"Homa data packet after error\n");
			kfree_skb(skb);
		}
	}
	INC_METRIC(packets_sent[0], 1);
}

/**
 * homa_resend_data() - This function is invoked as part of handling RESEND
 * requests. It retransmits the packets containing a given range of bytes
 * from a message.
 * @msgout:   Message containing the packets.
 * @start:    Offset within @msgout of the first byte to retransmit.
 * @end:      Offset within @msgout of the byte just after the last one
 *            to retransmit.
 * @sk:       Socket to use for transmission.
 * @peer:     Information about the destination.
 * @priority: Priority level to use for the retransmitted data packets.
 */
void homa_resend_data(struct homa_rpc *rpc, int start, int end,
		int priority)
{
	struct sk_buff *skb;
	
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
					+ HOMA_IPV4_HEADER_LENGTH
					+ HOMA_SKB_EXTRA, GFP_KERNEL);
			if (unlikely(!new_skb)) {
				if (rpc->hsk->homa->verbose)
					printk(KERN_NOTICE "homa_resend_data "
						"couldn't allocate skb\n");
				continue;
			}
			skb_reserve(new_skb, HOMA_IPV4_HEADER_LENGTH
				+ HOMA_SKB_EXTRA);
			skb_reset_transport_header(new_skb);
			__skb_put_data(new_skb, skb_transport_header(skb),
					sizeof32(struct data_header)
					- sizeof32(struct data_segment));
			__skb_put_data(new_skb, seg, sizeof32(*seg) + length);
			if (unlikely(new_skb->len < HOMA_MAX_HEADER))
					skb_put(new_skb, HOMA_MAX_HEADER
					- new_skb->len);
			h = ((struct data_header *) skb_transport_header(new_skb));
			h->retransmit = 1;
			if ((offset + length) > end)
				h->incoming = htonl(offset + length);
			else
				h->incoming = htonl(end);
			tt_record3("retransmitting offset %d, length %d, id %d",
					offset, length,
					h->common.id & 0xffffffff);
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
	homa->cycles_per_kbyte = (105*homa->cycles_per_kbyte)/100;
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
	bytes += HOMA_IPV4_HEADER_LENGTH + HOMA_VLAN_HEADER + HOMA_ETH_OVERHEAD;
	if (segs > 0)
		bytes += (segs - 1) * (sizeof32(struct data_header)
				- sizeof32(struct data_segment)
				+ HOMA_IPV4_HEADER_LENGTH + HOMA_VLAN_HEADER
				+ HOMA_ETH_OVERHEAD);
	cycles_for_packet = (bytes*homa->cycles_per_kbyte)/1000;
	while (1) {
		clock = get_cycles();
		idle = atomic64_read(&homa->link_idle_time);
		if (((clock + homa->max_nic_queue_cycles) < idle) && !force
				&& !(homa->flags & HOMA_FLAG_DONT_THROTTLE))
			return 0;
		if (idle < clock)
			new_idle = clock + cycles_for_packet;
		else
			new_idle = idle + cycles_for_packet;
		
		/* This method must be thread-safe. */
		if (atomic64_cmpxchg_relaxed(&homa->link_idle_time, idle,
				new_idle) == idle)
			break;
	}
	return 1;
}

/**
 * homa_pacer_thread() - Top-level function for the pacer thread.
 * @transportInfo:  Pointer to struct homa.
 *
 * Return:         Always 0.
 */
int homa_pacer_main(void *transportInfo)
{
	cycles_t start, now;
	struct homa *homa = (struct homa *) transportInfo;
	
	start = get_cycles();
	while (1) {
		if (homa->pacer_exit) {
			break;
		}
		
		/* Sleep this thread if the throttled list is empty. */
		set_current_state(TASK_INTERRUPTIBLE);
		if (list_first_or_null_rcu(&homa->throttled_rpcs,
				struct homa_rpc, throttled_links) == NULL) {
			tt_record("pacer sleeping");
			INC_METRIC(pacer_cycles, get_cycles() - start);
			schedule();
			start = get_cycles();
			tt_record("pacer woke up");
			continue;
		}
		__set_current_state(TASK_RUNNING);
		
		homa_pacer_xmit(homa);
		now = get_cycles();
		INC_METRIC(pacer_cycles, now - start);
		start = now;
	}
	do_exit(0);
	return 0;
}

/**
 * homa_pacer_xmit() - Transmit as many packets as possible from
 * the throttled list. Note: this function may be invoked from either
 * process context or softirq (BH) level. This function is invoked from
 * multiple places, not just in the pacer thread. The reason for this is
 * that (as of 10/2019) Linux's scheduling of the pacer thread is
 * unpredictable: the thread may block for long periods of time (e.g., because
 * it is assigned to the same CPU as a busy interrupt handler). This can
 * result in poor utilization of the network link. So, this method gets
 * invoked from other places as well, to increase the likelihood that we keep
 * the link busy. Those other invocations are not guaranteed to happen, so
 * the pacer thread provides a backstop.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_pacer_xmit(struct homa *homa)
{
	struct homa_rpc *rpc;
        int i;
	static __u64 gap_start = 0;
	
	/* Make sure only one instance of this function executes at a
	 * time.
	 */
	if (gap_start == 0)
		gap_start = get_cycles();
	local_bh_disable();
	if (atomic_cmpxchg(&homa->pacer_active, 0, 1) != 0)
		goto done;
	
	/* Each iteration through the following loop makes one attempt
	 * at sending packets. We limit the number of passes through this
	 * loop in order to cap the time that interrupts are disabled.
	 */
	for (i = 0; i < 5; i++) {
		__s64 backlog = (__s64) (atomic64_read(&homa->link_idle_time)
				- get_cycles());
		if (backlog > homa->max_nic_queue_cycles)
			break;
		
		/* Lock the first throttled RPC. This may not be possible
		 * because we have to hold throttle_lock while locking
		 * the RPC, but then we can't wait for the RPC lock because
		 * of lock ordering constraints (see sync.txt). Thus, if
		 * the RPC lock isn't available, do nothing.
		 */
		spin_lock_bh(&homa->throttle_lock);
		rpc = list_first_or_null_rcu(&homa->throttled_rpcs,
				struct homa_rpc, throttled_links);
		if ((rpc == NULL) || !(spin_trylock_bh(rpc->lock))) {
			spin_unlock_bh(&homa->throttle_lock);
			INC_METRIC(pacer_skipped_rpcs, 1);
			break;
		}
		spin_unlock_bh(&homa->throttle_lock);

		if (backlog < 0) {
			INC_METRIC(pacer_lost_cycles, -backlog);
			tt_record2("homa_pacer_xmit lost %d cycles (lockout %d)",
					-backlog, get_cycles() - gap_start);
		}
		tt_record2("pacer calling homa_xmit_data for rpc id %llu, "
				"port %d",
				rpc->id, rpc->is_client ? rpc->hsk->client_port
				: rpc->hsk->server_port);
		homa_xmit_data(rpc, true);
		if (!rpc->msgout.next_packet
				|| (homa_data_offset(rpc->msgout.next_packet)
				>= rpc->msgout.granted)) {
			/* Nothing more to transmit from this message (right now),
			 * so remove it from the throttled list.
			 */
			spin_lock_bh(&homa->throttle_lock);
			if (!list_empty(&rpc->throttled_links)) {
				list_del_rcu(&rpc->throttled_links);

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
			spin_unlock_bh(&homa->throttle_lock);
			if (!rpc->msgout.next_packet && !rpc->is_client) {
				homa_rpc_free(rpc);
			}
		}
		spin_unlock_bh(rpc->lock);
	}
	atomic_set(&homa->pacer_active, 0);
	
done:
	local_bh_enable();
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

	if (!list_empty(&rpc->throttled_links)) {
		return;
	}
	spin_lock_bh(&homa->throttle_lock);
	list_for_each_entry_rcu(candidate, &homa->throttled_rpcs,
			throttled_links) {
		int bytes_left, bytes_left_cand;
		bytes_left = rpc->msgout.length - homa_data_offset(
				rpc->msgout.next_packet);
		
		/* Watch out: the pacer might have just transmitted the last
		 * packet from candidate.
		 */
		if (!candidate->msgout.next_packet)
			bytes_left_cand = 0;
		else
			bytes_left_cand = candidate->msgout.length - homa_data_offset(
				candidate->msgout.next_packet);
		if (bytes_left_cand > bytes_left) {
			list_add_tail_rcu(&rpc->throttled_links,
					&candidate->throttled_links);
			goto done;
		}
	}
	list_add_tail_rcu(&rpc->throttled_links, &homa->throttled_rpcs);
done:
	spin_unlock_bh(&homa->throttle_lock);
	wake_up_process(homa->pacer_kthread);
//	tt_record("woke up pacer thread");
}