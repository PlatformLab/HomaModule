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
 * from a user-space buffer. Will also start sending packets, if requested
 * by @homa->pipeline_xmit.
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
	rpc->msgout.next_offset = 0;
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
		h->unscheduled = htonl(rpc->msgout.unscheduled);
		h->cutoff_version = rpc->peer->cutoff_version;
		h->retransmit = 0;
		available = skb_size - HOMA_IPV4_HEADER_LENGTH
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
		
		if (rpc->hsk->homa->pipeline_xmit)
			homa_xmit_data(rpc, false);
	}
	tt_record("Output message initialized");
	return 0;
	
    error:
	homa_message_out_destroy(&rpc->msgout);
	return err;
}

/**
 * homa_message_out_reset() - Reset a homa_message_out to its initial state,
 * as if no packets had been sent. Data for the message is preserved.
 * @msgout:    Struct to reset. Must have been successfully initialized in
 *             the past, and some packets may have been transmitted since
 *             then.
 */
void homa_message_out_reset(struct homa_message_out *msgout)
{
	struct sk_buff *skb;
	msgout->next_packet = msgout->packets;
	msgout->next_offset = 0;
	msgout->granted = msgout->unscheduled;
	if (msgout->granted > msgout->length)
		msgout->granted = msgout->length;
	for (skb = msgout->packets; skb !=  NULL; skb = *homa_next_skb(skb)) {
		struct data_header *h = (struct data_header *)
				skb_transport_header(skb);
		h->retransmit = 0;
	}
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
 * @use_pacer: True means that we should add this RPC to the throttled
 *             list if the NIC queue is too long for this packet right now.
 *             False means the caller will try to send the packet again later.
 */
void homa_xmit_data(struct homa_rpc *rpc, bool use_pacer)
{
	while ((rpc->msgout.next_offset < rpc->msgout.granted)
			&& rpc->msgout.next_packet) {
		int priority;
		struct sk_buff *skb = rpc->msgout.next_packet;
		struct homa *homa = rpc->hsk->homa;
	
		if (((rpc->msgout.length - rpc->msgout.next_offset)
				> homa->throttle_min_bytes)
				&& ((get_cycles() + homa->max_nic_queue_cycles)
				< atomic_long_read(&homa->link_idle_time))
				&& !(homa->flags & HOMA_FLAG_DONT_THROTTLE)) {
			if (use_pacer)
				homa_add_to_throttled(rpc);
			return;
		}
		
		rpc->msgout.next_packet = *homa_next_skb(skb);
		if (rpc->msgout.next_offset < rpc->msgout.unscheduled) {
			priority = homa_unsched_priority(rpc->peer,
					rpc->msgout.length);
		} else {
			priority = rpc->msgout.sched_priority;
		}
		rpc->msgout.next_offset += skb->len
				- sizeof32(struct data_header);
		
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
	tt_record4("Finished queueing packet: rpc id %llu, offset %d, len %d, "
			"next_offset %d",
			h->common.id, ntohl(h->seg.offset), skb->len,
			rpc->msgout.next_offset);
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
	homa_update_idle_time(rpc->hsk->homa,
			skb->tail - skb->transport_header);
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
				if (homa->verbose)
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
			tt_record3("retransmitting offset %d, length %d, id %d",
					offset, length,
					h->common.id & 0xffffffff);
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
 * homa_update_idle_time() - This function is invoked whenever a packet
 * is queued for transmission; it updates homa->link_idle_time to reflect
 * the new transmission.
 * @homa:    Overall data about the Homa protocol implementation.
 * @bytes:   Number of bytes in the packet that was just transmitted,
 *           not including IP or Ethernet headers.
 */
void homa_update_idle_time(struct homa *homa, int bytes)
{
	__u64 old_idle, new_idle, clock;
	int cycles_for_packet;
	
	bytes += HOMA_IPV4_HEADER_LENGTH + HOMA_VLAN_HEADER + HOMA_ETH_OVERHEAD;
	cycles_for_packet = (bytes*homa->cycles_per_kbyte)/1000;
	while (1) {
		clock = get_cycles();
		old_idle = atomic_long_read(&homa->link_idle_time);
		if (old_idle < clock)
			new_idle = clock + cycles_for_packet;
		else
			new_idle = old_idle + cycles_for_packet;
		if (atomic_long_cmpxchg_relaxed(&homa->link_idle_time, old_idle,
				new_idle) == old_idle)
			break;
	}
}

/**
 * homa_pacer_thread() - Top-level function for the pacer thread.
 * @transportInfo:  Pointer to struct homa.
 * @return:         Always 0.
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
			tt_record1("pacer woke up on core %d",
					smp_processor_id());
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
 * homa_pacer_xmit() - Wait until we can send at least one packet from
 * the throttled list, then send as many packets as possible from the
 * highest priority message. Note: this function is only invoked from
 * process context (never BH).
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_pacer_xmit(struct homa *homa)
{
	struct homa_rpc *rpc;
	struct sock *sk;
	
	while ((get_cycles() + homa->max_nic_queue_cycles)
			< atomic_long_read(&homa->link_idle_time)) {}
	rcu_read_lock();
	while (1) {
		rpc = list_first_or_null_rcu(&homa->throttled_rpcs,
				struct homa_rpc, throttled_links);
		if (rpc == NULL) {
			rcu_read_unlock();
			return;
		}
		sk = (struct sock *) rpc->hsk;
		lock_sock(sk);
		if (rpc == list_first_or_null_rcu(&homa->throttled_rpcs,
				struct homa_rpc, throttled_links))
			break;
			
		/* RPC might have been deleted before we got the socket
		 * lock; start over.
		 */
		release_sock(sk);
		continue;
	}

	/* At this point we've identified the highest priority RPC and
	 * locked its socket. We can now release the RCU read lock: the
	 * socket can't go away now, nor can the RPC.
	 */
	rcu_read_unlock();
	homa_xmit_data(rpc, false);
	if ((rpc->msgout.next_offset >= rpc->msgout.granted)
			|| !rpc->msgout.next_packet) {
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
		if ((rpc->msgout.next_offset >= rpc->msgout.length)
				&& (rpc->dport >= HOMA_MIN_CLIENT_PORT)) {
			homa_rpc_free(rpc);
		}
	}
	release_sock(sk);
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
		if ((candidate->msgout.length - candidate->msgout.next_offset)
				> (rpc->msgout.length - rpc->msgout.next_offset)) {
			list_add_tail_rcu(&rpc->throttled_links,
					&candidate->throttled_links);
			goto done;
		}
	}
	list_add_tail_rcu(&rpc->throttled_links, &homa->throttled_rpcs);
done:
	spin_unlock_bh(&homa->throttle_lock);
	wake_up_process(homa->pacer_kthread);
	tt_record("woke up pacer thread");
}