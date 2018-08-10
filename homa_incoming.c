/* This file contains functions that handle incoming Homa messages, including
 * both receiving information for those messages and sending grants. */

#include "homa_impl.h"

/**
 * homa_message_in_init() - Constructor for homa_message_in.
 * @msgin:        Structure to initialize.
 * @length:       Total number of bytes in message.
 * @unscheduled:  Initial bytes of message that will be sent without grants.
 * @request:      Non-zero means this message is a request message; zero
 *                means response.
 */
void homa_message_in_init(struct homa_message_in *msgin, int length,
		int unscheduled, int request)
{
	msgin->total_length = length;
	__skb_queue_head_init(&msgin->packets);
	msgin->bytes_remaining = length;
	msgin->granted = unscheduled;
	msgin->priority = 0;
	msgin->scheduled = length > unscheduled;
	msgin->request = request;
	INIT_LIST_HEAD(&msgin->grantable_links);
}

/**
 * homa_message_in_destroy() - Destructor for homa_message_in.
 * @msgin:       Structure to clean up.
 */
void homa_message_in_destroy(struct homa_message_in *msgin)
{
	struct sk_buff *skb, *next;
	if (msgin->total_length < 0)
		return;
	skb_queue_walk_safe(&msgin->packets, skb, next) {
		kfree_skb(skb);
	}
	__skb_queue_head_init(&msgin->packets);
	if (!list_empty(&msgin->grantable_links)) {
		/* Shouldn't ever get here: homa_remove_from_grantable
		 * should have been called by higher-level software in order
		 * to synchronize properly with homa_manage_grants.
		 */
		printk(KERN_ERR "homa_message_in_destroy found msgin on "
			"grantable list");
		__list_del_entry(&msgin->grantable_links);
	}
}

/**
 * homa_add_packet() - Add an incoming packet to the contents of a
 * partially received message.
 * @msgin: Overall information about the incoming message.
 * @skb:   The new packet. This function takes ownership of the packet
 *         and will free it, if it doesn't get added to msgin (because
 *         it provides no new data).
 */
void homa_add_packet(struct homa_message_in *msgin, struct sk_buff *skb)
{
	struct data_header *h = (struct data_header *) skb->data;
	int offset = ntohl(h->offset);
	struct sk_buff *skb2;
	
	/* Any data from the packet with offset less than this is
	 * of no value.*/
	int floor = 0;
	
	/* Any data with offset >= this is useless. */
	int ceiling = msgin->total_length;
	
	/* Figure out where in the list of existing packets to insert the
	 * new one. It doesn't necessarily go at the end, but it almost
	 * always will in practice, so work backwards from the end of the
	 * list.
	 */
	skb_queue_reverse_walk(&msgin->packets, skb2) {
		struct data_header *h2 = (struct data_header *) skb2->data;
		int offset2 = ntohl(h2->offset);
		if (offset2 < offset) {
			floor = offset2 + HOMA_MAX_DATA_PER_PACKET;
			break;
		}
		ceiling = offset2;
	} 
		
	/* New packet goes right after skb2 (which may refer to the header).
	 * Packets shouldn't overlap in byte ranges, but the code below
	 * assumes they might, so it computes how many non-overlapping bytes
	 * are contributed by the new packet.
	 */
	if (unlikely(floor < offset)) {
		floor = offset;
	}
	if (ceiling > offset + HOMA_MAX_DATA_PER_PACKET) {
		ceiling = offset + HOMA_MAX_DATA_PER_PACKET;
	}
	if (floor >= ceiling) {
		/* This packet is redundant. */
		char buffer[100];
		printk(KERN_NOTICE "redundant Homa packet: %s\n",
			homa_print_packet(skb, buffer, sizeof(buffer)));
		kfree_skb(skb);
		return;
	}
	__skb_insert(skb, skb2, skb2->next, &msgin->packets);
	msgin->bytes_remaining -= (ceiling - floor);
}

/**
 * homa_message_in_copy_data() - Extract the data from an incoming message
 * and copy it to buffer(s) in user space.
 * @msgin:      The message whose data should be extracted.
 * @iter:       Describes the available buffer space at user-level; message
 *              data gets copied here.
 * @max_bytes   Total amount of space available via iter.
 * 
 * Return:      The number of bytes copied, or a negative errno.
 */
int homa_message_in_copy_data(struct homa_message_in *msgin,
		struct iov_iter *iter, int max_bytes)
{
	struct sk_buff *skb;
	int offset;
	int err;
	int remaining = max_bytes;
	
	/* Do the right thing even if packets have overlapping ranges.
	 * Honestly, though, this shouldn't happen.
	 */
	offset = 0;
	skb_queue_walk(&msgin->packets, skb) {
		struct data_header *h = (struct data_header *) skb->data;
		int this_offset = ntohl(h->offset);
		int this_size = msgin->total_length - offset;
		if (this_size > HOMA_MAX_DATA_PER_PACKET) {
			this_size = HOMA_MAX_DATA_PER_PACKET;
		}
		if (offset > this_offset) {
			this_size -= (offset - this_offset);
		}
		if (this_size > remaining) {
			this_size =  remaining;
		}
		err = skb_copy_datagram_iter(skb,
				sizeof(*h) + (offset - this_offset),
				iter, this_size);
		if (err) {
			return err;
		}
		remaining -= this_size;
		offset += this_size;
		if (remaining == 0) {
			break;
		}
	}
	return max_bytes - remaining;
}

/**
 * homa_data_from_client() - Server-side handler for incoming DATA packets
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * @srpc:    Information about the RPC corresponding to this packet, or NULL
 *           if no such data currently exists.
 * @hsk:     Socket for which the packet was received.
 * 
 * This method may change the RPC's state to SRPC_READY.
 */
void homa_data_from_client(struct sk_buff *skb, struct homa_server_rpc *srpc,
		struct homa_sock *hsk)
{
	struct data_header *h = (struct data_header *) skb->data;
	
	if (!srpc) {
		srpc = homa_server_rpc_new(hsk, ip_hdr(skb)->saddr, h);
		if (IS_ERR(srpc)) {
			printk(KERN_WARNING "homa_data_from_client couldn't "
					"create server rpc: error %lu",
					-PTR_ERR(srpc));
			kfree_skb(skb);
			return;
		}
	} else if (unlikely(srpc->state != SRPC_INCOMING)) {
		kfree_skb(skb);
		return;
	}
	homa_add_packet(&srpc->request, skb);
	if (srpc->request.scheduled)
		homa_manage_grants(srpc->hsk->homa, &srpc->request);
	if (srpc->request.bytes_remaining == 0) {
		struct sock *sk = (struct sock *) hsk;
		srpc->state = SRPC_READY;
		list_add_tail(&srpc->ready_links, &hsk->ready_server_rpcs);
		sk->sk_data_ready(sk);
	}
}

/**
 * homa_data_from_server() - Client-side handler for incoming DATA packets
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * @crpc:    Information about the RPC corresponding to this packet.
 * 
 * This method may change the RPC's state.
 */
void homa_data_from_server(struct sk_buff *skb, struct homa_client_rpc *crpc)
{
	struct data_header *h = (struct data_header *) skb->data;
	
	if (crpc->state != CRPC_INCOMING) {
		if (unlikely(crpc->state != CRPC_WAITING)) {
			kfree_skb(skb);
			return;			
		}
		homa_message_in_init(&crpc->response, ntohl(h->message_length),
				ntohl(h->unscheduled), 0);
		crpc->state = CRPC_INCOMING;
	}
	homa_add_packet(&crpc->response, skb);
	if (crpc->response.scheduled)
		homa_manage_grants(crpc->hsk->homa, &crpc->response);
	if (crpc->response.bytes_remaining == 0) {
		struct sock *sk = (struct sock *) crpc->hsk;
		crpc->state = CRPC_READY;
		list_add_tail(&crpc->ready_links,
				&crpc->hsk->ready_client_rpcs);
		sk->sk_data_ready(sk);
	}
}

/**
 * homa_grant_from_client() - Server-side handler for incoming GRANT packets
 * @skb:     Incoming packet; size already verified large enough for header.
 *           This function now owns the packet.
 * @srpc:    Information about the RPC corresponding to this packet.
 */
void homa_grant_from_client(struct sk_buff *skb, struct homa_server_rpc *srpc)
{
	struct grant_header *h = (struct grant_header *) skb->data;
	
	if (srpc->state == SRPC_RESPONSE) {
		int new_offset = ntohl(h->offset);

		if (new_offset > srpc->response.granted)
			srpc->response.granted = new_offset;
		srpc->response.priority = h->priority;
		homa_xmit_packets(&srpc->response, (struct sock *) srpc->hsk,
				&srpc->client);
	}
	kfree_skb(skb);
}

/**
 * homa_grant_from_server() - Client-side handler for incoming GRANT packets
 * @skb:     Incoming packet; size already verified large enough for header.
 *           This function now owns the packet.
 * @crpc:    Information about the RPC corresponding to this packet.
 */
void homa_grant_from_server(struct sk_buff *skb, struct homa_client_rpc *crpc)
{
	struct grant_header *h = (struct grant_header *) skb->data;
	
	if (crpc->state == CRPC_WAITING) {
		int new_offset = ntohl(h->offset);
		if (new_offset > crpc->request.granted)
			crpc->request.granted = new_offset;
		crpc->request.priority = h->priority;
		homa_xmit_packets(&crpc->request, (struct sock *) crpc->hsk,
				&crpc->dest);
	}
	kfree_skb(skb);
}

/**
 * homa_manage_grants() - This function is invoked whenever a data packet
 * is received for a message that contains scheduled bytes. It does
 * all the work of prioritizing messages for grants and actually issuing
 * grants.
 * @homa:    Overall data about the Homa protocol implementation.
 * @msgin:   The message for which a packet was received; msgin->scheduled
 *           should be true.
 */
void homa_manage_grants(struct homa *homa, struct homa_message_in *msgin)
{
	/* The overall goal is to grant simultaneously to up to
	 * homa->max_overcommit messages. Ideally, each message should use
	 * a different priority level, determined by bytes_remaining (fewest
	 * bytes_remaining gets the highest priority). If there aren't enough
	 * scheduled priority levels for all of the messages, then the lowest
	 * level gets shared by multiple messages. If there are fewer messages
	 * than priority levels, then we use the lowest available levels
	 * (new higher-priority messages can use the higher levels to achieve
	 * instantaneous preemption).
	 */
	struct list_head *pos;
	struct homa_message_in *other;
	struct grant_header *h;
	int msgs_skipped, priority;
	struct sk_buff *skb;
	int extra_levels;
	
	spin_lock_bh(&homa->lock);
	
	/* First, make sure this message is in the right place in (or not in)
	 * homa->grantable_msgs.
	 */
	if (msgin->granted >= msgin->total_length) {
		/* Message fully granted; no need to track it anymore. */
		if (!list_empty(&msgin->grantable_links)) {
			homa->num_grantable--;
			list_del_init(&msgin->grantable_links);
		}
	} else if (list_empty(&msgin->grantable_links)) {
		/* Message not yet tracked; add it in priority order. */
		homa->num_grantable++;
		list_for_each(pos, &homa->grantable_msgs) {
			other = list_entry(pos, struct homa_message_in,
					grantable_links);
			if (other->bytes_remaining > msgin->bytes_remaining) {
				list_add_tail(&msgin->grantable_links, pos);
				goto check_grant;
			}
		}
		list_add_tail(&msgin->grantable_links, &homa->grantable_msgs);
	} else while (homa->grantable_msgs.next != &msgin->grantable_links) {
		/* Message is on the list, but its priority may have
		 * increased because of the recent packet arrival. If so,
		 * adjust its position in the list. Note: priorities only
		 * increase.
		 */
		other = list_prev_entry(msgin, grantable_links);
		if (other->bytes_remaining <= msgin->bytes_remaining)
			goto check_grant;
		__list_del_entry(&other->grantable_links);
		list_add(&other->grantable_links, &msgin->grantable_links);
	}
	
    check_grant:
	/* Next, see if there is a message that deserves a grant (it has
	 * fewer than homa->rtt_bytes of data that have been granted but
	 * not yet received). */
	msgs_skipped = 0;
	list_for_each(pos, &homa->grantable_msgs) {
		other = list_entry(pos, struct homa_message_in,
				grantable_links);
		if ((other->granted - (other->total_length -
				other->bytes_remaining)) < homa->rtt_bytes) {
			other->granted += HOMA_MAX_DATA_PER_PACKET;
			goto send_grant;
		}
		msgs_skipped++;
		if (msgs_skipped >= homa->max_overcommit)
			break;
	}
	/* There's no (appropriate) message to send a grant to. */
	goto done;
	
    send_grant:
	/* Finally, send a grant packet. */
	skb = alloc_skb(HOMA_SKB_SIZE, GFP_KERNEL);
	if (unlikely(!skb))
		/* No buffers available, so just skip this grant. */
		return;
	skb_reserve(skb, HOMA_SKB_RESERVE);
	skb_reset_transport_header(skb);
	h = (struct grant_header *) skb_put(skb, sizeof(*h));
	h->common.type = GRANT;
	h->offset = htonl(other->granted);
	priority = homa->max_sched_prio - msgs_skipped;
	extra_levels = (homa->max_sched_prio + 1 - homa->min_sched_prio)
			- homa->num_grantable;
	if (extra_levels >= 0)
		priority -= extra_levels;
	else if (priority < homa->min_sched_prio)
		priority = homa->min_sched_prio;
	h->priority = priority;
	homa_xmit_to_sender(skb, other);
	/* It's important to hold homa->lock until here: this keeps other
	 * from going away. */
	
    done:
	spin_unlock_bh(&homa->lock);
}

/**
 * homa_remove_from_grantable() - This method is invoked by RPC destructors;
 * it makes sure that the the RPC's input message is no longer visible to
 * homa_manage_grants.
 * @homa:    Overall data about the Homa protocol implementation.
 * @msgin:   Input message that is being destroyed.
 */
void homa_remove_from_grantable(struct homa *homa,
		struct homa_message_in *msgin)
{
	spin_lock(&homa->lock);
	if (!list_empty(&msgin->grantable_links)) {
		homa->num_grantable--;
		list_del_init(&msgin->grantable_links);
	}
	spin_unlock(&homa->lock);
}