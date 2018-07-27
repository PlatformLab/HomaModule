/* This file contains functions that handle incoming Homa packets. */

#include "homa_impl.h"

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
	int ceiling = msgin->total_length;
	int floor = 0;
	struct sk_buff *skb2;
	
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
			homa_print_header(skb, buffer, sizeof(buffer)));
		kfree_skb(skb);
		return;
	}
	__skb_insert(skb, skb2, skb2->next, &msgin->packets);
	msgin->bytes_remaining -= (ceiling - floor);
}

/**
 * homa_data_from_client() - Server-side handler for incoming DATA packets
 * @homa:    Overall data about the Homa protocol implementation.
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * @hsk:     Socket for which the packet was received.
 * @srpc:    Information about the RPC corresponding to this packet, or NULL
 *           if no such data currently exists.
 * 
 * This method may change the RPC's state to SRPC_READY.
 */
void homa_data_from_client(struct homa *homa, struct sk_buff *skb,
		struct homa_sock *hsk, struct homa_server_rpc *srpc)
{
	struct data_header *h = (struct data_header *) skb->data;
	int err;
	
	if (!srpc) {
		srpc = homa_server_rpc_new(hsk, ip_hdr(skb)->saddr, h, &err);
		if (!srpc) {
			printk(KERN_WARNING "homa_data_from_client couldn't "
					"create server rpc: error %d", -err);
			kfree_skb(skb);
			return;
		}
	} else if (unlikely(srpc->state != SRPC_INCOMING)) {
		kfree_skb(skb);
		return;
	}
	homa_add_packet(&srpc->request, skb);
	if (srpc->request.bytes_remaining == 0) {
		struct sock *sk = (struct sock *) hsk;
		srpc->state = SRPC_READY;
		list_add_tail(&srpc->ready_links, &hsk->ready_server_rpcs);
		sk->sk_data_ready(sk);
	}
}

/**
 * homa_data_from_server() - Client-side handler for incoming DATA packets
 * @homa:    Overall data about the Homa protocol implementation.
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * @hsk:     Socket for which the packet was received.
 * @crpc:    Information about the RPC corresponding to this packet.
 * 
 * This method may change the RPC's state.
 */
void homa_data_from_server(struct homa *homa, struct sk_buff *skb,
		struct homa_sock *hsk, struct homa_client_rpc *crpc)
{
	struct data_header *h = (struct data_header *) skb->data;
	
	if (crpc->state != CRPC_INCOMING) {
		if (unlikely(crpc->state != CRPC_WAITING)) {
			kfree_skb(skb);
			return;			
		}
		homa_message_in_init(&crpc->response, ntohl(h->message_length),
				ntohl(h->unscheduled));
		crpc->state = CRPC_INCOMING;
	}
	homa_add_packet(&crpc->response, skb);
	if (crpc->response.bytes_remaining == 0) {
		struct sock *sk = (struct sock *) hsk;
		crpc->state = CRPC_READY;
		list_add_tail(&crpc->ready_links, &hsk->ready_client_rpcs);
		sk->sk_data_ready(sk);
	}
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
 * homa_message_in_destroy() - Destructor for homa_message_in.
 * @msgin:       Structure to clean up.
 */
void homa_message_in_destroy(struct homa_message_in *msgin)
{
	struct sk_buff *skb, *next;
	skb_queue_walk_safe(&msgin->packets, skb, next) {
		kfree_skb(skb);
	}
	__skb_queue_head_init(&msgin->packets);
}

/**
 * homa_message_in_init() - Constructor for homa_message_in.
 * @msgin:        Structure to initialize.
 * @length:       Total number of bytes in message.
 * @unscheduled:  Initial bytes of message that will be sent without grants.
 */
void homa_message_in_init(struct homa_message_in *msgin, int length,
	int unscheduled)
{
	__skb_queue_head_init(&msgin->packets);
	msgin->total_length = length;
	msgin->bytes_remaining = length;
	msgin->granted = unscheduled;
	msgin->priority = 0;
}