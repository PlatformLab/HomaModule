/* This file contains functions that handle incoming Homa packets. */

#include "homa_impl.h"

/**
 * homa_add_packet() - Add an incoming packet to the contents of a
 * partially received message.
 * @hmi:   Overall information about the incoming message.
 * @skb:   The new packet. This function takes ownership of the packet
 *         and will free it, if it doesn't get added to hmi.
 */
void homa_add_packet(struct homa_message_in *hmi, struct sk_buff *skb)
{
	struct data_header *h = (struct data_header *) skb->data;
	int offset = ntohl(h->offset);
	int ceiling = hmi->total_length;
	int floor = 0;
	struct sk_buff *skb2;
	
	/* Figure out where in the list of existing packets to insert the
	 * new one. It doesn't necessarily go at the end, but it almost
	 * always will in practice, so work backwards from the end of the
	 * list.
	 */
	skb_queue_reverse_walk(&hmi->packets, skb2) {
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
	__skb_insert(skb, skb2, skb2->next, &hmi->packets);
	hmi->bytes_remaining -= (ceiling - floor);
}
/**
 * homa_data_from_client() - Server-side handler for incoming DATA packets
 * @homa:    Overall data about the Homa protocol implementation.
 * @skb:     Incoming packet; size known to be large enough for the header.
 * @hsk:     Socket for which the packet was received.
 * @srpc:    Information about the RPC corresponding to this packet, or NULL
 *           if no such data currently exists.
 */
void homa_data_from_client(struct homa *homa, struct sk_buff *skb,
		struct homa_sock *hsk, struct homa_server_rpc *srpc)
{
	struct data_header *h = (struct data_header *) skb->data;
	if (!srpc) {
		srpc = (struct homa_server_rpc *) kmalloc(sizeof(*srpc),
				GFP_KERNEL);
		srpc->saddr = ip_hdr(skb)->saddr;
		srpc->sport = ntohs(h->common.sport);
		srpc->id = h->common.id;
		homa_message_in_init(&srpc->request, ntohl(h->message_length),
				ntohl(h->unscheduled));
		list_add(&srpc->server_rpc_links, &hsk->server_rpcs);
	}
	homa_add_packet(&srpc->request, skb);
}

/**
 * homa_message_in_destroy() - Destructor for homa_message_in.
 * @hmo:       Structure to clean up.
 */
void homa_message_in_destroy(struct homa_message_in *hmi)
{
	struct sk_buff *skb, *tmp;
	skb_queue_walk_safe(&hmi-> packets, skb, tmp) {
		kfree_skb(skb);
	}
}

/**
 * homa_message_in_init() - Constructor for homa_message_in.
 * @hmi:          Structure to initialize.
 * @length:       Total number of bytes in message.
 * @unscheduled:  Initial bytes of message that will be sent without grants.
 */
void homa_message_in_init(struct homa_message_in *hmi, int length,
	int unscheduled)
{
	__skb_queue_head_init(&hmi->packets);
	hmi->total_length = length;
	hmi->bytes_remaining = length;
	hmi->granted = unscheduled;
	hmi->priority = 0;
}