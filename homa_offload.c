/* This file implements GSO (Generic Ssegmentation Offload) and GRO (Generic
 * Receive Offload) for Homa.
 */

#include "homa_impl.h"

static const struct net_offload homa_offload = {
	.callbacks = {
		.gso_segment	=	NULL,
		.gro_receive	=	homa_gro_receive,
		.gro_complete	=	homa_gro_complete,
	},
};

/**
 * homa_offload_init() - Invoked to enable GRO and GSO. Typically invoked
 * when the Homa module loads.
 * Return: nonzero means error.
 */
int homa_offload_init(void)
{
	return inet_add_offload(&homa_offload, IPPROTO_HOMA);
}

/**
 * homa_offload_end() - Disables GRO and GSO for Homa; typically invoked
 * during Homa module unloading.
 * 
 * Return: nonzero means error.
 */
int homa_offload_end(void)
{
	return inet_del_offload(&homa_offload, IPPROTO_HOMA);
}

/**
 * homa_gro_receive() - Invoked for each input packet at a very low
 * level in the stack; attempts to merge consecutive data packets into
 * a single large packet.
 * @gro_list:   Pointer to pointer to first in list of packets that are being
 *              held for possible GRO merging.
 * @skb:        The newly arrived packet.
 * 
 * Return: If the return value is non-NULL, it refers to a link in
 * gro_list. The skb referred to by that link should be removed from the
 * list by the caller and passed up the stack immediately.
 */
struct sk_buff **homa_gro_receive(struct sk_buff **gro_list, struct sk_buff *skb)
{
	/* This function will do one of the following things:
	 * 1. Merge skb with a packet in gro_list by calling skb_gro_receive.
	 * 2. Set NAPI_GRO_CB(skb)->flush, indicating that skb is not a
	 *    candidate for merging and should be passed up the networking
	 *    stack immediately.
	 * 3. Leave skb untouched, in which case it will be added to
	 *    gro_list by the caller, so it will be considered for merges
	 *    in the future.
	 */
	struct data_header *h, *h2;
	int hdr_offset, hdr_end;
	struct sk_buff *held_skb;
	struct sk_buff **pp;
	
	/* Get access to the Homa header for the packet. I don't understand
	 * why such ornate code is needed, but it mimics what TCP does.
	 */
	hdr_offset = skb_gro_offset(skb);
	hdr_end = hdr_offset + HOMA_MAX_HEADER;
	h = skb_gro_header_fast(skb, hdr_offset);
	if (skb_gro_header_hard(skb, hdr_end)) {
		h = (struct data_header *) skb_gro_header_slow(skb, hdr_end,
				hdr_offset);
		if (unlikely(!h)) {
			/* Header not available in contiguous memory. */
			UNIT_LOG(";", "no header");
			goto flush;
		}
	}
	
	if (h->common.type != DATA)
		goto flush;
	
	skb_gro_pull(skb, sizeof32(struct data_header));
	if (htonl(h->message_length) == skb_gro_len(skb))
		goto flush;
	for (pp = gro_list; (held_skb = *pp); pp = &held_skb->next) {
		if (!NAPI_GRO_CB(held_skb)->same_flow)
			continue;

		h2 = (struct data_header *) skb_transport_header(held_skb);

		if ((h->common.sport ^ h2->common.sport)
				| (h->common.dport ^ h2->common.dport)
				| (h->common.id ^ h2->common.id)
				| (ntohl(h->offset) ^ (ntohl(h2->offset)
				+ skb_gro_len(held_skb)))) {
			NAPI_GRO_CB(held_skb)->same_flow = 0;
			continue;
		}
		
		/* skb contains data immediately following that in held_skb. */
		skb_gro_receive(pp, skb);
		break;
	}
	return NULL;
	
flush:
	NAPI_GRO_CB(skb)->flush = 1;
	return NULL;
}


/**
 * homa_gro_complete() - This function is invoked just before a packet that
 * was held for GRO processing is passed up the network stack, in case the
 * protocol needs to do some cleanup on the merged packet (we don't need to
 * do anything)
 * @skb:     The packet for which GRO processing is now finished.
 * @hoffset: Offset within the packet of the transport header.
 *
 * Return:   Always returns 0, signifying success. 
 */
int homa_gro_complete(struct sk_buff *skb, int hoffset)
{
	return 0;
}