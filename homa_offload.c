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

extern struct homa *homa;

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
 * homa_set_softirq_cpu() - Arrange for SoftIRQ processing of a packet to
 * occur on a specific core (creates a socket flow table entry for the core,
 * and sets the packet's hash to map to the given entry).
 * @skb:  Incoming packet
 * @cpu:  Index of core to which the packet should be directed for
 *        SoftIRQ processing.
 */
static inline void homa_set_softirq_cpu(struct sk_buff *skb, int cpu)
{
	struct rps_sock_flow_table *sock_flow_table;
	int hash;
	
	sock_flow_table = rcu_dereference(rps_sock_flow_table);
	if (sock_flow_table == NULL)
		return;
	hash = cpu + rps_cpu_mask + 1;
	if (sock_flow_table->ents[hash] != hash) {
		rcu_read_lock();
		sock_flow_table = rcu_dereference(rps_sock_flow_table);
		sock_flow_table->ents[hash] = hash;
		rcu_read_unlock();
	}
	__skb_set_sw_hash(skb, hash, false);
}

/**
 * homa_gro_receive() - Invoked for each input packet at a very low
 * level in the stack to perform GRO. However, this code does GRO in an
 * unusual way: it simply aggregates all packets targeted to a particular
 * destination port, so that the entire bundle can get through the networking
 * stack in a single traversal.
 * @gro_list:   Pointer to pointer to first in list of packets that are being
 *              held for possible GRO merging.
 * @skb:        The newly arrived packet.
 * 
 * Return: If the return value is non-NULL, it refers to a link in
 * gro_list. The skb referred to by that link should be removed from the
 * list by the caller and passed up the stack immediately. This function
 * always returns NULL.
 */
struct sk_buff **homa_gro_receive(struct sk_buff **gro_list, struct sk_buff *skb)
{
	/* This function will do one of the following things:
	 * 1. Merge skb with a packet in gro_list by appending it to
	 *    the frag_list of that packet.
	 * 2. Set NAPI_GRO_CB(skb)->flush, indicating that skb is not a
	 *    candidate for merging and should be passed up the networking
	 *    stack immediately.
	 * 3. Leave skb untouched, in which case it will be added to
	 *    gro_list by the caller, so it will be considered for merges
	 *    in the future.
	 */
	struct data_header *h_new;
//	int hdr_offset, hdr_end;
	struct sk_buff *held_skb;
	struct sk_buff **pp;
	struct iphdr *iph;
	struct sk_buff **result = NULL;
	
	if (!pskb_may_pull(skb, 64))
		tt_record("homa_gro_receive can't pull enough data "
				"from packet for trace");
	iph = (struct iphdr *) skb_network_header(skb);
	h_new = (struct data_header *) skb_transport_header(skb);
	if (h_new->common.type == 20)
		tt_record4("homa_gro_receive got packet from 0x%x "
				"id %llu, offset %d, priority %d",
				ntohl(ip_hdr(skb)->saddr),
				h_new->common.id & 0xffffffff,
				ntohl(h_new->seg.offset),
				iph->tos >> 5);
	else
		tt_record4("homa_gro_receive got packet from 0x%x "
				"id %llu, type %d, priority %d",
				ntohl(ip_hdr(skb)->saddr),
				h_new->common.id & 0xffffffff,
				h_new->common.type, iph->tos >> 5);
	
	homa_cores[smp_processor_id()]->last_active = get_cycles();
	
	if (homa->gro_policy & HOMA_GRO_BYPASS) {
		homa_softirq(skb);
		
		/* This return value indicates that we have freed skb. */
		return ERR_PTR(-EINPROGRESS);
	}
	
	/* Get access to the Homa header for the packet. I don't understand
	 * why such ornate code is needed, but this mimics what TCP does.
	 */
//	hdr_offset = skb_gro_offset(skb);
//	hdr_end = hdr_offset + sizeof32(*h_new);
//	h_new = (struct common_header *) skb_gro_header_fast(skb, hdr_offset);
//	if (skb_gro_header_hard(skb, hdr_end)) {
//		h_new = (struct common_header *) skb_gro_header_slow(skb, hdr_end,
//				hdr_offset);
//		if (unlikely(!h_new)) {
//			/* Header not available in contiguous memory. */
//			UNIT_LOG(";", "no header");
//			goto flush;
//		}
//	}
	
	h_new->common.gro_count = 1;
	for (pp = gro_list; (held_skb = *pp) != NULL; pp = &held_skb->next) {
		struct iphdr *held_iph  = (struct iphdr *)
				skb_network_header(held_skb);
		struct common_header *h_held = (struct common_header *)
				skb_transport_header(held_skb);
		
		/* Packets can be batched together as long as they are all
		 * Homa packets, even if they are from different RPCs. Don't
		 * use the same_flow mechanism that is normally used in
		 * gro_receive, because it won't allow packets from different
		 * sources to be aggregated.
		 */
		if (held_iph->protocol != IPPROTO_HOMA)
			continue;
		
		/* Aggregate skb into held_skb. We don't update the length of
		 * held_skb, because we'll eventually split it up and process
		 * each skb independently.
		 */
		if (NAPI_GRO_CB(held_skb)->last == held_skb)
			skb_shinfo(held_skb)->frag_list = skb;
		else
			NAPI_GRO_CB(held_skb)->last->next = skb;
		NAPI_GRO_CB(held_skb)->last = skb;
		skb->next = NULL;
		NAPI_GRO_CB(skb)->same_flow = 1;
		NAPI_GRO_CB(held_skb)->count++;
		h_held->gro_count++;
		if (h_held->gro_count >= homa->max_gro_skbs)
			result = pp;
	        goto done;
	}
	
	/* There was no existing Homa packet that this packet could be
	 * batched with, so this packet will now go on gro_list for future
	 * packets to be batched with. If the packet is sent up the stack
	 * before another packet arrives for batching, we want it to be
	 * processed on this same core (it's faster that way, and if
	 * batching doesn't occur it means we aren't heavily loaded; if
	 * batching does occur, homa_gro_complete will pick a different
	 * core).
	 */
	if (likely(homa->gro_policy & HOMA_GRO_SAME_CORE))
		homa_set_softirq_cpu(skb, smp_processor_id());
	
	done:
	homa_check_pacer(homa, 1);
	return result;
}


/**
 * homa_gro_complete() - This function is invoked just before a packet that
 * was held for GRO processing is passed up the network stack, in case the
 * protocol needs to do some cleanup on the merged packet. Right now there
 * is nothing to do.
 * @skb:     The packet for which GRO processing is now finished.
 * @hoffset: Offset within the packet of the transport header.
 *
 * Return:   Always returns 0, signifying success. 
 */
int homa_gro_complete(struct sk_buff *skb, int hoffset)
{	
//	struct common_header *h = (struct common_header *)
//			skb_transport_header(skb);
//	struct data_header *d = (struct data_header *) h;
//	tt_record4("homa_gro_complete type %d, id %d, offset %d, count %d",
//			h->type, h->id, ntohl(d->seg.offset), h->gro_count);
	
	if (homa->gro_policy & HOMA_GRO_IDLE) {
		int i, core, best;
		__u64 best_time = ~0;
		/* Pick a specific core to handle SoftIRQ processing for this
		 * group of packets. The goal here is to spread load so that no
		 * core gets overloaded. We do that by checking the next several
		 * cores in order after this one, and choosing the one that
		 * has been idle the longest (hasn't done NAPI or SoftIRQ
		 * processing for Homa).
		 */
		core = best = smp_processor_id();
		for (i = 0; i < 4; i++) {
			core++;
			if (unlikely(core >= nr_cpu_ids))
				core = 0;
			if (homa_cores[core]->last_active < best_time) {
				best_time = homa_cores[core]->last_active;
				best = core;
			}
		}
		homa_set_softirq_cpu(skb, best);
	} else if (homa->gro_policy & HOMA_GRO_NEXT) {
		/* Use the next core (in circular order) to handle the
		 * SoftIRQ processing.
		 */
		int target = smp_processor_id() + 1;
		if (unlikely(target >= nr_cpu_ids))
			target = 0;
		homa_set_softirq_cpu(skb, target);
	}
	
	return 0;
}