/* Copyright (c) 2019-2021 Stanford University
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

/* This file implements GSO (Generic Segmentation Offload) and GRO (Generic
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
 * @held_list:  Pointer to header for list of packets that are being
 *              held for possible GRO merging. Note: this list contains
 *              only packets matching a given hash.
 * @skb:        The newly arrived packet.
 * 
 * Return: If the return value is non-NULL, it refers to an skb in
 * gro_list. The skb will be removed from the list by the caller and
 * passed up the stack immediately.
 */
struct sk_buff *homa_gro_receive(struct list_head *held_list,
		struct sk_buff *skb)
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
	struct iphdr *iph;
	struct sk_buff *result = NULL;
	struct homa_core *core = homa_cores[smp_processor_id()];
	__u32 hash;
	
	if (!pskb_may_pull(skb, 64))
		tt_record("homa_gro_receive can't pull enough data "
				"from packet for trace");
	iph = (struct iphdr *) skb_network_header(skb);
	h_new = (struct data_header *) skb_transport_header(skb);
	if (h_new->common.type == 20)
		tt_record4("homa_gro_receive got packet from 0x%x "
				"id %llu, offset %d, priority %d",
				ntohl(ip_hdr(skb)->saddr),
				homa_local_id(&h_new->common),
				ntohl(h_new->seg.offset),
				iph->tos >> 5);
	else
		tt_record4("homa_gro_receive got packet from 0x%x "
				"id %llu, type %d, priority %d",
				ntohl(ip_hdr(skb)->saddr),
				homa_local_id(&h_new->common),
				h_new->common.type, iph->tos >> 5);
	
	core->last_active = get_cycles();
	
	if (homa->gro_policy & HOMA_GRO_BYPASS) {
		homa_softirq(skb);
		
		/* This return value indicates that we have freed skb. */
		return ERR_PTR(-EINPROGRESS);
	}
	
	/* The GRO mechanism tries to separate packets onto different
	 * gro_lists by hash. This is bad for us, because we want to batch
	 * packets together regardless of their RPCs. So, instead of
	 * checking the list they gave us, check the last list where this
	 * core added a Homa packet (if there is such a list).
	 */
	hash = skb_get_hash_raw(skb) & (GRO_HASH_BUCKETS - 1);
	if (core->held_skb) {
		/* Reverse-engineer the location of the napi_struct, so we
		 * can verify that held_skb is still valid.
		 */
		struct gro_list *gro_list = container_of(held_list,
				struct gro_list, list);
		struct napi_struct *napi = container_of(gro_list,
				struct napi_struct, gro_hash[hash]);
		
		/* Make sure that core->held_skb is on the list. */
		list_for_each_entry(held_skb,
				&napi->gro_hash[core->held_bucket].list, list) {
			if (held_skb != core->held_skb)
				continue;

			/* Aggregate skb into held_skb. We don't update the
			 * length of held_skb because we'll eventually split
			 * it up and process each skb independently.
			 */
			if (NAPI_GRO_CB(held_skb)->last == held_skb)
				skb_shinfo(held_skb)->frag_list = skb;
			else
				NAPI_GRO_CB(held_skb)->last->next = skb;
			NAPI_GRO_CB(held_skb)->last = skb;
			skb->next = NULL;
			NAPI_GRO_CB(skb)->same_flow = 1;
			NAPI_GRO_CB(held_skb)->count++;
			if (NAPI_GRO_CB(held_skb)->count >= homa->max_gro_skbs) {
				/* Push this batch up through the SoftIRQ
				 * layer. This code is a hack, needed because
				 * returning skb as result is no longer
				 * sufficient (as of 5.4.80) to push it up
				 * the stack; the packet just gets queued on
				 * napi->rx_list. This code basically steals
				 * the packet from dev_gro_receive and
				 * pushes it upward.
				 */
				skb_list_del_init(held_skb);
				homa_gro_complete(held_skb, 0);
				netif_receive_skb(held_skb);
				napi->gro_hash[core->held_bucket].count--;
				if (napi->gro_hash[core->held_bucket].count == 0)
					__clear_bit(core->held_bucket,
							&napi->gro_bitmask);
				result = ERR_PTR(-EINPROGRESS);
			}
			goto done;
		}
	}
	
	/* There was no existing Homa packet that this packet could be
	 * batched with, so this packet will become the new merge_skb.
	 * If the packet is sent up the stack before another packet
	 * arrives for batching, we want it to be processed on this same
	 * core (it's faster that way, and if batching doesn't occur it
	 * means we aren't heavily loaded; if batching does occur,
	 * homa_gro_complete will pick a different core).
	 */
	core->held_skb = skb;
	core->held_bucket = hash;
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
//			h->type, h->id, ntohl(d->seg.offset),
//			NAPI_GRO_CB(skb)->count);
	
	if (homa->gro_policy & HOMA_GRO_IDLE) {
		int i, core, best;
		__u64 best_time = ~0;
		__u64 last_active;
		
		/* Pick a specific core to handle SoftIRQ processing for this
		 * group of packets. The goal here is to spread load so that no
		 * core gets overloaded. We do that by checking the next several
		 * cores in order after this one, and choosing the one that
		 * hasn't done NAPI or SoftIRQ processing for Homa in the
		 * longest time. Also, if HOMA_GRO_NO_TASK is set, compute
		 * a second "best" core where we only consider cores that have
		 * no runnable user tasks; if there is such a core, use this
		 * in preference to the first "best".
		 */
		core = best = smp_processor_id();
		for (i = 0; i < 4; i++) {
			core++;
			if (unlikely(core >= nr_cpu_ids))
				core = 0;
			last_active = homa_cores[core]->last_active;
			if (last_active < best_time) {
				best_time = last_active;
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