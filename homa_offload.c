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

/* This file implements GSO (Generic Segmentation Offload) and GRO (Generic
 * Receive Offload) for Homa.
 */

#include "homa_impl.h"

#define CORES_TO_CHECK 4

static const struct net_offload homa_offload = {
	.callbacks = {
		.gso_segment	=	homa_gso_segment,
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
	int res1 = inet_add_offload(&homa_offload, IPPROTO_HOMA);
	int res2 = inet6_add_offload(&homa_offload, IPPROTO_HOMA);
	return res1 ? res1 : res2;
}

/**
 * homa_offload_end() - Disables GRO and GSO for Homa; typically invoked
 * during Homa module unloading.
 *
 * Return: nonzero means error.
 */
int homa_offload_end(void)
{
	int res1 = inet_del_offload(&homa_offload, IPPROTO_HOMA);
	int res2 = inet6_del_offload(&homa_offload, IPPROTO_HOMA);
	return res1 ? res1 : res2;
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
 * homa_gso_segment() - Split up a large outgoing Homa packet (larger than MTU)
 * into multiple smaller packets.
 * @skb:       Packet to split.
 * @features:  Passed through to skb_segment.
 * Return: A list of packets, or NULL if for the packet couldn't be split.
 */
struct sk_buff *homa_gso_segment(struct sk_buff *skb,
		netdev_features_t features)
{
	struct sk_buff *segs;
	tt_record2("homa_gso_segment invoked, frags %d, headlen %d",
			skb_shinfo(skb)->nr_frags, skb_headlen(skb));

	/* This is needed to separate header info (which is replicated
	 * in each segment) from data, which is divided among the segments.
	 */
	__skb_pull(skb, sizeof(struct data_header)
			- sizeof(struct data_segment));
	segs = skb_segment(skb, features);

	/* Set incrementing ids in each of the segments (mimics behavior
	 * of Mellanox NICs and other segmenters).
	 */
	if (ip_hdr(segs)->version == 4) {
		struct sk_buff *seg;
		int i = 0;
		for (seg = segs; seg != NULL; seg = seg->next) {
			ip_hdr(seg)->id = htons(i);
			i++;
		}
	}

	tt_record("homa_gso_segment returning");
	return segs;
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
//	int hdr_offset, hdr_end;
	struct sk_buff *held_skb;
	struct sk_buff *result = NULL;
	struct homa_core *core = homa_cores[raw_smp_processor_id()];
	__u32 hash;
	__u64 saved_softirq_metric, softirq_cycles;
	struct data_header *h_new = (struct data_header *)
			skb_transport_header(skb);
	int priority;
	__u32 saddr;
	if (skb_is_ipv6(skb)) {
		priority = ipv6_hdr(skb)->priority;
		saddr = ntohl(ipv6_hdr(skb)->saddr.in6_u.u6_addr32[3]);
	} else {
		priority = ((struct iphdr *) skb_network_header(skb))->tos >> 5;
		saddr = ntohl(ip_hdr(skb)->saddr);
	}

//      The test below is overly conservative except for data packets.
//	if (!pskb_may_pull(skb, 64))
//		tt_record("homa_gro_receive can't pull enough data "
//				"from packet for trace");
	if (h_new->common.type == DATA)
		tt_record4("homa_gro_receive got packet from 0x%x "
				"id %llu, offset %d, priority %d",
				saddr, homa_local_id(h_new->common.sender_id),
				ntohl(h_new->seg.offset), priority);
	else if (h_new->common.type == GRANT) {
		tt_record4("homa_gro_receive got grant from 0x%x "
				"id %llu, offset %d, priority %d",
				saddr, homa_local_id(h_new->common.sender_id),
				ntohl(((struct grant_header *) h_new)->offset),
				priority);
		/* The following optimization handles grants here at NAPI
		 * level, bypassing the SoftIRQ mechanism (and avoiding the
		 * delay of handing off to a different core). This makes
		 * a significant difference in throughput for large
		 * messages, especially when the system is loaded.
		 */
		if (homa->gro_policy & HOMA_GRO_FAST_GRANTS)
			goto bypass;
	} else
		tt_record4("homa_gro_receive got packet from 0x%x "
				"id %llu, type 0x%x, priority %d",
				saddr, homa_local_id(h_new->common.sender_id),
				h_new->common.type, priority);

	core->last_active = get_cycles();

	if ((homa->gro_policy & HOMA_GRO_BYPASS)
			|| ((homa->gro_policy & HOMA_GRO_SHORT_BYPASS)
			&& (skb->len < 1400)))
		goto bypass;

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
		homa_set_softirq_cpu(skb, raw_smp_processor_id());

    done:
	homa_check_pacer(homa, 1);
	return result;

    bypass:
        /* Record SoftIRQ cycles in a different metric to reflect that
	 * they happened during bypass.
	 */
	saved_softirq_metric = homa_cores[raw_smp_processor_id()]
			->metrics.softirq_cycles;
	homa_softirq(skb);
	softirq_cycles = homa_cores[raw_smp_processor_id()]
			->metrics.softirq_cycles - saved_softirq_metric;
	homa_cores[raw_smp_processor_id()]->metrics.softirq_cycles
			= saved_softirq_metric;
	INC_METRIC(bypass_softirq_cycles, softirq_cycles);

	/* This return value indicates that we have freed skb. */
	return ERR_PTR(-EINPROGRESS);

}

/**
 * homa_gro_gen2() - When the Gen2 load balancer is being used this function
 * is invoked by homa_gro_complete to choose a core to handle SoftIRQ for a
 * batch of packets
 * @skb:     First in a group of packets that are ready to be passed to SoftIRQ.
 *           Information will be updated in the packet so that Linux will
 *           direct it to the chosen core.
 */
void homa_gro_gen2(struct sk_buff *skb)
{
	/* Scan the next several cores in order after the current core,
	 * trying to find one that is not already busy with SoftIRQ processing,
	 * and that doesn't appear to be active with NAPI/GRO processing
	 * either. If there is no such core, just rotate among the next
	 * cores. See balance.txt for overall design information on load
	 * balancing.
	 */
	struct data_header *h = (struct data_header *) skb_transport_header(skb);
	int i;
	int this_core = raw_smp_processor_id();
	int candidate = this_core;
	__u64 now = get_cycles();
	struct homa_core *core;
	for (i = CORES_TO_CHECK; i > 0; i--) {
		candidate++;
		if (unlikely(candidate >= nr_cpu_ids))
			candidate = 0;
		core = homa_cores[candidate];
		if (atomic_read(&core->softirq_backlog)  > 0)
			continue;
		if ((core->last_gro + homa->busy_cycles) > now)
			continue;
		tt_record3("homa_gro_gen2 chose core %d for id %d "
				"offset %d",
				candidate, homa_local_id(h->common.sender_id),
				ntohl(h->seg.offset));
		break;
	}
	if (i <= 0) {
		/* All of the candidates appear to be busy; just
		 * rotate among them.
		 */
		int offset = homa_cores[this_core]->softirq_offset;
		offset += 1;
		if (offset > CORES_TO_CHECK)
			offset = 1;
		homa_cores[this_core]->softirq_offset = offset;
		candidate = this_core + offset;
		while (candidate >= nr_cpu_ids) {
			candidate -= nr_cpu_ids;
		}
		tt_record3("homa_gro_gen2 chose core %d for id %d "
				"offset %d (all cores busy)",
				candidate, homa_local_id(h->common.sender_id),
				ntohl(h->seg.offset));
	}
	atomic_inc(&homa_cores[candidate]->softirq_backlog);
	homa_cores[this_core]->last_gro = now;
	homa_set_softirq_cpu(skb, candidate);
}

/**
 * homa_gro_gen3() - When the Gen3 load balancer is being used this function
 * is invoked by homa_gro_complete to choose a core to handle SoftIRQ for a
 * batch of packets
 * @skb:     First in a group of packets that are ready to be passed to SoftIRQ.
 *           Information will be updated in the packet so that Linux will
 *           direct it to the chosen core.
 */
void homa_gro_gen3(struct sk_buff *skb)
{
	/* See balance.txt for overall design information on the Gen3
	 * load balancer.
	 */
	struct data_header *h = (struct data_header *) skb_transport_header(skb);
	int i, core;
	__u64 now, busy_time;
	int *candidates = homa_cores[raw_smp_processor_id()]->gen3_softirq_cores;

	now = get_cycles();
	busy_time = now - homa->busy_cycles;

	core = candidates[0];
	for (i = 0; i <  NUM_GEN3_SOFTIRQ_CORES; i++) {
		int candidate = candidates[i];
		if (candidate < 0) {
			break;
		}
		if (homa_cores[candidate]->last_app_active < busy_time) {
			core = candidate;
			break;
		}
	}
	homa_set_softirq_cpu(skb, core);
	homa_cores[core]->last_active = now;
	tt_record4("homa_gro_gen3 chose core %d for id %d, offset %d, delta %d",
			core, homa_local_id(h->common.sender_id),
			ntohl(h->seg.offset),
			now - homa_cores[core]->last_app_active);
	INC_METRIC(gen3_handoffs, 1);
	if (core != candidates[0])
		INC_METRIC(gen3_alt_handoffs, 1);
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
	struct data_header *h = (struct data_header *) skb_transport_header(skb);
//	tt_record4("homa_gro_complete type %d, id %d, offset %d, count %d",
//			h->type, homa_local_id(h->sender_id), ntohl(d->seg.offset),
//			NAPI_GRO_CB(skb)->count);

	if (homa->gro_policy & HOMA_GRO_GEN3) {
		homa_gro_gen3(skb);
	} else if (homa->gro_policy & HOMA_GRO_GEN2) {
		homa_gro_gen2(skb);
	} else if (homa->gro_policy & HOMA_GRO_IDLE) {
		int i, core, best;
		__u64 best_time = ~0;
		__u64 last_active;

		/* Pick a specific core to handle SoftIRQ processing for this
		 * group of packets. The goal here is to spread load so that no
		 * core gets overloaded. We do that by checking the next several
		 * cores in order after this one, and choosing the one that
		 * hasn't done NAPI or SoftIRQ processing for Homa in the
		 * longest time.
		 */
		core = best = raw_smp_processor_id();
		for (i = 0; i < CORES_TO_CHECK; i++) {
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
		tt_record3("homa_gro_complete chose core %d for id %d "
				"offset %d with IDLE policy",
				best, homa_local_id(h->common.sender_id),
				ntohl(h->seg.offset));
	} else if (homa->gro_policy & HOMA_GRO_NEXT) {
		/* Use the next core (in circular order) to handle the
		 * SoftIRQ processing.
		 */
		int target = raw_smp_processor_id() + 1;
		if (unlikely(target >= nr_cpu_ids))
			target = 0;
		homa_set_softirq_cpu(skb, target);
		tt_record3("homa_gro_complete chose core %d for id %d "
				"offset %d with NEXT policy",
				target, homa_local_id(h->common.sender_id),
				ntohl(h->seg.offset));
	}

	return 0;
}
