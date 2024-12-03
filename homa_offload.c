// SPDX-License-Identifier: BSD-2-Clause

/* This file implements GSO (Generic Segmentation Offload) and GRO (Generic
 * Receive Offload) for Homa.
 */

#include "homa_impl.h"
#include "homa_offload.h"

DEFINE_PER_CPU(struct homa_offload_core, homa_offload_core);

#define CORES_TO_CHECK 4

static const struct net_offload homa_offload = {
	.callbacks = {
		.gso_segment	=	homa_gso_segment,
		.gro_receive	=	homa_gro_receive,
		.gro_complete	=	homa_gro_complete,
	},
};

/* Pointers to TCP's net_offload structures. NULL means homa_gro_hook_tcp
 * hasn't been called yet.
 */
static const struct net_offload *tcp_net_offload;
static const struct net_offload *tcp6_net_offload;

/*
 * Identical to *tcp_net_offload except that the gro_receive function
 * has been replaced.
 */
static struct net_offload hook_tcp_net_offload;
static struct net_offload hook_tcp6_net_offload;

/**
 * homa_offload_init() - Invoked to enable GRO and GSO. Typically invoked
 * when the Homa module loads.
 * Return: nonzero means error.
 */
int homa_offload_init(void)
{
	int i;

	for (i = 0; i < nr_cpu_ids; i++) {
		struct homa_offload_core *offload_core;
		int j;

		offload_core = &per_cpu(homa_offload_core, i);
		offload_core->last_active = 0;
		offload_core->last_gro = 0;
		atomic_set(&offload_core->softirq_backlog, 0);
		offload_core->softirq_offset = 0;
		offload_core->gen3_softirq_cores[0] = i ^ 1;
		for (j = 1; j < NUM_GEN3_SOFTIRQ_CORES; j++)
			offload_core->gen3_softirq_cores[j] = -1;
		offload_core->last_app_active = 0;
		offload_core->held_skb = NULL;
		offload_core->held_bucket = 0;
	}

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
	int res2 = inet6_del_offload(&homa_offload, IPPROTO_HOMA);
	int res1 = inet_del_offload(&homa_offload, IPPROTO_HOMA);

	return res1 ? res1 : res2;
}

/**
 * homa_gro_hook_tcp() - Arranges for TCP gro_receive calls to be
 * mediated by this file, so that Homa-over-TCP packets can be retrieved
 * and funneled through Homa.
 */
void homa_gro_hook_tcp(void)
{
	if (tcp_net_offload)
		return;

	pr_notice("Homa setting up TCP hijacking\n");
	tcp_net_offload = rcu_dereference(inet_offloads[IPPROTO_TCP]);
	hook_tcp_net_offload = *tcp_net_offload;
	hook_tcp_net_offload.callbacks.gro_receive = homa_tcp_gro_receive;
	inet_offloads[IPPROTO_TCP] = (struct net_offload __rcu *)
			&hook_tcp_net_offload;

	tcp6_net_offload = rcu_dereference(inet6_offloads[IPPROTO_TCP]);
	hook_tcp6_net_offload = *tcp6_net_offload;
	hook_tcp6_net_offload.callbacks.gro_receive = homa_tcp_gro_receive;
	inet6_offloads[IPPROTO_TCP] = (struct net_offload __rcu *)
			&hook_tcp6_net_offload;
}

/**
 * homa_gro_unhook_tcp() - Reverses the effects of a previous call to
 * homa_hook_tcp_gro, so that TCP packets are now passed directly to
 * Tcp's gro_receive function without mediation.
 */
void homa_gro_unhook_tcp(void)
{
	if (!tcp_net_offload)
		return;
	pr_notice("Homa cancelling TCP hijacking\n");
	inet_offloads[IPPROTO_TCP] = (struct net_offload __rcu *)
			tcp_net_offload;
	tcp_net_offload = NULL;
	inet6_offloads[IPPROTO_TCP] = (struct net_offload __rcu *)
			tcp6_net_offload;
	tcp6_net_offload = NULL;
}

/**
 * homa_tcp_gro_receive() - Invoked instead of TCP's normal gro_receive function
 * when hooking is enabled. Identifies Homa-over-TCP packets and passes them
 * to Homa; sends real TCP packets to TCP's gro_receive function.
 * @held_list:  Pointer to header for list of packets that are being
 *              held for possible GRO merging.
 * @skb:        The newly arrived packet.
 */
struct sk_buff *homa_tcp_gro_receive(struct list_head *held_list,
				     struct sk_buff *skb)
{
	struct common_header *h = (struct common_header *)
			skb_transport_header(skb);

	// tt_record4("homa_tcp_gro_receive got type 0x%x, flags 0x%x, "
	//		"urgent 0x%x, id %d", h->type, h->flags,
	//		ntohs(h->urgent), homa_local_id(h->sender_id));
	if (h->flags != HOMA_TCP_FLAGS ||
	    ntohs(h->urgent) != HOMA_TCP_URGENT)
		return tcp_net_offload->callbacks.gro_receive(held_list, skb);

	/* Change the packet's IP protocol to Homa so that it will get
	 * dispatched directly to Homa in the future.
	 */
	if (skb_is_ipv6(skb)) {
		ipv6_hdr(skb)->nexthdr = IPPROTO_HOMA;
	} else {
		ip_hdr(skb)->check = ~csum16_add(csum16_sub(~ip_hdr(skb)->check,
							    htons(ip_hdr(skb)->protocol)),
						 htons(IPPROTO_HOMA));
		ip_hdr(skb)->protocol = IPPROTO_HOMA;
	}
	return homa_gro_receive(held_list, skb);
}

/**
 * homa_set_softirq_cpu() - Arrange for SoftIRQ processing of a packet to
 * occur on a specific core (creates a socket flow table entry for the core,
 * and sets the packet's hash to map to the given entry).
 * @skb:  Incoming packet
 * @cpu:  Index of core to which the packet should be directed for
 *        SoftIRQ processing.
 */
static void homa_set_softirq_cpu(struct sk_buff *skb, int cpu)
{
	struct rps_sock_flow_table *sock_flow_table;
	int hash;

	sock_flow_table = rcu_dereference(net_hotdata.rps_sock_flow_table);
	if (!sock_flow_table)
		return;
	hash = cpu + net_hotdata.rps_cpu_mask + 1;
	if (sock_flow_table->ents[hash] != hash) {
		rcu_read_lock();
		sock_flow_table = rcu_dereference(net_hotdata.rps_sock_flow_table);
		sock_flow_table->ents[hash] = hash;
		rcu_read_unlock();
	}
	__skb_set_sw_hash(skb, hash, false);
}

/**
 * homa_send_ipis() - If there are any interprocessor interrupts pending
 * from this core to others (for packets queued for SoftIRQ processing)
 * issue those interrupts now. This function is needed because calling
 * netif_receive_skb doesn't actually issue IPIs; it queues them until
 * all NAPI processing is finished, and this could be a long time if a
 * lot more packets are available for processing.
 */
void homa_send_ipis(void)
{
#if defined(CONFIG_RPS) && !defined(__UNIT_TEST__)
	/* This function duplicates the code from net_rps_send_ipi because
	 * we can't call that function from here.
	 */
	struct softnet_data *sd = this_cpu_ptr(&softnet_data);
	struct softnet_data *remsd;

	local_irq_disable();
	remsd = sd->rps_ipi_list;
	sd->rps_ipi_list = NULL;
	local_irq_enable();

	while (remsd) {
		struct softnet_data *next = remsd->rps_ipi_next;

		if (cpu_online(remsd->cpu))
			smp_call_function_single_async(remsd->cpu, &remsd->csd);
		remsd = next;
	}
#endif
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
			- sizeof(struct seg_header));
	segs = skb_segment(skb, features);

	/* Set incrementing ids in each of the segments (mimics behavior
	 * of Mellanox NICs and other segmenters).
	 */
	if (ip_hdr(segs)->version == 4) {
		struct sk_buff *seg;
		int i = 0;

		for (seg = segs; seg; seg = seg->next) {
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
	__u64 saved_softirq_metric, softirq_ns;
	struct homa_offload_core *offload_core;
	struct homa *homa = global_homa;
	struct sk_buff *result = NULL;
	__u64 *softirq_ns_metric;
	struct data_header *h_new;
	struct sk_buff *held_skb;
	__u64 now = sched_clock();
	int priority;
	__u32 saddr;
	__u32 hash;
	int busy;

	h_new = (struct data_header *)skb_transport_header(skb);
	offload_core = &per_cpu(homa_offload_core, raw_smp_processor_id());
	busy = (now - offload_core->last_gro) < homa->gro_busy_ns;
	offload_core->last_active = now;
	if (skb_is_ipv6(skb)) {
		priority = ipv6_hdr(skb)->priority;
		saddr = ntohl(ipv6_hdr(skb)->saddr.in6_u.u6_addr32[3]);
	} else {
		priority = ((struct iphdr *)skb_network_header(skb))->tos >> 5;
		saddr = ntohl(ip_hdr(skb)->saddr);
	}

//      The test below is overly conservative except for data packets.
//	if (!pskb_may_pull(skb, 64))
//		tt_record("homa_gro_receive can't pull enough data "
//				"from packet for trace");
	if (h_new->common.type == DATA) {
		if (h_new->seg.offset == (__force __be32)-1) {
			tt_record2("homa_gro_receive replaced offset %d with %d",
				   ntohl(h_new->seg.offset),
				   ntohl(h_new->common.sequence));
			h_new->seg.offset = h_new->common.sequence;
		}
		tt_record4("homa_gro_receive got packet from 0x%x id %llu, offset %d, priority %d",
			   saddr, homa_local_id(h_new->common.sender_id),
			   ntohl(h_new->seg.offset), priority);
		if (homa_data_len(skb) == ntohl(h_new->message_length) &&
		    (homa->gro_policy & HOMA_GRO_SHORT_BYPASS) &&
		    !busy) {
			INC_METRIC(gro_data_bypasses, 1);
			goto bypass;
		}
	} else if (h_new->common.type == GRANT) {
		tt_record4("homa_gro_receive got grant from 0x%x id %llu, offset %d, priority %d",
			   saddr, homa_local_id(h_new->common.sender_id),
			   ntohl(((struct grant_header *)h_new)->offset),
			   priority);
		/* The following optimization handles grants here at NAPI
		 * level, bypassing the SoftIRQ mechanism (and avoiding the
		 * delay of handing off to a different core). This makes
		 * a significant difference in throughput for large
		 * messages, especially when the system is loaded.
		 */
		if ((homa->gro_policy & HOMA_GRO_FAST_GRANTS) && !busy) {
			INC_METRIC(gro_grant_bypasses, 1);
			goto bypass;
		}
	} else {
		tt_record4("homa_gro_receive got packet from 0x%x id %llu, type 0x%x, priority %d",
			   saddr, homa_local_id(h_new->common.sender_id),
			   h_new->common.type, priority);
	}

	/* The GRO mechanism tries to separate packets onto different
	 * gro_lists by hash. This is bad for us, because we want to batch
	 * packets together regardless of their RPCs. So, instead of
	 * checking the list they gave us, check the last list where this
	 * core added a Homa packet (if there is such a list).
	 */
	hash = skb_get_hash_raw(skb) & (GRO_HASH_BUCKETS - 1);
	if (offload_core->held_skb) {
		/* Reverse-engineer the location of the napi_struct, so we
		 * can verify that held_skb is still valid.
		 */
		struct gro_list *gro_list = container_of(held_list,
				struct gro_list, list);
		struct napi_struct *napi = container_of(gro_list,
				struct napi_struct, gro_hash[hash]);

		/* Must verify that offload_core->held_skb points to a packet on
		 * the list, and that the packet is a Homa packet.
		 * homa_gro_complete isn't always invoked before removing
		 * packets from the list, so offload_core->held_skb could be a
		 * dangling pointer (or the skb could have been reused for
		 * some other protocol).
		 */
		list_for_each_entry(held_skb,
				    &napi->gro_hash[offload_core->held_bucket].list,
				    list) {
			int protocol;

			if (held_skb != offload_core->held_skb)
				continue;
			if (skb_is_ipv6(held_skb))
				protocol = ipv6_hdr(held_skb)->nexthdr;
			else
				protocol = ip_hdr(held_skb)->protocol;
			if (protocol != IPPROTO_HOMA) {
				tt_record3("homa_gro_receive held_skb 0x%0x%0x isn't Homa: protocol %d",
					   SPLIT_64(held_skb), protocol);
				continue;
			}

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
				homa_send_ipis();
				napi->gro_hash[offload_core->held_bucket].count--;
				if (napi->gro_hash[offload_core->held_bucket].count == 0)
					__clear_bit(offload_core->held_bucket,
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
	offload_core->held_skb = skb;
	offload_core->held_bucket = hash;
	if (likely(homa->gro_policy & HOMA_GRO_SAME_CORE))
		homa_set_softirq_cpu(skb, raw_smp_processor_id());

done:
	homa_check_pacer(homa, 1);
	offload_core->last_gro = sched_clock();
	return result;

bypass:
	/* Record SoftIRQ cycles in a different metric to reflect that
	 * they happened during bypass.
	 */
	softirq_ns_metric = &homa_metrics_per_cpu()->softirq_ns;
	saved_softirq_metric = *softirq_ns_metric;
	homa_softirq(skb);
	softirq_ns = *softirq_ns_metric - saved_softirq_metric;
	*softirq_ns_metric = saved_softirq_metric;
	INC_METRIC(bypass_softirq_ns, softirq_ns);
	offload_core->last_gro = sched_clock();

	/* This return value indicates that we have freed skb. */
	return ERR_PTR(-EINPROGRESS);
}

/**
 * homa_gro_gen2() - When the Gen2 load balancer is being used this function
 * is invoked by homa_gro_complete to choose a core to handle SoftIRQ for a
 * batch of packets
 * @homa:    Overall information about the Homa transport.
 * @skb:     First in a group of packets that are ready to be passed to SoftIRQ.
 *           Information will be updated in the packet so that Linux will
 *           direct it to the chosen core.
 */
void homa_gro_gen2(struct homa *homa, struct sk_buff *skb)
{
	/* Scan the next several cores in order after the current core,
	 * trying to find one that is not already busy with SoftIRQ processing,
	 * and that doesn't appear to be active with NAPI/GRO processing
	 * either. If there is no such core, just rotate among the next
	 * cores. See balance.txt for overall design information on load
	 * balancing.
	 */
	struct data_header *h = (struct data_header *)skb_transport_header(skb);
	int this_core = raw_smp_processor_id();
	struct homa_offload_core *offload_core;
	int candidate = this_core;
	__u64 now = sched_clock();
	int i;

	for (i = CORES_TO_CHECK; i > 0; i--) {
		candidate++;
		if (unlikely(candidate >= nr_cpu_ids))
			candidate = 0;
		offload_core = &per_cpu(homa_offload_core, candidate);
		if (atomic_read(&offload_core->softirq_backlog)  > 0)
			continue;
		if ((offload_core->last_gro + homa->busy_ns) > now)
			continue;
		tt_record3("homa_gro_gen2 chose core %d for id %d offset %d",
			   candidate, homa_local_id(h->common.sender_id),
			   ntohl(h->seg.offset));
		break;
	}
	if (i <= 0) {
		/* All of the candidates appear to be busy; just
		 * rotate among them.
		 */
		int offset = per_cpu(homa_offload_core, this_core).softirq_offset;

		offset += 1;
		if (offset > CORES_TO_CHECK)
			offset = 1;
		per_cpu(homa_offload_core, this_core).softirq_offset = offset;
		candidate = this_core + offset;
		while (candidate >= nr_cpu_ids)
			candidate -= nr_cpu_ids;
		tt_record3("homa_gro_gen2 chose core %d for id %d offset %d (all cores busy)",
			   candidate, homa_local_id(h->common.sender_id),
			   ntohl(h->seg.offset));
	}
	atomic_inc(&per_cpu(homa_offload_core, candidate).softirq_backlog);
	homa_set_softirq_cpu(skb, candidate);
}

/**
 * homa_gro_gen3() - When the Gen3 load balancer is being used this function
 * is invoked by homa_gro_complete to choose a core to handle SoftIRQ for a
 * batch of packets
 * @homa:    Overall information about the Homa transport.
 * @skb:     First in a group of packets that are ready to be passed to SoftIRQ.
 *           Information will be updated in the packet so that Linux will
 *           direct it to the chosen core.
 */
void homa_gro_gen3(struct homa *homa, struct sk_buff *skb)
{
	/* See balance.txt for overall design information on the Gen3
	 * load balancer.
	 */
	struct data_header *h = (struct data_header *)skb_transport_header(skb);
	__u64 now, busy_time;
	int *candidates;
	int i, core;

	candidates = per_cpu(homa_offload_core,
			     raw_smp_processor_id()).gen3_softirq_cores;
	now = sched_clock();
	busy_time = now - homa->busy_ns;

	core = candidates[0];
	for (i = 0; i <  NUM_GEN3_SOFTIRQ_CORES; i++) {
		int candidate = candidates[i];

		if (candidate < 0)
			break;
		if (per_cpu(homa_offload_core, candidate).last_app_active
				< busy_time) {
			core = candidate;
			break;
		}
	}
	homa_set_softirq_cpu(skb, core);
	per_cpu(homa_offload_core, core).last_active = now;
	tt_record4("homa_gro_gen3 chose core %d for id %d, offset %d, delta %d",
		   core, homa_local_id(h->common.sender_id),
		   ntohl(h->seg.offset),
		   now - per_cpu(homa_offload_core, core).last_app_active);
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
	struct data_header *h = (struct data_header *)skb_transport_header(skb);
	struct homa *homa = global_homa;

	// tt_record4("homa_gro_complete type %d, id %d, offset %d, count %d",
	//		h->common.type, homa_local_id(h->common.sender_id),
	//		ntohl(h->seg.offset),
	//		NAPI_GRO_CB(skb)->count);

	per_cpu(homa_offload_core, raw_smp_processor_id()).held_skb = NULL;
	if (homa->gro_policy & HOMA_GRO_GEN3) {
		homa_gro_gen3(homa, skb);
	} else if (homa->gro_policy & HOMA_GRO_GEN2) {
		homa_gro_gen2(homa, skb);
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
		best = raw_smp_processor_id();
		core = best;
		for (i = 0; i < CORES_TO_CHECK; i++) {
			core++;
			if (unlikely(core >= nr_cpu_ids))
				core = 0;
			last_active = per_cpu(homa_offload_core, core).last_active;
			if (last_active < best_time) {
				best_time = last_active;
				best = core;
			}
		}
		homa_set_softirq_cpu(skb, best);
		tt_record3("homa_gro_complete chose core %d for id %d offset %d with IDLE policy",
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
		tt_record3("homa_gro_complete chose core %d for id %d offset %d with NEXT policy",
			   target, homa_local_id(h->common.sender_id),
			   ntohl(h->seg.offset));
	}

	return 0;
}
