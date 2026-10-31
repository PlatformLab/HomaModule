// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

/* This file implements GRO (Generic Receive Offload) for Homa packets that
 * travel inside UDP (outer ports HOMA_UDP_PORT). The kernel's UDP GRO code
 * (udp4_gro_receive/udp6_gro_receive) finds the namespace's Homa tunnel
 * socket and calls homa_udp_gro_receive with the GRO cursor already past the
 * UDP header; homa_udp_gro_complete is called by udp_gro_complete when an
 * aggregate is released.
 *
 * Homa does GRO in an unusual way, unchanged from earlier versions of Homa
 * that did not run over UDP: it aggregates all packets that arrive in one
 * NAPI cycle, regardless of RPC, packet type, or sender, by chaining them on
 * the frag_list of the first packet (the "held" packet), so that the whole
 * batch traverses the network stack once. The per-core held packet may live
 * in a different GRO hash bucket than the one the kernel passes to the
 * callback. homa_softirq splits the batch apart again and regroups it by RPC.
 *
 * Contract between GRO and receive dispatch (homa_udp_encap_rcv and
 * homa_softirq). Transmit segmentation does not use this file: it is done by
 * the kernel's UDP L4 segmenter on frames that Homa pre-built.
 *
 * - Head of a batch. An ordinary UDP datagram that carries a frag_list.
 *   Its len, data_len, truesize, IP total length and UDP length describe only
 *   the head's own datagram; the children are NOT accounted for in any of
 *   them. gso_size, gso_segs and gso_type are 0 and encapsulation is 0
 *   (homa_gro_complete clears what the kernel's tunnel completion set: a
 *   nonzero gso_size with a type other than UDP_TUNNEL[_CSUM] would make
 *   udp_unexpected_gso() resegment the datagram, and SKB_GSO_UDP_L4 must
 *   never be set for the same reason). The UDP checksum field is nonzero
 *   (the kernel's completion leaves a nonzero folded pseudo-header sum in
 *   it). The checksum was verified before encap_rcv runs; ip_summed then
 *   depends on the NIC and the GRO/UDP receive path (for example
 *   CHECKSUM_UNNECESSARY, or CHECKSUM_COMPLETE with csum_valid set after
 *   software verification or conversion in udp_unicast_rcv_skb) and Homa
 *   ignores it from then on. Once the IP layer has delivered it, data points
 *   at the UDP header when encap_rcv is called.
 * - frag_list. Children are linked through ->next in arrival order, NULL
 *   terminated. Receive must detach the list (homa_softirq does) before
 *   handling or freeing the children individually; freeing the head with the
 *   list attached frees every child.
 * - Child. The untouched skb as it was handed to the tunnel callback: data
 *   at the start of the IP header, len covering the whole IP datagram
 *   (len == IP total length, because GRO flushes on any mismatch), network
 *   header at the IP header, transport header at the UDP header (so
 *   skb_transport_offset() is the IP header length), skb->dev and protocol
 *   set, sk == NULL, no destructor, stale NAPI_GRO_CB in skb->cb (do not
 *   interpret). The UDP header is still present and has both ports equal to
 *   HOMA_UDP_PORT, a nonzero checksum, a length equal to len minus the IP
 *   header length, and at least the type's header length (the common header
 *   for types other than DATA, GRANT and START_MSG) behind it. The UDP
 *   checksum was validated by GRO; Homa does not use ip_summed.
 *   Receive must still pskb_may_pull before touching bytes beyond the
 *   headers, remove the IP and UDP headers from each child with __skb_pull
 *   and reset its transport header; the network header stays valid for
 *   skb_canonical_ipv6_saddr().
 * - A batch contains only packets with the same netns, protocol family and
 *   destination address as its head, because children skip the IP layer and
 *   inherit the head's routing/local-delivery decision and Homa's netns.
 * - A packet that is not mergeable (flush set by IP/UDP GRO, malformed UDP or
 *   Homa header, ...) is flushed and reaches encap_rcv as an ordinary
 *   single datagram with no frag_list, so receive handles that case with the
 *   same code.
 */

#include "homa_impl.h"
#include "homa_offload.h"
#include "homa_qdisc.h"
#include "homa_udp_tunnel.h"
#include <net/udp.h>

DEFINE_PER_CPU(struct homa_offload_core, homa_offload_core);

#define CORES_TO_CHECK 4

/**
 * homa_offload_init() - Initializes the per-core GRO state. Typically
 * invoked when the Homa module loads. The tunnel GRO callbacks themselves
 * are installed with the namespace tunnel sockets (see homa_udp_init), not
 * here.
 * Return: Always zero.
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
	return 0;
}

/**
 * homa_offload_end() - Discards per-core references to held packets;
 * typically invoked during Homa module unloading. The caller must already
 * have removed and quiesced the tunnel sockets, which stops further GRO
 * callbacks.
 * Return: Always zero.
 */
int homa_offload_end(void)
{
	int i;

	for (i = 0; i < nr_cpu_ids; i++)
		per_cpu(homa_offload_core, i).held_skb = NULL;
	return 0;
}

/**
 * homa_set_softirq_cpu() - Arrange for SoftIRQ processing of a packet to
 * occur on a specific core (creates a socket flow table entry for the core,
 * and sets the packet's hash to map to the given entry).
 * @skb:  Incoming packet
 * @cpu:  Index of core to which the packet should be directed for
 *        SoftIRQ processing.
 */
void homa_set_softirq_cpu(struct sk_buff *skb, int cpu)
{
	struct rps_sock_flow_table *sock_flow_table;
	int hash;

	rcu_read_lock();
	sock_flow_table = rcu_dereference(net_hotdata.rps_sock_flow_table);
	if (sock_flow_table) {
		hash = cpu + net_hotdata.rps_cpu_mask + 1;
		if (sock_flow_table->ents[hash] != hash) {
			sock_flow_table = rcu_dereference(net_hotdata.rps_sock_flow_table);
			sock_flow_table->ents[hash] = hash;
		}
		__skb_set_sw_hash(skb, hash, false);
	}
	rcu_read_unlock();
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
 * homa_gro_hdr() - Locate the Homa header of a packet that has been through
 * homa_udp_gro_receive.
 * @skb:   Packet whose transport header is the UDP header (as set by the IP
 *         GRO layer) and whose Homa header was made linear by
 *         homa_udp_gro_receive.
 * Return: Pointer to the Homa header; only the fields that
 *         homa_udp_gro_receive validated may be used.
 */
static struct homa_data_hdr *homa_gro_hdr(struct sk_buff *skb)
{
	return (struct homa_data_hdr *)(skb_transport_header(skb) +
			sizeof(struct udphdr));
}

/**
 * homa_gro_tt_offset() - Offset to report in timetrace records for a packet.
 * @h:   Homa header of the packet.
 * Return: The byte offset for DATA packets, 0 for other types (which don't
 *         have a long enough header to contain one).
 */
static u32 homa_gro_tt_offset(struct homa_data_hdr *h)
{
	return h->common.type == DATA ? ntohl(h->seg.offset) : 0;
}

/**
 * homa_gro_hdrs_ok() - Make a UDP-encapsulated Homa packet's headers
 * linear and check that it is safe to put into a batch. Children skip the IP
 * and UDP receive layers, so packets that fail must not be batched; receive
 * dispatch still re-checks every member and drops a malformed child on its
 * own.
 * @skb:   Incoming packet.
 * @off:   skb_gro_offset(skb): offset of the Homa header from skb->data
 *         (the UDP header ends there).
 * Return: True if the UDP header (both ports HOMA_UDP_PORT, nonzero
 *         checksum, length consistent with the buffer) and the Homa
 *         header (long enough for its type) are present and valid; false
 *         otherwise.
 */
static bool homa_gro_hdrs_ok(struct sk_buff *skb, unsigned int off)
{
	struct homa_common_hdr *c;
	unsigned int pull, min_len;
	struct udphdr *uh;

	if (off < sizeof(*uh) || off > skb->len ||
	    skb->len - off < sizeof(*c))
		return false;
	pull = off + HOMA_MAX_HEADER;
	if (pull > skb->len)
		pull = skb->len;
	if (!pskb_may_pull(skb, pull))
		return false;
	uh = (struct udphdr *)(skb->data + off - sizeof(*uh));
	c = (struct homa_common_hdr *)(skb->data + off);
	if (uh->source != htons(HOMA_UDP_PORT) ||
	    uh->dest != htons(HOMA_UDP_PORT) || !uh->check ||
	    ntohs(uh->len) != skb->len - off + sizeof(*uh))
		return false;
	switch (c->type) {
	case DATA:
		min_len = sizeof(struct homa_data_hdr);
		break;
	case GRANT:
		min_len = sizeof(struct homa_grant_hdr);
		break;
	case START_MSG:
		min_len = sizeof(struct homa_start_msg_hdr);
		break;
	default:
		min_len = sizeof(*c);
		break;
	}
	return skb->len - off >= min_len;
}

/**
 * homa_gro_can_merge() - Decide whether a new packet may be appended to the
 * frag_list of a held packet. The held packet may have been put in the GRO
 * list by anything, so it is not trusted to be a Homa packet.
 * @held:  Candidate head of a batch, known to be on a GRO list.
 * @skb:   New packet that has passed homa_gro_hdrs_ok.
 * Return: True if @skb can join the batch. Children skip the IP layer, so
 *         they must be in the same namespace (Homa state is per namespace)
 *         and addressed to the same destination as the head, whose routing
 *         and local-delivery decision they inherit.
 */
static bool homa_gro_can_merge(struct sk_buff *held, struct sk_buff *skb)
{
	struct udphdr *uh;

	if (held->protocol != skb->protocol ||
	    !net_eq(dev_net(held->dev), dev_net(skb->dev)) ||
	    skb_headlen(held) < skb_transport_offset(held) + sizeof(*uh))
		return false;
	if (skb_is_ipv6(held)) {
		if (ipv6_hdr(held)->nexthdr != IPPROTO_UDP ||
		    !ipv6_addr_equal(&ipv6_hdr(held)->daddr,
				     &ipv6_hdr(skb)->daddr))
			return false;
	} else {
		if (ip_hdr(held)->protocol != IPPROTO_UDP ||
		    ip_hdr(held)->daddr != ip_hdr(skb)->daddr)
			return false;
	}
	uh = (struct udphdr *)skb_transport_header(held);
	return uh->source == htons(HOMA_UDP_PORT) &&
	       uh->dest == htons(HOMA_UDP_PORT);
}

/**
 * homa_udp_gro_receive() - UDP tunnel gro_receive callback; invoked for each
 * Homa packet that reaches the namespace tunnel socket at a very low level
 * in the stack to perform GRO. However, this code does GRO in an unusual
 * way: it simply aggregates all packets arriving on a core, so that the
 * entire bundle can get through the networking stack in a single traversal.
 * @sk:         Namespace-owned Homa tunnel socket (sk_user_data is the
 *              struct homa_net; it may already be NULL during shutdown).
 * @held_list:  Pointer to header for list of packets that are being
 *              held for possible GRO merging. Note: this list contains
 *              only packets matching a given hash.
 * @skb:        The newly arrived packet. The UDP layer has already pulled
 *              the UDP header with skb_gro_pull (skb->data still points at
 *              the IP header) and has validated or trusted its checksum.
 *
 * Return: NULL means @skb was either flushed (NAPI_GRO_CB(skb)->flush is
 * set and it continues up the stack by itself as an ordinary datagram),
 * merged into a held packet (NAPI_GRO_CB(skb)->same_flow is set), or is
 * left for the caller to add to the GRO list. ERR_PTR(-EINPROGRESS) means
 * this function consumed @skb itself (the caller must not touch it again),
 * either because it was a bypass packet processed immediately or because the
 * merge completed a batch that was pushed up the stack from here. Never
 * returns a non-NULL pointer to a packet, because the generic
 * "release the returned packet" step would decrement the wrong bucket's
 * count when the held packet is in another bucket. See the file comment for
 * the layout of the resulting batch.
 */
struct sk_buff *homa_udp_gro_receive(struct sock *sk,
				     struct list_head *held_list,
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
	 * 4. Consume skb directly (bypass), returning -EINPROGRESS.
	 */
	u64 saved_softirq_metric, softirq_cycles;
	struct homa_offload_core *offload_core;
	struct sk_buff *result = NULL;
	struct homa_data_hdr *h_new;
	u64 *softirq_cycles_metric;
	unsigned int off = skb_gro_offset(skb);
	struct sk_buff *held_skb;
	u64 now = homa_clock();
	struct homa_net *hnet;
	struct homa *homa;
	int priority;
	u32 saddr;
	u32 hash;
	int busy;

	rcu_read_lock();
	hnet = sk ? rcu_dereference_sk_user_data(sk) : NULL;
	if (!hnet || NAPI_GRO_CB(skb)->flush || !homa_gro_hdrs_ok(skb, off))
		goto flush;
	homa = hnet->homa;

	h_new = (struct homa_data_hdr *)(skb->data + off);
	offload_core = &per_cpu(homa_offload_core, smp_processor_id());
	busy = (now - offload_core->last_gro) < homa->gro_busy_cycles;
	offload_core->last_active = now;
	if (skb_is_ipv6(skb)) {
		priority = ipv6_hdr(skb)->priority;
		saddr = ntohl(ipv6_hdr(skb)->saddr.in6_u.u6_addr32[3]);
	} else {
		priority = ((struct iphdr *)skb_network_header(skb))->tos >> 5;
		saddr = ntohl(ip_hdr(skb)->saddr);
	}

	if (h_new->common.type == DATA) {
		tt_record4("homa_gro_receive got packet from 0x%x id %llu, offset %d, priority %d",
			   saddr, homa_local_id(h_new->common.sender_id),
			   ntohl(h_new->seg.offset), priority);
		if (skb->len - off - sizeof(struct homa_data_hdr) ==
		    ntohl(h_new->msg_length) &&
		    (homa->gro_policy & HOMA_GRO_SHORT_BYPASS) &&
		    !busy) {
			INC_METRIC(gro_data_bypasses, 1);
			goto bypass;
		}
	} else if (h_new->common.type == GRANT) {
		tt_record4("homa_gro_receive got grant from 0x%x id %llu, offset %d, priority %d",
			   saddr, homa_local_id(h_new->common.sender_id),
			   ntohl(((struct homa_grant_hdr *)h_new)->offset),
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
#ifndef __STRIP__ /* See strip.py */
	} else if (h_new->common.type == START_MSG) {
		tt_record3("homa_gro_receive got START_MSG from 0x%x, id %llu, msg_length %d",
			   saddr, homa_local_id(h_new->common.sender_id),
			   ntohl(((struct homa_start_msg_hdr *)h_new)->msg_length));
	} else {
		tt_record4("homa_gro_receive got packet from 0x%x id %llu, type 0x%x, priority %d",
			   saddr, homa_local_id(h_new->common.sender_id),
			   h_new->common.type, priority);
#endif /* See strip.py */
	}

	/* The GRO mechanism tries to separate packets onto different
	 * gro_lists by hash. This is bad for us, because we want to batch
	 * packets together regardless of their RPCs. So, instead of
	 * checking the list they gave us, check the last list where this
	 * core added a Homa packet (if there is such a list).
	 */
	hash = skb_get_hash_raw(skb) & (GRO_HASH_BUCKETS - 1);
	if (offload_core->held_skb) {
		/* Reverse-engineer the location of the gro_node, so we
		 * can verify that held_skb is still valid.
		 */
		struct gro_list *gro_list = container_of(held_list,
				struct gro_list, list);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
		struct napi_struct *napi = container_of(gro_list,
				struct napi_struct, gro_hash[hash]);
#else
		struct gro_node *gro_node = container_of(gro_list,
				struct gro_node, hash[hash]);
#endif

		/* Must verify that offload_core->held_skb points to a packet on
		 * the list, and that the packet is a Homa packet that skb may
		 * join. homa_gro_complete isn't always invoked before removing
		 * packets from the list, so offload_core->held_skb could be a
		 * dangling pointer (or the skb could have been reused for
		 * some other protocol).
		 */
		list_for_each_entry(held_skb,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
				    &napi->gro_hash[offload_core->held_bucket].list,
#else
				    &gro_node->hash[offload_core->held_bucket].list,
#endif
				    list) {
			if (held_skb != offload_core->held_skb)
				continue;
			if (!homa_gro_can_merge(held_skb, skb)) {
				tt_record2("homa_gro_receive held_skb 0x%0x%0x can't be merged with new packet",
					   tt_hi(held_skb), tt_lo(held_skb));
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
				 * gro_node->rx_list. This code basically steals
				 * the packet from dev_gro_receive and
				 * pushes it upward. The UDP/IP completion
				 * callbacks are not needed: the head's headers
				 * already describe just the head, and
				 * homa_gro_complete clears the GSO state that
				 * dev_gro_receive set for it.
				 */
				skb_list_del_init(held_skb);
				homa_gro_complete(held_skb);
				netif_receive_skb(held_skb);
				homa_send_ipis();
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
				napi->gro_hash[offload_core->held_bucket].count--;
				if (napi->gro_hash[offload_core->held_bucket].count == 0)
					__clear_bit(offload_core->held_bucket,
						    &napi->gro_bitmask);
#else
				gro_node->hash[offload_core->held_bucket].count--;
				if (gro_node->hash[offload_core->held_bucket].count == 0)
					__clear_bit(offload_core->held_bucket,
						    &gro_node->bitmask);
#endif
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
		homa_set_softirq_cpu(skb, smp_processor_id());

done:
	homa_qdisc_pacer_check(homa);
	offload_core->last_gro = homa_clock();
	rcu_read_unlock();
	return result;

flush:
	NAPI_GRO_CB(skb)->flush = 1;
	rcu_read_unlock();
	return NULL;

bypass:
	/* Record SoftIRQ cycles in a different metric to reflect that
	 * they happened during bypass. The packet goes through the UDP
	 * receive callback (which strips the UDP header) rather than
	 * homa_softirq directly; it still has its IP header at skb->data.
	 */
	softirq_cycles_metric = &homa_metrics_per_cpu()->softirq_cycles;
	saved_softirq_metric = *softirq_cycles_metric;
	homa_udp_encap_rcv(sk, skb);
	softirq_cycles = *softirq_cycles_metric - saved_softirq_metric;
	*softirq_cycles_metric = saved_softirq_metric;
	INC_METRIC(bypass_softirq_cycles, softirq_cycles);
	offload_core->last_gro = homa_clock();
	rcu_read_unlock();

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
	struct homa_data_hdr *h = homa_gro_hdr(skb);
	struct homa_offload_core *offload_core;
	int this_core = smp_processor_id();
	int candidate = this_core;
	u64 now = homa_clock();
	int i;

	for (i = CORES_TO_CHECK; i > 0; i--) {
		candidate++;
		if (unlikely(candidate >= nr_cpu_ids))
			candidate = 0;
		offload_core = &per_cpu(homa_offload_core, candidate);
		if (atomic_read(&offload_core->softirq_backlog)  > 0)
			continue;
		if ((offload_core->last_gro + homa->busy_cycles) > now)
			continue;
		tt_record3("homa_gro_gen2 chose core %d for id %d offset %d",
			   candidate, homa_local_id(h->common.sender_id),
			   homa_gro_tt_offset(h));
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
			   homa_gro_tt_offset(h));
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
	struct homa_data_hdr *h = homa_gro_hdr(skb);
	u64 now, busy_time;
	int *candidates;
	int i, core;

	candidates = per_cpu(homa_offload_core,
			     smp_processor_id()).gen3_softirq_cores;
	now = homa_clock();
	busy_time = now - homa->busy_cycles;

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
		   homa_gro_tt_offset(h),
		   now - per_cpu(homa_offload_core, core).last_app_active);
	INC_METRIC(gen3_handoffs, 1);
	if (core != candidates[0])
		INC_METRIC(gen3_alt_handoffs, 1);
}

/**
 * homa_gro_complete() - This function is invoked just before a packet that
 * was held for GRO processing is passed up the network stack. It chooses the
 * core that will run SoftIRQ for the batch and turns the head back into
 * an ordinary datagram (see the file comment).
 * @skb:     The packet for which GRO processing is now finished. Its
 *           transport header must be the UDP header.
 *
 * Return:   Always returns 0, signifying success.
 */
int homa_gro_complete(struct sk_buff *skb)
{
	struct homa_data_hdr *h = homa_gro_hdr(skb);
	struct homa *homa = homa_net(dev_net(skb->dev))->homa;

	per_cpu(homa_offload_core, smp_processor_id()).held_skb = NULL;

	/* The children are not accounted for in the head, so the head must
	 * not look like a GSO/tunnel aggregate to the UDP receive path.
	 */
	skb_shinfo(skb)->gso_type = 0;
	skb_shinfo(skb)->gso_size = 0;
	skb_shinfo(skb)->gso_segs = 0;
	skb->encapsulation = 0;

	if (homa->gro_policy & HOMA_GRO_GEN3) {
		homa_gro_gen3(homa, skb);
	} else if (homa->gro_policy & HOMA_GRO_GEN2) {
		homa_gro_gen2(homa, skb);
	} else if (homa->gro_policy & HOMA_GRO_IDLE) {
		int i, core, best;
		u64 best_time = ~0;
		u64 last_active;

		/* Pick a specific core to handle SoftIRQ processing for this
		 * group of packets. The goal here is to spread load so that no
		 * core gets overloaded. We do that by checking the next several
		 * cores in order after this one, and choosing the one that
		 * hasn't done NAPI or SoftIRQ processing for Homa in the
		 * longest time.
		 */
		best = smp_processor_id();
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
			   homa_gro_tt_offset(h));
	} else if (homa->gro_policy & HOMA_GRO_NEXT) {
		/* Use the next core (in circular order) to handle the
		 * SoftIRQ processing.
		 */
		int target = smp_processor_id() + 1;

		if (unlikely(target >= nr_cpu_ids))
			target = 0;
		homa_set_softirq_cpu(skb, target);
		tt_record3("homa_gro_complete chose core %d for id %d offset %d with NEXT policy",
			   target, homa_local_id(h->common.sender_id),
			   homa_gro_tt_offset(h));
	}

	return 0;
}

/**
 * homa_udp_gro_complete() - UDP tunnel gro_complete callback; invoked by
 * udp_gro_complete (after the outer UDP/IP completion has run) for a batch
 * with more than one packet, just before it is passed up the stack. The
 * kernel's completion code computes the IP total length and UDP length from
 * skb->len, which does not include the frag_list children (Homa never
 * calls skb_gro_receive), so it leaves them describing only the head;
 * nothing here or in the kernel changes the head's len, data_len or
 * truesize, and homa_udp_encap_rcv relies on that.
 * @sk:     Namespace-owned Homa tunnel socket.
 * @skb:    Head of the batch.
 * @nhoff:  Offset from skb->data of the Homa header (just past the UDP
 *          header).
 *
 * Return:  0 on success. A negative errno makes the caller free the whole
 *          batch, which is correct when the namespace is going away
 *          (-ENODEV) or the offset is impossible (-EINVAL).
 */
int homa_udp_gro_complete(struct sock *sk, struct sk_buff *skb, int nhoff)
{
	struct homa_net *hnet;
	int result;

	rcu_read_lock();
	hnet = sk ? rcu_dereference_sk_user_data(sk) : NULL;
	if (!hnet) {
		per_cpu(homa_offload_core, smp_processor_id()).held_skb = NULL;
		rcu_read_unlock();
		return -ENODEV;
	}
	if (nhoff < (int)sizeof(struct udphdr)) {
		per_cpu(homa_offload_core, smp_processor_id()).held_skb = NULL;
		rcu_read_unlock();
		return -EINVAL;
	}

	result = homa_gro_complete(skb);
	rcu_read_unlock();
	return result;
}
