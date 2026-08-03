// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

/* This file implements TCP hijacking for Homa. See comments at the top of
 * homa_hijack.h for an overview of TCP hijacking.
 */

#include "homa_hijack.h"
#include "homa_offload.h"
#include "homa_peer.h"

/* Pointers to TCP's net_offload structures. NULL means homa_hijack_init
 * hasn't been called yet.
 */
static const struct net_offload *tcp_net_offload;
static const struct net_offload *tcp6_net_offload;

/*
 * Identical to *tcp_net_offload except that the gro_receive function
 * has been replaced with homa_hijack_gro_receive.
 */
static struct net_offload hook_tcp_net_offload;
static struct net_offload hook_tcp6_net_offload;

/**
 * homa_hijack_init() - Initializes the mechanism for TCP hijacking (allows
 * incoming Homa packets encapsulated as TCP frames to be "stolen" back from
 * the TCP pipeline and funneled through Homa).
 */
void homa_hijack_init(void)
{
	if (tcp_net_offload)
		return;

	pr_notice("Homa setting up TCP hijacking\n");
	rcu_read_lock();
	tcp_net_offload = rcu_dereference(inet_offloads[IPPROTO_TCP]);
	hook_tcp_net_offload = *tcp_net_offload;
	hook_tcp_net_offload.callbacks.gro_receive = homa_hijack_gro_receive;
	inet_offloads[IPPROTO_TCP] = (struct net_offload __rcu *)
			&hook_tcp_net_offload;

	tcp6_net_offload = rcu_dereference(inet6_offloads[IPPROTO_TCP]);
	hook_tcp6_net_offload = *tcp6_net_offload;
	hook_tcp6_net_offload.callbacks.gro_receive = homa_hijack_gro_receive;
	inet6_offloads[IPPROTO_TCP] = (struct net_offload __rcu *)
			&hook_tcp6_net_offload;
	rcu_read_unlock();
}

/**
 * homa_hijack_end() - Reverses the effects of a previous call to
 * homa_hijack_init, so that incoming TCP packets are no longer checked
 * to see if they are actually Homa frames.
 */
void homa_hijack_end(void)
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
 * homa_hijack_gro_receive() - Invoked instead of TCP's gro_receive function
 * when hijacking is enabled. Identifies Homa-over-TCP packets and passes them
 * to Homa; sends real TCP packets to TCP's gro_receive function.
 * @held_list:  Pointer to header for list of packets that are being
 *              held for possible GRO merging.
 * @skb:        The newly arrived packet.
 */
struct sk_buff *homa_hijack_gro_receive(struct list_head *held_list,
					struct sk_buff *skb)
{
	// tt_record4("homa_hijack_gro_receive got type 0x%x, flags 0x%x, "
	//		"urgent 0x%x, id %d", h->type, h->flags,
	//		ntohs(h->urgent), homa_local_id(h->sender_id));
	if (!homa_skb_hijacked(skb))
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
 * homa_hijack_set_hdr() - Set all of the header fields in an outgoing Homa
 * packet that are needed for TCP hijacking to work properly except doff (use
 * homa_set_doff for that). This function doesn't actually cause the packet
 * to be sent via TCP (that is determined by hsk->sock.sk_protocol, which is
 * set elsewhere). The modifications made here are safe even if the packet
 * isn't actually sent via TCP.
 * @skb:    Packet buffer in which to set fields.
 * @route:  Contains source and destination addresses for the packet.
 * @ipv6:   True means the packet is going to be sent via IPv6; false means
 *          IPv4.
 */
void homa_hijack_set_hdr(struct sk_buff *skb, struct homa_route *route,
			 bool ipv6)
{
	struct homa_common_hdr *h;

	h = (struct homa_common_hdr *)skb_transport_header(skb);
	h->flags = HOMA_HIJACK_FLAGS;
	h->urgent = htons(HOMA_HIJACK_URGENT);
	/* Arrange for proper TCP checksumming. */
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct homa_common_hdr, checksum);
	if (ipv6)
		h->checksum = ~tcp_v6_check(skb->len, &route->flow.u.ip6.saddr,
					    &route->flow.u.ip6.daddr, 0);
	else
		h->checksum = ~tcp_v4_check(skb->len, route->flow.u.ip4.saddr,
					    route->flow.u.ip4.daddr, 0);
}
