// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

/* This file implements TCP and UDP hijacking for Homa. See comments at the
 * top of homa_hijack.h for an overview of TCP hijacking. UDP hijacking works
 * similarly but uses UDP as the IP protocol, which avoids issues with
 * firewalls that inspect TCP flags.
 */

#include "homa_hijack.h"
#include "homa_offload.h"

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

/* Pointers to UDP's net_offload structures. NULL means homa_udp_hijack_init
 * hasn't been called yet.
 */
static const struct net_offload *udp_net_offload;
static const struct net_offload *udp6_net_offload;

/*
 * Identical to *udp_net_offload except that the gro_receive function
 * has been replaced with homa_udp_hijack_gro_receive.
 */
static struct net_offload hook_udp_net_offload;
static struct net_offload hook_udp6_net_offload;

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
 * homa_udp_hijack_init() - Initializes the mechanism for UDP hijacking
 * (allows incoming Homa packets encapsulated as UDP datagrams to be
 * "stolen" back from the UDP pipeline and funneled through Homa).
 */
void homa_udp_hijack_init(void)
{
	if (udp_net_offload)
		return;

	pr_notice("Homa setting up UDP hijacking\n");
	rcu_read_lock();
	udp_net_offload = rcu_dereference(inet_offloads[IPPROTO_UDP]);
	hook_udp_net_offload = *udp_net_offload;
	hook_udp_net_offload.callbacks.gro_receive = homa_udp_hijack_gro_receive;
	inet_offloads[IPPROTO_UDP] = (struct net_offload __rcu *)
			&hook_udp_net_offload;

	udp6_net_offload = rcu_dereference(inet6_offloads[IPPROTO_UDP]);
	hook_udp6_net_offload = *udp6_net_offload;
	hook_udp6_net_offload.callbacks.gro_receive = homa_udp_hijack_gro_receive;
	inet6_offloads[IPPROTO_UDP] = (struct net_offload __rcu *)
			&hook_udp6_net_offload;
	rcu_read_unlock();
}

/**
 * homa_udp_hijack_end() - Reverses the effects of a previous call to
 * homa_udp_hijack_init, so that incoming UDP packets are no longer checked
 * to see if they are actually Homa frames.
 */
void homa_udp_hijack_end(void)
{
	if (!udp_net_offload)
		return;
	pr_notice("Homa cancelling UDP hijacking\n");
	inet_offloads[IPPROTO_UDP] = (struct net_offload __rcu *)
			udp_net_offload;
	udp_net_offload = NULL;
	inet6_offloads[IPPROTO_UDP] = (struct net_offload __rcu *)
			udp6_net_offload;
	udp6_net_offload = NULL;
}

/**
 * homa_udp_hijack_gro_receive() - Invoked instead of UDP's gro_receive
 * function when UDP hijacking is enabled. Identifies Homa-over-UDP packets
 * and passes them to Homa; sends real UDP packets to UDP's gro_receive.
 * @held_list:  Pointer to header for list of packets that are being
 *              held for possible GRO merging.
 * @skb:        The newly arrived packet.
 */
struct sk_buff *homa_udp_hijack_gro_receive(struct list_head *held_list,
					    struct sk_buff *skb)
{
	/* Need at least 20 bytes of transport data to safely check the
	 * flags (offset 13) and urgent (offset 18-19) fields.
	 */
	if (skb_headlen(skb) >= skb_transport_offset(skb) + 20 &&
	    homa_skb_udp_hijacked(skb)) {
		if (skb_is_ipv6(skb)) {
			ipv6_hdr(skb)->nexthdr = IPPROTO_HOMA;
		} else {
			ip_hdr(skb)->check = ~csum16_add(
					csum16_sub(~ip_hdr(skb)->check,
						   htons(ip_hdr(skb)->protocol)),
					htons(IPPROTO_HOMA));
			ip_hdr(skb)->protocol = IPPROTO_HOMA;
		}
		return homa_gro_receive(held_list, skb);
	}
	return udp_net_offload->callbacks.gro_receive(held_list, skb);
}