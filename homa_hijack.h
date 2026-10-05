/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */

/* This file defines things related to TCP hijacking. TCP hijacking is an
 * optional mechanism in which Homa packets are encapsulated as TCP frames
 * and transmittted with an IP protocol of IPPROTO_TCP instead of
 * IPPROTO_HOMA. The TCP headers for these frames use bit combinations that
 * never occur for "real" TCP packets. On the destination side, Homa
 * interposes itself in the GRO path for incoming TCP packets, checks the
 * header bits, and steals back the Homa packets; "real" TCP frames are
 * returned to the normal TCP pipeline for further processing.
 *
 * The reason for TCP hijacking is to allow Homa packets to take advantage
 * of TSO in NICs. Without TCP hijacking, many NICs will not perform
 * segmentation on Homa packets, which results in a large performance
 * penalty. In some cases NICs can be configured to recognize Homa packets
 * and segment them, but it is unwieldy to incorporate support for every
 * conceivable NIC into Homa. TCP hijacking provides a general mechanism that
 * makes it easy to use Homa with any NIC that performs TSO.
 */

#ifndef _HOMA_HIJACK_H
#define _HOMA_HIJACK_H

#include "homa_impl.h"
#include "homa_sock.h"
#include "homa_wire.h"

#ifndef __STRIP__ /* See strip.py */
#include <net/udp.h>
#endif /* See strip.py */

/* Special value stored in the flags field of TCP headers to indicate that
 * the packet is actually a Homa packet. It includes the SYN and RST flags
 * which TCP never uses together; must not include URG or FIN (TSO will turn
 * off FIN for all but the last segment).
 */
#define HOMA_HIJACK_FLAGS 6

/* Special value stored in the urgent pointer of a TCP header to indicate
 * that the packet is actually a Homa packet (note that urgent pointer is
 * set even though the URG flag is not set).
 */
#define HOMA_HIJACK_URGENT 0xb97d

/**
 * homa_hijack_sock_init() - Perform socket initialization related to
 * TCP hijacking (arrange for outgoing packets on the socket to use TCP,
 * if the hijack_tcp option is set.)
 * @hsk:    New socket to initialize.
 */
static inline void homa_hijack_sock_init(struct homa_sock *hsk)
{
	if (hsk->homa->hijack_tcp)
		hsk->sock.sk_protocol = IPPROTO_TCP;
}

/* homa_sock_hijacked() - Returns true if outgoing packets on a socket
 * should use TCP hijacking, false if they should be transmitted as native
 * Homa packets.
 */
static inline bool homa_sock_hijacked(struct homa_sock *hsk)
{
	return hsk->sock.sk_protocol == IPPROTO_TCP;
}

/**
 * homa_skb_hijacked() - Return true if the TCP header fields in a packet
 * indicate that the packet is actually a Homa packet, false otherwise.
 * @skb:    Packet to check: must have an IP protocol of IPPROTO_TCP or
 *          IPPROTO_HOMA.
 */
static inline bool homa_skb_hijacked(struct sk_buff *skb)
{
	struct homa_common_hdr *h;

	h = (struct homa_common_hdr *)skb_transport_header(skb);
	return h->flags == HOMA_HIJACK_FLAGS &&
	       h->urgent == ntohs(HOMA_HIJACK_URGENT);
}

void     homa_hijack_end(void);
struct sk_buff *
	 homa_hijack_gro_receive(struct list_head *held_list,
				 struct sk_buff *skb);
void     homa_hijack_init(void);
void     homa_hijack_set_hdr(struct sk_buff *skb, struct homa_route *route,
			     bool ipv6);

/**
 * homa_skb_inner_hdr() - Return a pointer to the inner Homa header of an
 * outgoing packet, regardless of whether it is a native, TCP-hijacked, or
 * UDP-hijacked packet. skb_transport_header(skb) always identifies the
 * real (outermost) transport header for outgoing packets (see
 * homa_hijack_prepend_udp()); this function looks past that header, and
 * past any UDP encapsulation header, to find the inner Homa header,
 * performing bounds checking along the way.
 * @skb:    Outgoing packet to examine.
 * Return:  Pointer to the packet's homa_common_hdr, or NULL if @skb isn't
 *          a well-formed outgoing Homa packet (wrong outer protocol or
 *          UDP destination port, too short to hold a Homa header, or an
 *          invalid packet type).
 */
static inline struct homa_common_hdr *homa_skb_inner_hdr(struct sk_buff *skb)
{
	struct homa_common_hdr *h;
	int eth_prot, protocol;
	int extra = 0;

	eth_prot = ntohs(skb_protocol(skb, true));
	if (eth_prot == ETH_P_IP)
		protocol = ip_hdr(skb)->protocol;
	else if (eth_prot == ETH_P_IPV6)
		protocol = ipv6_hdr(skb)->nexthdr;
	else
		return NULL;

#ifndef __STRIP__ /* See strip.py */
	if (protocol == IPPROTO_UDP) {
		if (!pskb_may_pull(skb, skb_transport_offset(skb) +
				   sizeof(struct udphdr)) ||
		    udp_hdr(skb)->dest != htons(HOMA_UDP_HIJACK_PORT))
			return NULL;
		extra = sizeof(struct udphdr);
	} else if (protocol != IPPROTO_HOMA &&
		   !(protocol == IPPROTO_TCP && homa_skb_hijacked(skb))) {
		return NULL;
	}
#else /* See strip.py */
	if (protocol != IPPROTO_HOMA &&
	    !(protocol == IPPROTO_TCP && homa_skb_hijacked(skb)))
		return NULL;
#endif /* See strip.py */

	if (!pskb_may_pull(skb, skb_transport_offset(skb) + extra +
			   sizeof(struct homa_common_hdr)))
		return NULL;
	h = (struct homa_common_hdr *)(skb_transport_header(skb) + extra);
	if (h->type < DATA || h->type > MAX_OP)
		return NULL;
	return h;
}

#ifndef __STRIP__ /* See strip.py */
/* UDP hijacking: an optional mechanism in which Homa packets are
 * encapsulated in UDP datagrams sent to/from a dedicated pair of kernel
 * "tunnel" sockets (one for IPv4, one for IPv6), using the real Linux
 * udp_tunnel socket infrastructure. Unlike TCP hijacking, this preserves
 * a real UDP source port that NICs/switches can use for ECMP/RSS entropy.
 * See homa_hijack.c for the full implementation.
 */

/**
 * homa_sock_udp_hijacked() - Returns true if outgoing packets on a socket
 * should use UDP hijacking, false otherwise.
 * @hsk:    Socket to check.
 */
static inline bool homa_sock_udp_hijacked(struct homa_sock *hsk)
{
	return hsk->sock.sk_protocol == IPPROTO_UDP;
}

/**
 * homa_hijack_udp_sock_select() - Perform socket initialization related to
 * UDP hijacking: if TCP hijacking hasn't already claimed the socket and
 * UDP hijacking is currently enabled for this namespace, arrange for
 * outgoing packets on the socket to use UDP. Must be called with the
 * socket not yet visible to other threads (e.g. during homa_sock_init()).
 * Leaves @hsk->hnet->udp_mutex locked; the caller must eventually invoke
 * homa_hijack_udp_unlock().
 * @hsk:    New socket to initialize.
 */
static inline void homa_hijack_udp_sock_select(struct homa_sock *hsk)
	__acquires(&hsk->hnet->udp_mutex)
{
	struct homa_net *hnet = hsk->hnet;

	mutex_lock(&hnet->udp_mutex);
	if (homa_sock_hijacked(hsk))
		return;
	if (hnet->udp_state == HOMA_UDP_ENABLED)
		hsk->sock.sk_protocol = IPPROTO_UDP;
}

/**
 * homa_hijack_udp_unlock() - Release the lock acquired by a matching call
 * to homa_hijack_udp_sock_select().
 * @hnet:   Namespace whose udp_mutex should be released.
 */
static inline void homa_hijack_udp_unlock(struct homa_net *hnet)
	__releases(&hnet->udp_mutex)
{
	mutex_unlock(&hnet->udp_mutex);
}

void homa_hijack_udp_net_init(struct homa_net *hnet);
int  homa_hijack_udp_net_start(struct homa_net *hnet, struct net *net);
void homa_hijack_udp_net_exit_begin(struct homa_net *hnet);
void homa_hijack_udp_net_destroy(struct homa_net *hnet);
int  homa_hijack_udp_set_enabled(struct homa_net *hnet, struct net *net,
				 int enable);
int  homa_hijack_udp_admit(struct homa_rpc *rpc);
void homa_hijack_udp_end_rpc(struct homa_rpc *rpc);
void homa_hijack_prepend_udp(struct sk_buff *skb, struct homa_route *route,
			     bool ipv6);
#endif /* See strip.py */

#endif /* _HOMA_HIJACK_H */
