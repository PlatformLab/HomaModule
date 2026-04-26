/* SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+ */

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
#include "homa_peer.h"
#include "homa_sock.h"
#include "homa_wire.h"
#include <net/ip6_checksum.h>

/* Special value stored in the flags field of TCP headers to indicate that
 * the packet is actually a Homa packet. It includes the SYN and RST flags
 * which TCP never uses together; must not include URG or FIN (TSO will turn
 * off FIN for all but the last segment).
 */
#define HOMA_HIJACK_FLAGS 6

/* Special value stored in the flags field for UDP hijacking, distinct from
 * the TCP hijack value.
 */
#define HOMA_UDP_FLAGS 5

/* Special value stored in the urgent pointer of a TCP header to indicate
 * that the packet is actually a Homa packet (note that urgent pointer is
 * set even though the URG flag is not set).
 */
#define HOMA_HIJACK_URGENT 0xb97d

/**
 * homa_hijack_set_hdr() - Set all of the header fields in an outgoing Homa
 * packet that are needed for TCP hijacking to work properly except doff (use
 * homa_set_doff for that). This function doesn't actually cause the packet
 * to be sent via TCP (that is determined by hsk->sock.sk_protocol, which is
 * set elsewhere). The modifications made here are safe even if the packet
 * isn't actually sent via TCP.
 * @skb:    Packet buffer in which to set fields.
 * @peer:   Peer that contains source and destination addresses for the packet.
 * @ipv6:   True means the packet is going to be sent via IPv6; false means
 *          IPv4.
 */
static inline void homa_hijack_set_hdr(struct sk_buff *skb,
				       struct homa_peer *peer,
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
		h->checksum = ~csum_ipv6_magic(&peer->flow.u.ip6.saddr,
					       &peer->flow.u.ip6.daddr,
					       skb->len, IPPROTO_TCP, 0);
	else
		h->checksum = ~tcp_v4_check(skb->len, peer->flow.u.ip4.saddr,
					    peer->flow.u.ip4.daddr, 0);
}

/**
 * homa_hijack_sock_init() - Perform socket initialization related to
 * TCP/UDP hijacking (arrange for outgoing packets on the socket to use
 * TCP or UDP, if the corresponding hijack option is set.)
 * @hsk:    New socket to initialize.
 */
static inline void homa_hijack_sock_init(struct homa_sock *hsk)
{
	if (hsk->homa->hijack_tcp)
		hsk->sock.sk_protocol = IPPROTO_TCP;
	else if (hsk->homa->hijack_udp)
		hsk->sock.sk_protocol = IPPROTO_UDP;
}

/* homa_sock_hijacked() - Returns true if outgoing packets on a socket
 * should use TCP hijacking, false if they should be transmitted as native
 * Homa packets.
 */
static inline bool homa_sock_hijacked(struct homa_sock *hsk)
{
	return hsk->sock.sk_protocol == IPPROTO_TCP;
}

/* homa_sock_udp_hijacked() - Returns true if outgoing packets on a socket
 * should use UDP hijacking.
 */
static inline bool homa_sock_udp_hijacked(struct homa_sock *hsk)
{
	return hsk->sock.sk_protocol == IPPROTO_UDP;
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

/**
 * homa_udp_hijack_set_hdr() - Set all header fields needed for UDP hijacking
 * in an outgoing Homa packet. Overwrites the sequence field (bytes 4-7) with
 * UDP length and checksum, so the packet offset must be stored in seg.offset.
 * @skb:    Packet buffer in which to set fields.
 * @peer:   Peer that contains source and destination addresses for the packet.
 * @ipv6:   True means the packet is going to be sent via IPv6.
 */
static inline void homa_udp_hijack_set_hdr(struct sk_buff *skb,
					    struct homa_peer *peer,
					    bool ipv6)
{
	struct homa_common_hdr *h;
	int transport_len;

	h = (struct homa_common_hdr *)skb_transport_header(skb);
	h->flags = HOMA_UDP_FLAGS;
	h->urgent = htons(HOMA_UDP_URGENT);

	transport_len = skb->len - skb_transport_offset(skb);

	/* Set UDP length at bytes 4-5 (overlaps high 16 bits of sequence). */
	*((__be16 *)((u8 *)h + 4)) = htons(transport_len);

	/* Arrange for proper UDP checksumming at bytes 6-7. */
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = 6;
	if (ipv6)
		*((__be16 *)((u8 *)h + 6)) = ~csum_ipv6_magic(
				&peer->flow.u.ip6.saddr,
				&peer->flow.u.ip6.daddr,
				transport_len, IPPROTO_UDP, 0);
	else
		*((__be16 *)((u8 *)h + 6)) = ~csum_tcpudp_magic(
				peer->flow.u.ip4.saddr,
				peer->flow.u.ip4.daddr,
				transport_len, IPPROTO_UDP, 0);
}

/**
 * homa_skb_udp_hijacked() - Return true if the header fields in a UDP
 * packet indicate that the packet is actually a Homa packet, false otherwise.
 * @skb:    Packet to check: must have an IP protocol of IPPROTO_UDP.
 */
static inline bool homa_skb_udp_hijacked(struct sk_buff *skb)
{
	struct homa_common_hdr *h;

	/* Need at least 20 bytes of transport data to safely check the
	 * flags (offset 13) and urgent (offset 18-19) fields.
	 */
	if (skb_headlen(skb) < skb_transport_offset(skb) + 20)
		return false;
	h = (struct homa_common_hdr *)skb_transport_header(skb);
	return h->flags == HOMA_UDP_FLAGS &&
	       h->urgent == ntohs(HOMA_UDP_URGENT);
}

void     homa_hijack_end(void);
struct sk_buff *
	 homa_hijack_gro_receive(struct list_head *held_list,
				 struct sk_buff *skb);
void     homa_hijack_init(void);
void     homa_udp_hijack_end(void);
struct sk_buff *
	 homa_udp_hijack_gro_receive(struct list_head *held_list,
				     struct sk_buff *skb);
void     homa_udp_hijack_init(void);

#endif /* _HOMA_HIJACK_H */
