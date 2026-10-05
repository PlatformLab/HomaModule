// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

/* This file implements TCP hijacking for Homa. See comments at the top of
 * homa_hijack.h for an overview of TCP hijacking.
 */

#include "homa_hijack.h"
#include "homa_offload.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#ifndef __STRIP__ /* See strip.py */
#include <net/ip6_checksum.h>
#include <net/udp_tunnel.h>
#endif /* See strip.py */

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

#ifndef __STRIP__ /* See strip.py */
/* The remainder of this file implements UDP hijacking; see the comments
 * in homa_hijack.h for an overview.
 *
 * The encap_rcv/encap_err_lookup/encap_err_rcv callbacks below implement
 * the data-receive and ICMP-error paths for UDP-hijacked traffic. Both
 * paths reuse Homa's normal dispatch machinery (homa_softirq_dispatch(),
 * homa_dispatch_pkts(), homa_abort_rpcs()) so that header validation and
 * RPC handling stay identical to the native/TCP-hijacked paths; the only
 * addition is transport-isolation bookkeeping (enum homa_pkt_origin) so
 * a UDP-hijacked socket can't be reached by native traffic or vice versa.
 */

/**
 * homa_hijack_prepend_udp() - Push a real UDP header onto an outgoing
 * Homa packet that is already completely built (i.e. skb_transport_header()
 * currently points at the packet's homa_common_hdr). This is the UDP
 * hijacking counterpart of homa_hijack_set_hdr(): unlike TCP hijacking,
 * which reuses fields already present in the Homa header, UDP hijacking
 * must add an actual 8-byte header, so this function is only ever
 * invoked for sockets where homa_sock_udp_hijacked() is true, and it is
 * mutually exclusive with homa_hijack_set_hdr() (never call both for the
 * same packet).
 * @skb:    Packet buffer to modify; must have enough headroom (guaranteed
 *          by HOMA_SKB_EXTRA) to hold an additional UDP header.
 * @route:  Contains source and destination addresses for the packet.
 * @ipv6:   True means the packet is going to be sent via IPv6; false means
 *          IPv4.
 */
void homa_hijack_prepend_udp(struct sk_buff *skb, struct homa_route *route,
			     bool ipv6)
{
	struct udphdr *uh;

	uh = skb_push(skb, sizeof(struct udphdr));
	skb_reset_transport_header(skb);
	uh->source = htons(HOMA_UDP_HIJACK_PORT);
	uh->dest = htons(HOMA_UDP_HIJACK_PORT);
	uh->len = htons(skb->len);
	uh->check = 0;
	if (ipv6)
		udp6_set_csum(false, skb, &route->flow.u.ip6.saddr,
			     &route->flow.u.ip6.daddr, skb->len);
	else
		udp_set_csum(false, skb, route->flow.u.ip4.saddr,
			    route->flow.u.ip4.daddr, skb->len);
}

/**
 * homa_hijack_udp_encap_rcv() - encap_rcv callback for the UDP hijack
 * tunnel sockets: strips off the outer UDP header and hands the packet
 * to Homa's normal receive dispatch, tagged as having arrived via UDP so
 * that homa_dispatch_pkts() can enforce transport isolation.
 * @sk:     Tunnel socket that received the packet.
 * @skb:    The received packet, still including its outer UDP header.
 * Return:  0 always: the packet is always consumed here (either
 *          dispatched to Homa or discarded).
 */
static int homa_hijack_udp_encap_rcv(struct sock *sk, struct sk_buff *skb)
{
	if (!pskb_may_pull(skb, sizeof(struct udphdr)) ||
	    udp_hdr(skb)->dest != htons(HOMA_UDP_HIJACK_PORT)) {
		kfree_skb(skb);
		return 0;
	}
	skb_pull(skb, sizeof(struct udphdr));
	skb_reset_transport_header(skb);
	homa_softirq_dispatch(skb, HOMA_PKT_UDP);
	return 0;
}

/**
 * homa_hijack_udp_quoted_ip() - Find the IP header quoted by an ICMP error.
 * @skb: Error skb whose transport header points at the quoted UDP header.
 * @quoted_udp: Expected location of the quoted UDP header.
 * Return: The quoted IP header, or NULL if its layout is not recognized.
 *
 * Some kernels leave the network header at the outer ICMP packet while
 * skb->data points at the quoted IP header. Others position the network
 * header at the quote. Validate both layouts against the quoted UDP header.
 */
static const u8 *homa_hijack_udp_quoted_ip(struct sk_buff *skb,
					   const u8 *quoted_udp)
{
	const u8 *candidates[] = {skb_network_header(skb), skb->data};
	int i;

	for (i = 0; i < ARRAY_SIZE(candidates); i++) {
		const u8 *candidate = candidates[i];
		int version;

		if (candidate >= quoted_udp)
			continue;
		version = candidate[0] >> 4;
		if (version == 4) {
			const struct iphdr *iph = (const struct iphdr *)candidate;

			if (iph->ihl >= 5 && iph->protocol == IPPROTO_UDP &&
			    candidate + iph->ihl * 4 == quoted_udp)
				return candidate;
		} else if (version == 6) {
			const struct ipv6hdr *iph =
					(const struct ipv6hdr *)candidate;

			if (iph->nexthdr == IPPROTO_UDP &&
			    candidate + sizeof(*iph) == quoted_udp)
				return candidate;
		}
	}
	return NULL;
}

/**
 * homa_hijack_udp_encap_err_lookup() - Decides whether an ICMP error
 * (already known to be addressed to one of Homa's UDP hijack tunnel
 * sockets) actually quotes a well-formed Homa-over-UDP packet, so that
 * the kernel will go on to invoke homa_hijack_udp_encap_err_rcv() for it.
 * @sk:     Tunnel socket that received the ICMP error.
 * @skb:    Packet describing the ICMP error; skb_network_header(skb)
 *          points at the quoted (original) IP/IPv6 header, and
 *          skb_transport_header(skb) points at the quoted UDP header.
 * Return:  0 if the quoted packet is a Homa-over-UDP packet with room
 *          for at least a common Homa header (accept), 1 otherwise
 *          (reject; the kernel drops the error without calling back).
 */
static int homa_hijack_udp_encap_err_lookup(struct sock *sk,
					    struct sk_buff *skb)
{
	int hdr_end = skb_transport_offset(skb) + sizeof(struct udphdr) +
			sizeof(struct homa_common_hdr);

	if (!pskb_may_pull(skb, hdr_end))
		return 1;
	if (udp_hdr(skb)->dest != htons(HOMA_UDP_HIJACK_PORT) ||
	    udp_hdr(skb)->source != htons(HOMA_UDP_HIJACK_PORT))
		return 1;
	if (!homa_hijack_udp_quoted_ip(skb, skb_transport_header(skb)))
		return 1;
	return 0;
}

/**
 * homa_hijack_udp_encap_err_rcv() - ICMP error callback for the UDP
 * hijack tunnel sockets, invoked only after
 * homa_hijack_udp_encap_err_lookup() has already verified that @skb
 * quotes a well-formed Homa-over-UDP packet with room for at least a
 * common Homa header.
 *
 * Note: @err is classified by the generic IPv4/IPv6 ICMP handling code,
 * which uses different conventions than Homa's native ICMP handlers
 * (homa_err_handler_v4/v6): in particular, port-unreachable errors are
 * reported here as ECONNREFUSED rather than Homa's native -ENOTCONN. That
 * one case is translated below for consistency; all other error codes
 * are passed through unchanged (this is actually more precise than the
 * native handlers, which collapse several distinct ICMP codes together).
 * @sk:      Tunnel socket that received the ICMP error.
 * @skb:     Packet describing the ICMP error; skb_network_header(skb)
 *           points at the quoted (original) IP/IPv6 header.
 * @err:     Positive errno describing the error.
 * @port:    Destination port from the quoted UDP header (network byte
 *           order); always equal to htons(HOMA_UDP_HIJACK_PORT).
 * @info:    For EMSGSIZE errors, the new path MTU, in host byte order.
 *           Unused otherwise.
 * @payload: Pointer to the quoted Homa header, immediately following the
 *           quoted UDP header (already verified to be within the linear
 *           part of @skb by homa_hijack_udp_encap_err_lookup()).
 */
static void homa_hijack_udp_encap_err_rcv(struct sock *sk,
					  struct sk_buff *skb, int err,
					  __be16 port, u32 info, u8 *payload)
{
	struct homa_common_hdr *h = (struct homa_common_hdr *)payload;
	struct homa_net *hnet = rcu_dereference_sk_user_data(sk);
	const u8 *quoted_ip = homa_hijack_udp_quoted_ip(
			skb, skb_transport_header(skb));
	struct in6_addr daddr;
	int hport = ntohs(h->dport);
	int error;

	if (!quoted_ip)
		quoted_ip = homa_hijack_udp_quoted_ip(
				skb, payload - sizeof(struct udphdr));
	if (!quoted_ip)
		return;
	if (quoted_ip[0] >> 4 == 6) {
		const struct ipv6hdr *iph =
				(const struct ipv6hdr *)quoted_ip;

		daddr = iph->daddr;
	} else {
		const struct iphdr *iph = (const struct iphdr *)quoted_ip;

		ipv6_addr_set_v4mapped(iph->daddr, &daddr);
	}

	if (err == ECONNREFUSED) {
		error = -ENOTCONN;
	} else {
		error = -err;
	}

	if (error == -EMSGSIZE) {
		int old_network_offset = skb_network_offset(skb);

		/* Existing RPCs cannot change their message geometry. Future
		 * RPCs will pick up the reduced MTU through a fresh route.
		 */
		skb_set_network_header(skb, quoted_ip - skb->data);
		homa_route_update_pmtu(hnet, skb, &daddr, info);
		skb_set_network_header(skb, old_network_offset);
	}

	homa_abort_rpcs(hnet->homa, &daddr, hport, error, IPPROTO_UDP);
}


/**
 * homa_hijack_udp_release_pair() - Release the UDP tunnel sockets for a
 * namespace, if they exist. Idempotent.
 * @hnet:   Namespace whose tunnel sockets should be released. Caller
 *          must hold @hnet->udp_mutex, unless this is being called during
 *          final namespace teardown (when no other thread can be
 *          accessing @hnet any more).
 */
static void homa_hijack_udp_release_pair(struct homa_net *hnet)
{
	if (hnet->udp_tun4) {
		udp_tunnel_sock_release(hnet->udp_tun4);
		hnet->udp_tun4 = NULL;
	}
	if (hnet->udp_tun6) {
		udp_tunnel_sock_release(hnet->udp_tun6);
		hnet->udp_tun6 = NULL;
	}
}

/**
 * homa_hijack_udp_create_pair() - Create the pair of UDP tunnel sockets
 * (IPv4 and IPv6) used for UDP hijacking in a namespace. On failure, no
 * tunnel sockets are left behind (any partially created socket is
 * released before returning).
 * @hnet:   Namespace that will own the new tunnel sockets. Caller must
 *          hold @hnet->udp_mutex.
 * @net:    The network namespace to create the sockets in; corresponds
 *          to @hnet.
 * Return:  0 on success, otherwise a negative errno.
 */
static int homa_hijack_udp_create_pair(struct homa_net *hnet,
				       struct net *net)
{
	struct udp_tunnel_sock_cfg tunnel_cfg;
	struct udp_port_cfg udp_cfg;
	struct socket *sock4;
	struct socket *sock6;
	int err;

	memset(&udp_cfg, 0, sizeof(udp_cfg));
	udp_cfg.family = AF_INET;
	udp_cfg.local_udp_port = htons(HOMA_UDP_HIJACK_PORT);
	udp_cfg.use_udp_checksums = 1;
	err = udp_sock_create(net, &udp_cfg, &sock4);
	if (err)
		return err;

	memset(&udp_cfg, 0, sizeof(udp_cfg));
	udp_cfg.family = AF_INET6;
	udp_cfg.local_udp_port = htons(HOMA_UDP_HIJACK_PORT);
	udp_cfg.use_udp_checksums = 1;
	udp_cfg.use_udp6_tx_checksums = 1;
	udp_cfg.use_udp6_rx_checksums = 1;
	udp_cfg.ipv6_v6only = 1;
	err = udp_sock_create(net, &udp_cfg, &sock6);
	if (err) {
		udp_tunnel_sock_release(sock4);
		return err;
	}

	memset(&tunnel_cfg, 0, sizeof(tunnel_cfg));
	tunnel_cfg.sk_user_data = hnet;
	tunnel_cfg.encap_type = 1;
	tunnel_cfg.encap_rcv = homa_hijack_udp_encap_rcv;
	tunnel_cfg.encap_err_lookup = homa_hijack_udp_encap_err_lookup;
	tunnel_cfg.encap_err_rcv = homa_hijack_udp_encap_err_rcv;
	setup_udp_tunnel_sock(net, sock4, &tunnel_cfg);
	setup_udp_tunnel_sock(net, sock6, &tunnel_cfg);

	hnet->udp_tun4 = sock4;
	hnet->udp_tun6 = sock6;
	return 0;
}

/**
 * homa_hijack_udp_release_work_fn() - Work function scheduled when UDP
 * hijacking is disabled while RPCs are still using it; releases the
 * tunnel sockets once the last such RPC has completed.
 * @work:   The &homa_net.udp_release_work embedded in the target
 *          &struct homa_net.
 */
static void homa_hijack_udp_release_work_fn(struct work_struct *work)
{
	struct homa_net *hnet = container_of(work, struct homa_net,
					     udp_release_work);

	mutex_lock(&hnet->udp_mutex);
	if (hnet->udp_state == HOMA_UDP_DRAINING &&
	    atomic_read(&hnet->udp_rpc_count) == 0) {
		homa_hijack_udp_release_pair(hnet);
		hnet->udp_state = HOMA_UDP_DISABLED;
	}
	mutex_unlock(&hnet->udp_mutex);
}

/**
 * homa_hijack_udp_net_init() - Initialize the UDP hijacking fields of a
 * new &struct homa_net. Does not create tunnel sockets or register
 * sysctl (see homa_hijack_udp_net_start() for that); safe to call even
 * when no real "struct net" exists yet (e.g. in unit tests).
 * @hnet:   The (newly allocated) homa_net to initialize.
 */
void homa_hijack_udp_net_init(struct homa_net *hnet)
{
	mutex_init(&hnet->udp_mutex);
	hnet->udp_state = HOMA_UDP_DISABLED;
	hnet->udp_tun4 = NULL;
	hnet->udp_tun6 = NULL;
	atomic_set(&hnet->udp_rpc_count, 0);
	hnet->udp_drain_deadline = 0;
	INIT_WORK(&hnet->udp_release_work, homa_hijack_udp_release_work_fn);
	hnet->udp_ctl_table = NULL;
	hnet->udp_ctl_header = NULL;
}

/**
 * homa_hijack_udp_sysctl_handler() - proc_handler for the per-namespace
 * net.homa.hijack_udp sysctl entry; parses the requested value and then
 * drives the UDP hijacking enable/disable state machine.
 * @table:   Sysctl table entry being accessed (a per-namespace copy whose
 *           @data field points at the target homa_net's @hijack_udp).
 * @write:   Nonzero for a write access, zero for a read access.
 * @buffer:  User-space buffer for input or output.
 * @lenp:    Number of bytes in @buffer; modified to reflect number
 *           actually used.
 * @ppos:    File position; not used by this function.
 * Return:   0 on success, otherwise a negative errno.
 */
static int homa_hijack_udp_sysctl_handler(const struct ctl_table *table,
					  int write, void *buffer,
					  size_t *lenp, loff_t *ppos)
{
	struct homa_net *hnet = container_of((int *)table->data,
					     struct homa_net, hijack_udp);
	struct ctl_table tmp_table;
	int value;
	int err;

	value = READ_ONCE(hnet->hijack_udp);
	tmp_table = *table;
	tmp_table.data = &value;
	tmp_table.extra1 = SYSCTL_ZERO;
	tmp_table.extra2 = SYSCTL_ONE;

	err = proc_dointvec_minmax(&tmp_table, write, buffer, lenp, ppos);
	if (err || !write)
		return err;

	return homa_hijack_udp_set_enabled(hnet, current->nsproxy->net_ns,
					   value);
}

/* Template used to build a per-namespace copy of the sysctl table that
 * exposes net.homa.hijack_udp. A private copy is needed for each
 * namespace because .data must point at that namespace's homa_net.
 */
static const struct ctl_table homa_udp_ctl_table_template[] = {
	{
		.procname	= "hijack_udp",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_hijack_udp_sysctl_handler,
	},
};

/**
 * homa_hijack_udp_net_start() - Register the per-namespace
 * net.homa.hijack_udp sysctl entry. Invoked once for each namespace,
 * after homa_hijack_udp_net_init() has already initialized @hnet.
 * @hnet:   Namespace to register the sysctl entry for.
 * @net:    The network namespace corresponding to @hnet.
 * Return:  0 on success, otherwise a negative errno.
 */
int homa_hijack_udp_net_start(struct homa_net *hnet, struct net *net)
{
	hnet->udp_ctl_table = kmemdup(homa_udp_ctl_table_template,
				      sizeof(homa_udp_ctl_table_template),
				      GFP_KERNEL);
	if (!hnet->udp_ctl_table)
		return -ENOMEM;
	hnet->udp_ctl_table[0].data = &hnet->hijack_udp;

	hnet->udp_ctl_header = register_net_sysctl_sz(net, "net/homa",
						      hnet->udp_ctl_table,
						      ARRAY_SIZE(homa_udp_ctl_table_template));
	if (!hnet->udp_ctl_header) {
		kfree(hnet->udp_ctl_table);
		hnet->udp_ctl_table = NULL;
		return -ENOMEM;
	}
	return 0;
}

/**
 * homa_hijack_udp_net_exit_begin() - First half of UDP hijack cleanup for
 * a namespace that is being destroyed: unregisters the sysctl entry (so
 * no new enable/disable requests can arrive) and marks the namespace as
 * being torn down. Must be called before the namespace's sockets and
 * RPCs are torn down (i.e. before homa_net_destroy()).
 * @hnet:   Namespace being destroyed.
 */
void homa_hijack_udp_net_exit_begin(struct homa_net *hnet)
{
	if (hnet->udp_ctl_header) {
		unregister_net_sysctl_table(hnet->udp_ctl_header);
		hnet->udp_ctl_header = NULL;
	}
	mutex_lock(&hnet->udp_mutex);
	hnet->udp_state = HOMA_UDP_TEARDOWN;
	mutex_unlock(&hnet->udp_mutex);
}

/**
 * homa_hijack_udp_net_destroy() - Final, unconditional UDP hijack cleanup
 * for a namespace that is being destroyed: cancels any pending release
 * work, releases the tunnel sockets (if any), and frees the per-namespace
 * sysctl table copy. Idempotent. Must be called after the namespace's
 * sockets and RPCs have already been torn down (i.e. after
 * homa_net_destroy(), or in test code that never created any).
 * @hnet:   Namespace being destroyed.
 */
void homa_hijack_udp_net_destroy(struct homa_net *hnet)
{
	cancel_work_sync(&hnet->udp_release_work);
	mutex_lock(&hnet->udp_mutex);
	homa_hijack_udp_release_pair(hnet);
	mutex_unlock(&hnet->udp_mutex);
	kfree(hnet->udp_ctl_table);
	hnet->udp_ctl_table = NULL;
}

/**
 * homa_hijack_udp_set_enabled() - Implements the UDP hijacking enable/
 * disable state machine; invoked when net.homa.hijack_udp is written.
 * @hnet:    Namespace whose UDP hijacking state should change.
 * @net:     The network namespace corresponding to @hnet.
 * @enable:  Nonzero to enable UDP hijacking, zero to disable it.
 * Return:   0 on success, otherwise a negative errno (only possible when
 *           enabling, if the tunnel sockets can't be created).
 */
int homa_hijack_udp_set_enabled(struct homa_net *hnet, struct net *net,
				int enable)
{
	int err = 0;

	mutex_lock(&hnet->udp_mutex);
	if (hnet->udp_state == HOMA_UDP_TEARDOWN) {
		mutex_unlock(&hnet->udp_mutex);
		return -ENETDOWN;
	}

	if (enable) {
		if (hnet->udp_state == HOMA_UDP_DISABLED) {
			err = homa_hijack_udp_create_pair(hnet, net);
			if (err) {
				mutex_unlock(&hnet->udp_mutex);
				return err;
			}
		}
		/* HOMA_UDP_DRAINING -> HOMA_UDP_ENABLED reuses the tunnel
		 * sockets that are still being drained; HOMA_UDP_ENABLED
		 * is a no-op.
		 */
		hnet->udp_state = HOMA_UDP_ENABLED;
		WRITE_ONCE(hnet->hijack_udp, 1);
	} else {
		WRITE_ONCE(hnet->hijack_udp, 0);
		if (hnet->udp_state == HOMA_UDP_ENABLED) {
			hnet->udp_state = HOMA_UDP_DRAINING;

			/* Full barrier so this state store is visible to
			 * homa_hijack_udp_admit() before udp_rpc_count is
			 * read below; pairs with the barrier in
			 * homa_hijack_udp_admit().
			 */
			smp_mb();
			UNIT_HOOK("udp_disable_after_state");
			if (atomic_read(&hnet->udp_rpc_count) == 0) {
				homa_hijack_udp_release_pair(hnet);
				hnet->udp_state = HOMA_UDP_DISABLED;
			} else {
				hnet->udp_drain_deadline =
						hnet->homa->timer_ticks +
						hnet->homa->timeout_ticks;
			}
		}
		/* HOMA_UDP_DISABLED and HOMA_UDP_DRAINING are unaffected
		 * by a repeated request to disable.
		 */
	}
	mutex_unlock(&hnet->udp_mutex);
	return err;
}

/**
 * homa_hijack_udp_admit() - Invoked when a new RPC is about to become
 * visible, while its socket's bucket and socket locks are held; decides
 * whether the RPC may be admitted as a UDP-hijacked RPC and, if so,
 * accounts for it so that the tunnel sockets aren't released while it is
 * still active.
 * @rpc:    The new RPC (not yet visible to other threads).
 * Return:  0 if the RPC may proceed (whether or not it was admitted for
 *          UDP hijacking; check rpc->udp_admitted to tell which), or a
 *          negative errno if the RPC must be rejected because UDP
 *          hijacking has been disabled out from under it.
 */
int homa_hijack_udp_admit(struct homa_rpc *rpc)
{
	struct homa_net *hnet = rpc->hsk->hnet;

	if (!homa_sock_udp_hijacked(rpc->hsk))
		return 0;

	atomic_inc(&hnet->udp_rpc_count);

	/* Full barrier so the increment above is visible to
	 * homa_hijack_udp_set_enabled() before udp_state is read below;
	 * pairs with the barrier in homa_hijack_udp_set_enabled().
	 */
	smp_mb();
	UNIT_HOOK("udp_admit_after_increment");
	if (READ_ONCE(hnet->udp_state) != HOMA_UDP_ENABLED) {
		if (atomic_dec_and_test(&hnet->udp_rpc_count) &&
		    READ_ONCE(hnet->udp_state) == HOMA_UDP_DRAINING)
			schedule_work(&hnet->udp_release_work);
		return -ENETDOWN;
	}
	rpc->udp_admitted = true;
	return 0;
}

/**
 * homa_hijack_udp_end_rpc() - Invoked from homa_rpc_end() when an RPC
 * makes its (idempotent) transition to RPC_DEAD; releases any UDP
 * hijacking accounting held by the RPC. Softirq-safe: never sleeps and
 * never acquires @hnet->udp_mutex.
 * @rpc:    The RPC that is being ended.
 */
void homa_hijack_udp_end_rpc(struct homa_rpc *rpc)
{
	struct homa_net *hnet;

	if (!rpc->udp_admitted)
		return;
	rpc->udp_admitted = false;
	hnet = rpc->hsk->hnet;
	if (atomic_dec_and_test(&hnet->udp_rpc_count) &&
	    READ_ONCE(hnet->udp_state) == HOMA_UDP_DRAINING)
		schedule_work(&hnet->udp_release_work);
}
#endif /* See strip.py */
