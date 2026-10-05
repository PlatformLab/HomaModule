// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

#include "homa_impl.h"
#include "homa_hijack.h"
#include "homa_offload.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#define cur_offload_core (&per_cpu(homa_offload_core, smp_processor_id()))

static struct sk_buff *test_tcp_gro_receive(struct list_head *held_list,
				       struct sk_buff *skb)
{
	UNIT_LOG("; ", "test_tcp_gro_receive");
	return NULL;
}
static struct sk_buff *unit_tcp6_gro_receive(struct list_head *held_list,
				       struct sk_buff *skb)
{
	UNIT_LOG("; ", "unit_tcp6_gro_receive");
	return NULL;
}

static struct homa_net *udp_race_hnet;
static struct net *udp_race_net;
static struct homa_rpc *udp_race_rpc;
static int udp_race_admit_result;
static struct sk_buff *udp_release_skb;
static struct homa_common_hdr *udp_release_hdr;
static int udp_release_callback_count;

static void udp_disable_during_admit_hook(char *id)
{
	if (strcmp(id, "udp_admit_after_increment") != 0)
		return;
	homa_hijack_udp_set_enabled(udp_race_hnet, udp_race_net, 0);
}

static void udp_admit_during_disable_hook(char *id)
{
	if (strcmp(id, "udp_disable_after_state") != 0)
		return;
	udp_race_admit_result = homa_hijack_udp_admit(udp_race_rpc);
}

static void udp_callback_during_release_hook(char *id)
{
	struct sock *sk;

	if (strcmp(id, "udp_tunnel_release") != 0 ||
	    udp_release_callback_count != 0)
		return;
	sk = udp_race_hnet->udp_tun4->sk;
	if (rcu_dereference_sk_user_data(sk) != udp_race_hnet) {
		udp_release_callback_count = -1;
		return;
	}
	rcu_read_lock();
	mock_udp_tunnel_cfg.encap_err_rcv(sk, udp_release_skb,
			EHOSTUNREACH, htons(HOMA_UDP_HIJACK_PORT), 0,
			(u8 *)udp_release_hdr);
	rcu_read_unlock();
	udp_release_callback_count = 1;
}

FIXTURE(homa_hijack)
{
	struct homa homa;
	struct homa_net *hnet;
	struct homa_sock hsk;
	struct in6_addr src_ip;
	struct in6_addr dst_ip;
	struct homa_data_hdr header;
	struct list_head empty_list;
	struct net_offload tcp_offloads;
	struct net_offload tcp6_offloads;
};
FIXTURE_SETUP(homa_hijack)
{
	homa_init(&self->homa);
	self->hnet = mock_hnet(0, &self->homa);
	self->homa.unsched_bytes = 10000;
	mock_sock_init(&self->hsk, self->hnet, 99);
	self->src_ip = unit_get_in_addr("196.168.0.1");
	self->dst_ip = unit_get_in_addr("1.2.3.4");
	memset(&self->header, 0, sizeof(self->header));
	self->header.common = (struct homa_common_hdr){
		.sport = htons(40000), .dport = htons(88),
		.type = DATA,
		.flags = HOMA_HIJACK_FLAGS,
		.urgent = HOMA_HIJACK_URGENT,
		.sender_id = cpu_to_be64(1002)
	};
	self->header.msg_length = htonl(10000);
	self->header.seg.offset = htonl(4000);
	INIT_LIST_HEAD(&self->empty_list);
	self->tcp_offloads.callbacks.gro_receive = test_tcp_gro_receive;
	inet_offloads[IPPROTO_TCP] = &self->tcp_offloads;
	self->tcp6_offloads.callbacks.gro_receive = unit_tcp6_gro_receive;
	inet6_offloads[IPPROTO_TCP] = &self->tcp6_offloads;
	homa_offload_init();

	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_hijack)
{
	homa_offload_end();
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_hijack, homa_hijack_init)
{
	homa_hijack_init();
	EXPECT_EQ(&homa_hijack_gro_receive,
		  inet_offloads[IPPROTO_TCP]->callbacks.gro_receive);
	EXPECT_EQ(&homa_hijack_gro_receive,
		  inet6_offloads[IPPROTO_TCP]->callbacks.gro_receive);

	/* Second hook call should do nothing. */
	homa_hijack_init();

	homa_hijack_end();
	EXPECT_EQ(&test_tcp_gro_receive,
		  inet_offloads[IPPROTO_TCP]->callbacks.gro_receive);
	EXPECT_EQ(&unit_tcp6_gro_receive,
		  inet6_offloads[IPPROTO_TCP]->callbacks.gro_receive);

	/* Second unhook call should do nothing. */
	homa_hijack_end();
	EXPECT_EQ(&test_tcp_gro_receive,
		  inet_offloads[IPPROTO_TCP]->callbacks.gro_receive);
	EXPECT_EQ(&unit_tcp6_gro_receive,
		  inet6_offloads[IPPROTO_TCP]->callbacks.gro_receive);
}

TEST_F(homa_hijack, homa_hijack_gro_receive__pass_to_tcp)
{
	struct homa_common_hdr *h;
	struct sk_buff *skb;

	homa_hijack_init();
	self->header.seg.offset = htonl(6000);
	skb = mock_skb_alloc(&self->src_ip, &self->dst_ip,
			     &self->header.common, 1400, 0);
	h = (struct homa_common_hdr *) skb_transport_header(skb);
	h->flags = 0;
	EXPECT_EQ(NULL, homa_hijack_gro_receive(&self->empty_list, skb));
	EXPECT_STREQ("test_tcp_gro_receive", unit_log_get());
	kfree_skb(skb);
	unit_log_clear();

	skb = mock_skb_alloc(&self->src_ip, &self->dst_ip,
			     &self->header.common, 1400, 0);
	h = (struct homa_common_hdr *)skb_transport_header(skb);
	h->urgent -= 1;
	EXPECT_EQ(NULL, homa_hijack_gro_receive(&self->empty_list, skb));
	EXPECT_STREQ("test_tcp_gro_receive", unit_log_get());
	kfree_skb(skb);
	homa_hijack_end();
}
TEST_F(homa_hijack, homa_hijack_gro_receive__pass_to_homa_ipv6)
{
	struct homa_common_hdr *h;
	struct sk_buff *skb;

	mock_ipv6 = true;
	homa_hijack_init();
	self->header.seg.offset = htonl(6000);
	skb = mock_skb_alloc(&self->src_ip, &self->dst_ip, &self->header.common,
			     1400, 0);
	ip_hdr(skb)->protocol = IPPROTO_TCP;
	h = (struct homa_common_hdr *)skb_transport_header(skb);
	h->flags = HOMA_HIJACK_FLAGS;
	h->urgent = htons(HOMA_HIJACK_URGENT);
	NAPI_GRO_CB(skb)->same_flow = 0;
	cur_offload_core->held_skb = NULL;
	cur_offload_core->held_bucket = 99;
	EXPECT_EQ(NULL, homa_hijack_gro_receive(&self->empty_list, skb));
	EXPECT_EQ(skb, cur_offload_core->held_skb);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(IPPROTO_HOMA, ipv6_hdr(skb)->nexthdr);
	kfree_skb(skb);
	homa_hijack_end();
}
TEST_F(homa_hijack, homa_hijack_gro_receive__pass_to_homa_ipv4)
{
	struct homa_common_hdr *h;
	struct sk_buff *skb;

	mock_ipv6 = false;
	homa_hijack_init();
	self->header.seg.offset = htonl(6000);
	skb = mock_skb_alloc(&self->src_ip, &self->dst_ip,
			     &self->header.common, 1400, 0);
	ip_hdr(skb)->protocol = IPPROTO_TCP;
	h = (struct homa_common_hdr *)skb_transport_header(skb);
	h->flags = HOMA_HIJACK_FLAGS;
	h->urgent = htons(HOMA_HIJACK_URGENT);
	NAPI_GRO_CB(skb)->same_flow = 0;
	cur_offload_core->held_skb = NULL;
	cur_offload_core->held_bucket = 99;
	EXPECT_EQ(NULL, homa_hijack_gro_receive(&self->empty_list, skb));
	EXPECT_EQ(skb, cur_offload_core->held_skb);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(IPPROTO_HOMA, ip_hdr(skb)->protocol);
	EXPECT_EQ(29695, ip_hdr(skb)->check);
	kfree_skb(skb);
	homa_hijack_end();
}

/* Tests for functions in homa_hijack.h: */

TEST_F(homa_hijack, homa_hijack_set_hdr)
{
	struct homa_route *route = homa_route_get(&self->hsk, &self->src_ip);
	struct homa_common_hdr *h;
	struct sk_buff *skb;
	int summed;

	skb = mock_skb_alloc(&self->src_ip, &self->dst_ip,
			     &self->header.common, 1400, 0);
	homa_hijack_set_hdr(skb, route, true);
	h = (struct homa_common_hdr *)skb_transport_header(skb);
	EXPECT_EQ(HOMA_HIJACK_FLAGS, h->flags);
	EXPECT_EQ(HOMA_HIJACK_URGENT, ntohs(h->urgent));
	summed = skb->ip_summed;
	EXPECT_EQ(CHECKSUM_PARTIAL, summed);

	homa_route_release(route);
	kfree_skb(skb);
}

TEST_F(homa_hijack, homa_hijack_sock_init)
{
	EXPECT_EQ(IPPROTO_HOMA, self->hsk.sock.sk_protocol);

	/* First call: hijack_tcp option not set. */
	homa_hijack_sock_init(&self->hsk);
	EXPECT_EQ(IPPROTO_HOMA, self->hsk.sock.sk_protocol);

	/* Second call: hijack_tcp option set. */
	self->homa.hijack_tcp = 1;
	homa_hijack_sock_init(&self->hsk);
	EXPECT_EQ(IPPROTO_TCP, self->hsk.sock.sk_protocol);
}

TEST_F(homa_hijack, homa_sock_hijacked)
{
	EXPECT_EQ(0, homa_sock_hijacked(&self->hsk));

	self->homa.hijack_tcp = 1;
	homa_hijack_sock_init(&self->hsk);
	EXPECT_EQ(1, homa_sock_hijacked(&self->hsk));
}

TEST_F(homa_hijack, homa_skb_hijacked)
{
	struct homa_route *route = homa_route_get(&self->hsk, &self->src_ip);
	struct sk_buff *skb;

	skb = mock_skb_alloc(&self->src_ip, &self->dst_ip,
			     &self->header.common, 1400, 0);
	EXPECT_EQ(0, homa_skb_hijacked(skb));
	homa_hijack_set_hdr(skb, route, true);
	EXPECT_EQ(1, homa_skb_hijacked(skb));

	homa_route_release(route);
	kfree_skb(skb);
}

TEST_F(homa_hijack, homa_skb_inner_hdr__native)
{
	struct homa_common_hdr *h;
	struct sk_buff *skb;

	skb = mock_skb_alloc(&self->src_ip, &self->dst_ip,
			     &self->header.common, 1400, 0);
	h = homa_skb_inner_hdr(skb);
	ASSERT_NE(NULL, h);
	EXPECT_EQ((unsigned char *)h, skb_transport_header(skb));
	EXPECT_EQ(self->header.common.sender_id, h->sender_id);
	kfree_skb(skb);
}

TEST_F(homa_hijack, homa_skb_inner_hdr__tcp_hijacked)
{
	struct homa_route *route = homa_route_get(&self->hsk, &self->src_ip);
	struct homa_common_hdr *h;
	struct sk_buff *skb;

	mock_ipv6 = false;
	skb = mock_skb_alloc(&self->src_ip, &self->dst_ip,
			     &self->header.common, 1400, 0);
	homa_hijack_set_hdr(skb, route, false);
	ip_hdr(skb)->protocol = IPPROTO_TCP;
	h = homa_skb_inner_hdr(skb);
	ASSERT_NE(NULL, h);
	EXPECT_EQ((unsigned char *)h, skb_transport_header(skb));
	EXPECT_EQ(self->header.common.sender_id, h->sender_id);

	homa_route_release(route);
	kfree_skb(skb);
}

TEST_F(homa_hijack, homa_skb_inner_hdr__not_hijacked_tcp)
{
	struct sk_buff *skb;

	/* Real (non-hijacked) TCP packets must not be mistaken for Homa
	 * packets, even if the IP protocol matches.
	 */
	mock_ipv6 = false;
	skb = mock_skb_alloc(&self->src_ip, &self->dst_ip,
			     &self->header.common, 1400, 0);
	ip_hdr(skb)->protocol = IPPROTO_TCP;
	EXPECT_EQ(NULL, homa_skb_inner_hdr(skb));
	kfree_skb(skb);
}

TEST_F(homa_hijack, homa_skb_inner_hdr__unknown_eth_type)
{
	struct sk_buff *skb;

	skb = mock_skb_alloc(&self->src_ip, &self->dst_ip,
			     &self->header.common, 1400, 0);
	skb->protocol = htons(ETH_P_ARP);
	EXPECT_EQ(NULL, homa_skb_inner_hdr(skb));
	kfree_skb(skb);
}

TEST_F(homa_hijack, homa_skb_inner_hdr__invalid_type)
{
	struct homa_common_hdr *h;
	struct sk_buff *skb;

	skb = mock_skb_alloc(&self->src_ip, &self->dst_ip,
			     &self->header.common, 1400, 0);
	h = (struct homa_common_hdr *)skb_transport_header(skb);
	h->type = MAX_OP + 1;
	EXPECT_EQ(NULL, homa_skb_inner_hdr(skb));
	kfree_skb(skb);
}

TEST_F(homa_hijack, homa_skb_inner_hdr__too_short)
{
	struct sk_buff *skb;

	skb = mock_raw_skb(&self->src_ip, &self->dst_ip, IPPROTO_HOMA,
			   sizeof(struct homa_common_hdr) - 1);
	skb_put(skb, sizeof(struct homa_common_hdr) - 1);
	EXPECT_EQ(NULL, homa_skb_inner_hdr(skb));
	kfree_skb(skb);
}

TEST_F(homa_hijack, homa_skb_inner_hdr__udp_header_in_nonlinear_data)
{
	struct skb_shared_info *shinfo;
	struct homa_common_hdr *h;
	struct sk_buff *skb;
	struct udphdr *uh;

	mock_ipv6 = false;
	skb = mock_raw_skb(&self->src_ip, &self->dst_ip, IPPROTO_UDP,
			   sizeof(*uh) + sizeof(self->header.common));
	uh = skb_put(skb, sizeof(*uh));
	uh->source = htons(HOMA_UDP_HIJACK_PORT);
	uh->dest = htons(HOMA_UDP_HIJACK_PORT);
	shinfo = skb_shinfo(skb);
	unit_alloc_frags(1, shinfo->frags, 0,
			 sizeof(self->header.common));
	memcpy(unit_frag_first_byte(&shinfo->frags[0]), &self->header.common,
	       sizeof(self->header.common));
	shinfo->nr_frags = 1;
	skb->data_len = sizeof(self->header.common);
	skb->len += skb->data_len;

	h = homa_skb_inner_hdr(skb);
	ASSERT_NE(NULL, h);
	EXPECT_EQ(self->header.common.sender_id, h->sender_id);
	EXPECT_EQ(0, skb->data_len);
	EXPECT_EQ(0, shinfo->nr_frags);
	kfree_skb(skb);
}

/* Tests for UDP hijacking (homa_hijack.c/h). */
#ifndef __STRIP__ /* See strip.py */

TEST_F(homa_hijack, homa_sock_udp_hijacked)
{
	EXPECT_EQ(0, homa_sock_udp_hijacked(&self->hsk));
	self->hsk.sock.sk_protocol = IPPROTO_UDP;
	EXPECT_EQ(1, homa_sock_udp_hijacked(&self->hsk));
	self->hsk.sock.sk_protocol = IPPROTO_HOMA;
}

TEST_F(homa_hijack, homa_hijack_udp_sock_select__tcp_hijack_wins)
{
	self->hnet->udp_state = HOMA_UDP_ENABLED;
	self->homa.hijack_tcp = 1;
	homa_hijack_sock_init(&self->hsk);
	homa_hijack_udp_sock_select(&self->hsk);
	homa_hijack_udp_unlock(self->hnet);
	EXPECT_EQ(IPPROTO_TCP, self->hsk.sock.sk_protocol);
}

TEST_F(homa_hijack, homa_hijack_udp_sock_select__enabled)
{
	self->hnet->udp_state = HOMA_UDP_ENABLED;
	homa_hijack_udp_sock_select(&self->hsk);
	homa_hijack_udp_unlock(self->hnet);
	EXPECT_EQ(IPPROTO_UDP, self->hsk.sock.sk_protocol);
}

TEST_F(homa_hijack, homa_hijack_udp_sock_select__disabled)
{
	homa_hijack_udp_sock_select(&self->hsk);
	homa_hijack_udp_unlock(self->hnet);
	EXPECT_EQ(IPPROTO_HOMA, self->hsk.sock.sk_protocol);
}

TEST_F(homa_hijack, homa_hijack_udp_net_init)
{
	struct homa_net hnet2;

	memset(&hnet2, 0xab, sizeof(hnet2));
	homa_hijack_udp_net_init(&hnet2);
	EXPECT_EQ(HOMA_UDP_DISABLED, hnet2.udp_state);
	EXPECT_EQ(NULL, hnet2.udp_tun4);
	EXPECT_EQ(NULL, hnet2.udp_tun6);
	EXPECT_EQ(0, atomic_read(&hnet2.udp_rpc_count));
	EXPECT_EQ(NULL, hnet2.udp_ctl_table);
	EXPECT_EQ(NULL, hnet2.udp_ctl_header);
}

TEST_F(homa_hijack, homa_hijack_udp_net_start__basics)
{
	struct net *net = mock_net_for_hnet(self->hnet);

	EXPECT_EQ(0, homa_hijack_udp_net_start(self->hnet, net));
	EXPECT_NE(NULL, self->hnet->udp_ctl_table);
	EXPECT_NE(NULL, self->hnet->udp_ctl_header);
	EXPECT_EQ(&self->hnet->hijack_udp, self->hnet->udp_ctl_table[0].data);
	EXPECT_EQ(1, mock_register_sysctl_size);

	homa_hijack_udp_net_exit_begin(self->hnet);
	EXPECT_EQ(NULL, self->hnet->udp_ctl_header);
	EXPECT_EQ(HOMA_UDP_TEARDOWN, self->hnet->udp_state);
	EXPECT_STREQ("unregister_net_sysctl_table", unit_log_get());

	homa_hijack_udp_net_destroy(self->hnet);
	EXPECT_EQ(NULL, self->hnet->udp_ctl_table);
}

TEST_F(homa_hijack, homa_hijack_udp_net_start__kmalloc_error)
{
	struct net *net = mock_net_for_hnet(self->hnet);

	mock_kmalloc_errors = 1;
	EXPECT_EQ(ENOMEM, -homa_hijack_udp_net_start(self->hnet, net));
	EXPECT_EQ(NULL, self->hnet->udp_ctl_table);
}

TEST_F(homa_hijack, homa_hijack_udp_net_start__register_sysctl_error)
{
	struct net *net = mock_net_for_hnet(self->hnet);

	mock_register_sysctl_errors = 1;
	EXPECT_EQ(ENOMEM, -homa_hijack_udp_net_start(self->hnet, net));
	EXPECT_EQ(NULL, self->hnet->udp_ctl_table);
}

TEST_F(homa_hijack, homa_hijack_udp_set_enabled__enable_creates_pair)
{
	struct net *net = mock_net_for_hnet(self->hnet);

	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 1));
	EXPECT_EQ(HOMA_UDP_ENABLED, self->hnet->udp_state);
	EXPECT_EQ(1, self->hnet->hijack_udp);
	EXPECT_NE(NULL, self->hnet->udp_tun4);
	EXPECT_NE(NULL, self->hnet->udp_tun6);

	/* Enabling again is a no-op (doesn't recreate the pair). */
	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 1));
	EXPECT_EQ(HOMA_UDP_ENABLED, self->hnet->udp_state);
}

TEST_F(homa_hijack, homa_hijack_udp_set_enabled__create_pair_v4_error)
{
	struct net *net = mock_net_for_hnet(self->hnet);

	mock_udp_sock_create_errors = 1;
	EXPECT_EQ(EADDRINUSE, -homa_hijack_udp_set_enabled(self->hnet, net,
			1));
	EXPECT_EQ(HOMA_UDP_DISABLED, self->hnet->udp_state);
	EXPECT_EQ(NULL, self->hnet->udp_tun4);
	EXPECT_EQ(NULL, self->hnet->udp_tun6);
}

TEST_F(homa_hijack, homa_hijack_udp_set_enabled__create_pair_v6_error)
{
	struct net *net = mock_net_for_hnet(self->hnet);

	mock_udp_sock_create_errors = 2;
	EXPECT_EQ(EADDRINUSE, -homa_hijack_udp_set_enabled(self->hnet, net,
			1));
	EXPECT_EQ(HOMA_UDP_DISABLED, self->hnet->udp_state);
	EXPECT_EQ(NULL, self->hnet->udp_tun4);
	EXPECT_EQ(NULL, self->hnet->udp_tun6);
	EXPECT_EQ(1, mock_udp_tunnel_release_count);
}

TEST_F(homa_hijack, homa_hijack_udp_set_enabled__disable_no_rpcs)
{
	struct net *net = mock_net_for_hnet(self->hnet);

	homa_hijack_udp_set_enabled(self->hnet, net, 1);
	mock_udp_tunnel_release_count = 0;
	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 0));
	EXPECT_EQ(HOMA_UDP_DISABLED, self->hnet->udp_state);
	EXPECT_EQ(0, self->hnet->hijack_udp);
	EXPECT_EQ(NULL, self->hnet->udp_tun4);
	EXPECT_EQ(NULL, self->hnet->udp_tun6);
	EXPECT_EQ(2, mock_udp_tunnel_release_count);
}

TEST_F(homa_hijack, homa_hijack_udp_set_enabled__disable_with_active_rpc_drains)
{
	struct net *net = mock_net_for_hnet(self->hnet);

	homa_hijack_udp_set_enabled(self->hnet, net, 1);
	atomic_set(&self->hnet->udp_rpc_count, 1);
	self->homa.timer_ticks = 500;
	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 0));
	EXPECT_EQ(HOMA_UDP_DRAINING, self->hnet->udp_state);
	EXPECT_EQ(0, self->hnet->hijack_udp);
	EXPECT_NE(NULL, self->hnet->udp_tun4);
	EXPECT_NE(NULL, self->hnet->udp_tun6);
	EXPECT_EQ(500 + self->homa.timeout_ticks,
		  self->hnet->udp_drain_deadline);

	/* Repeated disable requests while draining are no-ops. */
	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 0));
	EXPECT_EQ(HOMA_UDP_DRAINING, self->hnet->udp_state);
}

TEST_F(homa_hijack, homa_hijack_udp_set_enabled__teardown_rejects)
{
	struct net *net = mock_net_for_hnet(self->hnet);

	self->hnet->udp_state = HOMA_UDP_TEARDOWN;
	EXPECT_EQ(ENETDOWN, -homa_hijack_udp_set_enabled(self->hnet, net, 1));
	EXPECT_EQ(ENETDOWN, -homa_hijack_udp_set_enabled(self->hnet, net, 0));
}

TEST_F(homa_hijack, homa_hijack_udp_admit__socket_not_hijacked)
{
	struct homa_rpc rpc;

	memset(&rpc, 0, sizeof(rpc));
	rpc.hsk = &self->hsk;
	self->hsk.sock.sk_protocol = IPPROTO_HOMA;
	EXPECT_EQ(0, homa_hijack_udp_admit(&rpc));
	EXPECT_EQ(0, rpc.udp_admitted);
	EXPECT_EQ(0, atomic_read(&self->hnet->udp_rpc_count));
}

TEST_F(homa_hijack, homa_hijack_udp_admit__enabled)
{
	struct homa_rpc rpc;

	memset(&rpc, 0, sizeof(rpc));
	rpc.hsk = &self->hsk;
	self->hsk.sock.sk_protocol = IPPROTO_UDP;
	self->hnet->udp_state = HOMA_UDP_ENABLED;
	EXPECT_EQ(0, homa_hijack_udp_admit(&rpc));
	EXPECT_EQ(1, rpc.udp_admitted);
	EXPECT_EQ(1, atomic_read(&self->hnet->udp_rpc_count));
}

TEST_F(homa_hijack, homa_hijack_udp_admit__disabled_rejects)
{
	struct homa_rpc rpc;

	memset(&rpc, 0, sizeof(rpc));
	rpc.hsk = &self->hsk;
	self->hsk.sock.sk_protocol = IPPROTO_UDP;
	self->hnet->udp_state = HOMA_UDP_DRAINING;
	EXPECT_EQ(ENETDOWN, -homa_hijack_udp_admit(&rpc));
	EXPECT_EQ(0, rpc.udp_admitted);
	EXPECT_EQ(0, atomic_read(&self->hnet->udp_rpc_count));
}

TEST_F(homa_hijack, homa_hijack_udp_admit__disable_race_releases_pair)
{
	struct net *net = mock_net_for_hnet(self->hnet);
	struct homa_rpc rpc;

	memset(&rpc, 0, sizeof(rpc));
	rpc.hsk = &self->hsk;
	self->hsk.sock.sk_protocol = IPPROTO_UDP;
	ASSERT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 1));
	udp_race_hnet = self->hnet;
	udp_race_net = net;
	unit_hook_register(udp_disable_during_admit_hook);

	EXPECT_EQ(ENETDOWN, -homa_hijack_udp_admit(&rpc));
	EXPECT_EQ(0, rpc.udp_admitted);
	EXPECT_EQ(0, atomic_read(&self->hnet->udp_rpc_count));
	EXPECT_EQ(HOMA_UDP_DISABLED, self->hnet->udp_state);
	EXPECT_EQ(NULL, self->hnet->udp_tun4);
	EXPECT_EQ(NULL, self->hnet->udp_tun6);
}

TEST_F(homa_hijack, homa_hijack_udp_admit__disable_wins_race)
{
	struct net *net = mock_net_for_hnet(self->hnet);
	struct homa_rpc rpc;

	memset(&rpc, 0, sizeof(rpc));
	rpc.hsk = &self->hsk;
	self->hsk.sock.sk_protocol = IPPROTO_UDP;
	ASSERT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 1));
	udp_race_rpc = &rpc;
	udp_race_admit_result = 0;
	unit_hook_register(udp_admit_during_disable_hook);

	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 0));
	EXPECT_EQ(ENETDOWN, -udp_race_admit_result);
	EXPECT_EQ(0, rpc.udp_admitted);
	EXPECT_EQ(0, atomic_read(&self->hnet->udp_rpc_count));
	EXPECT_EQ(HOMA_UDP_DISABLED, self->hnet->udp_state);
	EXPECT_EQ(NULL, self->hnet->udp_tun4);
	EXPECT_EQ(NULL, self->hnet->udp_tun6);
}

TEST_F(homa_hijack, homa_hijack_udp_release__active_callback_completes)
{
	struct net *net = mock_net_for_hnet(self->hnet);
	struct homa_common_hdr hdr;

	ASSERT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 1));
	memset(&hdr, 0, sizeof(hdr));
	hdr.dport = htons(self->hsk.port);
	udp_race_hnet = self->hnet;
	udp_release_skb = mock_raw_skb(&self->src_ip, &self->dst_ip,
			IPPROTO_UDP, 0);
	udp_release_hdr = &hdr;
	udp_release_callback_count = 0;
	unit_hook_register(udp_callback_during_release_hook);

	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 0));
	EXPECT_EQ(1, udp_release_callback_count);
	EXPECT_EQ(HOMA_UDP_DISABLED, self->hnet->udp_state);
	EXPECT_EQ(2, mock_udp_tunnel_release_count);
	kfree_skb(udp_release_skb);
}

TEST_F(homa_hijack, homa_hijack_udp_end_rpc__triggers_release_when_draining)
{
	struct net *net = mock_net_for_hnet(self->hnet);
	struct homa_rpc rpc;

	memset(&rpc, 0, sizeof(rpc));
	rpc.hsk = &self->hsk;
	self->hsk.sock.sk_protocol = IPPROTO_UDP;
	homa_hijack_udp_set_enabled(self->hnet, net, 1);
	EXPECT_EQ(0, homa_hijack_udp_admit(&rpc));
	homa_hijack_udp_set_enabled(self->hnet, net, 0);
	EXPECT_EQ(HOMA_UDP_DRAINING, self->hnet->udp_state);
	EXPECT_NE(NULL, self->hnet->udp_tun4);

	homa_hijack_udp_end_rpc(&rpc);
	EXPECT_EQ(0, rpc.udp_admitted);
	EXPECT_EQ(HOMA_UDP_DISABLED, self->hnet->udp_state);
	EXPECT_EQ(NULL, self->hnet->udp_tun4);
	EXPECT_EQ(NULL, self->hnet->udp_tun6);

	/* Calling again is idempotent (no double-decrement or crash). */
	homa_hijack_udp_end_rpc(&rpc);
}

/* The tests below exercise the encap_rcv/encap_err_lookup/encap_err_rcv
 * callbacks registered with the UDP tunnel sockets (see homa_hijack.c).
 * Those callbacks are static, so they're reached indirectly: enabling
 * UDP hijacking populates mock_udp_tunnel_cfg (see
 * mock_setup_udp_tunnel_sock()) with the same function pointers that
 * were passed to setup_udp_tunnel_sock(), and the tests invoke them
 * through that struct.
 */
TEST_F(homa_hijack, homa_hijack_udp_encap_rcv__dispatches_udp_packet)
{
	struct net *net = mock_net_for_hnet(self->hnet);
	struct homa_resend_hdr h = {{.sport = htons(40000),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(1234),
			.type = RESEND},
			.offset = htonl(0), .length = htonl(100)};
	struct sk_buff *skb;
	struct udphdr *uh;

	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 1));
	self->hsk.sock.sk_protocol = IPPROTO_UDP;

	skb = mock_raw_skb(&self->src_ip, &self->dst_ip, IPPROTO_UDP,
			   sizeof(*uh) + sizeof(h));
	uh = skb_put(skb, sizeof(*uh));
	uh->source = htons(HOMA_UDP_HIJACK_PORT);
	uh->dest = htons(HOMA_UDP_HIJACK_PORT);
	memcpy(skb_put(skb, sizeof(h)), &h, sizeof(h));

	unit_log_clear();
	EXPECT_EQ(0, mock_udp_tunnel_cfg.encap_rcv(&self->hsk.sock, skb));
	EXPECT_SUBSTR("xmit RPC_UNKNOWN", unit_log_get());
}
TEST_F(homa_hijack, homa_hijack_udp_encap_rcv__ipv6_extension_header)
{
	struct net *net = mock_net_for_hnet(self->hnet);
	struct homa_resend_hdr h = {{.sport = htons(40000),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(1234),
			.type = RESEND},
			.offset = htonl(0), .length = htonl(100)};
	unsigned char *extension;
	struct sk_buff *skb;
	struct udphdr *uh;

	mock_ipv6 = true;
	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 1));
	self->hsk.sock.sk_protocol = IPPROTO_UDP;
	skb = mock_raw_skb(&self->src_ip, &self->dst_ip, IPPROTO_UDP,
			   8 + sizeof(*uh) + sizeof(h));
	ipv6_hdr(skb)->nexthdr = NEXTHDR_DEST;
	extension = skb_put(skb, 8);
	extension[0] = IPPROTO_UDP;
	extension[1] = 0;
	uh = skb_put(skb, sizeof(*uh));
	uh->source = htons(HOMA_UDP_HIJACK_PORT);
	uh->dest = htons(HOMA_UDP_HIJACK_PORT);
	memcpy(skb_put(skb, sizeof(h)), &h, sizeof(h));
	skb_pull(skb, 8);
	skb_reset_transport_header(skb);

	unit_log_clear();
	EXPECT_EQ(0, mock_udp_tunnel_cfg.encap_rcv(&self->hsk.sock, skb));
	EXPECT_SUBSTR("xmit RPC_UNKNOWN", unit_log_get());
}
TEST_F(homa_hijack, homa_hijack_udp_encap_rcv__nonlinear_homa_header)
{
	struct net *net = mock_net_for_hnet(self->hnet);
	struct homa_resend_hdr h = {{.sport = htons(40000),
			.dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(1234),
			.type = RESEND},
			.offset = htonl(0), .length = htonl(100)};
	struct skb_shared_info *shinfo;
	struct sk_buff *skb;
	struct udphdr *uh;

	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 1));
	self->hsk.sock.sk_protocol = IPPROTO_UDP;
	skb = mock_raw_skb(&self->src_ip, &self->dst_ip, IPPROTO_UDP,
			   sizeof(*uh) + sizeof(h));
	uh = skb_put(skb, sizeof(*uh));
	uh->source = htons(HOMA_UDP_HIJACK_PORT);
	uh->dest = htons(HOMA_UDP_HIJACK_PORT);
	shinfo = skb_shinfo(skb);
	unit_alloc_frags(1, shinfo->frags, 0, sizeof(h));
	memcpy(unit_frag_first_byte(&shinfo->frags[0]), &h, sizeof(h));
	shinfo->nr_frags = 1;
	skb->data_len = sizeof(h);
	skb->len += skb->data_len;

	unit_log_clear();
	EXPECT_EQ(0, mock_udp_tunnel_cfg.encap_rcv(&self->hsk.sock, skb));
	EXPECT_SUBSTR("xmit RPC_UNKNOWN", unit_log_get());
	EXPECT_NOSUBSTR("pskb discard", unit_log_get());
}
TEST_F(homa_hijack, homa_hijack_udp_encap_rcv__wrong_port_dropped)
{
	struct net *net = mock_net_for_hnet(self->hnet);
	struct sk_buff *skb;
	struct udphdr *uh;

	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 1));

	skb = mock_raw_skb(&self->src_ip, &self->dst_ip, IPPROTO_UDP,
			   sizeof(*uh));
	uh = skb_put(skb, sizeof(*uh));
	uh->source = htons(HOMA_UDP_HIJACK_PORT);
	uh->dest = htons(HOMA_UDP_HIJACK_PORT + 1);

	unit_log_clear();
	EXPECT_EQ(0, mock_udp_tunnel_cfg.encap_rcv(&self->hsk.sock, skb));
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_hijack, homa_hijack_udp_encap_rcv__too_short_dropped)
{
	struct net *net = mock_net_for_hnet(self->hnet);
	struct sk_buff *skb;

	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 1));

	skb = mock_raw_skb(&self->src_ip, &self->dst_ip, IPPROTO_UDP, 2);
	skb_put(skb, 2);

	unit_log_clear();
	EXPECT_EQ(0, mock_udp_tunnel_cfg.encap_rcv(&self->hsk.sock, skb));
	EXPECT_STREQ("", unit_log_get());
}

TEST_F(homa_hijack, homa_hijack_udp_encap_err_lookup__valid_accepted)
{
	struct net *net = mock_net_for_hnet(self->hnet);
	struct homa_common_hdr h;
	struct sk_buff *skb;
	struct udphdr *uh;

	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 1));

	memset(&h, 0, sizeof(h));
	skb = mock_raw_skb(&self->src_ip, &self->dst_ip, IPPROTO_UDP,
			   sizeof(*uh) + sizeof(h));
	uh = skb_put(skb, sizeof(*uh));
	uh->source = htons(HOMA_UDP_HIJACK_PORT);
	uh->dest = htons(HOMA_UDP_HIJACK_PORT);
	memcpy(skb_put(skb, sizeof(h)), &h, sizeof(h));

	EXPECT_EQ(0, mock_udp_tunnel_cfg.encap_err_lookup(&self->hsk.sock,
							  skb));
	kfree_skb(skb);
}
TEST_F(homa_hijack, homa_hijack_udp_encap_err_lookup__wrong_port_rejected)
{
	struct net *net = mock_net_for_hnet(self->hnet);
	struct homa_common_hdr h;
	struct sk_buff *skb;
	struct udphdr *uh;

	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 1));

	memset(&h, 0, sizeof(h));
	skb = mock_raw_skb(&self->src_ip, &self->dst_ip, IPPROTO_UDP,
			   sizeof(*uh) + sizeof(h));
	uh = skb_put(skb, sizeof(*uh));
	uh->source = htons(HOMA_UDP_HIJACK_PORT);
	uh->dest = htons(HOMA_UDP_HIJACK_PORT + 1);
	memcpy(skb_put(skb, sizeof(h)), &h, sizeof(h));

	EXPECT_EQ(1, mock_udp_tunnel_cfg.encap_err_lookup(&self->hsk.sock,
							  skb));
	kfree_skb(skb);
}
TEST_F(homa_hijack, homa_hijack_udp_encap_err_lookup__too_short_rejected)
{
	struct net *net = mock_net_for_hnet(self->hnet);
	struct sk_buff *skb;
	struct udphdr *uh;

	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 1));

	skb = mock_raw_skb(&self->src_ip, &self->dst_ip, IPPROTO_UDP,
			   sizeof(*uh));
	uh = skb_put(skb, sizeof(*uh));
	uh->source = htons(HOMA_UDP_HIJACK_PORT);
	uh->dest = htons(HOMA_UDP_HIJACK_PORT);

	EXPECT_EQ(1, mock_udp_tunnel_cfg.encap_err_lookup(&self->hsk.sock,
							  skb));
	kfree_skb(skb);
}

TEST_F(homa_hijack, homa_hijack_udp_encap_err_rcv__econnrefused_translated)
{
	struct net *net = mock_net_for_hnet(self->hnet);
	struct homa_rpc *crpc;
	struct homa_common_hdr h;
	struct sk_buff *skb;

	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 1));
	self->hsk.sock.sk_protocol = IPPROTO_UDP;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->src_ip,
			       &self->dst_ip, 99, 1000, 100, 100);
	ASSERT_NE(NULL, crpc);

	memset(&h, 0, sizeof(h));
	h.dport = htons(99);
	skb = mock_raw_skb(&self->src_ip, &self->dst_ip, IPPROTO_UDP, 0);

	mock_udp_tunnel_cfg.encap_err_rcv(self->hnet->udp_tun4->sk, skb,
					  ECONNREFUSED,
					  htons(HOMA_UDP_HIJACK_PORT), 0,
					  (u8 *)&h);
	EXPECT_EQ(ENOTCONN, -crpc->error);

	kfree_skb(skb);
}
TEST_F(homa_hijack, homa_hijack_udp_encap_err_rcv__other_errno_uses_port_filter)
{
	struct net *net = mock_net_for_hnet(self->hnet);
	struct homa_rpc *crpc;
	struct homa_common_hdr h;
	struct sk_buff *skb;

	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 1));
	self->hsk.sock.sk_protocol = IPPROTO_UDP;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->src_ip,
			       &self->dst_ip, 99, 1000, 100, 100);
	ASSERT_NE(NULL, crpc);

	memset(&h, 0, sizeof(h));
	h.dport = htons(12345);
	skb = mock_raw_skb(&self->src_ip, &self->dst_ip, IPPROTO_UDP, 0);

	mock_udp_tunnel_cfg.encap_err_rcv(self->hnet->udp_tun4->sk, skb,
					  EHOSTUNREACH,
					  htons(HOMA_UDP_HIJACK_PORT), 0,
					  (u8 *)&h);
	EXPECT_EQ(0, crpc->error);

	h.dport = htons(99);
	mock_udp_tunnel_cfg.encap_err_rcv(self->hnet->udp_tun4->sk, skb,
					  EHOSTUNREACH,
					  htons(HOMA_UDP_HIJACK_PORT), 0,
					  (u8 *)&h);
	EXPECT_EQ(EHOSTUNREACH, -crpc->error);

	kfree_skb(skb);
}
TEST_F(homa_hijack, homa_hijack_udp_encap_err_rcv__emsgsize_updates_pmtu_and_aborts)
{
	struct net *net = mock_net_for_hnet(self->hnet);
	struct homa_rpc *crpc;
	struct homa_route *route;
	struct homa_common_hdr h;
	struct sk_buff *skb;
	u64 route_allocs;

	EXPECT_EQ(0, homa_hijack_udp_set_enabled(self->hnet, net, 1));
	self->hsk.sock.sk_protocol = IPPROTO_UDP;
	mock_ipv6 = false;
	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->src_ip,
			       &self->dst_ip, 99, 1000, 100, 100);
	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(1, self->hnet->num_routes);
	route_allocs = homa_metrics_per_cpu()->route_allocs;

	memset(&h, 0, sizeof(h));
	h.dport = htons(99);
	skb = mock_raw_skb(&self->src_ip, &self->dst_ip, IPPROTO_UDP, 64);
	skb_put(skb, 64);
	skb_push(skb, sizeof(struct iphdr));
	((struct iphdr *)skb->data)->ihl = 5;
	skb_set_network_header(skb, 40);

	unit_log_clear();
	mock_udp_tunnel_cfg.encap_err_rcv(self->hnet->udp_tun4->sk, skb,
					  EMSGSIZE,
					  htons(HOMA_UDP_HIJACK_PORT), 500,
					  (u8 *)&h);
	EXPECT_SUBSTR("update_pmtu mtu 500", unit_log_get());
	EXPECT_EQ(EMSGSIZE, -crpc->error);
	EXPECT_EQ(0, self->hnet->num_routes);

	route = homa_route_get(&self->hsk, &self->dst_ip);
	ASSERT_FALSE(IS_ERR(route));
	EXPECT_EQ(route_allocs + 1, homa_metrics_per_cpu()->route_allocs);
	EXPECT_EQ(1, self->hnet->num_routes);
	homa_route_release(route);

	kfree_skb(skb);
}

TEST_F(homa_hijack, homa_hijack_prepend_udp__ipv4)
{
	struct homa_route *route = homa_route_get(&self->hsk, &self->src_ip);
	struct homa_common_hdr *h;
	struct udphdr *uh;
	struct sk_buff *skb;
	int orig_len;

	skb = mock_skb_alloc(&self->src_ip, &self->dst_ip,
			     &self->header.common, 1400, 0);
	orig_len = skb->len;

	homa_hijack_prepend_udp(skb, route, false);

	EXPECT_EQ(orig_len + sizeof(struct udphdr), skb->len);
	uh = (struct udphdr *)skb_transport_header(skb);
	EXPECT_EQ(HOMA_UDP_HIJACK_PORT, ntohs(uh->source));
	EXPECT_EQ(HOMA_UDP_HIJACK_PORT, ntohs(uh->dest));
	EXPECT_EQ(orig_len + sizeof(struct udphdr), ntohs(uh->len));
	EXPECT_EQ(555U, uh->check);

	/* The original Homa header must still be intact immediately after
	 * the new UDP header.
	 */
	h = (struct homa_common_hdr *)(uh + 1);
	EXPECT_EQ(self->header.common.type, h->type);
	EXPECT_EQ(self->header.common.sender_id, h->sender_id);

	homa_route_release(route);
	kfree_skb(skb);
}

TEST_F(homa_hijack, homa_hijack_prepend_udp__ipv6)
{
	struct homa_route *route = homa_route_get(&self->hsk, &self->src_ip);
	struct homa_common_hdr *h;
	struct udphdr *uh;
	struct sk_buff *skb;
	int orig_len;

	skb = mock_skb_alloc(&self->src_ip, &self->dst_ip,
			     &self->header.common, 1400, 0);
	orig_len = skb->len;

	homa_hijack_prepend_udp(skb, route, true);

	EXPECT_EQ(orig_len + sizeof(struct udphdr), skb->len);
	uh = (struct udphdr *)skb_transport_header(skb);
	EXPECT_EQ(HOMA_UDP_HIJACK_PORT, ntohs(uh->source));
	EXPECT_EQ(HOMA_UDP_HIJACK_PORT, ntohs(uh->dest));
	EXPECT_EQ(orig_len + sizeof(struct udphdr), ntohs(uh->len));
	EXPECT_EQ(777U, uh->check);

	h = (struct homa_common_hdr *)(uh + 1);
	EXPECT_EQ(self->header.common.type, h->type);
	EXPECT_EQ(self->header.common.sender_id, h->sender_id);

	homa_route_release(route);
	kfree_skb(skb);
}

TEST_F(homa_hijack, homa_skb_inner_hdr__udp_hijacked)
{
	struct homa_route *route = homa_route_get(&self->hsk, &self->src_ip);
	struct homa_common_hdr *h;
	struct sk_buff *skb;

	mock_ipv6 = false;
	skb = mock_skb_alloc(&self->src_ip, &self->dst_ip,
			     &self->header.common, 1400, 0);
	homa_hijack_prepend_udp(skb, route, false);
	ip_hdr(skb)->protocol = IPPROTO_UDP;

	h = homa_skb_inner_hdr(skb);
	ASSERT_NE(NULL, h);
	EXPECT_EQ((unsigned char *)h,
		 skb_transport_header(skb) + sizeof(struct udphdr));
	EXPECT_EQ(self->header.common.sender_id, h->sender_id);

	homa_route_release(route);
	kfree_skb(skb);
}

TEST_F(homa_hijack, homa_skb_inner_hdr__udp_wrong_port)
{
	struct homa_route *route = homa_route_get(&self->hsk, &self->src_ip);
	struct udphdr *uh;
	struct sk_buff *skb;

	/* A UDP packet that isn't using the reserved hijack port must not
	 * be mistaken for a Homa-over-UDP packet.
	 */
	mock_ipv6 = false;
	skb = mock_skb_alloc(&self->src_ip, &self->dst_ip,
			     &self->header.common, 1400, 0);
	homa_hijack_prepend_udp(skb, route, false);
	ip_hdr(skb)->protocol = IPPROTO_UDP;
	uh = (struct udphdr *)skb_transport_header(skb);
	uh->dest = htons(HOMA_UDP_HIJACK_PORT + 1);

	EXPECT_EQ(NULL, homa_skb_inner_hdr(skb));

	homa_route_release(route);
	kfree_skb(skb);
}
#endif /* See strip.py */