// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

#include "homa_impl.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#include "homa_sock.h"
#include "homa_udp_tunnel.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "utils.h"

#ifndef __STRIP__ /* See strip.py */
#include "homa_offload.h"

static const int control_header_lengths[] = {
	sizeof(struct homa_grant_hdr),
	sizeof(struct homa_resend_hdr),
	sizeof(struct homa_rpc_unknown_hdr),
	sizeof(struct homa_busy_hdr),
	sizeof(struct homa_cutoffs_hdr),
	sizeof(struct homa_freeze_hdr),
	sizeof(struct homa_need_ack_hdr),
	sizeof(struct homa_ack_hdr),
	sizeof(struct homa_start_msg_hdr)
};
#endif /* See strip.py */

FIXTURE(homa_udp_tunnel) {
	struct homa homa;
	struct homa_net *hnet;
	struct homa_sock hsk;
	struct in6_addr client;
	struct in6_addr server;
	struct homa_data_hdr data;
};

FIXTURE_SETUP(homa_udp_tunnel)
{
	homa_init(&self->homa);
	self->hnet = mock_hnet(0, &self->homa);
	mock_sock_init(&self->hsk, self->hnet, 99);
	self->client = unit_get_in_addr("1.2.3.4");
	self->server = unit_get_in_addr("5.6.7.8");
	memset(&self->data, 0, sizeof(self->data));
	self->data.common.sport = htons(40000);
	self->data.common.dport = htons(99);
	self->data.common.sender_id = cpu_to_be64(100);
	self->data.common.type = DATA;
	self->data.msg_length = htonl(64);
	unit_log_clear();
}

FIXTURE_TEARDOWN(homa_udp_tunnel)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_udp_tunnel, socket_pair_and_checksum_policy)
{
	struct socket *udp4 = rcu_access_pointer(self->hnet->udp4);
	struct socket *udp6 = rcu_access_pointer(self->hnet->udp6);

	ASSERT_NE(NULL, udp4);
	ASSERT_NE(NULL, udp6);
	EXPECT_EQ(AF_INET, udp4->sk->sk_family);
	EXPECT_EQ(AF_INET6, udp6->sk->sk_family);
	EXPECT_EQ(htons(HOMA_UDP_PORT), mock_udp_port_cfg[0].local_udp_port);
	EXPECT_EQ(htons(HOMA_UDP_PORT), mock_udp_port_cfg[1].local_udp_port);
	EXPECT_TRUE((bool)mock_udp_port_cfg[0].use_udp_checksums);
	EXPECT_TRUE((bool)mock_udp_port_cfg[1].ipv6_v6only);
	EXPECT_TRUE((bool)mock_udp_port_cfg[1].use_udp6_tx_checksums);
	EXPECT_TRUE((bool)mock_udp_port_cfg[1].use_udp6_rx_checksums);
	EXPECT_NE(0, udp_sk(udp4->sk)->encap_type);
	EXPECT_NE(0, udp_sk(udp6->sk)->encap_type);
	EXPECT_EQ(&homa_udp_encap_rcv, udp_sk(udp4->sk)->encap_rcv);
	EXPECT_EQ(&homa_udp_encap_err_rcv, udp_sk(udp6->sk)->encap_err_rcv);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(&homa_udp_gro_receive, udp_sk(udp6->sk)->gro_receive);
	EXPECT_EQ(&homa_udp_gro_complete, udp_sk(udp6->sk)->gro_complete);
#endif /* See strip.py */

	/* Both sockets are published with the namespace. */
	EXPECT_EQ(self->hnet, udp4->sk->sk_user_data);
	EXPECT_EQ(self->hnet, udp6->sk->sk_user_data);
}

TEST_F(homa_udp_tunnel, first_socket_failure_preserves_error)
{
	struct homa_net fresh;
	int releases = mock_udp_release_calls;

	homa_net_init(&fresh, &self->homa);
	mock_udp_create_errors = 1;
	mock_udp_create_errno = -EAFNOSUPPORT;
	EXPECT_EQ(-EAFNOSUPPORT, homa_udp_init(&fresh, &mock_nets[0]));
	EXPECT_EQ(NULL, rcu_access_pointer(fresh.udp4));
	EXPECT_EQ(NULL, rcu_access_pointer(fresh.udp6));
	EXPECT_EQ(releases, mock_udp_release_calls);
}

TEST_F(homa_udp_tunnel, second_socket_failure_unwinds_once)
{
	struct homa_net fresh;
	int releases = mock_udp_release_calls;

	homa_net_init(&fresh, &self->homa);
	mock_udp_create_errors = 2;
	mock_udp_create_errno = -EADDRINUSE;
	EXPECT_EQ(-EADDRINUSE, homa_udp_init(&fresh, &mock_nets[0]));
	EXPECT_EQ(NULL, rcu_access_pointer(fresh.udp4));
	EXPECT_EQ(NULL, rcu_access_pointer(fresh.udp6));
	EXPECT_EQ(releases + 1, mock_udp_release_calls);
	homa_udp_destroy(&fresh);
	EXPECT_EQ(releases + 1, mock_udp_release_calls);
}

TEST_F(homa_udp_tunnel, net_start_failure_unwinds_without_double_release)
{
	struct homa_net fresh;
	int releases = mock_udp_release_calls;

	/* homa_net_start destroys the homa_net when homa_udp_init fails. */
	homa_net_init(&fresh, &self->homa);
	mock_udp_create_errors = 2;
	EXPECT_EQ(-EADDRINUSE, homa_udp_init(&fresh, &mock_nets[0]));
	homa_net_destroy(&fresh);
	EXPECT_EQ(releases + 1, mock_udp_release_calls);
}

TEST_F(homa_udp_tunnel, receive_both_families_dispatches_inner_homa)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct socket *socket = i ? rcu_access_pointer(self->hnet->udp6) :
					   rcu_access_pointer(self->hnet->udp4);
		struct homa_rpc *rpc;
		struct sk_buff *skb;
		int count = mock_skb_count();

		mock_ipv6 = i;
		self->client = unit_get_in_addr(i ? "2001:db8::1" : "1.2.3.4");
		self->server = unit_get_in_addr(i ? "2001:db8::2" : "5.6.7.8");
		self->hsk.sock.sk_family = i ? AF_INET6 : AF_INET;
		self->data.common.sender_id = cpu_to_be64(100 + 2 * i);
		skb = unit_udp_skb(&self->client, &self->server,
				   &self->data.common, 64);
		EXPECT_EQ(sizeof(struct udphdr) + sizeof(self->data) + 64,
			  skb->len);
		EXPECT_EQ(htons(HOMA_UDP_PORT), udp_hdr(skb)->source);
		EXPECT_EQ(htons(HOMA_UDP_PORT), udp_hdr(skb)->dest);
		/* Keep an inspection reference across the consuming callback. */
		skb_get(skb);
		EXPECT_EQ(0, udp_sk(socket->sk)->encap_rcv(socket->sk, skb));
		EXPECT_EQ(i + 1, unit_list_length(&self->hsk.active_rpcs));
		IF_NO_STRIP(EXPECT_EQ(i + 1,
			homa_metrics_per_cpu()->packets_received[DATA - DATA]));
		EXPECT_EQ(0, skb_transport_offset(skb));
		EXPECT_EQ(sizeof(self->data) + 64, skb->len);
		EXPECT_EQ(i, skb_is_ipv6(skb));
		EXPECT_EQ(0, memcmp(&self->data, skb->data, sizeof(self->data)));
		EXPECT_EQ(2, refcount_read(&skb->users));
		EXPECT_EQ(count + 1, mock_skb_count());
		rpc = homa_rpc_find_server(&self->hsk, &self->client, 101 + 2 * i);
		ASSERT_NE(NULL, rpc);
		EXPECT_EQ(40000, rpc->dport);
		EXPECT_EQ(64, rpc->msgin.length);
		EXPECT_EQ(0, rpc->msgin.bytes_remaining);
		EXPECT_EQ(skb, skb_peek(&rpc->msgin.packets));
		EXPECT_TRUE(ipv6_addr_equal(&self->client,
					   &rpc->route->peer->addr));
		homa_rpc_unlock(rpc);
		kfree_skb(skb);
		EXPECT_EQ(count + 1, mock_skb_count());
	}
	IF_NO_STRIP(EXPECT_EQ(2, homa_metrics_per_cpu()->softirq_calls));
}

#ifndef __STRIP__ /* See strip.py */
static void receive_control_types(struct __test_metadata *_metadata,
				 FIXTURE_DATA(homa_udp_tunnel) *self, int family)
{
	struct homa_route *route;
	struct socket *socket;
	int type;

	mock_ipv6 = family == AF_INET6;
	self->hsk.sock.sk_family = family;
	self->client = unit_get_in_addr(mock_ipv6 ? "2001:db8::1" : "1.2.3.4");
	self->server = unit_get_in_addr(mock_ipv6 ? "2001:db8::2" : "5.6.7.8");
	socket = mock_ipv6 ? rcu_access_pointer(self->hnet->udp6) :
			     rcu_access_pointer(self->hnet->udp4);
	ASSERT_EQ(family, socket->sk->sk_family);
	route = homa_route_get(&self->hsk, &self->client);
	ASSERT_FALSE(IS_ERR(route));
	mock_xmit_log_verbose = 1;
	for (type = GRANT; type <= MAX_OP; type++) {
		union {
			struct homa_common_hdr common;
			struct homa_grant_hdr grant;
			struct homa_resend_hdr resend;
			struct homa_cutoffs_hdr cutoffs;
			struct homa_ack_hdr ack;
			struct homa_start_msg_hdr start;
		} packet = {};
		struct homa_rpc *rpc = NULL;
		struct sk_buff *skb;
		int header_length = control_header_lengths[type - GRANT];
		int length = max_t(int, header_length, HOMA_MIN_PKT_LENGTH);
		int id = 100 + 2 * (type - GRANT);
		int active, count, calls;
		u64 received, softirqs;

		packet.common = self->data.common;
		packet.common.type = type;
		packet.common.sender_id = cpu_to_be64(id);
		switch (type) {
		case GRANT:
			rpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING,
					&self->client, &self->server, 40000,
					id ^ 1, 64, 256);
			ASSERT_NE(NULL, rpc);
			rpc->msgout.granted = 0;
			rpc->silent_ticks = 17;
			packet.grant.offset = htonl(128);
			packet.grant.priority = 3;
			break;
		case RESEND:
			packet.resend.offset = htonl(32);
			packet.resend.length = htonl(64);
			packet.resend.priority = 2;
			break;
		case RPC_UNKNOWN:
		case BUSY:
		case ACK:
			self->data.common.sender_id = packet.common.sender_id;
			rpc = homa_rpc_alloc_server(&self->hsk, &self->client,
						   &self->data.common);
			ASSERT_FALSE(IS_ERR(rpc));
			rpc->silent_ticks = 17;
			homa_rpc_unlock(rpc);
			break;
		case CUTOFFS:
			packet.cutoffs.unsched_cutoffs[1] = htonl(900);
			packet.cutoffs.unsched_cutoffs[7] = htonl(100);
			packet.cutoffs.cutoff_version = htons(7);
			break;
		case FREEZE:
			ASSERT_EQ(0, tt_init(NULL));
			EXPECT_EQ(0, atomic_read(&tt_frozen));
			break;
		case NEED_ACK:
			/* A server requests an ACK from a client with no RPC. */
			packet.common.sender_id = cpu_to_be64(id | 1);
			break;
		case START_MSG:
			packet.start.msg_length = htonl(64);
			break;
		}
		active = unit_list_length(&self->hsk.active_rpcs);
		count = mock_skb_count();
		calls = mock_udp_xmit_calls;
		received = homa_metrics_per_cpu()->packets_received[type - DATA];
		softirqs = homa_metrics_per_cpu()->softirq_calls;
		skb = unit_udp_skb(&self->client, &self->server, &packet.common,
				   length - header_length);
		EXPECT_EQ(sizeof(struct udphdr) + length, skb->len);
		EXPECT_EQ(htons(HOMA_UDP_PORT), udp_hdr(skb)->source);
		EXPECT_EQ(htons(HOMA_UDP_PORT), udp_hdr(skb)->dest);
		EXPECT_EQ(skb->len, ntohs(udp_hdr(skb)->len));
		EXPECT_EQ(CHECKSUM_UNNECESSARY, (int)skb->ip_summed);
		skb_get(skb);
		unit_log_clear();
		EXPECT_EQ(0, udp_sk(socket->sk)->encap_rcv(socket->sk, skb));
		EXPECT_EQ(softirqs + 1, homa_metrics_per_cpu()->softirq_calls);
		EXPECT_EQ(received + (type != FREEZE),
			  homa_metrics_per_cpu()->packets_received[type - DATA]);
		EXPECT_EQ(0, homa_metrics_per_cpu()->short_packets);
		EXPECT_EQ(0, homa_metrics_per_cpu()->unknown_rpcs);
		EXPECT_EQ(0, homa_metrics_per_cpu()->unknown_packet_types);
		EXPECT_EQ(0, skb_transport_offset(skb));
		EXPECT_EQ(length, skb->len);
		EXPECT_EQ(family == AF_INET6, skb_is_ipv6(skb));
		EXPECT_EQ((mock_ipv6 ? sizeof(struct ipv6hdr) :
				      sizeof(struct iphdr)) + sizeof(struct udphdr),
			  skb_transport_header(skb) - skb_network_header(skb));
		EXPECT_EQ(0, memcmp(&packet, skb->data, header_length));
		EXPECT_EQ(1, refcount_read(&skb->users));
		EXPECT_EQ(count + 1, mock_skb_count());
		switch (type) {
		case GRANT:
			EXPECT_EQ(128, rpc->msgout.granted);
			EXPECT_EQ(3, rpc->msgout.priority);
			EXPECT_EQ(0, rpc->silent_ticks);
			break;
		case RESEND:
		case NEED_ACK: {
			char expected[80];

			EXPECT_EQ(calls + 1, mock_udp_xmit_calls);
			EXPECT_EQ(family, mock_udp_last_family);
			EXPECT_EQ(htons(HOMA_UDP_PORT), mock_udp_last_header.source);
			EXPECT_EQ(htons(HOMA_UDP_PORT), mock_udp_last_header.dest);
			EXPECT_SUBSTR(type == RESEND ? "xmit RPC_UNKNOWN" :
						      "xmit ACK", unit_log_get());
			snprintf(expected, sizeof(expected), "dport 40000, id %llu",
				 (unsigned long long)homa_local_id(
					 packet.common.sender_id));
			EXPECT_SUBSTR(expected, unit_log_get());
			break;
		}
		case RPC_UNKNOWN:
			EXPECT_EQ(1, homa_metrics_per_cpu()->server_rpcs_unknown);
			break;
		case BUSY:
			EXPECT_EQ(RPC_INCOMING, rpc->state);
			EXPECT_EQ(0, rpc->silent_ticks);
			break;
		case CUTOFFS:
			EXPECT_EQ(900, route->peer->unsched_cutoffs[1]);
			EXPECT_EQ(100, route->peer->unsched_cutoffs[7]);
			EXPECT_EQ(htons(7), route->peer->cutoff_version);
			break;
		case FREEZE:
			EXPECT_EQ(1, atomic_read(&tt_frozen));
			tt_unfreeze();
			tt_destroy();
			break;
		case START_MSG:
			rpc = homa_rpc_find_server(&self->hsk, &self->client, id ^ 1);
			ASSERT_NE(NULL, rpc);
			EXPECT_EQ(40000, rpc->dport);
			EXPECT_EQ(RPC_INCOMING, rpc->state);
			EXPECT_EQ(64, rpc->msgin.length);
			EXPECT_EQ(64, rpc->msgin.bytes_remaining);
			EXPECT_TRUE(test_bit(RPC_GOT_START_MSG, &rpc->flags));
			homa_rpc_unlock(rpc);
			break;
		}
		if (type == ACK || type == RPC_UNKNOWN) {
			struct homa_rpc *found;

			EXPECT_EQ(active - 1,
				  unit_list_length(&self->hsk.active_rpcs));
			found = homa_rpc_find_server(&self->hsk, &self->client, id ^ 1);
			EXPECT_EQ(NULL, found);
			if (found)
				homa_rpc_unlock(found);
		} else {
			EXPECT_EQ(active + (type == START_MSG),
				  unit_list_length(&self->hsk.active_rpcs));
		}
		kfree_skb(skb);
		EXPECT_EQ(count, mock_skb_count());
	}
	homa_route_release(route);
}

TEST_F(homa_udp_tunnel, receive_all_control_types_ipv4)
{
	receive_control_types(_metadata, self, AF_INET);
}

TEST_F(homa_udp_tunnel, receive_all_control_types_ipv6)
{
	receive_control_types(_metadata, self, AF_INET6);
}
#endif /* See strip.py */

TEST_F(homa_udp_tunnel, receive_zero_checksum_both_families)
{
	int i, count = mock_skb_count();

	for (i = 0; i < 2; i++) {
		struct socket *socket = i ? rcu_access_pointer(self->hnet->udp6) :
					   rcu_access_pointer(self->hnet->udp4);
		struct sk_buff *skb;

		mock_ipv6 = i;
		if (i) {
			self->client = unit_get_in_addr("2001:db8::1");
			self->server = unit_get_in_addr("2001:db8::2");
		}
		skb = unit_udp_skb(&self->client, &self->server,
				   &self->data.common, 64);
		udp_hdr(skb)->check = 0;
		EXPECT_EQ(0, homa_udp_encap_rcv(socket->sk, skb));
		EXPECT_EQ(SKB_DROP_REASON_UDP_CSUM, mock_drop_reasons[i]);
	}
	EXPECT_EQ(2, mock_num_drop_reasons);
	EXPECT_EQ(count, mock_skb_count());
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	IF_NO_STRIP(EXPECT_EQ(0, homa_metrics_per_cpu()->softirq_calls));
}

TEST_F(homa_udp_tunnel, malformed_lengths_ports_and_missing_linear_header)
{
	struct socket *socket = rcu_access_pointer(self->hnet->udp4);
	enum skb_drop_reason expected[] = {
		SKB_DROP_REASON_PKT_TOO_SMALL, SKB_DROP_REASON_PKT_TOO_SMALL,
		SKB_DROP_REASON_PKT_TOO_BIG, SKB_DROP_REASON_UNHANDLED_PROTO,
		SKB_DROP_REASON_HDR_TRUNC
	};
	int count = mock_skb_count(), i;

	for (i = 0; i < 5; i++) {
		struct sk_buff *skb = unit_udp_skb(&self->client, &self->server,
						&self->data.common, 64);
		if (i == 0)
			udp_hdr(skb)->len = htons(7);
		if (i == 1)
			udp_hdr(skb)->len = htons(skb->len + 1);
		if (i == 2)
			udp_hdr(skb)->len = htons(skb->len - 1);
		if (i == 3)
			udp_hdr(skb)->dest = htons(123);
		if (i == 4) {
			skb->tail -= skb->len - 4;
			skb->data_len = skb->len - 4;
		}
		EXPECT_EQ(0, homa_udp_encap_rcv(socket->sk, skb));
		EXPECT_EQ(expected[i], mock_drop_reasons[i]);
	}
	EXPECT_EQ(5, mock_num_drop_reasons);
	EXPECT_EQ(count, mock_skb_count());
	IF_NO_STRIP(EXPECT_EQ(0, homa_metrics_per_cpu()->softirq_calls));
}

TEST_F(homa_udp_tunnel, valid_nonlinear_header_is_pulled)
{
	struct socket *socket = rcu_access_pointer(self->hnet->udp4);
	struct sk_buff *skb = unit_udp_skb(&self->client, &self->server,
					  &self->data.common, 64);
	struct page *page = alloc_page(GFP_KERNEL);
	int nonlinear = skb->len - 4;

	memcpy(page_address(page), skb->data + 4, nonlinear);
	skb_fill_page_desc(skb, 0, page, 0, nonlinear);
	skb->data_len = nonlinear;
	skb->tail -= nonlinear;
	EXPECT_EQ(0, homa_udp_encap_rcv(socket->sk, skb));
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
}

TEST_F(homa_udp_tunnel, null_userdata_consumes_without_dispatch)
{
	struct socket *socket = rcu_access_pointer(self->hnet->udp4);
	struct sk_buff *skb = unit_udp_skb(&self->client, &self->server,
					  &self->data.common, 64);
	int count = mock_skb_count();

	rcu_assign_sk_user_data(socket->sk, NULL);
	EXPECT_EQ(0, homa_udp_encap_rcv(socket->sk, skb));
	EXPECT_EQ(count - 1, mock_skb_count());
	EXPECT_EQ(SKB_DROP_REASON_NO_SOCKET, mock_drop_reasons[0]);
	IF_NO_STRIP(EXPECT_EQ(0, homa_metrics_per_cpu()->softirq_calls));
}

#ifndef __STRIP__ /* See strip.py */
/**
 * gro_child() - Create a UDP-encapsulated Homa DATA packet in the layout
 * that a packet has on the frag_list of a Homa GRO batch (or when the tunnel
 * GRO callback bypasses it): skb->data at the IP header, transport header at
 * the UDP header.
 * @self:    Test fixture.
 * @offset:  Message offset to put in the packet.
 * Return:   The new packet carrying 64 bytes of data.
 */
static struct sk_buff *gro_child(FIXTURE_DATA(homa_udp_tunnel) *self,
				 int offset)
{
	struct sk_buff *skb;

	self->data.seg.offset = htonl(offset);
	skb = unit_udp_skb(&self->client, &self->server, &self->data.common, 64);
	skb_push(skb, mock_ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr));
	return skb;
}

TEST_F(homa_udp_tunnel, gro_aggregate_dispatches_head_and_children)
{
	struct socket *socket = rcu_access_pointer(self->hnet->udp4);
	int count = mock_skb_count();
	struct sk_buff *head, *child1, *child2;
	struct homa_rpc *rpc;

	self->data.msg_length = htonl(192);
	self->data.seg.offset = htonl(0);
	head = unit_udp_skb(&self->client, &self->server, &self->data.common, 64);
	child1 = gro_child(self, 64);
	child2 = gro_child(self, 128);

	/* Children are linked on the frag_list but are not accounted for in
	 * the head, as in the GRO contract.
	 */
	skb_shinfo(head)->frag_list = child1;
	child1->next = child2;
	ASSERT_EQ(sizeof(struct udphdr) + sizeof(self->data) + 64, head->len);
	ASSERT_EQ(0, head->data_len);
	ASSERT_EQ(head->len, ntohs(udp_hdr(head)->len));
	ASSERT_EQ(child1->len - skb_transport_offset(child1),
		  ntohs(udp_hdr(child1)->len));

	EXPECT_EQ(0, homa_udp_encap_rcv(socket->sk, head));
	EXPECT_EQ(0, unit_count_drops());
	EXPECT_EQ(1, homa_metrics_per_cpu()->softirq_calls);
	EXPECT_EQ(3, homa_metrics_per_cpu()->packets_received[DATA - DATA]);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(count + 3, mock_skb_count());
	rpc = homa_rpc_find_server(&self->hsk, &self->client, 101);
	ASSERT_NE(NULL, rpc);
	EXPECT_EQ(192, rpc->msgin.length);
	EXPECT_EQ(0, rpc->msgin.bytes_remaining);
	EXPECT_EQ(3, skb_queue_len(&rpc->msgin.packets));
	homa_rpc_unlock(rpc);

	/* Every packet now starts at its Homa header, and the head's frag
	 * list was detached without touching its accounting.
	 */
	EXPECT_EQ(NULL, skb_shinfo(head)->frag_list);
	EXPECT_EQ(sizeof(self->data) + 64, head->len);
	EXPECT_EQ(sizeof(self->data) + 64, child1->len);
	EXPECT_EQ(sizeof(self->data) + 64, child2->len);
	EXPECT_EQ(0, skb_transport_offset(head));
	EXPECT_EQ(0, skb_transport_offset(child1));
	EXPECT_EQ(0, skb_transport_offset(child2));
}

TEST_F(homa_udp_tunnel, gro_bad_child_dropped_alone)
{
	struct socket *socket = rcu_access_pointer(self->hnet->udp4);
	enum skb_drop_reason expected[] = {
		SKB_DROP_REASON_PKT_TOO_SMALL, SKB_DROP_REASON_PKT_TOO_BIG,
		SKB_DROP_REASON_UDP_CSUM, SKB_DROP_REASON_UNHANDLED_PROTO
	};
	int count = mock_skb_count(), i;

	for (i = 0; i < 4; i++) {
		struct sk_buff *head, *bad, *good;

		/* A separate RPC for each case, so there are no duplicates. */
		self->data.common.sender_id = cpu_to_be64(100 + 2 * i);
		self->data.msg_length = htonl(192);
		self->data.seg.offset = htonl(0);
		head = unit_udp_skb(&self->client, &self->server,
				    &self->data.common, 64);
		bad = gro_child(self, 64);
		good = gro_child(self, 128);
		if (i == 0)
			udp_hdr(bad)->len = htons(ntohs(udp_hdr(bad)->len) + 1);
		else if (i == 1)
			udp_hdr(bad)->len = htons(ntohs(udp_hdr(bad)->len) - 1);
		else if (i == 2)
			udp_hdr(bad)->check = 0;
		else
			udp_hdr(bad)->source = htons(123);
		skb_shinfo(head)->frag_list = bad;
		bad->next = good;
		EXPECT_EQ(0, homa_udp_encap_rcv(socket->sk, head));
		EXPECT_EQ(expected[i], unit_drop_reason(i));
		EXPECT_EQ(NULL, skb_shinfo(head)->frag_list);
	}

	/* The head and the good child of each batch were dispatched. */
	EXPECT_EQ(4, unit_count_drops());
	EXPECT_EQ(4, homa_metrics_per_cpu()->softirq_calls);
	EXPECT_EQ(8, homa_metrics_per_cpu()->packets_received[DATA - DATA]);
	EXPECT_EQ(4, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(count + 8, mock_skb_count());
}

TEST_F(homa_udp_tunnel, gro_bad_head_drops_whole_aggregate)
{
	struct socket *socket = rcu_access_pointer(self->hnet->udp4);
	int count = mock_skb_count();
	struct sk_buff *head, *child;

	self->data.msg_length = htonl(128);
	self->data.seg.offset = htonl(0);
	head = unit_udp_skb(&self->client, &self->server, &self->data.common, 64);
	udp_hdr(head)->dest = htons(123);
	child = gro_child(self, 64);
	skb_shinfo(head)->frag_list = child;
	EXPECT_EQ(0, homa_udp_encap_rcv(socket->sk, head));
	EXPECT_EQ(SKB_DROP_REASON_UNHANDLED_PROTO, mock_drop_reasons[0]);
	EXPECT_EQ(count, mock_skb_count());
	EXPECT_EQ(0, homa_metrics_per_cpu()->softirq_calls);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
}

TEST_F(homa_udp_tunnel, bypassed_packet_with_ip_header_present)
{
	struct socket *socket = rcu_access_pointer(self->hnet->udp4);
	struct sk_buff *skb = gro_child(self, 0);
	int count = mock_skb_count();

	EXPECT_EQ(0, homa_udp_encap_rcv(socket->sk, skb));
	EXPECT_EQ(0, unit_count_drops());
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(count, mock_skb_count());
	EXPECT_EQ(0, skb_transport_offset(skb));
	EXPECT_EQ(sizeof(self->data) + 64, skb->len);
}
#endif /* See strip.py */

/**
 * tx_skb() - Create an outgoing Homa packet with the headroom and layout
 * that the real packet builders produce (skb->data at the Homa header).
 * @header:  Homa header (of the full size for its type) to copy.
 * @payload: Number of data bytes to add after the header.
 * Return:   The new packet, padded to the minimum Homa packet length.
 */
static struct sk_buff *tx_skb(struct homa_common_hdr *header, int payload)
{
	int header_length = sizeof(struct homa_data_hdr);
	int length;
	struct sk_buff *skb;

#ifndef __STRIP__ /* See strip.py */
	if (header->type != DATA)
		header_length = control_header_lengths[header->type - GRANT];
#endif /* See strip.py */
	length = max_t(int, header_length + payload, HOMA_MIN_PKT_LENGTH);
	skb = __homa_skb_alloc(length);

	memcpy(skb_put(skb, header_length), header, header_length);
	memset(skb_put(skb, length - header_length), 0, length - header_length);
	if (header->type == DATA) {
		memset(homa_get_skb_info(skb), 0, sizeof(struct homa_skb_info));
		homa_get_skb_info(skb)->data_bytes = payload;
	}
	return skb;
}

TEST_F(homa_udp_tunnel, transmit_both_families_owns_skb_not_route)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct homa_route *route;
		struct sk_buff *skb;
		int count = mock_skb_count(), refs;

		mock_ipv6 = i;
		if (i)
			self->client = unit_get_in_addr("2001:db8::1");
		self->hsk.sock.sk_family = i ? AF_INET6 : AF_INET;
		route = homa_route_get(&self->hsk, &self->client);
		ASSERT_FALSE(IS_ERR(route));
		refs = refcount_read(&route->refs);
		skb = tx_skb(&self->data.common, 64);
		IF_NO_STRIP(self->homa.priority_map[3] = 6);
		homa_route_xmit(skb, &self->hsk, route, 3);
		EXPECT_EQ(count, mock_skb_count());
		EXPECT_EQ(refs, refcount_read(&route->refs));
		EXPECT_EQ(i ? AF_INET6 : AF_INET, mock_udp_last_family);
#ifndef __STRIP__ /* See strip.py */
		EXPECT_EQ(6 << 5, mock_udp_last_tos);
#else /* See strip.py */
		EXPECT_EQ(0, mock_udp_last_tos);
#endif /* See strip.py */
		EXPECT_EQ(htons(HOMA_UDP_PORT), mock_udp_last_header.source);
		EXPECT_EQ(htons(HOMA_UDP_PORT), mock_udp_last_header.dest);
		EXPECT_NE(0, mock_udp_last_header.check);
		EXPECT_EQ(CHECKSUM_PARTIAL, mock_udp_last_ip_summed);
		EXPECT_EQ(64, mock_udp_last_data_bytes);
		EXPECT_EQ(offsetof(struct udphdr, check),
			  mock_udp_last_csum_offset);
		homa_route_release(route);
	}
	EXPECT_EQ(2, mock_udp_xmit_calls);
}

TEST_F(homa_udp_tunnel, unsendable_control_rejected_before_handoff)
{
	struct homa_busy_hdr busy = {.common = {.type = BUSY}};
	int i;

	for (i = 0; i < 2; i++) {
		unsigned int overhead = sizeof(struct udphdr) +
				(i ? sizeof(struct ipv6hdr) : sizeof(struct iphdr));
		struct homa_route *route;
		int calls, count;

		mock_ipv6 = i;
		self->hsk.sock.sk_family = i ? AF_INET6 : AF_INET;
		self->client = unit_get_in_addr(i ? "2001:db8::1" : "1.2.3.4");
		route = homa_route_get(&self->hsk, &self->client);
		ASSERT_FALSE(IS_ERR(route));
		calls = mock_udp_xmit_calls;
		count = mock_skb_count();

		/* A padded control packet cannot be shrunk to fit; it is
		 * rejected before the consuming tunnel helper is invoked.
		 */
		mock_mtu = overhead + HOMA_MIN_PKT_LENGTH - 1;
		EXPECT_EQ(-EMSGSIZE, __homa_xmit_control(&busy, sizeof(busy),
							 route, &self->hsk));
		EXPECT_EQ(calls, mock_udp_xmit_calls);
		EXPECT_EQ(count, mock_skb_count());

		mock_mtu++;
		EXPECT_EQ(0, __homa_xmit_control(&busy, sizeof(busy), route,
						 &self->hsk));
		EXPECT_EQ(calls + 1, mock_udp_xmit_calls);
		EXPECT_EQ(count, mock_skb_count());
		homa_route_release(route);
	}
}

#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_udp_tunnel, all_control_types_transmit_without_rpc)
{
	unsigned char storage[HOMA_MAX_HEADER] = {};
	struct homa_common_hdr *header = (struct homa_common_hdr *)storage;
	int i, type;

	header->sport = htons(99);
	header->dport = htons(40000);
	header->sender_id = cpu_to_be64(100);
	for (i = 0; i < 2; i++) {
		struct homa_route *route;
		int calls = mock_udp_xmit_calls, refs;

		mock_ipv6 = i;
		self->hsk.sock.sk_family = i ? AF_INET6 : AF_INET;
		self->client = unit_get_in_addr(i ? "2001:db8::1" : "1.2.3.4");
		self->server = unit_get_in_addr(i ? "2001:db8::2" : "5.6.7.8");
		route = homa_route_get(&self->hsk, &self->client);
		ASSERT_FALSE(IS_ERR(route));
		refs = refcount_read(&route->refs);
		for (type = DATA + 1; type <= MAX_OP; type++) {
			int header_length = control_header_lengths[type - GRANT];
			int length = max_t(int, header_length, HOMA_MIN_PKT_LENGTH);
			int count = mock_skb_count();
			struct homa_common_hdr *inner;
			struct sk_buff *skb;

			header->type = type;
			skb = tx_skb(header, length - header_length);
			skb_get(skb);
			homa_route_xmit(skb, &self->hsk, route, 0);
			EXPECT_EQ(calls + type - DATA, mock_udp_xmit_calls);
			EXPECT_EQ(i ? AF_INET6 : AF_INET, mock_udp_last_family);
			EXPECT_EQ(htons(HOMA_UDP_PORT), mock_udp_last_header.source);
			EXPECT_EQ(htons(HOMA_UDP_PORT), mock_udp_last_header.dest);
			EXPECT_NE(0, mock_udp_last_header.check);
			EXPECT_EQ(CHECKSUM_PARTIAL, mock_udp_last_ip_summed);
			EXPECT_EQ(offsetof(struct udphdr, check),
				  mock_udp_last_csum_offset);
			EXPECT_EQ(sizeof(struct udphdr) + length,
				  ntohs(mock_udp_last_header.len));
			EXPECT_EQ((i ? sizeof(struct ipv6hdr) :
				       sizeof(struct iphdr)) +
				  sizeof(struct udphdr) + length, skb->len);
			EXPECT_EQ(i ? sizeof(struct ipv6hdr) : sizeof(struct iphdr),
				  skb_transport_header(skb) - skb_network_header(skb));
			EXPECT_EQ(i, skb_is_ipv6(skb));
			EXPECT_EQ(IPPROTO_UDP, i ? ipv6_hdr(skb)->nexthdr :
						  ip_hdr(skb)->protocol);
			inner = (struct homa_common_hdr *)(skb_transport_header(skb) +
							  sizeof(struct udphdr));
			EXPECT_EQ(type, inner->type);
			EXPECT_EQ(htons(99), inner->sport);
			EXPECT_EQ(htons(40000), inner->dport);
			EXPECT_EQ(cpu_to_be64(100), inner->sender_id);
			EXPECT_EQ(0, memcmp(header, inner, header_length));
			EXPECT_EQ(refs, refcount_read(&route->refs));
			EXPECT_EQ(1, refcount_read(&skb->users));
			EXPECT_EQ(count + 1, mock_skb_count());
			kfree_skb(skb);
			EXPECT_EQ(count, mock_skb_count());
			EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
		}
		EXPECT_EQ(calls + MAX_OP - DATA, mock_udp_xmit_calls);
		EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
		homa_route_release(route);
	}
}

TEST_F(homa_udp_tunnel, software_gso_keeps_udp_l4_and_forces_checksum_none)
{
	struct homa_route *route = homa_route_get(&self->hsk, &self->client);
	struct sk_buff *skb = tx_skb(&self->data.common,
				     sizeof(self->data) + 64);
	struct homa_data_hdr *second;

	ASSERT_FALSE(IS_ERR(route));
	skb_shinfo(skb)->gso_type = SKB_GSO_UDP_L4;
	skb_shinfo(skb)->gso_size = sizeof(self->data) + 32;
	skb_shinfo(skb)->gso_segs = 2;
	second = (struct homa_data_hdr *)(skb->data + sizeof(self->data) + 32);
	*second = self->data;
	second->seg.offset = htonl(32);
	homa_get_skb_info(skb)->data_bytes = 64;
	self->homa.gso_force_software = 1;
	homa_route_xmit(skb, &self->hsk, route, 0);
	EXPECT_EQ(CHECKSUM_NONE, mock_udp_last_ip_summed);
	EXPECT_EQ(SKB_GSO_UDP_L4, mock_udp_last_gso_type);
	EXPECT_EQ(sizeof(self->data) + 32, mock_udp_last_gso_size);
	EXPECT_EQ(2, mock_udp_last_gso_segs);
	EXPECT_EQ(offsetof(struct udphdr, check), mock_udp_last_csum_offset);
	homa_route_release(route);
}
#endif /* See strip.py */

TEST_F(homa_udp_tunnel, net_destroy_releases_pair_once_after_sockets)
{
	int releases = mock_udp_release_calls;

	EXPECT_NE(NULL, rcu_access_pointer(self->hnet->udp4));
	EXPECT_NE(NULL, rcu_access_pointer(self->hnet->udp6));
	homa_net_destroy(self->hnet);
	EXPECT_EQ(releases + 2, mock_udp_release_calls);
	EXPECT_EQ(NULL, rcu_access_pointer(self->hnet->udp4));
	EXPECT_EQ(NULL, rcu_access_pointer(self->hnet->udp6));
	EXPECT_TRUE(self->hsk.shutdown);

	/* A repeated release finds nothing left to do. */
	homa_udp_destroy(self->hnet);
	EXPECT_EQ(releases + 2, mock_udp_release_calls);
}

/**
 * use_family() - Configure the fixture and mocks for IPv4 or IPv6.
 * @self:  Test fixture.
 * @ipv6:  Nonzero means IPv6.
 */
static void use_family(FIXTURE_DATA(homa_udp_tunnel) *self, int ipv6)
{
	mock_ipv6 = ipv6;
	self->hsk.sock.sk_family = ipv6 ? AF_INET6 : AF_INET;
	self->client = unit_get_in_addr(ipv6 ? "2001:db8::1" : "1.2.3.4");
	self->server = unit_get_in_addr(ipv6 ? "2001:db8::2" : "5.6.7.8");
}

/**
 * icmp_quote() - Create an ICMP error whose quote is a Homa packet that
 * was sent to self->server through the tunnel.
 * @self:       Test fixture.
 * @ipv6:       True means ICMPv6 quoting IPv6, false means ICMP quoting IPv4.
 * @type:       ICMP type.
 * @code:       ICMP code.
 * @udp:        True means the quote includes the UDP header.
 * @homa_bytes: Number of bytes of the Homa common header included in the
 *              quote after the UDP header.
 * @dport:      Application destination port in the quoted Homa header.
 * Return:      skb with data at the quoted IP header and the transport
 *              header at the ICMP header.
 */
static struct sk_buff *icmp_quote(FIXTURE_DATA(homa_udp_tunnel) *self,
				  bool ipv6, int type, int code, bool udp,
				  int homa_bytes, int dport)
{
	struct homa_common_hdr common = self->data.common;
	struct sk_buff *skb = mock_raw_skb(&self->server, &self->client,
					   ipv6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP,
					   200);

	common.dport = htons(dport);
	if (ipv6) {
		struct icmp6hdr *icmp = skb_put(skb, sizeof(*icmp));
		struct ipv6hdr *ip;

		memset(icmp, 0, sizeof(*icmp));
		icmp->icmp6_type = type;
		icmp->icmp6_code = code;
		__skb_pull(skb, sizeof(*icmp));
		ip = skb_put(skb, sizeof(*ip));
		memset(ip, 0, sizeof(*ip));
		ip->version = 6;
		ip->nexthdr = IPPROTO_UDP;
		ip->saddr = self->client;
		ip->daddr = self->server;
	} else {
		struct icmphdr *icmp = skb_put(skb, sizeof(*icmp));
		struct iphdr *ip;

		memset(icmp, 0, sizeof(*icmp));
		icmp->type = type;
		icmp->code = code;
		__skb_pull(skb, sizeof(*icmp));
		ip = skb_put(skb, sizeof(*ip));
		memset(ip, 0, sizeof(*ip));
		ip->version = 4;
		ip->ihl = 5;
		ip->protocol = IPPROTO_UDP;
		ip->saddr = ipv6_to_ipv4(self->client);
		ip->daddr = ipv6_to_ipv4(self->server);
	}
	if (udp) {
		struct udphdr *uh = skb_put(skb, sizeof(*uh));

		memset(uh, 0, sizeof(*uh));
		uh->source = htons(HOMA_UDP_PORT);
		uh->dest = htons(HOMA_UDP_PORT);
		uh->len = htons(sizeof(*uh) + sizeof(common));
		memcpy(skb_put(skb, homa_bytes), &common, homa_bytes);
	}
	return skb;
}

/**
 * deliver_err() - Invoke the tunnel's error callback the way the UDP
 * stack does for an ICMP error.
 * @sk:     Tunnel socket to use.
 * @quote:  Error packet created by icmp_quote.
 * @ipv6:   True means @quote is an ICMPv6 error.
 * @err:    Positive errno that UDP would have derived from the ICMP error.
 */
static void deliver_err(struct sock *sk, struct sk_buff *quote, bool ipv6,
			int err)
{
	u8 *payload = quote->data + sizeof(struct udphdr) +
		      (ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr));

	udp_sk(sk)->encap_err_rcv(sk, quote, err, htons(HOMA_UDP_PORT), 0,
				  payload);
}

static struct sock *tunnel_sock(struct homa_net *hnet, bool ipv6)
{
	return (ipv6 ? rcu_access_pointer(hnet->udp6) :
		       rcu_access_pointer(hnet->udp4))->sk;
}

TEST_F(homa_udp_tunnel, errors_ignore_pmtu)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct homa_rpc *rpc;
		struct sk_buff *quote;

		use_family(self, i);
		rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client,
				      &self->server, 99, 100 + 2 * i, 100,
				      200);
		ASSERT_NE(NULL, rpc);
		quote = icmp_quote(self, i, i ? ICMPV6_PKT_TOOBIG :
					      ICMP_DEST_UNREACH,
				   i ? 0 : ICMP_FRAG_NEEDED, true,
				   sizeof(struct homa_common_hdr), 99);
		mock_printk_output[0] = 0;
		deliver_err(tunnel_sock(self->hnet, i), quote, i, EMSGSIZE);
		EXPECT_EQ(0, rpc->error);
		EXPECT_STREQ("", mock_printk_output);
		kfree_skb(quote);
	}
}

TEST_F(homa_udp_tunnel, errors_zero_err_ignored)
{
	struct homa_rpc *rpc;
	struct sk_buff *quote;

	use_family(self, 0);
	rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client,
			      &self->server, 99, 100, 100, 200);
	ASSERT_NE(NULL, rpc);
	quote = icmp_quote(self, false, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH,
			   true, sizeof(struct homa_common_hdr), 99);
	deliver_err(tunnel_sock(self->hnet, false), quote, false, 0);
	EXPECT_EQ(0, rpc->error);
	kfree_skb(quote);
}

TEST_F(homa_udp_tunnel, errors_only_abort_namespace_of_receiving_device)
{
	struct homa_net *other_net = mock_hnet(1, &self->homa);
	int i;

	mock_devices[1].nd_net.net = &mock_nets[1];
	for (i = 0; i < 2; i++) {
		struct homa_sock other_sock;
		struct homa_rpc *rpc, *other_rpc;
		struct sk_buff *quote;
		int unreach = i ? ICMPV6_DEST_UNREACH : ICMP_DEST_UNREACH;
		int host = i ? ICMPV6_ADDR_UNREACH : ICMP_HOST_UNREACH;

		use_family(self, i);
		mock_sock_init(&other_sock, other_net, 100);
		rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client,
				      &self->server, 99, 100, 100, 200);
		other_rpc = unit_client_rpc(&other_sock, UNIT_OUTGOING,
					    &self->client, &self->server, 99,
					    102, 100, 200);
		ASSERT_NE(NULL, rpc);
		ASSERT_NE(NULL, other_rpc);

		/* Error arrives on a device of the first namespace. */
		quote = icmp_quote(self, i, unreach, host, true,
				   sizeof(struct homa_common_hdr), 99);
		deliver_err(tunnel_sock(self->hnet, i), quote, i, EHOSTUNREACH);
		EXPECT_EQ(-EHOSTUNREACH, rpc->error);
		EXPECT_EQ(0, other_rpc->error);
		kfree_skb(quote);

		/* Error arrives on a device of the second namespace. */
		quote = icmp_quote(self, i, unreach, host, true,
				   sizeof(struct homa_common_hdr), 99);
		quote->dev = &mock_devices[1];
		deliver_err(tunnel_sock(other_net, i), quote, i, EHOSTUNREACH);
		EXPECT_EQ(-EHOSTUNREACH, other_rpc->error);
		kfree_skb(quote);
		unit_sock_destroy(&other_sock);
		unit_sock_destroy(&self->hsk);
		mock_sock_init(&self->hsk, self->hnet, 99);
	}
}

TEST_F(homa_udp_tunnel, errors_port_unreachable_scoped_to_homa_port)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct homa_rpc *rpc, *other_port;
		struct sk_buff *quote;
		int unreach = i ? ICMPV6_DEST_UNREACH : ICMP_DEST_UNREACH;
		int port = i ? ICMPV6_PORT_UNREACH : ICMP_PORT_UNREACH;

		use_family(self, i);
		rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client,
				      &self->server, 99, 100 + 4 * i, 100, 200);
		other_port = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
					     &self->client, &self->server, 100,
					     102 + 4 * i, 100, 200);
		ASSERT_NE(NULL, rpc);
		ASSERT_NE(NULL, other_port);

		/* The Homa destination port in the quote selects the RPCs. */
		quote = icmp_quote(self, i, unreach, port, true,
				   sizeof(struct homa_common_hdr), 99);
		deliver_err(tunnel_sock(self->hnet, i), quote, i, ECONNREFUSED);
		EXPECT_EQ(-ENOTCONN, rpc->error);
		EXPECT_EQ(0, other_port->error);
		kfree_skb(quote);

		/* A quote too short to hold the port affects the whole peer. */
		quote = icmp_quote(self, i, unreach, port, true,
				   offsetof(struct homa_common_hdr, dport) + 1,
				   99);
		deliver_err(tunnel_sock(self->hnet, i), quote, i, ECONNREFUSED);
		EXPECT_EQ(-ENOTCONN, other_port->error);
		kfree_skb(quote);
	}
}

TEST_F(homa_udp_tunnel, errors_other_icmp_types_use_baseline_filter)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct homa_rpc *rpc;
		struct sk_buff *quote;

		use_family(self, i);
		rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client,
				      &self->server, 99, 100 + 2 * i, 100,
				      200);
		ASSERT_NE(NULL, rpc);
		quote = icmp_quote(self, i, i ? ICMPV6_TIME_EXCEED :
					      ICMP_TIME_EXCEEDED, 0, true,
				   sizeof(struct homa_common_hdr), 99);
		mock_printk_output[0] = 0;
		deliver_err(tunnel_sock(self->hnet, i), quote, i, EHOSTUNREACH);

		/* Logged (IPv4 handler only), but the RPC is not aborted. */
		EXPECT_EQ(0, rpc->error);
		if (!i)
			EXPECT_SUBSTR("ICMP type 11, ICMP code 0",
				      mock_printk_output);
		kfree_skb(quote);
	}
}

TEST_F(homa_udp_tunnel, errors_without_namespace_or_quoted_udp_ignored)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct socket *socket = i ? rcu_access_pointer(self->hnet->udp6) :
					    rcu_access_pointer(self->hnet->udp4);
		struct homa_rpc *rpc;
		struct sk_buff *quote;

		use_family(self, i);
		rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client,
				      &self->server, 99, 100 + 2 * i, 100,
				      200);
		ASSERT_NE(NULL, rpc);

		/* The quote doesn't include the UDP header. */
		quote = icmp_quote(self, i, i ? ICMPV6_DEST_UNREACH :
					      ICMP_DEST_UNREACH,
				   i ? ICMPV6_ADDR_UNREACH : ICMP_HOST_UNREACH,
				   false, 0, 99);
		deliver_err(socket->sk, quote, i, EHOSTUNREACH);
		EXPECT_EQ(0, rpc->error);
		kfree_skb(quote);

		/* The tunnel socket doesn't belong to a namespace. */
		quote = icmp_quote(self, i, i ? ICMPV6_DEST_UNREACH :
					      ICMP_DEST_UNREACH,
				   i ? ICMPV6_ADDR_UNREACH : ICMP_HOST_UNREACH,
				   true, sizeof(struct homa_common_hdr), 99);
		rcu_assign_sk_user_data(socket->sk, NULL);
		deliver_err(socket->sk, quote, i, EHOSTUNREACH);
		EXPECT_EQ(0, rpc->error);
		rcu_assign_sk_user_data(socket->sk, self->hnet);
		kfree_skb(quote);
	}
}
