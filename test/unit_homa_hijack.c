// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

#include "homa_impl.h"
#include "homa_hijack.h"
#include "homa_offload.h"
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

FIXTURE(homa_hijack)
{
	struct homa homa;
	struct homa_net *hnet;
	struct homa_sock hsk;
	struct in6_addr ip;
	struct homa_data_hdr header;
	struct list_head empty_list;
	struct net_offload tcp_offloads;
	struct net_offload tcp6_offloads;
};
FIXTURE_SETUP(homa_hijack)
{
	homa_init(&self->homa);
	self->hnet = mock_hnet(0, &self->homa);
	self->homa.flags |= HOMA_FLAG_DONT_THROTTLE;
	self->homa.unsched_bytes = 10000;
	mock_sock_init(&self->hsk, self->hnet, 99);
	self->ip = unit_get_in_addr("196.168.0.1");
	memset(&self->header, 0, sizeof(self->header));
	self->header.common = (struct homa_common_hdr){
		.sport = htons(40000), .dport = htons(88),
		.type = DATA,
		.flags = HOMA_HIJACK_FLAGS,
		.urgent = HOMA_HIJACK_URGENT,
		.sender_id = cpu_to_be64(1002)
	};
	self->header.message_length = htonl(10000);
	self->header.incoming = htonl(10000);
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
	skb = mock_skb_alloc(&self->ip, &self->header.common, 1400, 0);
	h = (struct homa_common_hdr *) skb_transport_header(skb);
	h->flags = 0;
	EXPECT_EQ(NULL, homa_hijack_gro_receive(&self->empty_list, skb));
	EXPECT_STREQ("test_tcp_gro_receive", unit_log_get());
	kfree_skb(skb);
	unit_log_clear();

	skb = mock_skb_alloc(&self->ip, &self->header.common, 1400, 0);
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
	skb = mock_skb_alloc(&self->ip, &self->header.common, 1400, 0);
	ip_hdr(skb)->protocol = IPPROTO_TCP;
	h = (struct homa_common_hdr *)skb_transport_header(skb);
	h->flags = HOMA_HIJACK_FLAGS;
	h->urgent = htons(HOMA_HIJACK_URGENT);
	NAPI_GRO_CB(skb)->same_flow = 0;
	cur_offload_core->held_skb = NULL;
	cur_offload_core->held_bucket = 99;
	EXPECT_EQ(NULL, homa_hijack_gro_receive(&self->empty_list, skb));
	EXPECT_STREQ("homa_gro_receive", unit_log_get());
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
	skb = mock_skb_alloc(&self->ip, &self->header.common, 1400, 0);
	ip_hdr(skb)->protocol = IPPROTO_TCP;
	h = (struct homa_common_hdr *)skb_transport_header(skb);
	h->flags = HOMA_HIJACK_FLAGS;
	h->urgent = htons(HOMA_HIJACK_URGENT);
	NAPI_GRO_CB(skb)->same_flow = 0;
	cur_offload_core->held_skb = NULL;
	cur_offload_core->held_bucket = 99;
	EXPECT_EQ(NULL, homa_hijack_gro_receive(&self->empty_list, skb));
	EXPECT_STREQ("homa_gro_receive", unit_log_get());
	EXPECT_EQ(IPPROTO_HOMA, ip_hdr(skb)->protocol);
	EXPECT_EQ(29695, ip_hdr(skb)->check);
	kfree_skb(skb);
	homa_hijack_end();
}

/* Tests for functions in homa_hijack.h: */

TEST_F(homa_hijack, homa_hijack_set_hdr)
{
	struct homa_peer *peer = homa_peer_get(&self->hsk, &self->ip);
	struct homa_common_hdr *h;
	struct sk_buff *skb;
	int summed;

	skb = mock_skb_alloc(&self->ip, &self->header.common, 1400, 0);
	homa_hijack_set_hdr(skb, peer, true);
	h = (struct homa_common_hdr *)skb_transport_header(skb);
	EXPECT_EQ(HOMA_HIJACK_FLAGS, h->flags);
	EXPECT_EQ(HOMA_HIJACK_URGENT, ntohs(h->urgent));
	summed = skb->ip_summed;
	EXPECT_EQ(CHECKSUM_PARTIAL, summed);

	homa_peer_release(peer);
	kfree_skb(skb);
}

TEST_F(homa_hijack, homa_hijack_sock_init)
{
	EXPECT_EQ(IPPROTO_HOMA, (int)self->hsk.sock.sk_protocol);

	/* First call: hijack_tcp option not set. */
	homa_hijack_sock_init(&self->hsk);
	EXPECT_EQ(IPPROTO_HOMA, (int)self->hsk.sock.sk_protocol);

	/* Second call: hijack_tcp option set. */
	self->homa.hijack_tcp = 1;
	homa_hijack_sock_init(&self->hsk);
	EXPECT_EQ(IPPROTO_TCP, (int)self->hsk.sock.sk_protocol);
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
	struct homa_peer *peer = homa_peer_get(&self->hsk, &self->ip);
	struct sk_buff *skb;

	skb = mock_skb_alloc(&self->ip, &self->header.common, 1400, 0);
	EXPECT_EQ(0, homa_skb_hijacked(skb));
	homa_hijack_set_hdr(skb, peer, true);
	EXPECT_EQ(1, homa_skb_hijacked(skb));

	homa_peer_release(peer);
	kfree_skb(skb);
}