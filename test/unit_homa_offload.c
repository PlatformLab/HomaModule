// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

#include "homa_impl.h"
#include "homa_offload.h"
#include "homa_rpc.h"
#include "homa_sock.h"
#include "homa_udp_tunnel.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#define cur_offload_core (&per_cpu(homa_offload_core, smp_processor_id()))

/* Length of the IP header in packets created by gro_skb. */
#define IP_LEN (mock_ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr))

/**
 * gro_skb() - Build a UDP-encapsulated Homa packet as it looks when the
 * kernel's UDP GRO layer invokes the tunnel callback: skb->data is the IP
 * header, the transport header is the UDP header and the GRO cursor is just
 * past the UDP header.
 * @src:     Source address.
 * @dst:     Destination address.
 * @type:    Homa packet type (DATA, GRANT, START_MSG, or anything else
 *           for a bare common header).
 * @id:      Sender RPC id.
 * @dport:   Homa destination port.
 * @offset:  Message offset (DATA) or granted offset (GRANT).
 * @bytes:   Payload bytes (DATA only).
 * Return:   New packet.
 */
static struct sk_buff *gro_skb(struct in6_addr *src, struct in6_addr *dst,
			       int type, u64 id, int dport, int offset,
			       int bytes)
{
	u8 buf[sizeof(struct homa_data_hdr)] = {};
	struct homa_common_hdr *c = (struct homa_common_hdr *)buf;
	int hlen = sizeof(*c);
	struct udphdr udp = {};
	struct sk_buff *skb;
	int ip_len = IP_LEN;

	c->sport = htons(40000);
	c->dport = htons(dport);
	c->type = type;
	c->sender_id = cpu_to_be64(id);
	switch (type) {
	case DATA:
		hlen = sizeof(struct homa_data_hdr);
		((struct homa_data_hdr *)buf)->msg_length = htonl(10000);
		((struct homa_data_hdr *)buf)->seg.offset = htonl(offset);
		break;
	case GRANT:
		hlen = sizeof(struct homa_grant_hdr);
		((struct homa_grant_hdr *)buf)->offset = htonl(offset);
		((struct homa_grant_hdr *)buf)->priority = 3;
		break;
	case START_MSG:
		hlen = sizeof(struct homa_start_msg_hdr);
		((struct homa_start_msg_hdr *)buf)->msg_length = htonl(10000);
		break;
	}
	if (type != DATA)
		bytes = 0;
	udp.source = htons(HOMA_UDP_PORT);
	udp.dest = htons(HOMA_UDP_PORT);
	udp.len = htons(sizeof(udp) + hlen + bytes);
	udp.check = htons(1);
	skb = mock_raw_skb(src, dst, IPPROTO_UDP, sizeof(udp) + hlen + bytes);
	memcpy(skb_put(skb, sizeof(udp)), &udp, sizeof(udp));
	memcpy(skb_put(skb, hlen), buf, hlen);
	memset(skb_put(skb, bytes), 0xab, bytes);
	skb_push(skb, ip_len);
	skb_set_transport_header(skb, ip_len);
	memset(NAPI_GRO_CB(skb), 0, sizeof(struct napi_gro_cb));
	NAPI_GRO_CB(skb)->data_offset = ip_len + sizeof(udp);
	NAPI_GRO_CB(skb)->count = 1;
	NAPI_GRO_CB(skb)->last = skb;
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	return skb;
}

/* The Homa header of a packet built by gro_skb. */
static struct homa_data_hdr *homa_hdr(struct sk_buff *skb)
{
	return (struct homa_data_hdr *)(skb_transport_header(skb) +
			sizeof(struct udphdr));
}

static struct udphdr *udp_hdr_of(struct sk_buff *skb)
{
	return (struct udphdr *)skb_transport_header(skb);
}

FIXTURE(homa_offload)
{
	struct homa homa;
	struct homa_net *hnet;
	struct homa_sock hsk;
	struct sock sk;
	struct in6_addr src_ip;
	struct in6_addr dst_ip;
	struct napi_struct napi;
	struct sk_buff *skb, *skb2;
};
FIXTURE_SETUP(homa_offload)
{
	int i;

	homa_init(&self->homa);
	self->hnet = mock_hnet(0, &self->homa);
	self->homa.unsched_bytes = 10000;
	mock_sock_init(&self->hsk, self->hnet, 99);
	memset(&self->sk, 0, sizeof(self->sk));
	RCU_INIT_POINTER(self->sk.sk_user_data, self->hnet);
	self->src_ip = unit_get_in_addr("196.168.0.1");
	self->dst_ip = unit_get_in_addr("1.2.3.4");
	for (i = 0; i < GRO_HASH_BUCKETS; i++) {
		INIT_LIST_HEAD(&self->napi.gro.hash[i].list);
		self->napi.gro.hash[i].count = 0;
	}
	self->napi.gro.bitmask = 0;

	self->skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1000, 99,
			    2000, 1400);
	self->skb2 = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1002, 88,
			     4000, 1400);
	self->napi.gro.bitmask = 6;
	self->napi.gro.hash[2].count = 2;
	list_add_tail(&self->skb->list, &self->napi.gro.hash[2].list);
	list_add_tail(&self->skb2->list, &self->napi.gro.hash[2].list);
	homa_offload_init();

	unit_log_clear();

	/* Configure so core isn't considered too busy for bypasses. */
	mock_clock = 1000;
	self->homa.gro_busy_cycles = 500;
	cur_offload_core->last_gro = 400;
}
FIXTURE_TEARDOWN(homa_offload)
{
	struct sk_buff *skb, *tmp;
	int i;

	homa_offload_end();
	for (i = 0; i < GRO_HASH_BUCKETS; i++) {
		list_for_each_entry_safe(skb, tmp, &self->napi.gro.hash[i].list,
					 list)
			kfree_skb(skb);
	}
	homa_destroy(&self->homa);
	unit_teardown();
}

#define RECV(skb) homa_udp_gro_receive(&self->sk, \
		&self->napi.gro.hash[3].list, skb)

TEST_F(homa_offload, homa_offload_init__basics)
{
	struct homa_offload_core *core = &per_cpu(homa_offload_core, 2);

	core->last_active = 5;
	core->last_gro = 6;
	atomic_set(&core->softirq_backlog, 7);
	core->softirq_offset = 8;
	core->gen3_softirq_cores[1] = 4;
	core->last_app_active = 9;
	core->held_skb = self->skb;
	core->held_bucket = 3;
	EXPECT_EQ(0, homa_offload_init());
	EXPECT_EQ(0, core->last_active);
	EXPECT_EQ(0, core->last_gro);
	EXPECT_EQ(0, atomic_read(&core->softirq_backlog));
	EXPECT_EQ(0, core->softirq_offset);
	EXPECT_EQ(3, core->gen3_softirq_cores[0]);
	EXPECT_EQ(-1, core->gen3_softirq_cores[1]);
	EXPECT_EQ(-1, core->gen3_softirq_cores[2]);
	EXPECT_EQ(0, core->last_app_active);
	EXPECT_EQ(NULL, core->held_skb);
	EXPECT_EQ(0, core->held_bucket);
}
TEST_F(homa_offload, homa_offload_end__clear_held_skb)
{
	per_cpu(homa_offload_core, 1).held_skb = self->skb;
	cur_offload_core->held_skb = self->skb2;
	EXPECT_EQ(0, homa_offload_end());
	EXPECT_EQ(NULL, per_cpu(homa_offload_core, 1).held_skb);
	EXPECT_EQ(NULL, cur_offload_core->held_skb);
}

TEST_F(homa_offload, homa_udp_gro_receive__HOMA_GRO_SHORT_BYPASS)
{
	struct homa_rpc *srpc;
	struct sk_buff *skb, *result;
	u64 client_id = 1234;
	u64 server_id = 1235;

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->src_ip,
			&self->dst_ip, 40000, server_id, 10000, 200);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	/* First attempt: HOMA_GRO_SHORT_BYPASS not enabled. */
	self->homa.gro_policy = 0;
	skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, client_id, 99, 2000,
		      1400);
	result = RECV(skb);
	EXPECT_EQ(0, -PTR_ERR(result));
	EXPECT_EQ(0, homa_metrics_per_cpu()->gro_data_bypasses);
	cur_offload_core->held_skb = NULL;
	kfree_skb(skb);

	/* Second attempt: HOMA_GRO_SHORT_BYPASS enabled but message longer
	 * than one packet.
	 */
	self->homa.gro_policy |= HOMA_GRO_SHORT_BYPASS;
	cur_offload_core->last_gro = 400;
	skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, client_id, 99, 2000,
		      1400);
	result = RECV(skb);
	EXPECT_EQ(0, -PTR_ERR(result));
	EXPECT_EQ(0, homa_metrics_per_cpu()->gro_data_bypasses);
	cur_offload_core->held_skb = NULL;
	kfree_skb(skb);

	/* Third attempt: bypass should happen (the packet is consumed by
	 * the UDP receive path).
	 */
	cur_offload_core->last_gro = 400;
	skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, client_id, 99, 0,
		      1400);
	homa_hdr(skb)->msg_length = htonl(1400);
	result = RECV(skb);
	EXPECT_EQ(EINPROGRESS, -PTR_ERR(result));
	EXPECT_EQ(1, homa_metrics_per_cpu()->gro_data_bypasses);

	/* Fourth attempt: no bypass because core busy. */
	cur_offload_core->last_gro = 600;
	skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, client_id, 99, 0,
		      1400);
	homa_hdr(skb)->msg_length = htonl(1400);
	result = RECV(skb);
	EXPECT_EQ(0, -PTR_ERR(result));
	EXPECT_EQ(1, homa_metrics_per_cpu()->gro_data_bypasses);
	cur_offload_core->held_skb = NULL;
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_udp_gro_receive__fast_grant_optimization)
{
	struct homa_rpc *srpc;
	struct sk_buff *skb, *result;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING, &self->src_ip,
			&self->dst_ip, 40000, 3001, 100, 20000);
	ASSERT_NE(NULL, srpc);
	homa_rpc_lock(srpc);
	homa_xmit_data(srpc);
	homa_rpc_unlock(srpc);
	unit_log_clear();

	/* First attempt: HOMA_GRO_FAST_GRANTS not enabled. */
	self->homa.gro_policy = 0;
	skb = gro_skb(&self->src_ip, &self->dst_ip, GRANT, 3000, 99, 1000, 0);
	result = RECV(skb);
	EXPECT_EQ(0, -PTR_ERR(result));
	EXPECT_EQ(0, homa_metrics_per_cpu()->gro_grant_bypasses);
	EXPECT_STREQ("", unit_log_get());
	cur_offload_core->held_skb = NULL;
	kfree_skb(skb);

	/* Second attempt: HOMA_FAST_GRANTS is enabled. */
	self->homa.gro_policy = HOMA_GRO_FAST_GRANTS;
	cur_offload_core->last_gro = 400;
	skb = gro_skb(&self->src_ip, &self->dst_ip, GRANT, 3000, 99, 1000, 0);
	result = RECV(skb);
	EXPECT_EQ(EINPROGRESS, -PTR_ERR(result));
	EXPECT_EQ(1, homa_metrics_per_cpu()->gro_grant_bypasses);
	EXPECT_SUBSTR("xmit DATA", unit_log_get());

	/* Third attempt: core is too busy for fast grants. */
	cur_offload_core->last_gro = 600;
	skb = gro_skb(&self->src_ip, &self->dst_ip, GRANT, 3000, 99, 1000, 0);
	result = RECV(skb);
	EXPECT_EQ(0, -PTR_ERR(result));
	EXPECT_EQ(1, homa_metrics_per_cpu()->gro_grant_bypasses);
	cur_offload_core->held_skb = NULL;
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_udp_gro_receive__no_held_skb)
{
	struct sk_buff *skb;
	int same_flow;

	skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1000, 99, 6000, 1400);
	skb->hash = 2;
	cur_offload_core->held_skb = NULL;
	cur_offload_core->held_bucket = 0;
	self->homa.gro_policy = 0;
	EXPECT_EQ(NULL, homa_udp_gro_receive(&self->sk,
			&self->napi.gro.hash[2].list, skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(0, same_flow);
	EXPECT_FALSE(NAPI_GRO_CB(skb)->flush);
	EXPECT_EQ(skb, cur_offload_core->held_skb);
	EXPECT_EQ(2, cur_offload_core->held_bucket);
	EXPECT_EQ(2, skb->hash);
	EXPECT_EQ(NULL, skb_shinfo(skb)->frag_list);
	cur_offload_core->held_skb = NULL;
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_udp_gro_receive__HOMA_GRO_SAME_CORE)
{
	struct sk_buff *skb;

	skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1000, 99, 6000, 1400);
	self->homa.gro_policy = HOMA_GRO_SAME_CORE;
	mock_set_core(4);
	cur_offload_core->held_skb = NULL;
	EXPECT_EQ(NULL, RECV(skb));
	EXPECT_EQ(4, skb->hash - 32);
	cur_offload_core->held_skb = NULL;
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_udp_gro_receive__empty_merge_list)
{
	struct sk_buff *skb;
	int same_flow;

	skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1000, 99, 6000, 1400);
	skb->hash = 2;
	cur_offload_core->held_skb = self->skb;
	cur_offload_core->held_bucket = 3;
	EXPECT_EQ(NULL, homa_udp_gro_receive(&self->sk,
			&self->napi.gro.hash[2].list, skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(0, same_flow);
	EXPECT_EQ(skb, cur_offload_core->held_skb);
	EXPECT_EQ(2, cur_offload_core->held_bucket);
	cur_offload_core->held_skb = NULL;
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_udp_gro_receive__held_skb_not_in_merge_list)
{
	struct sk_buff *skb;
	int same_flow;

	skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1000, 99, 6000, 1400);
	cur_offload_core->held_skb = skb;
	cur_offload_core->held_bucket = 2;
	EXPECT_EQ(NULL, RECV(skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(0, same_flow);
	EXPECT_EQ(skb, cur_offload_core->held_skb);
	EXPECT_EQ(3, cur_offload_core->held_bucket);
	EXPECT_EQ(NULL, skb_shinfo(self->skb)->frag_list);
	cur_offload_core->held_skb = NULL;
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_udp_gro_receive__held_skb_in_merge_list_but_wrong_proto)
{
	struct sk_buff *skb;
	int same_flow;

	skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1000, 99, 6000, 1400);
	cur_offload_core->held_skb = self->skb2;
	cur_offload_core->held_bucket = 2;
	if (skb_is_ipv6(self->skb2))
		ipv6_hdr(self->skb2)->nexthdr = IPPROTO_TCP;
	else
		ip_hdr(self->skb2)->protocol = IPPROTO_TCP;
	EXPECT_EQ(NULL, RECV(skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(0, same_flow);
	EXPECT_EQ(NULL, skb_shinfo(self->skb2)->frag_list);
	EXPECT_EQ(skb, cur_offload_core->held_skb);
	EXPECT_EQ(3, cur_offload_core->held_bucket);
	cur_offload_core->held_skb = NULL;
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_udp_gro_receive__held_skb_ineligible_for_merge)
{
	int which;

	for (which = 0; which < 5; which++) {
		struct sk_buff *skb;
		int same_flow;

		skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1000, 99,
			      6000, 1400);
		cur_offload_core->held_skb = self->skb2;
		cur_offload_core->held_bucket = 2;
		switch (which) {
		case 0:
			udp_hdr_of(self->skb2)->source = htons(1);
			break;
		case 1:
			udp_hdr_of(self->skb2)->dest = htons(1);
			break;
		case 2:
			if (skb_is_ipv6(skb))
				ipv6_hdr(skb)->daddr.s6_addr32[3]++;
			else
				ip_hdr(skb)->daddr++;
			break;
		case 3:
			skb->dev = mock_dev(1, &self->homa);
			skb->dev->nd_net.net = mock_net_for_hnet(
					mock_hnet(1, &self->homa));
			break;
		case 4:
			self->skb2->protocol = skb_is_ipv6(skb) ?
					htons(ETH_P_IP) : htons(ETH_P_IPV6);
			break;
		}
		EXPECT_EQ(NULL, RECV(skb));
		same_flow = NAPI_GRO_CB(skb)->same_flow;
		EXPECT_EQ(0, same_flow);
		EXPECT_EQ(NULL, skb_shinfo(self->skb2)->frag_list);
		EXPECT_EQ(1, NAPI_GRO_CB(self->skb2)->count);

		/* Restore everything for the next iteration. */
		udp_hdr_of(self->skb2)->source = htons(HOMA_UDP_PORT);
		udp_hdr_of(self->skb2)->dest = htons(HOMA_UDP_PORT);
		self->skb2->protocol = mock_ipv6 ? htons(ETH_P_IPV6) :
				htons(ETH_P_IP);
		if (which == 3)
			mock_dev(1, &self->homa)->nd_net.net =
					mock_net_for_hnet(self->hnet);
		cur_offload_core->held_skb = NULL;
		kfree_skb(skb);
	}
}
TEST_F(homa_offload, homa_udp_gro_receive__merge)
{
	struct sk_buff *skb, *skb2;
	int len = self->skb2->len;
	int data_len = self->skb2->data_len;
	int truesize = self->skb2->truesize;
	int child_len, same_flow;

	cur_offload_core->held_skb = self->skb2;
	cur_offload_core->held_bucket = 2;

	skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1002, 88, 6000, 1400);
	child_len = skb->len;
	EXPECT_EQ(NULL, RECV(skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(1, same_flow);
	EXPECT_EQ(2, NAPI_GRO_CB(self->skb2)->count);

	skb2 = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1004, 88, 7000, 1400);
	EXPECT_EQ(NULL, RECV(skb2));
	same_flow = NAPI_GRO_CB(skb2)->same_flow;
	EXPECT_EQ(1, same_flow);
	EXPECT_EQ(3, NAPI_GRO_CB(self->skb2)->count);

	/* Children are chained in order; nothing is accounted to the head
	 * and the children are untouched.
	 */
	EXPECT_EQ(skb, skb_shinfo(self->skb2)->frag_list);
	EXPECT_EQ(skb2, skb->next);
	EXPECT_EQ(NULL, skb2->next);
	EXPECT_EQ(skb2, NAPI_GRO_CB(self->skb2)->last);
	EXPECT_EQ(len, self->skb2->len);
	EXPECT_EQ(data_len, self->skb2->data_len);
	EXPECT_EQ(truesize, self->skb2->truesize);
	EXPECT_EQ(child_len, skb->len);
	EXPECT_EQ(skb_network_header(skb), skb->data);
	EXPECT_EQ(IP_LEN, skb_transport_offset(skb));
	EXPECT_EQ(NULL, skb->sk);
	EXPECT_EQ(NULL, skb->destructor);
	EXPECT_EQ(1003, homa_local_id(homa_hdr(skb)->common.sender_id));
	EXPECT_EQ(6000, ntohl(homa_hdr(skb)->seg.offset));
	EXPECT_EQ(7000, ntohl(homa_hdr(skb2)->seg.offset));
	EXPECT_EQ(self->skb2, cur_offload_core->held_skb);

	/* Freeing the head frees the children. */
	list_del_init(&self->skb2->list);
	kfree_skb(self->skb2);
	self->napi.gro.hash[2].count = 1;
	cur_offload_core->held_skb = NULL;
}
TEST_F(homa_offload, homa_udp_gro_receive__aggregates_all_types_rpcs_and_orders)
{
	struct sk_buff *pkts[6];
	struct sk_buff *child;
	int i;

	cur_offload_core->held_skb = self->skb;
	cur_offload_core->held_bucket = 2;

	/* Different RPC, packet types, duplicate and reordered offsets: GRO
	 * does not judge them; dispatch does.
	 */
	pkts[0] = gro_skb(&self->src_ip, &self->dst_ip, DATA, 2000, 77, 0, 100);
	pkts[1] = gro_skb(&self->src_ip, &self->dst_ip, GRANT, 1000, 99, 500, 0);
	pkts[2] = gro_skb(&self->src_ip, &self->dst_ip, BUSY, 1000, 99, 0, 0);
	pkts[3] = gro_skb(&self->src_ip, &self->dst_ip, START_MSG, 4000, 99, 0, 0);
	pkts[4] = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1000, 99, 2000, 1400);
	pkts[5] = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1000, 99, 0, 1400);
	self->homa.max_gro_skbs = 20;
	self->homa.gro_policy = 0;
	for (i = 0; i < 6; i++) {
		EXPECT_EQ(NULL, RECV(pkts[i]));
		EXPECT_FALSE(NAPI_GRO_CB(pkts[i])->flush);
	}
	EXPECT_EQ(7, NAPI_GRO_CB(self->skb)->count);
	child = skb_shinfo(self->skb)->frag_list;
	for (i = 0; i < 6; i++) {
		EXPECT_EQ(pkts[i], child);
		child = child->next;
	}
	EXPECT_EQ(NULL, child);
	cur_offload_core->held_skb = NULL;
}
TEST_F(homa_offload, homa_udp_gro_receive__max_gro_skbs)
{
	struct sk_buff *skb;

	/* First packet: fits below the limit. */
	self->homa.max_gro_skbs = 3;
	cur_offload_core->held_skb = self->skb2;
	cur_offload_core->held_bucket = 2;
	skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1002, 88, 6000, 1400);
	RECV(skb);
	EXPECT_EQ(2, NAPI_GRO_CB(self->skb2)->count);
	EXPECT_EQ(2, self->napi.gro.hash[2].count);

	/* Second packet hits the limit. The head still has the GSO state
	 * that dev_gro_receive gave it.
	 */
	skb_shinfo(self->skb2)->gso_size = 1441;
	skb_shinfo(self->skb2)->gso_type = SKB_GSO_UDP_TUNNEL;
	skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1006, 88, 6000, 1400);
	unit_log_clear();
	EXPECT_EQ(EINPROGRESS, -PTR_ERR(RECV(skb)));
	EXPECT_EQ(3, NAPI_GRO_CB(self->skb2)->count);
	EXPECT_EQ(1, self->napi.gro.hash[2].count);
	EXPECT_STREQ("netif_receive_skb, id 1002, offset 4000",
		     unit_log_get());
	EXPECT_EQ(0, skb_shinfo(self->skb2)->gso_size);
	EXPECT_EQ(0, skb_shinfo(self->skb2)->gso_type);
	EXPECT_EQ(NULL, cur_offload_core->held_skb);
	kfree_skb(self->skb2);
	self->skb2 = NULL;
	EXPECT_EQ(1, self->napi.gro.hash[2].count);
	EXPECT_EQ(6, self->napi.gro.bitmask);

	/* Third packet also hits the limit for skb, causing the bucket
	 * to become empty.
	 */
	self->homa.max_gro_skbs = 2;
	cur_offload_core->held_skb = self->skb;
	skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1006, 88, 6000, 1400);
	unit_log_clear();
	EXPECT_EQ(EINPROGRESS, -PTR_ERR(RECV(skb)));
	EXPECT_EQ(2, NAPI_GRO_CB(self->skb)->count);
	EXPECT_EQ(0, self->napi.gro.hash[2].count);
	EXPECT_EQ(2, self->napi.gro.bitmask);
	EXPECT_STREQ("netif_receive_skb, id 1000, offset 2000",
		     unit_log_get());
	kfree_skb(self->skb);
	self->skb = NULL;
}
TEST_F(homa_offload, homa_udp_gro_receive__flush_on_entry)
{
	struct sk_buff *skb;
	int same_flow;

	skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1002, 88, 6000, 1400);
	NAPI_GRO_CB(skb)->flush = 1;
	cur_offload_core->held_skb = self->skb2;
	cur_offload_core->held_bucket = 2;
	EXPECT_EQ(NULL, RECV(skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(0, same_flow);
	EXPECT_TRUE(NAPI_GRO_CB(skb)->flush);
	EXPECT_EQ(NULL, skb_shinfo(self->skb2)->frag_list);
	EXPECT_EQ(self->skb2, cur_offload_core->held_skb);
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_udp_gro_receive__malformed_packets_are_flushed)
{
	int which;

	cur_offload_core->held_skb = self->skb2;
	cur_offload_core->held_bucket = 2;
	for (which = 0; which < 11; which++) {
		struct sk_buff *skb;
		int type = which == 8 ? GRANT : which == 9 ? START_MSG : DATA;

		skb = gro_skb(&self->src_ip, &self->dst_ip, type, 1002, 88,
			      6000, 1400);
		switch (which) {
		case 0:
			udp_hdr_of(skb)->len = htons(
					ntohs(udp_hdr_of(skb)->len) - 1);
			break;
		case 1:
			udp_hdr_of(skb)->source = htons(HOMA_UDP_PORT + 1);
			break;
		case 2:
			udp_hdr_of(skb)->dest = htons(HOMA_UDP_PORT + 1);
			break;
		case 3:
			udp_hdr_of(skb)->check = 0;
			break;
		case 4:
			/* GRO cursor at the end of the packet. */
			NAPI_GRO_CB(skb)->data_offset = skb->len;
			break;
		case 5:
			/* Cursor inside the IP header, before the UDP header. */
			NAPI_GRO_CB(skb)->data_offset = 4;
			break;
		case 6:
			/* DATA header truncated (UDP length adjusted). */
			__skb_trim(skb, IP_LEN + sizeof(struct udphdr) + 20);
			udp_hdr_of(skb)->len = htons(sizeof(struct udphdr) + 20);
			break;
		case 7:
			/* Not even a common header. */
			__skb_trim(skb, IP_LEN + sizeof(struct udphdr) + 5);
			udp_hdr_of(skb)->len = htons(sizeof(struct udphdr) + 5);
			break;
		case 8:
			__skb_trim(skb, skb->len - 3);
			udp_hdr_of(skb)->len = htons(
					ntohs(udp_hdr_of(skb)->len) - 3);
			break;
		case 9:
			__skb_trim(skb, skb->len - 3);
			udp_hdr_of(skb)->len = htons(
					ntohs(udp_hdr_of(skb)->len) - 3);
			break;
		case 10:
			/* UDP length claims more bytes than the buffer has. */
			udp_hdr_of(skb)->len = htons(
					ntohs(udp_hdr_of(skb)->len) + 4);
			break;
		}
		EXPECT_EQ(NULL, RECV(skb));
		EXPECT_TRUE(NAPI_GRO_CB(skb)->flush);
		EXPECT_EQ(NULL, skb_shinfo(self->skb2)->frag_list);
		EXPECT_EQ(self->skb2, cur_offload_core->held_skb);
		kfree_skb(skb);
	}
}
TEST_F(homa_offload, homa_udp_gro_receive__nonlinear_packet)
{
	struct sk_buff *skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1002,
				      88, 6000, 1400);
	struct page *page = alloc_page(GFP_KERNEL);
	unsigned int linear = IP_LEN + sizeof(struct udphdr) + 5;
	unsigned int bytes = skb->len - linear;
	int len = skb->len;

	ASSERT_NE(NULL, page);
	memcpy(page_address(page), skb->data + linear, bytes);
	skb->tail -= bytes;
	skb->data_len = bytes;
	skb_fill_page_desc(skb, 0, page, 0, bytes);
	cur_offload_core->held_skb = self->skb2;
	cur_offload_core->held_bucket = 2;
	EXPECT_EQ(NULL, RECV(skb));

	/* The header was made linear and the packet merged unchanged. */
	EXPECT_EQ(skb, skb_shinfo(self->skb2)->frag_list);
	EXPECT_EQ(len, skb->len);
	EXPECT_EQ(1, skb_shinfo(skb)->nr_frags);
	EXPECT_GE(skb_headlen(skb), IP_LEN + sizeof(struct udphdr) +
		  sizeof(struct homa_data_hdr));
	EXPECT_EQ(6000, ntohl(homa_hdr(skb)->seg.offset));
	cur_offload_core->held_skb = NULL;
}
TEST_F(homa_offload, homa_udp_gro_receive__children_freed_with_head)
{
	int before = mock_skb_count();
	struct sk_buff *skb;

	skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1002, 88, 6000, 1400);
	self->homa.max_gro_skbs = 20;
	cur_offload_core->held_skb = self->skb2;
	cur_offload_core->held_bucket = 2;
	EXPECT_EQ(NULL, RECV(skb));
	EXPECT_EQ(before + 1, mock_skb_count());
	list_del_init(&self->skb2->list);
	self->napi.gro.hash[2].count = 1;
	kfree_skb(self->skb2);
	self->skb2 = NULL;
	EXPECT_EQ(before - 1, mock_skb_count());
	cur_offload_core->held_skb = NULL;
}
TEST_F(homa_offload, homa_udp_gro_receive__both_address_families)
{
	bool saved = mock_ipv6;
	int family;

	for (family = 0; family < 2; family++) {
		struct sk_buff *a, *b;

		mock_ipv6 = family;
		a = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1000, 99, 0, 100);
		b = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1000, 99, 100, 100);
		a->hash = 3;
		cur_offload_core->held_skb = NULL;
		EXPECT_EQ(NULL, RECV(a));
		EXPECT_EQ(a, cur_offload_core->held_skb);
		list_add_tail(&a->list, &self->napi.gro.hash[3].list);
		EXPECT_EQ(NULL, RECV(b));
		EXPECT_EQ(b, skb_shinfo(a)->frag_list);
		EXPECT_EQ(2, NAPI_GRO_CB(a)->count);
		EXPECT_EQ(IP_LEN, skb_transport_offset(b));
		list_del_init(&a->list);
		cur_offload_core->held_skb = NULL;
		kfree_skb(a);
	}
	mock_ipv6 = saved;
}
TEST_F(homa_offload, homa_udp_gro_receive__missing_context)
{
	struct sk_buff *skb;

	skb = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1002, 88, 6000, 1400);
	cur_offload_core->held_skb = self->skb2;
	cur_offload_core->held_bucket = 2;
	RCU_INIT_POINTER(self->sk.sk_user_data, NULL);
	EXPECT_EQ(NULL, RECV(skb));
	EXPECT_TRUE(NAPI_GRO_CB(skb)->flush);
	EXPECT_EQ(NULL, skb_shinfo(self->skb2)->frag_list);
	NAPI_GRO_CB(skb)->flush = 0;
	EXPECT_EQ(NULL, homa_udp_gro_receive(NULL,
			&self->napi.gro.hash[3].list, skb));
	EXPECT_TRUE(NAPI_GRO_CB(skb)->flush);
	EXPECT_EQ(NULL, skb_shinfo(self->skb2)->frag_list);
	kfree_skb(skb);
}

TEST_F(homa_offload, homa_gro_gen2)
{
	self->homa.gro_policy = HOMA_GRO_GEN2;
	mock_clock = 1000;
	self->homa.busy_cycles = 100;
	mock_set_core(5);
	atomic_set(&per_cpu(homa_offload_core, 6).softirq_backlog, 1);
	per_cpu(homa_offload_core, 6).last_gro = 0;
	atomic_set(&per_cpu(homa_offload_core, 7).softirq_backlog, 0);
	per_cpu(homa_offload_core, 7).last_gro = 901;
	atomic_set(&per_cpu(homa_offload_core, 0).softirq_backlog, 2);
	per_cpu(homa_offload_core, 0).last_gro = 0;
	atomic_set(&per_cpu(homa_offload_core, 1).softirq_backlog, 0);
	per_cpu(homa_offload_core, 1).last_gro = 899;
	atomic_set(&per_cpu(homa_offload_core, 2).softirq_backlog, 0);
	per_cpu(homa_offload_core, 2).last_gro = 0;

	// Avoid busy cores.
	homa_gro_complete(self->skb);
	EXPECT_EQ(1, self->skb->hash - 32);
	EXPECT_EQ(1, atomic_read(&per_cpu(homa_offload_core, 1).softirq_backlog));

	// All cores busy; must rotate.
	homa_gro_complete(self->skb);
	EXPECT_EQ(6, self->skb->hash - 32);
	homa_gro_complete(self->skb);
	EXPECT_EQ(7, self->skb->hash - 32);
	EXPECT_EQ(2, per_cpu(homa_offload_core, 5).softirq_offset);
	homa_gro_complete(self->skb);
	EXPECT_EQ(0, self->skb->hash - 32);
	homa_gro_complete(self->skb);
	EXPECT_EQ(1, self->skb->hash - 32);
	homa_gro_complete(self->skb);
	EXPECT_EQ(6, self->skb->hash - 32);
	EXPECT_EQ(1, per_cpu(homa_offload_core, 5).softirq_offset);
}

TEST_F(homa_offload, homa_gro_gen3__basics)
{
	struct homa_offload_core *offload_core = cur_offload_core;
	struct homa_offload_core *offload3 = &per_cpu(homa_offload_core, 3);
	struct homa_offload_core *offload5 = &per_cpu(homa_offload_core, 5);
	struct homa_offload_core *offload7 = &per_cpu(homa_offload_core, 7);

	self->homa.gro_policy = HOMA_GRO_GEN3;
	offload_core->gen3_softirq_cores[0] = 3;
	offload_core->gen3_softirq_cores[1] = 7;
	offload_core->gen3_softirq_cores[2] = 5;
	offload3->last_app_active = 4100;
	offload7->last_app_active = 3900;
	offload5->last_app_active = 2000;
	mock_clock = 5000;
	self->homa.busy_cycles = 1000;

	homa_gro_complete(self->skb);
	EXPECT_EQ(7, self->skb->hash - 32);
	EXPECT_EQ(0, offload3->last_active);
	EXPECT_EQ(5000, offload7->last_active);
	EXPECT_EQ(1, homa_metrics_per_cpu()->gen3_handoffs);
	EXPECT_EQ(1, homa_metrics_per_cpu()->gen3_alt_handoffs);

	/* Gen3 does not use the backlog counter. */
	EXPECT_EQ(0, atomic_read(&offload7->softirq_backlog));
}
TEST_F(homa_offload, homa_gro_gen3__stop_on_negative_core_id)
{
	struct homa_offload_core *offload_core = cur_offload_core;

	self->homa.gro_policy = HOMA_GRO_GEN3;
	offload_core->gen3_softirq_cores[0] = 3;
	offload_core->gen3_softirq_cores[1] = -1;
	offload_core->gen3_softirq_cores[2] = 5;
	per_cpu(homa_offload_core, 3).last_app_active = 4100;
	per_cpu(homa_offload_core, 5).last_app_active = 2000;
	mock_clock = 5000;
	self->homa.busy_cycles = 1000;

	homa_gro_complete(self->skb);
	EXPECT_EQ(3, self->skb->hash - 32);
	EXPECT_EQ(5000, per_cpu(homa_offload_core, 3).last_active);
	EXPECT_EQ(1, homa_metrics_per_cpu()->gen3_handoffs);
	EXPECT_EQ(0, homa_metrics_per_cpu()->gen3_alt_handoffs);
}
TEST_F(homa_offload, homa_gro_gen3__all_cores_busy_so_pick_first)
{
	struct homa_offload_core *offload_core = cur_offload_core;

	self->homa.gro_policy = HOMA_GRO_GEN3;
	offload_core->gen3_softirq_cores[0] = 3;
	offload_core->gen3_softirq_cores[1] = 7;
	offload_core->gen3_softirq_cores[2] = 5;
	per_cpu(homa_offload_core, 3).last_app_active = 4100;
	per_cpu(homa_offload_core, 7).last_app_active = 4001;
	per_cpu(homa_offload_core, 5).last_app_active = 4500;
	mock_clock = 5000;
	self->homa.busy_cycles = 1000;

	homa_gro_complete(self->skb);
	EXPECT_EQ(3, self->skb->hash - 32);
	EXPECT_EQ(5000, per_cpu(homa_offload_core, 3).last_active);
}

TEST_F(homa_offload, homa_gro_complete__clear_held_skb)
{
	cur_offload_core->held_skb = self->skb2;
	homa_gro_complete(self->skb);
	EXPECT_EQ(NULL, cur_offload_core->held_skb);
}
TEST_F(homa_offload, homa_gro_complete__clear_gso_state)
{
	skb_shinfo(self->skb)->gso_size = 1441;
	skb_shinfo(self->skb)->gso_segs = 3;
	skb_shinfo(self->skb)->gso_type = SKB_GSO_UDP_TUNNEL_CSUM;
	self->skb->encapsulation = 1;
	EXPECT_EQ(0, homa_gro_complete(self->skb));
	EXPECT_EQ(0, skb_shinfo(self->skb)->gso_size);
	EXPECT_EQ(0, skb_shinfo(self->skb)->gso_segs);
	EXPECT_EQ(0, skb_shinfo(self->skb)->gso_type);
	EXPECT_EQ(0, (int)self->skb->encapsulation);
	EXPECT_EQ(CHECKSUM_UNNECESSARY, (unsigned int)self->skb->ip_summed);
}
TEST_F(homa_offload, homa_gro_complete__GRO_IDLE)
{
	self->homa.gro_policy = HOMA_GRO_IDLE;
	per_cpu(homa_offload_core, 6).last_active = 30;
	per_cpu(homa_offload_core, 7).last_active = 25;
	per_cpu(homa_offload_core, 0).last_active = 20;
	per_cpu(homa_offload_core, 1).last_active = 15;
	per_cpu(homa_offload_core, 2).last_active = 10;

	mock_set_core(5);
	homa_gro_complete(self->skb);
	EXPECT_EQ(1, self->skb->hash - 32);

	per_cpu(homa_offload_core, 6).last_active = 5;
	mock_set_core(5);
	homa_gro_complete(self->skb);
	EXPECT_EQ(6, self->skb->hash - 32);

	mock_set_core(6);
	homa_gro_complete(self->skb);
	EXPECT_EQ(2, self->skb->hash - 32);
}
TEST_F(homa_offload, homa_gro_complete__GRO_NEXT)
{
	self->homa.gro_policy = HOMA_GRO_NEXT;
	mock_set_core(5);
	homa_gro_complete(self->skb);
	EXPECT_EQ(6, self->skb->hash - 32);

	mock_set_core(nr_cpu_ids - 1);
	homa_gro_complete(self->skb);
	EXPECT_EQ(0, self->skb->hash - 32);
}

TEST_F(homa_offload, homa_udp_gro_complete__kernel_completed_head)
{
	struct sk_buff *skb = self->skb;
	int nhoff = IP_LEN + sizeof(struct udphdr);

	/* Emulate what udp_gro_complete leaves for a tunnel aggregate. */
	skb_shinfo(skb)->gso_type = SKB_GSO_UDP_TUNNEL_CSUM;
	skb_shinfo(skb)->gso_size = 1441;
	skb_shinfo(skb)->gso_segs = 3;
	skb->encapsulation = 1;
	udp_hdr_of(skb)->check = htons(0x1234);
	cur_offload_core->held_skb = skb;
	self->homa.gro_policy = HOMA_GRO_NEXT;
	mock_set_core(5);
	EXPECT_EQ(0, homa_udp_gro_complete(&self->sk, skb, nhoff));
	EXPECT_EQ(0, skb_shinfo(skb)->gso_type);
	EXPECT_EQ(0, skb_shinfo(skb)->gso_size);
	EXPECT_EQ(0, skb_shinfo(skb)->gso_segs);
	EXPECT_EQ(0, (int)skb->encapsulation);
	EXPECT_EQ(htons(0x1234), udp_hdr_of(skb)->check);
	EXPECT_EQ(6, skb->hash - 32);
	EXPECT_EQ(NULL, cur_offload_core->held_skb);
}
TEST_F(homa_offload, homa_udp_gro_complete__missing_context_or_bad_offset)
{
	cur_offload_core->held_skb = self->skb;
	EXPECT_EQ(-EINVAL, homa_udp_gro_complete(&self->sk, self->skb, 4));
	EXPECT_EQ(NULL, cur_offload_core->held_skb);

	cur_offload_core->held_skb = self->skb;
	RCU_INIT_POINTER(self->sk.sk_user_data, NULL);
	EXPECT_EQ(-ENODEV, homa_udp_gro_complete(&self->sk, self->skb,
			IP_LEN + sizeof(struct udphdr)));
	EXPECT_EQ(NULL, cur_offload_core->held_skb);
	EXPECT_EQ(-ENODEV, homa_udp_gro_complete(NULL, self->skb,
			IP_LEN + sizeof(struct udphdr)));
}

TEST_F(homa_offload, udp_gro_aggregate_reaches_dispatch)
{
	struct sk_buff *a = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1000, 99, 0, 100);
	struct sk_buff *b = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1000, 99, 100, 100);
	struct sk_buff *c = gro_skb(&self->src_ip, &self->dst_ip, DATA, 1000, 99, 200, 100);
	int nhoff = IP_LEN + sizeof(struct udphdr);
	int len = a->len;
	unsigned int truesize = a->truesize;
	u64 before = homa_metrics_per_cpu()->packets_received[DATA - DATA];

	homa_hdr(a)->msg_length = htonl(300);
	homa_hdr(b)->msg_length = htonl(300);
	homa_hdr(c)->msg_length = htonl(300);
	cur_offload_core->held_skb = NULL;
	EXPECT_EQ(NULL, RECV(a));
	list_add_tail(&a->list, &self->napi.gro.hash[3].list);
	EXPECT_EQ(NULL, RECV(b));
	EXPECT_EQ(NULL, RECV(c));
	ASSERT_EQ(3, NAPI_GRO_CB(a)->count);

	/* Emulate the kernel's completion and IP delivery of the head. */
	skb_shinfo(a)->gso_type = SKB_GSO_UDP_TUNNEL_CSUM;
	skb_shinfo(a)->gso_size = 141;
	a->encapsulation = 1;
	skb_list_del_init(a);
	ASSERT_EQ(0, homa_udp_gro_complete(&self->sk, a, nhoff));

	/* The children are linked on the head but not accounted for in it,
	 * and every packet is still a whole datagram.
	 */
	EXPECT_EQ(len, a->len);
	EXPECT_EQ(0, a->data_len);
	EXPECT_EQ(truesize, a->truesize);
	EXPECT_EQ(len - IP_LEN, ntohs(udp_hdr_of(a)->len));
	ASSERT_EQ(b, skb_shinfo(a)->frag_list);
	ASSERT_EQ(c, b->next);
	EXPECT_EQ(NULL, c->next);
	EXPECT_EQ(len, b->len);
	EXPECT_EQ(len - IP_LEN, ntohs(udp_hdr_of(b)->len));
	EXPECT_EQ(IP_LEN, skb_transport_offset(b));
	__skb_pull(a, IP_LEN);
	skb_reset_transport_header(a);

	/* The head and its children are all dispatched. */
	EXPECT_EQ(0, homa_udp_encap_rcv(&self->sk, a));
	EXPECT_EQ(0, unit_count_drops());
	EXPECT_EQ(1, homa_metrics_per_cpu()->softirq_calls);
	EXPECT_EQ(before + 3, homa_metrics_per_cpu()->packets_received[DATA - DATA]);
}
