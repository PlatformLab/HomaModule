// SPDX-License-Identifier: BSD-2-Clause

#include "homa_impl.h"
#include "homa_offload.h"
#include "homa_rpc.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#define cur_offload_core (&per_cpu(homa_offload_core, raw_smp_processor_id()))

extern struct homa *homa;

static struct sk_buff *tcp_gro_receive(struct list_head *held_list,
				       struct sk_buff *skb)
{
	UNIT_LOG("; ", "tcp_gro_receive");
	return NULL;
}
static struct sk_buff *tcp6_gro_receive(struct list_head *held_list,
				       struct sk_buff *skb)
{
	UNIT_LOG("; ", "tcp6_gro_receive");
	return NULL;
}

FIXTURE(homa_offload)
{
	struct homa homa;
	struct homa_sock hsk;
	struct in6_addr ip;
	struct data_header header;
	struct napi_struct napi;
	struct sk_buff *skb, *skb2;
	struct list_head empty_list;
	struct net_offload tcp_offloads;
	struct net_offload tcp6_offloads;
};
FIXTURE_SETUP(homa_offload)
{
	int i;

	homa_init(&self->homa);
	self->homa.flags |= HOMA_FLAG_DONT_THROTTLE;
	homa = &self->homa;
	mock_sock_init(&self->hsk, &self->homa, 99);
	self->ip = unit_get_in_addr("196.168.0.1");
	self->header = (struct data_header){.common = {
			.sport = htons(40000), .dport = htons(99),
			.type = DATA,
			.flags = HOMA_TCP_FLAGS,
			.urgent = HOMA_TCP_URGENT,
			.sender_id = cpu_to_be64(1000)},
			.message_length = htonl(10000),
			.incoming = htonl(10000), .cutoff_version = 0,
			.ack = {0, 0, 0},
			.retransmit = 0,
			.seg = {.offset = htonl(2000)}};
	for (i = 0; i < GRO_HASH_BUCKETS; i++) {
		INIT_LIST_HEAD(&self->napi.gro_hash[i].list);
		self->napi.gro_hash[i].count = 0;
	}
	self->napi.gro_bitmask = 0;

	self->skb = mock_skb_new(&self->ip, &self->header.common, 1400, 2000);
	NAPI_GRO_CB(self->skb)->same_flow = 0;
	NAPI_GRO_CB(self->skb)->last = self->skb;
	NAPI_GRO_CB(self->skb)->count = 1;
	self->header.seg.offset = htonl(4000);
	self->header.common.dport = htons(88);
	self->header.common.sender_id = cpu_to_be64(1002);
	self->skb2 = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(self->skb2)->same_flow = 0;
	NAPI_GRO_CB(self->skb2)->last = self->skb2;
	NAPI_GRO_CB(self->skb2)->count = 1;
	self->napi.gro_bitmask = 6;
	self->napi.gro_hash[2].count = 2;
	list_add_tail(&self->skb->list, &self->napi.gro_hash[2].list);
	list_add_tail(&self->skb2->list, &self->napi.gro_hash[2].list);
	INIT_LIST_HEAD(&self->empty_list);
	self->tcp_offloads.callbacks.gro_receive = tcp_gro_receive;
	inet_offloads[IPPROTO_TCP] = &self->tcp_offloads;
	self->tcp6_offloads.callbacks.gro_receive = tcp6_gro_receive;
	inet6_offloads[IPPROTO_TCP] = &self->tcp6_offloads;
	homa_offload_init();

	unit_log_clear();

	/* Configure so core isn't considered too busy for bypasses. */
	mock_cycles = 1000;
	self->homa.gro_busy_cycles = 500;
	cur_offload_core->last_gro = 400;
}
FIXTURE_TEARDOWN(homa_offload)
{
	struct sk_buff *skb, *tmp;

	homa_offload_end();
	list_for_each_entry_safe(skb, tmp, &self->napi.gro_hash[2].list, list)
		kfree_skb(skb);
	homa_destroy(&self->homa);
	homa = NULL;
	unit_teardown();
}

TEST_F(homa_offload, homa_gro_hook_tcp)
{
	homa_gro_hook_tcp();
	EXPECT_EQ(&homa_tcp_gro_receive,
		  inet_offloads[IPPROTO_TCP]->callbacks.gro_receive);
	EXPECT_EQ(&homa_tcp_gro_receive,
		  inet6_offloads[IPPROTO_TCP]->callbacks.gro_receive);

	/* Second hook call should do nothing. */
	homa_gro_hook_tcp();

	homa_gro_unhook_tcp();
	EXPECT_EQ(&tcp_gro_receive,
		  inet_offloads[IPPROTO_TCP]->callbacks.gro_receive);
	EXPECT_EQ(&tcp6_gro_receive,
		  inet6_offloads[IPPROTO_TCP]->callbacks.gro_receive);

	/* Second unhook call should do nothing. */
	homa_gro_unhook_tcp();
	EXPECT_EQ(&tcp_gro_receive,
		  inet_offloads[IPPROTO_TCP]->callbacks.gro_receive);
	EXPECT_EQ(&tcp6_gro_receive,
		  inet6_offloads[IPPROTO_TCP]->callbacks.gro_receive);
}

TEST_F(homa_offload, homa_tcp_gro_receive__pass_to_tcp)
{
	struct common_header *h;
	struct sk_buff *skb;

	homa_gro_hook_tcp();
	self->header.seg.offset = htonl(6000);
	skb = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	h = (struct common_header *) skb_transport_header(skb);
	h->flags = 0;
	EXPECT_EQ(NULL, homa_tcp_gro_receive(&self->empty_list, skb));
	EXPECT_STREQ("tcp_gro_receive", unit_log_get());
	kfree_skb(skb);
	unit_log_clear();

	skb = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	h = (struct common_header *)skb_transport_header(skb);
	h->urgent -= 1;
	EXPECT_EQ(NULL, homa_tcp_gro_receive(&self->empty_list, skb));
	EXPECT_STREQ("tcp_gro_receive", unit_log_get());
	kfree_skb(skb);
	homa_gro_unhook_tcp();
}
TEST_F(homa_offload, homa_tcp_gro_receive__pass_to_homa_ipv6)
{
	struct common_header *h;
	struct sk_buff *skb;

	homa_gro_hook_tcp();
	self->header.seg.offset = htonl(6000);
	skb = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	ip_hdr(skb)->protocol = IPPROTO_TCP;
	h = (struct common_header *)skb_transport_header(skb);
	h->flags = HOMA_TCP_FLAGS;
	h->urgent = htons(HOMA_TCP_URGENT);
	NAPI_GRO_CB(skb)->same_flow = 0;
	cur_offload_core->held_skb = NULL;
	cur_offload_core->held_bucket = 99;
	EXPECT_EQ(NULL, homa_tcp_gro_receive(&self->empty_list, skb));
	EXPECT_EQ(skb, cur_offload_core->held_skb);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(IPPROTO_HOMA, ipv6_hdr(skb)->nexthdr);
	kfree_skb(skb);
	homa_gro_unhook_tcp();
}
TEST_F(homa_offload, homa_tcp_gro_receive__pass_to_homa_ipv4)
{
	struct common_header *h;
	struct sk_buff *skb;

	mock_ipv6 = false;
	homa_gro_hook_tcp();
	self->header.seg.offset = htonl(6000);
	skb = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	ip_hdr(skb)->protocol = IPPROTO_TCP;
	h = (struct common_header *)skb_transport_header(skb);
	h->flags = HOMA_TCP_FLAGS;
	h->urgent = htons(HOMA_TCP_URGENT);
	NAPI_GRO_CB(skb)->same_flow = 0;
	cur_offload_core->held_skb = NULL;
	cur_offload_core->held_bucket = 99;
	EXPECT_EQ(NULL, homa_tcp_gro_receive(&self->empty_list, skb));
	EXPECT_EQ(skb, cur_offload_core->held_skb);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(IPPROTO_HOMA, ip_hdr(skb)->protocol);
	EXPECT_EQ(2303, ip_hdr(skb)->check);
	kfree_skb(skb);
	homa_gro_unhook_tcp();
}

TEST_F(homa_offload, homa_gso_segment_set_ip_ids)
{
	struct sk_buff *skb, *segs;
	int version;

	mock_ipv6 = false;
	skb = mock_skb_new(&self->ip, &self->header.common, 1400, 2000);
	version = ip_hdr(skb)->version;
	EXPECT_EQ(4, version);
	segs = homa_gso_segment(skb, 0);
	ASSERT_NE(NULL, segs);
	ASSERT_NE(NULL, segs->next);
	EXPECT_EQ(NULL, segs->next->next);
	EXPECT_EQ(0, ntohs(ip_hdr(segs)->id));
	EXPECT_EQ(1, ntohs(ip_hdr(segs->next)->id));
	kfree_skb(skb);
	kfree_skb(segs->next);
	kfree_skb(segs);
}

TEST_F(homa_offload, homa_gro_receive__update_offset_from_sequence)
{
	struct sk_buff *skb, *skb2;
	struct data_header *h;

	/* First call: copy offset from sequence number. */
	self->header.common.sequence = htonl(6000);
	self->header.seg.offset = -1;
	skb = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 0;
	cur_offload_core->held_skb = NULL;
	cur_offload_core->held_bucket = 99;
	EXPECT_EQ(NULL, homa_gro_receive(&self->empty_list, skb));
	h = (struct data_header *) skb_transport_header(skb);
	EXPECT_EQ(6000, htonl(h->seg.offset));

	/* Second call: offset already valid. */
	self->header.common.sequence = htonl(6000);
	self->header.seg.offset = ntohl(5000);
	skb2 = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb2)->same_flow = 0;
	EXPECT_EQ(NULL, homa_gro_receive(&self->empty_list, skb2));
	h = (struct data_header *)skb_transport_header(skb2);
	EXPECT_EQ(5000, htonl(h->seg.offset));

	kfree_skb(skb);
	kfree_skb(skb2);
}
TEST_F(homa_offload, homa_gro_receive__HOMA_GRO_SHORT_BYPASS)
{
	struct in6_addr client_ip = unit_get_in_addr("196.168.0.1");
	struct in6_addr server_ip = unit_get_in_addr("1.2.3.4");
	struct sk_buff *skb, *skb2, *skb3, *skb4, *result;
	int client_port = 40000;
	__u64 client_id = 1234;
	__u64 server_id = 1235;
	struct homa_rpc *srpc;
	int server_port = 99;
	struct data_header h;

	h.common.sport = htons(40000);
	h.common.dport = htons(server_port);
	h.common.type = DATA;
	h.common.sender_id = cpu_to_be64(client_id);
	h.message_length = htonl(10000);
	h.incoming = htonl(10000);
	h.cutoff_version = 0;
	h.ack.client_id = 0;
	h.ack.client_port = 0;
	h.ack.server_port = 0;
	h.retransmit = 0;
	h.seg.offset = htonl(2000);

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT,
			&client_ip, &server_ip, client_port, server_id, 10000,
			200);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	/* First attempt: HOMA_GRO_SHORT_BYPASS not enabled. */
	skb = mock_skb_new(&self->ip, &h.common, 1400, 2000);
	result = homa_gro_receive(&self->empty_list, skb);
	EXPECT_EQ(0, -PTR_ERR(result));
	EXPECT_EQ(0, homa_metrics_per_cpu()->gro_data_bypasses);

	/* Second attempt: HOMA_GRO_SHORT_BYPASS enabled but message longer
	 * than one packet.
	 */
	self->homa.gro_policy |= HOMA_GRO_SHORT_BYPASS;
	cur_offload_core->last_gro = 400;
	skb2 = mock_skb_new(&self->ip, &h.common, 1400, 2000);
	result = homa_gro_receive(&self->empty_list, skb2);
	EXPECT_EQ(0, -PTR_ERR(result));
	EXPECT_EQ(0, homa_metrics_per_cpu()->gro_data_bypasses);

	/* Third attempt: bypass should happen. */
	h.message_length = htonl(1400);
	h.incoming = htonl(1400);
	cur_offload_core->last_gro = 400;
	skb3 = mock_skb_new(&self->ip, &h.common, 1400, 4000);
	result = homa_gro_receive(&self->empty_list, skb3);
	EXPECT_EQ(EINPROGRESS, -PTR_ERR(result));
	EXPECT_EQ(1, homa_metrics_per_cpu()->gro_data_bypasses);

	/* Third attempt: no bypass because core busy. */
	cur_offload_core->last_gro = 600;
	skb4 = mock_skb_new(&self->ip, &h.common, 1400, 4000);
	result = homa_gro_receive(&self->empty_list, skb3);
	EXPECT_EQ(0, -PTR_ERR(result));
	EXPECT_EQ(1, homa_metrics_per_cpu()->gro_data_bypasses);

	kfree_skb(skb);
	kfree_skb(skb2);
	kfree_skb(skb4);
}
TEST_F(homa_offload, homa_gro_receive__fast_grant_optimization)
{
	struct in6_addr client_ip = unit_get_in_addr("196.168.0.1");
	struct in6_addr server_ip = unit_get_in_addr("1.2.3.4");
	struct sk_buff *skb, *skb2, *skb3, *result;
	int client_port = 40000;
	__u64 client_id = 1234;
	__u64 server_id = 1235;
	struct homa_rpc *srpc;
	struct grant_header h;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING,
			&client_ip, &server_ip, client_port, server_id, 100,
			20000);
	ASSERT_NE(NULL, srpc);
	homa_xmit_data(srpc, false);
	unit_log_clear();

	h.common.sport = htons(srpc->dport);
	h.common.dport = htons(self->hsk.port);
	h.common.sender_id = cpu_to_be64(client_id);
	h.common.type = GRANT;
	h.offset = htonl(11000);
	h.priority = 3;
	h.resend_all = 0;

	/* First attempt: HOMA_GRO_FAST_GRANTS not enabled. */
	self->homa.gro_policy = 0;
	skb = mock_skb_new(&client_ip, &h.common, 0, 0);
	result = homa_gro_receive(&self->empty_list, skb);
	EXPECT_EQ(0, -PTR_ERR(result));
	EXPECT_EQ(0, homa_metrics_per_cpu()->gro_grant_bypasses);
	EXPECT_STREQ("", unit_log_get());

	/* Second attempt: HOMA_FAST_GRANTS is enabled. */
	self->homa.gro_policy = HOMA_GRO_FAST_GRANTS;
	cur_offload_core->last_gro = 400;
	skb2 = mock_skb_new(&client_ip, &h.common, 0, 0);
	result = homa_gro_receive(&self->empty_list, skb2);
	EXPECT_EQ(EINPROGRESS, -PTR_ERR(result));
	EXPECT_EQ(1, homa_metrics_per_cpu()->gro_grant_bypasses);
	EXPECT_SUBSTR("xmit DATA 1400@10000", unit_log_get());

	/* Third attempt: core is too busy for fast grants. */
	cur_offload_core->last_gro = 600;
	skb3 = mock_skb_new(&client_ip, &h.common, 0, 0);
	result = homa_gro_receive(&self->empty_list, skb3);
	EXPECT_EQ(0, -PTR_ERR(result));
	EXPECT_EQ(1, homa_metrics_per_cpu()->gro_grant_bypasses);
	kfree_skb(skb);
	kfree_skb(skb3);
}
TEST_F(homa_offload, homa_gro_receive__no_held_skb)
{
	struct sk_buff *skb;
	int same_flow;

	self->header.seg.offset = htonl(6000);
	skb = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	skb->hash = 2;
	NAPI_GRO_CB(skb)->same_flow = 0;
	cur_offload_core->held_skb = NULL;
	cur_offload_core->held_bucket = 2;
	EXPECT_EQ(NULL, homa_gro_receive(&self->napi.gro_hash[2].list, skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(0, same_flow);
	EXPECT_EQ(skb, cur_offload_core->held_skb);
	EXPECT_EQ(2, cur_offload_core->held_bucket);
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_gro_receive__empty_merge_list)
{
	struct sk_buff *skb;
	int same_flow;

	self->header.seg.offset = htonl(6000);
	skb = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	skb->hash = 2;
	NAPI_GRO_CB(skb)->same_flow = 0;
	cur_offload_core->held_skb = self->skb;
	cur_offload_core->held_bucket = 3;
	EXPECT_EQ(NULL, homa_gro_receive(&self->napi.gro_hash[2].list, skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(0, same_flow);
	EXPECT_EQ(skb, cur_offload_core->held_skb);
	EXPECT_EQ(2, cur_offload_core->held_bucket);
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_gro_receive__held_skb_not_in_merge_list)
{
	struct sk_buff *skb;
	int same_flow;

	self->header.seg.offset = htonl(6000);
	skb = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	skb->hash = 3;
	NAPI_GRO_CB(skb)->same_flow = 0;
	cur_offload_core->held_skb = skb;
	cur_offload_core->held_bucket = 2;
	EXPECT_EQ(NULL, homa_gro_receive(&self->napi.gro_hash[3].list, skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(0, same_flow);
	EXPECT_EQ(skb, cur_offload_core->held_skb);
	EXPECT_EQ(3, cur_offload_core->held_bucket);
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_gro_receive__held_skb__in_merge_list_but_wrong_proto)
{
	struct sk_buff *skb;
	int same_flow;

	self->header.seg.offset = htonl(6000);
	skb = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	skb->hash = 3;
	NAPI_GRO_CB(skb)->same_flow = 0;
	cur_offload_core->held_skb = self->skb;
	if (skb_is_ipv6(self->skb))
		ipv6_hdr(self->skb)->nexthdr = IPPROTO_TCP;
	else
		ip_hdr(self->skb)->protocol = IPPROTO_TCP;
	cur_offload_core->held_bucket = 2;
	EXPECT_EQ(NULL, homa_gro_receive(&self->napi.gro_hash[3].list, skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(0, same_flow);
	EXPECT_EQ(skb, cur_offload_core->held_skb);
	EXPECT_EQ(3, cur_offload_core->held_bucket);
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_gro_receive__merge)
{
	struct sk_buff *skb, *skb2;
	int same_flow;

	cur_offload_core->held_skb = self->skb2;
	cur_offload_core->held_bucket = 2;

	self->header.seg.offset = htonl(6000);
	self->header.common.sender_id = cpu_to_be64(1002);
	skb = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 0;
	EXPECT_EQ(NULL, homa_gro_receive(&self->napi.gro_hash[3].list, skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(1, same_flow);
	EXPECT_EQ(2, NAPI_GRO_CB(self->skb2)->count);

	self->header.seg.offset = htonl(7000);
	self->header.common.sender_id = cpu_to_be64(1004);
	skb2 = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb2)->same_flow = 0;
	EXPECT_EQ(NULL, homa_gro_receive(&self->napi.gro_hash[3].list, skb2));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(1, same_flow);
	EXPECT_EQ(3, NAPI_GRO_CB(self->skb2)->count);

	unit_log_frag_list(self->skb2, 1);
	EXPECT_STREQ("DATA from 196.168.0.1:40000, dport 88, id 1002, message_length 10000, offset 6000, data_length 1400, incoming 10000; "
			"DATA from 196.168.0.1:40000, dport 88, id 1004, message_length 10000, offset 7000, data_length 1400, incoming 10000",
			unit_log_get());
}
TEST_F(homa_offload, homa_gro_receive__max_gro_skbs)
{
	struct sk_buff *skb;

	// First packet: fits below the limit.
	homa->max_gro_skbs = 3;
	cur_offload_core->held_skb = self->skb2;
	cur_offload_core->held_bucket = 2;
	self->header.seg.offset = htonl(6000);
	skb = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	homa_gro_receive(&self->napi.gro_hash[3].list, skb);
	EXPECT_EQ(2, NAPI_GRO_CB(self->skb2)->count);
	EXPECT_EQ(2, self->napi.gro_hash[2].count);

	// Second packet hits the limit.
	self->header.common.sport = htons(40001);
	skb = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	unit_log_clear();
	EXPECT_EQ(EINPROGRESS, -PTR_ERR(homa_gro_receive(
			&self->napi.gro_hash[3].list, skb)));
	EXPECT_EQ(3, NAPI_GRO_CB(self->skb2)->count);
	EXPECT_EQ(1, self->napi.gro_hash[2].count);
	EXPECT_STREQ("netif_receive_skb, id 1002, offset 4000",
			unit_log_get());
	kfree_skb(self->skb2);
	EXPECT_EQ(1, self->napi.gro_hash[2].count);
	EXPECT_EQ(6, self->napi.gro_bitmask);

	// Third packet also hits the limit for skb, causing the bucket
	// to become empty.
	homa->max_gro_skbs = 2;
	cur_offload_core->held_skb = self->skb;
	skb = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	unit_log_clear();
	EXPECT_EQ(EINPROGRESS, -PTR_ERR(homa_gro_receive(
			&self->napi.gro_hash[3].list, skb)));
	EXPECT_EQ(2, NAPI_GRO_CB(self->skb)->count);
	EXPECT_EQ(0, self->napi.gro_hash[2].count);
	EXPECT_EQ(2, self->napi.gro_bitmask);
	EXPECT_STREQ("netif_receive_skb, id 1000, offset 2000",
			unit_log_get());
	kfree_skb(self->skb);
}

TEST_F(homa_offload, homa_gro_gen2)
{
	homa->gro_policy = HOMA_GRO_GEN2;
	mock_cycles = 1000;
	homa->busy_cycles = 100;
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
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(1, self->skb->hash - 32);
	EXPECT_EQ(1, atomic_read(&per_cpu(homa_offload_core, 1).softirq_backlog));

	// All cores busy; must rotate.
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(6, self->skb->hash - 32);
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(7, self->skb->hash - 32);
	EXPECT_EQ(2, per_cpu(homa_offload_core, 5).softirq_offset);
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(0, self->skb->hash - 32);
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(1, self->skb->hash - 32);
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(6, self->skb->hash - 32);
	EXPECT_EQ(1, per_cpu(homa_offload_core, 5).softirq_offset);
}

TEST_F(homa_offload, homa_gro_gen3__basics)
{
	struct homa_offload_core *offload_core = cur_offload_core;
	struct homa_offload_core *offload3 = &per_cpu(homa_offload_core, 3);
	struct homa_offload_core *offload5 = &per_cpu(homa_offload_core, 5);
	struct homa_offload_core *offload7 = &per_cpu(homa_offload_core, 7);

	homa->gro_policy = HOMA_GRO_GEN3;
	offload_core->gen3_softirq_cores[0] = 3;
	offload_core->gen3_softirq_cores[1] = 7;
	offload_core->gen3_softirq_cores[2] = 5;
	offload3->last_app_active = 4100;
	offload7->last_app_active = 3900;
	offload5->last_app_active = 2000;
	mock_cycles = 5000;
	self->homa.busy_cycles = 1000;

	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(7, self->skb->hash - 32);
	EXPECT_EQ(0, offload3->last_active);
	EXPECT_EQ(5000, offload7->last_active);
}
TEST_F(homa_offload, homa_gro_gen3__stop_on_negative_core_id)
{
	struct homa_offload_core *offload_core = cur_offload_core;

	homa->gro_policy = HOMA_GRO_GEN3;
	offload_core->gen3_softirq_cores[0] = 3;
	offload_core->gen3_softirq_cores[1] = -1;
	offload_core->gen3_softirq_cores[2] = 5;
	per_cpu(homa_offload_core, 3).last_app_active = 4100;
	per_cpu(homa_offload_core, 5).last_app_active = 2000;
	mock_cycles = 5000;
	self->homa.busy_cycles = 1000;

	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(3, self->skb->hash - 32);
	EXPECT_EQ(5000, per_cpu(homa_offload_core, 3).last_active);
}
TEST_F(homa_offload, homa_gro_gen3__all_cores_busy_so_pick_first)
{
	struct homa_offload_core *offload_core = cur_offload_core;

	homa->gro_policy = HOMA_GRO_GEN3;
	offload_core->gen3_softirq_cores[0] = 3;
	offload_core->gen3_softirq_cores[1] = 7;
	offload_core->gen3_softirq_cores[2] = 5;
	per_cpu(homa_offload_core, 3).last_app_active = 4100;
	per_cpu(homa_offload_core, 7).last_app_active = 4001;
	per_cpu(homa_offload_core, 5).last_app_active = 4500;
	mock_cycles = 5000;
	self->homa.busy_cycles = 1000;

	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(3, self->skb->hash - 32);
	EXPECT_EQ(5000, per_cpu(homa_offload_core, 3).last_active);
}


TEST_F(homa_offload, homa_gro_complete__clear_held_skb)
{
	struct homa_offload_core *offload_core = &per_cpu(homa_offload_core,
			raw_smp_processor_id());

	offload_core->held_skb = self->skb2;
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(NULL, offload_core->held_skb);
}
TEST_F(homa_offload, homa_gro_complete__GRO_IDLE)
{
	homa->gro_policy = HOMA_GRO_IDLE;
	per_cpu(homa_offload_core, 6).last_active = 30;
	per_cpu(homa_offload_core, 7).last_active = 25;
	per_cpu(homa_offload_core, 0).last_active = 20;
	per_cpu(homa_offload_core, 1).last_active = 15;
	per_cpu(homa_offload_core, 2).last_active = 10;

	mock_set_core(5);
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(1, self->skb->hash - 32);

	per_cpu(homa_offload_core, 6).last_active = 5;
	mock_set_core(5);
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(6, self->skb->hash - 32);

	mock_set_core(6);
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(2, self->skb->hash - 32);
}
