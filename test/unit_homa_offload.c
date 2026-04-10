// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

#include "homa_impl.h"
#include "homa_offload.h"
#include "homa_rpc.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#define cur_offload_core (&per_cpu(homa_offload_core, smp_processor_id()))

static struct sk_buff **test_tcp_gro_receive(struct sk_buff **gro_list,
				       struct sk_buff *skb)
{
	UNIT_LOG("; ", "test_tcp_gro_receive");
	return NULL;
}
static struct sk_buff **unit_tcp6_gro_receive(struct sk_buff **gro_list,
				       struct sk_buff *skb)
{
	UNIT_LOG("; ", "unit_tcp6_gro_receive");
	return NULL;
}

FIXTURE(homa_offload)
{
	struct homa homa;
	struct homa_net *hnet;
	struct homa_sock hsk;
	struct in6_addr ip;
	struct homa_data_hdr header;
	struct sk_buff *gro_list;
	struct sk_buff *skb, *skb2;
	struct net_offload tcp_offloads;
	struct net_offload tcp6_offloads;
};
FIXTURE_SETUP(homa_offload)
{
	homa_init(&self->homa);
	self->hnet = mock_hnet(0, &self->homa);
	self->homa.flags |= HOMA_FLAG_DONT_THROTTLE;
	self->homa.unsched_bytes = 10000;
	mock_sock_init(&self->hsk, self->hnet, 99);
	self->ip = unit_get_in_addr("196.168.0.1");
	memset(&self->header, 0, sizeof(self->header));
	self->header.common = (struct homa_common_hdr){
		.sport = htons(40000), .dport = htons(99),
		.type = DATA,
		.sender_id = cpu_to_be64(1000)
	};
	self->header.message_length = htonl(10000);
	self->header.incoming = htonl(10000);
	self->header.seg.offset = htonl(2000);

	self->skb = mock_skb_alloc(&self->ip, &self->header.common, 1400, 2000);
	NAPI_GRO_CB(self->skb)->same_flow = 0;
	((struct iphdr *) skb_network_header(self->skb))->protocol = IPPROTO_HOMA+1;
	NAPI_GRO_CB(self->skb)->data_offset = sizeof(struct homa_data_hdr);
	NAPI_GRO_CB(self->skb)->last = self->skb;
	self->header.seg.offset = htonl(4000);
	self->header.common.dport = htons(88);
	self->header.common.sender_id = cpu_to_be64(1002);
	self->skb2 = mock_skb_alloc(&self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(self->skb2)->same_flow = 0;
	NAPI_GRO_CB(self->skb2)->data_offset = sizeof(struct homa_data_hdr);
	NAPI_GRO_CB(self->skb2)->last = self->skb2;
	self->gro_list = self->skb;
	self->skb->next = self->skb2;
	self->skb2->next = NULL;
	self->tcp_offloads.callbacks.gro_receive = test_tcp_gro_receive;
	inet_offloads[IPPROTO_TCP] = &self->tcp_offloads;
	self->tcp6_offloads.callbacks.gro_receive = unit_tcp6_gro_receive;
	inet6_offloads[IPPROTO_TCP] = &self->tcp6_offloads;
	homa_offload_init();

	unit_log_clear();

	/* Configure so core isn't considered too busy for bypasses. */
	mock_clock = 1000;
	self->homa.gro_busy_cycles = 500;
	cur_offload_core->last_gro = 400;
}
FIXTURE_TEARDOWN(homa_offload)
{
	homa_offload_end();
	while (self->gro_list) {
		struct sk_buff *next = self->gro_list->next;
		kfree_skb(self->gro_list);
		self->gro_list = next;
	}
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_offload, homa_gso_segment_set_ip_ids)
{
	struct sk_buff *skb, *segs;
	int version;

	mock_ipv6 = false;
	skb = mock_skb_alloc(&self->ip, &self->header.common, 1400, 2000);
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
	struct homa_data_hdr *h;

	/* First call: copy offset from sequence number. */
	self->header.common.sequence = htonl(6000);
	self->header.seg.offset = -1;
	skb = mock_skb_alloc(&self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 0;
	EXPECT_EQ(NULL, homa_gro_receive(&self->gro_list, skb));
	h = (struct homa_data_hdr *) skb_transport_header(skb);
	EXPECT_EQ(6000, htonl(h->seg.offset));

	/* Second call: offset already valid. */
	self->header.common.sequence = htonl(6000);
	self->header.seg.offset = ntohl(5000);
	skb2 = mock_skb_alloc(&self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb2)->same_flow = 0;
	EXPECT_EQ(NULL, homa_gro_receive(&self->gro_list, skb2));
	h = (struct homa_data_hdr *)skb_transport_header(skb2);
	EXPECT_EQ(5000, htonl(h->seg.offset));
}
TEST_F(homa_offload, homa_gro_receive__HOMA_GRO_SHORT_BYPASS)
{
	struct in6_addr client_ip = unit_get_in_addr("196.168.0.1");
	struct in6_addr server_ip = unit_get_in_addr("1.2.3.4");
	struct sk_buff *skb, *skb2, *skb3, *skb4;
	struct sk_buff **result;
	int client_port = 40000;
	u64 client_id = 1234;
	u64 server_id = 1235;
	struct homa_rpc *srpc;
	int server_port = 99;
	struct homa_data_hdr h;

	memset(&h, 0, sizeof(h));
	h.common.sport = htons(40000);
	h.common.dport = htons(server_port);
	h.common.type = DATA;
	h.common.sender_id = cpu_to_be64(client_id);
	h.message_length = htonl(10000);
	h.incoming = htonl(10000);
	h.seg.offset = htonl(2000);

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT,
			&client_ip, &server_ip, client_port, server_id, 10000,
			200);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	/* First attempt: HOMA_GRO_SHORT_BYPASS not enabled. */
	skb = mock_skb_alloc(&self->ip, &h.common, 1400, 2000);
	result = homa_gro_receive(&self->gro_list, skb);
	EXPECT_EQ(0, -PTR_ERR(result));
	EXPECT_EQ(0, homa_metrics_per_cpu()->gro_data_bypasses);

	/* Second attempt: HOMA_GRO_SHORT_BYPASS enabled but message longer
	 * than one packet.
	 */
	self->homa.gro_policy |= HOMA_GRO_SHORT_BYPASS;
	cur_offload_core->last_gro = 400;
	skb2 = mock_skb_alloc(&self->ip, &h.common, 1400, 2000);
	result = homa_gro_receive(&self->gro_list, skb2);
	EXPECT_EQ(0, -PTR_ERR(result));
	EXPECT_EQ(0, homa_metrics_per_cpu()->gro_data_bypasses);

	/* Third attempt: bypass should happen. */
	h.message_length = htonl(1400);
	h.incoming = htonl(1400);
	cur_offload_core->last_gro = 400;
	skb3 = mock_skb_alloc(&self->ip, &h.common, 1400, 4000);
	result = homa_gro_receive(&self->gro_list, skb3);
	EXPECT_EQ(EINPROGRESS, -PTR_ERR(result));
	EXPECT_EQ(1, homa_metrics_per_cpu()->gro_data_bypasses);

	/* Fourth attempt: no bypass because core busy. */
	cur_offload_core->last_gro = 600;
	skb4 = mock_skb_alloc(&self->ip, &h.common, 1400, 4000);
	result = homa_gro_receive(&self->gro_list, skb4);
	EXPECT_EQ(0, -PTR_ERR(result));
	EXPECT_EQ(1, homa_metrics_per_cpu()->gro_data_bypasses);
}
TEST_F(homa_offload, homa_gro_receive__fast_grant_optimization)
{
	struct in6_addr client_ip = unit_get_in_addr("196.168.0.1");
	struct in6_addr server_ip = unit_get_in_addr("1.2.3.4");
	struct sk_buff *skb, *skb2, *skb3;
	struct sk_buff **result;
	struct homa_grant_hdr h;
	int client_port = 40000;
	u64 client_id = 1234;
	u64 server_id = 1235;
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING,
			&client_ip, &server_ip, client_port, server_id, 100,
			20000);
	ASSERT_NE(NULL, srpc);
	homa_rpc_lock(srpc);
	homa_xmit_data(srpc, false);
	homa_rpc_unlock(srpc);
	unit_log_clear();

	h.common.sport = htons(srpc->dport);
	h.common.dport = htons(self->hsk.port);
	h.common.sender_id = cpu_to_be64(client_id);
	h.common.type = GRANT;
	h.offset = htonl(11000);
	h.priority = 3;

	/* First attempt: HOMA_GRO_FAST_GRANTS not enabled. */
	self->homa.gro_policy = 0;
	skb = mock_skb_alloc(&client_ip, &h.common, 0, 0);
	result = homa_gro_receive(&self->gro_list, skb);
	EXPECT_EQ(0, -PTR_ERR(result));
	EXPECT_EQ(0, homa_metrics_per_cpu()->gro_grant_bypasses);
	EXPECT_STREQ("", unit_log_get());

	/* Second attempt: HOMA_FAST_GRANTS is enabled. */
	self->homa.gro_policy = HOMA_GRO_FAST_GRANTS;
	cur_offload_core->last_gro = 400;
	skb2 = mock_skb_alloc(&client_ip, &h.common, 0, 0);
	result = homa_gro_receive(&self->gro_list, skb2);
	EXPECT_EQ(EINPROGRESS, -PTR_ERR(result));
	EXPECT_EQ(1, homa_metrics_per_cpu()->gro_grant_bypasses);
	EXPECT_SUBSTR("xmit DATA 1400@10000", unit_log_get());

	/* Third attempt: core is too busy for fast grants. */
	cur_offload_core->last_gro = 600;
	skb3 = mock_skb_alloc(&client_ip, &h.common, 0, 0);
	result = homa_gro_receive(&self->gro_list, skb3);
	EXPECT_EQ(0, -PTR_ERR(result));
	EXPECT_EQ(1, homa_metrics_per_cpu()->gro_grant_bypasses);
}
TEST_F(homa_offload, homa_gro_receive__no_held_skbs)
{
	struct sk_buff *held_list = NULL;
	struct sk_buff *skb;
	int same_flow;

	self->header.seg.offset = htonl(6000);
	skb = mock_skb_alloc(&self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 0;
	EXPECT_EQ(NULL, homa_gro_receive(&held_list, skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(0, same_flow);
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_gro_receive__skip_held_skbs_that_arent_homa_packets)
{
	struct sk_buff *skb;
	int same_flow;

	if (skb_is_ipv6(self->gro_list))
		ipv6_hdr(self->gro_list)->nexthdr = IPPROTO_TCP;
	else
		ip_hdr(self->gro_list)->protocol = IPPROTO_TCP;

	self->header.seg.offset = htonl(6000);
	skb = mock_skb_alloc(&self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 0;
	EXPECT_EQ(NULL, homa_gro_receive(&self->gro_list, skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(1, same_flow);
	unit_log_clear();
	unit_log_frag_list(self->gro_list, 0);
	EXPECT_STREQ("",
			unit_log_get());
	unit_log_clear();
	unit_log_frag_list(self->gro_list->next, 0);
	EXPECT_STREQ("DATA 1400@6000",
			unit_log_get());
}
TEST_F(homa_offload, homa_gro_receive__add_to_frag_list)
{
	struct sk_buff *skb;
	int same_flow;

	self->header.seg.offset = htonl(6000);
	skb = mock_skb_alloc(&self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 0;
	EXPECT_EQ(NULL, homa_gro_receive(&self->gro_list, skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(1, same_flow);

	self->header.seg.offset = htonl(7400);
	skb = mock_skb_alloc(&self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 0;
	EXPECT_EQ(NULL, homa_gro_receive(&self->gro_list, skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(1, same_flow);
	unit_log_clear();
	unit_log_frag_list(self->gro_list, 0);
	EXPECT_STREQ("DATA 1400@6000; DATA 1400@7400", unit_log_get());
}
TEST_F(homa_offload, homa_gro_receive__max_gro_skbs)
{
	struct homa_common_hdr *h;
	struct sk_buff *skb;

	h = (struct homa_common_hdr *)skb_transport_header(self->gro_list);

	// First packet fits below the limit.
	self->homa.max_gro_skbs = 3;
	self->header.seg.offset = htonl(6000);
	skb = mock_skb_alloc(&self->ip, &self->header.common, 1400, 0);
	EXPECT_EQ(NULL, homa_gro_receive(&self->gro_list, skb));
	EXPECT_EQ(1, NAPI_GRO_CB(self->gro_list)->count);
	EXPECT_EQ(1, h->gro_count);

	// Second packet also fits below the limit.
	self->header.seg.offset = htonl(8000);
	skb = mock_skb_alloc(&self->ip, &self->header.common, 1400, 0);
	EXPECT_EQ(NULL, homa_gro_receive(&self->gro_list, skb));
	EXPECT_EQ(2, NAPI_GRO_CB(self->gro_list)->count);
	EXPECT_EQ(2, h->gro_count);

	// Third packet hits the limit.
	self->header.seg.offset = htonl(10000);
	skb = mock_skb_alloc(&self->ip, &self->header.common, 1400, 0);
	EXPECT_EQ(&self->gro_list, homa_gro_receive(&self->gro_list, skb));
	EXPECT_EQ(3, NAPI_GRO_CB(self->gro_list)->count);
	EXPECT_EQ(3, h->gro_count);
}
TEST_F(homa_offload, homa_gro_receive__set_softirq_cpu)
{
	struct sk_buff *held_list = NULL;
	struct sk_buff *skb;

	cpu_number = 5;

	/* First call: HOMA_GRO_SAME_CORE not set. */
	skb = mock_skb_alloc(&self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 0;
	skb->hash = 0;
	self->homa.gro_policy &= ~HOMA_GRO_SAME_CORE;
	EXPECT_EQ(NULL, homa_gro_receive(&held_list, skb));
	EXPECT_EQ(0, skb->hash);

	/* Second call: HOMA_GRO_SAME_CORE set. */
	self->homa.gro_policy |= HOMA_GRO_SAME_CORE;
	EXPECT_EQ(NULL, homa_gro_receive(&held_list, skb));
	EXPECT_EQ(rps_cpu_mask + 6, skb->hash);
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

	self->homa.gro_policy = HOMA_GRO_GEN3;
	offload_core->gen3_softirq_cores[0] = 3;
	offload_core->gen3_softirq_cores[1] = 7;
	offload_core->gen3_softirq_cores[2] = 5;
	offload3->last_app_active = 4100;
	offload7->last_app_active = 3900;
	offload5->last_app_active = 2000;
	mock_clock = 5000;
	self->homa.busy_cycles = 1000;

	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(7, self->skb->hash - 32);
	EXPECT_EQ(0, offload3->last_active);
	EXPECT_EQ(5000, offload7->last_active);
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

	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(3, self->skb->hash - 32);
	EXPECT_EQ(5000, per_cpu(homa_offload_core, 3).last_active);
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

	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(3, self->skb->hash - 32);
	EXPECT_EQ(5000, per_cpu(homa_offload_core, 3).last_active);
}

TEST_F(homa_offload, homa_gro_complete__clear_held_skb)
{
	struct homa_offload_core *offload_core = &per_cpu(homa_offload_core,
			smp_processor_id());

	offload_core->held_skb = self->skb2;
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(NULL, offload_core->held_skb);
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
