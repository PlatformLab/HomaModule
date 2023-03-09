/* Copyright (c) 2019-2022 Stanford University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "homa_impl.h"
#include "homa_lcache.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

extern struct homa *homa;

FIXTURE(homa_offload) {
	struct homa homa;
	struct homa_sock hsk;
	struct in6_addr ip;
	struct data_header header;
	struct napi_struct napi;
	struct sk_buff *skb, *skb2;
	struct list_head empty_list;
};
FIXTURE_SETUP(homa_offload)
{
	int i;
	homa_init(&self->homa);
	self->homa.flags |= HOMA_FLAG_DONT_THROTTLE;
	self->homa.grant_threshold = self->homa.rtt_bytes;
	homa = &self->homa;
	mock_sock_init(&self->hsk, &self->homa, 99);
	self->ip = unit_get_in_addr("196.168.0.1");
	self->header = (struct data_header){.common = {
			.sport = htons(40000), .dport = htons(99),
			.type = DATA,
			.sender_id = cpu_to_be64(1000)},
			.message_length = htonl(10000),
			.incoming = htonl(10000), .cutoff_version = 0,
			.retransmit = 0,
			.seg = {.offset = htonl(2000),
			        .segment_length = htonl(1400),
	                        .ack = {0, 0, 0}}};
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
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_offload)
{
        struct sk_buff *skb, *tmp;

	list_for_each_entry_safe(skb, tmp, &self->napi.gro_hash[2].list, list)
		kfree_skb(skb);
	homa_destroy(&self->homa);
	homa = NULL;
	unit_teardown();
}

TEST_F(homa_offload, homa_gso_segment_set_ip_ids)
{
	mock_ipv6 = false;
	struct sk_buff *skb = mock_skb_new(&self->ip, &self->header.common,
			1400, 2000);
	int version = ip_hdr(skb)->version;
	EXPECT_EQ(4, version);
	struct sk_buff *segs = homa_gso_segment(skb, 0);
	ASSERT_NE(NULL, segs);
	ASSERT_NE(NULL, segs->next);
	EXPECT_EQ(NULL, segs->next->next);
	EXPECT_EQ(0, ntohs(ip_hdr(segs)->id));
	EXPECT_EQ(1, ntohs(ip_hdr(segs->next)->id));
	kfree_skb(skb);
	kfree_skb(segs->next);
	kfree_skb(segs);
}

TEST_F(homa_offload, homa_gro_receive__fast_grant_optimization)
{
	struct in6_addr client_ip = unit_get_in_addr("196.168.0.1");
	struct in6_addr server_ip = unit_get_in_addr("1.2.3.4");
	int client_port = 40000;
	__u64 client_id = 1234;
	__u64 server_id = 1235;
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING,
			&client_ip, &server_ip, client_port, server_id, 100,
			20000);
	ASSERT_NE(NULL, srpc);
	homa_xmit_data(srpc, false);
	unit_log_clear();

	struct grant_header h = {{.sport = htons(srpc->dport),
	                .dport = htons(self->hsk.port),
			.sender_id = cpu_to_be64(client_id),
			.type = GRANT},
		        .offset = htonl(12600),
			.priority = 3};
	self->homa.gro_policy = HOMA_GRO_FAST_GRANTS;
	struct sk_buff *result = homa_gro_receive(&self->empty_list,
			mock_skb_new(&client_ip, &h.common, 0, 0));
	EXPECT_EQ(EINPROGRESS, -PTR_ERR(result));
	EXPECT_EQ(12600, srpc->msgout.granted);
	EXPECT_STREQ("xmit DATA 1400@11200", unit_log_get());

	unit_log_clear();
	h.offset = htonl(14000);
	self->homa.gro_policy = 0;
	struct sk_buff *skb = mock_skb_new(&client_ip, &h.common, 0, 0);
	result = homa_gro_receive(&self->empty_list, skb);
	EXPECT_EQ(NULL, result);
	EXPECT_EQ(12600, srpc->msgout.granted);
	EXPECT_STREQ("", unit_log_get());
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_gro_receive__HOMA_GRO_SHORT_BYPASS)
{
	struct in6_addr client_ip = unit_get_in_addr("196.168.0.1");
	struct in6_addr server_ip = unit_get_in_addr("1.2.3.4");
	int client_port = 40000;
	int server_port = 99;
	__u64 client_id = 1234;
	__u64 server_id = 1235;
	struct data_header h = {.common = {
			.sport = htons(40000), .dport = htons(server_port),
			.type = DATA,
			.sender_id = cpu_to_be64(client_id)},
			.message_length = htonl(10000),
			.incoming = htonl(10000), .cutoff_version = 0,
			.retransmit = 0,
			.seg = {.offset = htonl(2000),
			        .segment_length = htonl(1400),
	                        .ack = {0, 0, 0}}};
	struct sk_buff *skb, *skb2, *skb3;

	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT,
			&client_ip, &server_ip, client_port, server_id, 10000,
			200);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();

	/* First attempt: HOMA_GRO_SHORT_BYPASS not enabled. */
	skb = mock_skb_new(&self->ip, &h.common, 1400, 2000);
	struct sk_buff *result = homa_gro_receive(&self->empty_list, skb);
	EXPECT_EQ(0, -PTR_ERR(result));
	EXPECT_EQ(8600, srpc->msgin.bytes_remaining);

	/* Second attempt: HOMA_GRO_SHORT_BYPASS enabled but packet too long. */
	self->homa.gro_policy |= HOMA_GRO_SHORT_BYPASS;
	skb2 = mock_skb_new(&self->ip, &h.common, 1400, 3000);
	result = homa_gro_receive(&self->empty_list, skb2);
	EXPECT_EQ(0, -PTR_ERR(result));
	EXPECT_EQ(8600, srpc->msgin.bytes_remaining);

	/* Third attempt: bypass should happen. */
	h.seg.segment_length = htonl(100);
	skb3 = mock_skb_new(&self->ip, &h.common, 100, 4000);
	result = homa_gro_receive(&self->empty_list, skb3);
	EXPECT_EQ(EINPROGRESS, -PTR_ERR(result));
	EXPECT_EQ(8500, srpc->msgin.bytes_remaining);

	kfree_skb(skb);
	kfree_skb(skb2);
}
TEST_F(homa_offload, homa_gro_receive__no_held_skb)
{
	struct sk_buff *skb;
	int same_flow;
	self->header.seg.offset = htonl(6000);
	skb = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 0;
	homa_cores[cpu_number]->held_skb = NULL;
	homa_cores[cpu_number]->held_bucket = 99;
	EXPECT_EQ(NULL, homa_gro_receive(&self->empty_list, skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(0, same_flow);
	EXPECT_EQ(skb, homa_cores[cpu_number]->held_skb);
	EXPECT_EQ(3, homa_cores[cpu_number]->held_bucket);
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_gro_receive__empty_merge_list)
{
	struct sk_buff *skb;
	int same_flow;
	self->header.seg.offset = htonl(6000);
	skb = mock_skb_new(&self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 0;
	homa_cores[cpu_number]->held_skb = skb;
	homa_cores[cpu_number]->held_bucket = 3;
	EXPECT_EQ(NULL, homa_gro_receive(&self->empty_list, skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(0, same_flow);
	EXPECT_EQ(skb, homa_cores[cpu_number]->held_skb);
	EXPECT_EQ(3, homa_cores[cpu_number]->held_bucket);
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_gro_receive__merge)
{
	struct sk_buff *skb, *skb2;
	int same_flow;
	homa_cores[cpu_number]->held_skb = self->skb2;
	homa_cores[cpu_number]->held_bucket = 2;

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
	EXPECT_STREQ("DATA from 196.168.0.1:40000, dport 88, id 1002, "
			"message_length 10000, offset 6000, "
			"data_length 1400, incoming 10000; "
			"DATA from 196.168.0.1:40000, dport 88, id 1004, "
			"message_length 10000, offset 7000, "
			"data_length 1400, incoming 10000",
			unit_log_get());
}
TEST_F(homa_offload, homa_gro_receive__max_gro_skbs)
{
	struct sk_buff *skb;

	// First packet: fits below the limit.
	homa->max_gro_skbs = 3;
	homa_cores[cpu_number]->held_skb = self->skb2;
	homa_cores[cpu_number]->held_bucket = 2;
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
	homa_cores[cpu_number]->held_skb = self->skb;
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

TEST_F(homa_offload, homa_gro_complete__GRO_IDLE_NEW)
{
	homa->gro_policy = HOMA_GRO_IDLE_NEW;
	mock_cycles = 1000;
	homa->gro_busy_cycles = 100;
	cpu_number = 5;
	atomic_set(&homa_cores[6]->softirq_backlog, 1);
	homa_cores[6]->last_gro = 0;
	atomic_set(&homa_cores[7]->softirq_backlog, 0);
	homa_cores[7]->last_gro = 901;
	atomic_set(&homa_cores[0]->softirq_backlog, 2);
	homa_cores[0]->last_gro = 0;
	atomic_set(&homa_cores[1]->softirq_backlog, 0);
	homa_cores[1]->last_gro = 899;
	atomic_set(&homa_cores[2]->softirq_backlog, 0);
	homa_cores[2]->last_gro = 0;

	// Avoid busy cores.
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(1, self->skb->hash - 32);
	EXPECT_EQ(1, atomic_read(&homa_cores[1]->softirq_backlog));

	// All cores busy; must rotate.
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(6, self->skb->hash - 32);
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(7, self->skb->hash - 32);
	EXPECT_EQ(2, homa_cores[5]->softirq_offset);
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(0, self->skb->hash - 32);
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(1, self->skb->hash - 32);
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(6, self->skb->hash - 32);
	EXPECT_EQ(1, homa_cores[5]->softirq_offset);
}

TEST_F(homa_offload, homa_gro_complete__GRO_IDLE)
{
	homa->gro_policy = HOMA_GRO_IDLE;
	homa_cores[6]->last_active = 30;
	homa_cores[7]->last_active = 25;
	homa_cores[0]->last_active = 20;
	homa_cores[1]->last_active = 15;
	homa_cores[2]->last_active = 10;

	cpu_number = 5;
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(1, self->skb->hash - 32);

	homa_cores[6]->last_active = 5;
	cpu_number = 5;
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(6, self->skb->hash - 32);

	cpu_number = 6;
	homa_gro_complete(self->skb, 0);
	EXPECT_EQ(2, self->skb->hash - 32);
}
