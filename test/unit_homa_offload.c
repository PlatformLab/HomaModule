/* Copyright (c) 2019-2020, Stanford University
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
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

extern struct homa *homa;

FIXTURE(homa_offload) {
	struct homa homa;
	__be32 ip;
	struct data_header header;
	struct list_head gro_list;
};
FIXTURE_SETUP(homa_offload)
{
	struct sk_buff *skb, *skb2;
	homa_init(&self->homa);
	homa_init(homa);
	self->ip = unit_get_in_addr("196.168.0.1");
	self->header = (struct data_header){.common = {
			.sport = htons(40000), .dport = htons(99),
			.type = DATA, .id = 1000, .generation = htons(1)},
			.message_length = htonl(10000),
			.incoming = htonl(10000), .cutoff_version = 0,
			.retransmit = 0,
			.seg = {.offset = htonl(2000),
			.segment_length = htonl(1400)}};
	skb = mock_skb_new(self->ip, &self->header.common, 3000,
			self->header.seg.offset);
	NAPI_GRO_CB(skb)->same_flow = 0;
	((struct iphdr *) skb_network_header(skb))->protocol = IPPROTO_HOMA+1;
	NAPI_GRO_CB(skb)->data_offset = sizeof32(struct data_header);
	NAPI_GRO_CB(skb)->last = skb;
	NAPI_GRO_CB(skb)->count = 1;
        self->header.seg.offset = htonl(4000);
        self->header.common.dport = htons(88);
        self->header.common.id = 1001;
	skb2 = mock_skb_new(self->ip, &self->header.common, 2000, 0);
	NAPI_GRO_CB(skb2)->same_flow = 0;
	NAPI_GRO_CB(skb2)->data_offset = sizeof32(struct data_header);
	NAPI_GRO_CB(skb2)->last = skb2;
	NAPI_GRO_CB(skb2)->count = 1;
	INIT_LIST_HEAD(&self->gro_list);
	list_add_tail(&skb->list, &self->gro_list);
	list_add_tail(&skb2->list, &self->gro_list);
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_offload)
{
        struct sk_buff *skb, *tmp;
	
	list_for_each_entry_safe(skb, tmp, &self->gro_list, list)
		kfree_skb(skb);
	homa_destroy(&self->homa);
	homa_destroy(homa);
	unit_teardown();
}

//TEST_F(homa_offload, homa_gro_receive__header_too_short)
//{
//	struct sk_buff *skb;
//	int flush;
//	self->header.common.type = 0;
//	skb = mock_skb_new(self->ip, &self->header.common, 0, 0);
//	skb->len -= 2;
//	homa_gro_receive(&self->gro_list, skb);
//	EXPECT_STREQ("no header", unit_log_get());
//	flush = NAPI_GRO_CB(skb)->flush;
//	EXPECT_EQ(1, flush);
//	kfree_skb(skb);
//}
TEST_F(homa_offload, homa_gro_receive__no_merge_list)
{
	struct sk_buff *skb;
	int same_flow;
	self->header.seg.offset = htonl(6000);
	skb = mock_skb_new(self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 0;
	homa_cores[cpu_number]->merge_list = NULL;
	EXPECT_EQ(NULL, homa_gro_receive(&self->gro_list, skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(0, same_flow);
	EXPECT_EQ(&self->gro_list, homa_cores[cpu_number]->merge_list);
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_gro_receive__empty_merge_list)
{
	struct list_head skb_list;
	struct sk_buff *skb;
	int same_flow;
	self->header.seg.offset = htonl(6000);
	skb = mock_skb_new(self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 0;
	INIT_LIST_HEAD(&skb_list);
	homa_cores[cpu_number]->merge_list = &skb_list;
	EXPECT_EQ(NULL, homa_gro_receive(&self->gro_list, skb));
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(0, same_flow);
	EXPECT_EQ(&self->gro_list, homa_cores[cpu_number]->merge_list);
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_gro_receive__merge)
{
	struct sk_buff *skb, *skb2;
	int same_flow;
	struct list_head skb_list;
	INIT_LIST_HEAD(&skb_list);
	homa_cores[cpu_number]->merge_list = &self->gro_list;
	
	self->header.seg.offset = htonl(6000);
	skb = mock_skb_new(self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 0;
	EXPECT_EQ(NULL, homa_gro_receive(&skb_list, skb));
	
	self->header.common.sport = htons(40001);
	skb2 = mock_skb_new(self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb2)->same_flow = 1;
	EXPECT_EQ(NULL, homa_gro_receive(&skb_list, skb2));
	
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(1, same_flow);
	skb = list_first_entry(&self->gro_list, struct sk_buff, list)->next;
	EXPECT_EQ(3, NAPI_GRO_CB(skb)->count);
	unit_log_frag_list(skb, 1);
	EXPECT_STREQ("DATA from 196.168.0.1:40000, dport 88, id 1001, "
			"message_length 10000, offset 6000, "
			"data_length 1400, incoming 10000; "
			"DATA from 196.168.0.1:40001, dport 88, id 1001, "
			"message_length 10000, offset 6000, "
			"data_length 1400, incoming 10000",
			unit_log_get());
	EXPECT_EQ(&self->gro_list, homa_cores[cpu_number]->merge_list);
}
TEST_F(homa_offload, homa_gro_receive__max_gro_skbs__list_mismatch)
{
	struct sk_buff *skb, *skb2, *merge;
	int same_flow;
	homa_cores[cpu_number]->merge_list = &self->gro_list;
	
	struct list_head skb_list;
	INIT_LIST_HEAD(&skb_list);
	
	homa->max_gro_skbs = 2;
	homa_cores[cpu_number]->merge_list = &self->gro_list;
	self->header.seg.offset = htonl(6000);
	skb = mock_skb_new(self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 0;
	homa_gro_receive(&skb_list, skb);
	
	self->header.common.sport = htons(40001);
	skb2 = mock_skb_new(self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 1;
	NAPI_GRO_CB(skb2)->same_flow = 0;
	EXPECT_EQ(NULL, homa_gro_receive(&skb_list, skb2));
	
	merge = list_first_entry(&self->gro_list, struct sk_buff, list)->next;
	EXPECT_EQ(3, NAPI_GRO_CB(merge)->count);
	unit_log_frag_list(merge, 1);
	EXPECT_STREQ("DATA from 196.168.0.1:40000, dport 88, id 1001, "
			"message_length 10000, offset 6000, "
			"data_length 1400, incoming 10000; "
			"DATA from 196.168.0.1:40001, dport 88, id 1001, "
			"message_length 10000, offset 6000, "
			"data_length 1400, incoming 10000",
			unit_log_get());
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(1, same_flow);
	same_flow = NAPI_GRO_CB(skb2)->same_flow;
	EXPECT_EQ(1, same_flow);
}
TEST_F(homa_offload, homa_gro_receive__max_gro_skbs)
{
	struct sk_buff *skb, *skb2, *skb3;
	int same_flow;
	
	homa->max_gro_skbs = 4;
	homa_cores[cpu_number]->merge_list = &self->gro_list;
	self->header.seg.offset = htonl(6000);
	skb = mock_skb_new(self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 0;
	homa_gro_receive(&self->gro_list, skb);
	
	self->header.common.sport = htons(40001);
	skb2 = mock_skb_new(self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 1;
	NAPI_GRO_CB(skb2)->same_flow = 0;
	EXPECT_EQ(NULL, homa_gro_receive(&self->gro_list, skb2));
	
	self->header.common.sport = htons(40002);
	skb3 = mock_skb_new(self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 1;
	NAPI_GRO_CB(skb3)->same_flow = 0;
	EXPECT_NE(NULL, homa_gro_receive(&self->gro_list, skb3));
	
	unit_log_frag_list(list_first_entry(&self->gro_list, struct sk_buff,
			list)->next, 1);
	EXPECT_STREQ("DATA from 196.168.0.1:40000, dport 88, id 1001, "
			"message_length 10000, offset 6000, "
			"data_length 1400, incoming 10000; "
			"DATA from 196.168.0.1:40001, dport 88, id 1001, "
			"message_length 10000, offset 6000, "
			"data_length 1400, incoming 10000; "
			"DATA from 196.168.0.1:40002, dport 88, id 1001, "
			"message_length 10000, offset 6000, "
			"data_length 1400, incoming 10000",
			unit_log_get());
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(1, same_flow);
	same_flow = NAPI_GRO_CB(skb2)->same_flow;
	EXPECT_EQ(1, same_flow);
	same_flow = NAPI_GRO_CB(skb3)->same_flow;
	EXPECT_EQ(1, same_flow);
}

TEST_F(homa_offload, homa_gro_complete__GRO_IDLE)
{
	struct sk_buff *skb = list_first_entry(&self->gro_list,
			struct sk_buff, list);
	homa->gro_policy = HOMA_GRO_IDLE;
	homa_cores[6]->last_active = 30;
	homa_cores[7]->last_active = 25;
	homa_cores[0]->last_active = 20;
	homa_cores[1]->last_active = 15;
	homa_cores[2]->last_active = 10;
	
	cpu_number = 5;
	homa_gro_complete(skb, 0);
	EXPECT_EQ(1, skb->hash - 32);
	
	homa_cores[6]->last_active = 5;
	cpu_number = 5;
	homa_gro_complete(skb, 0);
	EXPECT_EQ(6, skb->hash - 32);
	
	cpu_number = 6;
	homa_gro_complete(skb, 0);
	EXPECT_EQ(2, skb->hash - 32);
}
