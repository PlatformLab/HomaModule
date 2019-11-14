/* Copyright (c) 2019, Stanford University
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
	__be32 ip;
	struct data_header header;
	struct sk_buff *gro_list;
};
FIXTURE_SETUP(homa_offload)
{
	struct sk_buff *skb, *skb2;
	self->ip = unit_get_in_addr("196.168.0.1");
	self->header = (struct data_header){.common = {
			.sport = htons(40000), .dport = htons(99),
			.type = DATA, .id = 1000},
			.message_length = htonl(10000),
			.incoming = htonl(10000), .cutoff_version = 0,
			.retransmit = 0,
			.seg = {.offset = htonl(2000),
			.segment_length = htonl(1400)}};
	skb = mock_skb_new(self->ip, &self->header.common, 3000,
			self->header.seg.offset);
	NAPI_GRO_CB(skb)->same_flow = 1;
	NAPI_GRO_CB(skb)->data_offset = sizeof32(struct data_header);
	NAPI_GRO_CB(skb)->last = skb;
        self->header.seg.offset = htonl(4000);
        self->header.common.dport = htons(88);
        self->header.common.id = 1001;
	skb2 = mock_skb_new(self->ip, &self->header.common, 2000, 0);
	NAPI_GRO_CB(skb2)->same_flow = 1;
	NAPI_GRO_CB(skb2)->data_offset = sizeof32(struct data_header);
	NAPI_GRO_CB(skb2)->last = skb2;
	self->gro_list = skb;
	skb->next = skb2;
	skb2->next = NULL;
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_offload)
{
	while (self->gro_list) {
		struct sk_buff *next = self->gro_list->next;
		kfree_skb(self->gro_list);
		self->gro_list = next;
	}
	unit_teardown();
}

TEST_F(homa_offload, homa_gro_receive__header_too_short)
{
	struct sk_buff *skb;
	int flush;
	self->header.common.type = 0;
	skb = mock_skb_new(self->ip, &self->header.common, 0, 0);
	skb->len -= 2;
	homa_gro_receive(&self->gro_list, skb);
	EXPECT_STREQ("no header", unit_log_get());
	flush = NAPI_GRO_CB(skb)->flush;
	EXPECT_EQ(1, flush);
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_gro_receive__dport_doesnt_match)
{
	struct sk_buff *skb;
	int same_flow;
	self->header.seg.offset = htonl(6000);
	self->header.common.dport += 1;
	skb = mock_skb_new(self->ip, &self->header.common, 1400, 0);
	homa_gro_receive(&self->gro_list, skb);
	NAPI_GRO_CB(skb)->same_flow = 0;
	EXPECT_STREQ("", unit_log_get());
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(0, same_flow);
	kfree_skb(skb);
}
TEST_F(homa_offload, homa_gro_receive__append)
{
	struct sk_buff *skb, *skb2;
	int same_flow;
	self->header.seg.offset = htonl(6000);
	skb = mock_skb_new(self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 0;
	homa_gro_receive(&self->gro_list, skb);
	
	self->header.common.sport = htons(40001);
	skb2 = mock_skb_new(self->ip, &self->header.common, 1400, 0);
	NAPI_GRO_CB(skb)->same_flow = 1;
	homa_gro_receive(&self->gro_list, skb2);
	
	unit_log_frag_list(self->gro_list->next, 1);
	EXPECT_STREQ("DATA from 196.168.0.1:40000, dport 88, id 1001, "
			"message_length 10000, offset 6000, data_length 1400, "
			"incoming 10000, cutoff_version 0; "
			"DATA from 196.168.0.1:40001, dport 88, id 1001, "
			"message_length 10000, offset 6000, data_length 1400, "
			"incoming 10000, cutoff_version 0", unit_log_get());
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(1, same_flow);
	same_flow = NAPI_GRO_CB(skb2)->same_flow;
	EXPECT_EQ(1, same_flow);
}
TEST_F(homa_offload, homa_gro_receive__max_gro_skbs)
{
	struct sk_buff *skb, *skb2, *skb3;
	int same_flow;
	
	homa->max_gro_skbs = 3;
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
	
	unit_log_frag_list(self->gro_list->next, 1);
	EXPECT_STREQ("DATA from 196.168.0.1:40000, dport 88, id 1001, "
			"message_length 10000, offset 6000, data_length 1400, "
			"incoming 10000, cutoff_version 0; "
			"DATA from 196.168.0.1:40001, dport 88, id 1001, "
			"message_length 10000, offset 6000, data_length 1400, "
			"incoming 10000, cutoff_version 0; "
			"DATA from 196.168.0.1:40002, dport 88, id 1001, "
			"message_length 10000, offset 6000, data_length 1400, "
			"incoming 10000, cutoff_version 0", unit_log_get());
	same_flow = NAPI_GRO_CB(skb)->same_flow;
	EXPECT_EQ(1, same_flow);
	same_flow = NAPI_GRO_CB(skb2)->same_flow;
	EXPECT_EQ(1, same_flow);
	same_flow = NAPI_GRO_CB(skb3)->same_flow;
	EXPECT_EQ(1, same_flow);
}
