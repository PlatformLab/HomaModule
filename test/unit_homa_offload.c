#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

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
			.sport = htons(40000), .dport = htons(99), .id = 1000,
			.type = DATA}, .message_length = htonl(10000),
			.offset = 2000, .unscheduled = htonl(10000),
			.cutoff_version = 0, .retransmit = 0};
	skb = mock_skb_new(self->ip, &self->header.common, 3000,
			self->header.offset);
	NAPI_GRO_CB(skb)->same_flow = 1;
	NAPI_GRO_CB(skb)->data_offset = sizeof32(struct data_header);
        self->header.offset = htonl(4000);
        self->header.common.dport = htons(88);
        self->header.common.id = 1001;
	skb2 = mock_skb_new(self->ip, &self->header.common, 2000, 0);
	NAPI_GRO_CB(skb2)->same_flow = 1;
	NAPI_GRO_CB(skb2)->data_offset = sizeof32(struct data_header);
	self->gro_list = skb;
	skb->next = skb2;
	skb2->next = NULL;
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_offload)
{
	kfree_skb(self->gro_list->next);
	kfree_skb(self->gro_list);
	unit_teardown();
}

TEST_F(homa_offload, homa_gro_receive__header_too_short)
{
	struct sk_buff *skb;
	int flush;
	self->header.common.type = 0;
	skb = mock_skb_new(self->ip, &self->header.common, 0, 0);
	homa_gro_receive(&self->gro_list, skb);
	EXPECT_STREQ("no header", unit_log_get());
	flush = NAPI_GRO_CB(skb)->flush;
	EXPECT_EQ(1, flush);
	kfree_skb(skb);
}

TEST_F(homa_offload, homa_gro_receive__not_data_packet)
{
	struct sk_buff *skb;
	int flush;
	struct grant_header grant = (struct grant_header){.common = {
			.sport = htons(40000), .dport = htons(99),
			.id = 1000, .type = GRANT}, .offset = 4000,
			.priority = 3};
	skb = mock_skb_new(self->ip, &grant.common, 100, 0);
	homa_gro_receive(&self->gro_list, skb);
	EXPECT_STREQ("", unit_log_get());
	flush = NAPI_GRO_CB(skb)->flush;
	EXPECT_EQ(1, flush);
	kfree_skb(skb);
}

TEST_F(homa_offload, homa_gro_receive__sport_doesnt_match)
{
	struct sk_buff *skb;
	int same_flow;
	self->header.offset = htonl(6000);
	self->header.common.sport += 1;
	skb = mock_skb_new(self->ip, &self->header.common, 1500, 0);
	homa_gro_receive(&self->gro_list, skb);
	EXPECT_STREQ("", unit_log_get());
	same_flow = NAPI_GRO_CB(self->gro_list)->same_flow;
	EXPECT_EQ(0, same_flow);
	kfree_skb(skb);
}

TEST_F(homa_offload, homa_gro_receive__dport_doesnt_match)
{
	struct sk_buff *skb;
	self->header.offset = htonl(6000);
	self->header.common.dport += 1;
	skb = mock_skb_new(self->ip, &self->header.common, 1500, 0);
	homa_gro_receive(&self->gro_list, skb);
	EXPECT_STREQ("", unit_log_get());
	kfree_skb(skb);
}

TEST_F(homa_offload, homa_gro_receive__id_doesnt_match)
{
	struct sk_buff *skb;
	self->header.offset = htonl(6000);
	self->header.common.id += 1;
	skb = mock_skb_new(self->ip, &self->header.common, 1500, 0);
	homa_gro_receive(&self->gro_list, skb);
	EXPECT_STREQ("", unit_log_get());
	kfree_skb(skb);
}

TEST_F(homa_offload, homa_gro_receive__data_not_consecutive)
{
	struct sk_buff *skb;
	self->header.offset = htonl(6002);
	skb = mock_skb_new(self->ip, &self->header.common, 1500, 0);
	homa_gro_receive(&self->gro_list, skb);
	EXPECT_STREQ("", unit_log_get());
	kfree_skb(skb);
}

TEST_F(homa_offload, homa_gro_receive__append)
{
	struct sk_buff *skb;
	self->header.offset = htonl(6000);
	skb = mock_skb_new(self->ip, &self->header.common, 1500, 0);
	homa_gro_receive(&self->gro_list, skb);
	EXPECT_STREQ("skb_gro_receive appending id 1001, bytes 6000-7500 to "
			"id 1001, bytes 4000-6000", unit_log_get());
	kfree_skb(skb);
}
