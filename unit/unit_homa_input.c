#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#define n(x) htons(x)
#define N(x) htonl(x)

FIXTURE(message_in) {
	struct homa homa;
	struct homa_sock hsk;
	struct homa_message_in message;
	struct data_header data ;
	__be32 saddr;
	
};
FIXTURE_SETUP(message_in)
{
	homa_init(&homa);
	homa_message_in_init(&self->message, 10000, 10000);
	self->data = (struct data_header){.common = {.sport = n(5),
	                .dport = n(7), .id = 99, .type = DATA},
		        .message_length = N(5000), .offset = 0,
			.unscheduled = N(10000), .retransmit = 0};
	self->saddr = unit_get_in_addr("196.168.0.1");
}
FIXTURE_TEARDOWN(message_in)
{
	homa_message_in_destroy(&self->message);
	homa_destroy(&homa);
	unit_teardown();
}

TEST_F(message_in, homa_add_packet__basics) {
	self->data.offset = N(1400);
	homa_add_packet(&self->message, mock_skb_new(self->saddr,
			&self->data.common, 1400, 1400));
	
	self->data.offset = N(4200);
	homa_add_packet(&self->message, mock_skb_new(self->saddr,
			&self->data.common, 1400, 4200));
	
	self->data.offset = 0;
	homa_add_packet(&self->message, mock_skb_new(self->saddr,
			&self->data.common, 1400, 0));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 0/5000; DATA 1400/5000; DATA 4200/5000",
			unit_log_get());
	EXPECT_EQ(5800, self->message.bytes_remaining);
	
	unit_log_clear();
	self->data.offset = N(2800);
	homa_add_packet(&self->message, mock_skb_new(self->saddr,
			&self->data.common, 1400, 2800));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 0/5000; DATA 1400/5000; DATA 2800/5000; "
			"DATA 4200/5000", unit_log_get());
}

TEST_F(message_in, homa_add_packet__redundant_packet) {
	self->data.offset = N(1400);
	homa_add_packet(&self->message, mock_skb_new(self->saddr,
			&self->data.common, 1400, 1400));
	homa_add_packet(&self->message, mock_skb_new(self->saddr,
			&self->data.common, 1400, 1400));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 1400/5000", unit_log_get());
}

TEST_F(message_in, homa_add_packet__overlapping_ranges) {
	self->data.offset = N(1400);
	homa_add_packet(&self->message, mock_skb_new(self->saddr,
			&self->data.common, 1400, 1400));
	self->data.offset = N(2000);
	homa_add_packet(&self->message, mock_skb_new(self->saddr,
			&self->data.common, 1400, 2000));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 1400/5000; DATA 2000/5000", unit_log_get());
	EXPECT_EQ(8000, self->message.bytes_remaining);
	
	unit_log_clear();
	self->data.offset = N(1800);
	homa_add_packet(&self->message, mock_skb_new(self->saddr,
			&self->data.common, 1400, 1800));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 1400/5000; DATA 2000/5000", unit_log_get());
	EXPECT_EQ(8000, self->message.bytes_remaining);
}

//TEST_HARNESS_MAIN