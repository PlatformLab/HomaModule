#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#define n(x) htons(x)
#define N(x) htonl(x)

FIXTURE(homa_input) {
	struct homa homa;
	struct homa_sock hsk;
	__be32 client_ip;
	__be32 server_ip;
	struct sockaddr_in server_addr;
	struct data_header data;
	struct homa_message_in message;
	struct homa_client_rpc *crpc;
	struct homa_server_rpc *srpc;
	int starting_skb_count;
};
FIXTURE_SETUP(homa_input)
{
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, &self->homa);
	self->client_ip = unit_get_in_addr("196.168.0.1");
	self->server_ip = unit_get_in_addr("1.2.3.4");
	self->server_addr.sin_family = AF_INET;
	self->server_addr.sin_addr.s_addr = self->server_ip;
	self->server_addr.sin_port = htons(99);
	self->data = (struct data_header){.common = {.sport = n(5),
	                .dport = n(99), .id = 12345, .type = DATA},
		        .message_length = N(10000), .offset = 0,
			.unscheduled = N(10000), .retransmit = 0};
	homa_message_in_init(&self->message, 10000, 10000);
	self->crpc = homa_client_rpc_new(&self->hsk, &self->server_addr,
			1000, NULL);
	if (IS_ERR(self->crpc))
		FAIL("homa_client_rpc_new failed with errno %lu",
				-PTR_ERR(self->crpc));
	self->srpc = homa_server_rpc_new(&self->hsk, self->client_ip,
			&self->data);
	if (IS_ERR(self->srpc))
		FAIL("homa_server_rpc_new failed with code %lu",
				-PTR_ERR(self->srpc));
	self->starting_skb_count = mock_skb_count();
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_input)
{
	homa_message_in_destroy(&self->message);
	mock_sock_destroy(&self->hsk, &self->homa.port_map);
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_input, homa_add_packet__basics)
{
	self->data.offset = N(1400);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	
	self->data.offset = N(4200);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 800, 4200));
	
	self->data.offset = 0;
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 0/10000; DATA 1400/10000; DATA 4200/10000",
			unit_log_get());
	EXPECT_EQ(5800, self->message.bytes_remaining);
	
	unit_log_clear();
	self->data.offset = N(2800);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 2800));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 0/10000; DATA 1400/10000; DATA 2800/10000; "
			"DATA 4200/10000", unit_log_get());
}

TEST_F(homa_input, homa_add_packet__redundant_packet)
{
	self->data.offset = N(1400);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 1400/10000", unit_log_get());
}

TEST_F(homa_input, homa_add_packet__overlapping_ranges)
{
	self->data.offset = N(1400);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	self->data.offset = N(2000);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 2000));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 1400/10000; DATA 2000/10000", unit_log_get());
	EXPECT_EQ(8000, self->message.bytes_remaining);
	
	unit_log_clear();
	self->data.offset = N(1800);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1800));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 1400/10000; DATA 2000/10000", unit_log_get());
	EXPECT_EQ(8000, self->message.bytes_remaining);
}

TEST_F(homa_input, homa_data_from_client__basics)
{
	struct homa_server_rpc *srpc;
	self->data.common.id = 55;
	homa_data_from_client(&self->homa, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0), &self->hsk, NULL);
	EXPECT_EQ(2, unit_list_length(&self->hsk.server_rpcs));
	srpc = list_first_entry(&self->hsk.server_rpcs,
			struct homa_server_rpc, server_rpc_links);
	unit_log_skb_list(&srpc->request.packets, 0);
	EXPECT_STREQ("DATA 0/10000", unit_log_get());
	
	unit_log_clear();
	self->data.offset = N(1400);
	homa_data_from_client(&self->homa, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0), &self->hsk, srpc);
	unit_log_skb_list(&srpc->request.packets, 0);
	EXPECT_STREQ("DATA 0/10000; DATA 1400/10000", unit_log_get());
}

TEST_F(homa_input, homa_data_from_client__cant_create_rpc)
{
	mock_malloc_errors = 1;
	self->data.common.id = 55;
	homa_data_from_client(&self->homa, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0), &self->hsk, NULL);
	EXPECT_EQ(1, unit_list_length(&self->hsk.server_rpcs));
	EXPECT_EQ(self->starting_skb_count, mock_skb_count());
}

TEST_F(homa_input, homa_data_from_client__wrong_rpc_state)
{
	self->srpc->state = SRPC_IN_SERVICE;
	homa_data_from_client(&self->homa, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0), &self->hsk, self->srpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.server_rpcs));
	EXPECT_EQ(self->starting_skb_count, mock_skb_count());
}

TEST_F(homa_input, homa_data_from_client__message_complete)
{
	struct homa_server_rpc *srpc;
	self->data.message_length = N(2500);
	self->data.common.id = 55;
	homa_data_from_client(&self->homa, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 0), &self->hsk, NULL);
	EXPECT_EQ(2, unit_list_length(&self->hsk.server_rpcs));
	srpc = list_first_entry(&self->hsk.server_rpcs,
			struct homa_server_rpc, server_rpc_links);
	EXPECT_EQ(0, unit_list_length(&self->hsk.ready_server_rpcs));
	EXPECT_EQ(SRPC_INCOMING, srpc->state);
	EXPECT_STREQ("", unit_log_get());
	
	self->data.offset = N(1400);
	homa_data_from_client(&self->homa, mock_skb_new(self->client_ip,
			&self->data.common, 1100, 1400), &self->hsk, srpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_server_rpcs));
	EXPECT_EQ(SRPC_READY, srpc->state);
	EXPECT_STREQ("sk->sk_data_ready invoked", unit_log_get());
}

TEST_F(homa_input, homa_data_from_server__basics)
{
	EXPECT_EQ(CRPC_WAITING, self->crpc->state);
	self->data.common.id = self->crpc->id;
	self->data.message_length = N(1600);
	homa_data_from_server(&self->homa, mock_skb_new(self->server_ip,
			&self->data.common, 1400, 0), &self->hsk, self->crpc);
	EXPECT_EQ(CRPC_INCOMING, self->crpc->state);
	EXPECT_EQ(0, unit_list_length(&self->hsk.ready_client_rpcs));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(200, self->crpc->response.bytes_remaining);
	
	unit_log_clear();
	self->data.offset = N(1400);
	homa_data_from_server(&self->homa, mock_skb_new(self->server_ip,
			&self->data.common, 200, 1400), &self->hsk, self->crpc);
	EXPECT_EQ(CRPC_READY, self->crpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_client_rpcs));
	EXPECT_EQ(0, self->crpc->response.bytes_remaining);
	EXPECT_STREQ("sk->sk_data_ready invoked", unit_log_get());
}

TEST_F(homa_input, homa_data_from_server__wrong_rpc_state)
{
	self->data.common.id = self->crpc->id;
	self->data.message_length = N(2000);
	homa_data_from_server(&self->homa, mock_skb_new(self->server_ip,
			&self->data.common, 1400, 0), &self->hsk, self->crpc);
	
	self->crpc->state = CRPC_READY;
	self->data.offset = N(1400);
	homa_data_from_server(&self->homa, mock_skb_new(self->server_ip,
			&self->data.common, 600, 1400), &self->hsk, self->crpc);
	EXPECT_EQ(600, self->crpc->response.bytes_remaining);
	EXPECT_EQ(self->starting_skb_count+1, mock_skb_count());
	self->crpc->state = CRPC_INCOMING;
}

TEST_F(homa_input, homa_message_in_copy_data)
{
	int count;
	self->data.common.id = self->crpc->id;
	self->data.message_length = N(4000);
	homa_data_from_server(&self->homa, mock_skb_new(self->server_ip,
			&self->data.common, 1400, 0), &self->hsk, self->crpc);
	self->data.offset = N(1000);
	homa_data_from_server(&self->homa, mock_skb_new(self->server_ip,
			&self->data.common, 1400, 101000), &self->hsk,
			self->crpc);
	self->data.offset = N(1800);
	homa_data_from_server(&self->homa, mock_skb_new(self->server_ip,
			&self->data.common, 1400, 201800), &self->hsk,
			self->crpc);
	self->data.offset = N(3200);
	homa_data_from_server(&self->homa, mock_skb_new(self->server_ip,
			&self->data.common, 800, 303200), &self->hsk,
			self->crpc);
	unit_log_clear();
	count = homa_message_in_copy_data(&self->crpc->response, NULL,
			5000);
	EXPECT_STREQ("skb_copy_datagram_iter 0-1399; "
		"skb_copy_datagram_iter 101400-102399; "
		"skb_copy_datagram_iter 202400-203199; "
		"skb_copy_datagram_iter 303200-303999", unit_log_get());
	EXPECT_EQ(4000, count);
	
	unit_log_clear();
	count = homa_message_in_copy_data(&self->crpc->response, NULL, 200);
	EXPECT_STREQ("skb_copy_datagram_iter 0-199", unit_log_get());
	EXPECT_EQ(200, count);
}