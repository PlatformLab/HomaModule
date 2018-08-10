#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#define n(x) htons(x)
#define N(x) htonl(x)

FIXTURE(homa_utils) {
	struct homa homa;
	struct homa_sock hsk;
	__be32 client_ip;
	__be32 server_ip;
	struct sockaddr_in server_addr;
	struct data_header data;
	struct homa_client_rpc *crpc;
};
FIXTURE_SETUP(homa_utils)
{
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, &self->homa, 0, 0);
	self->client_ip = unit_get_in_addr("196.168.0.1");
	self->server_ip = unit_get_in_addr("1.2.3.4");
	self->server_addr.sin_family = AF_INET;
	self->server_addr.sin_addr.s_addr = self->server_ip;
	self->server_addr.sin_port = htons(99);
	self->data = (struct data_header){.common = {.sport = n(5),
	                .dport = n(99), .id = 12345, .type = DATA},
		        .message_length = N(10000), .offset = 0,
			.unscheduled = N(10000), .retransmit = 0};
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_utils)
{
	mock_sock_destroy(&self->hsk, &self->homa.port_map);
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_utils, homa_addr_init__normal)
{
	struct homa_addr addr;
	EXPECT_EQ(0, -homa_addr_init(&addr,
			(struct sock *) &self->hsk, self->client_ip, 40000,
			self->server_ip, 100));
	homa_addr_destroy(&addr);
}
TEST_F(homa_utils, homa_addr_init__error)
{
	struct homa_addr addr;
	mock_route_errors = 1;
	EXPECT_EQ(EHOSTUNREACH, -homa_addr_init(&addr,
			(struct sock *) &self->hsk, self->client_ip, 40000,
			self->server_ip, 100));
	homa_addr_destroy(&addr);
}

TEST_F(homa_utils, homa_client_rpc_free__state_incoming)
{
	struct homa_client_rpc *crpc = homa_client_rpc_new(&self->hsk,
			&self->server_addr, 1000, NULL);
	EXPECT_FALSE(IS_ERR(crpc));
	EXPECT_EQ(CRPC_WAITING, crpc->state);
	self->data.common.id = crpc->id;
	self->data.message_length = N(1600);
	homa_data_from_server(mock_skb_new(self->server_ip, &self->data.common,
			1400, 0), crpc);
	EXPECT_EQ(CRPC_INCOMING, crpc->state);
	homa_client_rpc_free(crpc);
}
TEST_F(homa_utils, homa_client_rpc_free__state_ready)
{
	struct homa_client_rpc *crpc = homa_client_rpc_new(&self->hsk,
			&self->server_addr, 1000, NULL);
	EXPECT_FALSE(IS_ERR(crpc));
	EXPECT_EQ(CRPC_WAITING, crpc->state);
	self->data.common.id = crpc->id;
	self->data.message_length = N(100);
	homa_data_from_server(mock_skb_new(self->server_ip, &self->data.common,
			100, 0), crpc);
	EXPECT_EQ(CRPC_READY, crpc->state);
	homa_client_rpc_free(crpc);
}

TEST_F(homa_utils, homa_client_rpc_new__normal)
{
	struct homa_client_rpc *crpc = homa_client_rpc_new(&self->hsk,
			&self->server_addr, 10000, NULL);
	EXPECT_FALSE(IS_ERR(crpc));
	homa_client_rpc_free(crpc);
}
TEST_F(homa_utils, homa_client_rpc_new__malloc_error)
{
	mock_malloc_errors = 1;
	struct homa_client_rpc *crpc = homa_client_rpc_new(&self->hsk,
			&self->server_addr, 10000, NULL);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(ENOMEM, -PTR_ERR(crpc));
}
TEST_F(homa_utils, homa_client_rpc_new__route_error)
{
	mock_route_errors = 1;
	struct homa_client_rpc *crpc = homa_client_rpc_new(&self->hsk,
			&self->server_addr, 10000, NULL);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(EHOSTUNREACH, -PTR_ERR(crpc));
}

TEST_F(homa_utils, homa_find_client_rpc)
{
	struct homa_client_rpc *crpc1 = homa_client_rpc_new(&self->hsk,
			&self->server_addr, 1000, NULL);
	EXPECT_FALSE(IS_ERR(crpc1));
	struct homa_client_rpc *crpc2 = homa_client_rpc_new(&self->hsk,
			&self->server_addr, 1000, NULL);
	EXPECT_FALSE(IS_ERR(crpc2));
	EXPECT_EQ(crpc1, homa_find_client_rpc(&self->hsk,
			self->hsk.client_port, crpc1->id));
	EXPECT_EQ(crpc2, homa_find_client_rpc(&self->hsk,
			self->hsk.client_port, crpc2->id));
	EXPECT_EQ(NULL, homa_find_client_rpc(&self->hsk,
			self->hsk.client_port, crpc2->id+1));
	homa_client_rpc_free(crpc1);
	homa_client_rpc_free(crpc2);
}

TEST_F(homa_utils, homa_print_ipv4_addr)
{
	char buffer[100];
	__be32 addr = unit_get_in_addr("192.168.0.1");
	homa_print_ipv4_addr(addr, buffer);
	EXPECT_STREQ("192.168.0.1", buffer);
	
	addr = htonl((1<<24) + (2<<16) + (3<<8) + 4);
	homa_print_ipv4_addr(addr, buffer);
	EXPECT_STREQ("1.2.3.4", buffer);
}

TEST_F(homa_utils, homa_server_rpc_free__state_response)
{
	struct homa_server_rpc *srpc = homa_server_rpc_new(&self->hsk,
			self->client_ip, &self->data);
	EXPECT_FALSE(IS_ERR(srpc));
	srpc->state = SRPC_RESPONSE;
	homa_message_out_init(&srpc->response, (struct sock *)&self->hsk,
			NULL, 10000, &srpc->client, self->hsk.client_port,
			srpc->id);
	homa_server_rpc_free(srpc);
	EXPECT_EQ(0, unit_list_length(&self->hsk.server_rpcs));
}
TEST_F(homa_utils, homa_server_rpc_free__state_ready)
{
	self->data.message_length = N(100);
	struct homa_server_rpc *srpc = homa_server_rpc_new(&self->hsk,
			self->client_ip, &self->data);
	EXPECT_FALSE(IS_ERR(srpc));
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			100, 0), srpc, &self->hsk);
	EXPECT_EQ(SRPC_READY, srpc->state);
	homa_server_rpc_free(srpc);
	EXPECT_EQ(0, unit_list_length(&self->hsk.server_rpcs));
}

TEST_F(homa_utils, homa_server_rpc_new__normal)
{
	struct homa_server_rpc *srpc = homa_server_rpc_new(&self->hsk,
			self->client_ip, &self->data);
	EXPECT_FALSE(IS_ERR(srpc));
	self->data.message_length = N(1600);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), srpc, &self->hsk);
	EXPECT_EQ(SRPC_INCOMING, srpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.server_rpcs));
	homa_server_rpc_free(srpc);
}
TEST_F(homa_utils, homa_server_rpc_new__malloc_error)
{
	mock_malloc_errors = 1;
	struct homa_server_rpc *srpc = homa_server_rpc_new(&self->hsk,
			self->client_ip, &self->data);
	EXPECT_TRUE(IS_ERR(srpc));
	EXPECT_EQ(ENOMEM, -PTR_ERR(srpc));
}
TEST_F(homa_utils, homa_server_rpc_new__addr_error)
{
	mock_route_errors = 1;
	struct homa_server_rpc *srpc = homa_server_rpc_new(&self->hsk,
			self->client_ip, &self->data);
	EXPECT_TRUE(IS_ERR(srpc));
	EXPECT_EQ(EHOSTUNREACH, -PTR_ERR(srpc));
}