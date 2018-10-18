#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#define n(x) htons(x)
#define N(x) htonl(x)

FIXTURE(homa_utils) {
	__be32 client_ip;
	int client_port;
	__be32 server_ip;
	int server_port;
	__u64 rpcid;
	struct homa homa;
	struct homa_sock hsk;
	struct sockaddr_in server_addr;
	struct data_header data;
	struct homa_rpc *crpc;
};
FIXTURE_SETUP(homa_utils)
{
	self->client_ip = unit_get_in_addr("196.168.0.1");
	self->client_port = 40000;
	self->server_ip = unit_get_in_addr("1.2.3.4");
	self->server_port = 99;
	self->rpcid = 12345;
	self->server_addr.sin_family = AF_INET;
	self->server_addr.sin_addr.s_addr = self->server_ip;
	self->server_addr.sin_port =  htons(self->server_port);
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, &self->homa, 0, 0);
	self->data = (struct data_header){.common = {
			.sport = htons(self->client_port),
	                .dport = htons(self->server_port), .id = self->rpcid,
			.type = DATA}, .message_length = htonl(10000), .offset = 0,
			.unscheduled = htonl(10000), .retransmit = 0};
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

TEST_F(homa_utils, homa_rpc_new_client__normal)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 10000, NULL);
	EXPECT_FALSE(IS_ERR(crpc));
	homa_rpc_free(crpc);
}
TEST_F(homa_utils, homa_rpc_new_client__malloc_error)
{
	mock_malloc_errors = 1;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 10000, NULL);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(ENOMEM, -PTR_ERR(crpc));
}
TEST_F(homa_utils, homa_rpc_new_client__route_error)
{
	mock_route_errors = 1;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 10000, NULL);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(EHOSTUNREACH, -PTR_ERR(crpc));
}

TEST_F(homa_utils, homa_rpc_new_server__normal)
{
	struct homa_rpc *srpc = homa_rpc_new_server(&self->hsk,
			self->client_ip, &self->data);
	EXPECT_FALSE(IS_ERR(srpc));
	self->data.message_length = N(1600);
	homa_data_pkt(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), srpc);
	EXPECT_EQ(RPC_INCOMING, srpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.server_rpcs));
	homa_rpc_free(srpc);
}
TEST_F(homa_utils, homa_rpc_new_server__malloc_error)
{
	mock_malloc_errors = 1;
	struct homa_rpc *srpc = homa_rpc_new_server(&self->hsk,
			self->client_ip, &self->data);
	EXPECT_TRUE(IS_ERR(srpc));
	EXPECT_EQ(ENOMEM, -PTR_ERR(srpc));
}
TEST_F(homa_utils, homa_rpc_new_server__addr_error)
{
	mock_route_errors = 1;
	struct homa_rpc *srpc = homa_rpc_new_server(&self->hsk,
			self->client_ip, &self->data);
	EXPECT_TRUE(IS_ERR(srpc));
	EXPECT_EQ(EHOSTUNREACH, -PTR_ERR(srpc));
}

TEST_F(homa_utils, homa_rpc_free__state_incoming)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 1000, 20000);
	EXPECT_EQ(1, unit_list_length(&self->homa.grantable_rpcs));
	EXPECT_NE(NULL, crpc);
	homa_rpc_free(crpc);
	EXPECT_EQ(0, unit_list_length(&self->homa.grantable_rpcs));
}
TEST_F(homa_utils, homa_rpc_free__state_ready)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 1000, 100);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_rpcs));
	homa_rpc_free(crpc);
	EXPECT_EQ(0, unit_list_length(&self->hsk.ready_rpcs));
}

TEST_F(homa_utils, homa_find_client_rpc)
{
	struct homa_rpc *crpc1 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 1000, NULL);
	EXPECT_FALSE(IS_ERR(crpc1));
	struct homa_rpc *crpc2 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 1000, NULL);
	EXPECT_FALSE(IS_ERR(crpc2));
	EXPECT_EQ(crpc1, homa_find_client_rpc(&self->hsk,
			self->hsk.client_port, crpc1->id));
	EXPECT_EQ(crpc2, homa_find_client_rpc(&self->hsk,
			self->hsk.client_port, crpc2->id));
	EXPECT_EQ(NULL, homa_find_client_rpc(&self->hsk,
			self->hsk.client_port, crpc2->id+1));
	homa_rpc_free(crpc1);
	homa_rpc_free(crpc2);
}

TEST_F(homa_utils, homa_find_server_rpc)
{
	struct homa_rpc *srpc1 = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			1, 10000, 100);
	EXPECT_NE(NULL, srpc1);
	struct homa_rpc *srpc2 = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			2, 10000, 100);
	EXPECT_NE(NULL, srpc2);
	struct homa_rpc *srpc3 = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port+1,
			3, 10000, 100);
	EXPECT_NE(NULL, srpc3);
	EXPECT_EQ(srpc1, homa_find_server_rpc(&self->hsk, self->client_ip,
			self->client_port, 1));
	EXPECT_EQ(srpc2, homa_find_server_rpc(&self->hsk, self->client_ip,
			self->client_port, 2));
	EXPECT_EQ(srpc3, homa_find_server_rpc(&self->hsk, self->client_ip,
			self->client_port+1, 3));
	EXPECT_EQ(NULL, homa_find_server_rpc(&self->hsk, self->client_ip,
			self->client_port, 3));
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

TEST_F(homa_utils, homa_append_metric)
{
	self->homa.metrics_length = 0;
	homa_append_metric(&self->homa,  "x: %d, y: %d", 10, 20);
	EXPECT_EQ(12, self->homa.metrics_length);
	EXPECT_STREQ("x: 10, y: 20", self->homa.metrics);
	
	homa_append_metric(&self->homa, ", z: %d", 12345);
	EXPECT_EQ(22, self->homa.metrics_length);
	EXPECT_STREQ("x: 10, y: 20, z: 12345", self->homa.metrics);
	EXPECT_EQ(30, self->homa.metrics_capacity);
	
	homa_append_metric(&self->homa, ", q: %050d", 88);
	EXPECT_EQ(77, self->homa.metrics_length);
	EXPECT_STREQ("x: 10, y: 20, z: 12345, "
			"q: 00000000000000000000000000000000000000000000000088",
			self->homa.metrics);
	EXPECT_EQ(120, self->homa.metrics_capacity);
}