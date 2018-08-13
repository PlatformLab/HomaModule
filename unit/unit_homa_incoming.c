#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

FIXTURE(homa_incoming) {
	__be32 client_ip;
	int client_port;
	__be32 server_ip;
	int server_port;
	__u64 rpcid;
	struct sockaddr_in server_addr;
	struct homa homa;
	struct homa_sock hsk;
	struct data_header data;
	struct homa_message_in message;
};
FIXTURE_SETUP(homa_incoming)
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
	homa_message_in_init(&self->message, 10000, 10000, 1);
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_incoming)
{
	homa_message_in_destroy(&self->message);
	mock_sock_destroy(&self->hsk, &self->homa.port_map);
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_incoming, homa_add_packet__basics)
{
	self->data.offset = htonl(1400);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	
	self->data.offset = htonl(4200);
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
	self->data.offset = htonl(2800);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 2800));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 0/10000; DATA 1400/10000; DATA 2800/10000; "
			"DATA 4200/10000", unit_log_get());
}

TEST_F(homa_incoming, homa_add_packet__redundant_packet)
{
	self->data.offset = htonl(1400);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 1400/10000", unit_log_get());
}

TEST_F(homa_incoming, homa_add_packet__overlapping_ranges)
{
	self->data.offset = htonl(1400);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1400));
	self->data.offset = htonl(2000);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 2000));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 1400/10000; DATA 2000/10000", unit_log_get());
	EXPECT_EQ(8000, self->message.bytes_remaining);
	
	unit_log_clear();
	self->data.offset = htonl(1800);
	homa_add_packet(&self->message, mock_skb_new(self->client_ip,
			&self->data.common, 1400, 1800));
	unit_log_skb_list(&self->message.packets, 0);
	EXPECT_STREQ("DATA 1400/10000; DATA 2000/10000", unit_log_get());
	EXPECT_EQ(8000, self->message.bytes_remaining);
}

TEST_F(homa_incoming, homa_message_in_copy_data)
{
	int count;
	struct homa_client_rpc *crpc = unit_client_rpc(&self->hsk,
			CRPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 1000, 4000);
	EXPECT_NE(NULL, crpc);
	self->data.message_length = htonl(4000);
	self->data.offset = htonl(1000);
	homa_data_from_server(mock_skb_new(self->server_ip, &self->data.common,
			1400, 101000), crpc);
	self->data.offset = htonl(1800);
	homa_data_from_server(mock_skb_new(self->server_ip, &self->data.common,
			1400, 201800), crpc);
	self->data.offset = htonl(3200);
	homa_data_from_server(mock_skb_new(self->server_ip, &self->data.common,
			800, 303200), crpc);
	unit_log_clear();
	count = homa_message_in_copy_data(&crpc->response, NULL,
			5000);
	EXPECT_STREQ("skb_copy_datagram_iter 0-1399; "
		"skb_copy_datagram_iter 101400-102399; "
		"skb_copy_datagram_iter 202400-203199; "
		"skb_copy_datagram_iter 303200-303999", unit_log_get());
	EXPECT_EQ(4000, count);
	
	unit_log_clear();
	count = homa_message_in_copy_data(&crpc->response, NULL, 200);
	EXPECT_STREQ("skb_copy_datagram_iter 0-199", unit_log_get());
	EXPECT_EQ(200, count);
}

TEST_F(homa_incoming, homa_data_from_client__basics)
{
	struct homa_server_rpc *srpc;
	self->data.common.id = 55;
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	EXPECT_EQ(1, unit_list_length(&self->hsk.server_rpcs));
	srpc = list_first_entry(&self->hsk.server_rpcs,
			struct homa_server_rpc, server_rpc_links);
	unit_log_skb_list(&srpc->request.packets, 0);
	EXPECT_STREQ("DATA 0/10000", unit_log_get());
	
	unit_log_clear();
	self->data.offset = htonl(1400);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), srpc, &self->hsk);
	unit_log_skb_list(&srpc->request.packets, 0);
	EXPECT_STREQ("DATA 0/10000; DATA 1400/10000", unit_log_get());
}

TEST_F(homa_incoming, homa_data_from_client__cant_create_rpc)
{
	mock_malloc_errors = 1;
	self->data.common.id = 55;
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	EXPECT_EQ(0, unit_list_length(&self->hsk.server_rpcs));
	EXPECT_EQ(0, mock_skb_count());
}

TEST_F(homa_incoming, homa_data_from_client__wrong_rpc_state)
{
	struct homa_server_rpc *srpc = unit_server_rpc(&self->hsk,
			SRPC_IN_SERVICE, self->client_ip, self->server_ip,
			self->client_port, self->rpcid, 2800, 1000);
	EXPECT_NE(NULL, srpc);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), srpc, &self->hsk);
	EXPECT_EQ(1, unit_list_length(&self->hsk.server_rpcs));
	EXPECT_EQ(2, mock_skb_count());
}

TEST_F(homa_incoming, homa_data_from_client__send_grant)
{
	struct homa_server_rpc *srpc = unit_server_rpc(&self->hsk,
			SRPC_INCOMING, self->client_ip, self->server_ip,
			self->client_port, self->rpcid, 100000, 1000);
	EXPECT_NE(NULL, srpc);
	EXPECT_STREQ("xmit GRANT 11400@0", unit_log_get());
	EXPECT_EQ(11400, srpc->request.granted);
}

TEST_F(homa_incoming, homa_data_from_client__message_complete)
{
	struct homa_server_rpc *srpc = unit_server_rpc(&self->hsk,
			SRPC_INCOMING, self->client_ip, self->server_ip,
			self->client_port, self->rpcid, 2500, 1000);
	EXPECT_NE(NULL, srpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.server_rpcs));
	srpc = list_first_entry(&self->hsk.server_rpcs,
			struct homa_server_rpc, server_rpc_links);
	EXPECT_EQ(0, unit_list_length(&self->hsk.ready_server_rpcs));
	EXPECT_EQ(SRPC_INCOMING, srpc->state);
	EXPECT_STREQ("", unit_log_get());
	
	self->data.offset = htonl(1400);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1100, 1400), srpc, &self->hsk);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_server_rpcs));
	EXPECT_EQ(SRPC_READY, srpc->state);
	EXPECT_STREQ("sk->sk_data_ready invoked", unit_log_get());
}

TEST_F(homa_incoming, homa_data_from_server__basics)
{
	struct homa_client_rpc *crpc = unit_client_rpc(&self->hsk,
			CRPC_WAITING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 1000, 1600);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	self->data.message_length = htonl(1600);
	homa_data_from_server(mock_skb_new(self->server_ip, &self->data.common,
			1400, 0), crpc);
	EXPECT_EQ(CRPC_INCOMING, crpc->state);
	EXPECT_EQ(0, unit_list_length(&self->hsk.ready_client_rpcs));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(200, crpc->response.bytes_remaining);
	
	unit_log_clear();
	self->data.offset = htonl(1400);
	homa_data_from_server(mock_skb_new(self->server_ip, &self->data.common,
			200, 1400), crpc);
	EXPECT_EQ(CRPC_READY, crpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_client_rpcs));
	EXPECT_EQ(0, crpc->response.bytes_remaining);
	EXPECT_STREQ("sk->sk_data_ready invoked", unit_log_get());
}

TEST_F(homa_incoming, homa_data_from_server__wrong_rpc_state)
{
	struct homa_client_rpc *crpc = unit_client_rpc(&self->hsk,
			CRPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 1000, 2000);
	EXPECT_NE(NULL, crpc);
	
	crpc->state = CRPC_READY;
	self->data.message_length = htonl(2000);
	self->data.offset = htonl(1400);
	homa_data_from_server(mock_skb_new(self->server_ip, &self->data.common,
			600, 1400), crpc);
	EXPECT_EQ(600, crpc->response.bytes_remaining);
	crpc->state = CRPC_INCOMING;
}

TEST_F(homa_incoming, homa_data_from_server__send_grant)
{
	struct homa_client_rpc *crpc = unit_client_rpc(&self->hsk,
			CRPC_WAITING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 1000, 100000);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	self->data.message_length = htonl(100000);
	self->data.unscheduled = htonl(5000);
	homa_data_from_server(mock_skb_new(self->server_ip, &self->data.common,
			1400, 0), crpc);
	EXPECT_EQ(CRPC_INCOMING, crpc->state);
	EXPECT_STREQ("xmit GRANT 6400@0", unit_log_get());
	EXPECT_EQ(6400, crpc->response.granted);
}

TEST_F(homa_incoming, homa_grant_from_client)
{
	struct homa_server_rpc *srpc = unit_server_rpc(&self->hsk,
			SRPC_RESPONSE, self->client_ip, self->server_ip,
			self->client_port, self->rpcid, 100, 20000);
	EXPECT_NE(NULL, srpc);
	homa_xmit_packets(&srpc->response, (struct sock *) &self->hsk,
			&srpc->client);
	unit_log_clear();
	
	struct grant_header h = {{.sport = htons(srpc->client.dport),
	                .dport = htons(self->hsk.server_port),
			.id = srpc->id, .type = GRANT},
		        .offset = htonl(11200),
			.priority = 3};
	homa_pkt_dispatch((struct sock *)&self->hsk,
			mock_skb_new(self->client_ip, &h.common, 0, 0));
	EXPECT_EQ(11200, srpc->response.granted);
	EXPECT_STREQ("xmit DATA 9800/20000", unit_log_get());
	
	/* Don't let grant offset go backwards. */
	h.offset = htonl(10000);
	unit_log_clear();
	homa_pkt_dispatch((struct sock *)&self->hsk,
			mock_skb_new(self->client_ip, &h.common, 0, 0));
	EXPECT_EQ(11200, srpc->response.granted);
	EXPECT_STREQ("", unit_log_get());
	
	/* Wrong state. */
	h.offset = htonl(20000);
	srpc->state = SRPC_INCOMING;
	unit_log_clear();
	homa_pkt_dispatch((struct sock *)&self->hsk,
			mock_skb_new(self->client_ip, &h.common, 0, 0));
	EXPECT_EQ(11200, srpc->response.granted);
	EXPECT_STREQ("", unit_log_get());
	
	/* Must restore old state to avoid potential crashes. */
	srpc->state = SRPC_RESPONSE;
}

TEST_F(homa_incoming, homa_grant_from_server)
{
	struct homa_client_rpc *crpc = unit_client_rpc(&self->hsk,
			CRPC_WAITING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 20000, 100);
	EXPECT_NE(NULL, crpc);
	homa_xmit_packets(&crpc->request, (struct sock *) &self->hsk,
			&crpc->dest);
	unit_log_clear();
	
	struct grant_header h = {{.sport = self->server_addr.sin_port,
	                .dport = htons(self->hsk.client_port),
			.id = crpc->id, .type = GRANT},
		        .offset = htonl(11200),
			.priority = 3};
	homa_pkt_dispatch((struct sock *)&self->hsk,
			mock_skb_new(self->server_ip, &h.common, 0, 0));
	EXPECT_EQ(11200, crpc->request.granted);
	EXPECT_STREQ("xmit DATA 9800/20000", unit_log_get());
	
	/* Don't let grant offset go backwards. */
	h.offset = htonl(10000);
	unit_log_clear();
	homa_pkt_dispatch((struct sock *)&self->hsk,
			mock_skb_new(self->server_ip, &h.common, 0, 0));
	EXPECT_EQ(11200, crpc->request.granted);
	EXPECT_STREQ("", unit_log_get());
	
	/* Wrong state. */
	h.offset = htonl(20000);
	crpc->state = CRPC_READY;
	unit_log_clear();
	homa_pkt_dispatch((struct sock *)&self->hsk,
			mock_skb_new(self->server_ip, &h.common, 0, 0));
	EXPECT_EQ(11200, crpc->request.granted);
	EXPECT_STREQ("", unit_log_get());
	
	/* Must restore old state to avoid crash. */
	crpc->state = CRPC_WAITING;
}

TEST_F(homa_incoming, homa_manage_grants__untrack_once_fully_granted)
{
	struct homa_server_rpc *srpc = unit_server_rpc(&self->hsk,
			SRPC_INCOMING, self->client_ip, self->server_ip,
			self->client_port, self->rpcid, 20000, 100);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request 12345, remaining 18600", unit_log_get());
	
	srpc->request.granted = 20000;
	homa_manage_grants(&self-> homa, &srpc->request);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}

TEST_F(homa_incoming, homa_manage_grants__insert_in_order)
{
	self->data.common.id = 1;
	self->data.message_length = htonl(100000);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	self->data.common.id = 2;
	self->data.message_length = htonl(50000);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	self->data.common.id = 3;
	self->data.message_length = htonl(120000);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	self->data.common.id = 4;
	self->data.message_length = htonl(70000);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request 2, remaining 48600; "
			"request 4, remaining 68600; "
			"request 1, remaining 98600; "
			"request 3, remaining 118600", unit_log_get());
}

TEST_F(homa_incoming, homa_manage_grants__adjust_priority_order)
{
	struct homa_server_rpc *srpc;
	self->data.common.id = 1;
	self->data.message_length = htonl(20000);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	self->data.common.id = 2;
	self->data.message_length = htonl(30000);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	self->data.common.id = 3;
	self->data.message_length = htonl(40000);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	self->data.common.id = 4;
	self->data.message_length = htonl(50000);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request 1, remaining 18600; "
			"request 2, remaining 28600; "
			"request 3, remaining 38600; "
			"request 4, remaining 48600", unit_log_get());

	srpc = homa_find_server_rpc(&self->hsk, self->client_ip,
			htons(self->data.common.sport), 3);
	EXPECT_NE(NULL, srpc);
	srpc->request.bytes_remaining = 28600;
	homa_manage_grants(&self-> homa, &srpc->request);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request 1, remaining 18600; "
			"request 2, remaining 28600; "
			"request 3, remaining 28600; "
			"request 4, remaining 48600", unit_log_get());
	
	srpc->request.bytes_remaining = 28599;
	homa_manage_grants(&self-> homa, &srpc->request);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request 1, remaining 18600; "
			"request 3, remaining 28599; "
			"request 2, remaining 28600; "
			"request 4, remaining 48600", unit_log_get());

	srpc = homa_find_server_rpc(&self->hsk, self->client_ip,
			htons(self->data.common.sport), 4);
	EXPECT_NE(NULL, srpc);
	srpc->request.bytes_remaining = 1000;
	homa_manage_grants(&self-> homa, &srpc->request);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request 4, remaining 1000; "
			"request 1, remaining 18600; "
			"request 3, remaining 28599; "
			"request 2, remaining 28600", unit_log_get());
}

TEST_F(homa_incoming, homa_manage_grants__pick_message_to_grant)
{
	struct homa_server_rpc *srpc;
	self->data.common.id = 1;
	self->data.message_length = htonl(20000);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	self->data.common.id = 2;
	self->data.message_length = htonl(30000);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	self->data.common.id = 3;
	self->data.message_length = htonl(40000);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	self->data.common.id = 4;
	self->data.message_length = htonl(50000);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	
	/* No messages need grants. */

	srpc = homa_find_server_rpc(&self->hsk, self->client_ip,
			htons(self->data.common.sport), 3);
	EXPECT_NE(NULL, srpc);
	unit_log_clear();
	homa_manage_grants(&self-> homa, &srpc->request);
	EXPECT_STREQ("", unit_log_get());
	
	/* Messages that need grants are beyond max_overcommitted. */
	self->homa.max_overcommit = 2;
	srpc->request.bytes_remaining -= 1;
	unit_log_clear();
	homa_manage_grants(&self-> homa, &srpc->request);
	EXPECT_STREQ("", unit_log_get());
	
	/* There is a message to grant. */
	self->homa.max_overcommit = 4;
	srpc->request.bytes_remaining -= 1;
	unit_log_clear();
	homa_manage_grants(&self-> homa, &srpc->request);
	EXPECT_STREQ("xmit GRANT 12800@1", unit_log_get());
}

TEST_F(homa_incoming, homa_manage_grants__choose_priority_level)
{
	struct homa_server_rpc *srpc;
	self->data.common.id = 1;
	self->data.message_length = htonl(40000);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	self->data.common.id = 2;
	self->data.message_length = htonl(30000);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	self->data.common.id = 3;
	self->data.message_length = htonl(20000);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	EXPECT_STREQ("xmit GRANT 11400@0; "
			"xmit GRANT 11400@1; "
			"xmit GRANT 11400@2", unit_log_get());

	srpc = homa_find_server_rpc(&self->hsk, self->client_ip,
			htons(self->data.common.sport), 1);
	EXPECT_NE(NULL, srpc);
	
	/* Share lowest priority level. */
	self->homa.min_sched_prio = 2;
	srpc->request.bytes_remaining -= 1400;
	unit_log_clear();
	homa_manage_grants(&self->homa, &srpc->request);
	EXPECT_STREQ("xmit GRANT 12800@2", unit_log_get());
}

TEST_F(homa_incoming, homa_remove_from_grantable)
{
	struct homa_server_rpc *srpc;
	self->data.common.id = 1;
	self->data.message_length = htonl(20000);
	homa_data_from_client(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), NULL, &self->hsk);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("request 1, remaining 18600", unit_log_get());
	srpc = homa_find_server_rpc(&self->hsk, self->client_ip,
			htons(self->data.common.sport), self->data.common.id);
	EXPECT_NE(NULL, srpc);
	
	/* First time: on the list. */
	homa_remove_from_grantable(&self->homa, &srpc->request);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	
	/* Second time: not on the list. */
	homa_remove_from_grantable(&self->homa, &srpc->request);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	
	
}