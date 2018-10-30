#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

FIXTURE(homa_outgoing) {
	__be32 client_ip;
	int client_port;
	__be32 server_ip;
	int server_port;
	__u64 rpcid;
	struct homa homa;
	struct homa_sock hsk;
	struct sockaddr_in server_addr;
};
FIXTURE_SETUP(homa_outgoing)
{
	self->client_ip = unit_get_in_addr("196.168.0.1");
	self->client_port = 40000;
	self->server_ip = unit_get_in_addr("1.2.3.4");
	self->server_port = 99;
	self->rpcid = 12345;
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, &self->homa, self->client_port,
			self->server_port);
	self->server_addr.sin_family = AF_INET;
	self->server_addr.sin_addr.s_addr = self->server_ip;
	self->server_addr.sin_port = htons(self->server_port);
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_outgoing)
{
	homa_sock_destroy(&self->hsk);
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_outgoing, homa_message_out_init_basics)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 3000, NULL);
	EXPECT_FALSE(IS_ERR(crpc));
	EXPECT_EQ(1, unit_list_length(&self->hsk.client_rpcs));
	EXPECT_STREQ("csum_and_copy_from_iter_full copied 1400 bytes; "
		"csum_and_copy_from_iter_full copied 1400 bytes; "
		"csum_and_copy_from_iter_full copied 200 bytes", unit_log_get());
	unit_log_clear();
	unit_log_message_out_packets(&crpc->msgout, 1);
	EXPECT_STREQ("DATA from 0.0.0.0:40000, dport 99, id 1, length 1428, "
			"message_length 3000, offset 0, unscheduled 10000; "
		     "DATA from 0.0.0.0:40000, dport 99, id 1, length 1428, "
			"message_length 3000, offset 1400, unscheduled 10000; "
		     "DATA from 0.0.0.0:40000, dport 99, id 1, length 228, "
			"message_length 3000, offset 2800, unscheduled 10000",
		     unit_log_get());
}

TEST_F(homa_outgoing, homa_message_out_init__message_too_long)
{
	mock_alloc_skb_errors = 2;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 2000000, NULL);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(EINVAL, -PTR_ERR(crpc));
	EXPECT_EQ(0, unit_list_length(&self->hsk.client_rpcs));
}

TEST_F(homa_outgoing, homa_message_out_init__cant_alloc_skb)
{
	mock_alloc_skb_errors = 2;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 3000, NULL);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(ENOMEM, -PTR_ERR(crpc));
	EXPECT_EQ(0, unit_list_length(&self->hsk.client_rpcs));
}

TEST_F(homa_outgoing, homa_message_out_init__cant_copy_data)
{
	mock_copy_data_errors = 2;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 3000, NULL);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(EFAULT, -PTR_ERR(crpc));
	EXPECT_EQ(0, unit_list_length(&self->hsk.client_rpcs));
}

TEST_F(homa_outgoing, homa_set_priority)
{
	struct sk_buff *skb = alloc_skb(HOMA_SKB_SIZE, GFP_KERNEL);
	homa_set_priority(skb, 0);
	EXPECT_EQ(1, (skb->vlan_tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT);
	
	homa_set_priority(skb, 1);
	EXPECT_EQ(0, (skb->vlan_tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT);
	
	homa_set_priority(skb, 7);
	EXPECT_EQ(7, (skb->vlan_tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT);
	kfree_skb(skb);
}

TEST_F(homa_outgoing, homa_xmit_control__cant_alloc_skb)
{
	struct homa_rpc *srpc;
	struct grant_header h;
	
	srpc = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	EXPECT_NE(NULL, srpc);
	
	h.offset = htonl(12345);
	h.priority = 4;
	mock_xmit_log_verbose = 1;
	mock_alloc_skb_errors = 1;
	EXPECT_EQ(ENOBUFS, -homa_xmit_control(GRANT, &h, sizeof(h), srpc));
	EXPECT_STREQ("", unit_log_get());
}

TEST_F(homa_outgoing, homa_xmit_control__server_request)
{
	struct homa_rpc *srpc;
	struct grant_header h;
	
	srpc = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	EXPECT_NE(NULL, srpc);
	
	h.offset = htonl(12345);
	h.priority = 4;
	mock_xmit_log_verbose = 1;
	EXPECT_EQ(0, homa_xmit_control(GRANT, &h, sizeof(h), srpc));
	EXPECT_STREQ("xmit GRANT from 0.0.0.0:99, dport 40000, id 1111, "
			"length 48 prio 7, offset 12345, grant_prio 4, P7",
			unit_log_get());
}
TEST_F(homa_outgoing, homa_xmit_control__client_response)
{
	struct homa_rpc *crpc;
	struct grant_header h;
	
	crpc = unit_client_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
		self->server_ip, self->server_port, 1111, 100, 10000);
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	
	h.offset = htonl(12345);
	h.priority = 4;
	mock_xmit_log_verbose = 1;
	EXPECT_EQ(0, homa_xmit_control(GRANT, &h, sizeof(h), crpc));
	EXPECT_STREQ("xmit GRANT from 0.0.0.0:40000, dport 99, id 1111, "
			"length 48 prio 7, offset 12345, grant_prio 4, P7",
			unit_log_get());
}
TEST_F(homa_outgoing, homa_xmit_control__ip_queue_xmit_error)
{
	struct homa_rpc *srpc;
	struct grant_header h;
	
	srpc = unit_server_rpc(&self->hsk, RPC_INCOMING, self->client_ip,
		self->server_ip, self->client_port, 1111, 10000, 10000);
	EXPECT_NE(NULL, srpc);
	
	h.offset = htonl(12345);
	h.priority = 4;
	mock_xmit_log_verbose = 1;
	mock_ip_queue_xmit_errors = 1;
	EXPECT_EQ(ENETDOWN, -homa_xmit_control(GRANT, &h, sizeof(h), srpc));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(1, homa_metrics[1]->control_xmit_errors);
}

TEST_F(homa_outgoing, homa_xmit_data__basics)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 6000, NULL);
	EXPECT_FALSE(IS_ERR(crpc));
	crpc->msgout.sched_priority = 2;
	crpc->msgout.unscheduled = 2000;
	crpc->msgout.granted = 5000;
	homa_peer_set_cutoffs(crpc->peer, INT_MAX, 0, 0, 0, 0, INT_MAX,
			7000, 0);
	unit_log_clear();
	homa_xmit_data(&crpc->msgout, (struct sock *) &self->hsk, crpc->peer);
	EXPECT_STREQ("xmit DATA 0/6000, P6; "
		"xmit DATA 1400/6000, P6; "
		"xmit DATA 2800/6000, P2; "
		"xmit DATA 4200/6000, P2", unit_log_get());
}
TEST_F(homa_outgoing, homa_xmit_data__transmit_error)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, 1000, NULL);
	EXPECT_FALSE(IS_ERR(crpc));
	unit_log_clear();
	mock_ip_queue_xmit_errors = 1;
	homa_xmit_data(&crpc->msgout, (struct sock *) &self->hsk, crpc->peer);
	EXPECT_EQ(1, homa_metrics[1]->data_xmit_errors);
}