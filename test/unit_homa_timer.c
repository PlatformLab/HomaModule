#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

FIXTURE(homa_timer) {
	__be32 client_ip;
	int client_port;
	__be32 server_ip;
	int server_port;
	__u64 rpcid;
	struct sockaddr_in server_addr;
	struct homa homa;
	struct homa_sock hsk;
};
FIXTURE_SETUP(homa_timer)
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
	self->homa.flags |= HOMA_FLAG_DONT_THROTTLE;
	self->homa.timer_ticks = 100;
	mock_sock_init(&self->hsk, &self->homa, 0, 0);
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_timer)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_timer, homa_rpc_timeout__client_rpc)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 200, 10000);
	unit_log_clear();
	homa_rpc_timeout(crpc);
	EXPECT_EQ(1, unit_get_metrics()->client_rpc_timeouts);
	EXPECT_EQ(RPC_READY, crpc->state);
	EXPECT_EQ(-ETIMEDOUT, crpc->error);
}
TEST_F(homa_timer, homa_rpc_timeout__server_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 5000, 5000);
	unit_log_clear();
	homa_rpc_timeout(srpc);
	EXPECT_EQ(1, unit_get_metrics()->server_rpc_timeouts);
}

TEST_F(homa_timer, homa_server_crashed__basics)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 200, 10000);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip+1,
			self->server_port, self->rpcid, 200, 10000);
	struct homa_rpc *crpc3 = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port+1, self->rpcid, 200, 10000);
	struct homa_rpc *crpc4 = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 200, 10000);
	homa_server_crashed(&self->homa, crpc1->peer);
	EXPECT_EQ(3, unit_get_metrics()->client_rpc_timeouts);
	EXPECT_EQ(RPC_READY, crpc1->state);
	EXPECT_EQ(RPC_INCOMING, crpc2->state);
	EXPECT_EQ(RPC_READY, crpc3->state);
	EXPECT_EQ(RPC_READY, crpc4->state);
}
TEST_F(homa_timer, homa_server_crashed__cant_get_lock)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 200, 10000);
	((struct sock *) crpc->hsk)->sk_lock.owned = 1;
	homa_server_crashed(&self->homa, crpc->peer);
	EXPECT_EQ(0, unit_get_metrics()->client_rpc_timeouts);
	EXPECT_EQ(RPC_INCOMING, crpc->state);
	((struct sock *) crpc->hsk)->sk_lock.owned = 0;
}

TEST_F(homa_timer, homa_timer__basics)
{
	self->homa.abort_resends = 2;
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 5000, 5000);
	homa_timer(&self->homa);
	EXPECT_EQ(1, srpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());

	/* Send RESEND. */
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(2, srpc->silent_ticks);
	EXPECT_STREQ("xmit RESEND 1400-4999@7", unit_log_get());

	/* Send another RESEND. */
	unit_log_clear();
	self->homa.timer_ticks = 200;
	homa_timer(&self->homa);
	EXPECT_EQ(3, srpc->silent_ticks);
	EXPECT_STREQ("xmit RESEND 1400-4999@7", unit_log_get());
	
	/* Abort RPC. */
	unit_log_clear();
	self->homa.timer_ticks = 300;
	homa_timer(&self->homa);
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(1, unit_get_metrics()->server_rpc_timeouts);
	EXPECT_STREQ("homa_remove_from_grantable invoked", unit_log_get());
}
TEST_F(homa_timer, homa_timer__cant_get_lock)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 200, 10000);
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(1, crpc->silent_ticks);
	((struct sock *) crpc->hsk)->sk_lock.owned = 1;
	homa_timer(&self->homa);
	EXPECT_EQ(1, crpc->silent_ticks);
	((struct sock *) crpc->hsk)->sk_lock.owned = 0;
}
TEST_F(homa_timer, homa_timer__rpc_ready)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 5000, 200);
	unit_log_clear();
	crpc->silent_ticks = 2;
	homa_timer(&self->homa);
	EXPECT_EQ(0, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_timer__rpc_in_service)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_IN_SERVICE,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 5000, 5000);
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(0, srpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
	
}
TEST_F(homa_timer, homa_timer__client_rpc__granted_bytes_not_sent)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 5000, 200);
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(1, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
	
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(0, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_timer__client_rpc__all_granted_bytes_received)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 100, 5000);
	unit_log_clear();
	crpc->msgin.granted = 1400;
	homa_timer(&self->homa);
	EXPECT_EQ(1, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
	homa_timer(&self->homa);
	EXPECT_EQ(0, crpc->silent_ticks);
	EXPECT_STREQ("xmit BUSY", unit_log_get());
}
TEST_F(homa_timer, homa_timer__client_rpc__all_granted_bytes_received2)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 200, 10000);
	unit_log_clear();
	crpc->msgin.granted = 1000;
	crpc->silent_ticks = 5;
	homa_timer(&self->homa);
	EXPECT_STREQ("xmit BUSY", unit_log_get());
	EXPECT_EQ(0, crpc->silent_ticks);
}
TEST_F(homa_timer, homa_rpc_timeout__client_timeout)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 200, 10000);
	unit_log_clear();
	crpc->silent_ticks = 100;
	crpc->num_resends = self->homa.abort_resends;
	homa_timer(&self->homa);
	EXPECT_EQ(1, unit_get_metrics()->client_rpc_timeouts);
	EXPECT_EQ(RPC_READY, crpc->state);
	EXPECT_EQ(-ETIMEDOUT, crpc->error);
}
TEST_F(homa_timer, homa_timer__server_rpc__all_granted_bytes_received)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 5000, 5000);
	srpc->msgin.granted = 1400;
	homa_timer(&self->homa);
	EXPECT_EQ(1, srpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_timer__server_rpc__all_granted_bytes_received2)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 10000, 100);
	EXPECT_NE(NULL, srpc);
	EXPECT_EQ(8600, srpc->msgin.bytes_remaining);
	srpc->msgin.granted = 1000;
	srpc->silent_ticks = 5;
	homa_timer(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, srpc->silent_ticks);
}
TEST_F(homa_timer, homa_timer__server_rpc__state_not_incoming)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 100, 20000);
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(1, srpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_timer__too_soon_for_resend)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 5000, 5000);
	homa_timer(&self->homa);
	EXPECT_EQ(1, srpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());

	/* Send RESEND. */
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_STREQ("xmit RESEND 1400-4999@7", unit_log_get());

	/* No RESEND: not enough time since last one. */
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	
	/* Send another RESEND. */
	unit_log_clear();
	self->homa.timer_ticks = 200;
	homa_timer(&self->homa);
	EXPECT_STREQ("xmit RESEND 1400-4999@7", unit_log_get());
}
