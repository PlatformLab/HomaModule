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
	mock_sock_init(&self->hsk, &self->homa, 0, 0);
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_timer)
{
	homa_destroy(&self->homa);
	unit_teardown();
}
TEST_F(homa_timer, homa_timer__server_rpc__basics)
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
	EXPECT_EQ(2, srpc->silent_ticks);
	EXPECT_STREQ("xmit RESEND 1400-4999@7", unit_log_get());

	/* Send another RESEND. */
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(3, srpc->silent_ticks);
	EXPECT_STREQ("xmit RESEND 1400-4999@7", unit_log_get());
	
	/* Abort RPC. */
	unit_log_clear();
	srpc->silent_ticks = self->homa.abort_ticks - 1;
	homa_timer(&self->homa);
	EXPECT_EQ(0, unit_list_length(&self->hsk.server_rpcs));
	EXPECT_EQ(1, unit_get_metrics()->server_rpc_timeouts);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_timer__server_rpc__rpc_in_service)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_IN_SERVICE,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 5000, 5000);
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(0, srpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
	
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

TEST_F(homa_timer, homa_timer__client_rpc_basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 5000, 200);
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(1, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
	
	/* Don't send RESEND: granted bytes not sent. */
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(0, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
	
	/* Send RESEND: granted bytes now sent. */
	homa_xmit_data(&crpc->msgout, (struct sock *) crpc->hsk, crpc->peer);
	unit_log_clear();
	homa_timer(&self->homa);
	homa_timer(&self->homa);
	EXPECT_EQ(2, crpc->silent_ticks);
	EXPECT_STREQ("xmit RESEND 0-1399@7", unit_log_get());
	
	/* Abort after timeout. */
	unit_log_clear();
	crpc->silent_ticks = self->homa.abort_ticks - 1;
	homa_timer(&self->homa);
	EXPECT_EQ(self->homa.abort_ticks, crpc->silent_ticks);
	EXPECT_STREQ("sk->sk_data_ready invoked", unit_log_get());
	EXPECT_EQ(RPC_READY, crpc->state);
	EXPECT_EQ(ETIMEDOUT, -crpc->error);
}
TEST_F(homa_timer, homa_timer__all_granted_bytes_received)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 100, 5000);
	unit_log_clear();
	crpc->msgout.next_offset = crpc->msgout.length;
	crpc->msgin.granted = 1400;
	homa_timer(&self->homa);
	EXPECT_EQ(1, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
	homa_timer(&self->homa);
	EXPECT_EQ(0, crpc->silent_ticks);
	EXPECT_STREQ("xmit BUSY", unit_log_get());
}
TEST_F(homa_timer, homa_timer__rpc_ready)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 5000, 200);
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(1, crpc->silent_ticks);
	homa_timer(&self->homa);
	EXPECT_EQ(0, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}