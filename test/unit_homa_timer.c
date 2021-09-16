/* Copyright (c) 2019-2020 Stanford University
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
	self->homa.resend_ticks = 2;
	self->homa.timer_ticks = 100;
	mock_sock_init(&self->hsk, &self->homa, 0);
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_timer)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_timer, homa_check_timeout__client_rpc__granted_bytes_not_sent)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 5000, 200);
	unit_log_clear();
	crpc->silent_ticks = 10;
	EXPECT_EQ(0, homa_check_timeout(crpc));
	EXPECT_EQ(0, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_check_timeout__all_granted_bytes_received)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 100, 5000);
	unit_log_clear();
	crpc->msgin.incoming = 1400;
	crpc->silent_ticks = 10;
	EXPECT_EQ(0, homa_check_timeout(crpc));
	EXPECT_EQ(0, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_check_timeout__client_rpc__all_granted_bytes_received_no_busy)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 5000, 5000);
	srpc->msgin.incoming = 1400;
	srpc->silent_ticks = 10;
	EXPECT_EQ(0, homa_check_timeout(srpc));
	EXPECT_EQ(0, srpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_check_timeout__resend_ticks_not_reached)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 50000, 200);
	unit_log_clear();
	crpc->msgout.granted = 0;
	crpc->silent_ticks = 1;
	crpc->peer->outstanding_resends = self->homa.timeout_resends + 10;
	EXPECT_EQ(0, homa_check_timeout(crpc));
	EXPECT_EQ(1, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_check_timeout__peer_timeout)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 200, 10000);
	unit_log_clear();
	crpc->silent_ticks = self->homa.resend_ticks;
	crpc->peer->outstanding_resends = self->homa.timeout_resends;
	EXPECT_EQ(1, homa_check_timeout(crpc));
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.peer_timeouts);
	EXPECT_EQ(0, crpc->peer->outstanding_resends);
}
TEST_F(homa_timer, homa_check_timeout__server_rpc__state_not_incoming)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 100, 20000);
	unit_log_clear();
	srpc->silent_ticks = self->homa.resend_ticks;
	srpc->msgout.granted = 0;
	EXPECT_EQ(0, homa_check_timeout(srpc));
	EXPECT_EQ(self->homa.resend_ticks, srpc->silent_ticks);
}
TEST_F(homa_timer, homa_check_timeout__special_case_for_first_grantable)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 50000, 5000);

	/* Don't consider special case unless we already sent one resend
	 * to this peer.
	 */
	unit_log_clear();
	srpc->silent_ticks = self->homa.resend_ticks;
	srpc->peer->most_recent_resend = self->homa.timer_ticks - 1;
	EXPECT_EQ(0, homa_check_timeout(srpc));
	EXPECT_STREQ("", unit_log_get());
	
	/* Try again with the right value for most_recent_resend. */
	unit_log_clear();
	srpc->peer->most_recent_resend = self->homa.timer_ticks;
	EXPECT_EQ(0, homa_check_timeout(srpc));
	EXPECT_STREQ("xmit RESEND 1400-9999@7", unit_log_get());
}
TEST_F(homa_timer, homa_check_timeout__too_soon_for_another_resend)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 5000, 5000);

	/* Send RESEND. */
	unit_log_clear();
	srpc->silent_ticks = self->homa.resend_ticks;
	srpc->peer->most_recent_resend = self->homa.timer_ticks
			- self->homa.resend_interval + 1;
	EXPECT_EQ(0, homa_check_timeout(srpc));
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_check_timeout__send_resend)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 5000, 5000);

	/* Send RESEND. */
	unit_log_clear();
	srpc->silent_ticks = self->homa.resend_ticks;
	EXPECT_EQ(0, srpc->peer->most_recent_resend);
	EXPECT_EQ(0, homa_check_timeout(srpc));
	EXPECT_STREQ("xmit RESEND 1400-4999@7", unit_log_get());
	EXPECT_EQ(100, srpc->peer->most_recent_resend);
	EXPECT_EQ(1, srpc->peer->outstanding_resends);
}

TEST_F(homa_timer, homa_timer__basics)
{
	self->homa.timeout_resends = 2;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 200, 5000);
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(1, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());

	/* Send RESEND. */
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(2, crpc->silent_ticks);
	EXPECT_STREQ("xmit RESEND 1400-4999@7", unit_log_get());

	/* Don't send another RESEND (resend_interval not reached). */
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(3, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
	
	/* Timeout the peer. */
	unit_log_clear();
	crpc->peer->outstanding_resends = self->homa.timeout_resends;
	homa_timer(&self->homa);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_responses));
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.peer_timeouts);
	EXPECT_EQ(RPC_READY, crpc->state);
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
TEST_F(homa_timer, homa_timer__abort_server_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->rpcid, 5000, 5000);
	unit_log_clear();
	srpc->silent_ticks = self->homa.resend_ticks-1;
	srpc->peer->outstanding_resends = self->homa.timeout_resends;
	srpc->msgout.granted = 0;
	homa_timer(&self->homa);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.server_rpc_discards);
	EXPECT_EQ(1, unit_list_length(&self->hsk.dead_rpcs));
	EXPECT_STREQ("homa_remove_from_grantable invoked", unit_log_get());
}
TEST_F(homa_timer, homa_timer__update_forced_reap_count)
{
	homa_cores[0]->metrics.requests_received = 1000;
	homa_cores[1]->metrics.requests_received = 500;
	homa_cores[2]->metrics.responses_received = 800;
	homa_cores[1]->metrics.packets_sent[0] = 5000;
	homa_cores[3]->metrics.packets_sent[0] = 2000;
	homa_cores[1]->metrics.packets_received[0] = 1000;
	homa_cores[2]->metrics.packets_received[0] = 6000;
	homa_cores[3]->metrics.packets_received[0] = 4000;
	self->homa.last_rpcs = 1290;
	self->homa.last_sent = 1000;
	self->homa.last_received = 2000;
	self->homa.timer_ticks = 0x3f;
	self->homa.forced_reap_count = 999;
	homa_timer(&self->homa);
	EXPECT_EQ(15, self->homa.forced_reap_count);
	EXPECT_EQ(2300, self->homa.last_rpcs);
	EXPECT_EQ(7000, self->homa.last_sent);
	EXPECT_EQ(11000, self->homa.last_received);
}
TEST_F(homa_timer, homa_timer__update_forced_reap_count__skip_wrong_tick)
{
	homa_cores[0]->metrics.requests_received = 1000;
	homa_cores[1]->metrics.requests_received = 500;
	homa_cores[2]->metrics.responses_received = 800;
	homa_cores[1]->metrics.packets_sent[0] = 5000;
	homa_cores[3]->metrics.packets_sent[0] = 2000;
	homa_cores[1]->metrics.packets_received[0] = 1000;
	homa_cores[2]->metrics.packets_received[0] = 6000;
	homa_cores[3]->metrics.packets_received[0] = 4000;
	self->homa.last_rpcs = 1290;
	self->homa.last_sent = 1000;
	self->homa.last_received = 2000;
	self->homa.timer_ticks = 0x3e;
	self->homa.forced_reap_count = 999;
	homa_timer(&self->homa);
	EXPECT_EQ(999, self->homa.forced_reap_count);
	EXPECT_EQ(1290, self->homa.last_rpcs);
	EXPECT_EQ(1000, self->homa.last_sent);
	EXPECT_EQ(2000, self->homa.last_received);
}
TEST_F(homa_timer, homa_timer__update_forced_reap_count__skip_not_enough_data)
{
	homa_cores[0]->metrics.requests_received = 1000;
	homa_cores[1]->metrics.requests_received = 500;
	homa_cores[2]->metrics.responses_received = 800;
	homa_cores[1]->metrics.packets_sent[0] = 5000;
	homa_cores[3]->metrics.packets_sent[0] = 2000;
	homa_cores[1]->metrics.packets_received[0] = 1000;
	homa_cores[2]->metrics.packets_received[0] = 6000;
	homa_cores[3]->metrics.packets_received[0] = 4000;
	self->homa.last_rpcs = 1310;
	self->homa.last_sent = 1000;
	self->homa.last_received = 2000;
	self->homa.timer_ticks = 0x3f;
	self->homa.forced_reap_count = 999;
	homa_timer(&self->homa);
	EXPECT_EQ(999, self->homa.forced_reap_count);
	EXPECT_EQ(1310, self->homa.last_rpcs);
	EXPECT_EQ(1000, self->homa.last_sent);
	EXPECT_EQ(2000, self->homa.last_received);
}