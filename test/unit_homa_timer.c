/* Copyright (c) 2019-2021 Stanford University
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
	__u64 client_id;
	__u64 server_id;
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
	self->client_id = 1234;
	self->server_id = 1235;
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

TEST_F(homa_timer, homa_check_timeout__request_ack)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 100);
	ASSERT_NE(NULL, srpc);
	self->homa.request_ack_ticks = 2;
	
	/* First call: do nothing (response not fully transmitted). */
	homa_check_rpc(srpc);
	EXPECT_EQ(0, srpc->done_timer_ticks);
	
	/* Second call: set done_timer_ticks. */
	homa_xmit_data(srpc, false);
	unit_log_clear();
	homa_check_rpc(srpc);
	EXPECT_EQ(100, srpc->done_timer_ticks);
	EXPECT_STREQ("", unit_log_get());
	
	/* Third call: haven't hit request_ack_ticks yet. */
	unit_log_clear();
	self->homa.timer_ticks++;
	homa_check_rpc(srpc);
	EXPECT_EQ(100, srpc->done_timer_ticks);
	EXPECT_STREQ("", unit_log_get());
	
	/* Fourth call: request ack. */
	unit_log_clear();
	self->homa.timer_ticks++;
	homa_check_rpc(srpc);
	EXPECT_EQ(100, srpc->done_timer_ticks);
	EXPECT_STREQ("xmit NEED_ACK", unit_log_get());
}
TEST_F(homa_timer, homa_check_timeout__client_rpc__granted_bytes_not_sent)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 200);
	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	crpc->silent_ticks = 10;
	EXPECT_EQ(0, homa_check_rpc(crpc));
	EXPECT_EQ(0, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_check_timeout__all_granted_bytes_received)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 100, 5000);
	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	crpc->msgin.incoming = 1400;
	crpc->silent_ticks = 10;
	EXPECT_EQ(0, homa_check_rpc(crpc));
	EXPECT_EQ(0, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_check_timeout__client_rpc__all_granted_bytes_received_no_busy)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 5000, 5000);
	ASSERT_NE(NULL, srpc);
	srpc->msgin.incoming = 1400;
	srpc->silent_ticks = 10;
	EXPECT_EQ(0, homa_check_rpc(srpc));
	EXPECT_EQ(0, srpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_check_timeout__resend_ticks_not_reached)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 50000, 200);
	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	self->homa.resend_ticks = 3;
	crpc->msgout.granted = 0;
	crpc->peer->outstanding_resends = self->homa.timeout_resends + 10;
	
	/* First call: resend_ticks-1 not reached. */
	crpc->silent_ticks = 1;
	EXPECT_EQ(0, homa_check_rpc(crpc));
	EXPECT_EQ(1, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
	
	/* Second call: resend_ticks-1 reached. */
	crpc->silent_ticks = 2;
	EXPECT_EQ(1, homa_check_rpc(crpc));
	EXPECT_EQ(2, crpc->silent_ticks);
	EXPECT_EQ(0, crpc->peer->outstanding_resends);
}
TEST_F(homa_timer, homa_check_timeout__peer_timeout)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 200, 10000);
	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	crpc->silent_ticks = self->homa.resend_ticks;
	crpc->peer->outstanding_resends = self->homa.timeout_resends;
	EXPECT_EQ(1, homa_check_rpc(crpc));
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.peer_timeouts);
	EXPECT_EQ(0, crpc->peer->outstanding_resends);
}
TEST_F(homa_timer, homa_check_timeout__server_rpc__state_not_incoming)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 20000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();
	srpc->silent_ticks = self->homa.resend_ticks;
	srpc->msgout.granted = 0;
	EXPECT_EQ(0, homa_check_rpc(srpc));
	EXPECT_EQ(self->homa.resend_ticks, srpc->silent_ticks);
}
TEST_F(homa_timer, homa_check_timeout__rollover_state_for_least_recent_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 20000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();
	srpc->msgout.granted = 0;
	srpc->silent_ticks = self->homa.resend_ticks;
	srpc->peer->least_recent_rpc = srpc;
	srpc->peer->least_recent_ticks = 0;
	srpc->peer->resend_rpc = NULL;
	srpc->peer->current_ticks = self->homa.timer_ticks-1;
	EXPECT_EQ(0, homa_check_rpc(srpc));
	EXPECT_EQ(srpc, srpc->peer->resend_rpc);
	EXPECT_EQ(NULL, srpc->peer->least_recent_rpc);
	EXPECT_EQ(self->homa.timer_ticks, srpc->peer->least_recent_ticks);
	EXPECT_EQ(self->homa.timer_ticks, srpc->peer->current_ticks);
}
TEST_F(homa_timer, homa_check_timeout__compute_least_recent_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 20000);
	struct homa_rpc *srpc2 = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id+1, 100, 20000);
	struct homa_rpc *srpc3 = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id+2, 100, 20000);
	ASSERT_NE(NULL, srpc);
	ASSERT_NE(NULL, srpc2);
	ASSERT_NE(NULL, srpc3);
	unit_log_clear();
	srpc->msgout.granted = 0;
	srpc->silent_ticks = self->homa.resend_ticks;
	srpc->resend_timer_ticks = self->homa.timer_ticks - 5;
	srpc2->msgout.granted = 0;
	srpc2->silent_ticks = self->homa.resend_ticks;
	srpc2->resend_timer_ticks = self->homa.timer_ticks - 10;
	srpc3->msgout.granted = 0;
	srpc3->silent_ticks = self->homa.resend_ticks;
	srpc3->resend_timer_ticks = self->homa.timer_ticks - 3;
	srpc->peer->current_ticks = self->homa.timer_ticks-1;
	EXPECT_EQ(0, homa_check_rpc(srpc));
	EXPECT_EQ(srpc, srpc->peer->least_recent_rpc);
	EXPECT_EQ(0, homa_check_rpc(srpc2));
	EXPECT_EQ(srpc2, srpc->peer->least_recent_rpc);
	EXPECT_EQ(0, homa_check_rpc(srpc3));
	EXPECT_EQ(srpc2, srpc->peer->least_recent_rpc);
	EXPECT_EQ(self->homa.timer_ticks - 10, srpc->peer->least_recent_ticks);
	EXPECT_EQ(self->homa.timer_ticks, srpc->peer->current_ticks);
}
TEST_F(homa_timer, homa_check_timeout__least_recent_rpc_with_ticks_overflow)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 20000);
	struct homa_rpc *srpc2 = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id+1, 100, 20000);
	struct homa_rpc *srpc3 = unit_server_rpc(&self->hsk, RPC_OUTGOING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id+2, 100, 20000);
	ASSERT_NE(NULL, srpc);
	ASSERT_NE(NULL, srpc2);
	ASSERT_NE(NULL, srpc3);
	unit_log_clear();
	srpc->msgout.granted = 0;
	srpc->silent_ticks = self->homa.resend_ticks;
	srpc->resend_timer_ticks = 5;
	srpc2->msgout.granted = 0;
	srpc2->silent_ticks = self->homa.resend_ticks;
	srpc2->resend_timer_ticks = -10;
	srpc3->msgout.granted = 0;
	srpc3->silent_ticks = self->homa.resend_ticks;
	srpc3->resend_timer_ticks = 3;
	srpc->peer->current_ticks = self->homa.timer_ticks-1;
	EXPECT_EQ(0, homa_check_rpc(srpc));
	EXPECT_EQ(srpc, srpc->peer->least_recent_rpc);
	EXPECT_EQ(0, homa_check_rpc(srpc2));
	EXPECT_EQ(srpc2, srpc->peer->least_recent_rpc);
	EXPECT_EQ(0, homa_check_rpc(srpc3));
	EXPECT_EQ(srpc2, srpc->peer->least_recent_rpc);
	EXPECT_EQ(-10, srpc->peer->least_recent_ticks);
	EXPECT_EQ(self->homa.timer_ticks, srpc->peer->current_ticks);
}
TEST_F(homa_timer, homa_check_timeout__too_soon_for_another_resend)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 5000, 5000);
	ASSERT_NE(NULL, srpc);

	/* Send RESEND. */
	unit_log_clear();
	srpc->silent_ticks = self->homa.resend_ticks;
	srpc->peer->resend_rpc = srpc;
	srpc->peer->most_recent_resend = self->homa.timer_ticks
			- self->homa.resend_interval + 1;
	EXPECT_EQ(0, homa_check_rpc(srpc));
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_check_timeout__send_resend)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 5000, 5000);
	ASSERT_NE(NULL, srpc);

	unit_log_clear();
	srpc->silent_ticks = self->homa.resend_ticks-1;
	srpc->resend_timer_ticks = self->homa.timer_ticks - 10;
	srpc->peer->resend_rpc = srpc;
	
	/* First call: no resend, but choose this RPC for least_recent_rpc. */
	EXPECT_EQ(0, homa_check_rpc(srpc));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, srpc->peer->outstanding_resends);
	EXPECT_EQ(srpc, srpc->peer->least_recent_rpc);
	
	/* Second call: issue resend. */
	self->homa.timer_ticks++;
	srpc->silent_ticks++;
	EXPECT_EQ(0, homa_check_rpc(srpc));
	EXPECT_STREQ("xmit RESEND 1400-4999@7", unit_log_get());
	EXPECT_EQ(self->homa.timer_ticks, srpc->resend_timer_ticks);
	EXPECT_EQ(self->homa.timer_ticks, srpc->peer->most_recent_resend);
	EXPECT_EQ(1, srpc->peer->outstanding_resends);
	EXPECT_EQ(NULL, srpc->peer->least_recent_rpc);
}

TEST_F(homa_timer, homa_timer__basics)
{
	self->homa.timeout_resends = 2;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 200, 5000);
	ASSERT_NE(NULL, crpc);
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
TEST_F(homa_timer, homa_timer__reap_dead_rpcs)
{
	struct homa_rpc *dead = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 20000);
	ASSERT_NE(NULL, dead);
	homa_rpc_free(dead);
	EXPECT_EQ(30, self->hsk.dead_skbs);
	
	// First call to homa_timer: not enough dead skbs.
	self->homa.dead_buffs_limit = 31;
	homa_timer(&self->homa);
	EXPECT_EQ(30, self->hsk.dead_skbs);
	
	// Second call to homa_timer: must reap.
	self->homa.dead_buffs_limit = 15;
	homa_timer(&self->homa);
	EXPECT_EQ(10, self->hsk.dead_skbs);
}
TEST_F(homa_timer, homa_timer__rpc_ready)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 200);
	ASSERT_NE(NULL, crpc);
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
			self->server_id, 5000, 5000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(0, srpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_timer__abort_server_rpc)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 5000, 5000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();
	srpc->silent_ticks = self->homa.resend_ticks-1;
	srpc->peer->outstanding_resends = self->homa.timeout_resends;
	srpc->msgout.granted = 0;
	homa_timer(&self->homa);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.server_rpc_discards);
	EXPECT_EQ(1, unit_list_length(&self->hsk.dead_rpcs));
	EXPECT_STREQ("homa_remove_from_grantable invoked", unit_log_get());
}
