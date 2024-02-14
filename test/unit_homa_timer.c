/* Copyright (c) 2019-2023 Homa Developers
 * SPDX-License-Identifier: BSD-1-Clause
 */

#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

FIXTURE(homa_timer) {
	struct in6_addr client_ip[1];
	int client_port;
	struct in6_addr server_ip[1];
	int server_port;
	__u64 client_id;
	__u64 server_id;
	sockaddr_in_union server_addr;
	struct homa homa;
	struct homa_sock hsk;
};
FIXTURE_SETUP(homa_timer)
{
	self->client_ip[0] = unit_get_in_addr("196.168.0.1");
	self->client_port = 40000;
	self->server_ip[0] = unit_get_in_addr("1.2.3.4");
	self->server_port = 99;
	self->client_id = 1234;
	self->server_id = 1235;
	self->server_addr.in6.sin6_family = AF_INET;
	self->server_addr.in6.sin6_addr = *self->server_ip;
	self->server_addr.in6.sin6_port =  htons(self->server_port);
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

TEST_F(homa_timer, homa_check_rpc__request_ack)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_OUTGOING,
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
TEST_F(homa_timer, homa_check_rpc__all_granted_bytes_received)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 100, 5000);
	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	crpc->msgin.granted = 1400;
	crpc->silent_ticks = 10;
	 homa_check_rpc(crpc);
	EXPECT_EQ(0, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_check_rpc__no_buffer_space)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 100, 5000);
	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	crpc->msgin.num_bpages = 0;
	crpc->silent_ticks = 10;
	homa_check_rpc(crpc);
	EXPECT_EQ(0, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_check_rpc__server_has_received_request)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_IN_SERVICE,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 100, 100);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();
	srpc->silent_ticks = 10;
	homa_check_rpc(srpc);
	EXPECT_EQ(0, srpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_check_rpc__granted_bytes_not_sent)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 200);
	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	crpc->silent_ticks = 10;
	homa_check_rpc(crpc);
	EXPECT_EQ(0, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_timer, homa_check_rpc__timeout)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 200, 10000);
	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	crpc->silent_ticks = self->homa.timeout_ticks-1;
	homa_check_rpc(crpc);
	EXPECT_EQ(0, homa_cores[cpu_number]->metrics.rpc_timeouts);
	EXPECT_EQ(0, crpc->error);
	crpc->silent_ticks = self->homa.timeout_ticks;
	homa_check_rpc(crpc);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.rpc_timeouts);
	EXPECT_EQ(ETIMEDOUT, -crpc->error);
}
TEST_F(homa_timer, homa_check_rpc__check_for_resend)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 50000, 200);
	ASSERT_NE(NULL, crpc);
	self->homa.resend_ticks = 3;
	self->homa.resend_interval = 2;
	crpc->msgout.granted = 0;

	/* First call: resend_ticks-1. */
	crpc->silent_ticks = 2;
	unit_log_clear();
	homa_check_rpc(crpc);
	EXPECT_STREQ("", unit_log_get());

	/* Second call: resend_ticks. */
	crpc->silent_ticks = 3;
	unit_log_clear();
	homa_check_rpc(crpc);
	EXPECT_STREQ("xmit RESEND 0-99@7", unit_log_get());

	/* Third call: not yet time for next resend. */
	crpc->silent_ticks = 4;
	unit_log_clear();
	homa_check_rpc(crpc);
	EXPECT_STREQ("", unit_log_get());

	/* Fourth call: time for second resend. */
	crpc->silent_ticks = 5;
	unit_log_clear();
	homa_check_rpc(crpc);
	EXPECT_STREQ("xmit RESEND 0-99@7", unit_log_get());
}

TEST_F(homa_timer, homa_timer__basics)
{
	self->homa.timeout_ticks = 5;
	self->homa.resend_ticks = 3;
	self->homa.resend_interval = 2;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 200, 5000);
	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	crpc->silent_ticks = 1;
	homa_timer(&self->homa);
	EXPECT_EQ(2, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());

	/* Send RESEND. */
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(3, crpc->silent_ticks);
	EXPECT_STREQ("xmit RESEND 1400-4999@7", unit_log_get());

	/* Don't send another RESEND (resend_interval not reached). */
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(4, crpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());

	/* Timeout the peer. */
	unit_log_clear();
	crpc->peer->outstanding_resends = self->homa.timeout_resends;
	homa_timer(&self->homa);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.rpc_timeouts);
	EXPECT_EQ(ETIMEDOUT, -crpc->error);
}
TEST_F(homa_timer, homa_timer__reap_dead_rpcs)
{
	struct homa_rpc *dead = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 20000, 20000);
	ASSERT_NE(NULL, dead);
	homa_rpc_free(dead);
	EXPECT_EQ(31, self->hsk.dead_skbs);

	// First call to homa_timer: not enough dead skbs.
	self->homa.dead_buffs_limit = 32;
	homa_timer(&self->homa);
	EXPECT_EQ(31, self->hsk.dead_skbs);

	// Second call to homa_timer: must reap.
	self->homa.dead_buffs_limit = 15;
	homa_timer(&self->homa);
	EXPECT_EQ(11, self->hsk.dead_skbs);
}
TEST_F(homa_timer, homa_timer__rpc_in_service)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk, UNIT_IN_SERVICE,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 5000, 5000);
	ASSERT_NE(NULL, srpc);
	unit_log_clear();
	homa_timer(&self->homa);
	EXPECT_EQ(0, srpc->silent_ticks);
	EXPECT_STREQ("", unit_log_get());
}
