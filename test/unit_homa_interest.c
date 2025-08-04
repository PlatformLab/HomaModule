// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

#include "homa_impl.h"
#include "homa_interest.h"
#include "homa_sock.h"

#ifndef __STRIP__ /* See strip.py */
#include "homa_offload.h"
#endif /* See strip.py */

#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

static int hook_count;
static struct homa_interest *hook_interest;

#ifndef __STRIP__ /* See strip.py */
static void log_hook(char *id)
{
	if (strcmp(id, "unlock") == 0 ||
            strcmp(id, "schedule") == 0) {
		unit_log_printf("; ", "%s", id);
	}
}
#endif /* See strip.py */

static void notify_hook(char *id)
{
	if (strcmp(id, "schedule") != 0 &&
	    strcmp(id, "do_wait_intr_irq") != 0 &&
	    strcmp(id, "prepare_to_wait") != 0)
		return;
	if (hook_count <= 0)
		return;
	hook_count--;
	if (hook_count != 0)
		return;
	atomic_set(&hook_interest->ready, 1);
}

FIXTURE(homa_interest) {
	struct homa homa;
	struct homa_net *hnet;
	struct homa_sock hsk;
	struct in6_addr client_ip;
	int client_port;
	struct in6_addr server_ip;
	int server_port;
	u64 client_id;
	u64 server_id;
	union sockaddr_in_union server_addr;
};
FIXTURE_SETUP(homa_interest)
{
	homa_init(&self->homa);
	self->hnet = mock_alloc_hnet(&self->homa);
	mock_sock_init(&self->hsk, self->hnet, 0);
	self->client_ip = unit_get_in_addr("196.168.0.1");
	self->client_port = 40000;
	self->server_ip = unit_get_in_addr("1.2.3.4");
	self->server_port = 99;
	self->client_id = 1234;
	self->server_id = 1235;
	self->server_addr.in6.sin6_family = self->hsk.inet.sk.sk_family;
	self->server_addr.in6.sin6_addr = self->server_ip;
	self->server_addr.in6.sin6_port =  htons(self->server_port);
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_interest)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_interest, homa_interest_init_shared_and_unlink_shared)
{
	struct homa_interest interests[4];
	int i;

	for (i = 0; i < 4; i++) {
		homa_interest_init_shared(&interests[i], &self->hsk);
		EXPECT_EQ(i + 1, unit_list_length(&self->hsk.interests));
	}
	EXPECT_EQ(3, list_first_entry(&self->hsk.interests,
				      struct homa_interest, links)
		      - interests);
	homa_interest_unlink_shared(&interests[1]);
	EXPECT_EQ(3, unit_list_length(&self->hsk.interests));
	homa_interest_unlink_shared(&interests[0]);
	EXPECT_EQ(2, unit_list_length(&self->hsk.interests));
	homa_interest_unlink_shared(&interests[3]);
	EXPECT_EQ(1, unit_list_length(&self->hsk.interests));
	homa_interest_unlink_shared(&interests[2]);
	EXPECT_EQ(0, unit_list_length(&self->hsk.interests));
}

TEST_F(homa_interest, homa_interest_init_private)
{
	struct homa_interest interest;
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
			       &self->server_ip, self->server_port,
			       self->client_id, 20000, 1600);

	/* First call succeeds. */
	EXPECT_EQ(0, homa_interest_init_private(&interest, crpc));
	EXPECT_EQ(&interest, crpc->private_interest);
	EXPECT_EQ(crpc, interest.rpc);

	/* Second call fails (rpc already has interest). */
	EXPECT_EQ(EINVAL, -homa_interest_init_private(&interest, crpc));

	homa_interest_unlink_private(&interest);
}

TEST_F(homa_interest, homa_interest_unlink_private)
{
	struct homa_interest interest, interest2;
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
			       &self->server_ip, self->server_port,
			       self->client_id, 20000, 1600);

	EXPECT_EQ(0, homa_interest_init_private(&interest, crpc));
	homa_interest_unlink_private(&interest);
	EXPECT_EQ(NULL, crpc->private_interest);

	/* Second call does nothing (rpc doesn't refer to interest). */
	crpc->private_interest = &interest2;
	homa_interest_unlink_private(&interest);
	EXPECT_EQ(&interest2, crpc->private_interest);

	crpc->private_interest = NULL;
}

TEST_F(homa_interest, homa_interest_wait__already_ready)
{
	struct homa_interest interest;

	homa_interest_init_shared(&interest, &self->hsk);
	atomic_set(&interest.ready, 1);
	EXPECT_EQ(0, homa_interest_wait(&interest));
	EXPECT_EQ(0, interest.blocked);

	homa_interest_unlink_shared(&interest);
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_interest, homa_interest_wait__call_schedule)
{
	struct homa_interest interest;

	homa_interest_init_shared(&interest, &self->hsk);

	self->homa.poll_cycles = 100;
	unit_hook_register(log_hook);
	unit_hook_register(notify_hook);
	hook_interest = &interest;
	hook_count = 2;
	unit_log_clear();

	EXPECT_EQ(0, homa_interest_wait(&interest));
	EXPECT_STREQ("schedule; schedule", unit_log_get());
	homa_interest_unlink_shared(&interest);
}
#endif /* See strip.py */
TEST_F(homa_interest, homa_interest_wait__call_homa_rpc_reap)
{
	struct homa_interest interest;
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
			       &self->server_ip, self->server_port,
			       self->client_id, 20000, 1600);
	ASSERT_NE(NULL, crpc);
	homa_rpc_end(crpc);
	EXPECT_EQ(15, self->hsk.dead_skbs);

	homa_interest_init_shared(&interest, &self->hsk);

	IF_NO_STRIP(self->homa.poll_cycles = 0);
	unit_hook_register(notify_hook);
	hook_interest = &interest;
	hook_count = 1;
	unit_log_clear();

	EXPECT_EQ(0, homa_interest_wait(&interest));
	EXPECT_EQ(5, self->hsk.dead_skbs);
	homa_interest_unlink_shared(&interest);
}
TEST_F(homa_interest, homa_interest_wait__poll_then_block)
{
	struct homa_interest interest;

	homa_interest_init_shared(&interest, &self->hsk);
	IF_NO_STRIP(self->homa.poll_cycles = 3000);
	mock_set_clock_vals(1000, 2000, 3999, 4000, 0);
	mock_clock = 4000;
	unit_hook_register(notify_hook);
	hook_interest = &interest;
	hook_count = 4;

	EXPECT_EQ(0, -homa_interest_wait(&interest));
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(3000, homa_metrics_per_cpu()->poll_cycles);
	EXPECT_EQ(0, homa_metrics_per_cpu()->blocked_cycles);
	EXPECT_EQ(1, interest.blocked);
#endif /* See strip.py */
	homa_interest_unlink_shared(&interest);
}
TEST_F(homa_interest, homa_interest_wait__interrupted_by_signal)
{
	struct homa_interest interest;

	homa_interest_init_shared(&interest, &self->hsk);
	mock_prepare_to_wait_errors = 1;
	IF_NO_STRIP(self->homa.poll_cycles = 0);

	EXPECT_EQ(EINTR, -homa_interest_wait(&interest));
	EXPECT_EQ(1, interest.blocked);
	homa_interest_unlink_shared(&interest);
}
TEST_F(homa_interest, homa_interest_wait__time_metrics)
{
	struct homa_interest interest;

	homa_interest_init_shared(&interest, &self->hsk);
	IF_NO_STRIP(self->homa.poll_cycles = 0);
	mock_set_clock_vals(1000, 1500, 3000, 3200, 0);
	mock_clock = 4000;
	unit_hook_register(notify_hook);
	hook_interest = &interest;
	hook_count = 4;

	EXPECT_EQ(0, -homa_interest_wait(&interest));
	IF_NO_STRIP(EXPECT_EQ(700, homa_metrics_per_cpu()->poll_cycles));
	IF_NO_STRIP(EXPECT_EQ(1500, homa_metrics_per_cpu()->blocked_cycles));
	homa_interest_unlink_shared(&interest);
}

TEST_F(homa_interest, homa_interest_wait__notify_private)
{
	struct homa_interest interest;
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
			       &self->server_ip, self->server_port,
			       self->client_id, 20000, 1600);
	ASSERT_NE(NULL, crpc);

	homa_interest_init_private(&interest, crpc);
	EXPECT_EQ(0, atomic_read(&interest.ready));
	unit_log_clear();
	mock_log_wakeups = 1;

	/* First call: RPC has an interest. */
	homa_interest_notify_private(crpc);
	EXPECT_EQ(1, atomic_read(&interest.ready));
	EXPECT_STREQ("wake_up", unit_log_get());
	homa_interest_unlink_private(&interest);

	/* Second call: No interest on RPC. */
	unit_log_clear();
	homa_interest_notify_private(crpc);
	EXPECT_STREQ("", unit_log_get());
}

#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_interest, homa_choose_interest__find_idle_core)
{
	struct homa_interest interest1, interest2, interest3;

	homa_interest_init_shared(&interest1, &self->hsk);
	interest1.core = 1;
	homa_interest_init_shared(&interest2, &self->hsk);
	interest2.core = 2;
	homa_interest_init_shared(&interest3, &self->hsk);
	interest3.core = 3;

	mock_clock = 5000;
	self->homa.busy_cycles = 1000;
	per_cpu(homa_offload_core, 1).last_active = 2000;
	per_cpu(homa_offload_core, 2).last_active = 3500;
	per_cpu(homa_offload_core, 3).last_active = 4100;

	struct homa_interest *result = homa_choose_interest(&self->hsk);
	EXPECT_EQ(&interest2, result);
	EXPECT_EQ(2, result->core);
	IF_NO_STRIP(EXPECT_EQ(1, homa_metrics_per_cpu()->handoffs_alt_thread));
	INIT_LIST_HEAD(&self->hsk.interests);
}
TEST_F(homa_interest, homa_choose_interest__all_cores_busy)
{
	struct homa_interest interest1, interest2, interest3;

	homa_interest_init_shared(&interest1, &self->hsk);
	interest1.core = 1;
	homa_interest_init_shared(&interest2, &self->hsk);
	interest2.core = 2;
	homa_interest_init_shared(&interest3, &self->hsk);
	interest3.core = 3;

	mock_clock = 5000;
	self->homa.busy_cycles = 1000;
	per_cpu(homa_offload_core, 1).last_active = 4100;
	per_cpu(homa_offload_core, 2).last_active = 4001;
	per_cpu(homa_offload_core, 3).last_active = 4800;

	struct homa_interest *result = homa_choose_interest(&self->hsk);
	EXPECT_EQ(3, result->core);
	IF_NO_STRIP(EXPECT_EQ(0, homa_metrics_per_cpu()->handoffs_alt_thread));
	INIT_LIST_HEAD(&self->hsk.interests);
}
#endif /* See strip.py */
