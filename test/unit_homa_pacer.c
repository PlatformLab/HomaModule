// SPDX-License-Identifier: BSD-2-Clause

#include "homa_impl.h"
#include "homa_pacer.h"
#include "homa_rpc.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

static struct homa_rpc *hook_rpc;
static int hook_count;
static void unmanage_hook(char *id) {
	if (strcmp(id, "spin_lock") != 0)
		return;
	if (hook_count <= 0)
		return;
	hook_count--;
	if (hook_count == 0)
		homa_pacer_unmanage_rpc(hook_rpc);
}

static u64 hook_exit_cycles;
static struct homa_pacer *hook_pacer;
static void exit_hook(char *id) {
	mock_clock += mock_clock_tick;
	if (mock_clock >= hook_exit_cycles)
		hook_pacer->exit = true;
}

static void exit_idle_hook(char *id) {
	if (strcmp(id, "schedule") == 0)
		unit_log_printf("; ", "time %llu", mock_clock);
	if (list_empty(&hook_pacer->throttled_rpcs))
		hook_pacer->exit = true;
}

static void manage_hook(char *id)
{
	if (strcmp(id, "prepare_to_wait") == 0 && hook_rpc) {
		homa_pacer_manage_rpc(hook_rpc);
		hook_rpc = NULL;
	}
}

FIXTURE(homa_pacer) {
	struct in6_addr client_ip[1];
	int client_port;
	struct in6_addr server_ip[1];
	int server_port;
	u64 client_id;
	u64 server_id;
	struct homa homa;
	struct homa_net *hnet;
	struct homa_sock hsk;
};
FIXTURE_SETUP(homa_pacer)
{
	self->client_ip[0] = unit_get_in_addr("196.168.0.1");
	self->client_port = 40000;
	self->server_ip[0] = unit_get_in_addr("1.2.3.4");
	self->server_port = 99;
	self->client_id = 1234;
	self->server_id = 1235;
	homa_init(&self->homa);
	self->hnet = mock_alloc_hnet(&self->homa);
	self->homa.pacer->cycles_per_mbyte = 1000000;
	self->homa.pacer->throttle_min_bytes = 0;
#ifndef __STRIP__ /* See strip.py */
	self->homa.pacer->fifo_fraction = 0;
#endif /* See strip.py */
	mock_sock_init(&self->hsk, self->hnet, self->client_port);
}
FIXTURE_TEARDOWN(homa_pacer)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_pacer, homa_pacer_new__success)
{
	struct homa_pacer *pacer;

	pacer = homa_pacer_alloc(&self->homa);
	EXPECT_FALSE(IS_ERR(pacer));
	EXPECT_EQ(&self->homa, pacer->homa);
	homa_pacer_free(pacer);
}
TEST_F(homa_pacer, homa_pacer_new__cant_allocate_memory)
{
	struct homa_pacer *pacer;

	mock_kmalloc_errors = 1;
	pacer = homa_pacer_alloc(&self->homa);
	EXPECT_TRUE(IS_ERR(pacer));
	EXPECT_EQ(ENOMEM, -PTR_ERR(pacer));
}
TEST_F(homa_pacer, homa_pacer_new__cant_create_pacer_thread)
{
	struct homa_pacer *pacer;

	mock_kthread_create_errors = 1;
	pacer = homa_pacer_alloc(&self->homa);
	EXPECT_TRUE(IS_ERR(pacer));
	EXPECT_EQ(EACCES, -PTR_ERR(pacer));
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_pacer, homa_pacer_new__cant_register_sysctls)
{
	struct homa_pacer *pacer;

	mock_register_sysctl_errors = 1;
	pacer = homa_pacer_alloc(&self->homa);
	EXPECT_TRUE(IS_ERR(pacer));
	EXPECT_EQ(ENOMEM, -PTR_ERR(pacer));
}
#endif /* See strip.py */

TEST_F(homa_pacer, homa_pacer_free__basics)
{
	struct homa_pacer *pacer;

	pacer = homa_pacer_alloc(&self->homa);
	EXPECT_FALSE(IS_ERR(pacer));
	unit_log_clear();
	homa_pacer_free(pacer);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("unregister_net_sysctl_table; kthread_stop",
		     unit_log_get());
#else /* See strip.py */
	EXPECT_STREQ("kthread_stop",
		     unit_log_get());
#endif /* See strip.py */
}
TEST_F(homa_pacer, homa_pacer_free__no_thread)
{
	struct homa_pacer *pacer;

	pacer = homa_pacer_alloc(&self->homa);
	EXPECT_FALSE(IS_ERR(pacer));
	pacer->kthread = NULL;
	unit_log_clear();
	homa_pacer_free(pacer);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("unregister_net_sysctl_table", unit_log_get());
#endif /* See strip.py */
}

TEST_F(homa_pacer, homa_pacer_check_nic_q__success)
{
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 500, 1000);

	homa_get_skb_info(crpc->msgout.packets)->wire_bytes = 500;
	unit_log_clear();
	atomic64_set(&self->homa.pacer->link_idle_time, 9000);
	mock_clock = 8000;
	self->homa.pacer->max_nic_queue_cycles = 1000;
	EXPECT_EQ(1, homa_pacer_check_nic_q(self->homa.pacer,
					    crpc->msgout.packets, false));
	EXPECT_EQ(9500, atomic64_read(&self->homa.pacer->link_idle_time));
}
TEST_F(homa_pacer, homa_pacer_check_nic_q__queue_full)
{
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 500, 1000);

	homa_get_skb_info(crpc->msgout.packets)->wire_bytes = 500;
	unit_log_clear();
	atomic64_set(&self->homa.pacer->link_idle_time, 9000);
	mock_clock = 7999;
	self->homa.pacer->max_nic_queue_cycles = 1000;
	EXPECT_EQ(0, homa_pacer_check_nic_q(self->homa.pacer,
					    crpc->msgout.packets, false));
	EXPECT_EQ(9000, atomic64_read(&self->homa.pacer->link_idle_time));
}
TEST_F(homa_pacer, homa_pacer_check_nic_q__queue_full_but_force)
{
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 500, 1000);

	homa_get_skb_info(crpc->msgout.packets)->wire_bytes = 500;
	unit_log_clear();
	atomic64_set(&self->homa.pacer->link_idle_time, 9000);
	mock_clock = 7999;
	self->homa.pacer->max_nic_queue_cycles = 1000;
	EXPECT_EQ(1, homa_pacer_check_nic_q(self->homa.pacer,
					    crpc->msgout.packets, true));
	EXPECT_EQ(9500, atomic64_read(&self->homa.pacer->link_idle_time));
}
TEST_F(homa_pacer, homa_pacer_check_nic_q__pacer_metrics)
{
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 500, 1000);

	homa_get_skb_info(crpc->msgout.packets)->wire_bytes = 500;
	homa_pacer_manage_rpc(crpc);
	unit_log_clear();
	atomic64_set(&self->homa.pacer->link_idle_time, 9000);
	self->homa.pacer->wake_time = 9800;
	mock_clock = 10000;
	self->homa.pacer->max_nic_queue_cycles = 1000;
	EXPECT_EQ(1, homa_pacer_check_nic_q(self->homa.pacer,
					    crpc->msgout.packets, true));
	EXPECT_EQ(10500, atomic64_read(&self->homa.pacer->link_idle_time));
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(500, homa_metrics_per_cpu()->pacer_bytes);
	EXPECT_EQ(200, homa_metrics_per_cpu()->pacer_lost_cycles);
#endif /* See strip.py */
}
TEST_F(homa_pacer, homa_pacer_check_nic_q__queue_empty)
{
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 500, 1000);

	homa_get_skb_info(crpc->msgout.packets)->wire_bytes = 500;
	unit_log_clear();
	atomic64_set(&self->homa.pacer->link_idle_time, 9000);
	mock_clock = 10000;
	self->homa.pacer->max_nic_queue_cycles = 1000;
	EXPECT_EQ(1, homa_pacer_check_nic_q(self->homa.pacer,
					    crpc->msgout.packets, true));
	EXPECT_EQ(10500, atomic64_read(&self->homa.pacer->link_idle_time));
}

TEST_F(homa_pacer, homa_pacer_main__exit)
{
	unit_hook_register(exit_hook);
	hook_pacer = self->homa.pacer;
	hook_exit_cycles = 5000;
	mock_clock_tick = 200;
	homa_pacer_main(self->homa.pacer);
	EXPECT_TRUE(mock_clock >= 5000);
}
TEST_F(homa_pacer, homa_pacer_main__xmit_data)
{
	struct homa_rpc *crpc1, *crpc2;

	crpc1 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port,
				self->client_id, 5000, 1000);
	crpc2 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port,
				self->client_id+2, 10000, 1000);

	homa_pacer_manage_rpc(crpc1);
	homa_pacer_manage_rpc(crpc2);
	self->homa.pacer->max_nic_queue_cycles = 3000;
	mock_clock_tick = 200;
	unit_hook_register(exit_idle_hook);
	hook_pacer = self->homa.pacer;
	unit_log_clear();
	homa_pacer_main(self->homa.pacer);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("xmit DATA 1400@0; "
		     "xmit DATA 1400@1400; "
		     "xmit DATA 1400@2800; time 1600; time 2200; "
		     "xmit DATA 800@4200; "
		     "removing id 1234 from throttled list; time 3200; "
		     "xmit DATA 1400@0; time 4400; "
		     "xmit DATA 1400@1400; time 5600; time 6200; "
		     "xmit DATA 1400@2800; time 7400; "
		     "xmit DATA 1400@4200; time 8600; time 9200; "
		     "xmit DATA 1400@5600; time 10400; time 11000; "
		     "xmit DATA 1400@7000; time 12200; "
		     "xmit DATA 1400@8400; time 13400; time 14000; "
		     "xmit DATA 200@9800; "
		     "removing id 1236 from throttled list",
		     unit_log_get());
#endif /* See strip.py */
}
TEST_F(homa_pacer, homa_pacer_main__rpc_arrives_while_sleeping)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id,
			5000, 1000);

	unit_hook_register(exit_hook);
	hook_pacer = self->homa.pacer;
	hook_exit_cycles = 5000;
	mock_clock_tick = 200;
	unit_hook_register(manage_hook);
	hook_rpc = crpc;
	self->homa.pacer->max_nic_queue_cycles = 2000;

	unit_log_clear();
	homa_pacer_main(self->homa.pacer);
	EXPECT_STREQ("xmit DATA 1400@0; xmit DATA 1400@1400; xmit DATA 1400@2800",
		     unit_log_get());
}
TEST_F(homa_pacer, homa_pacer_main__exit_on_signal)
{
	mock_prepare_to_wait_errors = 1;
	mock_prepare_to_wait_status = -EINVAL;
	unit_log_clear();
	homa_pacer_main(self->homa.pacer);
}

TEST_F(homa_pacer, homa_pacer_xmit__basics)
{
	struct homa_rpc *crpc1, *crpc2, *crpc3;

	crpc1 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port,
				self->client_id, 5000, 1000);
	crpc2 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port,
				self->client_id+2, 10000, 1000);
	crpc3 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port,
				self->client_id+4, 150000, 1000);

	homa_pacer_manage_rpc(crpc1);
	homa_pacer_manage_rpc(crpc2);
	homa_pacer_manage_rpc(crpc3);
	self->homa.pacer->max_nic_queue_cycles = 2000;
	unit_log_clear();
	homa_pacer_xmit(self->homa.pacer);
	EXPECT_STREQ("xmit DATA 1400@0; xmit DATA 1400@1400",
		     unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 1234, next_offset 2800; "
		     "request id 1236, next_offset 0; "
		     "request id 1238, next_offset 0", unit_log_get());
}
TEST_F(homa_pacer, homa_pacer_xmit__pacer_already_active)
{
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 10000, 1000);

	homa_pacer_manage_rpc(crpc);
	self->homa.pacer->max_nic_queue_cycles = 2000;
	mock_trylock_errors = 1;
	unit_log_clear();
	homa_pacer_xmit(self->homa.pacer);
	EXPECT_STREQ("", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 1234, next_offset 0", unit_log_get());
}
TEST_F(homa_pacer, homa_pacer_xmit__nic_queue_fills)
{
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 10000, 1000);

	homa_pacer_manage_rpc(crpc);
	self->homa.pacer->max_nic_queue_cycles = 2001;
	mock_clock = 10000;
	atomic64_set(&self->homa.pacer->link_idle_time, 12000);
	unit_log_clear();
	homa_pacer_xmit(self->homa.pacer);

	/* Just room for one packet before NIC queue fills. */
	EXPECT_STREQ("xmit DATA 1400@0", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 1234, next_offset 1400", unit_log_get());
}
TEST_F(homa_pacer, homa_pacer_xmit__queue_empty)
{
	self->homa.pacer->max_nic_queue_cycles = 2000;
	unit_log_clear();
	homa_pacer_xmit(self->homa.pacer);
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_pacer, homa_pacer_xmit__xmit_fifo)
{
	struct homa_rpc *crpc1, *crpc2, *crpc3;

	mock_clock = 10000;
	crpc1 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port, 2,
				20000, 1000);
	mock_clock = 11000;
	crpc2 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port, 4,
				10000, 1000);
	mock_clock = 12000;
	crpc3 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port, 6,
				30000, 1000);
	homa_pacer_manage_rpc(crpc1);
	homa_pacer_manage_rpc(crpc2);
	homa_pacer_manage_rpc(crpc3);

	/* First attempt: pacer->fifo_count doesn't reach zero. */
	self->homa.pacer->max_nic_queue_cycles = 1300;
	self->homa.pacer->fifo_count = 200;
	self->homa.pacer->fifo_fraction = 150;
	mock_clock= 13000;
	atomic64_set(&self->homa.pacer->link_idle_time, 10000);
	unit_log_clear();
	mock_xmit_log_verbose = 1;
	homa_pacer_xmit(self->homa.pacer);
	EXPECT_SUBSTR("id 4, message_length 10000, offset 0, data_length 1400",
		      unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 4, next_offset 1400; "
		     "request id 2, next_offset 0; "
		     "request id 6, next_offset 0", unit_log_get());
	EXPECT_EQ(50, self->homa.pacer->fifo_count);

	/* Second attempt: pacer->fifo_count reaches zero. */
	atomic64_set(&self->homa.pacer->link_idle_time, 10000);
	unit_log_clear();
	homa_pacer_xmit(self->homa.pacer);
	EXPECT_SUBSTR("id 2, message_length 20000, offset 0, data_length 1400",
		      unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 4, next_offset 1400; "
		     "request id 2, next_offset 1400; "
		     "request id 6, next_offset 0", unit_log_get());
	EXPECT_EQ(900, self->homa.pacer->fifo_count);
}
TEST_F(homa_pacer, homa_pacer_xmit__rpc_removed_from_queue_before_locked)
{
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 10000, 1000);

	homa_pacer_manage_rpc(crpc);
	self->homa.pacer->max_nic_queue_cycles = 10000;
	unit_log_clear();
	unit_hook_register(unmanage_hook);
	hook_rpc = crpc;
	hook_count = 2;
	homa_pacer_xmit(self->homa.pacer);

	EXPECT_STREQ("removing id 1234 from throttled list", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_pacer, homa_pacer_xmit__remove_from_queue)
{
	struct homa_rpc *crpc1, *crpc2;

	crpc1 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port, 2,
				1000, 1000);
	crpc2 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port, 4,
				2000, 1000);

	homa_pacer_manage_rpc(crpc1);
	homa_pacer_manage_rpc(crpc2);
	self->homa.pacer->max_nic_queue_cycles = 2000;
	unit_log_clear();

	/* First call completes id 2, but id 4 is still in the queue. */
	homa_pacer_xmit(self->homa.pacer);
	EXPECT_STREQ("xmit DATA 1000@0; removing id 2 from throttled list; "
		     "xmit DATA 1400@0", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 4, next_offset 1400", unit_log_get());
	EXPECT_TRUE(list_empty(&crpc1->throttled_links));

	/* Second call completes id 4, queue now empty. */
	unit_log_clear();
	self->homa.pacer->max_nic_queue_cycles = 10000;
	homa_pacer_xmit(self->homa.pacer);
	EXPECT_STREQ("xmit DATA 600@1400; removing id 4 from throttled list",
		     unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_TRUE(list_empty(&crpc2->throttled_links));
}

TEST_F(homa_pacer, homa_pacer_manage_rpc__basics)
{
	struct homa_rpc *crpc1, *crpc2, *crpc3, *crpc4, *crpc5;

	crpc1 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port, 2, 10000,
				1000);
	crpc2 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port, 4, 5000,
				1000);
	crpc3 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port, 6, 15000,
				1000);
	crpc4 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port, 8, 12000,
				1000);
	crpc5 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port, 10, 10000,
				1000);

	/* Basics: add one RPC. */
	mock_log_wakeups = 1;
	unit_log_clear();
	homa_pacer_manage_rpc(crpc1);
	EXPECT_STREQ("wake_up", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 2, next_offset 0", unit_log_get());

	/* Check priority ordering. */
	homa_pacer_manage_rpc(crpc2);
	homa_pacer_manage_rpc(crpc3);
	homa_pacer_manage_rpc(crpc4);
	homa_pacer_manage_rpc(crpc5);
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 4, next_offset 0; "
		"request id 2, next_offset 0; "
		"request id 10, next_offset 0; "
		"request id 8, next_offset 0; "
		"request id 6, next_offset 0", unit_log_get());

	/* Don't reinsert if already present. */
	unit_log_clear();
	homa_pacer_manage_rpc(crpc1);
	EXPECT_STREQ("", unit_log_get());
	unit_log_clear();
	unit_log_throttled(&self->homa);
	EXPECT_STREQ("request id 4, next_offset 0; "
		"request id 2, next_offset 0; "
		"request id 10, next_offset 0; "
		"request id 8, next_offset 0; "
		"request id 6, next_offset 0", unit_log_get());
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_pacer, homa_pacer_manage_rpc__inc_metrics)
{
	struct homa_rpc *crpc1, *crpc2, *crpc3;

	crpc1 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port,
				self->client_id, 5000, 1000);
	crpc2 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port,
				self->client_id+2, 10000, 1000);
	crpc3 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port,
				self->client_id+4, 15000, 1000);

	homa_pacer_manage_rpc(crpc1);
	EXPECT_EQ(1, homa_metrics_per_cpu()->throttle_list_adds);
	EXPECT_EQ(0, homa_metrics_per_cpu()->throttle_list_checks);

	homa_pacer_manage_rpc(crpc2);
	EXPECT_EQ(2, homa_metrics_per_cpu()->throttle_list_adds);
	EXPECT_EQ(1, homa_metrics_per_cpu()->throttle_list_checks);

	homa_pacer_manage_rpc(crpc3);
	EXPECT_EQ(3, homa_metrics_per_cpu()->throttle_list_adds);
	EXPECT_EQ(3, homa_metrics_per_cpu()->throttle_list_checks);
}
#endif /* See strip.py */

TEST_F(homa_pacer, homa_pacer_unmanage_rpc__basics)
{
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port,
			       self->client_id, 5000, 1000);

	homa_pacer_manage_rpc(crpc);
	EXPECT_FALSE(list_empty(&self->homa.pacer->throttled_rpcs));

	// First attempt will remove.
	unit_log_clear();
	homa_pacer_unmanage_rpc(crpc);
	EXPECT_TRUE(list_empty(&self->homa.pacer->throttled_rpcs));
	EXPECT_STREQ("removing id 1234 from throttled list", unit_log_get());

	// Second attempt: nothing to do.
	unit_log_clear();
	homa_pacer_unmanage_rpc(crpc);
	EXPECT_TRUE(list_empty(&self->homa.pacer->throttled_rpcs));
	EXPECT_STREQ("", unit_log_get());
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_pacer, homa_pacer_unmanage_rpc__metrics)
{
	struct homa_rpc *crpc1, *crpc2;

	crpc1 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port,
				self->client_id, 5000, 1000);
	crpc2 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
				self->server_ip, self->server_port,
				self->client_id+2, 5000, 1000);

	mock_clock = 1000;
	homa_pacer_manage_rpc(crpc1);
	EXPECT_EQ(1000, self->homa.pacer->throttle_add);
	EXPECT_EQ(0, homa_metrics_per_cpu()->throttled_cycles);

	mock_clock = 3000;
	homa_pacer_manage_rpc(crpc2);
	EXPECT_EQ(3000, self->homa.pacer->throttle_add);
	EXPECT_EQ(2000, homa_metrics_per_cpu()->throttled_cycles);

	mock_clock = 7000;
	homa_pacer_unmanage_rpc(crpc1);
	EXPECT_EQ(3000, self->homa.pacer->throttle_add);
	EXPECT_EQ(2000, homa_metrics_per_cpu()->throttled_cycles);

	mock_clock = 8000;
	homa_pacer_unmanage_rpc(crpc2);
	EXPECT_EQ(3000, self->homa.pacer->throttle_add);
	EXPECT_EQ(7000, homa_metrics_per_cpu()->throttled_cycles);
}
#endif /* See strip.py */

TEST_F(homa_pacer, homa_pacer_update_sysctl_deps)
{
	self->homa.pacer->max_nic_queue_ns = 6000;
	self->homa.pacer->link_mbps = 10000;
	homa_pacer_update_sysctl_deps(self->homa.pacer);
	EXPECT_EQ(6000, self->homa.pacer->max_nic_queue_cycles);
	EXPECT_EQ(808000, self->homa.pacer->cycles_per_mbyte);

	self->homa.pacer->link_mbps = 1000;
	homa_pacer_update_sysctl_deps(self->homa.pacer);
	EXPECT_EQ(8080000, self->homa.pacer->cycles_per_mbyte);

	self->homa.pacer->link_mbps = 40000;
	homa_pacer_update_sysctl_deps(self->homa.pacer);
	EXPECT_EQ(202000, self->homa.pacer->cycles_per_mbyte);
}