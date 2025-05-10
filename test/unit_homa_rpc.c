// SPDX-License-Identifier: BSD-2-Clause

#include "homa_impl.h"
#include "homa_grant.h"
#include "homa_pacer.h"
#include "homa_peer.h"
#include "homa_pool.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#define n(x) htons(x)
#define N(x) htonl(x)

static struct homa_sock *hook_hsk;
void unprotect_hsk_hook(char *id)
{
	if (strcmp(id, "unlock") != 0)
		return;
	if (hook_hsk) {
		homa_unprotect_rpcs(hook_hsk);
		hook_hsk = NULL;
	}
}

#if 0
static struct homa_rpc *hook_rpc;
static int hook_count;
static void unlink_rpc_hook(char *id)
{
	if (strcmp(id, "spin_lock")!= 0)
		return;
	if (hook_count == 0)
		return;
	hook_count--;
	if (hook_count == 0) {
		list_del_init(&hook_rpc->ready_links);
		homa_rpc_put(hook_rpc);
	}
}
#endif

FIXTURE(homa_rpc) {
	struct in6_addr client_ip[1];
	int client_port;
	struct in6_addr server_ip[1];
	int server_port;
	u64 client_id;
	u64 server_id;
	struct homa homa;
	struct homa_sock hsk;
	union sockaddr_in_union server_addr;
	struct homa_data_hdr data;
	struct homa_rpc *crpc;
	struct iovec iovec;
	struct iov_iter iter;
};
FIXTURE_SETUP(homa_rpc)
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
	homa_init(&self->homa, &mock_net);
	mock_set_homa(&self->homa);
#ifndef __STRIP__ /* See strip.py */
	self->homa.unsched_bytes = 10000;
	self->homa.grant->window = 10000;
#endif /* See strip.py */
	mock_sock_init(&self->hsk, &self->homa, 0);
	memset(&self->data, 0, sizeof(self->data));
	self->data.common = (struct homa_common_hdr){
		.sport = htons(self->client_port),
		.dport = htons(self->server_port),
		.type = DATA,
		.sender_id = self->client_id
	};
	self->data.message_length = htonl(10000);
#ifndef __STRIP__ /* See strip.py */
	self->data.incoming = htonl(10000);
#endif /* See strip.py */
	self->iovec.iov_base = (void *) 2000;
	self->iovec.iov_len = 10000;
	iov_iter_init(&self->iter, WRITE, &self->iovec, 1, self->iovec.iov_len);
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_rpc)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

/**
 * dead_rpcs() - Logs the ids for all of the RPCS in hsk->dead_rpcs.
 * @hsk:  Homa socket to check for dead RPCs.
 *
 * Return: the contents of the unit test log.
 */
static const char *dead_rpcs(struct homa_sock *hsk)
{
	struct homa_rpc *rpc;

	list_for_each_entry_rcu(rpc, &hsk->dead_rpcs, dead_links)
		UNIT_LOG(" ", "%llu", rpc->id);
	return unit_log_get();
}

TEST_F(homa_rpc, homa_rpc_alloc_client_normal)
{
	struct homa_rpc *crpc = homa_rpc_alloc_client(&self->hsk,
			&self->server_addr);

	ASSERT_FALSE(IS_ERR(crpc));
	homa_rpc_end(crpc);
	homa_rpc_unlock(crpc);
}
TEST_F(homa_rpc, homa_rpc_alloc_client_malloc_error)
{
	struct homa_rpc *crpc;

	mock_kmalloc_errors = 1;
	crpc = homa_rpc_alloc_client(&self->hsk, &self->server_addr);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(ENOMEM, -PTR_ERR(crpc));
}
TEST_F(homa_rpc, homa_rpc_alloc_client_route_error)
{
	struct homa_rpc *crpc;

	mock_route_errors = 1;
	crpc = homa_rpc_alloc_client(&self->hsk, &self->server_addr);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(EHOSTUNREACH, -PTR_ERR(crpc));
}
TEST_F(homa_rpc, homa_rpc_alloc_client_socket_shutdown)
{
	struct homa_rpc *crpc;

	self->hsk.shutdown = 1;
	crpc = homa_rpc_alloc_client(&self->hsk, &self->server_addr);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(ESHUTDOWN, -PTR_ERR(crpc));
	self->hsk.shutdown = 0;
}

TEST_F(homa_rpc, homa_rpc_alloc_server__normal)
{
	struct homa_rpc *srpc;
	int created;

	srpc = homa_rpc_alloc_server(&self->hsk, self->client_ip, &self->data,
			&created);
	ASSERT_FALSE(IS_ERR(srpc));
	homa_rpc_unlock(srpc);
	self->data.message_length = N(1600);
	homa_data_pkt(mock_skb_alloc(self->client_ip, &self->data.common,
			1400, 0), srpc);
	EXPECT_EQ(RPC_INCOMING, srpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(1, created);
	homa_rpc_end(srpc);
}
TEST_F(homa_rpc, homa_rpc_alloc_server__already_exists)
{
	struct homa_rpc *srpc1, *srpc2, *srpc3;
	int created;

	srpc1 = homa_rpc_alloc_server(&self->hsk, self->client_ip, &self->data,
			&created);
	ASSERT_FALSE(IS_ERR(srpc1));
	homa_rpc_unlock(srpc1);
	self->data.common.sender_id = cpu_to_be64(
			be64_to_cpu(self->data.common.sender_id)
			+ 2*HOMA_SERVER_RPC_BUCKETS);
	srpc2 = homa_rpc_alloc_server(&self->hsk, self->client_ip, &self->data,
			&created);
	ASSERT_FALSE(IS_ERR(srpc2));
	EXPECT_EQ(1, created);
	homa_rpc_unlock(srpc2);
	EXPECT_NE(srpc2, srpc1);
	self->data.common.sender_id = cpu_to_be64(
			be64_to_cpu(self->data.common.sender_id)
			- 2*HOMA_SERVER_RPC_BUCKETS);
	srpc3 = homa_rpc_alloc_server(&self->hsk, self->client_ip, &self->data,
			&created);
	ASSERT_FALSE(IS_ERR(srpc3));
	EXPECT_EQ(0, created);
	homa_rpc_unlock(srpc3);
	EXPECT_EQ(srpc3, srpc1);
}
TEST_F(homa_rpc, homa_rpc_alloc_server__malloc_error)
{
	struct homa_rpc *srpc;
	int created;

	mock_kmalloc_errors = 1;
	srpc = homa_rpc_alloc_server(&self->hsk, self->client_ip, &self->data,
			&created);
	EXPECT_TRUE(IS_ERR(srpc));
	EXPECT_EQ(ENOMEM, -PTR_ERR(srpc));
}
TEST_F(homa_rpc, homa_rpc_alloc_server__addr_error)
{
	struct homa_rpc *srpc;
	int created;

	mock_route_errors = 1;
	srpc = homa_rpc_alloc_server(&self->hsk, self->client_ip, &self->data,
			&created);
	EXPECT_TRUE(IS_ERR(srpc));
	EXPECT_EQ(EHOSTUNREACH, -PTR_ERR(srpc));
}
TEST_F(homa_rpc, homa_rpc_alloc_server__socket_shutdown)
{
	struct homa_rpc *srpc;
	int created;

	self->hsk.shutdown = 1;
	srpc = homa_rpc_alloc_server(&self->hsk, self->client_ip, &self->data,
			&created);
	EXPECT_TRUE(IS_ERR(srpc));
	EXPECT_EQ(ESHUTDOWN, -PTR_ERR(srpc));
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	self->hsk.shutdown = 0;
}
TEST_F(homa_rpc, homa_rpc_alloc_server__allocate_buffers)
{
	struct homa_rpc *srpc;
	int created;

	self->data.message_length = N(3*HOMA_BPAGE_SIZE);
	srpc = homa_rpc_alloc_server(&self->hsk, self->client_ip, &self->data,
			&created);
	ASSERT_FALSE(IS_ERR(srpc));
	homa_rpc_unlock(srpc);
	EXPECT_EQ(3, srpc->msgin.num_bpages);
	homa_rpc_end(srpc);
}
TEST_F(homa_rpc, homa_rpc_alloc_server__no_buffer_pool)
{
	struct homa_rpc *srpc;
	int created;

	self->data.message_length = N(1400);
	homa_pool_free(self->hsk.buffer_pool);
	self->hsk.buffer_pool = homa_pool_alloc(&self->hsk);
	srpc = homa_rpc_alloc_server(&self->hsk, self->client_ip, &self->data,
			&created);
	ASSERT_TRUE(IS_ERR(srpc));
	EXPECT_EQ(ENOMEM, -PTR_ERR(srpc));
}
TEST_F(homa_rpc, homa_rpc_alloc_server__handoff_rpc)
{
	struct homa_rpc *srpc;
	int created;

	self->data.message_length = N(1400);
	srpc = homa_rpc_alloc_server(&self->hsk, self->client_ip, &self->data,
			&created);
	ASSERT_FALSE(IS_ERR(srpc));
	homa_rpc_unlock(srpc);
	EXPECT_EQ(RPC_INCOMING, srpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_rpcs));
	homa_rpc_end(srpc);
}
TEST_F(homa_rpc, homa_rpc_alloc_server__dont_handoff_no_buffers)
{
	struct homa_rpc *srpc;
	int created;

	self->data.message_length = N(1400);
	atomic_set(&self->hsk.buffer_pool->free_bpages, 0);
	srpc = homa_rpc_alloc_server(&self->hsk, self->client_ip, &self->data,
			&created);
	ASSERT_FALSE(IS_ERR(srpc));
	homa_rpc_unlock(srpc);
	EXPECT_EQ(0, unit_list_length(&self->hsk.ready_rpcs));
	homa_rpc_end(srpc);
}
TEST_F(homa_rpc, homa_rpc_alloc_server__dont_handoff_rpc)
{
	struct homa_rpc *srpc;
	int created;

	self->data.message_length = N(2800);
	self->data.seg.offset = N(1400);
	srpc = homa_rpc_alloc_server(&self->hsk, self->client_ip, &self->data,
			&created);
	ASSERT_FALSE(IS_ERR(srpc));
	homa_rpc_unlock(srpc);
	EXPECT_EQ(RPC_INCOMING, srpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(0, unit_list_length(&self->hsk.ready_rpcs));
	homa_rpc_end(srpc);
}

#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_rpc, homa_bucket_lock_slow)
{
	struct homa_rpc *crpc, *srpc;
	int created;

	mock_clock_tick = 10;
	crpc = homa_rpc_alloc_client(&self->hsk, &self->server_addr);
	ASSERT_FALSE(IS_ERR(crpc));
	homa_rpc_end(crpc);
	homa_rpc_unlock(crpc);
	srpc = homa_rpc_alloc_server(&self->hsk, self->client_ip, &self->data,
			&created);
	ASSERT_FALSE(IS_ERR(srpc));
	homa_rpc_unlock(srpc);

	EXPECT_EQ(0, homa_metrics_per_cpu()->client_lock_misses);
	EXPECT_EQ(0, homa_metrics_per_cpu()->client_lock_miss_cycles);
	homa_bucket_lock_slow(crpc->bucket, crpc->id);
	homa_rpc_unlock(crpc);
	EXPECT_EQ(1, homa_metrics_per_cpu()->client_lock_misses);
	EXPECT_NE(0, homa_metrics_per_cpu()->client_lock_miss_cycles);
	EXPECT_EQ(0, homa_metrics_per_cpu()->server_lock_misses);
	EXPECT_EQ(0, homa_metrics_per_cpu()->server_lock_miss_cycles);
	homa_bucket_lock_slow(srpc->bucket, srpc->id);
	homa_rpc_unlock(srpc);
	EXPECT_EQ(1, homa_metrics_per_cpu()->server_lock_misses);
	EXPECT_EQ(10, homa_metrics_per_cpu()->server_lock_miss_cycles);
}
#endif /* See strip.py */

TEST_F(homa_rpc, homa_rpc_acked__basics)
{
	struct homa_rpc *srpc;
	struct homa_sock hsk;
	struct homa_ack ack = {};

	mock_sock_init(&hsk, &self->homa, self->server_port);
	srpc = unit_server_rpc(&hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->client_port, self->server_id,
			100, 3000);
	ASSERT_NE(NULL, srpc);
	ack.server_port = htons(self->server_port);
	ack.client_id = cpu_to_be64(self->client_id);
	homa_rpc_acked(&hsk, self->client_ip, &ack);
	EXPECT_EQ(0, unit_list_length(&hsk.active_rpcs));
	EXPECT_STREQ("DEAD", homa_symbol_for_state(srpc));
	homa_sock_destroy(&hsk);
}
TEST_F(homa_rpc, homa_rpc_acked__lookup_socket)
{
	struct homa_ack ack = {};
	struct homa_rpc *srpc;
	struct homa_sock hsk;

	mock_sock_init(&hsk, &self->homa, self->server_port);
	srpc = unit_server_rpc(&hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->client_port, self->server_id,
			100, 3000);
	ASSERT_NE(NULL, srpc);
	ack.server_port = htons(self->server_port);
	ack.client_id = cpu_to_be64(self->client_id);
	homa_rpc_acked(&self->hsk, self->client_ip, &ack);
	EXPECT_EQ(0, unit_list_length(&hsk.active_rpcs));
	EXPECT_STREQ("DEAD", homa_symbol_for_state(srpc));
	homa_sock_destroy(&hsk);
}
TEST_F(homa_rpc, homa_rpc_acked__no_such_socket)
{
	struct homa_ack ack = {};
	struct homa_rpc *srpc;
	struct homa_sock hsk;

	mock_sock_init(&hsk, &self->homa, self->server_port);
	srpc = unit_server_rpc(&hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->client_port, self->server_id,
			100, 3000);
	ASSERT_NE(NULL, srpc);
	ack.server_port = htons(self->server_port+1);
	ack.client_id = cpu_to_be64(self->client_id);
	homa_rpc_acked(&hsk, self->client_ip, &ack);
	EXPECT_EQ(1, unit_list_length(&hsk.active_rpcs));
	EXPECT_STREQ("OUTGOING", homa_symbol_for_state(srpc));
	homa_sock_destroy(&hsk);
}
TEST_F(homa_rpc, homa_rpc_acked__no_such_rpc)
{
	struct homa_ack ack = {};
	struct homa_rpc *srpc;
	struct homa_sock hsk;

	mock_sock_init(&hsk, &self->homa, self->server_port);
	srpc = unit_server_rpc(&hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->client_port, self->server_id,
			100, 3000);
	ASSERT_NE(NULL, srpc);
	ack.server_port = htons(self->server_port);
	ack.client_id = cpu_to_be64(self->client_id+10);
	homa_rpc_acked(&hsk, self->client_ip, &ack);
	EXPECT_EQ(1, unit_list_length(&hsk.active_rpcs));
	EXPECT_STREQ("OUTGOING", homa_symbol_for_state(srpc));
	homa_sock_destroy(&hsk);
}

TEST_F(homa_rpc, homa_rpc_end__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 20000);

#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, self->homa.grant->num_grantable_rpcs);
#endif /* See strip.py */
	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	mock_log_rcu_sched = 1;
	homa_rpc_end(crpc);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(0, self->homa.grant->num_grantable_rpcs);
#endif /* See strip.py */
	EXPECT_EQ(NULL, homa_rpc_find_client(&self->hsk, crpc->id));
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(1, unit_list_length(&self->hsk.dead_rpcs));
}
TEST_F(homa_rpc, homa_rpc_end__already_dead)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 100);

	ASSERT_NE(NULL, crpc);
	unit_log_clear();
	homa_rpc_end(crpc);
	EXPECT_STREQ("homa_rpc_end invoked",
		unit_log_get());
	unit_log_clear();
	homa_rpc_end(crpc);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_rpc, homa_rpc_end__remove_from_ready_rpcs)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 100);

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_rpcs));
	homa_rpc_end(crpc);
	EXPECT_EQ(0, unit_list_length(&self->hsk.ready_rpcs));
}
TEST_F(homa_rpc, homa_rpc_end__state_ready)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 100);

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_rpcs));
	homa_rpc_end(crpc);
	EXPECT_EQ(0, unit_list_length(&self->hsk.ready_rpcs));
}
TEST_F(homa_rpc, homa_rpc_end__free_gaps)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, 99, 1000, 1000);

#ifndef __STRIP__ /* See strip.py */
	homa_message_in_init(crpc, 10000, 0);
#else /* See strip.py */
	homa_message_in_init(crpc, 10000);
#endif /* See strip.py */
	unit_log_clear();
	self->data.seg.offset = htonl(1400);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 1400));

	self->data.seg.offset = htonl(4200);
	homa_add_packet(crpc, mock_skb_alloc(self->client_ip,
			&self->data.common, 1400, 4200));
	EXPECT_STREQ("start 0, end 1400; start 2800, end 4200",
			unit_print_gaps(crpc));

	homa_rpc_end(crpc);
	/* (Test infrastructure will complain if gaps aren't freed) */
}
TEST_F(homa_rpc, homa_rpc_end__dead_buffs)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 10000, 1000);

	ASSERT_NE(NULL, crpc1);
	homa_rpc_end(crpc1);
	EXPECT_EQ(9, self->homa.max_dead_buffs);
	EXPECT_EQ(9, self->hsk.dead_skbs);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2, 5000, 1000);
	ASSERT_NE(NULL, crpc2);
	homa_rpc_end(crpc2);
	EXPECT_EQ(14, self->homa.max_dead_buffs);
	EXPECT_EQ(14, self->hsk.dead_skbs);
}
TEST_F(homa_rpc, homa_rpc_end__remove_from_throttled_list)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 10000, 1000);

	homa_pacer_manage_rpc(crpc);
	EXPECT_EQ(1, unit_list_length(&self->homa.pacer->throttled_rpcs));
	unit_log_clear();
	homa_rpc_end(crpc);
	EXPECT_EQ(0, unit_list_length(&self->homa.pacer->throttled_rpcs));
}

TEST_F(homa_rpc, homa_rpc_reap__basics)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 2000);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2, 5000, 100);
	struct homa_rpc *crpc3 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id+4, 2000, 100);

	ASSERT_NE(NULL, crpc1);
	ASSERT_NE(NULL, crpc2);
	ASSERT_NE(NULL, crpc3);
	homa_rpc_end(crpc1);
	homa_rpc_end(crpc2);
	homa_rpc_end(crpc3);
	unit_log_clear();
	EXPECT_STREQ("1234 1236 1238", dead_rpcs(&self->hsk));
	EXPECT_EQ(11, self->hsk.dead_skbs);
	unit_log_clear();
	self->homa.reap_limit = 7;
	EXPECT_EQ(1, homa_rpc_reap(&self->hsk, false));
	EXPECT_STREQ("reaped 1234", unit_log_get());
	unit_log_clear();
	EXPECT_STREQ("1236 1238", dead_rpcs(&self->hsk));
	EXPECT_EQ(3, self->hsk.dead_skbs);
}
TEST_F(homa_rpc, homa_rpc_reap__reap_all)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 2000);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2, 20000, 100);

	ASSERT_NE(NULL, crpc1);
	ASSERT_NE(NULL, crpc2);
	homa_rpc_end(crpc1);
	homa_rpc_end(crpc2);
	unit_log_clear();
	EXPECT_STREQ("1234 1236", dead_rpcs(&self->hsk));
	self->homa.reap_limit = 3;
	unit_log_clear();
	EXPECT_EQ(0, homa_rpc_reap(&self->hsk, true));
	EXPECT_STREQ("reaped 1234; reaped 1236", unit_log_get());
	unit_log_clear();
	EXPECT_STREQ("", dead_rpcs(&self->hsk));
	EXPECT_EQ(0, self->hsk.dead_skbs);
}
TEST_F(homa_rpc, homa_rpc_reap__protected)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 2000);

	ASSERT_NE(NULL, crpc1);
	homa_rpc_end(crpc1);
	unit_log_clear();
	homa_protect_rpcs(&self->hsk);
	EXPECT_EQ(0, homa_rpc_reap(&self->hsk, false));
	homa_unprotect_rpcs(&self->hsk);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_rpc, homa_rpc_reap__protected_and_reap_all)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 2000);

	ASSERT_NE(NULL, crpc1);
	homa_rpc_end(crpc1);
	unit_log_clear();
	homa_protect_rpcs(&self->hsk);
	hook_hsk = &self->hsk;
	unit_hook_register(unprotect_hsk_hook);
	EXPECT_EQ(0, homa_rpc_reap(&self->hsk, true));
	EXPECT_STREQ("reaped 1234", unit_log_get());
	EXPECT_EQ(0, self->hsk.dead_skbs);
}
TEST_F(homa_rpc, homa_rpc_reap__skip_rpc_because_locked)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 2000);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2, 1000, 2000);

	ASSERT_NE(NULL, crpc1);
	ASSERT_NE(NULL, crpc2);
	homa_rpc_end(crpc1);
	homa_rpc_end(crpc2);
	unit_log_clear();
	self->homa.reap_limit = 3;
#ifndef __STRIP__ /* See strip.py */
	mock_trylock_errors = 2;
#else /* See strip.py */
	mock_trylock_errors = 1;
#endif /* See strip.py */
	EXPECT_EQ(1, homa_rpc_reap(&self->hsk, false));
	EXPECT_STREQ("reaped 1236", unit_log_get());
	IF_NO_STRIP(EXPECT_EQ(1, homa_metrics_per_cpu()->deferred_rpc_reaps));
	unit_log_clear();
	EXPECT_EQ(0, homa_rpc_reap(&self->hsk, false));
	IF_NO_STRIP(EXPECT_EQ(1, homa_metrics_per_cpu()->deferred_rpc_reaps));
	EXPECT_STREQ("reaped 1234", unit_log_get());
}
TEST_F(homa_rpc, homa_rpc_reap__skip_rpc_because_of_refs)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 1000, 2000);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2, 1000, 2000);

	ASSERT_NE(NULL, crpc1);
	ASSERT_NE(NULL, crpc2);
	homa_rpc_end(crpc1);
	homa_rpc_end(crpc2);
	unit_log_clear();
	homa_rpc_hold(crpc1);
	self->homa.reap_limit = 3;
	EXPECT_EQ(1, homa_rpc_reap(&self->hsk, false));
	EXPECT_STREQ("reaped 1236", unit_log_get());
	IF_NO_STRIP(EXPECT_EQ(1, homa_metrics_per_cpu()->deferred_rpc_reaps));
	unit_log_clear();
	EXPECT_EQ(0, homa_rpc_reap(&self->hsk, false));
	IF_NO_STRIP(EXPECT_EQ(2, homa_metrics_per_cpu()->deferred_rpc_reaps));
	EXPECT_STREQ("", unit_log_get());
	homa_rpc_put(crpc1);
	EXPECT_EQ(0, homa_rpc_reap(&self->hsk, false));
	EXPECT_STREQ("reaped 1234", unit_log_get());
	IF_NO_STRIP(EXPECT_EQ(2, homa_metrics_per_cpu()->deferred_rpc_reaps));
}
TEST_F(homa_rpc, homa_rpc_reap__hit_limit_in_msgout_packets)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_MSG, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 10000, 100);

	ASSERT_NE(NULL, crpc);
	homa_rpc_end(crpc);
	EXPECT_EQ(9, self->hsk.dead_skbs);
	unit_log_clear();
	self->homa.reap_limit = 5;
	homa_rpc_reap(&self->hsk, false);
	EXPECT_STREQ("1234", dead_rpcs(&self->hsk));
	EXPECT_EQ(4, self->hsk.dead_skbs);
}
TEST_F(homa_rpc, homa_rpc_reap__skb_memory_accounting)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			self->server_port, self->client_id, 5000, 2000);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->client_id+2, 5000, 100);

	ASSERT_NE(NULL, crpc1);
	ASSERT_NE(NULL, crpc2);
	crpc1->msgout.skb_memory = 2000;
	crpc2->msgout.skb_memory = 3000;
	homa_rpc_end(crpc1);
	homa_rpc_end(crpc2);
	unit_log_clear();
	EXPECT_STREQ("1234 1236", dead_rpcs(&self->hsk));
	refcount_set(&self->hsk.sock.sk_wmem_alloc, 5001);
	EXPECT_EQ(9, self->hsk.dead_skbs);
	unit_log_clear();
	self->homa.reap_limit = 7;
	EXPECT_EQ(1, homa_rpc_reap(&self->hsk, false));
	EXPECT_STREQ("reaped 1234", unit_log_get());
	unit_log_clear();
	EXPECT_STREQ("1236", dead_rpcs(&self->hsk));
	EXPECT_EQ(1, self->hsk.dead_skbs);
	EXPECT_EQ(3001, refcount_read(&self->hsk.sock.sk_wmem_alloc));
}
TEST_F(homa_rpc, homa_rpc_reap__release_buffers)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			4000, 98, 1000,	150000);
	struct homa_pool *pool = self->hsk.buffer_pool;

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(1, atomic_read(&pool->descriptors[1].refs));
	homa_rpc_end(crpc);
	EXPECT_EQ(1, atomic_read(&pool->descriptors[1].refs));
	self->hsk.buffer_pool->check_waiting_invoked = 0;
	self->homa.reap_limit = 5;
	homa_rpc_reap(&self->hsk, false);
	EXPECT_EQ(0, atomic_read(&pool->descriptors[1].refs));
	EXPECT_EQ(1, self->hsk.buffer_pool->check_waiting_invoked);
}
TEST_F(homa_rpc, homa_rpc_reap__free_gaps)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			4000, 98, 1000,	150000);

	ASSERT_NE(NULL, crpc);
	homa_gap_alloc(&crpc->msgin.gaps, 1000, 2000);
	mock_clock = 1000;
	homa_gap_alloc(&crpc->msgin.gaps, 5000, 6000);

	EXPECT_STREQ("start 1000, end 2000; start 5000, end 6000, time 1000",
			unit_print_gaps(crpc));
	homa_rpc_end(crpc);
	self->homa.reap_limit = 5;
	homa_rpc_reap(&self->hsk, false);
	// Test framework will complain if memory not freed.
}
TEST_F(homa_rpc, homa_rpc_reap__release_peer_ref)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			4000, 98, 1000,	150000);
	struct homa_peer *peer;

	ASSERT_NE(NULL, crpc);
	peer = crpc->peer;
	EXPECT_EQ(1, atomic_read(&peer->refs));

	homa_rpc_end(crpc);
	homa_rpc_reap(&self->hsk, false);
	EXPECT_EQ(0, atomic_read(&peer->refs));
	EXPECT_EQ(NULL, crpc->peer);
}
TEST_F(homa_rpc, homa_rpc_reap__call_homa_sock_wakeup_wmem)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, self->client_ip, self->server_ip,
			4000, 98, 1000,	150000);

	ASSERT_NE(NULL, crpc);
	homa_rpc_end(crpc);
	set_bit(SOCK_NOSPACE, &self->hsk.sock.sk_socket->flags);
	homa_rpc_reap(&self->hsk, false);
	EXPECT_EQ(0, test_bit(SOCK_NOSPACE, &self->hsk.sock.sk_socket->flags));
}
TEST_F(homa_rpc, homa_rpc_reap__nothing_to_reap)
{
	EXPECT_EQ(0, homa_rpc_reap(&self->hsk, false));
}

TEST_F(homa_rpc, homa_rpc_find_client)
{
	struct homa_rpc *crpc1, *crpc2, *crpc3, *crpc4;

	atomic64_set(&self->homa.next_outgoing_id, 3);
	crpc1 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id,
			10000, 1000);
	atomic64_set(&self->homa.next_outgoing_id, 3 + 3*HOMA_CLIENT_RPC_BUCKETS);
	crpc2 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id+2,
			10000, 1000);
	atomic64_set(&self->homa.next_outgoing_id,
			3 + 10*HOMA_CLIENT_RPC_BUCKETS);
	crpc3 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id+4,
			10000, 1000);
	atomic64_set(&self->homa.next_outgoing_id, 40);
	crpc4 = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			self->server_ip, self->server_port, self->client_id+6,
			10000, 1000);

	EXPECT_EQ(crpc1, homa_rpc_find_client(&self->hsk, crpc1->id));
	homa_rpc_unlock(crpc1);
	EXPECT_EQ(crpc2, homa_rpc_find_client(&self->hsk, crpc2->id));
	homa_rpc_unlock(crpc2);
	EXPECT_EQ(crpc3, homa_rpc_find_client(&self->hsk, crpc3->id));
	homa_rpc_unlock(crpc3);
	EXPECT_EQ(crpc4, homa_rpc_find_client(&self->hsk, crpc4->id));
	homa_rpc_unlock(crpc4);
	EXPECT_EQ(NULL, homa_rpc_find_client(&self->hsk, 15));
	homa_rpc_end(crpc1);
	homa_rpc_end(crpc2);
	homa_rpc_end(crpc3);
	homa_rpc_end(crpc4);
}

TEST_F(homa_rpc, homa_rpc_find_server)
{
	struct homa_rpc *srpc1 = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id, 10000, 100);
	struct homa_rpc *srpc2 = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT,
			self->client_ip, self->server_ip, self->client_port,
			self->server_id + 30*HOMA_SERVER_RPC_BUCKETS,
			10000, 100);
	struct homa_rpc *srpc3 = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT,
			self->client_ip, self->server_ip, self->client_port+1,
			self->server_id + 10*HOMA_SERVER_RPC_BUCKETS,
			10000, 100);
	struct homa_rpc *srpc4 = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT,
			self->client_ip, self->server_ip, self->client_port+1,
			self->server_id + 4, 10000, 100);

	ASSERT_NE(NULL, srpc1);
	ASSERT_NE(NULL, srpc2);
	ASSERT_NE(NULL, srpc3);
	ASSERT_NE(NULL, srpc4);
	EXPECT_EQ(srpc1, homa_rpc_find_server(&self->hsk, self->client_ip,
		  srpc1->id));
	homa_rpc_unlock(srpc1);
	EXPECT_EQ(srpc2, homa_rpc_find_server(&self->hsk, self->client_ip,
		  srpc2->id));
	homa_rpc_unlock(srpc2);
	EXPECT_EQ(srpc3, homa_rpc_find_server(&self->hsk, self->client_ip,
		  srpc3->id));
	homa_rpc_unlock(srpc3);
	EXPECT_EQ(srpc4, homa_rpc_find_server(&self->hsk, self->client_ip,
		  srpc4->id));
	homa_rpc_unlock(srpc4);
	EXPECT_EQ(NULL, homa_rpc_find_server(&self->hsk, self->client_ip, 3));
}
