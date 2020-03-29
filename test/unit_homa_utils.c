/* Copyright (c) 2019-2020, Stanford University
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

#define n(x) htons(x)
#define N(x) htonl(x)

FIXTURE(homa_utils) {
	__be32 client_ip;
	int client_port;
	__be32 server_ip;
	int server_port;
	__u64 rpcid;
	struct homa homa;
	struct homa_sock hsk;
	struct sockaddr_in server_addr;
	struct data_header data;
	struct homa_rpc *crpc;
};
FIXTURE_SETUP(homa_utils)
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
	                .dport = htons(self->server_port),
			.type = DATA, .id = self->rpcid},
			.message_length = htonl(10000),
			.incoming = htonl(10000), .cutoff_version = 0,
		        .retransmit = 0,
			.seg = {.offset = 0}};
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_utils)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

/**
 * set_cutoffs() - A convenience method to allow all of the values in
 * homa->unsched_cutoffs to be set concisely.
 * @homa:   Contains the unsched_cutoffs to be modified.
 * @c0:     New value for homa->unsched_cutoffs[0]
 * @c1:     New value for homa->unsched_cutoffs[1]
 * @c2:     New value for homa->unsched_cutoffs[2]
 * @c3:     New value for homa->unsched_cutoffs[3]
 * @c4:     New value for homa->unsched_cutoffs[4]
 * @c5:     New value for homa->unsched_cutoffs[5]
 * @c6:     New value for homa->unsched_cutoffs[6]
 * @c7:     New value for homa->unsched_cutoffs[7]
 */
static void set_cutoffs(struct homa *homa, int c0, int c1, int c2, 
		int c3, int c4, int c5, int c6, int c7)
{
	homa->unsched_cutoffs[0] = c0;
	homa->unsched_cutoffs[1] = c1;
	homa->unsched_cutoffs[2] = c2;
	homa->unsched_cutoffs[3] = c3;
	homa->unsched_cutoffs[4] = c4;
	homa->unsched_cutoffs[5] = c5;
	homa->unsched_cutoffs[6] = c6;
	homa->unsched_cutoffs[7] = c7;
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

TEST_F(homa_utils, homa_rpc_new_client__normal)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, (char *) 2000, 10000);
	EXPECT_FALSE(IS_ERR(crpc));
	homa_rpc_free(crpc);
	homa_rpc_unlock(crpc);
}
TEST_F(homa_utils, homa_rpc_new_client__malloc_error)
{
	mock_kmalloc_errors = 1;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, (char *) 2000, 10000);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(ENOMEM, -PTR_ERR(crpc));
}
TEST_F(homa_utils, homa_rpc_new_client__route_error)
{
	mock_route_errors = 1;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, (char *) 2000, 10000);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(EHOSTUNREACH, -PTR_ERR(crpc));
}
TEST_F(homa_utils, homa_rpc_new_client__msgout_init_error)
{
	mock_alloc_skb_errors = 1;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, (char *) 2000, 10000);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(ENOMEM, -PTR_ERR(crpc));
}
TEST_F(homa_utils, homa_rpc_new_client__socket_shutdown)
{
	self->hsk.shutdown = 1;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, (char *) 2000, 10000);
	EXPECT_TRUE(IS_ERR(crpc));
	EXPECT_EQ(ESHUTDOWN, -PTR_ERR(crpc));
	self->hsk.shutdown = 1;
}

TEST_F(homa_utils, homa_rpc_new_server__normal)
{
	struct homa_rpc *srpc = homa_rpc_new_server(&self->hsk,
			self->client_ip, &self->data);
	EXPECT_FALSE(IS_ERR(srpc));
	homa_rpc_unlock(srpc);
	self->data.message_length = N(1600);
	homa_data_pkt(mock_skb_new(self->client_ip, &self->data.common,
			1400, 0), srpc);
	EXPECT_EQ(RPC_INCOMING, srpc->state);
	EXPECT_EQ(1, unit_list_length(&self->hsk.active_rpcs));
	homa_rpc_free(srpc);
}
TEST_F(homa_utils, homa_rpc_new_server__already_exists)
{
	struct homa_rpc *srpc1 = homa_rpc_new_server(&self->hsk,
			self->client_ip, &self->data);
	EXPECT_FALSE(IS_ERR(srpc1));
	if (srpc1->active_links.next == LIST_POISON1)
		list_add_tail_rcu(&srpc1->active_links,
				&srpc1->hsk->active_rpcs);
	homa_rpc_unlock(srpc1);
	self->data.common.id += HOMA_SERVER_RPC_BUCKETS;
	struct homa_rpc *srpc2 = homa_rpc_new_server(&self->hsk,
			self->client_ip, &self->data);
	EXPECT_FALSE(IS_ERR(srpc2));
	if (srpc2->active_links.next == LIST_POISON1)
		list_add_tail_rcu(&srpc2->active_links,
				&srpc2->hsk->active_rpcs);
	homa_rpc_unlock(srpc2);
	EXPECT_NE(srpc2, srpc1);
	self->data.common.id -= HOMA_SERVER_RPC_BUCKETS;
	struct homa_rpc *srpc3 = homa_rpc_new_server(&self->hsk,
			self->client_ip, &self->data);
	EXPECT_FALSE(IS_ERR(srpc3));
	if (srpc3->active_links.next == LIST_POISON1)
		list_add_tail_rcu(&srpc3->active_links,
				&srpc3->hsk->active_rpcs);
	homa_rpc_unlock(srpc3);
	EXPECT_EQ(srpc3, srpc1);
}
TEST_F(homa_utils, homa_rpc_new_server__malloc_error)
{
	mock_kmalloc_errors = 1;
	struct homa_rpc *srpc = homa_rpc_new_server(&self->hsk,
			self->client_ip, &self->data);
	EXPECT_TRUE(IS_ERR(srpc));
	EXPECT_EQ(ENOMEM, -PTR_ERR(srpc));
}
TEST_F(homa_utils, homa_rpc_new_server__addr_error)
{
	mock_route_errors = 1;
	struct homa_rpc *srpc = homa_rpc_new_server(&self->hsk,
			self->client_ip, &self->data);
	EXPECT_TRUE(IS_ERR(srpc));
	EXPECT_EQ(EHOSTUNREACH, -PTR_ERR(srpc));
}

TEST_F(homa_utils, homa_rpc_lock_slow)
{
	mock_cycles = ~0;
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, (char *) 2000, 10000);
	homa_rpc_free(crpc);
	homa_rpc_unlock(crpc);
	struct homa_rpc *srpc = homa_rpc_new_server(&self->hsk,
			self->client_ip, &self->data);
	EXPECT_FALSE(IS_ERR(srpc));
	list_add_tail_rcu(&srpc->active_links, &srpc->hsk->active_rpcs);
	homa_rpc_unlock(srpc);
	
	EXPECT_EQ(0, homa_cores[cpu_number]->metrics.client_lock_misses);
	EXPECT_EQ(0, homa_cores[cpu_number]->metrics.client_lock_miss_cycles);
	homa_rpc_lock_slow(crpc);
	homa_rpc_unlock(crpc);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.client_lock_misses);
	EXPECT_NE(0, homa_cores[cpu_number]->metrics.client_lock_miss_cycles);
	EXPECT_EQ(0, homa_cores[cpu_number]->metrics.server_lock_misses);
	EXPECT_EQ(0, homa_cores[cpu_number]->metrics.server_lock_miss_cycles);
	homa_rpc_lock_slow(srpc);
	homa_rpc_unlock(srpc);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.server_lock_misses);
	EXPECT_NE(0, homa_cores[cpu_number]->metrics.server_lock_miss_cycles);
	
}

TEST_F(homa_utils, homa_rpc_free__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 1000, 20000);
	EXPECT_EQ(1, unit_list_length(&self->homa.grantable_rpcs));
	EXPECT_NE(NULL, crpc);
	unit_log_clear();
	mock_log_rcu_sched = 1;
	homa_rpc_free(crpc);
	EXPECT_STREQ("homa_remove_from_grantable invoked",
			unit_log_get());
	EXPECT_EQ(0, unit_list_length(&self->homa.grantable_rpcs));
	EXPECT_EQ(NULL, homa_find_client_rpc(&self->hsk, crpc->id));
	EXPECT_EQ(0, unit_list_length(&self->hsk.active_rpcs));
	EXPECT_EQ(1, unit_list_length(&self->hsk.dead_rpcs));
}
TEST_F(homa_utils, homa_rpc_free__already_dead)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 1000, 100);
	unit_log_clear();
	homa_rpc_free(crpc);
	EXPECT_STREQ("homa_remove_from_grantable invoked",
		unit_log_get());
	unit_log_clear();
	homa_rpc_free(crpc);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_utils, homa_rpc_free__state_ready)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_READY, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 1000, 100);
	EXPECT_EQ(1, unit_list_length(&self->hsk.ready_responses));
	homa_rpc_free(crpc);
	EXPECT_EQ(0, unit_list_length(&self->hsk.ready_responses));
}
TEST_F(homa_utils, homa_rpc_free__wakeup_interest)
{
	struct homa_interest interest;
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 1000, 100);
	atomic_long_set(&interest.id, 0);
	interest.reg_rpc = crpc;
	crpc->interest = &interest;
	unit_log_clear();
	homa_rpc_free(crpc);
	EXPECT_EQ(NULL, interest.reg_rpc);
	EXPECT_STREQ("homa_remove_from_grantable invoked; wake_up_process",
		unit_log_get());
}
TEST_F(homa_utils, homa_rpc_free__remove_from_throttled_list)
{
	struct homa_rpc *crpc = homa_rpc_new_client(&self->hsk,
			&self->server_addr, (char *) 2000, 5000);
	EXPECT_NE(NULL, crpc);
	homa_rpc_unlock(crpc);
	homa_add_to_throttled(crpc);
	EXPECT_EQ(1, unit_list_length(&self->homa.throttled_rpcs));
	unit_log_clear();
	homa_rpc_free(crpc);
	EXPECT_EQ(0, unit_list_length(&self->homa.throttled_rpcs));
}

TEST_F(homa_utils, homa_rpc_free_rcu)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 1000, 20000);
	homa_rpc_free(crpc);
	EXPECT_EQ(RPC_DEAD, crpc->state);
}

TEST_F(homa_utils, homa_rpc_reap__basics)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 5000, 2000);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid+1, 5000, 100);
	struct homa_rpc *crpc3 = unit_client_rpc(&self->hsk,
			RPC_OUTGOING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid+2, 2000, 100);
	homa_rpc_free(crpc1);
	homa_rpc_free(crpc2);
	homa_rpc_free(crpc3);
	unit_log_clear();
	EXPECT_STREQ("12345 12346 12347", dead_rpcs(&self->hsk));
	EXPECT_EQ(11, self->hsk.dead_skbs);
	unit_log_clear();
	self->homa.reap_limit = 7;
	EXPECT_EQ(1, homa_rpc_reap(&self->hsk));
	EXPECT_STREQ("reaped 12345", unit_log_get());
	unit_log_clear();
	EXPECT_STREQ("12346 12347", dead_rpcs(&self->hsk));
	EXPECT_EQ(4, self->hsk.dead_skbs);
}
TEST_F(homa_utils, homa_rpc_reap__reap_disabled)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 5000, 2000);
	homa_rpc_free(crpc1);
	unit_log_clear();
	atomic_inc(&self->hsk.reap_disable);
	EXPECT_EQ(-1, homa_rpc_reap(&self->hsk));
	atomic_dec(&self->hsk.reap_disable);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_utils, homa_rpc_reap__dont_reap_flag)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid, 1000, 2000);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			RPC_INCOMING, self->client_ip, self->server_ip,
			self->server_port, self->rpcid+1, 1000, 2000);
	homa_rpc_free(crpc1);
	homa_rpc_free(crpc2);
	unit_log_clear();
	self->homa.reap_limit = 3;
	crpc1->dont_reap = true;
	EXPECT_EQ(1, homa_rpc_reap(&self->hsk));
	EXPECT_STREQ("reaped 12346", unit_log_get());
	unit_log_clear();
	EXPECT_EQ(0, homa_rpc_reap(&self->hsk));
	EXPECT_STREQ("", unit_log_get());
	crpc1->dont_reap = false;
	EXPECT_EQ(1, homa_rpc_reap(&self->hsk));
	EXPECT_STREQ("reaped 12345", unit_log_get());
}
TEST_F(homa_utils, homa_rpc_reap__hit_limit_in_msgin_packets)
{
	struct homa_rpc *srpc1 = unit_server_rpc(&self->hsk, RPC_READY,
			self->client_ip, self->server_ip, self->client_port,
			41, 10000, 100);
	homa_rpc_free(srpc1);
	EXPECT_EQ(8, self->hsk.dead_skbs);
	unit_log_clear();
	self->homa.reap_limit = 5;
	homa_rpc_reap(&self->hsk);
	EXPECT_STREQ("41", dead_rpcs(&self->hsk));
	EXPECT_EQ(3, self->hsk.dead_skbs);
}
TEST_F(homa_utils, homa_rpc_reap__nothing_to_reap)
{
	EXPECT_EQ(0, homa_rpc_reap(&self->hsk));
}

TEST_F(homa_utils, homa_find_client_rpc)
{
	atomic64_set(&self->homa.next_outgoing_id, 3);
	struct homa_rpc *crpc1 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, (char *) 2000, 1000);
	EXPECT_FALSE(IS_ERR(crpc1));
	homa_rpc_unlock(crpc1);
	atomic64_set(&self->homa.next_outgoing_id, 3 + 3*HOMA_CLIENT_RPC_BUCKETS);
	struct homa_rpc *crpc2 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, (char *) 2000, 1000);
	EXPECT_FALSE(IS_ERR(crpc2));
	homa_rpc_unlock(crpc2);
	atomic64_set(&self->homa.next_outgoing_id,
			3 + 10*HOMA_CLIENT_RPC_BUCKETS);
	struct homa_rpc *crpc3 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, (char *) 2000, 1000);
	EXPECT_FALSE(IS_ERR(crpc3));
	homa_rpc_unlock(crpc3);
	atomic64_set(&self->homa.next_outgoing_id, 40);
	struct homa_rpc *crpc4 = homa_rpc_new_client(&self->hsk,
			&self->server_addr, (char *) 2000, 1000);
	EXPECT_FALSE(IS_ERR(crpc4));
	homa_rpc_unlock(crpc4);
	EXPECT_EQ(crpc1, homa_find_client_rpc(&self->hsk, crpc1->id));
	homa_rpc_unlock(crpc1);
	EXPECT_EQ(crpc2, homa_find_client_rpc(&self->hsk, crpc2->id));
	homa_rpc_unlock(crpc2);
	EXPECT_EQ(crpc3, homa_find_client_rpc(&self->hsk, crpc3->id));
	homa_rpc_unlock(crpc3);
	EXPECT_EQ(crpc4, homa_find_client_rpc(&self->hsk, crpc4->id));
	homa_rpc_unlock(crpc4);
	EXPECT_EQ(NULL, homa_find_client_rpc(&self->hsk, 15));
	homa_rpc_free(crpc1);
	homa_rpc_free(crpc2);
	homa_rpc_free(crpc3);
	homa_rpc_free(crpc4);
}

TEST_F(homa_utils, homa_find_server_rpc)
{
	struct homa_rpc *srpc1 = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			41, 10000, 100);
	EXPECT_NE(NULL, srpc1);
	struct homa_rpc *srpc2 = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port,
			41 + 15*HOMA_SERVER_RPC_BUCKETS, 10000, 100);
	EXPECT_NE(NULL, srpc2);
	struct homa_rpc *srpc3 = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port+1,
			41 + 5*HOMA_SERVER_RPC_BUCKETS, 10000, 100);
	EXPECT_NE(NULL, srpc3);
	struct homa_rpc *srpc4 = unit_server_rpc(&self->hsk, RPC_INCOMING,
			self->client_ip, self->server_ip, self->client_port+1,
			17, 10000, 100);
	EXPECT_NE(NULL, srpc4);
	EXPECT_EQ(srpc1, homa_find_server_rpc(&self->hsk, self->client_ip,
			self->client_port, srpc1->id));
	homa_rpc_unlock(srpc1);
	EXPECT_EQ(srpc2, homa_find_server_rpc(&self->hsk, self->client_ip,
			self->client_port, srpc2->id));
	homa_rpc_unlock(srpc2);
	EXPECT_EQ(srpc3, homa_find_server_rpc(&self->hsk, self->client_ip,
			self->client_port+1, srpc3->id));
	homa_rpc_unlock(srpc3);
	EXPECT_EQ(srpc4, homa_find_server_rpc(&self->hsk, self->client_ip,
			self->client_port+1, srpc4->id));
	homa_rpc_unlock(srpc4);
	EXPECT_EQ(NULL, homa_find_server_rpc(&self->hsk, self->client_ip,
			self->client_port, 3));
}

TEST_F(homa_utils, homa_print_ipv4_addr)
{
	char *p1, *p2;
	int i;
	
	p1 = homa_print_ipv4_addr(unit_get_in_addr("192.168.0.1"));
	p2 = homa_print_ipv4_addr(htonl((1<<24) + (2<<16) + (3<<8) + 4));
	EXPECT_STREQ("192.168.0.1", p1);
	EXPECT_STREQ("1.2.3.4", p2);
	
	/* Make sure buffers eventually did reused. */
	for (i = 0; i < 20; i++)
		homa_print_ipv4_addr(unit_get_in_addr("5.6.7.8"));
	EXPECT_STREQ("5.6.7.8", p1);
}

TEST_F(homa_utils, homa_snprintf)
{
	char buffer[50];
	int used = 0;
	used = homa_snprintf(buffer, sizeof32(buffer), used,
			"Test message with values: %d and %d", 100, 1000);
	EXPECT_EQ(38, used);
	EXPECT_STREQ("Test message with values: 100 and 1000", buffer);
	
	used = homa_snprintf(buffer, sizeof32(buffer), used,
			"; plus: %d", 123456);
	EXPECT_EQ(49, used);
	EXPECT_STREQ("Test message with values: 100 and 1000; plus: 123",
			buffer);
	
	used = homa_snprintf(buffer, sizeof32(buffer), used,
			"more text, none of which fits");
	EXPECT_EQ(49, used);
	EXPECT_STREQ("Test message with values: 100 and 1000; plus: 123",
			buffer);
}

TEST_F(homa_utils, homa_append_metric)
{
	self->homa.metrics_length = 0;
	homa_append_metric(&self->homa,  "x: %d, y: %d", 10, 20);
	EXPECT_EQ(12, self->homa.metrics_length);
	EXPECT_STREQ("x: 10, y: 20", self->homa.metrics);
	
	homa_append_metric(&self->homa, ", z: %d", 12345);
	EXPECT_EQ(22, self->homa.metrics_length);
	EXPECT_STREQ("x: 10, y: 20, z: 12345", self->homa.metrics);
	EXPECT_EQ(30, self->homa.metrics_capacity);
	
	homa_append_metric(&self->homa, ", q: %050d", 88);
	EXPECT_EQ(77, self->homa.metrics_length);
	EXPECT_STREQ("x: 10, y: 20, z: 12345, "
			"q: 00000000000000000000000000000000000000000000000088",
			self->homa.metrics);
	EXPECT_EQ(120, self->homa.metrics_capacity);
}

TEST_F(homa_utils, homa_prios_changed__basics)
{
	set_cutoffs(&self->homa, 90, 80, 10000000, 60, 50, 40, 30, 0);
	self->homa.num_priorities = 6;
	homa_prios_changed(&self->homa);
	EXPECT_EQ(0, self->homa.unsched_cutoffs[6]);
	EXPECT_EQ(40, self->homa.unsched_cutoffs[5]);
	EXPECT_EQ(60, self->homa.unsched_cutoffs[3]);
	EXPECT_EQ(10000000, self->homa.unsched_cutoffs[2]);
	EXPECT_EQ(80, self->homa.unsched_cutoffs[1]);
	EXPECT_EQ(INT_MAX, self->homa.unsched_cutoffs[0]);
	EXPECT_EQ(1, self->homa.max_sched_prio);
	EXPECT_EQ(1, self->homa.cutoff_version);
}
TEST_F(homa_utils, homa_prios_changed__num_priorities_too_large)
{
	self->homa.num_priorities = 100;
	homa_prios_changed(&self->homa);
	EXPECT_EQ(8, self->homa.num_priorities);
}
TEST_F(homa_utils, homa_prios_changed__share_lowest_priority)
{
	set_cutoffs(&self->homa, 90, 80, 70, 60, 50, 40, 30, 0);
	self->homa.num_priorities = 7;
	homa_prios_changed(&self->homa);
	EXPECT_EQ(30, self->homa.unsched_cutoffs[6]);
	EXPECT_EQ(80, self->homa.unsched_cutoffs[1]);
	EXPECT_EQ(0x7fffffff, self->homa.unsched_cutoffs[0]);
	EXPECT_EQ(0, self->homa.max_sched_prio);
}