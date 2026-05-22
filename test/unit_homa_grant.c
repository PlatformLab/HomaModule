// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

#include "homa_impl.h"
#include "homa_grant.h"
#include "homa_pacer.h"
#include "homa_peer.h"
#include "homa_pool.h"
#include "homa_rpc.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

char *rpc_ids(struct homa_rpc **rpcs, int count)
{
	static char buffer[1000];
	size_t length = 0;
	int i;

	for (i = 0; i < count; i++) {
		if (length != 0)
			length += snprintf(buffer + length,
					sizeof(buffer) - length, " ");
		length += snprintf(buffer + length, sizeof(buffer) - length,
				"%lld", rpcs[i]->id);
	}
	return buffer;
}

static int hook_spinlock_count;
static void grant_spinlock_hook(char *id)
{
	if (strcmp(id, "spin_lock") != 0)
		return;
	mock_clock = 1000;
	hook_spinlock_count++;
}

static int hook_spinlock2_count;
static struct homa_rpc *hook_spinlock2_rpc;
static bool hook_spinlock2_manage;
static void grant_spinlock2_hook(char *id)
{
	if (strcmp(id, "spin_lock") != 0)
		return;
	hook_spinlock2_count--;
	if (hook_spinlock2_count != 0)
		return;
	homa_rpc_lock(hook_spinlock2_rpc);
	if (hook_spinlock2_manage)
		homa_grant_manage_rpc(hook_spinlock2_rpc->hsk->homa->grant,
				      hook_spinlock2_rpc);
	else
		homa_rpc_end(hook_spinlock2_rpc);
	homa_rpc_unlock(hook_spinlock2_rpc);
}

static int hook_spinlock3_count;
static struct homa_grant *hook_spinlock3_grant;
static void grant_spinlock_hook3(char *id)
{
	if (strcmp(id, "spin_lock") != 0)
		return;
	hook_spinlock3_count--;
	if (hook_spinlock3_count != 0)
		return;
	hook_spinlock3_grant->needy_active = 0;
}

FIXTURE(homa_grant) {
	struct in6_addr client_ip[5];
	int client_port;
	struct in6_addr server_ip[5];
	int server_port;
	u64 client_id;
	u64 server_id;
	union sockaddr_in_union server_addr;
	struct homa homa;
	struct homa_net *hnet;
	struct homa_sock hsk;
	struct homa_data_hdr data;
	int incoming_delta;
};
FIXTURE_SETUP(homa_grant)
{
	int i;

	self->client_ip[0] = unit_get_in_addr("196.168.0.1");
	self->client_ip[1] = unit_get_in_addr("197.168.0.1");
	self->client_ip[2] = unit_get_in_addr("198.168.0.1");
	self->client_ip[3] = unit_get_in_addr("199.168.0.1");
	self->client_ip[4] = unit_get_in_addr("200.168.0.1");
	self->client_port = 40000;
	self->server_ip[0] = unit_get_in_addr("1.2.3.4");
	self->server_ip[1] = unit_get_in_addr("2.2.3.4");
	self->server_ip[2] = unit_get_in_addr("3.2.3.4");
	self->server_ip[3] = unit_get_in_addr("4.2.3.4");
	self->server_ip[4] = unit_get_in_addr("5.2.3.4");
	self->server_port = 99;
	self->client_id = 1234;
	self->server_id = 1235;
	homa_init(&self->homa);
	self->hnet = mock_hnet(0, &self->homa);
	self->homa.num_priorities = 1;
	self->homa.poll_cycles = 0;
	self->homa.flags |= HOMA_FLAG_DONT_THROTTLE;
	self->homa.qshared->fifo_fraction = 0;
	self->homa.grant->fifo_fraction = 0;
	self->homa.grant->window = 1200;
	for (i = 0; i < HOMA_MAX_GRANTS; i++)
		self->homa.grant->windows[i] = 1200;
	self->homa.grant->max_incoming = 50000;
	mock_sock_init(&self->hsk, self->hnet, 0);
	self->server_addr.in6.sin6_family = self->hsk.inet.sk.sk_family;
	self->server_addr.in6.sin6_addr = self->server_ip[0];
	self->server_addr.in6.sin6_port =  htons(self->server_port);
	memset(&self->data, 0, sizeof(self->data));
	self->data.common = (struct homa_common_hdr){
		.sport = htons(self->client_port),
		.dport = htons(self->server_port),
		.type = DATA,
		.sender_id = cpu_to_be64(self->client_id)
	};
	self->data.message_length = htonl(10000);
	self->data.incoming = htonl(10000);
	unit_log_clear();
	self->incoming_delta = 0;
}
FIXTURE_TEARDOWN(homa_grant)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

/* Create a client RPC whose msgin is initialized but homa_grant_manage_rpc
 * hasn't been called.
 */
static struct homa_rpc *test_rpc(FIXTURE_DATA(homa_grant) *self,
		u64 id, struct in6_addr *server_ip, int size)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, server_ip, self->server_port,
			id, 1000, size);

	homa_rpc_lock(rpc);
	homa_message_in_init(rpc, size, 0);
	homa_rpc_unlock(rpc);
	return rpc;
}

/* Create a client RPC whose msgin is properly initialized with no
 * unscheduled bytes and no packets received (homa_grant_manage_rpc
 * will have been called).
 */
static struct homa_rpc *test_rpc_mngd(FIXTURE_DATA(homa_grant) *self,
		u64 id, struct in6_addr *server_ip, int size)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, server_ip, self->server_port,
			id, 1000, size);
	homa_rpc_lock(rpc);
	homa_message_in_init(rpc, size, 0);
	homa_grant_manage_rpc(rpc->hsk->homa->grant, rpc);
	homa_rpc_unlock(rpc);
	return rpc;
}

TEST_F(homa_grant, homa_grant_alloc__success)
{
	struct homa_grant *grant;

	grant = homa_grant_alloc(&self->homa);
	EXPECT_EQ(-1, grant->active_remaining[0]);
	EXPECT_EQ(-1, grant->active_remaining[HOMA_MAX_GRANTS - 1]);
	EXPECT_EQ(50, grant->fifo_fraction);
	homa_grant_free(grant);
}
TEST_F(homa_grant, homa_grant_alloc__cant_allocate_memory)
{
	struct homa_grant *grant;

	mock_kmalloc_errors = 1;
	grant = homa_grant_alloc(&self->homa);
	EXPECT_TRUE(IS_ERR(grant));
	EXPECT_EQ(ENOMEM, -PTR_ERR(grant));
}
TEST_F(homa_grant, homa_grant_alloc__cant_register_sysctls)
{
	struct homa_grant *grant;

	mock_register_sysctl_errors = 1;
	grant = homa_grant_alloc(&self->homa);
	EXPECT_TRUE(IS_ERR(grant));
	EXPECT_EQ(ENOMEM, -PTR_ERR(grant));
}

TEST_F(homa_grant, homa_grant_free__basics)
{
	struct homa_grant *grant;

	grant = homa_grant_alloc(&self->homa);
	homa_grant_free(grant);
	EXPECT_STREQ("unregister_net_sysctl_table", unit_log_get());
}
TEST_F(homa_grant, homa_grant_free__sysctls_not_registered)
{
	struct homa_grant *grant;

	grant = homa_grant_alloc(&self->homa);
	grant->sysctl_header = NULL;
	homa_grant_free(grant);
	EXPECT_STREQ("", unit_log_get());
}

TEST_F(homa_grant, homa_grant_init_rpc__rpc_needs_grants)
{
	struct homa_rpc *rpc;

	rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
		              self->server_ip, self->server_port, 100, 1000,
			      20000);
	homa_message_in_init(rpc, 2000, 800);
	EXPECT_EQ(1, test_bit(RPC_GRANTABLE, &rpc->flags));
}
TEST_F(homa_grant, homa_grant_init_rpc__unsched_past_end_of_message)
{
	struct homa_rpc *rpc;

	rpc= unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
		              self->server_ip, self->server_port, 100, 1000,
			      20000);

	homa_rpc_lock(rpc);
	homa_message_in_init(rpc, 2000, 3000);
	homa_rpc_unlock(rpc);
	EXPECT_EQ(-1, rpc->msgin.active_ix);
	EXPECT_EQ(2000, rpc->msgin.granted);
	EXPECT_EQ(0, test_bit(RPC_GRANTABLE, &rpc->flags));
}

TEST_F(homa_grant, homa_grant_add_active)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	rpc= unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
		              self->server_ip, self->server_port, 100, 1000,
			      20000);

	homa_message_in_init(rpc, 20000, 2000);
	EXPECT_EQ(-1, rpc->msgin.active_ix);
	rpc->msgin.granted = 500;
	grant->windows[1] = 44444;
	homa_grant_add_active(grant, rpc, 3);
	EXPECT_STREQ("active[3]: id 100 remaining 20000",
		     unit_log_grantables(&self->homa));
	EXPECT_EQ(3, rpc->msgin.active_ix);
	EXPECT_EQ(20000, grant->active_remaining[3]);
	EXPECT_EQ(1, rpc->peer->active_rpcs);
	EXPECT_EQ(1, grant->num_active);
	EXPECT_EQ(44444, grant->window);
}
TEST_F(homa_grant, homa_grant_add_active__not_grantable)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	rpc= unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
		              self->server_ip, self->server_port, 100, 1000,
			      20000);

	homa_message_in_init(rpc, 20000, 2000);
	EXPECT_EQ(-1, rpc->msgin.active_ix);
	clear_bit(RPC_GRANTABLE, &rpc->flags);
	homa_grant_add_active(grant, rpc, 3);
	EXPECT_STREQ("", unit_log_grantables(&self->homa));
	EXPECT_EQ(-1, rpc->msgin.active_ix);
	set_bit(RPC_GRANTABLE, &rpc->flags);
}

TEST_F(homa_grant, homa_grant_remove_active)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	rpc= unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
		              self->server_ip, self->server_port, 100, 1000,
			      20000);

	homa_message_in_init(rpc, 20000, 2000);
	EXPECT_EQ(-1, rpc->msgin.active_ix);
	rpc->msgin.granted = 500;
	grant->windows[0] = 55555;
	homa_grant_add_active(grant, rpc, 3);
	EXPECT_STREQ("active[3]: id 100 remaining 20000",
		     unit_log_grantables(&self->homa));
	homa_grant_remove_active(grant, 3);
	EXPECT_EQ(-1, rpc->msgin.active_ix);
	EXPECT_EQ(-1, grant->active_remaining[3]);
	EXPECT_EQ(0, rpc->peer->active_rpcs);
	EXPECT_EQ(0, grant->num_active);
	EXPECT_EQ(55555, grant->window);
}

TEST_F(homa_grant, homa_grant_outranks)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3, *rpc4;

	mock_clock = 3000;
	rpc1 = test_rpc_mngd(self, 100, self->server_ip, 20000);
	mock_clock = 2000;
	rpc2 = test_rpc_mngd(self, 102, self->server_ip, 30000);
	mock_clock = 1999;
	rpc3 = test_rpc_mngd(self, 104, self->server_ip, 30000);
	mock_clock = 2000;
	rpc4 = test_rpc_mngd(self, 106, self->server_ip, 30000);

	EXPECT_EQ(1, homa_grant_outranks(rpc1, rpc2));
	EXPECT_EQ(0, homa_grant_outranks(rpc2, rpc1));
	EXPECT_EQ(0, homa_grant_outranks(rpc2, rpc3));
	EXPECT_EQ(1, homa_grant_outranks(rpc3, rpc2));
	EXPECT_EQ(0, homa_grant_outranks(rpc2, rpc4));
	EXPECT_EQ(0, homa_grant_outranks(rpc4, rpc2));
}

TEST_F(homa_grant, homa_grant_priority__no_extra_levels)
{
	self->homa.max_sched_prio = 6;
	self->homa.grant->num_active = 7;
	EXPECT_EQ(6, homa_grant_priority(&self->homa, 0));
	EXPECT_EQ(0, homa_grant_priority(&self->homa, 7));
}
TEST_F(homa_grant, homa_grant_priority__extra_levels)
{
	self->homa.max_sched_prio = 6;
	self->homa.grant->num_active = 4;
	EXPECT_EQ(3, homa_grant_priority(&self->homa, 0));
	EXPECT_EQ(0, homa_grant_priority(&self->homa, 7));
}

TEST_F(homa_grant, homa_grant_find_victim__empty_slot)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	homa_grant_add_active(grant,
			      test_rpc(self, 100, &self->server_ip[1], 30000), 0);
	homa_grant_add_active(grant,
			      test_rpc(self, 102, &self->server_ip[0], 20000), 1);
	rpc = test_rpc(self, 104, &self->server_ip[2], 10000);
	EXPECT_EQ(2, homa_grant_find_victim(grant, rpc));
}
TEST_F(homa_grant, homa_grant_find_victim__respect_max_overcommit)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	homa_grant_add_active(grant,
			      test_rpc(self, 100, &self->server_ip[0], 20000), 0);
	homa_grant_add_active(grant,
			      test_rpc(self, 102, &self->server_ip[1], 30000), 1);
	rpc = test_rpc(self, 104, &self->server_ip[2], 10000);

	grant->max_overcommit = 3;
	EXPECT_EQ(2, homa_grant_find_victim(grant, rpc));

	grant->max_overcommit = 2;
	EXPECT_EQ(1, homa_grant_find_victim(grant, rpc));

	grant->max_overcommit = 1;
	EXPECT_EQ(0, homa_grant_find_victim(grant, rpc));
}
TEST_F(homa_grant, homa_grant_find_victim__pick_lp_with_more_peer_active)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	homa_grant_add_active(grant,
			      test_rpc(self, 100, &self->server_ip[0], 60000), 0);
	homa_grant_add_active(grant,
			      test_rpc(self, 102, &self->server_ip[1], 50000), 1);
	homa_grant_add_active(grant,
			      test_rpc(self, 104, &self->server_ip[1], 40000), 2);
	grant->max_overcommit = 3;
	rpc = test_rpc(self, 106, &self->server_ip[2], 10000);
	EXPECT_EQ(1, homa_grant_find_victim(grant, rpc));
}
TEST_F(homa_grant, homa_grant_find_victim__skip_candidate_with_less_peer_active)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	homa_grant_add_active(grant,
			      test_rpc(self, 100, &self->server_ip[0], 40000), 0);
	homa_grant_add_active(grant,
			      test_rpc(self, 102, &self->server_ip[0], 50000), 1);
	homa_grant_add_active(grant,
			      test_rpc(self, 104, &self->server_ip[1], 60000), 2);
	grant->max_overcommit = 3;
	rpc = test_rpc(self, 106, &self->server_ip[2], 10000);
	EXPECT_EQ(1, homa_grant_find_victim(grant, rpc));
}
TEST_F(homa_grant, homa_grant_find_victim__candidate_has_same_peer_as_new_rpc)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	homa_grant_add_active(grant,
			      test_rpc(self, 100, &self->server_ip[0], 60000), 0);
	homa_grant_add_active(grant,
			      test_rpc(self, 102, &self->server_ip[1], 50000), 1);
	homa_grant_add_active(grant,
			      test_rpc(self, 100, &self->server_ip[2], 60000), 2);
	grant->max_overcommit = 3;
	rpc = test_rpc(self, 106, &self->server_ip[1], 10000);
	EXPECT_EQ(1, homa_grant_find_victim(grant, rpc));
}
TEST_F(homa_grant, homa_grant_find_victim__pick_lp_based_on_birth)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc, *rpc1, *rpc2, *rpc3;

	mock_clock = 500;
	rpc1 = test_rpc(self, 100, &self->server_ip[0], 20000);
	homa_grant_add_active(grant, rpc1, 0);
	mock_clock = 700;
	rpc2 = test_rpc(self, 102, &self->server_ip[0], 20000);
	homa_grant_add_active(grant, rpc2, 1);
	mock_clock = 200;
	rpc3 = test_rpc(self, 104, &self->server_ip[0], 20000);
	homa_grant_add_active(grant, rpc3, 2);

	grant->max_overcommit = 3;
	rpc = test_rpc(self, 106, &self->server_ip[1], 10000);
	EXPECT_EQ(1, homa_grant_find_victim(grant, rpc));
}
TEST_F(homa_grant, homa_grant_find_victim__lp_has_more_active_than_new_rpc)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	homa_grant_add_active(grant,
			      test_rpc(self, 100, &self->server_ip[0], 60000), 0);
	homa_grant_add_active(grant,
			      test_rpc(self, 102, &self->server_ip[0], 50000), 1);
	grant->max_overcommit = 2;
	rpc = test_rpc(self, 104, &self->server_ip[1], 80000);
	EXPECT_EQ(0, homa_grant_find_victim(grant, rpc));
}
TEST_F(homa_grant, homa_grant_find_victim__compare_new_rpc_with_remaining)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc, *rpc1;

	mock_clock = 500;
	rpc1 = test_rpc(self, 100, &self->server_ip[0], 20000);
	homa_grant_add_active(grant, rpc1, 0);
	grant->max_overcommit = 1;

	/* First try: new RPC has larger remaining (lower priority). */
	mock_clock = 300;
	rpc = test_rpc(self, 102, &self->server_ip[1], 30000);
	EXPECT_EQ(-1, homa_grant_find_victim(grant, rpc));

	/* Second try: new RPC has smaller remaining. */
	rpc->msgin.bytes_remaining = 10000;
	EXPECT_EQ(0, homa_grant_find_victim(grant, rpc));
}
TEST_F(homa_grant, homa_grant_find_victim__compare_new_rpc_with_birth)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc, *rpc1;

	mock_clock = 500;
	rpc1 = test_rpc(self, 100, &self->server_ip[0], 20000);
	homa_grant_add_active(grant, rpc1, 0);
	grant->max_overcommit = 1;

	/* First try: new rpc has later birth (lower priority). */
	mock_clock = 700;
	rpc = test_rpc(self, 102, &self->server_ip[1], 20000);
	EXPECT_EQ(-1, homa_grant_find_victim(grant, rpc));

	/* Second try: new rpc has earlier birth (higher priority). */
	rpc->msgin.birth = 300;
	EXPECT_EQ(0, homa_grant_find_victim(grant, rpc));
}
TEST_F(homa_grant, homa_grant_find_victim__replace_rpc_from_same_peer)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	homa_grant_add_active(grant,
			      test_rpc(self, 100, &self->server_ip[0], 20000), 0);
	homa_grant_add_active(grant,
			      test_rpc(self, 102, &self->server_ip[0], 30000), 1);
	grant->max_overcommit = 2;
	rpc = test_rpc(self, 104, &self->server_ip[0], 10000);
	EXPECT_EQ(1, homa_grant_find_victim(grant, rpc));
}

TEST_F(homa_grant, homa_grant_adjust_peer__remove_peer_from_grantable_peers)
{
	struct homa_rpc *rpc = test_rpc(self, 200, self->server_ip, 100000);
	struct homa_peer *peer = rpc->peer;

	list_add_tail(&peer->grantable_links,
		      &self->homa.grant->grantable_peers);
	EXPECT_EQ(1, list_empty(&peer->grantable_rpcs));
	EXPECT_EQ(0, list_empty(&peer->grantable_links));
	EXPECT_EQ(0, list_empty(&self->homa.grant->grantable_peers));

	homa_grant_adjust_peer(self->homa.grant, peer);
	EXPECT_EQ(1, list_empty(&peer->grantable_links));
	EXPECT_EQ(1, list_empty(&self->homa.grant->grantable_peers));
}
TEST_F(homa_grant, homa_grant_adjust_peer__insert_in_grantable_peers)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 70000);

	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 200, self->server_ip + 1,
					     100000));
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 300, self->server_ip + 2,
					     50000));
	list_add_tail(&rpc->grantable_links, &rpc->peer->grantable_rpcs);
	homa_grant_adjust_peer(self->homa.grant, rpc->peer);

	EXPECT_STREQ("peer 3.2.3.4: id 300 remaining 50000; "
		     "peer 1.2.3.4: id 100 remaining 70000; "
		     "peer 2.2.3.4: id 200 remaining 100000",
		     unit_log_grantables(&self->homa));
}
TEST_F(homa_grant, homa_grant_adjust_peer__append_to_grantable_peers)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 120000);

	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 200, self->server_ip + 1,
					     100000));
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 300, self->server_ip + 2,
					     50000));
	list_add_tail(&rpc->grantable_links, &rpc->peer->grantable_rpcs);
	homa_grant_adjust_peer(self->homa.grant, rpc->peer);

	EXPECT_STREQ("peer 3.2.3.4: id 300 remaining 50000; "
		     "peer 2.2.3.4: id 200 remaining 100000; "
		     "peer 1.2.3.4: id 100 remaining 120000",
		     unit_log_grantables(&self->homa));
}
TEST_F(homa_grant, homa_grant_adjust_peer__move_peer_upwards)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 120000);

	homa_grant_insert_grantable(self->homa.grant, rpc);
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 200, self->server_ip + 1,
					     100000));
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 300, self->server_ip + 2,
					     50000));
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 400, self->server_ip + 3,
					     80000));
	rpc->msgin.bytes_remaining -= 45000;
	homa_grant_adjust_peer(self->homa.grant, rpc->peer);

	EXPECT_STREQ("peer 3.2.3.4: id 300 remaining 50000; "
		     "peer 1.2.3.4: id 100 remaining 75000; "
		     "peer 4.2.3.4: id 400 remaining 80000; "
		     "peer 2.2.3.4: id 200 remaining 100000",
		     unit_log_grantables(&self->homa));
}
TEST_F(homa_grant, homa_grant_adjust_peer__move_peer_to_front)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 100000);

	homa_grant_insert_grantable(self->homa.grant, rpc);
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 200, self->server_ip + 1,
					     50000));
	rpc->msgin.bytes_remaining -= 55000;
	homa_grant_adjust_peer(self->homa.grant, rpc->peer);

	EXPECT_STREQ("peer 1.2.3.4: id 100 remaining 45000; "
		     "peer 2.2.3.4: id 200 remaining 50000",
		     unit_log_grantables(&self->homa));
}
TEST_F(homa_grant, homa_grant_adjust_peer__move_peer_downwards)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 40000);

	homa_grant_insert_grantable(self->homa.grant, rpc);
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 200, self->server_ip + 1,
					     100000));
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 300, self->server_ip + 2,
					     50000));
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 400, self->server_ip + 3,
					     80000));
	rpc->msgin.length += 41000;
	rpc->msgin.bytes_remaining += 41000;
	homa_grant_adjust_peer(self->homa.grant, rpc->peer);

	EXPECT_STREQ("peer 3.2.3.4: id 300 remaining 50000; "
		     "peer 4.2.3.4: id 400 remaining 80000; "
		     "peer 1.2.3.4: id 100 remaining 81000; "
		     "peer 2.2.3.4: id 200 remaining 100000",
		     unit_log_grantables(&self->homa));
}
TEST_F(homa_grant, homa_grant_adjust_peer__move_peer_to_back)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 50000);

	homa_grant_insert_grantable(self->homa.grant, rpc);
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 200, self->server_ip + 1,
					     100000));
	rpc->msgin.length += 55000;
	rpc->msgin.bytes_remaining += 55000;
	homa_grant_adjust_peer(self->homa.grant, rpc->peer);

	EXPECT_STREQ("peer 2.2.3.4: id 200 remaining 100000; "
		     "peer 1.2.3.4: id 100 remaining 105000",
		     unit_log_grantables(&self->homa));
}

TEST_F(homa_grant, homa_grant_insert_grantable__not_grantable)
{
	struct homa_rpc *rpc;

	rpc = test_rpc(self, 100, self->server_ip, 100000);
	clear_bit(RPC_GRANTABLE, &rpc->flags);
	homa_grant_insert_grantable(self->homa.grant, rpc);
	set_bit(RPC_GRANTABLE, &rpc->flags);
	EXPECT_STREQ("", unit_log_grantables(&self->homa));
}
TEST_F(homa_grant, homa_grant_insert_grantable__insert_in_peer_list)
{
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 100, self->server_ip,
					     100000));
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 200, self->server_ip,
					     50000));
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 300, self->server_ip,
					     800000));
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 400, self->server_ip,
					     70000));
	EXPECT_STREQ("peer 1.2.3.4: id 200 remaining 50000 "
		     "id 400 remaining 70000 "
		     "id 100 remaining 100000 "
		     "id 300 remaining 800000",
		     unit_log_grantables(&self->homa));
}
TEST_F(homa_grant, homa_grant_insert_grantable__insert_peer_in_grantable_peers)
{
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 200, self->server_ip,
					     100000));
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 300, self->server_ip+1,
					     50000));
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 400, self->server_ip+2,
		                	     120000));
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 500, self->server_ip+3,
		                	     70000));

	EXPECT_STREQ("peer 2.2.3.4: id 300 remaining 50000; "
		     "peer 4.2.3.4: id 500 remaining 70000; "
		     "peer 1.2.3.4: id 200 remaining 100000; "
		     "peer 3.2.3.4: id 400 remaining 120000",
		     unit_log_grantables(&self->homa));
}

TEST_F(homa_grant, homa_grant_remove_grantable__not_first_in_peer_list)
{
	struct homa_rpc *rpc = test_rpc(self, 300, self->server_ip, 30000);

	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 200, self->server_ip,
					     20000));
	homa_grant_insert_grantable(self->homa.grant, rpc);
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 400, self->server_ip+1,
					     25000));

	EXPECT_STREQ("peer 1.2.3.4: id 200 remaining 20000 "
		     "id 300 remaining 30000; "
		     "peer 2.2.3.4: id 400 remaining 25000",
		     unit_log_grantables(&self->homa));

	homa_grant_remove_grantable(self->homa.grant, rpc);
	EXPECT_STREQ("peer 1.2.3.4: id 200 remaining 20000; "
		     "peer 2.2.3.4: id 400 remaining 25000",
		     unit_log_grantables(&self->homa));
}
TEST_F(homa_grant, homa_grant_remove_grantable__remove_peer_from_grantable_peers)
{
	struct homa_rpc *rpc = test_rpc(self, 200, self->server_ip, 30000);

	homa_grant_insert_grantable(self->homa.grant, rpc);
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 300, self->server_ip+1,
					     40000));
	homa_grant_insert_grantable(self->homa.grant,
				    test_rpc(self, 400, self->server_ip+2,
					     20000));

	EXPECT_STREQ("peer 3.2.3.4: id 400 remaining 20000; "
		     "peer 1.2.3.4: id 200 remaining 30000; "
		     "peer 2.2.3.4: id 300 remaining 40000",
		     unit_log_grantables(&self->homa));

	homa_grant_remove_grantable(self->homa.grant, rpc);
	EXPECT_STREQ("peer 3.2.3.4: id 400 remaining 20000; "
		     "peer 2.2.3.4: id 300 remaining 40000",
		     unit_log_grantables(&self->homa));
}

TEST_F(homa_grant, homa_grant_manage_rpc__evict_victim_and_add_to_active)
{
	struct homa_rpc *rpc1, *rpc2;

	rpc1 = test_rpc(self, 100, self->server_ip, 50000);
	rpc2 = test_rpc(self, 102, self->server_ip, 20000);

	self->homa.grant->max_overcommit = 1;
	self->homa.grant->last_grantable_change = 50;
	homa_rpc_lock(rpc1);
	homa_grant_manage_rpc(self->homa.grant, rpc1);
	homa_rpc_unlock(rpc1);
	EXPECT_EQ(0, rpc1->msgin.active_ix);
	homa_rpc_lock(rpc2);
	homa_grant_manage_rpc(self->homa.grant, rpc2);
	homa_rpc_unlock(rpc2);
	EXPECT_EQ(-1, rpc1->msgin.active_ix);
	EXPECT_EQ(0, rpc2->msgin.active_ix);
	EXPECT_STREQ("active[0]: id 102 remaining 20000; "
		     "peer 1.2.3.4: id 100 remaining 50000",
		     unit_log_grantables(&self->homa));
	EXPECT_EQ(2, self->homa.grant->num_grantable_rpcs);
}
TEST_F(homa_grant, homa_grant_manage_rpc__race_ends_rpc)
{
	struct homa_rpc *rpc1;

	rpc1 = test_rpc(self, 100, self->server_ip, 50000);

	self->homa.grant->max_overcommit = 1;
	unit_hook_register(grant_spinlock2_hook);
	hook_spinlock2_count = 2;
	hook_spinlock2_rpc = rpc1;
	hook_spinlock2_manage = false;

	homa_rpc_lock(rpc1);
	homa_grant_manage_rpc(self->homa.grant, rpc1);
	homa_rpc_unlock(rpc1);
	EXPECT_EQ(-1, rpc1->msgin.active_ix);
	EXPECT_TRUE(list_empty(&rpc1->grantable_links));
	EXPECT_EQ(0, self->homa.grant->num_grantable_rpcs);
	EXPECT_EQ(0, self->homa.grant->num_active);
}
TEST_F(homa_grant, homa_grant_manage_rpc__race_manages_rpc)
{
	struct homa_rpc *rpc1;

	rpc1 = test_rpc(self, 100, self->server_ip, 50000);

	self->homa.grant->max_overcommit = 1;
	unit_hook_register(grant_spinlock2_hook);
	hook_spinlock2_count = 2;
	hook_spinlock2_rpc = rpc1;
	hook_spinlock2_manage = true;

	homa_rpc_lock(rpc1);
	homa_grant_manage_rpc(self->homa.grant, rpc1);
	homa_rpc_unlock(rpc1);
	EXPECT_EQ(0, rpc1->msgin.active_ix);
	EXPECT_TRUE(list_empty(&rpc1->grantable_links));
	EXPECT_EQ(1, self->homa.grant->num_grantable_rpcs);
	EXPECT_EQ(1, self->homa.grant->num_active);
}
TEST_F(homa_grant, homa_grant_manage_rpc__restore_evicted_rpc_after_race)
{
	struct homa_rpc *rpc1, *rpc2;

	rpc1 = test_rpc(self, 100, self->server_ip, 50000);
	rpc2 = test_rpc(self, 102, self->server_ip, 20000);

	self->homa.grant->max_overcommit = 1;

	homa_rpc_lock(rpc1);
	homa_grant_manage_rpc(self->homa.grant, rpc1);
	homa_rpc_unlock(rpc1);
	EXPECT_EQ(0, rpc1->msgin.active_ix);
	EXPECT_EQ(1, self->homa.grant->num_active);

	unit_hook_register(grant_spinlock2_hook);
	hook_spinlock2_count = 2;
	hook_spinlock2_rpc = rpc2;
	hook_spinlock2_manage = false;

	homa_rpc_lock(rpc2);
	homa_grant_manage_rpc(self->homa.grant, rpc2);
	homa_rpc_unlock(rpc2);
	EXPECT_EQ(0, rpc1->msgin.active_ix);
	EXPECT_EQ(1, self->homa.grant->num_active);
}
TEST_F(homa_grant, homa_grant_manage_rpc__add_to_grantables_list)
{
	struct homa_rpc *rpc1, *rpc2;

	rpc1 = test_rpc(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc(self, 102, self->server_ip, 50000);

	self->homa.grant->max_overcommit = 1;
	self->homa.grant->last_grantable_change = 50;
	self->homa.grant->num_grantable_rpcs = 3;
	mock_clock = 200;
	homa_rpc_lock(rpc1);
	homa_grant_manage_rpc(self->homa.grant, rpc1);
	homa_rpc_unlock(rpc1);
	mock_clock = 300;
	homa_rpc_lock(rpc2);
	homa_grant_manage_rpc(self->homa.grant, rpc2);
	homa_rpc_unlock(rpc2);
	EXPECT_EQ(5, self->homa.grant->max_grantable_rpcs);
	EXPECT_EQ(850, homa_metrics_per_cpu()->grantable_rpcs_integral);
	EXPECT_EQ(300, self->homa.grant->last_grantable_change);
	EXPECT_EQ(0, rpc1->msgin.active_ix);
	EXPECT_EQ(-1, rpc2->msgin.active_ix);
	EXPECT_STREQ("active[0]: id 100 remaining 20000; "
		     "peer 1.2.3.4: id 102 remaining 50000",
		     unit_log_grantables(&self->homa));
	EXPECT_EQ(1, test_bit(RPC_GRANT_MANAGED, &rpc2->flags));
}
TEST_F(homa_grant, homa_grant_manage_rpc__update_metrics)
{
	struct homa_rpc *rpc;

	self->homa.grant->last_grantable_change = 50;
	self->homa.grant->num_grantable_rpcs = 3;
	mock_clock = 200;
	rpc = test_rpc(self, 100, self->server_ip, 100000);
	homa_rpc_lock(rpc);
	homa_grant_manage_rpc(self->homa.grant, rpc);
	homa_rpc_unlock(rpc);
	EXPECT_EQ(4, self->homa.grant->num_grantable_rpcs);
	EXPECT_EQ(450, homa_metrics_per_cpu()->grantable_rpcs_integral);
	EXPECT_EQ(200, self->homa.grant->last_grantable_change);
}
TEST_F(homa_grant, homa_grant_manage_rpc__dont_change_max_grantable_rpcs)
{
	struct homa_rpc *rpc;

	self->homa.grant->num_grantable_rpcs = 3;
	self->homa.grant->max_grantable_rpcs = 5;
	rpc = test_rpc(self, 100, self->server_ip, 100000);
	homa_rpc_lock(rpc);
	homa_grant_manage_rpc(self->homa.grant, rpc);
	homa_rpc_unlock(rpc);
	EXPECT_EQ(4, self->homa.grant->num_grantable_rpcs);
	EXPECT_EQ(5, self->homa.grant->max_grantable_rpcs);
}

TEST_F(homa_grant, homa_grant_unmanage_rpc__rpc_not_grantable)
{
	struct homa_rpc *rpc;

	self->homa.grant->max_incoming = 60000;
	self->homa.grant->last_grantable_change = 100;
	mock_clock = 250;
	rpc = test_rpc(self, 200, self->server_ip, 30000);
	clear_bit(RPC_GRANTABLE, &rpc->flags);
	rpc->msgin.rec_incoming = 1000;
	EXPECT_EQ(0, self->homa.grant->num_grantable_rpcs);

	homa_rpc_lock(rpc);
	homa_grant_unmanage_rpc(rpc);
	homa_rpc_unlock(rpc);
	EXPECT_EQ(0, self->homa.grant->num_grantable_rpcs);
	EXPECT_EQ(0, homa_metrics_per_cpu()->grantable_rpcs_integral);
	EXPECT_EQ(100, self->homa.grant->last_grantable_change);
	EXPECT_EQ(0, atomic_read(&self->homa.grant->total_incoming));
}
TEST_F(homa_grant, homa_grant_unmanage_rpc__remove_from_active_and_or_grantable_list)
{
	struct homa_rpc *rpc1, *rpc2;

	self->homa.grant->max_overcommit = 1;
	self->homa.grant->max_incoming = 60000;
	rpc1 = test_rpc(self, 100, self->server_ip, 20000);
	homa_rpc_lock(rpc1);
	homa_grant_manage_rpc(self->homa.grant, rpc1);
	homa_rpc_unlock(rpc1);

	rpc2 = test_rpc(self, 200, self->server_ip, 30000);
	homa_rpc_lock(rpc2);
	homa_grant_manage_rpc(self->homa.grant, rpc2);

	EXPECT_STREQ("active[0]: id 100 remaining 20000; "
		     "peer 1.2.3.4: id 200 remaining 30000",
		     unit_log_grantables(&self->homa));
	EXPECT_EQ(2, self->homa.grant->num_grantable_rpcs);

	self->homa.grant->last_grantable_change = 100;
	mock_clock = 250;

	homa_grant_unmanage_rpc(rpc2);
	homa_rpc_unlock(rpc2);
	EXPECT_STREQ("active[0]: id 100 remaining 20000",
		     unit_log_grantables(&self->homa));
	EXPECT_EQ(1, self->homa.grant->num_grantable_rpcs);
	EXPECT_EQ(300, homa_metrics_per_cpu()->grantable_rpcs_integral);
	EXPECT_EQ(250, self->homa.grant->last_grantable_change);

	homa_rpc_lock(rpc1);
	homa_grant_unmanage_rpc(self->homa.grant->active_rpcs[0].rpc);
	homa_rpc_unlock(rpc1);
	EXPECT_STREQ("", unit_log_grantables(&self->homa));
	EXPECT_EQ(0, self->homa.grant->num_grantable_rpcs);
}
TEST_F(homa_grant, homa_grant_unmanage_rpc__remove_from_active_and_promote)
{
	struct homa_rpc *rpc1, *rpc2;

	self->homa.grant->max_overcommit = 1;
	self->homa.grant->max_incoming = 60000;
	rpc1 = test_rpc(self, 100, self->server_ip, 20000);
	homa_rpc_lock(rpc1);
	homa_grant_manage_rpc(self->homa.grant, rpc1);
	homa_rpc_unlock(rpc1);

	rpc2 = test_rpc(self, 200, self->server_ip, 30000);
	homa_rpc_lock(rpc2);
	homa_grant_manage_rpc(self->homa.grant, rpc2);
	homa_rpc_unlock(rpc2);

	EXPECT_STREQ("active[0]: id 100 remaining 20000; "
		     "peer 1.2.3.4: id 200 remaining 30000",
		     unit_log_grantables(&self->homa));
	EXPECT_EQ(2, self->homa.grant->num_grantable_rpcs);

	homa_rpc_lock(rpc1);
	homa_grant_unmanage_rpc(rpc1);
	homa_rpc_unlock(rpc1);
	EXPECT_STREQ("active[0]: id 200 remaining 30000",
		     unit_log_grantables(&self->homa));
	EXPECT_EQ(0, rpc2->msgin.active_ix);
}
TEST_F(homa_grant, homa_grant_unmanage_rpc__remove_from_oldest_rpc)
{
	struct homa_rpc *rpc;

	rpc = test_rpc(self, 200, self->server_ip, 30000);
	homa_rpc_lock(rpc);
	homa_grant_manage_rpc(self->homa.grant, rpc);
	self->homa.grant->oldest_rpc = rpc;
	homa_rpc_hold(rpc);
	EXPECT_EQ(2, refcount_read(&rpc->refs));

	homa_grant_unmanage_rpc(rpc);
	homa_rpc_unlock(rpc);
	EXPECT_EQ(NULL, self->homa.grant->oldest_rpc);
	EXPECT_EQ(1, refcount_read(&rpc->refs));
}
TEST_F(homa_grant, homa_grant_unmanage_rpc__clear_rec_incoming)
{
	struct homa_rpc *rpc;

	rpc = test_rpc(self, 200, self->server_ip, 30000);
	homa_rpc_lock(rpc);
	homa_grant_manage_rpc(self->homa.grant, rpc);
	rpc->msgin.rec_incoming = 1200;

	homa_grant_unmanage_rpc(rpc);
	homa_rpc_unlock(rpc);
	EXPECT_EQ(0, rpc->msgin.rec_incoming);
	EXPECT_EQ(-1200, atomic_read(&self->homa.grant->total_incoming));
}

TEST_F(homa_grant, homa_grant_promote_queued__prefer_peer_with_no_active)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	rpc1 = test_rpc(self, 200, &self->server_ip[0], 10000);
	homa_grant_add_active(grant, rpc1, 0);

	rpc2 = test_rpc(self, 202, &self->server_ip[0], 20000);
	homa_grant_insert_grantable(grant, rpc2);

	rpc3 = test_rpc(self, 204, &self->server_ip[1], 30000);
	homa_grant_insert_grantable(grant, rpc3);

	EXPECT_STREQ("active[0]: id 200 remaining 10000; "
		     "peer 1.2.3.4: id 202 remaining 20000; "
		     "peer 2.2.3.4: id 204 remaining 30000",
		     unit_log_grantables(&self->homa));

	self->homa.grant->max_overcommit = 3;
	homa_grant_promote_queued(grant, 2);

	EXPECT_STREQ("active[0]: id 200 remaining 10000; "
		     "active[2]: id 204 remaining 30000; "
		     "peer 1.2.3.4: id 202 remaining 20000",
		     unit_log_grantables(&self->homa));
	EXPECT_EQ(4, grant->needy_active);
}
TEST_F(homa_grant, homa_grant_promote_queued__prefer_peer_with_fewer_active)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3, *rpc4, *rpc5;
	struct homa_grant *grant = self->homa.grant;

	self->homa.grant->max_overcommit = 4;
	rpc1 = test_rpc(self, 200, &self->server_ip[0], 10000);
	homa_grant_add_active(grant, rpc1, 0);

	rpc2 = test_rpc(self, 202, &self->server_ip[0], 20000);
	homa_grant_add_active(grant, rpc2, 2);

	rpc3 = test_rpc(self, 204, &self->server_ip[1], 30000);
	homa_grant_add_active(grant, rpc3, 1);

	rpc4 = test_rpc(self, 206, &self->server_ip[0], 40000);
	homa_grant_insert_grantable(grant, rpc4);

	rpc5 = test_rpc(self, 208, &self->server_ip[1], 50000);
	homa_grant_insert_grantable(grant, rpc5);

	EXPECT_STREQ("active[0]: id 200 remaining 10000; "
		     "active[1]: id 204 remaining 30000; "
		     "active[2]: id 202 remaining 20000; "
		     "peer 1.2.3.4: id 206 remaining 40000; "
		     "peer 2.2.3.4: id 208 remaining 50000",
		     unit_log_grantables(&self->homa));

	homa_grant_promote_queued(grant, 3);

	EXPECT_STREQ("active[0]: id 200 remaining 10000; "
		     "active[1]: id 204 remaining 30000; "
		     "active[2]: id 202 remaining 20000; "
		     "active[3]: id 208 remaining 50000; "
		     "peer 1.2.3.4: id 206 remaining 40000",
		     unit_log_grantables(&self->homa));
	EXPECT_EQ(8, grant->needy_active);
}
TEST_F(homa_grant, homa_grant_promote_queued__no_promotable_rpcs)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc1;

	self->homa.grant->max_overcommit = 4;
	rpc1 = test_rpc(self, 200, &self->server_ip[0], 10000);
	homa_grant_add_active(grant, rpc1, 0);

	EXPECT_STREQ("active[0]: id 200 remaining 10000",
		     unit_log_grantables(&self->homa));

	homa_grant_promote_queued(grant, 2);

	EXPECT_STREQ("active[0]: id 200 remaining 10000",
		     unit_log_grantables(&self->homa));
}

TEST_F(homa_grant, homa_grant_promote_rpc__rpc_not_in_lists)
{
	struct homa_rpc *rpc;

	rpc = test_rpc(self, 102, self->server_ip, 40000);
	homa_grant_add_active(self->homa.grant, rpc, 3);
	rpc->msgin.bytes_remaining -= 15000;
	EXPECT_EQ(3, rpc->msgin.active_ix);

	homa_grant_promote_rpc(self->homa.grant, rpc);
	EXPECT_EQ(3, rpc->msgin.active_ix);
}
TEST_F(homa_grant, homa_grant_promote_rpc__promote_within_peer_list)
{
	struct homa_rpc *rpc;

	self->homa.grant->max_overcommit = 1;
	test_rpc_mngd(self, 100, self->server_ip, 30000);
	test_rpc_mngd(self, 102, self->server_ip, 40000);
	test_rpc_mngd(self, 104, self->server_ip, 50000);
	test_rpc_mngd(self, 106, self->server_ip, 60000);
	rpc = test_rpc_mngd(self, 108, self->server_ip, 70000);
	rpc->msgin.bytes_remaining -= 25000;

	homa_grant_promote_rpc(self->homa.grant, rpc);
	EXPECT_STREQ("active[0]: id 100 remaining 30000; "
		     "peer 1.2.3.4: id 102 remaining 40000 "
		     "id 108 remaining 45000 "
		     "id 104 remaining 50000 "
		     "id 106 remaining 60000",
		     unit_log_grantables(&self->homa));
}
TEST_F(homa_grant, homa_grant_promote_rpc__promote_into_active_space_available)
{
	struct homa_rpc *rpc1, *rpc2;

	rpc1 = test_rpc_mngd(self, 100, self->server_ip, 30000);

	rpc2 = test_rpc(self, 102, self->server_ip, 40000);
	homa_grant_insert_grantable(self->homa.grant, rpc2);

	homa_grant_promote_rpc(self->homa.grant, rpc2);
	EXPECT_EQ(0, rpc1->msgin.active_ix);
	EXPECT_EQ(1, rpc2->msgin.active_ix);
}
TEST_F(homa_grant, homa_grant_promote_rpc__promote_into_active_demote_existing)
{
	struct homa_rpc *rpc1, *rpc2;

	self->homa.grant->max_overcommit = 1;
	rpc1 = test_rpc_mngd(self, 100, self->server_ip, 30000);
	rpc2 = test_rpc_mngd(self, 102, self->server_ip, 40000);
	EXPECT_EQ(0, rpc1->msgin.active_ix);
	EXPECT_EQ(-1, rpc2->msgin.active_ix);
	rpc2->msgin.bytes_remaining -= 15000;

	homa_rpc_lock(rpc2);
	homa_grant_promote_rpc(self->homa.grant, rpc2);
	homa_rpc_unlock(rpc2);
	EXPECT_EQ(-1, rpc1->msgin.active_ix);
	EXPECT_EQ(0, rpc2->msgin.active_ix);
}
TEST_F(homa_grant, homa_grant_promote_rpc__promote_to_top_of_peer_list_and_adjust_peer)
{
	struct homa_rpc *rpc;

	self->homa.grant->max_overcommit = 1;
	test_rpc_mngd(self, 100, self->server_ip, 30000);
	test_rpc_mngd(self, 102, self->server_ip + 1, 40000);
	test_rpc_mngd(self, 104, self->server_ip + 2, 50000);
	test_rpc_mngd(self, 106, self->server_ip + 2, 60000);
	rpc = test_rpc_mngd(self, 108, self->server_ip + 2, 70000);
	rpc->msgin.bytes_remaining -= 35000;

	homa_grant_promote_rpc(self->homa.grant, rpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 100 remaining 30000; "
		     "peer 3.2.3.4: id 108 remaining 35000 "
		     "id 104 remaining 50000 "
		     "id 106 remaining 60000; "
		     "peer 2.2.3.4: id 102 remaining 40000", unit_log_get());
}

TEST_F(homa_grant, homa_grant_update_incoming__basics)
{
	struct homa_rpc *rpc;

	rpc = test_rpc_mngd(self, 200, self->server_ip, 20000);

	/* Case 1: total_incoming increases. */
	atomic_set(&self->homa.grant->total_incoming, 1000);
	rpc->msgin.bytes_remaining = 19000;
	rpc->msgin.granted = 3000;
	rpc->msgin.rec_incoming = 500;
	homa_grant_update_incoming(self->homa.grant, rpc);
	EXPECT_EQ(2500, atomic_read(&self->homa.grant->total_incoming));
	EXPECT_EQ(2000, rpc->msgin.rec_incoming);

	/* Case 2: incoming negative. */
	atomic_set(&self->homa.grant->total_incoming, 1000);
	rpc->msgin.bytes_remaining = 16000;
	rpc->msgin.granted = 3000;
	rpc->msgin.rec_incoming = 500;
	homa_grant_update_incoming(self->homa.grant, rpc);
	EXPECT_EQ(500, atomic_read(&self->homa.grant->total_incoming));
	EXPECT_EQ(0, rpc->msgin.rec_incoming);

	/* Case 3: no change to rec_incoming. */
	atomic_set(&self->homa.grant->total_incoming, 1000);
	self->homa.grant->max_incoming = 1000;
	rpc->msgin.bytes_remaining = 16000;
	rpc->msgin.granted = 4500;
	rpc->msgin.rec_incoming = 500;
	homa_grant_update_incoming(self->homa.grant, rpc);
	EXPECT_EQ(1000, atomic_read(&self->homa.grant->total_incoming));
	EXPECT_EQ(500, rpc->msgin.rec_incoming);
}
TEST_F(homa_grant, homa_grant_update_incoming__rpc_not_grantable)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	rpc = test_rpc(self, 200, self->server_ip, 5000);

	rpc->msgin.bytes_remaining = 4000;
	rpc->msgin.granted = 3000;

	/* First try: not grantable. */
	clear_bit(RPC_GRANTABLE, &rpc->flags);
	homa_grant_update_incoming(grant, rpc);
	EXPECT_EQ(0, rpc->msgin.rec_incoming);

	/* Second try: grantable. */
	set_bit(RPC_GRANTABLE, &rpc->flags);
	homa_grant_update_incoming(grant, rpc);
	EXPECT_EQ(2000, rpc->msgin.rec_incoming);
}
TEST_F(homa_grant, homa_grant_update_incoming__promote)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	rpc = test_rpc(self, 200, self->server_ip, 5000);
	homa_grant_insert_grantable(grant, rpc);
	EXPECT_EQ(-1, rpc->msgin.active_ix);

	rpc->msgin.bytes_remaining = 4000;
	rpc->msgin.granted = 3000;
	homa_grant_update_incoming(grant, rpc);
	EXPECT_EQ(2000, rpc->msgin.rec_incoming);
	EXPECT_EQ(0, rpc->msgin.active_ix);
}

TEST_F(homa_grant, homa_grant_send)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);

	mock_xmit_log_verbose = 1;
	rpc->msgin.granted = 2600;
	unit_log_clear();
	homa_grant_send(rpc, 3);
	EXPECT_SUBSTR("id 100, offset 2600, grant_prio 3", unit_log_get());
}

TEST_F(homa_grant, homa_grant_try_send__basics)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	rpc = test_rpc_mngd(self, 100, self->server_ip, 20000);
	rpc->msgin.bytes_remaining = 19900;
	rpc->msgin.granted = 300;
	rpc->msgin.rec_incoming = 200;
	grant->max_incoming = 100000;
	grant->window = 1200;
	atomic_set(&grant->total_incoming, 500);
	unit_log_clear();

	homa_rpc_lock(rpc);
	homa_grant_try_send(grant, rpc, true);
	homa_rpc_unlock(rpc);
	EXPECT_STREQ("xmit GRANT 1300@0", unit_log_get());
	EXPECT_EQ(1300, rpc->msgin.granted);
	EXPECT_EQ(1200, rpc->msgin.rec_incoming);
	EXPECT_EQ(1500, atomic_read(&grant->total_incoming));
	EXPECT_EQ(0, grant->needy_active);
}
TEST_F(homa_grant, homa_grant_try_send__rpc_not_grantable)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	rpc = test_rpc_mngd(self, 100, self->server_ip, 20000);
	rpc->msgin.bytes_remaining = 19900;
	unit_log_clear();

	homa_rpc_lock(rpc);
	clear_bit(RPC_GRANTABLE, &rpc->flags);
	homa_grant_try_send(grant, rpc, true);
	set_bit(RPC_GRANTABLE, &rpc->flags);
	homa_rpc_unlock(rpc);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, atomic_read(&grant->total_incoming));
}
TEST_F(homa_grant, homa_grant_try_send__rpc_fully_granted)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	rpc = test_rpc_mngd(self, 100, self->server_ip, 20000);
	rpc->msgin.bytes_remaining = 19900;
	rpc->msgin.granted = 1300;
	rpc->msgin.rec_incoming = 200;
	grant->max_incoming = 100000;
	grant->window = 1200;
	atomic_set(&grant->total_incoming, 500);
	unit_log_clear();

	homa_rpc_lock(rpc);
	homa_grant_try_send(grant, rpc, true);
	homa_rpc_unlock(rpc);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(1300, rpc->msgin.granted);
	EXPECT_EQ(200, rpc->msgin.rec_incoming);
	EXPECT_EQ(500, atomic_read(&grant->total_incoming));
}
TEST_F(homa_grant, homa_grant_try_send__reduce_grant_because_of_message_end)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	rpc = test_rpc_mngd(self, 100, self->server_ip, 20000);
	rpc->msgin.bytes_remaining = 700;
	rpc->msgin.granted = 19300;
	rpc->msgin.rec_incoming = 200;
	grant->max_incoming = 100000;
	grant->window = 1200;
	atomic_set(&grant->total_incoming, 500);
	unit_log_clear();

	homa_rpc_lock(rpc);
	homa_grant_try_send(grant, rpc, true);
	homa_rpc_unlock(rpc);
	EXPECT_STREQ("xmit GRANT 20000@0", unit_log_get());
	EXPECT_EQ(20000, rpc->msgin.granted);
	EXPECT_EQ(900, rpc->msgin.rec_incoming);
	EXPECT_EQ(1200, atomic_read(&grant->total_incoming));
}
TEST_F(homa_grant, homa_grant_try_send__max_incoming_exceeded)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	rpc = test_rpc(self, 100, self->server_ip, 20000);
	homa_grant_add_active(grant, rpc, 2);
	rpc->msgin.bytes_remaining = 19900;
	rpc->msgin.granted = 300;
	rpc->msgin.rec_incoming = 200;
	grant->window = 1200;
	grant->max_incoming = 100000;
	atomic_set(&grant->total_incoming, 100010);
	unit_log_clear();

	homa_rpc_lock(rpc);
	homa_grant_try_send(grant, rpc, true);
	homa_rpc_unlock(rpc);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(300, rpc->msgin.granted);
	EXPECT_EQ(200, rpc->msgin.rec_incoming);
	EXPECT_EQ(100010, atomic_read(&grant->total_incoming));
	EXPECT_EQ(4, grant->needy_active);
}
TEST_F(homa_grant, homa_grant_try_send__needy_rpcs)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	rpc = test_rpc(self, 100, self->server_ip, 20000);
	homa_grant_add_active(grant, rpc, 2);
	rpc->msgin.bytes_remaining = 19900;
	rpc->msgin.granted = 300;
	rpc->msgin.rec_incoming = 200;
	grant->window = 1200;
	grant->max_incoming = 100000;
	atomic_set(&grant->total_incoming, 500);
	grant->needy_active = 8;
	unit_log_clear();

	homa_rpc_lock(rpc);
	homa_grant_try_send(grant, rpc, true);
	homa_rpc_unlock(rpc);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(300, rpc->msgin.granted);
	EXPECT_EQ(200, rpc->msgin.rec_incoming);
	EXPECT_EQ(500, atomic_read(&grant->total_incoming));
	EXPECT_EQ(12, grant->needy_active);
}
TEST_F(homa_grant, homa_grant_try_send__needy_rpcs_but_check_needy_false)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	rpc = test_rpc_mngd(self, 100, self->server_ip, 20000);
	rpc->msgin.bytes_remaining = 19900;
	rpc->msgin.granted = 300;
	rpc->msgin.rec_incoming = 200;
	grant->window = 1200;
	grant->max_incoming = 100000;
	atomic_set(&grant->total_incoming, 500);
	grant->needy_active = 8;
	unit_log_clear();

	homa_rpc_lock(rpc);
	homa_grant_try_send(grant, rpc, false);
	homa_rpc_unlock(rpc);
	EXPECT_STREQ("xmit GRANT 1300@0", unit_log_get());
	EXPECT_EQ(1300, rpc->msgin.granted);
	EXPECT_EQ(1200, rpc->msgin.rec_incoming);
	EXPECT_EQ(1500, atomic_read(&grant->total_incoming));
	EXPECT_EQ(8, grant->needy_active);
}
TEST_F(homa_grant, homa_grant_try_send__reduce_grant_because_of_incoming_limit)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	rpc = test_rpc(self, 100, self->server_ip, 20000);
	homa_grant_add_active(grant, rpc, 2);
	rpc->msgin.bytes_remaining = 19900;
	rpc->msgin.granted = 300;
	rpc->msgin.rec_incoming = 200;
	grant->max_incoming = 10000;
	grant->window = 1200;
	atomic_set(&grant->total_incoming, 9500);
	unit_log_clear();

	homa_rpc_lock(rpc);
	homa_grant_try_send(grant, rpc, true);
	homa_rpc_unlock(rpc);
	EXPECT_STREQ("xmit GRANT 800@0", unit_log_get());
	EXPECT_EQ(800, rpc->msgin.granted);
	EXPECT_EQ(700, rpc->msgin.rec_incoming);
	EXPECT_EQ(10000, atomic_read(&grant->total_incoming));
	EXPECT_EQ(4, grant->needy_active);
}
TEST_F(homa_grant, homa_grant_try_send__rank_basics)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc;

	/* This test tests proper handling of empty slots and rpc's slot,
	 * as well as basic test of remaining.
	 */

	test_rpc_mngd(self, 100, self->server_ip, 6000);

	rpc = test_rpc_mngd(self, 102, self->server_ip, 4000);

	test_rpc_mngd(self, 104, self->server_ip, 5000);

	grant->window = 1200;
	unit_log_clear();

	homa_rpc_lock(rpc);
	homa_grant_try_send(grant, rpc, true);
	homa_rpc_unlock(rpc);
	EXPECT_STREQ("xmit GRANT 1200@2", unit_log_get());
}
TEST_F(homa_grant, homa_grant_try_send__rank_use_birth_to_choose)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc1, *rpc2, *rpc3, *rpc4;

	mock_clock = 400;
	rpc1 = test_rpc(self, 100, self->server_ip, 4000);
	homa_grant_add_active(grant, rpc1, 2);

	mock_clock = 300;
	rpc2 = test_rpc(self, 102, self->server_ip, 4000);
	homa_grant_add_active(grant, rpc2, 1);

	mock_clock = 500;
	rpc3 = test_rpc(self, 104, self->server_ip, 4000);
	homa_grant_add_active(grant, rpc3, 3);

	mock_clock = 600;
	rpc4 = test_rpc(self, 104, self->server_ip, 4000);
	homa_grant_add_active(grant, rpc4, 6);

	grant->window = 1200;
	unit_log_clear();

	homa_rpc_lock(rpc1);
	homa_grant_try_send(grant, rpc1, true);
	homa_rpc_unlock(rpc1);
	EXPECT_STREQ("xmit GRANT 1200@2", unit_log_get());
}
TEST_F(homa_grant, homa_grant_try_send__fifo_grant)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc1, *rpc2;

	mock_clock = 5000;
	rpc1 = test_rpc_mngd(self, 100, self->server_ip, 50000);

	mock_clock = 1000;
	rpc2 = test_rpc_mngd(self, 102, self->server_ip, 100000);

	grant->window = 1200;
	grant->fifo_grant_time = 0;
	grant->fifo_grant_interval = 10000;
	grant->fifo_grant_increment = 20000;
	self->homa.grant->fifo_fraction = 50;
	unit_log_clear();

	homa_rpc_lock(rpc1);
	homa_grant_try_send(grant, rpc1, true);
	homa_rpc_unlock(rpc1);
	EXPECT_STREQ("xmit GRANT 1200@1; xmit GRANT 20000@0", unit_log_get());
	EXPECT_EQ(1200, rpc1->msgin.granted);
	EXPECT_EQ(20000, rpc2->msgin.granted);
}

TEST_F(homa_grant, homa_grant_check_needy__basics)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc1;

	rpc1 = test_rpc(self, 100, self->server_ip, 4000);
	homa_grant_add_active(grant, rpc1, 2);
	grant->window = 1200;
	set_bit(2, &grant->needy_active);
	unit_log_clear();

	homa_grant_check_needy(grant);
	EXPECT_STREQ("xmit GRANT 1200@0", unit_log_get());
	EXPECT_EQ(0, grant->needy_active);
	EXPECT_EQ(1200, rpc1->msgin.granted);
	EXPECT_EQ(1, homa_metrics_per_cpu()->needy_grants);
}
TEST_F(homa_grant, homa_grant_check_needy__max_incoming_exceeded)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc1;

	rpc1 = test_rpc(self, 100, self->server_ip, 4000);
	homa_grant_add_active(grant, rpc1, 2);
	grant->window = 1200;
	set_bit(2, &grant->needy_active);
	atomic_set(&grant->total_incoming, 10000);
	grant->max_incoming = 10000;
	unit_log_clear();

	homa_grant_check_needy(grant);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(4, grant->needy_active);
}
TEST_F(homa_grant, homa_grant_check_needy__no_needy_rpcs)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc1;

	rpc1 = test_rpc(self, 100, self->server_ip, 4000);
	homa_grant_add_active(grant, rpc1, 2);
	grant->window = 1200;
	grant->needy_active = 0;
	unit_log_clear();

	homa_grant_check_needy(grant);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, grant->needy_active);
}
TEST_F(homa_grant, homa_grant_check_needy__service_in_priority_order)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	mock_clock = 500;
	rpc1 = test_rpc(self, 100, self->server_ip, 4000);
	homa_grant_add_active(grant, rpc1, 1);

	mock_clock = 400;
	rpc2 = test_rpc(self, 102, self->server_ip, 5000);
	homa_grant_add_active(grant, rpc2, 2);

	mock_clock = 600;
	rpc3 = test_rpc(self, 104, self->server_ip, 4000);
	homa_grant_add_active(grant, rpc3, 4);

	grant->window = 1200;
	set_bit(1, &grant->needy_active);
	set_bit(2, &grant->needy_active);
	set_bit(4, &grant->needy_active);
	atomic_set(&grant->total_incoming, 7000);
	grant->max_incoming = 10000;
	unit_log_clear();

	homa_grant_check_needy(grant);
	EXPECT_STREQ("xmit GRANT 1200@2; xmit GRANT 1200@1; xmit GRANT 600@0",
		     unit_log_get());
	EXPECT_EQ(4, grant->needy_active);
	EXPECT_EQ(1200, rpc1->msgin.granted);
	EXPECT_EQ(600, rpc2->msgin.granted);
	EXPECT_EQ(1200, rpc3->msgin.granted);
	EXPECT_EQ(3, homa_metrics_per_cpu()->needy_grants);
}
TEST_F(homa_grant, homa_grant_check_needy__race_clears_needy_active)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc1;

	rpc1 = test_rpc(self, 100, self->server_ip, 4000);
	homa_grant_add_active(grant, rpc1, 2);
	grant->window = 1200;
	set_bit(2, &grant->needy_active);
	unit_log_clear();
	hook_spinlock3_count = 1;
	hook_spinlock3_grant = grant;
	unit_hook_register(grant_spinlock_hook3);

	homa_grant_check_needy(grant);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, grant->needy_active);
	EXPECT_EQ(0, rpc1->msgin.granted);
}

TEST_F(homa_grant, homa_grant_check_rpc__basics)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc1;

	rpc1 = test_rpc(self, 100, self->server_ip, 4000);
	homa_grant_add_active(grant, rpc1, 2);
	set_bit(RPC_GRANT_MANAGED, &rpc1->flags);
	grant->window = 1200;
	unit_log_clear();

	homa_rpc_lock(rpc1);
	homa_grant_check_rpc(rpc1);
	homa_rpc_unlock(rpc1);
	EXPECT_STREQ("xmit GRANT 1200@0", unit_log_get());
	EXPECT_EQ(0, grant->needy_active);
	EXPECT_EQ(1200, rpc1->msgin.granted);
	EXPECT_EQ(1200, rpc1->msgin.rec_incoming);
}
TEST_F(homa_grant, homa_grant_check_rpc__rpc_not_grantable)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc1;

	rpc1 = test_rpc(self, 100, self->server_ip, 4000);
	homa_grant_add_active(grant, rpc1, 2);
	set_bit(RPC_GRANT_MANAGED, &rpc1->flags);
	grant->window = 1200;
	unit_log_clear();

	homa_rpc_lock(rpc1);
	clear_bit(RPC_GRANTABLE, &rpc1->flags);
	homa_grant_check_rpc(rpc1);
	set_bit(RPC_GRANTABLE, &rpc1->flags);
	homa_rpc_unlock(rpc1);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, grant->needy_active);
	EXPECT_EQ(0, rpc1->msgin.granted);
	EXPECT_EQ(0, rpc1->msgin.rec_incoming);
}
TEST_F(homa_grant, homa_grant_check_rpc__rpc_fully_received)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc1, *rpc2;

	self->homa.grant->max_overcommit = 1;
	grant->window = 1200;
	rpc1 = test_rpc_mngd(self, 100, self->server_ip, 4000);
	rpc2 = test_rpc_mngd(self, 102, self->server_ip, 6000);
	rpc1->msgin.bytes_remaining = 0;
	unit_log_clear();

	homa_rpc_lock(rpc1);
	homa_grant_check_rpc(rpc1);
	homa_rpc_unlock(rpc1);
	EXPECT_STREQ("xmit GRANT 1200@0", unit_log_get());
	EXPECT_EQ(0, rpc1->msgin.granted);
	EXPECT_EQ(-1, rpc1->msgin.active_ix);
	EXPECT_EQ(0, rpc1->msgin.rec_incoming);
	EXPECT_EQ(0, test_bit(RPC_GRANTABLE, &rpc1->flags));
	EXPECT_EQ(1200, rpc2->msgin.granted);
	EXPECT_EQ(0, rpc2->msgin.active_ix);
	EXPECT_EQ(0, grant->needy_active);
}
TEST_F(homa_grant, homa_grant_check_rpc__add_to_managed)
{
	struct homa_rpc *rpc1;

	rpc1 = test_rpc(self, 100, self->server_ip, 4000);
	unit_log_clear();
	EXPECT_EQ(0, test_bit(RPC_GRANT_MANAGED, &rpc1->flags));

	homa_rpc_lock(rpc1);
	homa_grant_check_rpc(rpc1);
	homa_rpc_unlock(rpc1);
	EXPECT_STREQ("xmit GRANT 1200@0", unit_log_get());
	EXPECT_EQ(1200, rpc1->msgin.granted);
	EXPECT_EQ(1, test_bit(RPC_GRANT_MANAGED, &rpc1->flags));
}
TEST_F(homa_grant, homa_grant_check_rpc__dont_add_to_managed_no_bpages)
{
	struct homa_rpc *rpc1;
	int saved_bpages;

	rpc1 = test_rpc(self, 100, self->server_ip, 4000);
	saved_bpages = rpc1->msgin.num_bpages;
	rpc1->msgin.num_bpages = 0;
	unit_log_clear();
	EXPECT_EQ(0, test_bit(RPC_GRANT_MANAGED, &rpc1->flags));

	homa_rpc_lock(rpc1);
	homa_grant_check_rpc(rpc1);
	homa_rpc_unlock(rpc1);
	rpc1->msgin.num_bpages = saved_bpages;
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, rpc1->msgin.granted);
	EXPECT_EQ(0, test_bit(RPC_GRANT_MANAGED, &rpc1->flags));
}
TEST_F(homa_grant, homa_grant_check_rpc__update_incoming_no_new_grant)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc1;

	rpc1 = test_rpc(self, 100, self->server_ip, 4000);
	rpc1->msgin.granted = 1600;
	rpc1->msgin.bytes_remaining = 3700;
	homa_grant_add_active(grant, rpc1, 2);
	set_bit(RPC_GRANT_MANAGED, &rpc1->flags);
	grant->window = 1200;
	unit_log_clear();

	homa_rpc_lock(rpc1);
	homa_grant_check_rpc(rpc1);
	homa_rpc_unlock(rpc1);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(1600, rpc1->msgin.granted);
	EXPECT_EQ(1300, rpc1->msgin.rec_incoming);
}
TEST_F(homa_grant, homa_grant_check_rpc__rpc_not_active)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc1;

	rpc1 = test_rpc(self, 100, self->server_ip, 4000);
	homa_grant_insert_grantable(grant, rpc1);
	set_bit(RPC_GRANT_MANAGED, &rpc1->flags);
	grant->window = 1200;
	unit_log_clear();

	homa_rpc_lock(rpc1);
	homa_grant_check_rpc(rpc1);
	homa_rpc_unlock(rpc1);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, grant->needy_active);
	EXPECT_EQ(0, rpc1->msgin.granted);
	EXPECT_EQ(0, rpc1->msgin.rec_incoming);
}
TEST_F(homa_grant, homa_grant_check_rpc__check_needy)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc1, *rpc2;

	rpc1 = test_rpc(self, 100, self->server_ip, 4000);
	homa_grant_add_active(grant, rpc1, 1);
	set_bit(RPC_GRANT_MANAGED, &rpc1->flags);

	rpc2 = test_rpc(self, 102, self->server_ip, 5000);
	homa_grant_add_active(grant, rpc2, 2);
	set_bit(RPC_GRANT_MANAGED, &rpc2->flags);

	grant->window = 1200;
	set_bit(1, &grant->needy_active);
	atomic_set(&grant->total_incoming, 8500);
	grant->max_incoming = 10000;
	unit_log_clear();

	homa_rpc_lock(rpc2);
	homa_grant_check_rpc(rpc2);
	homa_rpc_unlock(rpc2);
	EXPECT_STREQ("xmit GRANT 1200@1; xmit GRANT 300@0",
		     unit_log_get());
	EXPECT_EQ(4, grant->needy_active);
	EXPECT_EQ(1200, rpc1->msgin.granted);
	EXPECT_EQ(300, rpc2->msgin.granted);
}

TEST_F(homa_grant, homa_grant_find_oldest__check_grantable_lists)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	mock_clock = 100;
	rpc1 = test_rpc(self, 100, self->server_ip, 40000);

	mock_clock = 200;
	rpc2 = test_rpc(self, 102, self->server_ip, 20000);

	mock_clock = 300;
	rpc3 = test_rpc(self, 104, self->server_ip, 30000);

	homa_grant_insert_grantable(self->homa.grant, rpc1);
	homa_grant_insert_grantable(self->homa.grant, rpc2);
	homa_grant_insert_grantable(self->homa.grant, rpc3);

	homa_grant_find_oldest(self->homa.grant);
	ASSERT_NE(NULL, self->homa.grant->oldest_rpc);
	EXPECT_EQ(100, self->homa.grant->oldest_rpc->id);
}
TEST_F(homa_grant, homa_grant_find_oldest__fifo_grant_unused)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	self->homa.grant->fifo_grant_increment = 10000;
	mock_clock = 100;
	rpc1 = test_rpc(self, 100, self->server_ip, 400000);
	rpc1->msgin.rec_incoming = 20000 + self->homa.grant->window;

	mock_clock = 200;
	rpc2 = test_rpc(self, 102, self->server_ip, 20000);

	mock_clock = 300;
	rpc3 = test_rpc(self, 104, self->server_ip, 30000);
	homa_grant_insert_grantable(self->homa.grant, rpc1);
	homa_grant_insert_grantable(self->homa.grant, rpc2);
	homa_grant_insert_grantable(self->homa.grant, rpc3);

	homa_grant_find_oldest(self->homa.grant);
	ASSERT_NE(NULL, self->homa.grant->oldest_rpc);
	EXPECT_EQ(102, self->homa.grant->oldest_rpc->id);
}
TEST_F(homa_grant, homa_grant_find_oldest__oldest_doesnt_need_grants)
{
	struct homa_rpc *rpc1, *rpc2;

	mock_clock = 100;
	rpc1 = test_rpc(self, 100, self->server_ip, 40000);
	rpc1->msgin.granted = rpc1->msgin.length;

	mock_clock = 200;
	rpc2 = test_rpc(self, 102, self->server_ip, 20000);

	homa_grant_insert_grantable(self->homa.grant, rpc1);
	homa_grant_insert_grantable(self->homa.grant, rpc2);

	homa_grant_find_oldest(self->homa.grant);
	ASSERT_NE(NULL, self->homa.grant->oldest_rpc);
	EXPECT_EQ(102, self->homa.grant->oldest_rpc->id);
}
TEST_F(homa_grant, homa_grant_find_oldest__check_active_rpcs)
{
	struct homa_grant *grant = self->homa.grant;

	mock_clock = 100;
	test_rpc_mngd(self, 100, self->server_ip, 40000);

	mock_clock = 200;
	test_rpc_mngd(self, 102, self->server_ip, 20000);

	mock_clock = 300;
	test_rpc_mngd(self, 104, self->server_ip, 30000);
	EXPECT_EQ(3, grant->num_active);

	homa_grant_find_oldest(grant);
	ASSERT_NE(NULL, grant->oldest_rpc);
	EXPECT_EQ(100, grant->oldest_rpc->id);
}
TEST_F(homa_grant, homa_grant_find_oldest__active_rpc_has_unused_fifo_grant)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc1, *rpc2;

	self->homa.grant->fifo_grant_increment = 10000;

	mock_clock = 100;
	rpc1 = test_rpc_mngd(self, 100, self->server_ip, 400000);
	rpc1->msgin.rec_incoming = 20000 + self->homa.grant->window;

	mock_clock = 300;
	test_rpc_mngd(self, 102, self->server_ip, 20000);

	mock_clock = 200;
	rpc2 = test_rpc(self, 104, self->server_ip, 30000);
	homa_grant_insert_grantable(grant, rpc2);
	EXPECT_EQ(2, grant->num_active);

	homa_grant_find_oldest(grant);
	ASSERT_NE(NULL, grant->oldest_rpc);
	EXPECT_EQ(104, grant->oldest_rpc->id);
}
TEST_F(homa_grant, homa_grant_find_oldest__active_rpc_doesnt_need_grants)
{
	struct homa_grant *grant = self->homa.grant;
	struct homa_rpc *rpc1;

	mock_clock = 100;
	rpc1 = test_rpc_mngd(self, 100, self->server_ip, 40000);
	rpc1->msgin.granted = rpc1->msgin.length;

	mock_clock = 200;
	test_rpc_mngd(self, 102, self->server_ip, 20000);

	EXPECT_EQ(2, grant->num_active);

	homa_grant_find_oldest(grant);
	ASSERT_NE(NULL, grant->oldest_rpc);
	EXPECT_EQ(102, grant->oldest_rpc->id);
}
TEST_F(homa_grant, homa_grant_find_oldest__no_good_candidates)
{
	self->homa.grant->oldest_rpc =
			test_rpc(self, 100, self->server_ip, 40000);
	homa_grant_find_oldest(self->homa.grant);
	EXPECT_EQ(NULL, self->homa.grant->oldest_rpc);
}
TEST_F(homa_grant, homa_grant_find_oldest__take_reference)
{
	struct homa_rpc *rpc;

	rpc = test_rpc(self, 100, self->server_ip, 40000);
	homa_grant_insert_grantable(self->homa.grant, rpc);
	EXPECT_EQ(1, refcount_read(&rpc->refs));

	homa_grant_find_oldest(self->homa.grant);
	EXPECT_EQ(rpc, self->homa.grant->oldest_rpc);
	EXPECT_EQ(2, refcount_read(&rpc->refs));
}

TEST_F(homa_grant, homa_grant_check_fifo__basics)
{
	struct homa_rpc *rpc;

	mock_clock = 1000;
	self->homa.num_priorities = 5;
	self->homa.grant->max_overcommit = 1;
	self->homa.grant->fifo_grant_time = 0;
	self->homa.grant->fifo_grant_interval = 10000;
	self->homa.grant->fifo_grant_increment = 20000;
	self->homa.grant->fifo_fraction = 50;

	test_rpc_mngd(self, 100, self->server_ip, 30000);
	rpc = test_rpc_mngd(self, 102, self->server_ip, 400000);
	EXPECT_EQ(-1, rpc->msgin.active_ix);
	EXPECT_EQ(0, rpc->msgin.granted);

	unit_log_clear();
	homa_grant_check_fifo(self->homa.grant);
	EXPECT_EQ(20000, rpc->msgin.granted);
	EXPECT_STREQ("xmit GRANT 20000@3", unit_log_get());
	EXPECT_EQ(rpc, self->homa.grant->oldest_rpc);
	EXPECT_EQ(11000, self->homa.grant->fifo_grant_time);
	EXPECT_EQ(20000, rpc->msgin.rec_incoming);
	EXPECT_EQ(20000, atomic_read(&self->homa.grant->total_incoming));
	EXPECT_EQ(20000, homa_metrics_per_cpu()->fifo_grant_bytes);
}
TEST_F(homa_grant, homa_grant_check_fifo__not_yet_time_for_a_fifo_grant)
{
	struct homa_rpc *rpc;

	mock_clock = 1000;
	self->homa.grant->max_overcommit = 1;
	self->homa.grant->fifo_grant_time = 1001;
	self->homa.grant->fifo_grant_increment = 20000;

	test_rpc_mngd(self, 100, self->server_ip, 30000);
	rpc = test_rpc_mngd(self, 102, self->server_ip, 400000);
	EXPECT_EQ(0, rpc->msgin.granted);

	unit_log_clear();
	homa_grant_check_fifo(self->homa.grant);
	EXPECT_EQ(0, rpc->msgin.granted);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(NULL, self->homa.grant->oldest_rpc);
	EXPECT_EQ(1001, self->homa.grant->fifo_grant_time);
}
TEST_F(homa_grant, homa_grant_check_fifo__fifo_grants_disabled)
{
	struct homa_rpc *rpc;

	mock_clock = 1000;
	self->homa.grant->max_overcommit = 1;
	self->homa.grant->fifo_grant_time = 1000;
	self->homa.grant->fifo_grant_increment = 0;
	self->homa.grant->fifo_grant_interval = 2000;
	self->homa.grant->fifo_fraction = 50;

	test_rpc_mngd(self, 100, self->server_ip, 30000);
	rpc = test_rpc_mngd(self, 102, self->server_ip, 400000);
	EXPECT_EQ(0, rpc->msgin.granted);

	unit_log_clear();
	homa_grant_check_fifo(self->homa.grant);
	EXPECT_EQ(0, rpc->msgin.granted);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(NULL, self->homa.grant->oldest_rpc);
	EXPECT_EQ(3000, self->homa.grant->fifo_grant_time);
}
TEST_F(homa_grant, homa_grant_check_fifo__oldest_rpc_not_responsive)
{
	struct homa_rpc *rpc1, *rpc2;

	mock_clock = 1000;
	self->homa.grant->max_overcommit = 1;
	self->homa.grant->fifo_grant_time = 1000;
	self->homa.grant->fifo_grant_increment = 20000;
	self->homa.grant->fifo_fraction = 50;

	mock_clock = 1000;
	rpc1 = test_rpc_mngd(self, 102, self->server_ip, 400000);
	mock_clock = 3000;
	rpc2 = test_rpc_mngd(self, 104, self->server_ip, 300000);
	homa_grant_find_oldest(self->homa.grant);
	EXPECT_EQ(102, self->homa.grant->oldest_rpc->id);
	rpc1->msgin.rec_incoming = 40000 + self->homa.grant->window;

	unit_log_clear();
	homa_grant_check_fifo(self->homa.grant);
	EXPECT_EQ(0, rpc1->msgin.granted);
	EXPECT_EQ(20000, rpc2->msgin.granted);
	EXPECT_STREQ("xmit GRANT 20000@0", unit_log_get());
	EXPECT_EQ(104, self->homa.grant->oldest_rpc->id);
}
TEST_F(homa_grant, homa_grant_check_fifo__oldest_is_fully_granted_so_pick_another)
{
	struct homa_rpc *rpc1, *rpc2;

	self->homa.grant->max_overcommit = 1;
	self->homa.grant->fifo_grant_time = 1000;
	self->homa.grant->fifo_grant_increment = 20000;
	self->homa.grant->fifo_fraction = 50;

	mock_clock = 1000;
	rpc1 = test_rpc_mngd(self, 102, self->server_ip, 400000);
	mock_clock = 3000;
	rpc2 = test_rpc_mngd(self, 104, self->server_ip, 300000);
	homa_grant_find_oldest(self->homa.grant);
	EXPECT_EQ(102, self->homa.grant->oldest_rpc->id);
	rpc1->msgin.granted = rpc1->msgin.length;

	unit_log_clear();
	homa_grant_check_fifo(self->homa.grant);
	EXPECT_EQ(400000, rpc1->msgin.granted);
	EXPECT_EQ(20000, rpc2->msgin.granted);
	EXPECT_STREQ("xmit GRANT 20000@0", unit_log_get());
	EXPECT_EQ(104, self->homa.grant->oldest_rpc->id);
}
TEST_F(homa_grant, homa_grant_check_fifo__no_suitable_rpc)
{
	struct homa_rpc *rpc1;

	mock_clock = 1000;
	self->homa.grant->max_overcommit = 1;
	self->homa.grant->fifo_grant_time = 1000;
	self->homa.grant->fifo_grant_increment = 20000;
	self->homa.grant->fifo_fraction = 50;

	rpc1 = test_rpc_mngd(self, 100, self->server_ip, 30000);
	rpc1->msgin.rec_incoming = 40000 + self->homa.grant->window;

	unit_log_clear();
	homa_grant_check_fifo(self->homa.grant);
	EXPECT_EQ(NULL, self->homa.grant->oldest_rpc);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_grant, homa_grant_check_fifo__rpc_dead)
{
	struct homa_rpc *rpc;
	int saved_state;

	mock_clock = 1000;
	self->homa.grant->max_overcommit = 1;
	self->homa.grant->fifo_grant_time = 0;
	self->homa.grant->fifo_grant_increment = 20000;
	self->homa.grant->fifo_fraction = 50;

	test_rpc_mngd(self, 100, self->server_ip, 30000);
	rpc = test_rpc_mngd(self, 102, self->server_ip, 400000);
	EXPECT_EQ(-1, rpc->msgin.active_ix);
	EXPECT_EQ(0, rpc->msgin.granted);
	self->homa.grant->oldest_rpc = rpc;
	homa_rpc_hold(rpc);

	unit_log_clear();
	saved_state = rpc->state;
	rpc->state = RPC_DEAD;
	homa_grant_check_fifo(self->homa.grant);
	rpc->state = saved_state;
	EXPECT_EQ(0, rpc->msgin.granted);
	EXPECT_EQ(0, homa_metrics_per_cpu()->fifo_grant_bytes);
}

TEST_F(homa_grant, homa_grant_lock_slow)
{
	mock_clock = 500;
	unit_hook_register(grant_spinlock_hook);

	homa_grant_lock_slow(self->homa.grant);
	homa_grant_unlock(self->homa.grant);

	EXPECT_EQ(1, homa_metrics_per_cpu()->grant_lock_misses);
	EXPECT_EQ(500, homa_metrics_per_cpu()->grant_lock_miss_cycles);
}

TEST_F(homa_grant, homa_grant_update_sysctl_deps__max_overcommit)
{
	self->homa.grant->max_overcommit = 2;
	homa_grant_update_sysctl_deps(self->homa.grant);
	EXPECT_EQ(2, self->homa.grant->max_overcommit);

	self->homa.grant->max_overcommit = HOMA_MAX_GRANTS;
	homa_grant_update_sysctl_deps(self->homa.grant);
	EXPECT_EQ(HOMA_MAX_GRANTS, self->homa.grant->max_overcommit);

	self->homa.grant->max_overcommit = HOMA_MAX_GRANTS+1;
	homa_grant_update_sysctl_deps(self->homa.grant);
	EXPECT_EQ(HOMA_MAX_GRANTS, self->homa.grant->max_overcommit);
}
TEST_F(homa_grant, homa_grant_update_sysctl_deps__fifo_fraction)
{
	self->homa.grant->fifo_fraction = 499;
	homa_grant_update_sysctl_deps(self->homa.grant);
	EXPECT_EQ(499, self->homa.grant->fifo_fraction);

	self->homa.grant->fifo_fraction = 501;
	homa_grant_update_sysctl_deps(self->homa.grant);
	EXPECT_EQ(500, self->homa.grant->fifo_fraction);
}
TEST_F(homa_grant, homa_grant_update_sysctl_deps__fifo_interval)
{
	self->homa.grant->fifo_grant_increment = 20000;
	self->homa.grant->fifo_fraction = 500;
	self->homa.link_mbps = 8000;
	homa_grant_update_sysctl_deps(self->homa.grant);
	EXPECT_EQ(40000, self->homa.grant->fifo_grant_interval);
}
TEST_F(homa_grant, homa_grant_update_sysctl_deps__fifo_interval_no_fifo_grants)
{
	self->homa.grant->fifo_grant_increment = 20000;
	self->homa.grant->fifo_fraction = 0;
	self->homa.link_mbps = 8000;
	homa_grant_update_sysctl_deps(self->homa.grant);
	EXPECT_EQ(1000000000, self->homa.grant->fifo_grant_interval);
}
TEST_F(homa_grant, homa_grant_update_sysctl_deps__grant_window_fixed_size)
{
	self->homa.grant->window_param = 50000;
	homa_grant_update_sysctl_deps(self->homa.grant);
	EXPECT_EQ(50000, self->homa.grant->windows[1]);
	EXPECT_EQ(50000, self->homa.grant->windows[2]);
	EXPECT_EQ(50000, self->homa.grant->windows[3]);
	EXPECT_EQ(50000, self->homa.grant->windows[HOMA_MAX_GRANTS - 1]);
	EXPECT_EQ(50000, self->homa.grant->windows[HOMA_MAX_GRANTS]);
}
TEST_F(homa_grant, homa_grant_update_sysctl_deps__dynamic_windows)
{
	self->homa.grant->window_param = 0;
	self->homa.grant->max_incoming = 100000;
	homa_grant_update_sysctl_deps(self->homa.grant);
	EXPECT_EQ(50000, self->homa.grant->windows[1]);
	EXPECT_EQ(33333, self->homa.grant->windows[2]);
	EXPECT_EQ(25000, self->homa.grant->windows[3]);
	EXPECT_EQ(12500, self->homa.grant->windows[HOMA_MAX_GRANTS - 1]);
	EXPECT_EQ(11111, self->homa.grant->windows[HOMA_MAX_GRANTS]);
}
