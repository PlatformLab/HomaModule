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

static struct homa_grant *hook_grant;
static void grant_check_stalled_hook(char *id)
{
	if (strcmp(id, "grant_check_needy") != 0)
		return;
	atomic_dec(&hook_grant->stalled_rank);
}

static struct homa_rpc *hook_end_rpc;
static int hook_end_lock_count;
static void grant_spinlock_end_hook(char *id)
{
	if (strcmp(id, "spin_lock") != 0)
		return;
	if (hook_end_lock_count > 0) {
		hook_end_lock_count--;
		if (hook_end_lock_count == 0)
			homa_rpc_end(hook_end_rpc);
	}
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
	struct homa_grant_candidates cand;
};
FIXTURE_SETUP(homa_grant)
{
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
	self->homa.grant->window = 10000;
	self->homa.grant->max_incoming = 50000;
	self->homa.grant->max_rpcs_per_peer = 10;
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
	homa_grant_cand_init(&self->cand);
}
FIXTURE_TEARDOWN(homa_grant)
{
	homa_grant_cand_check(&self->cand, self->homa.grant);
	homa_destroy(&self->homa);
	unit_teardown();
}

/* Create a client RPC whose msgin is mostly initialized, except
 * homa_grant_init_rpc isn't invoked.
 */
static struct homa_rpc *test_rpc(FIXTURE_DATA(homa_grant) *self,
		u64 id, struct in6_addr *server_ip, int size)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, server_ip, self->server_port,
			id, 1000, size);

	rpc->msgin.length = size;
	skb_queue_head_init(&rpc->msgin.packets);
	INIT_LIST_HEAD(&rpc->msgin.gaps);
	rpc->msgin.bytes_remaining = size;
	rpc->msgin.rank = -1;
	rpc->msgin.granted = 1000;
	return rpc;
}

/* Create a client RPC whose msgin is properly initialized with no
 * unscheduled bytes and no packets received.
 */
static struct homa_rpc *test_rpc_init(FIXTURE_DATA(homa_grant) *self,
		u64 id, struct in6_addr *server_ip, int size)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, server_ip, self->server_port,
			id, 1000, size);
	homa_message_in_init(rpc, size, 0);
	return rpc;
}

TEST_F(homa_grant, homa_grant_alloc__success)
{
	struct homa_grant *grant;

	grant = homa_grant_alloc(&self->homa);
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

TEST_F(homa_grant, homa_grant_init_rpc__grants_not_needed)
{
	struct homa_rpc *rpc;

	rpc= unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
		              self->server_ip, self->server_port, 100, 1000,
			      20000);
	homa_message_in_init(rpc, 2000, 2000);
	EXPECT_EQ(-1, rpc->msgin.rank);
	EXPECT_EQ(2000, rpc->msgin.granted);
}
TEST_F(homa_grant, homa_grant_init_rpc__grants_needed)
{
	struct homa_rpc *rpc;

	rpc= unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
		              self->server_ip, self->server_port, 100, 1000,
			      20000);

	homa_message_in_init(rpc, 5000, 2000);
	EXPECT_EQ(0, rpc->msgin.rank);
	EXPECT_EQ(2000, rpc->msgin.granted);
}
TEST_F(homa_grant, homa_grant_init_rpc__no_bpages_available)
{
	struct homa_rpc *rpc;

	rpc= unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
		              self->server_ip, self->server_port, 100, 1000,
			      20000);

	atomic_set(&self->hsk.buffer_pool->free_bpages, 0);
	homa_message_in_init(rpc, 20000, 10000);
	EXPECT_EQ(0, rpc->msgin.num_bpages);
	EXPECT_EQ(-1, rpc->msgin.rank);
	EXPECT_EQ(10000, rpc->msgin.granted);
}

TEST_F(homa_grant, homa_grant_end_rpc__basics)
{
	struct homa_rpc *rpc;

	rpc = test_rpc_init(self, 100, self->server_ip, 20000);
	rpc->msgin.rec_incoming = 100;
	EXPECT_EQ(0, rpc->msgin.rank);

	unit_hook_register(grant_spinlock_hook);
	hook_spinlock_count = 0;

	homa_grant_end_rpc(rpc);
	EXPECT_EQ(-1, rpc->msgin.rank);
	EXPECT_EQ(1, hook_spinlock_count);
	EXPECT_EQ(-100, atomic_read(&self->homa.grant->total_incoming));
	EXPECT_EQ(0, rpc->msgin.rec_incoming);
}
TEST_F(homa_grant, homa_grant_end_rpc__skip_cleanup_if_fully_granted)
{
	struct homa_rpc *rpc;

	rpc = test_rpc_init(self, 100, self->server_ip, 20000);
	rpc->msgin.rec_incoming = 100;
	rpc->msgin.granted = rpc->msgin.length;
	EXPECT_EQ(0, rpc->msgin.rank);

	homa_grant_end_rpc(rpc);
	EXPECT_EQ(0, rpc->msgin.rank);
	EXPECT_EQ(-100, atomic_read(&self->homa.grant->total_incoming));
	EXPECT_EQ(0, rpc->msgin.rec_incoming);
}
TEST_F(homa_grant, homa_grant_end_rpc__activate_other_rpc)
{
	struct homa_rpc *rpc1, *rpc2;

	self->homa.grant->max_rpcs_per_peer = 1;
	rpc1 = test_rpc_init(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc_init(self, 102, self->server_ip, 30000);
	EXPECT_EQ(0, rpc1->msgin.rank);
	EXPECT_EQ(-1, rpc2->msgin.rank);

	unit_hook_register(grant_spinlock_hook);
	hook_spinlock_count = 0;

	unit_log_clear();
	homa_rpc_lock(rpc1);
	homa_grant_end_rpc(rpc1);
	homa_rpc_unlock(rpc1);
	EXPECT_EQ(-1, rpc1->msgin.rank);
	EXPECT_EQ(0, rpc2->msgin.rank);
	EXPECT_EQ(4, hook_spinlock_count);
	EXPECT_STREQ("xmit GRANT 10000@0", unit_log_get());
}

TEST_F(homa_grant, homa_grant_window)
{
	/* Static grant window. */
	self->homa.grant->window_param = 5000;
	EXPECT_EQ(5000, homa_grant_window(self->homa.grant));

	/* Dynamic grant window. */
	self->homa.grant->window_param = 0;
	self->homa.grant->max_incoming = 100000;
	self->homa.grant->num_active_rpcs = 4;
	EXPECT_EQ(20000, homa_grant_window(self->homa.grant));
}

TEST_F(homa_grant, homa_grant_outranks)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3, *rpc4;

	rpc1 = test_rpc(self, 100, self->server_ip, 20000);
	rpc1->msgin.birth = 3000;
	rpc2 = test_rpc(self, 102, self->server_ip, 30000);
	rpc2->msgin.birth = 2000;
	rpc3 = test_rpc(self, 104, self->server_ip, 30000);
	rpc3->msgin.birth = 1999;
	rpc4 = test_rpc(self, 106, self->server_ip, 30000);
	rpc4->msgin.birth = 2000;

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
	self->homa.grant->num_active_rpcs = 7;
	EXPECT_EQ(6, homa_grant_priority(&self->homa, 0));
	EXPECT_EQ(0, homa_grant_priority(&self->homa, 7));
}
TEST_F(homa_grant, homa_grant_priority__extra_levels)
{
	self->homa.max_sched_prio = 6;
	self->homa.grant->num_active_rpcs = 4;
	EXPECT_EQ(3, homa_grant_priority(&self->homa, 0));
	EXPECT_EQ(0, homa_grant_priority(&self->homa, 7));
}

TEST_F(homa_grant, homa_grant_insert_active__basics)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	rpc1 = test_rpc(self, 100, self->server_ip, 30000);
	rpc2 = test_rpc(self, 102, self->server_ip, 20000);
	rpc3 = test_rpc(self, 104, self->server_ip, 30000);

	EXPECT_EQ(NULL, homa_grant_insert_active(rpc1));
	EXPECT_EQ(0, rpc1->msgin.rank);

	EXPECT_EQ(NULL, homa_grant_insert_active(rpc2));
	EXPECT_EQ(1, rpc1->msgin.rank);
	EXPECT_EQ(0, rpc2->msgin.rank);

	EXPECT_EQ(NULL, homa_grant_insert_active(rpc3));
	EXPECT_EQ(1, rpc1->msgin.rank);
	EXPECT_EQ(0, rpc2->msgin.rank);
	EXPECT_EQ(2, rpc3->msgin.rank);
	EXPECT_EQ(3, rpc1->peer->active_rpcs);
}
TEST_F(homa_grant, homa_grant_insert_active__too_many_from_same_peer)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3, *rpc4;

	rpc1 = test_rpc(self, 100, self->server_ip, 10000);
	rpc2 = test_rpc(self, 102, self->server_ip, 20000);
	rpc3 = test_rpc(self, 104, &self->server_ip[1], 30000);
	rpc4 = test_rpc(self, 106, self->server_ip, 25000);

	self->homa.grant->max_rpcs_per_peer = 2;
	EXPECT_EQ(NULL, homa_grant_insert_active(rpc1));
	EXPECT_EQ(NULL, homa_grant_insert_active(rpc2));
	EXPECT_EQ(NULL, homa_grant_insert_active(rpc3));
	EXPECT_EQ(rpc4, homa_grant_insert_active(rpc4));
	EXPECT_EQ(0, rpc1->msgin.rank);
	EXPECT_EQ(1, rpc2->msgin.rank);
	EXPECT_EQ(2, rpc3->msgin.rank);
	EXPECT_EQ(-1, rpc4->msgin.rank);
	EXPECT_EQ(2, rpc1->peer->active_rpcs);
}
TEST_F(homa_grant, homa_grant_insert_active__bump_rpc_from_same_peer)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3, *rpc4;

	rpc1 = test_rpc(self, 100, self->server_ip, 10000);
	rpc2 = test_rpc(self, 102, &self->server_ip[1], 20000);
	rpc3 = test_rpc(self, 104, self->server_ip, 30000);
	rpc4 = test_rpc(self, 106, self->server_ip, 5000);

	self->homa.grant->max_rpcs_per_peer = 2;
	EXPECT_EQ(NULL, homa_grant_insert_active(rpc1));
	EXPECT_EQ(NULL, homa_grant_insert_active(rpc2));
	EXPECT_EQ(NULL, homa_grant_insert_active(rpc3));
	EXPECT_EQ(rpc3, homa_grant_insert_active(rpc4));
	EXPECT_EQ(1, rpc1->msgin.rank);
	EXPECT_EQ(2, rpc2->msgin.rank);
	EXPECT_EQ(-1, rpc3->msgin.rank);
	EXPECT_EQ(0, rpc4->msgin.rank);
	EXPECT_EQ(2, rpc1->peer->active_rpcs);
	EXPECT_EQ(3, self->homa.grant->num_active_rpcs);
}
TEST_F(homa_grant, homa_grant_insert_active__no_room_for_new_rpc)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3, *rpc4;

	rpc1 = test_rpc(self, 100, self->server_ip, 10000);
	rpc2 = test_rpc(self, 102, self->server_ip, 20000);
	rpc3 = test_rpc(self, 104, self->server_ip, 30000);
	rpc4 = test_rpc(self, 106, self->server_ip, 30000);

	self->homa.grant->max_overcommit = 3;
	EXPECT_EQ(NULL, homa_grant_insert_active(rpc1));
	EXPECT_EQ(NULL, homa_grant_insert_active(rpc2));
	EXPECT_EQ(NULL, homa_grant_insert_active(rpc3));
	EXPECT_EQ(rpc4, homa_grant_insert_active(rpc4));
	EXPECT_EQ(0, rpc1->msgin.rank);
	EXPECT_EQ(1, rpc2->msgin.rank);
	EXPECT_EQ(2, rpc3->msgin.rank);
	EXPECT_EQ(-1, rpc4->msgin.rank);
	EXPECT_EQ(3, self->homa.grant->num_active_rpcs);
}
TEST_F(homa_grant, homa_grant_insert_active__insert_in_middle_and_bump)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3, *rpc4;

	rpc1 = test_rpc(self, 100, self->server_ip, 10000);
	rpc2 = test_rpc(self, 102, self->server_ip, 20000);
	rpc3 = test_rpc(self, 104, self->server_ip, 30000);
	rpc4 = test_rpc(self, 106, self->server_ip, 15000);

	self->homa.grant->max_overcommit = 3;
	EXPECT_EQ(NULL, homa_grant_insert_active(rpc1));
	EXPECT_EQ(NULL, homa_grant_insert_active(rpc2));
	EXPECT_EQ(NULL, homa_grant_insert_active(rpc3));
	EXPECT_EQ(rpc3, homa_grant_insert_active(rpc4));
	EXPECT_EQ(0, rpc1->msgin.rank);
	EXPECT_EQ(2, rpc2->msgin.rank);
	EXPECT_EQ(-1, rpc3->msgin.rank);
	EXPECT_EQ(1, rpc4->msgin.rank);
	EXPECT_EQ(3, self->homa.grant->num_active_rpcs);
	EXPECT_EQ(rpc4, self->homa.grant->active_rpcs[1]);
	EXPECT_EQ(rpc2, self->homa.grant->active_rpcs[2]);
	EXPECT_EQ(3, rpc1->peer->active_rpcs);
}
TEST_F(homa_grant, homa_grant_insert_active__insert_in_middle_no_bump)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3, *rpc4;

	rpc1 = test_rpc(self, 100, self->server_ip, 10000);
	rpc2 = test_rpc(self, 102, self->server_ip, 20000);
	rpc3 = test_rpc(self, 104, self->server_ip, 30000);
	rpc4 = test_rpc(self, 106, self->server_ip, 15000);

	EXPECT_EQ(NULL, homa_grant_insert_active(rpc1));
	EXPECT_EQ(NULL, homa_grant_insert_active(rpc2));
	EXPECT_EQ(NULL, homa_grant_insert_active(rpc3));
	EXPECT_EQ(NULL, homa_grant_insert_active(rpc4));
	EXPECT_EQ(0, rpc1->msgin.rank);
	EXPECT_EQ(2, rpc2->msgin.rank);
	EXPECT_EQ(3, rpc3->msgin.rank);
	EXPECT_EQ(1, rpc4->msgin.rank);
	EXPECT_EQ(4, self->homa.grant->num_active_rpcs);
	EXPECT_EQ(rpc4, self->homa.grant->active_rpcs[1]);
	EXPECT_EQ(rpc2, self->homa.grant->active_rpcs[2]);
	EXPECT_EQ(rpc3, self->homa.grant->active_rpcs[3]);
	EXPECT_EQ(4, rpc1->peer->active_rpcs);
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

	homa_grant_insert_grantable(test_rpc(self, 200, self->server_ip + 1,
					     100000));
	homa_grant_insert_grantable(test_rpc(self, 300, self->server_ip + 2,
					     50000));
	list_add_tail(&rpc->grantable_links, &rpc->peer->grantable_rpcs);
	homa_grant_adjust_peer(self->homa.grant, rpc->peer);

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("peer 3.2.3.4: id 300 ungranted 49000; "
		     "peer 1.2.3.4: id 100 ungranted 69000; "
		     "peer 2.2.3.4: id 200 ungranted 99000",
		     unit_log_get());
}
TEST_F(homa_grant, homa_grant_adjust_peer__append_to_grantable_peers)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 120000);

	homa_grant_insert_grantable(test_rpc(self, 200, self->server_ip + 1,
					     100000));
	homa_grant_insert_grantable(test_rpc(self, 300, self->server_ip + 2,
					     50000));
	list_add_tail(&rpc->grantable_links, &rpc->peer->grantable_rpcs);
	homa_grant_adjust_peer(self->homa.grant, rpc->peer);

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("peer 3.2.3.4: id 300 ungranted 49000; "
		     "peer 2.2.3.4: id 200 ungranted 99000; "
		     "peer 1.2.3.4: id 100 ungranted 119000",
		     unit_log_get());
}
TEST_F(homa_grant, homa_grant_adjust_peer__move_peer_upwards)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 120000);

	homa_grant_insert_grantable(rpc);
	homa_grant_insert_grantable(test_rpc(self, 200, self->server_ip + 1,
					     100000));
	homa_grant_insert_grantable(test_rpc(self, 300, self->server_ip + 2,
					     50000));
	homa_grant_insert_grantable(test_rpc(self, 400, self->server_ip + 3,
					     80000));
	rpc->msgin.granted += 45000;
	homa_grant_adjust_peer(self->homa.grant, rpc->peer);

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("peer 3.2.3.4: id 300 ungranted 49000; "
		     "peer 1.2.3.4: id 100 ungranted 74000; "
		     "peer 4.2.3.4: id 400 ungranted 79000; "
		     "peer 2.2.3.4: id 200 ungranted 99000",
		     unit_log_get());
}
TEST_F(homa_grant, homa_grant_adjust_peer__move_peer_to_front)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 100000);

	homa_grant_insert_grantable(rpc);
	homa_grant_insert_grantable(test_rpc(self, 200, self->server_ip + 1,
					     50000));
	rpc->msgin.granted += 55000;
	homa_grant_adjust_peer(self->homa.grant, rpc->peer);

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("peer 1.2.3.4: id 100 ungranted 44000; "
		     "peer 2.2.3.4: id 200 ungranted 49000",
		     unit_log_get());
}
TEST_F(homa_grant, homa_grant_adjust_peer__move_peer_downwards)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 40000);

	homa_grant_insert_grantable(rpc);
	homa_grant_insert_grantable(test_rpc(self, 200, self->server_ip + 1,
					     100000));
	homa_grant_insert_grantable(test_rpc(self, 300, self->server_ip + 2,
					     50000));
	homa_grant_insert_grantable(test_rpc(self, 400, self->server_ip + 3,
					     80000));
	rpc->msgin.length += 41000;
	homa_grant_adjust_peer(self->homa.grant, rpc->peer);

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("peer 3.2.3.4: id 300 ungranted 49000; "
		     "peer 4.2.3.4: id 400 ungranted 79000; "
		     "peer 1.2.3.4: id 100 ungranted 80000; "
		     "peer 2.2.3.4: id 200 ungranted 99000",
		     unit_log_get());
}
TEST_F(homa_grant, homa_grant_adjust_peer__move_peer_to_back)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 50000);

	homa_grant_insert_grantable(rpc);
	homa_grant_insert_grantable(test_rpc(self, 200, self->server_ip + 1,
					     100000));
	rpc->msgin.length += 55000;
	homa_grant_adjust_peer(self->homa.grant, rpc->peer);

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("peer 2.2.3.4: id 200 ungranted 99000; "
		     "peer 1.2.3.4: id 100 ungranted 104000",
		     unit_log_get());
}

TEST_F(homa_grant, homa_grant_insert_grantable__insert_in_peer_list)
{
	homa_grant_insert_grantable(test_rpc(self, 100, self->server_ip,
					     100000));
	homa_grant_insert_grantable(test_rpc(self, 200, self->server_ip,
					     50000));
	homa_grant_insert_grantable(test_rpc(self, 300, self->server_ip,
					     1200000));
	homa_grant_insert_grantable(test_rpc(self, 400, self->server_ip,
					     70000));
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("peer 1.2.3.4: id 200 ungranted 49000 "
		     "id 400 ungranted 69000 "
		     "id 100 ungranted 99000 "
		     "id 300 ungranted 1199000",
		     unit_log_get());
}
TEST_F(homa_grant, homa_grant_insert_grantable__insert_peer_in_grantable_peers)
{
	homa_grant_insert_grantable(test_rpc(self, 200, self->server_ip,
				    100000));
	homa_grant_insert_grantable(test_rpc(self, 300, self->server_ip+1,
				    50000));
	homa_grant_insert_grantable(test_rpc(self, 400, self->server_ip+2,
		                    120000));
	homa_grant_insert_grantable(test_rpc(self, 500, self->server_ip+3,
		                    70000));

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("peer 2.2.3.4: id 300 ungranted 49000; "
		     "peer 4.2.3.4: id 500 ungranted 69000; "
		     "peer 1.2.3.4: id 200 ungranted 99000; "
		     "peer 3.2.3.4: id 400 ungranted 119000",
		     unit_log_get());
}

TEST_F(homa_grant, homa_grant_manage_rpc__update_metrics)
{
	self->homa.grant->last_grantable_change = 50;
	self->homa.grant->num_grantable_rpcs = 3;
	mock_clock = 200;
	homa_grant_manage_rpc(test_rpc(self, 100, self->server_ip, 100000));
	EXPECT_EQ(4, self->homa.grant->num_grantable_rpcs);
	EXPECT_EQ(450, homa_metrics_per_cpu()->grantable_rpcs_integral);
	EXPECT_EQ(200, self->homa.grant->last_grantable_change);
}
TEST_F(homa_grant, homa_grant_manage_rpc__dont_change_max_grantable_rpcs)
{
	self->homa.grant->num_grantable_rpcs = 3;
	self->homa.grant->max_grantable_rpcs = 5;
	homa_grant_manage_rpc(test_rpc(self, 100, self->server_ip, 100000));
	EXPECT_EQ(4, self->homa.grant->num_grantable_rpcs);
	EXPECT_EQ(5, self->homa.grant->max_grantable_rpcs);
}
TEST_F(homa_grant, homa_grant_manage_rpc__insert_and_bump_to_grantables)
{
	struct homa_rpc *rpc1, *rpc2;

	rpc1 = test_rpc(self, 100, self->server_ip, 50000);
	rpc2 = test_rpc(self, 102, self->server_ip, 20000);

	self->homa.grant->max_overcommit = 1;
	self->homa.grant->last_grantable_change = 50;
	self->homa.grant->num_grantable_rpcs = 3;
	mock_clock = 200;
	homa_grant_manage_rpc(rpc1);
	mock_clock = 300;
	homa_grant_manage_rpc(rpc2);
	EXPECT_EQ(5, self->homa.grant->max_grantable_rpcs);
	EXPECT_EQ(850, homa_metrics_per_cpu()->grantable_rpcs_integral);
	EXPECT_EQ(300, self->homa.grant->last_grantable_change);
	EXPECT_EQ(-1, rpc1->msgin.rank);
	EXPECT_EQ(0, rpc2->msgin.rank);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 102 ungranted 19000; "
		     "peer 1.2.3.4: id 100 ungranted 49000", unit_log_get());
}
TEST_F(homa_grant, homa_grant_manage_rpc__set_window)
{
	struct homa_rpc *rpc1;

	rpc1 = test_rpc(self, 100, self->server_ip, 50000);

	self->homa.grant->max_incoming = 100000;
	self->homa.grant->window_param = 0;
	homa_grant_manage_rpc(rpc1);
	EXPECT_EQ(50000, self->homa.grant->window);
}

TEST_F(homa_grant, homa_grant_remove_grantable__not_first_in_peer_list)
{
	struct homa_rpc *rpc = test_rpc(self, 300, self->server_ip, 30000);

	homa_grant_insert_grantable(test_rpc(self, 200, self->server_ip,
					     20000));
	homa_grant_insert_grantable(rpc);
	homa_grant_insert_grantable(test_rpc(self, 400, self->server_ip+1,
					     25000));

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("peer 1.2.3.4: id 200 ungranted 19000 "
		     "id 300 ungranted 29000; "
		     "peer 2.2.3.4: id 400 ungranted 24000",
		     unit_log_get());

	homa_grant_remove_grantable(rpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("peer 1.2.3.4: id 200 ungranted 19000; "
		     "peer 2.2.3.4: id 400 ungranted 24000",
		     unit_log_get());
}
TEST_F(homa_grant, homa_grant_remove_grantable__remove_peer_from_grantable_peers)
{
	struct homa_rpc *rpc = test_rpc(self, 200, self->server_ip, 30000);

	homa_grant_insert_grantable(rpc);
	homa_grant_insert_grantable(test_rpc(self, 300, self->server_ip+1,
					     40000));
	homa_grant_insert_grantable(test_rpc(self, 400, self->server_ip+2,
					     20000));

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("peer 3.2.3.4: id 400 ungranted 19000; "
		     "peer 1.2.3.4: id 200 ungranted 29000; "
		     "peer 2.2.3.4: id 300 ungranted 39000",
		     unit_log_get());

	homa_grant_remove_grantable(rpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("peer 3.2.3.4: id 400 ungranted 19000; "
		     "peer 2.2.3.4: id 300 ungranted 39000",
		     unit_log_get());
}

TEST_F(homa_grant, homa_grant_remove_active__copy_existing_rpcs)
{
	struct homa_rpc *rpc;

	homa_grant_manage_rpc(test_rpc(self, 200, self->server_ip,
				       50000));
	homa_grant_manage_rpc(test_rpc(self, 300, self->server_ip,
				       40000));
	homa_grant_manage_rpc(test_rpc(self, 400, self->server_ip,
				       30000));
	homa_grant_manage_rpc(test_rpc(self, 500, self->server_ip,
				       20000));

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 500 ungranted 19000; "
		     "active[1]: id 400 ungranted 29000; "
		     "active[2]: id 300 ungranted 39000; "
		     "active[3]: id 200 ungranted 49000",
		     unit_log_get());

	rpc = self->homa.grant->active_rpcs[0];
	EXPECT_EQ(4, rpc->peer->active_rpcs);

	homa_grant_remove_active(rpc, &self->cand);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 400 ungranted 29000; "
		     "active[1]: id 300 ungranted 39000; "
		     "active[2]: id 200 ungranted 49000",
		     unit_log_get());
	EXPECT_EQ(-1, rpc->msgin.rank);
	EXPECT_EQ(3, rpc->peer->active_rpcs);
	EXPECT_TRUE(homa_grant_cand_empty(&self->cand));
}
TEST_F(homa_grant, homa_grant_remove_active__promote_from_grantable)
{
	struct homa_rpc *rpc;

	self->homa.grant->max_overcommit = 2;
	homa_grant_manage_rpc(test_rpc(self, 200, self->server_ip,
				       50000));
	homa_grant_manage_rpc(test_rpc(self, 300, self->server_ip,
				       40000));
	homa_grant_manage_rpc(test_rpc(self, 400, self->server_ip,
				       30000));
	homa_grant_manage_rpc(test_rpc(self, 500, self->server_ip,
				       20000));

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 500 ungranted 19000; "
		     "active[1]: id 400 ungranted 29000; "
		     "peer 1.2.3.4: id 300 ungranted 39000 "
		     "id 200 ungranted 49000",
		     unit_log_get());

	rpc = self->homa.grant->active_rpcs[1];
	EXPECT_EQ(2, rpc->peer->active_rpcs);

	homa_grant_remove_active(rpc, &self->cand);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 500 ungranted 19000; "
		     "active[1]: id 300 ungranted 39000; "
		     "peer 1.2.3.4: id 200 ungranted 49000",
		     unit_log_get());
	EXPECT_EQ(-1, rpc->msgin.rank);
	EXPECT_EQ(2, rpc->peer->active_rpcs);
	EXPECT_FALSE(homa_grant_cand_empty(&self->cand));
}
TEST_F(homa_grant, homa_grant_remove_active__skip_overactive_peer)
{
	struct homa_rpc *rpc;

	self->homa.grant->max_overcommit = 2;
	self->homa.grant->max_rpcs_per_peer = 1;
	homa_grant_manage_rpc(test_rpc(self, 200, self->server_ip+1,
				       50000));
	homa_grant_manage_rpc(test_rpc(self, 300, self->server_ip+1,
				       40000));
	homa_grant_manage_rpc(test_rpc(self, 400, self->server_ip,
				       30000));
	homa_grant_manage_rpc(test_rpc(self, 500, self->server_ip,
				       20000));

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 500 ungranted 19000; "
		     "active[1]: id 300 ungranted 39000; "
		     "peer 1.2.3.4: id 400 ungranted 29000; "
		     "peer 2.2.3.4: id 200 ungranted 49000",
		     unit_log_get());

	rpc = self->homa.grant->active_rpcs[1];

	homa_grant_remove_active(rpc, &self->cand);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 500 ungranted 19000; "
		     "active[1]: id 200 ungranted 49000; "
		     "peer 1.2.3.4: id 400 ungranted 29000",
		     unit_log_get());
	EXPECT_FALSE(homa_grant_cand_empty(&self->cand));
}

TEST_F(homa_grant, homa_grant_unmanage_rpc__basics)
{
	struct homa_rpc *rpc;

	self->homa.grant->max_rpcs_per_peer = 1;
	self->homa.grant->window_param = 0;
	self->homa.grant->max_incoming = 60000;
	homa_grant_manage_rpc(test_rpc(self, 100, self->server_ip,
				       20000));
	rpc = test_rpc(self, 200, self->server_ip, 30000);
	homa_grant_manage_rpc(rpc);

	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 100 ungranted 19000; "
		     "peer 1.2.3.4: id 200 ungranted 29000",
		     unit_log_get());
	EXPECT_EQ(2, self->homa.grant->num_grantable_rpcs);
	EXPECT_EQ(30000, self->homa.grant->window);

	self->homa.grant->last_grantable_change = 100;
	mock_clock = 250;

	homa_grant_unmanage_rpc(rpc, &self->cand);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 100 ungranted 19000", unit_log_get());
	EXPECT_EQ(1, self->homa.grant->num_grantable_rpcs);
	EXPECT_EQ(300, homa_metrics_per_cpu()->grantable_rpcs_integral);
	EXPECT_EQ(250, self->homa.grant->last_grantable_change);
	EXPECT_EQ(30000, self->homa.grant->window);

	homa_grant_unmanage_rpc(self->homa.grant->active_rpcs[0], &self->cand);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, self->homa.grant->num_grantable_rpcs);
	EXPECT_EQ(60000, self->homa.grant->window);
}
TEST_F(homa_grant, homa_grant_unmanage_rpc__rpc_not_managed)
{
	struct homa_rpc *rpc;

	self->homa.grant->max_rpcs_per_peer = 1;
	self->homa.grant->window_param = 0;
	self->homa.grant->max_incoming = 60000;
	self->homa.grant->last_grantable_change = 100;
	mock_clock = 250;
	rpc = test_rpc(self, 200, self->server_ip, 30000);
	EXPECT_EQ(0, self->homa.grant->num_grantable_rpcs);

	homa_grant_unmanage_rpc(rpc, &self->cand);
	EXPECT_EQ(0, self->homa.grant->num_grantable_rpcs);
	EXPECT_EQ(0, homa_metrics_per_cpu()->grantable_rpcs_integral);
	EXPECT_EQ(100, self->homa.grant->last_grantable_change);
}
TEST_F(homa_grant, homa_grant_unmanage_rpc__remove_from_oldest_rpc)
{
	struct homa_rpc *rpc;

	rpc = test_rpc(self, 200, self->server_ip, 30000);
	homa_grant_manage_rpc(rpc);
	self->homa.grant->oldest_rpc = rpc;
	homa_rpc_hold(rpc);
	EXPECT_EQ(2, refcount_read(&rpc->refs));

	homa_grant_unmanage_rpc(rpc, &self->cand);
	EXPECT_EQ(NULL, self->homa.grant->oldest_rpc);
	EXPECT_EQ(1, refcount_read(&rpc->refs));
}

TEST_F(homa_grant, homa_grant_update_incoming)
{
	struct homa_rpc *rpc;

	rpc = test_rpc(self, 200, self->server_ip, 20000);

	/* Case 1: total_incoming increases. */
	atomic_set(&self->homa.grant->total_incoming, 1000);
	rpc->msgin.bytes_remaining = 19000;
	rpc->msgin.granted = 3000;
	rpc->msgin.rec_incoming = 500;
	homa_grant_update_incoming(rpc, self->homa.grant);
	EXPECT_EQ(2500, atomic_read(&self->homa.grant->total_incoming));
	EXPECT_EQ(2000, rpc->msgin.rec_incoming);

	/* Case 2: incoming negative. */
	atomic_set(&self->homa.grant->total_incoming, 1000);
	rpc->msgin.bytes_remaining = 16000;
	rpc->msgin.granted = 3000;
	rpc->msgin.rec_incoming = 500;
	homa_grant_update_incoming(rpc, self->homa.grant);
	EXPECT_EQ(500, atomic_read(&self->homa.grant->total_incoming));
	EXPECT_EQ(0, rpc->msgin.rec_incoming);

	/* Case 3: no change to rec_incoming. */
	atomic_set(&self->homa.grant->total_incoming, 1000);
	self->homa.grant->max_incoming = 1000;
	rpc->msgin.bytes_remaining = 16000;
	rpc->msgin.granted = 4500;
	rpc->msgin.rec_incoming = 500;
	homa_grant_update_incoming(rpc, self->homa.grant);
	EXPECT_EQ(1000, atomic_read(&self->homa.grant->total_incoming));
	EXPECT_EQ(500, rpc->msgin.rec_incoming);
}

TEST_F(homa_grant, homa_grant_update_granted__basics)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);

	rpc->msgin.rank = 1;
	self->homa.grant->num_active_rpcs = 4;
	EXPECT_EQ(2, homa_grant_update_granted(rpc, self->homa.grant));
	self->homa.grant->num_active_rpcs = 0;
	EXPECT_EQ(10000, rpc->msgin.granted);
	EXPECT_EQ(INT_MAX, atomic_read(&self->homa.grant->stalled_rank));
}
TEST_F(homa_grant, homa_grant_update_granted__rpc_idle)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);

	rpc->silent_ticks = 2;
	EXPECT_EQ(-1, homa_grant_update_granted(rpc, self->homa.grant));
	EXPECT_EQ(1000, rpc->msgin.granted);
}
TEST_F(homa_grant, homa_grant_update_granted__not_active)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);

	rpc->msgin.rank = -1;
	EXPECT_EQ(-1, homa_grant_update_granted(rpc, self->homa.grant));
	EXPECT_EQ(1000, rpc->msgin.granted);
}
TEST_F(homa_grant, homa_grant_update_granted__already_fully_granted)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);

	rpc->msgin.rank = 2;
	rpc->msgin.granted = rpc->msgin.length;
	EXPECT_EQ(-1, homa_grant_update_granted(rpc, self->homa.grant));
}
TEST_F(homa_grant, homa_grant_update_granted__end_of_message)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);

        /* First call grants remaining bytes in message. */
	rpc->msgin.bytes_remaining = 5000;
	rpc->msgin.rank = 2;
	EXPECT_EQ(0, homa_grant_update_granted(rpc, self->homa.grant));
	EXPECT_EQ(20000, rpc->msgin.granted);

        /* Second call cannot grant anything additional. */
	EXPECT_EQ(-1, homa_grant_update_granted(rpc, self->homa.grant));
}
TEST_F(homa_grant, homa_grant_update_granted__insufficient_room_in_incoming)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);

	rpc->msgin.bytes_remaining = 5000;
	rpc->msgin.rank = 5;
	atomic_set(&self->homa.grant->total_incoming, 48000);
	EXPECT_EQ(0, homa_grant_update_granted(rpc, self->homa.grant));
	EXPECT_EQ(17000, rpc->msgin.granted);
}
TEST_F(homa_grant, homa_grant_update_granted__incoming_overcommitted)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);

	atomic_set(&self->homa.grant->total_incoming, 51000);
	atomic_set(&self->homa.grant->stalled_rank, 3);
	rpc->msgin.rank = 2;
	EXPECT_EQ(-1, homa_grant_update_granted(rpc, self->homa.grant));
	EXPECT_EQ(1000, rpc->msgin.granted);
	EXPECT_EQ(2, atomic_read(&self->homa.grant->stalled_rank));
}
TEST_F(homa_grant, homa_grant_update_granted__incoming_overcommitted_but_stalled_doesnt_change)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);

	atomic_set(&self->homa.grant->total_incoming, 51000);
	atomic_set(&self->homa.grant->stalled_rank, 3);
	rpc->msgin.rank = 4;
	EXPECT_EQ(-1, homa_grant_update_granted(rpc, self->homa.grant));
	EXPECT_EQ(1000, rpc->msgin.granted);
	EXPECT_EQ(3, atomic_read(&self->homa.grant->stalled_rank));
}

TEST_F(homa_grant, homa_grant_send__basics)
{
	struct homa_rpc *rpc = test_rpc(self, 100, self->server_ip, 20000);

	mock_xmit_log_verbose = 1;
	rpc->msgin.granted = 2600;
	unit_log_clear();
	homa_grant_send(rpc, 3);
	EXPECT_SUBSTR("id 100, offset 2600, grant_prio 3", unit_log_get());
}

TEST_F(homa_grant, homa_grant_check_rpc__msgin_not_initialized)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			100, 1000, 2000);

	rpc->msgin.bytes_remaining = 500;
	rpc->msgin.granted = 1000;
	rpc->msgin.rec_incoming = 0;
	unit_log_clear();
	homa_grant_check_rpc(rpc);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, rpc->msgin.rec_incoming);
	EXPECT_EQ(0, atomic_read(&self->homa.grant->total_incoming));
	EXPECT_EQ(0, homa_metrics_per_cpu()->grant_check_calls);
}
TEST_F(homa_grant, homa_grant_check_rpc__rpc_dead)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			100, 1000, 20000);

	homa_message_in_init(rpc, 20000, 0);
	EXPECT_EQ(0, rpc->msgin.granted);
	rpc->state = RPC_DEAD;

	unit_log_clear();
	homa_rpc_lock(rpc);
	homa_grant_check_rpc(rpc);
	homa_rpc_unlock(rpc);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, homa_metrics_per_cpu()->grant_check_calls);
	EXPECT_EQ(0, homa_metrics_per_cpu()->grant_check_locked);
	EXPECT_EQ(0, rpc->msgin.granted);
	rpc->state = RPC_INCOMING;
}
TEST_F(homa_grant, homa_grant_check_rpc__update_incoming_even_if_rpc_no_longer_active)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			100, 1000, 2000);

	homa_message_in_init(rpc, 2000, 0);
	EXPECT_EQ(0, rpc->msgin.rank);
	rpc->msgin.rank = -1;
	rpc->msgin.rec_incoming = 100;
	atomic_set(&self->homa.grant->total_incoming, 1000);
	unit_log_clear();
	homa_grant_check_rpc(rpc);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(1, homa_metrics_per_cpu()->grant_check_calls);
	EXPECT_EQ(900, atomic_read(&self->homa.grant->total_incoming));
	EXPECT_EQ(0, rpc->msgin.rec_incoming);
	EXPECT_EQ(0, homa_metrics_per_cpu()->grant_check_locked);
}
TEST_F(homa_grant, homa_grant_check_rpc__fix_order)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	rpc1 = test_rpc_init(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc_init(self, 102, self->server_ip, 30000);
	rpc3 = test_rpc_init(self, 104, self->server_ip, 40000);
	EXPECT_EQ(2, rpc3->msgin.rank);
	rpc3->msgin.granted = 25000;
	rpc3->msgin.bytes_remaining = 15000;
	atomic_set(&self->homa.grant->total_incoming,
		   self->homa.grant->max_incoming - 15000);
	mock_clock = self->homa.grant->next_recalc;

	unit_log_clear();
	homa_rpc_lock(rpc2);
	homa_grant_check_rpc(rpc2);
	homa_rpc_unlock(rpc2);
	EXPECT_STREQ("xmit GRANT 35000@2; xmit GRANT 5000@1", unit_log_get());
	EXPECT_EQ(5000, rpc1->msgin.granted);
	EXPECT_EQ(0, rpc2->msgin.granted);
	EXPECT_EQ(35000, rpc3->msgin.granted);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 104 ungranted 5000; "
		     "active[1]: id 100 ungranted 15000; "
		     "active[2]: id 102 ungranted 30000", unit_log_get());
	EXPECT_EQ(1, homa_metrics_per_cpu()->grant_check_locked);
	EXPECT_EQ(1, homa_metrics_per_cpu()->grant_check_recalcs);
	EXPECT_EQ(40000, self->homa.grant->next_recalc);
}
TEST_F(homa_grant, homa_grant_check_rpc__fast_path)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			100, 1000, 20000);

	homa_message_in_init(rpc, 20000, 0);
	EXPECT_EQ(0, rpc->msgin.granted);

	/* First call issues a grant. */
	unit_log_clear();
	homa_rpc_lock(rpc);
	homa_grant_check_rpc(rpc);
	EXPECT_STREQ("xmit GRANT 10000@0", unit_log_get());
	EXPECT_EQ(1, homa_metrics_per_cpu()->grant_check_calls);
	EXPECT_EQ(0, homa_metrics_per_cpu()->grant_check_locked);
	EXPECT_EQ(0, homa_metrics_per_cpu()->grant_check_recalcs);
	EXPECT_EQ(0, homa_metrics_per_cpu()->grant_check_others);
	EXPECT_EQ(10000, rpc->msgin.granted);

	/* Second call doesn't issue a grant (nothing has changed). */
	unit_log_clear();
	homa_grant_check_rpc(rpc);
	homa_rpc_unlock(rpc);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(2, homa_metrics_per_cpu()->grant_check_calls);
	EXPECT_EQ(0, homa_metrics_per_cpu()->grant_check_locked);
	EXPECT_EQ(10000, rpc->msgin.granted);
}
TEST_F(homa_grant, homa_grant_check_rpc__skip_fast_path_rpc_not_active)
{
	struct homa_rpc *rpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
			self->client_ip, self->server_ip, self->server_port,
			100, 1000, 20000);

	homa_message_in_init(rpc, 20000, 0);
	EXPECT_EQ(0, rpc->msgin.rank);
	rpc->msgin.rank = -1;

	unit_log_clear();
	homa_rpc_lock(rpc);

	homa_grant_check_rpc(rpc);
	homa_rpc_unlock(rpc);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, rpc->msgin.granted);
}
TEST_F(homa_grant, homa_grant_check_rpc__skip_fast_path_because_of_stalled_rpc)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	rpc1 = test_rpc_init(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc_init(self, 102, self->server_ip, 30000);
	rpc3 = test_rpc_init(self, 104, self->server_ip, 40000);
	atomic_set(&self->homa.grant->total_incoming,
		   self->homa.grant->max_incoming - 15000);

	unit_log_clear();
	atomic_set(&self->homa.grant->stalled_rank, 1);
	homa_rpc_lock(rpc3);
	homa_grant_check_rpc(rpc3);
	homa_rpc_unlock(rpc3);
	EXPECT_STREQ("xmit GRANT 10000@1; xmit GRANT 5000@0", unit_log_get());
	EXPECT_EQ(1, homa_metrics_per_cpu()->grant_check_locked);
	EXPECT_EQ(2, atomic_read(&self->homa.grant->stalled_rank));
	EXPECT_EQ(0, rpc1->msgin.granted);
	EXPECT_EQ(10000, rpc2->msgin.granted);
	EXPECT_EQ(5000, rpc3->msgin.granted);
	EXPECT_EQ(1, homa_metrics_per_cpu()->grant_check_others);
}
TEST_F(homa_grant, homa_grant_check_rpc__fast_path_grants_to_end_of_message)
{
	struct homa_rpc *rpc = test_rpc_init(self, 100, self->server_ip, 6000);

	EXPECT_EQ(1, self->homa.grant->num_grantable_rpcs);

	unit_log_clear();
	homa_rpc_lock(rpc);
	homa_grant_check_rpc(rpc);
	homa_rpc_unlock(rpc);
	EXPECT_STREQ("xmit GRANT 6000@0", unit_log_get());
	EXPECT_EQ(6000, rpc->msgin.granted);
	EXPECT_EQ(-1, rpc->msgin.rank);
	EXPECT_EQ(0, self->homa.grant->num_grantable_rpcs);
	EXPECT_EQ(0, homa_metrics_per_cpu()->grant_check_locked);
}
TEST_F(homa_grant, homa_grant_check_rpc__fast_path_promote_other_message)
{
	struct homa_rpc *rpc1, *rpc2;

	self->homa.grant->max_overcommit = 1;
	rpc1 = test_rpc_init(self, 100, self->server_ip, 8000);
	rpc2 = test_rpc_init(self, 102, self->server_ip, 25000);
	EXPECT_EQ(0, rpc1->msgin.rank);
	EXPECT_EQ(-1, rpc2->msgin.rank);

	unit_log_clear();
	homa_rpc_lock(rpc1);
	homa_grant_check_rpc(rpc1);
	homa_rpc_unlock(rpc1);
	EXPECT_STREQ("xmit GRANT 8000@0; xmit GRANT 10000@0", unit_log_get());
	EXPECT_EQ(8000, rpc1->msgin.granted);
	EXPECT_EQ(10000, rpc2->msgin.granted);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 102 ungranted 15000", unit_log_get());
	EXPECT_EQ(0, homa_metrics_per_cpu()->grant_check_locked);
}
TEST_F(homa_grant, homa_grant_check_rpc__fast_path_issue_fifo_grant)
{
	struct homa_rpc *rpc1, *rpc2;

	rpc1 = test_rpc_init(self, 100, self->server_ip, 50000);
	rpc2 = test_rpc_init(self, 102, self->server_ip, 100000);

	self->homa.grant->fifo_grant_time = 0;
	self->homa.grant->fifo_grant_interval = 10000;
	self->homa.grant->fifo_grant_increment = 20000;
	self->homa.grant->fifo_fraction = 50;

	unit_log_clear();
	homa_rpc_lock(rpc1);
	homa_grant_check_rpc(rpc1);
	EXPECT_STREQ("xmit GRANT 10000@1; xmit GRANT 20000@0", unit_log_get());
	EXPECT_EQ(10000, rpc1->msgin.granted);
	EXPECT_EQ(20000, rpc2->msgin.granted);
	homa_rpc_unlock(rpc1);
}
TEST_F(homa_grant, homa_grant_check_rpc__dont_check_needy_if_incoming_maxed)
{
	struct homa_rpc *rpc;

	test_rpc_init(self, 100, self->server_ip, 20000);
	test_rpc_init(self, 102, self->server_ip, 30000);
	rpc = test_rpc_init(self, 104, self->server_ip, 40000);
	atomic_set(&self->homa.grant->total_incoming,
		   self->homa.grant->max_incoming);

	unit_log_clear();
	atomic_set(&self->homa.grant->stalled_rank, 0);
	homa_rpc_lock(rpc);
	homa_grant_check_rpc(rpc);
	homa_rpc_unlock(rpc);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, homa_metrics_per_cpu()->grant_check_locked);
	EXPECT_EQ(0, homa_metrics_per_cpu()->grant_check_others);
}
TEST_F(homa_grant, homa_grant_check_rpc__reread_stalled_rank_before_checking_needy)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	rpc1 = test_rpc_init(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc_init(self, 102, self->server_ip, 30000);
	rpc3 = test_rpc_init(self, 104, self->server_ip, 40000);
	atomic_set(&self->homa.grant->total_incoming,
		   self->homa.grant->max_incoming - 5000);

	unit_hook_register(grant_check_stalled_hook);
	hook_grant = self->homa.grant;

	unit_log_clear();
	atomic_set(&self->homa.grant->stalled_rank, 1);
	homa_rpc_lock(rpc3);
	homa_grant_check_rpc(rpc3);
	homa_rpc_unlock(rpc3);
	EXPECT_EQ(1, homa_metrics_per_cpu()->grant_check_others);
	EXPECT_EQ(0, atomic_read(&self->homa.grant->stalled_rank));
	EXPECT_EQ(5000, rpc1->msgin.granted);
	EXPECT_EQ(0, rpc2->msgin.granted);
	EXPECT_EQ(0, rpc3->msgin.granted);
}
TEST_F(homa_grant, homa_grant_check_rpc__skip_rpc_with_too_much_incoming)
{
	struct homa_rpc *rpc2, *rpc3;

	test_rpc_init(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc_init(self, 102, self->server_ip, 30000);
	rpc3 = test_rpc_init(self, 104, self->server_ip, 40000);
	rpc2->msgin.rec_incoming = 10000;
	atomic_set(&self->homa.grant->total_incoming,
		   self->homa.grant->max_incoming - 15000);
	atomic_set(&self->homa.grant->stalled_rank, 0);

	homa_rpc_lock(rpc3);
	homa_grant_check_rpc(rpc3);
	homa_rpc_unlock(rpc3);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 100 ungranted 10000; "
		     "active[1]: id 102 ungranted 30000; "
		     "active[2]: id 104 ungranted 35000", unit_log_get());
}
TEST_F(homa_grant, homa_grant_check_rpc__skip_dead_rpc_when_checking_needy)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;
	int saved_state;

	rpc1 = test_rpc_init(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc_init(self, 102, self->server_ip, 30000);
	rpc3 = test_rpc_init(self, 104, self->server_ip, 40000);
	saved_state = rpc2->state;
	rpc2->state = RPC_DEAD;
	atomic_set(&self->homa.grant->total_incoming,
		   self->homa.grant->max_incoming - 15000);
	atomic_set(&self->homa.grant->stalled_rank, 0);

	unit_log_clear();
	homa_rpc_lock(rpc3);
	homa_grant_check_rpc(rpc3);
	homa_rpc_unlock(rpc3);
	EXPECT_STREQ("xmit GRANT 10000@2; xmit GRANT 5000@0", unit_log_get());
	EXPECT_EQ(10000, rpc1->msgin.granted);
	EXPECT_EQ(0, rpc2->msgin.granted);
	EXPECT_EQ(5000, rpc3->msgin.granted);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 100 ungranted 10000; "
		     "active[1]: id 102 ungranted 30000; "
		     "active[2]: id 104 ungranted 35000", unit_log_get());
	EXPECT_EQ(1, homa_metrics_per_cpu()->grant_check_locked);
	rpc2->state = saved_state;
}

TEST_F(homa_grant, homa_grant_fix_order)
{
	struct homa_rpc *rpc3, *rpc4;

	test_rpc_init(self, 100, self->server_ip, 20000);
	test_rpc_init(self, 102, self->server_ip, 30000);
	rpc3 = test_rpc_init(self, 104, self->server_ip, 40000);
	rpc4 = test_rpc_init(self, 106, self->server_ip, 50000);
	rpc3->msgin.granted = 15000;
	rpc3->msgin.bytes_remaining = 25000;
	rpc4->msgin.granted = 26000;
	rpc4->msgin.bytes_remaining = 24000;

	EXPECT_EQ(1,homa_grant_fix_order(self->homa.grant));
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 100 ungranted 20000; "
		     "active[1]: id 106 ungranted 24000; "
		     "active[2]: id 104 ungranted 25000; "
		     "active[3]: id 102 ungranted 30000", unit_log_get());
	EXPECT_EQ(3, homa_metrics_per_cpu()->grant_priority_bumps);

	/* Second call: nothing changes. */
	EXPECT_EQ(INT_MAX, homa_grant_fix_order(self->homa.grant));
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_EQ(3, homa_metrics_per_cpu()->grant_priority_bumps);
}

TEST_F(homa_grant, homa_grant_find_oldest__check_grantable_lists)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	rpc1 = test_rpc(self, 100, self->server_ip, 40000);
	rpc1->msgin.birth = 100;
	rpc2 = test_rpc(self, 102, self->server_ip, 20000);
	rpc2->msgin.birth = 200;
	rpc3 = test_rpc(self, 104, self->server_ip + 1, 30000);
	rpc3->msgin.birth = 300;
	homa_grant_insert_grantable(rpc1);
	homa_grant_insert_grantable(rpc2);
	homa_grant_insert_grantable(rpc3);

	homa_grant_find_oldest(self->homa.grant);
	ASSERT_NE(NULL, self->homa.grant->oldest_rpc);
	EXPECT_EQ(100, self->homa.grant->oldest_rpc->id);
}
TEST_F(homa_grant, homa_grant_find_oldest__fifo_grant_unused)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	rpc1 = test_rpc(self, 100, self->server_ip, 400000);
	rpc1->msgin.birth = 100;
	self->homa.grant->fifo_grant_increment = 10000;
	rpc1->msgin.rec_incoming = 20000 + self->homa.grant->window;
	rpc2 = test_rpc(self, 102, self->server_ip, 20000);
	rpc2->msgin.birth = 200;
	rpc3 = test_rpc(self, 104, self->server_ip + 1, 30000);
	rpc3->msgin.birth = 300;
	homa_grant_insert_grantable(rpc1);
	homa_grant_insert_grantable(rpc2);
	homa_grant_insert_grantable(rpc3);

	homa_grant_find_oldest(self->homa.grant);
	ASSERT_NE(NULL, self->homa.grant->oldest_rpc);
	EXPECT_EQ(102, self->homa.grant->oldest_rpc->id);
}
TEST_F(homa_grant, homa_grant_find_oldest__check_active_rpcs)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	rpc1 = test_rpc_init(self, 100, self->server_ip, 40000);
	rpc1->msgin.birth = 100;
	rpc2 = test_rpc_init(self, 102, self->server_ip, 20000);
	rpc2->msgin.birth = 200;
	rpc3 = test_rpc(self, 104, self->server_ip + 1, 30000);
	rpc3->msgin.birth = 300;
	homa_grant_insert_grantable(rpc3);
	EXPECT_EQ(2, self->homa.grant->num_active_rpcs);

	homa_grant_find_oldest(self->homa.grant);
	ASSERT_NE(NULL, self->homa.grant->oldest_rpc);
	EXPECT_EQ(100, self->homa.grant->oldest_rpc->id);
}
TEST_F(homa_grant, homa_grant_find_oldest__active_rpc_has_unused_fifo_grant)
{
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	rpc1 = test_rpc_init(self, 100, self->server_ip, 400000);
	rpc1->msgin.birth = 100;
	self->homa.grant->fifo_grant_increment = 10000;
	rpc1->msgin.rec_incoming = 20000 + self->homa.grant->window;

	/* This RPC will be skipped because it has rank 0. */
	rpc2 = test_rpc_init(self, 102, self->server_ip, 20000);
	rpc2->msgin.birth = 200;

	rpc3 = test_rpc(self, 104, self->server_ip + 1, 30000);
	rpc3->msgin.birth = 300;
	homa_grant_insert_grantable(rpc3);
	EXPECT_EQ(2, self->homa.grant->num_active_rpcs);

	homa_grant_find_oldest(self->homa.grant);
	ASSERT_NE(NULL, self->homa.grant->oldest_rpc);
	EXPECT_EQ(104, self->homa.grant->oldest_rpc->id);
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
	homa_grant_insert_grantable(rpc);
	EXPECT_EQ(1, refcount_read(&rpc->refs));

	homa_grant_find_oldest(self->homa.grant);
	EXPECT_EQ(rpc, self->homa.grant->oldest_rpc);
	EXPECT_EQ(2, refcount_read(&rpc->refs));
}

TEST_F(homa_grant, homa_grant_promote_rpc__rpc_is_active)
{
	struct homa_rpc *rpc;

	test_rpc_init(self, 100, self->server_ip, 30000);
	rpc = test_rpc_init(self, 102, self->server_ip, 40000);
	rpc->msgin.granted += 15000;
	EXPECT_EQ(1, rpc->msgin.rank);

	homa_grant_promote_rpc(self->homa.grant, rpc);
	EXPECT_EQ(1, rpc->msgin.rank);
}
TEST_F(homa_grant, homa_grant_promote_rpc__promote_into_active_space_available)
{
	struct homa_rpc *rpc1, *rpc2;

	rpc1 = test_rpc_init(self, 100, self->server_ip, 30000);

	rpc2 = test_rpc(self, 102, self->server_ip, 40000);
	homa_grant_insert_grantable(rpc2);

	homa_grant_promote_rpc(self->homa.grant, rpc2);
	EXPECT_EQ(0, rpc1->msgin.rank);
	EXPECT_EQ(1, rpc2->msgin.rank);
}
TEST_F(homa_grant, homa_grant_promote_rpc__promote_into_active_bump_existing)
{
	struct homa_rpc *rpc1, *rpc2;

	self->homa.grant->max_overcommit = 1;
	rpc1 = test_rpc_init(self, 100, self->server_ip, 30000);
	rpc2 = test_rpc_init(self, 102, self->server_ip, 40000);
	EXPECT_EQ(0, rpc1->msgin.rank);
	EXPECT_EQ(-1, rpc2->msgin.rank);
	rpc2->msgin.granted += 15000;

	homa_grant_promote_rpc(self->homa.grant, rpc2);
	EXPECT_EQ(-1, rpc1->msgin.rank);
	EXPECT_EQ(0, rpc2->msgin.rank);
}
TEST_F(homa_grant, homa_grant_promote_rpc__promote_within_peer_list)
{
	struct homa_rpc *rpc;

	self->homa.grant->max_overcommit = 1;
	test_rpc_init(self, 100, self->server_ip, 30000);
	test_rpc_init(self, 102, self->server_ip, 40000);
	test_rpc_init(self, 104, self->server_ip, 50000);
	test_rpc_init(self, 106, self->server_ip, 60000);
	rpc = test_rpc_init(self, 108, self->server_ip, 70000);
	rpc->msgin.granted += 25000;

	homa_grant_promote_rpc(self->homa.grant, rpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 100 ungranted 30000; "
		     "peer 1.2.3.4: id 102 ungranted 40000 "
		     "id 108 ungranted 45000 "
		     "id 104 ungranted 50000 "
		     "id 106 ungranted 60000", unit_log_get());
}
TEST_F(homa_grant, homa_grant_promote_rpc__promote_to_top_of_peer_list_and_adjust_peer)
{
	struct homa_rpc *rpc;

	self->homa.grant->max_overcommit = 1;
	test_rpc_init(self, 100, self->server_ip, 30000);
	test_rpc_init(self, 102, self->server_ip + 1, 40000);
	test_rpc_init(self, 104, self->server_ip + 2, 50000);
	test_rpc_init(self, 106, self->server_ip + 2, 60000);
	rpc = test_rpc_init(self, 108, self->server_ip + 2, 70000);
	rpc->msgin.granted += 35000;

	homa_grant_promote_rpc(self->homa.grant, rpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 100 ungranted 30000; "
		     "peer 3.2.3.4: id 108 ungranted 35000 "
		     "id 104 ungranted 50000 "
		     "id 106 ungranted 60000; "
		     "peer 2.2.3.4: id 102 ungranted 40000", unit_log_get());
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

	test_rpc_init(self, 100, self->server_ip, 30000);
	rpc = test_rpc_init(self, 102, self->server_ip, 400000);
	EXPECT_EQ(-1, rpc->msgin.rank);
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

	test_rpc_init(self, 100, self->server_ip, 30000);
	rpc = test_rpc_init(self, 102, self->server_ip, 400000);
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

	test_rpc_init(self, 100, self->server_ip, 30000);
	rpc = test_rpc_init(self, 102, self->server_ip, 400000);
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
	test_rpc_init(self, 100, self->server_ip, 30000);
	mock_clock = 2000;
	rpc1 = test_rpc_init(self, 102, self->server_ip, 400000);
	mock_clock = 3000;
	rpc2 = test_rpc_init(self, 104, self->server_ip, 300000);
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
TEST_F(homa_grant, homa_grant_check_fifo__no_suitable_rpc)
{
	mock_clock = 1000;
	self->homa.grant->max_overcommit = 1;
	self->homa.grant->fifo_grant_time = 1000;
	self->homa.grant->fifo_grant_increment = 20000;
	self->homa.grant->fifo_fraction = 50;

	test_rpc_init(self, 100, self->server_ip, 30000);

	unit_log_clear();
	homa_grant_check_fifo(self->homa.grant);
	EXPECT_EQ(NULL, self->homa.grant->oldest_rpc);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_grant, homa_grant_check_fifo__rpc_dead)
{
	struct homa_rpc *rpc;

	mock_clock = 1000;
	self->homa.grant->max_overcommit = 1;
	self->homa.grant->fifo_grant_time = 0;
	self->homa.grant->fifo_grant_increment = 20000;
	self->homa.grant->fifo_fraction = 50;

	test_rpc_init(self, 100, self->server_ip, 30000);
	rpc = test_rpc_init(self, 102, self->server_ip, 400000);
	EXPECT_EQ(-1, rpc->msgin.rank);
	EXPECT_EQ(0, rpc->msgin.granted);
	self->homa.grant->oldest_rpc = rpc;
	homa_rpc_hold(rpc);
	hook_end_rpc = rpc;
	hook_end_lock_count = 2;
	unit_hook_register(grant_spinlock_end_hook);

	unit_log_clear();
	homa_grant_check_fifo(self->homa.grant);
	EXPECT_EQ(0, rpc->msgin.granted);
	EXPECT_EQ(0, homa_metrics_per_cpu()->fifo_grant_bytes);
	EXPECT_EQ(RPC_DEAD, rpc->state);
}
TEST_F(homa_grant, homa_grant_check_fifo__rpc_becomes_fully_granted_so_promote_another)
{
	struct homa_rpc *rpc;

	self->homa.grant->max_overcommit = 2;
	self->homa.grant->fifo_grant_increment = 50000;
	self->homa.grant->fifo_fraction = 50;

	mock_clock = 1000;
	rpc = test_rpc_init(self, 100, self->server_ip, 40000);
	mock_clock = 2000;
	test_rpc_init(self, 102, self->server_ip, 30000);
	mock_clock = 3000;
	test_rpc_init(self, 104, self->server_ip, 50000);
	EXPECT_EQ(1, rpc->msgin.rank);

	unit_log_clear();
	homa_grant_check_fifo(self->homa.grant);
	EXPECT_EQ(40000, rpc->msgin.granted);
	EXPECT_EQ(-1, rpc->msgin.rank);
	EXPECT_STREQ("xmit GRANT 40000@0; xmit GRANT 10000@0", unit_log_get());
	EXPECT_EQ(NULL, self->homa.grant->oldest_rpc);
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 102 ungranted 30000; "
		     "active[1]: id 104 ungranted 40000", unit_log_get());
	EXPECT_EQ(40000, homa_metrics_per_cpu()->fifo_grant_bytes);
}
TEST_F(homa_grant, homa_grant_check_fifo__promote_after_fifo_grant)
{
	struct homa_rpc *rpc;

	self->homa.grant->max_overcommit = 1;
	self->homa.grant->fifo_grant_increment = 15000;
	self->homa.grant->fifo_fraction = 50;

	mock_clock = 1000;
	rpc = test_rpc_init(self, 100, self->server_ip, 50000);
	mock_clock = 2000;
	test_rpc_init(self, 102, self->server_ip, 30000);
	mock_clock = 3000;
	test_rpc_init(self, 104, self->server_ip, 40000);

	unit_log_clear();
	homa_grant_check_fifo(self->homa.grant);
	EXPECT_EQ(15000, rpc->msgin.granted);
	EXPECT_STREQ("xmit GRANT 15000@0", unit_log_get());
	unit_log_clear();
	unit_log_grantables(&self->homa);
	EXPECT_STREQ("active[0]: id 102 ungranted 30000; "
		     "peer 1.2.3.4: id 100 ungranted 35000 "
		     "id 104 ungranted 40000", unit_log_get());
}

TEST_F(homa_grant, homa_grant_cand_add__basics)
{
	struct homa_grant_candidates cand;
	struct homa_rpc *rpc1, *rpc2;

	rpc1 = test_rpc(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc(self, 102, self->server_ip, 30000);

	homa_grant_cand_init(&cand);
	homa_grant_cand_add(&cand, rpc2);
	homa_grant_cand_add(&cand, rpc1);
	EXPECT_EQ(2, cand.inserts);
	EXPECT_EQ(0, cand.removes);
	EXPECT_EQ(rpc2, cand.rpcs[0]);
	EXPECT_EQ(rpc1, cand.rpcs[1]);
	EXPECT_EQ(2, refcount_read(&rpc1->refs));
	homa_grant_cand_check(&cand, self->homa.grant);
}
TEST_F(homa_grant, homa_grant_cand_add__wrap_around)
{
	struct homa_grant_candidates cand;
	int i;

	homa_grant_cand_init(&cand);

	/* Add so many RPCs that some have to be dropped. */
	for (i = 0; i < HOMA_MAX_CAND_RPCS + 2; i++)
		homa_grant_cand_add(&cand, test_rpc(self, 100 + 2*i,
				    self->server_ip, 20000));
	EXPECT_EQ(HOMA_MAX_CAND_RPCS, cand.inserts);
	EXPECT_EQ(0, cand.removes);
	EXPECT_EQ(100, cand.rpcs[0]->id);
	EXPECT_EQ(114, cand.rpcs[HOMA_MAX_CAND_RPCS-1]->id);

	/* Discard a couple of RPCs then add more. */
	homa_rpc_put(cand.rpcs[0]);
	homa_rpc_put(cand.rpcs[1]);
	cand.removes = 2;
	for (i = 0; i < 3; i++)
		homa_grant_cand_add(&cand, test_rpc(self, 200 + 2*i,
				    self->server_ip, 20000));
	EXPECT_EQ(HOMA_MAX_CAND_RPCS + 2, cand.inserts);
	EXPECT_EQ(2, cand.removes);
	EXPECT_EQ(200, cand.rpcs[0]->id);
	EXPECT_EQ(202, cand.rpcs[1]->id);
	EXPECT_EQ(104, cand.rpcs[2]->id);
	homa_grant_cand_check(&cand, self->homa.grant);
}

TEST_F(homa_grant, homa_grant_cand_check__basics)
{
	struct homa_grant_candidates cand;
	struct homa_rpc *rpc1, *rpc2, *rpc3;

	rpc1 = test_rpc_init(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc_init(self, 102, self->server_ip, 20000);
	rpc3 = test_rpc_init(self, 104, self->server_ip, 20000);

	homa_grant_cand_init(&cand);
	homa_grant_cand_add(&cand, rpc1);
	homa_grant_cand_add(&cand, rpc2);
	homa_grant_cand_add(&cand, rpc3);
	rpc2->msgin.granted = 20000;
	unit_log_clear();
	homa_grant_cand_check(&cand, self->homa.grant);
	EXPECT_STREQ("xmit GRANT 10000@2; xmit GRANT 10000@0", unit_log_get());
	EXPECT_EQ(1, refcount_read(&rpc1->refs));
	EXPECT_EQ(1, refcount_read(&rpc2->refs));
	EXPECT_EQ(1, refcount_read(&rpc3->refs));
}
TEST_F(homa_grant, homa_grant_cand_check__rpc_dead)
{
	struct homa_grant_candidates cand;
	struct homa_rpc *rpc;
	int saved_state;

	rpc = test_rpc_init(self, 100, self->server_ip, 20000);

	homa_grant_cand_init(&cand);
	homa_grant_cand_add(&cand, rpc);
	saved_state = rpc->state;
	rpc->state = RPC_DEAD;

	unit_log_clear();
	homa_grant_cand_check(&cand, self->homa.grant);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(1, refcount_read(&rpc->refs));
	rpc->state = saved_state;
}
TEST_F(homa_grant, homa_grant_cand_check__rpc_becomes_fully_granted)
{
	struct homa_grant_candidates cand;
	struct homa_rpc *rpc1, *rpc2;

	self->homa.grant->max_rpcs_per_peer = 1;
	rpc1 = test_rpc_init(self, 100, self->server_ip, 20000);
	rpc2 = test_rpc_init(self, 102, self->server_ip, 30000);
	EXPECT_EQ(0, rpc1->msgin.rank);
	EXPECT_EQ(-1, rpc2->msgin.rank);
	rpc1->msgin.bytes_remaining = 10000;

	homa_grant_cand_init(&cand);
	homa_grant_cand_add(&cand, rpc1);

	unit_log_clear();
	homa_grant_cand_check(&cand, self->homa.grant);
	EXPECT_STREQ("xmit GRANT 20000@0; xmit GRANT 10000@0", unit_log_get());
	EXPECT_EQ(-1, rpc1->msgin.rank);
	EXPECT_EQ(0, rpc2->msgin.rank);
	EXPECT_EQ(2, cand.removes);
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
TEST_F(homa_grant, homa_grant_update_sysctl_deps__recalc_cycles)
{
	self->homa.grant->recalc_usecs = 7;
	homa_grant_update_sysctl_deps(self->homa.grant);
	EXPECT_EQ(7000, self->homa.grant->recalc_cycles);
}
TEST_F(homa_grant, homa_grant_update_sysctl_deps__grant_window)
{
	self->homa.grant->window_param = 30000;
	homa_grant_update_sysctl_deps(self->homa.grant);
	EXPECT_EQ(30000, self->homa.grant->window);
}
