// SPDX-License-Identifier: BSD-2-Clause

#include "homa_impl.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

struct in6_addr ip1111[1];
struct in6_addr ip2222[1];
struct in6_addr ip3333[1];

FIXTURE(homa_peer) {
	struct homa homa;
	struct homa_net *hnet;
	struct homa_sock hsk;
	struct in6_addr client_ip[1];
	struct in6_addr server_ip[1];
	int server_port;
};
FIXTURE_SETUP(homa_peer)
{
	homa_init(&self->homa);
	self->hnet = mock_alloc_hnet(&self->homa);
	mock_sock_init(&self->hsk, self->hnet, 0);
	self->client_ip[0] = unit_get_in_addr("196.168.0.1");
	self->server_ip[0] = unit_get_in_addr("1.2.3.4");
	ip1111[0] = unit_get_in_addr("1::1:1:1");
	ip2222[0] = unit_get_in_addr("2::2:2:2");
	ip3333[0] = unit_get_in_addr("3::3:3:3");
	self->server_port = 99;
}
FIXTURE_TEARDOWN(homa_peer)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

#ifndef __STRIP__ /* See strip.py */
static void peer_spinlock_hook(char *id)
{
	if (strcmp(id, "spin_lock") != 0)
		return;
	mock_clock += 1000;
}
#endif /* See strip.py */

static struct _test_data_homa_peer *test_data;
static struct homa_peer *conflicting_peer;
static int peer_race_hook_invocations;
static void peer_race_hook(char *id)
{
	if (strcmp(id, "kmalloc") != 0)
		return;
	if (peer_race_hook_invocations > 0)
		return;
	peer_race_hook_invocations++;

	/* Create a peer with the same address as the one being created
	 * by the current test.
	 */
	conflicting_peer = homa_peer_find(&test_data->hsk, ip3333);
	homa_peer_put(conflicting_peer);
}

TEST_F(homa_peer, homa_peertab_alloc__success)
{
	struct homa_peertab *peertab;

	peertab = homa_peertab_alloc();
	EXPECT_FALSE(IS_ERR(peertab));

	homa_peertab_free(peertab);
}
TEST_F(homa_peer, homa_peertab_alloc__cant_alloc_peertab)
{
	struct homa_peertab *peertab;

	mock_kmalloc_errors = 1;
	peertab = homa_peertab_alloc();
	EXPECT_TRUE(IS_ERR(peertab));
	EXPECT_EQ(ENOMEM, -PTR_ERR(peertab));
}
TEST_F(homa_peer, homa_peertab_alloc__rhashtable_init_fails)
{
	struct homa_peertab *peertab;

	mock_rht_init_errors = 1;
	peertab = homa_peertab_alloc();
	EXPECT_TRUE(IS_ERR(peertab));
	EXPECT_EQ(EINVAL, -PTR_ERR(peertab));
}

TEST_F(homa_peer, homa_peertab_free_net)
{
	/* Create peers from two different netns's, make sure only
	 * those from one get freed. */
	struct homa_peer *peer;
	struct homa_sock hsk2;
	struct homa_net *hnet2;

	hnet2 = mock_alloc_hnet(&self->homa);
	mock_sock_init(&hsk2, hnet2, 44);

	peer = homa_peer_find(&self->hsk, ip1111);
	homa_peer_put(peer);
	peer = homa_peer_find(&self->hsk, ip2222);
	homa_peer_put(peer);
	peer = homa_peer_find(&hsk2, ip3333);
	homa_peer_put(peer);
	EXPECT_EQ(3, unit_count_peers(&self->homa));

	homa_peertab_free_net(self->hnet);
	EXPECT_EQ(1, unit_count_peers(&self->homa));
}

TEST_F(homa_peer, homa_peertab_free_fn)
{
	struct homa_peer *peer;
	struct dst_entry *dst;

	peer = homa_peer_alloc(&self->hsk, ip3333);
	dst = peer->dst;
	dst_hold(dst);
	EXPECT_EQ(2, atomic_read(&dst->__rcuref.refcnt));
	homa_peer_put(peer);

	homa_peertab_free_fn(peer, NULL);
	EXPECT_EQ(1, atomic_read(&dst->__rcuref.refcnt));
	dst_release(dst);
}

TEST_F(homa_peer, homa_peertab_free) {
	struct homa_peer *peer;

	peer = homa_peer_find(&self->hsk, ip1111);
	homa_peer_put(peer);
	peer = homa_peer_find(&self->hsk, ip2222);
	mock_peer_free_no_fail = 1;

	unit_log_clear();
	homa_peertab_free(self->homa.peers);
	EXPECT_STREQ("peer [2::2:2:2] has reference count 1", unit_log_get());

	kfree(peer);
	self->homa.peers = homa_peertab_alloc();
}

TEST_F(homa_peer, homa_peer_alloc__success)
{
	struct homa_peer *peer;

	peer = homa_peer_alloc(&self->hsk, ip1111);
	ASSERT_FALSE(IS_ERR(peer));
	EXPECT_EQ_IP(*ip1111, peer->addr);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(INT_MAX, peer->unsched_cutoffs[HOMA_MAX_PRIORITIES-2]);
	EXPECT_EQ(0, peer->cutoff_version);
	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_new_entries);
#endif /* See strip.py */
	EXPECT_EQ(1, atomic_read(&peer->dst->__rcuref.refcnt));
	homa_peer_put(peer);
	homa_peer_free(peer);
}
TEST_F(homa_peer, homa_peer_alloc__kmalloc_error)
{
	struct homa_peer *peer;

	mock_kmalloc_errors = 1;
	peer = homa_peer_alloc(&self->hsk, ip3333);
	EXPECT_EQ(ENOMEM, -PTR_ERR(peer));

#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_kmalloc_errors);
#endif /* See strip.py */
}
TEST_F(homa_peer, homa_peer_alloc__route_error)
{
	struct homa_peer *peer;

	mock_route_errors = 1;
	peer = homa_peer_alloc(&self->hsk, ip3333);
	EXPECT_EQ(EHOSTUNREACH, -PTR_ERR(peer));

#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_route_errors);
#endif /* See strip.py */
}

TEST_F(homa_peer, homa_peer_free__normal)
{
	struct homa_peer *peer;
	struct dst_entry *dst;

	peer = homa_peer_alloc(&self->hsk, ip1111);
	ASSERT_FALSE(IS_ERR(peer));
	dst = peer->dst;
	dst_hold(dst);
	ASSERT_EQ(2, atomic_read(&dst->__rcuref.refcnt));

	homa_peer_put(peer);
	homa_peer_free(peer);
	ASSERT_EQ(1, atomic_read(&dst->__rcuref.refcnt));
	dst_release(dst);
}
TEST_F(homa_peer, homa_peer_free__nonzero_ref_count)
{
	struct homa_peer *peer;

	peer = homa_peer_alloc(&self->hsk, ip2222);
	ASSERT_FALSE(IS_ERR(peer));
	mock_peer_free_no_fail = 1;

	unit_log_clear();
	homa_peer_free(peer);
	EXPECT_STREQ("peer [2::2:2:2] has reference count 1", unit_log_get());
	kfree(peer);
}

TEST_F(homa_peer, homa_peer_find__basics)
{
	struct homa_peer *peer, *peer2;

	/* First call: create new peer. */
	peer = homa_peer_find(&self->hsk, ip1111);
	ASSERT_FALSE(IS_ERR(peer));
	EXPECT_EQ_IP(*ip1111, peer->addr);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(INT_MAX, peer->unsched_cutoffs[HOMA_MAX_PRIORITIES-2]);
	EXPECT_EQ(0, peer->cutoff_version);
#endif /* See strip.py */

	/* Second call: lookup existing peer. */
	peer2 = homa_peer_find(&self->hsk, ip1111);
	EXPECT_EQ(peer, peer2);
	EXPECT_EQ(2, atomic_read(&peer->refs));

	/* Third call: lookup new peer. */
	peer2 = homa_peer_find(&self->hsk, ip2222);
	EXPECT_NE(peer, peer2);
	ASSERT_FALSE(IS_ERR(peer2));
	EXPECT_EQ(1, atomic_read(&peer2->refs));

#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(2, homa_metrics_per_cpu()->peer_new_entries);
#endif /* See strip.py */
	homa_peer_put(peer);
	homa_peer_put(peer);
	homa_peer_put(peer2);
}
TEST_F(homa_peer, homa_peer_find__error_in_homa_peer_alloc)
{
	struct homa_peer *peer;

	mock_route_errors = 1;
	peer = homa_peer_find(&self->hsk, ip3333);
	EXPECT_EQ(EHOSTUNREACH, -PTR_ERR(peer));

#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_route_errors);
#endif /* See strip.py */
}
TEST_F(homa_peer, homa_peer_find__insert_error)
{
	struct homa_peer *peer;

	mock_rht_insert_errors = 1;
	peer = homa_peer_find(&self->hsk, ip3333);
	EXPECT_TRUE(IS_ERR(peer));
	EXPECT_EQ(EINVAL, -PTR_ERR(peer));
}
TEST_F(homa_peer, homa_peer_find__conflicting_create)
{
	struct homa_peer *peer;

	test_data = self;
	peer_race_hook_invocations = 0;
	unit_hook_register(peer_race_hook);
	peer = homa_peer_find(&self->hsk, ip3333);
	EXPECT_FALSE(IS_ERR(conflicting_peer));
	EXPECT_EQ(conflicting_peer, peer);
	EXPECT_EQ(1, atomic_read(&peer->refs));
	homa_peer_put(peer);
}

TEST_F(homa_peer, homa_dst_refresh__basics)
{
	struct dst_entry *old_dst;
	struct homa_peer *peer;

	peer = homa_peer_find(&self->hsk, ip1111);
	ASSERT_NE(NULL, peer);
	EXPECT_EQ_IP(*ip1111, peer->addr);

	old_dst = peer->dst;
	homa_dst_refresh(self->homa.peers, peer, &self->hsk);
	EXPECT_NE(old_dst, peer->dst);
	homa_peer_put(peer);
}
TEST_F(homa_peer, homa_dst_refresh__routing_error)
{
	struct dst_entry *old_dst;
	struct homa_peer *peer;

	peer = homa_peer_find(&self->hsk, ip1111);
	ASSERT_NE(NULL, peer);
	EXPECT_EQ_IP(*ip1111, peer->addr);

	old_dst = peer->dst;
	mock_route_errors = 1;
	homa_dst_refresh(self->homa.peers, peer, &self->hsk);
	EXPECT_EQ(old_dst, peer->dst);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_route_errors);
#endif /* See strip.py */
	homa_peer_put(peer);
}

#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_peer, homa_unsched_priority)
{
	struct homa_peer peer;

	homa_peer_set_cutoffs(&peer, INT_MAX, 0, 0, INT_MAX, 200, 100, 0, 0);

	EXPECT_EQ(5, homa_unsched_priority(&self->homa, &peer, 10));
	EXPECT_EQ(4, homa_unsched_priority(&self->homa, &peer, 200));
	EXPECT_EQ(3, homa_unsched_priority(&self->homa, &peer, 201));
}
#endif /* See strip.py */

TEST_F(homa_peer, homa_peer_get_dst_ipv4)
{
	struct dst_entry *dst;

	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, self->hnet, 0);

	struct homa_peer *peer = homa_peer_find(&self->hsk,
						&self->client_ip[0]);
	ASSERT_NE(NULL, peer);

	dst = homa_peer_get_dst(peer, &self->hsk);
	ASSERT_NE(NULL, dst);
	dst_release(dst);
	EXPECT_STREQ("196.168.0.1",
				homa_print_ipv4_addr(peer->flow.u.ip4.daddr));
	homa_peer_put(peer);
}
TEST_F(homa_peer, homa_peer_get_dst_ipv6)
{
	struct dst_entry *dst;
	char buffer[30];
	u32 addr;

	// Make sure the test uses IPv6.
	mock_ipv6 = true;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, self->hnet, 0);

	struct homa_peer *peer = homa_peer_find(&self->hsk, &ip1111[0]);
	ASSERT_NE(NULL, peer);

	dst = homa_peer_get_dst(peer, &self->hsk);
	ASSERT_NE(NULL, dst);
	dst_release(dst);
	addr = ntohl(peer->flow.u.ip4.daddr);
	snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", (addr >> 24) & 0xff,
			(addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff);
	EXPECT_STREQ("[1::1:1:1]",
			homa_print_ipv6_addr(&peer->flow.u.ip6.daddr));
	homa_peer_put(peer);
}

#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_peer, homa_peer_lock_slow)
{
	struct homa_peer *peer = homa_peer_find(&self->hsk, ip3333);

	ASSERT_NE(NULL, peer);
	mock_clock = 10000;
	homa_peer_lock(peer);
	EXPECT_EQ(0, homa_metrics_per_cpu()->peer_ack_lock_misses);
	EXPECT_EQ(0, homa_metrics_per_cpu()->peer_ack_lock_miss_cycles);
	homa_peer_unlock(peer);

	mock_trylock_errors = 1;
	unit_hook_register(peer_spinlock_hook);
	homa_peer_lock(peer);
	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_ack_lock_misses);
	EXPECT_EQ(1000, homa_metrics_per_cpu()->peer_ack_lock_miss_cycles);
	homa_peer_unlock(peer);
	homa_peer_put(peer);
}
#endif /* See strip.py */

TEST_F(homa_peer, homa_peer_add_ack)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
		self->client_ip, self->server_ip, self->server_port,
		101, 100, 100);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
		self->client_ip, self->server_ip, self->server_port,
		102, 100, 100);
	struct homa_rpc *crpc3 = unit_client_rpc(&self->hsk, UNIT_OUTGOING,
		self->client_ip, self->server_ip, self->server_port,
		103, 100, 100);
	struct homa_peer *peer = crpc1->peer;

	EXPECT_EQ(0, peer->num_acks);

	/* Initialize 3 acks in the peer. */
	peer->acks[0] = (struct homa_ack) {
			.server_port = htons(self->server_port),
			.client_id = cpu_to_be64(90)};
	peer->acks[1] = (struct homa_ack) {
			.server_port = htons(self->server_port),
			.client_id = cpu_to_be64(91)};
	peer->acks[2] = (struct homa_ack) {
			.server_port = htons(self->server_port),
			.client_id = cpu_to_be64(92)};
	peer->num_acks = 3;

	/* Add one RPC to unacked (fits). */
	homa_peer_add_ack(crpc1);
	EXPECT_EQ(4, peer->num_acks);
	EXPECT_STREQ("server_port 99, client_id 101",
			unit_ack_string(&peer->acks[3]));

	/* Add another RPC to unacked (also fits). */
	homa_peer_add_ack(crpc2);
	EXPECT_EQ(5, peer->num_acks);
	EXPECT_STREQ("server_port 99, client_id 102",
			unit_ack_string(&peer->acks[4]));

	/* Third RPC overflows, triggers ACK transmission. */
	unit_log_clear();
	mock_xmit_log_verbose = 1;
	homa_peer_add_ack(crpc3);
	EXPECT_EQ(0, peer->num_acks);
	EXPECT_STREQ("xmit ACK from 0.0.0.0:32768, dport 99, id 103, acks [sp 99, id 90] [sp 99, id 91] [sp 99, id 92] [sp 99, id 101] [sp 99, id 102]",
			unit_log_get());
}

TEST_F(homa_peer, homa_peer_get_acks)
{
	struct homa_peer *peer = homa_peer_find(&self->hsk, ip3333);
	struct homa_ack acks[2];

	ASSERT_NE(NULL, peer);
	EXPECT_EQ(0, peer->num_acks);

	// First call: nothing available.
	EXPECT_EQ(0, homa_peer_get_acks(peer, 2, acks));

	// Second call: retrieve 2 out of 3.
	peer->acks[0] = (struct homa_ack) {
			.server_port = htons(5000),
			.client_id = cpu_to_be64(100)};
	peer->acks[1] = (struct homa_ack) {
			.server_port = htons(5001),
			.client_id = cpu_to_be64(101)};
	peer->acks[2] = (struct homa_ack) {
			.server_port = htons(5002),
			.client_id = cpu_to_be64(102)};
	peer->num_acks = 3;
	EXPECT_EQ(2, homa_peer_get_acks(peer, 2, acks));
	EXPECT_STREQ("server_port 5001, client_id 101",
			unit_ack_string(&acks[0]));
	EXPECT_STREQ("server_port 5002, client_id 102",
			unit_ack_string(&acks[1]));
	EXPECT_EQ(1, peer->num_acks);

	// Third call: retrieve final id.
	EXPECT_EQ(1, homa_peer_get_acks(peer, 2, acks));
	EXPECT_STREQ("server_port 5000, client_id 100",
			unit_ack_string(&acks[0]));
	homa_peer_put(peer);
}
