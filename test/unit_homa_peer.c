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
struct in6_addr ip4444[1];
struct in6_addr ip5555[1];
struct in6_addr ip6666[1];

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
	ip4444[0] = unit_get_in_addr("4::4:4:4");
	ip5555[0] = unit_get_in_addr("5::5:5:5");
	ip6666[0] = unit_get_in_addr("6::6:6:6");
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
	conflicting_peer = homa_peer_get(&test_data->hsk, ip3333);
	homa_peer_release(conflicting_peer);
	jiffies += 10;
}

static struct homa_peertab *hook_peertab;
static void stop_gc_hook(char *id)
{
	if (strcmp(id, "kfree") != 0)
		return;
	unit_log_printf("; ", "gc_stop_count %d", hook_peertab->gc_stop_count);
}

static int hook_free_count;
static void complete_rcu_hook(char *id) {
	if (strcmp(id, "unlock") != 0)
		return;
	if (hook_free_count == 0)
		return;
	hook_free_count--;
	if (hook_free_count == 0)
		homa_peer_rcu_callback(&hook_peertab->rcu_head);
}

TEST_F(homa_peer, homa_peer_alloc_peertab__success)
{
	struct homa_peertab *peertab;

	peertab = homa_peer_alloc_peertab();
	EXPECT_FALSE(IS_ERR(peertab));

	homa_peer_free_peertab(peertab);
}
TEST_F(homa_peer, homa_peer_alloc_peertab__cant_alloc_peertab)
{
	struct homa_peertab *peertab;

	mock_kmalloc_errors = 1;
	peertab = homa_peer_alloc_peertab();
	EXPECT_TRUE(IS_ERR(peertab));
	EXPECT_EQ(ENOMEM, -PTR_ERR(peertab));
}
TEST_F(homa_peer, homa_peer_alloc_peertab__rhashtable_init_fails)
{
	struct homa_peertab *peertab;

	mock_rht_init_errors = 1;
	peertab = homa_peer_alloc_peertab();
	EXPECT_TRUE(IS_ERR(peertab));
	EXPECT_EQ(EINVAL, -PTR_ERR(peertab));
}
TEST_F(homa_peer, homa_peer_alloc_peertab__cant_register_sysctl)
{
	struct homa_peertab *peertab;

	mock_register_sysctl_errors = 1;
	peertab = homa_peer_alloc_peertab();
	EXPECT_TRUE(IS_ERR(peertab));
	EXPECT_EQ(ENOMEM, -PTR_ERR(peertab));
	EXPECT_SUBSTR("couldn't register sysctl parameters for Homa peertab",
		      mock_printk_output);
}

TEST_F(homa_peer, homa_peer_free_net__basics)
{
	/* Create peers from two different netns's, make sure only
	 * those from one get freed. */
	struct homa_peer *peer;
	struct homa_sock hsk2;
	struct homa_net *hnet2;

	hnet2 = mock_alloc_hnet(&self->homa);
	mock_sock_init(&hsk2, hnet2, 44);

	peer = homa_peer_get(&self->hsk, ip1111);
	homa_peer_release(peer);
	peer = homa_peer_get(&self->hsk, ip2222);
	homa_peer_release(peer);
	peer = homa_peer_get(&hsk2, ip3333);
	homa_peer_release(peer);
	EXPECT_EQ(3, unit_count_peers(&self->homa));
	EXPECT_EQ(3, self->homa.peertab->num_peers);
	EXPECT_EQ(2, self->hnet->num_peers);

	homa_peer_free_net(self->hnet);
	EXPECT_EQ(1, unit_count_peers(&self->homa));
	EXPECT_EQ(1, self->homa.peertab->num_peers);
}
TEST_F(homa_peer, homa_peer_free_net__set_gc_stop_count)
{
	struct homa_peer *peer;

	peer = homa_peer_get(&self->hsk, ip1111);
	homa_peer_release(peer);

	unit_hook_register(stop_gc_hook);
	hook_peertab = self->homa.peertab;
	unit_log_clear();
	self->homa.peertab->gc_stop_count = 3;

	homa_peer_free_net(self->hnet);
	EXPECT_EQ(0, unit_count_peers(&self->homa));
	EXPECT_STREQ("gc_stop_count 4", unit_log_get());
	EXPECT_EQ(3, self->homa.peertab->gc_stop_count);
}

TEST_F(homa_peer, homa_peer_free_fn)
{
	struct homa_peer *peer;
	struct dst_entry *dst;

	peer = homa_peer_alloc(&self->hsk, ip3333);
	dst = peer->dst;
	dst_hold(dst);
	EXPECT_EQ(2, atomic_read(&dst->__rcuref.refcnt));
	homa_peer_release(peer);

	homa_peer_free_fn(peer, NULL);
	EXPECT_EQ(1, atomic_read(&dst->__rcuref.refcnt));
	dst_release(dst);
}

TEST_F(homa_peer, homa_peer_free_peertab__basics) {
	struct homa_peer *peer;

	peer = homa_peer_get(&self->hsk, ip1111);
	homa_peer_release(peer);
	peer = homa_peer_get(&self->hsk, ip2222);
	mock_peer_free_no_fail = 1;

	unit_log_clear();
	homa_peer_free_peertab(self->homa.peertab);
	EXPECT_STREQ("peer [2::2:2:2] has reference count 1; "
		     "unregister_net_sysctl_table", unit_log_get());

	kfree(peer);
	self->homa.peertab = homa_peer_alloc_peertab();
}
TEST_F(homa_peer, homa_peer_free_peertab__free_dead_peers) {
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_peer *peer;

	jiffies = 100;
	peer = homa_peer_get(&self->hsk, ip1111);
	homa_peer_release(peer);
	peer = homa_peer_get(&self->hsk, ip2222);
	homa_peer_release(peer);

	jiffies = peertab->idle_jiffies_max + 1000;
	peertab->num_peers = peertab->gc_threshold + 100;
	homa_peer_gc(peertab);
	EXPECT_EQ(2, unit_list_length(&peertab->dead_peers));

	homa_peer_rcu_callback(&peertab->rcu_head);
	homa_peer_free_peertab(self->homa.peertab);

	/* Can't check explicitly for problems (peertab is gone now), but
	 * end-of-test checks will complain if the peers weren't freed.
	 */
	self->homa.peertab = homa_peer_alloc_peertab();
}

TEST_F(homa_peer, homa_peer_rcu_callback) {
	atomic_set(&self->homa.peertab->call_rcu_pending, 4);
	homa_peer_rcu_callback(&self->homa.peertab->rcu_head);
	EXPECT_EQ(0, atomic_read(&self->homa.peertab->call_rcu_pending));
}

TEST_F(homa_peer, homa_peer_free_dead) {
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_peer *peer1, *peer2;

	peer1 = homa_peer_alloc(&self->hsk, ip1111);
	peer2 = homa_peer_alloc(&self->hsk, ip2222);

	list_add_tail(&peer1->dead_links, &peertab->dead_peers);
	list_add_tail(&peer2->dead_links, &peertab->dead_peers);
	unit_log_clear();
	unit_log_dead_peers(&self->homa);
	EXPECT_STREQ("[1::1:1:1]; [2::2:2:2]", unit_log_get());

	/* First call: RCU pending. */
	atomic_set(&peertab->call_rcu_pending, 1);
	homa_peer_free_dead(peertab);
	unit_log_clear();
	unit_log_dead_peers(&self->homa);
	EXPECT_STREQ("[1::1:1:1]; [2::2:2:2]", unit_log_get());

	/* Second call: peers have nonzero reference counts. */
	atomic_set(&peertab->call_rcu_pending, 0);
	homa_peer_free_dead(peertab);
	unit_log_clear();
	unit_log_dead_peers(&self->homa);
	EXPECT_STREQ("[1::1:1:1]; [2::2:2:2]", unit_log_get());

	/* Third call: all reference counts zero. */
	homa_peer_release(peer1);
	homa_peer_release(peer2);
	homa_peer_free_dead(peertab);
	unit_log_clear();
	unit_log_dead_peers(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}

TEST_F(homa_peer, homa_peer_wait_dead) {
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_peer *peer;

	peer = homa_peer_alloc(&self->hsk, ip1111);
	homa_peer_release(peer);
	list_add_tail(&peer->dead_links, &peertab->dead_peers);
	unit_log_clear();
	unit_log_dead_peers(&self->homa);
	EXPECT_STREQ("[1::1:1:1]", unit_log_get());
	atomic_set(&peertab->call_rcu_pending, 1);

	unit_hook_register(complete_rcu_hook);
	hook_peertab = self->homa.peertab;
	hook_free_count = 5;

	homa_peer_wait_dead(peertab);
	unit_log_clear();
	unit_log_dead_peers(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, hook_free_count);
}

TEST_F(homa_peer, homa_peer_prefer_evict)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_peer *peer1, *peer2, *peer3, *peer4;
	struct homa_net *hnet2;
	struct homa_sock hsk2;

	hnet2 = mock_alloc_hnet(&self->homa);
	mock_sock_init(&hsk2, hnet2, 44);

	peer1 = homa_peer_get(&self->hsk, ip1111);
	homa_peer_release(peer1);
	peer1->access_jiffies = 100;

	peer2 = homa_peer_get(&self->hsk, ip2222);
	homa_peer_release(peer2);
	peer2->access_jiffies = 1000;

	peer3 = homa_peer_get(&hsk2, ip3333);
	homa_peer_release(peer3);
	peer3->access_jiffies = 500;

	peer4 = homa_peer_get(&hsk2, ip1111);
	homa_peer_release(peer4);
	peer4->access_jiffies = 300;
	hnet2->num_peers = peertab->net_max + 1;

	EXPECT_EQ(1, homa_peer_prefer_evict(peertab, peer3, peer1));
	EXPECT_EQ(0, homa_peer_prefer_evict(peertab, peer3, peer4));
	EXPECT_EQ(0, homa_peer_prefer_evict(peertab, peer1, peer4));
	EXPECT_EQ(1, homa_peer_prefer_evict(peertab, peer1, peer2));

	homa_sock_destroy(&hsk2);
	homa_peer_free_net(hnet2);
}

TEST_F(homa_peer, homa_peer_pick_victims__hash_table_wraparound)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_peer *peers[3], *victims[5];

	jiffies = 50;
	peers[0] = homa_peer_get(&self->hsk, ip1111);
	homa_peer_release(peers[0]);

	peers[1] = NULL;

	peers[2] = homa_peer_get(&self->hsk, ip2222);
	homa_peer_release(peers[2]);

	mock_rht_walk_results = (void **)peers;
	mock_rht_num_walk_results = 3;
	jiffies = peertab->idle_jiffies_max + 100;

	EXPECT_EQ(2, homa_peer_pick_victims(peertab, victims, 5));
	EXPECT_EQ(peers[0], victims[0]);
	EXPECT_EQ(peers[2], victims[1]);
}
TEST_F(homa_peer, homa_peer_pick_victims__EAGAIN_from_rht_walk)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_peer *peers[5], *victims[5];

	jiffies = 50;
	peers[0] = ERR_PTR(-EAGAIN);

	peers[1] = homa_peer_get(&self->hsk, ip1111);
	homa_peer_release(peers[1]);

	peers[2] = ERR_PTR(-EAGAIN);

	peers[3] = ERR_PTR(-EAGAIN);

	peers[4] = homa_peer_get(&self->hsk, ip2222);
	homa_peer_release(peers[4]);

	mock_rht_walk_results = (void **)peers;
	mock_rht_num_walk_results = 5;
	jiffies = peertab->idle_jiffies_max + 100;

	EXPECT_EQ(1, homa_peer_pick_victims(peertab, victims, 5));
	EXPECT_EQ(peers[1], victims[0]);
}
TEST_F(homa_peer, homa_peer_pick_victims__filter_idle_jiffies_min)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_peer *peers[2], *victims[5];

	jiffies = 100;
	peers[1] = homa_peer_get(&self->hsk, ip1111);
	homa_peer_release(peers[1]);

	jiffies = 200;
	peers[0] = homa_peer_get(&self->hsk, ip2222);
	homa_peer_release(peers[0]);

	mock_rht_walk_results = (void **)peers;
	mock_rht_num_walk_results = 2;
	jiffies = peertab->idle_jiffies_min + 150;
	self->hnet->num_peers = peertab->net_max + 1000;

	EXPECT_EQ(1, homa_peer_pick_victims(peertab, victims, 5));
	EXPECT_EQ(peers[1], victims[0]);
}
TEST_F(homa_peer, homa_peer_pick_victims__filter_idle_jiffies_max)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_peer *peers[3], *victims[5];
	struct homa_net *hnet2;
	struct homa_sock hsk2;

	hnet2 = mock_alloc_hnet(&self->homa);
	mock_sock_init(&hsk2, hnet2, 44);
	hnet2->num_peers = peertab->net_max + 1;

	/* First peer: net below limit, idle < max. */
	jiffies = 150;
	peers[0] = homa_peer_get(&self->hsk, ip1111);
	homa_peer_release(peers[0]);

	/* Second peer: net above limit, idle > max. */
	jiffies = 50;
	peers[1] = homa_peer_get(&hsk2, ip2222);
	homa_peer_release(peers[1]);

	/* Third peer: net below limit, idle > max. */
	jiffies = 50;
	peers[2] = homa_peer_get(&self->hsk, ip3333);
	homa_peer_release(peers[2]);

	mock_rht_walk_results = (void **)peers;
	mock_rht_num_walk_results = 3;
	jiffies = peertab->idle_jiffies_max + 100;

	EXPECT_EQ(2, homa_peer_pick_victims(peertab, victims, 5));
	EXPECT_EQ(peers[1], victims[0]);
	EXPECT_EQ(peers[2], victims[1]);
}
TEST_F(homa_peer, homa_peer_pick_victims__duplicate_peer)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_peer *peers[3], *victims[3];

	jiffies = 300;
	peers[0] = homa_peer_get(&self->hsk, ip1111);
	homa_peer_release(peers[0]);

	peers[1] = peers[0];
	peers[2] = peers[0];

	mock_rht_walk_results = (void **)peers;
	mock_rht_num_walk_results = 3;
	jiffies = peertab->idle_jiffies_max + 1000;

	EXPECT_EQ(1, homa_peer_pick_victims(peertab, victims, 3));
	EXPECT_EQ(peers[0], victims[0]);
}
TEST_F(homa_peer, homa_peer_pick_victims__select_best_candidates)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_peer *peers[6], *victims[3];

	jiffies = 300;
	peers[0] = homa_peer_get(&self->hsk, ip1111);
	homa_peer_release(peers[0]);

	jiffies = 400;
	peers[1] = homa_peer_get(&self->hsk, ip2222);
	homa_peer_release(peers[1]);

	jiffies = 500;
	peers[2] = homa_peer_get(&self->hsk, ip3333);
	homa_peer_release(peers[2]);

	jiffies = 200;
	peers[3] = homa_peer_get(&self->hsk, ip4444);
	homa_peer_release(peers[3]);

	jiffies = 350;
	peers[4] = homa_peer_get(&self->hsk, ip5555);
	homa_peer_release(peers[4]);

	jiffies = 600;
	peers[5] = homa_peer_get(&self->hsk, ip6666);
	homa_peer_release(peers[5]);

	mock_rht_walk_results = (void **)peers;
	mock_rht_num_walk_results = 6;
	jiffies = peertab->idle_jiffies_max + 1000;

	EXPECT_EQ(3, homa_peer_pick_victims(peertab, victims, 3));
	EXPECT_EQ(peers[3], victims[0]);
	EXPECT_EQ(peers[0], victims[1]);
	EXPECT_EQ(peers[4], victims[2]);
}

TEST_F(homa_peer, homa_peer_gc__basics)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_peer *peer;

	jiffies = 300;
	peer = homa_peer_get(&self->hsk, ip1111);
	homa_peer_release(peer);
	EXPECT_EQ(1, self->hnet->num_peers);

	jiffies = peertab->idle_jiffies_max + 1000;
	peertab->num_peers = peertab->gc_threshold;

	unit_log_clear();
	homa_peer_gc(peertab);
	unit_log_dead_peers(&self->homa);
	EXPECT_STREQ("call_rcu invoked; [1::1:1:1]", unit_log_get());
	EXPECT_EQ(1, atomic_read(&peertab->call_rcu_pending));
	EXPECT_EQ(0, self->hnet->num_peers);
	EXPECT_EQ(peertab->gc_threshold - 1, peertab->num_peers);

	homa_peer_rcu_callback(&peertab->rcu_head);
	unit_log_clear();
	homa_peer_gc(peertab);
	unit_log_dead_peers(&self->homa);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, atomic_read(&peertab->call_rcu_pending));
}
TEST_F(homa_peer, homa_peer_gc__gc_stop_count)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_peer *peer;

	jiffies = 300;
	peer = homa_peer_get(&self->hsk, ip1111);
	homa_peer_release(peer);

	jiffies = peertab->idle_jiffies_max + 1000;
	peertab->num_peers = peertab->gc_threshold;
	peertab->gc_stop_count = 1;

	unit_log_clear();
	homa_peer_gc(peertab);
	unit_log_dead_peers(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_peer, homa_peer_gc__call_rcu_pending)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_peer *peer;

	jiffies = 300;
	peer = homa_peer_get(&self->hsk, ip1111);
	homa_peer_release(peer);

	jiffies = peertab->idle_jiffies_max + 1000;
	peertab->num_peers = peertab->gc_threshold;
	atomic_set(&peertab->call_rcu_pending, 1);

	unit_log_clear();
	homa_peer_gc(peertab);
	unit_log_dead_peers(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_peer, homa_peer_gc__peers_below_gc_threshold)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_peer *peer;

	jiffies = 300;
	peer = homa_peer_get(&self->hsk, ip1111);
	homa_peer_release(peer);

	jiffies = peertab->idle_jiffies_max + 1000;
	peertab->num_peers = peertab->gc_threshold - 1;

	unit_log_clear();
	homa_peer_gc(peertab);
	unit_log_dead_peers(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_peer, homa_peer_gc__no_suitable_candidates)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_peer *peer;

	jiffies = 100;
	peer = homa_peer_get(&self->hsk, ip1111);
	homa_peer_release(peer);

	jiffies = peertab->idle_jiffies_min;
	peertab->num_peers = peertab->gc_threshold - 1;

	unit_log_clear();
	homa_peer_gc(peertab);
	unit_log_dead_peers(&self->homa);
	EXPECT_STREQ("", unit_log_get());
}

TEST_F(homa_peer, homa_peer_alloc__success)
{
	struct homa_peer *peer;

	jiffies = 999;
	peer = homa_peer_alloc(&self->hsk, ip1111);
	ASSERT_FALSE(IS_ERR(peer));
	EXPECT_EQ_IP(*ip1111, peer->addr);
	EXPECT_EQ(999, peer->access_jiffies);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(INT_MAX, peer->unsched_cutoffs[HOMA_MAX_PRIORITIES-2]);
	EXPECT_EQ(0, peer->cutoff_version);
	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_allocs);
#endif /* See strip.py */
	EXPECT_EQ(1, atomic_read(&peer->dst->__rcuref.refcnt));
	homa_peer_release(peer);
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

	homa_peer_release(peer);
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
	jiffies = 456;
	peer = homa_peer_get(&self->hsk, ip1111);
	ASSERT_FALSE(IS_ERR(peer));
	EXPECT_EQ_IP(*ip1111, peer->addr);
	EXPECT_EQ(456, peer->access_jiffies);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(INT_MAX, peer->unsched_cutoffs[HOMA_MAX_PRIORITIES-2]);
	EXPECT_EQ(0, peer->cutoff_version);
#endif /* See strip.py */
	EXPECT_EQ(1, self->homa.peertab->num_peers);
	EXPECT_EQ(1, self->hnet->num_peers);

	/* Second call: lookup existing peer. */
	peer2 = homa_peer_get(&self->hsk, ip1111);
	EXPECT_EQ(peer, peer2);
	EXPECT_EQ(2, atomic_read(&peer->refs));
	EXPECT_EQ(1, self->homa.peertab->num_peers);
	EXPECT_EQ(1, self->hnet->num_peers);

	/* Third call: lookup new peer. */
	peer2 = homa_peer_get(&self->hsk, ip2222);
	EXPECT_NE(peer, peer2);
	ASSERT_FALSE(IS_ERR(peer2));
	EXPECT_EQ(1, atomic_read(&peer2->refs));
	EXPECT_EQ(2, self->homa.peertab->num_peers);
	EXPECT_EQ(2, self->hnet->num_peers);

#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(2, homa_metrics_per_cpu()->peer_allocs);
#endif /* See strip.py */
	homa_peer_release(peer);
	homa_peer_release(peer);
	homa_peer_release(peer2);
}
TEST_F(homa_peer, homa_peer_find__error_in_homa_peer_alloc)
{
	struct homa_peer *peer;

	mock_route_errors = 1;
	peer = homa_peer_get(&self->hsk, ip3333);
	EXPECT_EQ(EHOSTUNREACH, -PTR_ERR(peer));

#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_route_errors);
#endif /* See strip.py */
}
TEST_F(homa_peer, homa_peer_find__insert_error)
{
	struct homa_peer *peer;

	mock_rht_insert_errors = 1;
	peer = homa_peer_get(&self->hsk, ip3333);
	EXPECT_TRUE(IS_ERR(peer));
	EXPECT_EQ(EINVAL, -PTR_ERR(peer));
}
TEST_F(homa_peer, homa_peer_find__conflicting_create)
{
	struct homa_peer *peer;

	test_data = self;
	peer_race_hook_invocations = 0;
	unit_hook_register(peer_race_hook);
	jiffies = 100;
	peer = homa_peer_get(&self->hsk, ip3333);
	EXPECT_FALSE(IS_ERR(conflicting_peer));
	EXPECT_EQ(conflicting_peer, peer);
	EXPECT_EQ(1, atomic_read(&peer->refs));
	EXPECT_EQ(110, peer->access_jiffies);
	homa_peer_release(peer);
	EXPECT_EQ(1, self->homa.peertab->num_peers);
	EXPECT_EQ(1, self->hnet->num_peers);
}

TEST_F(homa_peer, homa_dst_refresh__basics)
{
	struct dst_entry *old_dst;
	struct homa_peer *peer;

	peer = homa_peer_get(&self->hsk, ip1111);
	ASSERT_NE(NULL, peer);
	EXPECT_EQ_IP(*ip1111, peer->addr);

	old_dst = peer->dst;
	homa_dst_refresh(self->homa.peertab, peer, &self->hsk);
	EXPECT_NE(old_dst, peer->dst);
	homa_peer_release(peer);
}
TEST_F(homa_peer, homa_dst_refresh__routing_error)
{
	struct dst_entry *old_dst;
	struct homa_peer *peer;

	peer = homa_peer_get(&self->hsk, ip1111);
	ASSERT_NE(NULL, peer);
	EXPECT_EQ_IP(*ip1111, peer->addr);

	old_dst = peer->dst;
	mock_route_errors = 1;
	homa_dst_refresh(self->homa.peertab, peer, &self->hsk);
	EXPECT_EQ(old_dst, peer->dst);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_route_errors);
#endif /* See strip.py */
	homa_peer_release(peer);
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

	struct homa_peer *peer = homa_peer_get(&self->hsk,
						&self->client_ip[0]);
	ASSERT_NE(NULL, peer);

	dst = homa_peer_get_dst(peer, &self->hsk);
	ASSERT_NE(NULL, dst);
	dst_release(dst);
	EXPECT_STREQ("196.168.0.1",
				homa_print_ipv4_addr(peer->flow.u.ip4.daddr));
	homa_peer_release(peer);
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

	struct homa_peer *peer = homa_peer_get(&self->hsk, &ip1111[0]);
	ASSERT_NE(NULL, peer);

	dst = homa_peer_get_dst(peer, &self->hsk);
	ASSERT_NE(NULL, dst);
	dst_release(dst);
	addr = ntohl(peer->flow.u.ip4.daddr);
	snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", (addr >> 24) & 0xff,
			(addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff);
	EXPECT_STREQ("[1::1:1:1]",
			homa_print_ipv6_addr(&peer->flow.u.ip6.daddr));
	homa_peer_release(peer);
}

#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_peer, homa_peer_lock_slow)
{
	struct homa_peer *peer = homa_peer_get(&self->hsk, ip3333);

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
	homa_peer_release(peer);
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
	struct homa_peer *peer = homa_peer_get(&self->hsk, ip3333);
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
	homa_peer_release(peer);
}

TEST_F(homa_peer, homa_peer_update_sysctl_deps)
{
	struct homa_peertab *peertab = self->homa.peertab;

	peertab->idle_secs_min = 10;
	peertab->idle_secs_max = 100;
	homa_peer_update_sysctl_deps(peertab);
	EXPECT_EQ(10*HZ, peertab->idle_jiffies_min);
	EXPECT_EQ(100*HZ, peertab->idle_jiffies_max);
}
