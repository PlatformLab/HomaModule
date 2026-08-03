// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

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
	self->hnet = mock_hnet(0, &self->homa);
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
	mock_rcu_free();
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
static struct homa_route *conflicting_route;
static int route_race_hook_invocations;
static void route_race_hook(char *id)
{
	if (strcmp(id, "spin_lock") != 0)
		return;
	route_race_hook_invocations--;
	if (route_race_hook_invocations != 0)
		return;

	/* Create a route with the same address as the one being created
	 * by the current test.
	 */
	conflicting_route = homa_route_get(&test_data->hsk, ip3333);
	homa_route_release(conflicting_route);
	jiffies += 10;
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
TEST_F(homa_peer, homa_peer_alloc_peertab__rhashtable_init_fails_for_peer_ht)
{
	struct homa_peertab *peertab;

	mock_rht_init_errors = 1;
	peertab = homa_peer_alloc_peertab();
	EXPECT_TRUE(IS_ERR(peertab));
	EXPECT_EQ(EINVAL, -PTR_ERR(peertab));
}
TEST_F(homa_peer, homa_peer_alloc_peertab__rhashtable_init_fails_for_route_ht)
{
	struct homa_peertab *peertab;

	mock_rht_init_errors = 2;
	peertab = homa_peer_alloc_peertab();
	EXPECT_TRUE(IS_ERR(peertab));
	EXPECT_EQ(EINVAL, -PTR_ERR(peertab));
}
#ifndef __STRIP__ /* See strip.py */
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
#endif /* See strip.py */

TEST_F(homa_peer, homa_peer_free_net__basics)
{
	/* Create peers from two different netns's, make sure only
	 * those from one get freed. */
	struct homa_route *route;
	struct homa_sock hsk2;
	struct homa_net *hnet2;

	hnet2 = mock_hnet(1, &self->homa);
	mock_sock_init(&hsk2, hnet2, 44);

	route = homa_route_get(&self->hsk, ip1111);
	homa_route_release(route);
	route = homa_route_get(&self->hsk, ip2222);
	homa_route_release(route);
	route = homa_route_get(&hsk2, ip3333);
	homa_route_release(route);
	EXPECT_EQ(3, unit_count_routes(&self->homa));
	EXPECT_EQ(3, self->homa.peertab->num_routes);
	EXPECT_EQ(2, self->hnet->num_routes);

	homa_peer_free_net(self->hnet);
	EXPECT_EQ(1, unit_count_routes(&self->homa));
	EXPECT_EQ(1, self->homa.peertab->num_routes);
	unit_sock_destroy(&hsk2);
}

TEST_F(homa_peer, homa_route_delete_fn)
{
	struct homa_route *route;

	route = homa_route_get(&self->hsk, ip3333);
	homa_route_delete_fn(route, NULL);
	EXPECT_EQ(1, refcount_read(&route->refs));
	EXPECT_EQ(NULL, route->peer);
}

TEST_F(homa_peer, homa_peer_free_peertab) {
	struct homa_route *route;

	/* Create two peers, release one before destroying the table, the
	 * other after (test infrastructure will detect improper freeing).
	 */
	route = homa_route_get(&self->hsk, ip1111);
	homa_route_release(route);
	route = homa_route_get(&self->hsk, ip2222);

	unit_log_clear();
	homa_peer_free_peertab(self->homa.peertab);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_SUBSTR("unregister_net_sysctl_table", unit_log_get());
#endif /* See strip.py */

	homa_route_release(route);
	self->homa.peertab = homa_peer_alloc_peertab();
}

TEST_F(homa_peer, homa_peer_alloc__success)
{
	struct homa_peer *peer;

	peer = homa_peer_alloc(&self->hsk, ip1111);
	ASSERT_FALSE(IS_ERR(peer));
	EXPECT_EQ_IP(*ip1111, peer->addr);
	EXPECT_EQ(1, refcount_read(&peer->refs));
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(INT_MAX, peer->unsched_cutoffs[HOMA_MAX_PRIORITIES-2]);
	EXPECT_EQ(0, peer->cutoff_version);
#endif /* See strip.py */
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

TEST_F(homa_peer, homa_peer_free)
{
	struct homa_peer *peer;

	peer = homa_peer_alloc(&self->hsk, ip1111);
	ASSERT_FALSE(IS_ERR(peer));
	homa_peer_free(peer);

	/* Nothing to check here; test infrastructure will complain if
	 * peer's memory isn't freed.
	 */
}

TEST_F(homa_peer, homa_peer_get__basics)
{
	struct homa_peer *peer, *peer2;

	/* First call: create new peer. */
	peer = homa_peer_get(&self->hsk, ip1111);
	ASSERT_FALSE(IS_ERR(peer));
	EXPECT_EQ_IP(*ip1111, peer->addr);
	EXPECT_EQ(1, refcount_read(&peer->refs));
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(INT_MAX, peer->unsched_cutoffs[HOMA_MAX_PRIORITIES-2]);
	EXPECT_EQ(0, peer->cutoff_version);
#endif /* See strip.py */

	/* Second call: lookup existing peer. */
	peer2 = homa_peer_get(&self->hsk, ip1111);
	EXPECT_EQ(peer, peer2);
	EXPECT_EQ(2, refcount_read(&peer->refs));

	/* Third call: lookup new peer. */
	peer2 = homa_peer_get(&self->hsk, ip2222);
	EXPECT_NE(peer, peer2);
	ASSERT_FALSE(IS_ERR(peer2));
	EXPECT_EQ(1, refcount_read(&peer2->refs));

	homa_peer_free(peer);
	homa_peer_free(peer2);
}
TEST_F(homa_peer, homa_peer_get__error_in_homa_peer_alloc)
{
	struct homa_peer *peer;

	mock_kmalloc_errors = 1;
	peer = homa_peer_get(&self->hsk, ip3333);
	EXPECT_EQ(ENOMEM, -PTR_ERR(peer));
}
TEST_F(homa_peer, homa_peer_get__insert_error)
{
	struct homa_peer *peer;

	mock_rht_insert_errors = 1;
	peer = homa_peer_get(&self->hsk, ip3333);
	EXPECT_TRUE(IS_ERR(peer));
	EXPECT_EQ(EINVAL, -PTR_ERR(peer));
}

TEST_F(homa_peer, homa_route_alloc__success)
{
	struct homa_route_key key;
	struct homa_route *route;

	jiffies = 12345;
	homa_route_key_init(&key, &self->hsk, ip1111);
	route = homa_route_alloc(&self->hsk, &key);
	ASSERT_FALSE(IS_ERR(route));
	EXPECT_EQ_IP(*ip1111, route->flow.u.ip6.daddr);
	EXPECT_EQ(1, refcount_read(&route->refs));
	EXPECT_EQ(12345, route->access_jiffies);
	EXPECT_EQ(1, rcuref_read(&route->dst->__rcuref));
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->route_allocs);
#endif /* See strip.py */
	homa_route_free(&route->rcu_head);
}
TEST_F(homa_peer, homa_route_alloc__kmalloc_error)
{
	struct homa_route_key key;
	struct homa_route *route;

	mock_kmalloc_errors = 1;
	homa_route_key_init(&key, &self->hsk, ip3333);
	route = homa_route_alloc(&self->hsk, &key);
	EXPECT_EQ(ENOMEM, -PTR_ERR(route));

#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_kmalloc_errors);
#endif /* See strip.py */
}
TEST_F(homa_peer, homa_route_alloc__set_saddr_from_socket)
{
	struct homa_route_key key;
	struct homa_route *route;

	/* First try: use IPv4 address. */
	self->hsk.sock.sk_family = AF_INET;
	homa_route_key_init(&key, &self->hsk, ip1111);
	route = homa_route_alloc(&self->hsk, &key);
	EXPECT_STREQ("2.4.6.8", homa_print_ipv6_addr(&route->key.saddr));
	homa_route_free(&route->rcu_head);

	/* Second try: use IPv4 address. */
	self->hsk.sock.sk_family = AF_INET6;
	homa_route_key_init(&key, &self->hsk, ip1111);
	route = homa_route_alloc(&self->hsk, &key);
	EXPECT_STREQ("[6::7:8:9]", homa_print_ipv6_addr(&route->key.saddr));
	homa_route_free(&route->rcu_head);
}
TEST_F(homa_peer, homa_route_alloc__route_error_ipv4)
{
	struct homa_route_key key;
	struct homa_route *route;

	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	unit_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, self->hnet, 0);

	mock_route_errors = 1;

	homa_route_key_init(&key, &self->hsk, &self->client_ip[0]);
	route = homa_route_alloc(&self->hsk, &key);
	EXPECT_EQ(EHOSTUNREACH, -PTR_ERR(route));
	EXPECT_STREQ("couldn't find route for peer", self->hsk.error_msg);

#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_route_errors);
#endif /* See strip.py */
}
TEST_F(homa_peer, homa_route_alloc__route_error_ipv6)
{
	struct homa_route_key key;
	struct homa_route *route;

	// Make sure the test uses IPv6.
	mock_ipv6 = true;
	unit_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, self->hnet, 0);

	mock_route_errors = 1;

	homa_route_key_init(&key, &self->hsk, ip3333);
	route = homa_route_alloc(&self->hsk, &key);
	EXPECT_EQ(EHOSTUNREACH, -PTR_ERR(route));
	EXPECT_STREQ("couldn't find route for peer", self->hsk.error_msg);

#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_route_errors);
#endif /* See strip.py */
}

TEST_F(homa_peer, homa_route_free)
{
	struct homa_route_key key;
	struct homa_route *route;
	struct homa_peer *peer;
	struct dst_entry *dst;

	homa_route_key_init(&key, &self->hsk, ip1111);
	route = homa_route_alloc(&self->hsk, &key);
	EXPECT_EQ(NULL, route->peer);
	peer = homa_peer_alloc(&self->hsk, ip1111);
	route->peer = peer;
	refcount_inc(&peer->refs);
	EXPECT_EQ(2, refcount_read(&peer->refs));

	dst = route->dst;
	dst_hold(dst);
	EXPECT_EQ(2, rcuref_read(&dst->__rcuref));

	homa_route_free(&route->rcu_head);
	EXPECT_EQ(1, rcuref_read(&dst->__rcuref));
	EXPECT_EQ(1, refcount_read(&peer->refs));
	dst_release(dst);
	homa_peer_free(peer);
}

TEST_F(homa_peer, homa_route_get__basics)
{
	struct homa_route *route, *route2;

	/* First call: create new route. */
	jiffies = 456;
	route = homa_route_get(&self->hsk, ip1111);
	ASSERT_FALSE(IS_ERR(route));
	EXPECT_EQ_IP(*ip1111, route->peer->addr);
	EXPECT_EQ(456, route->access_jiffies);
	EXPECT_EQ(2, refcount_read(&route->refs));
	EXPECT_EQ(1, self->homa.peertab->num_routes);
	EXPECT_EQ(1, self->hnet->num_routes);

	/* Second call: lookup existing route. */
	jiffies = 700;
	route2 = homa_route_get(&self->hsk, ip1111);
	EXPECT_EQ(route, route2);
	EXPECT_EQ(3, refcount_read(&route->refs));
	EXPECT_EQ(700, route->access_jiffies);
	EXPECT_EQ(1, self->homa.peertab->num_routes);
	EXPECT_EQ(1, self->hnet->num_routes);

	/* Third call: lookup new route. */
	route2 = homa_route_get(&self->hsk, ip2222);
	EXPECT_NE(route, route2);
	ASSERT_FALSE(IS_ERR(route2));
	EXPECT_EQ(2, refcount_read(&route2->refs));
	EXPECT_EQ(2, self->homa.peertab->num_routes);
	EXPECT_EQ(2, self->hnet->num_routes);

#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(2, homa_metrics_per_cpu()->route_allocs);
#endif /* See strip.py */
	homa_route_release(route);
	homa_route_release(route);
	homa_route_release(route2);
}
struct homa_route *hook_route;
struct homa_peertab *hook_peertab;
/* Hook function that removes a route from the hash table and frees it. */
static void free_hook(char *id)
{
	extern struct rhashtable_params route_ht_params;

	if (strcmp(id, "spin_lock") != 0 || !hook_route)
		return;

	if (rhashtable_remove_fast(&hook_peertab->route_ht,
				   &hook_route->ht_linkage,
			           route_ht_params) == 0)
		homa_route_free(&hook_route->rcu_head);
	else
		FAIL("hook_route wasn't in hash table");
	hook_route = NULL;
}
TEST_F(homa_peer, homa_route_get__race_with_homa_route_release)
{
	struct homa_route *route, *route2;

	/* Create route, then release so refcount is 1. */
	route = homa_route_get(&self->hsk, ip1111);
	ASSERT_FALSE(IS_ERR(route));
	homa_route_release(route);
	EXPECT_EQ(1, refcount_read(&route->refs));

	/* Artificially set reference count to 0 so refcount_inc_not_zero
	 * will fail in homa_route_get, and arrange for gc to remove the route
	 * when homa_route_get acquires the spinlock.
	 */
	refcount_set(&route->refs, 0);
	unit_hook_register(free_hook);
	hook_route = route;
	hook_peertab = self->homa.peertab;

	/* Try to get the same route; make sure that a different route is
	 * returned.
	 */
	route2 = homa_route_get(&self->hsk, ip1111);
	EXPECT_NE(route, route2);
	homa_route_release(route2);
}
TEST_F(homa_peer, homa_route_get__homa_route_alloc_fails)
{
	struct homa_route *route;

	mock_kmalloc_errors = 1;
	route = homa_route_get(&self->hsk, ip1111);
	EXPECT_TRUE(IS_ERR(route));
	EXPECT_EQ(ENOMEM, -PTR_ERR(route));
	EXPECT_STREQ("couldn't allocate memory for homa_route",
		     self->hsk.error_msg);
}
TEST_F(homa_peer, homa_route_get__homa_peer_get_fails)
{
	struct homa_route *route;

	mock_rht_insert_errors = 1;
	route = homa_route_get(&self->hsk, ip1111);
	EXPECT_TRUE(IS_ERR(route));
	EXPECT_EQ(EINVAL, -PTR_ERR(route));
	EXPECT_STREQ("unexpected error return from rhashtable_lookup_insert_fast",
		     self->hsk.error_msg);
}
TEST_F(homa_peer, homa_route_get__cant_insert_new_key)
{
	struct homa_route *route;

	mock_rht_insert_errors = 2;
	route = homa_route_get(&self->hsk, ip1111);
	EXPECT_TRUE(IS_ERR(route));
	EXPECT_EQ(EINVAL, -PTR_ERR(route));
	EXPECT_STREQ("rhashtable_lookup_get_insert_key failed in homa_route_get",
		     self->hsk.error_msg);
}
TEST_F(homa_peer, homa_route_get__conflicting_create)
{
	struct homa_route *route;

	test_data = self;
	route_race_hook_invocations = 1;
	unit_hook_register(route_race_hook);
	jiffies = 100;
	route = homa_route_get(&self->hsk, ip3333);
	EXPECT_FALSE(IS_ERR(conflicting_route));
	EXPECT_EQ(conflicting_route, route);
	EXPECT_EQ(2, refcount_read(&route->refs));
	EXPECT_EQ(110, route->access_jiffies);
	homa_route_release(route);
	EXPECT_EQ(1, self->homa.peertab->num_routes);
	EXPECT_EQ(1, self->hnet->num_routes);
}

TEST_F(homa_peer, homa_route_validate)
{
	struct homa_route *route;
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port, 101, 100,
			       100);
	ASSERT_NE(NULL, crpc);

	route = crpc->route;

	/* First call: existing route is valid. */
	EXPECT_EQ(0, -homa_route_validate(crpc));
	EXPECT_EQ(route, crpc->route);

	/* Second call: route is invalid. */
	route->dst->obsolete = 1;
	mock_dst_check_errors = 1;
	EXPECT_EQ(0, -homa_route_validate(crpc));
	EXPECT_NE(route, crpc->route);
	EXPECT_EQ(1, self->homa.peertab->num_routes);
	EXPECT_EQ(1, crpc->hsk->hnet->num_routes);
	EXPECT_EQ(1, unit_count_routes(&self->homa));

	/* Third call: route is invalid but can't create replacement. */
	route = crpc->route;
	route->dst->obsolete = 1;
	mock_dst_check_errors = 1;
	mock_kmalloc_errors = 1;
	EXPECT_EQ(ENOMEM, -homa_route_validate(crpc));
	EXPECT_EQ(route, crpc->route);
	EXPECT_EQ(0, self->homa.peertab->num_routes);
	EXPECT_EQ(0, crpc->hsk->hnet->num_routes);
	EXPECT_EQ(0, unit_count_routes(&self->homa));

	/* Fourth call: route is still invalid and is not in the hash
	 * table at the time of the call. Replacement succeeds this time.
	 */
	mock_dst_check_errors = 1;
	EXPECT_EQ(0, -homa_route_validate(crpc));
	EXPECT_NE(route, crpc->route);
	EXPECT_EQ(1, self->homa.peertab->num_routes);
	EXPECT_EQ(1, crpc->hsk->hnet->num_routes);
	EXPECT_EQ(1, unit_count_routes(&self->homa));
}

TEST_F(homa_peer, homa_route_gc__basics)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_route *route;

	jiffies = 300;
	route = homa_route_get(&self->hsk, ip1111);
	homa_route_release(route);
	EXPECT_EQ(1, self->hnet->num_routes);

	jiffies = peertab->idle_jiffies_max + 1000;
	peertab->num_routes = peertab->gc_threshold;

	unit_log_clear();
	homa_route_gc(peertab);
	EXPECT_STREQ("call_rcu invoked", unit_log_get());
	EXPECT_EQ(0, self->hnet->num_routes);
	EXPECT_EQ(peertab->gc_threshold - 1, peertab->num_routes);
}
TEST_F(homa_peer, homa_route_gc__routes_below_gc_threshold)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_route *route;

	jiffies = 300;
	route = homa_route_get(&self->hsk, ip1111);
	homa_route_release(route);

	jiffies = peertab->idle_jiffies_max + 1000;
	peertab->num_routes = peertab->gc_threshold - 1;

	unit_log_clear();
	homa_route_gc(peertab);
	EXPECT_STREQ("", unit_log_get());
}
TEST_F(homa_peer, homa_route_gc__no_suitable_candidates)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_route *route;

	jiffies = 100;
	route = homa_route_get(&self->hsk, ip1111);
	homa_route_release(route);

	jiffies = peertab->idle_jiffies_min;
	peertab->num_routes = peertab->gc_threshold - 1;

	unit_log_clear();
	homa_route_gc(peertab);
	EXPECT_STREQ("", unit_log_get());
}

TEST_F(homa_peer, homa_route_pick_victims__hash_table_wraparound)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_route *routes[3], *victims[5];

	jiffies = 50;
	routes[0] = homa_route_get(&self->hsk, ip1111);
	homa_route_release(routes[0]);

	routes[1] = NULL;

	routes[2] = homa_route_get(&self->hsk, ip2222);
	homa_route_release(routes[2]);

	mock_rht_walk_results = (void **)routes;
	mock_rht_num_walk_results = 3;
	jiffies = peertab->idle_jiffies_max + 100;

	EXPECT_EQ(2, homa_route_pick_victims(peertab, victims, 5));
	EXPECT_EQ(routes[0], victims[0]);
	EXPECT_EQ(routes[2], victims[1]);
}
TEST_F(homa_peer, homa_route_pick_victims__EAGAIN_from_rht_walk)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_route *routes[5], *victims[5];

	jiffies = 50;
	routes[0] = ERR_PTR(-EAGAIN);

	routes[1] = homa_route_get(&self->hsk, ip1111);
	homa_route_release(routes[1]);

	routes[2] = ERR_PTR(-EAGAIN);

	routes[3] = ERR_PTR(-EAGAIN);

	routes[4] = homa_route_get(&self->hsk, ip2222);
	homa_route_release(routes[4]);

	mock_rht_walk_results = (void **)routes;
	mock_rht_num_walk_results = 5;
	jiffies = peertab->idle_jiffies_max + 100;

	EXPECT_EQ(1, homa_route_pick_victims(peertab, victims, 5));
	EXPECT_EQ(routes[1], victims[0]);
}
TEST_F(homa_peer, homa_route_pick_victims__filter_idle_jiffies_min)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_route *routes[2], *victims[5];

	jiffies = 100;
	routes[1] = homa_route_get(&self->hsk, ip1111);
	homa_route_release(routes[1]);

	jiffies = 200;
	routes[0] = homa_route_get(&self->hsk, ip2222);
	homa_route_release(routes[0]);

	mock_rht_walk_results = (void **)routes;
	mock_rht_num_walk_results = 2;
	jiffies = peertab->idle_jiffies_min + 150;
	self->hnet->num_routes = peertab->net_max + 1000;
	memset(victims, 0, sizeof(victims));

	/* First call selects one victim */
	EXPECT_EQ(1, homa_route_pick_victims(peertab, victims, 5));
	EXPECT_EQ(routes[1], victims[0]);

	/* Second call tests whether the comparison with idle_jiffies_min
	 * is robust if somehow jiffies < route->access_jiffies.
	 */
	mock_rht_walk_results = (void **)routes;
	mock_rht_num_walk_results = 2;
	routes[1]->access_jiffies = 500;
	jiffies = 400;
	memset(victims, 0, sizeof(victims));
	EXPECT_EQ(0, homa_route_pick_victims(peertab, victims, 5));
	EXPECT_EQ(NULL, victims[0]);
}
TEST_F(homa_peer, homa_route_pick_victims__filter_idle_jiffies_max)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_route *routes[4], *victims[5];
	struct homa_net *hnet2;
	struct homa_sock hsk2;

	hnet2 = mock_hnet(1, &self->homa);
	mock_sock_init(&hsk2, hnet2, 44);
	hnet2->num_routes = peertab->net_max + 1;

	/* First route: net below limit, idle < max. */
	jiffies = 150;
	routes[0] = homa_route_get(&self->hsk, ip1111);
	homa_route_release(routes[0]);

	/* Second route: net above limit, idle > max. */
	jiffies = 50;
	routes[1] = homa_route_get(&hsk2, ip2222);
	homa_route_release(routes[1]);

	/* Third route: net below limit, idle > max. */
	jiffies = 50;
	routes[2] = homa_route_get(&self->hsk, ip3333);
	homa_route_release(routes[2]);

	/* Fourth route: net below limit, idle negative (to test robustness). */
	jiffies = peertab->idle_jiffies_max + 200;
	routes[3] = homa_route_get(&self->hsk, ip4444);
	homa_route_release(routes[3]);

	/* Make sure idle_jiffies_min test is a no-op. */
	peertab->idle_jiffies_min = -10000;

	mock_rht_walk_results = (void **)routes;
	mock_rht_num_walk_results = 4;
	jiffies = peertab->idle_jiffies_max + 100;

	EXPECT_EQ(2, homa_route_pick_victims(peertab, victims, 5));
	EXPECT_EQ(routes[1], victims[0]);
	EXPECT_EQ(routes[2], victims[1]);
	unit_sock_destroy(&hsk2);
}
TEST_F(homa_peer, homa_route_pick_victims__duplicate_route)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_route *routes[3], *victims[3];

	jiffies = 300;
	routes[0] = homa_route_get(&self->hsk, ip1111);
	homa_route_release(routes[0]);

	routes[1] = routes[0];
	routes[2] = routes[0];

	mock_rht_walk_results = (void **)routes;
	mock_rht_num_walk_results = 3;
	jiffies = peertab->idle_jiffies_max + 1000;

	EXPECT_EQ(1, homa_route_pick_victims(peertab, victims, 3));
	EXPECT_EQ(routes[0], victims[0]);
}
TEST_F(homa_peer, homa_route_pick_victims__select_best_candidates)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_route *routes[6], *victims[3];

	jiffies = 300;
	routes[0] = homa_route_get(&self->hsk, ip1111);
	homa_route_release(routes[0]);

	jiffies = 400;
	routes[1] = homa_route_get(&self->hsk, ip2222);
	homa_route_release(routes[1]);

	jiffies = 500;
	routes[2] = homa_route_get(&self->hsk, ip3333);
	homa_route_release(routes[2]);

	jiffies = 200;
	routes[3] = homa_route_get(&self->hsk, ip4444);
	homa_route_release(routes[3]);

	jiffies = 350;
	routes[4] = homa_route_get(&self->hsk, ip5555);
	homa_route_release(routes[4]);

	jiffies = 600;
	routes[5] = homa_route_get(&self->hsk, ip6666);
	homa_route_release(routes[5]);

	mock_rht_walk_results = (void **)routes;
	mock_rht_num_walk_results = 6;
	jiffies = peertab->idle_jiffies_max + 1000;

	EXPECT_EQ(3, homa_route_pick_victims(peertab, victims, 3));
	EXPECT_EQ(routes[3], victims[0]);
	EXPECT_EQ(routes[0], victims[1]);
	EXPECT_EQ(routes[4], victims[2]);
}

TEST_F(homa_peer, homa_route_prefer_evict)
{
	struct homa_peertab *peertab = self->homa.peertab;
	struct homa_route *route1, *route2, *route3, *route4;
	struct homa_net *hnet2;
	struct homa_sock hsk2;

	hnet2 = mock_hnet(1, &self->homa);
	mock_sock_init(&hsk2, hnet2, 44);

	route1 = homa_route_get(&self->hsk, ip1111);
	homa_route_release(route1);
	route1->access_jiffies = 100;

	route2 = homa_route_get(&self->hsk, ip2222);
	homa_route_release(route2);
	route2->access_jiffies = 1000;

	route3 = homa_route_get(&hsk2, ip3333);
	homa_route_release(route3);
	route3->access_jiffies = 500;

	route4 = homa_route_get(&hsk2, ip1111);
	homa_route_release(route4);
	route4->access_jiffies = 300;
	hnet2->num_routes = peertab->net_max + 1;

	EXPECT_EQ(1, homa_route_prefer_evict(peertab, route3, route1));
	EXPECT_EQ(0, homa_route_prefer_evict(peertab, route3, route4));
	EXPECT_EQ(0, homa_route_prefer_evict(peertab, route1, route4));
	EXPECT_EQ(1, homa_route_prefer_evict(peertab, route1, route2));

	unit_sock_destroy(&hsk2);
	homa_peer_free_net(hnet2);
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

TEST_F(homa_peer, homa_peer_lock_slow)
{
	struct homa_route *route = homa_route_get(&self->hsk, ip3333);

	ASSERT_NE(NULL, route);
	mock_clock = 10000;
	homa_peer_lock(route->peer);
	EXPECT_EQ(0, homa_metrics_per_cpu()->peer_ack_lock_misses);
	EXPECT_EQ(0, homa_metrics_per_cpu()->peer_ack_lock_miss_cycles);
	homa_peer_unlock(route->peer);

	mock_trylock_errors = 1;
	unit_hook_register(peer_spinlock_hook);
	homa_peer_lock(route->peer);
	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_ack_lock_misses);
	EXPECT_EQ(1000, homa_metrics_per_cpu()->peer_ack_lock_miss_cycles);
	homa_peer_unlock(route->peer);
	homa_route_release(route);
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
	struct homa_peer *peer = crpc1->route->peer;

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
	homa_rpc_lock(crpc1);
	homa_peer_add_ack(crpc1);
	homa_rpc_unlock(crpc1);
	EXPECT_EQ(4, peer->num_acks);
	EXPECT_STREQ("server_port 99, client_id 101",
			unit_ack_string(&peer->acks[3]));

	/* Add another RPC to unacked (also fits). */
	homa_rpc_lock(crpc2);
	homa_peer_add_ack(crpc2);
	homa_rpc_unlock(crpc2);
	EXPECT_EQ(5, peer->num_acks);
	EXPECT_STREQ("server_port 99, client_id 102",
			unit_ack_string(&peer->acks[4]));

	/* Third RPC overflows, triggers ACK transmission. */
	unit_log_clear();
	mock_xmit_log_verbose = 1;
	homa_rpc_lock(crpc3);
	homa_peer_add_ack(crpc3);
	homa_rpc_unlock(crpc3);
	EXPECT_EQ(0, peer->num_acks);
	EXPECT_STREQ("xmit ACK from 0.0.0.0:32768, dport 99, id 103, acks [sp 99, id 90] [sp 99, id 91] [sp 99, id 92] [sp 99, id 101] [sp 99, id 102]",
			unit_log_get());
}

TEST_F(homa_peer, homa_peer_get_acks)
{
	struct homa_route *route = homa_route_get(&self->hsk, ip3333);
	struct homa_peer *peer = route->peer;
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
	homa_route_release(route);
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

/*--------------------------------------
 * Functions in homa_peer.h
 *--------------------------------------
 */

TEST_F(homa_peer, homa_peer_unlink__basics)
{
	struct homa_route *route, *route2;
	struct homa_route_key key;
	struct homa_peer *peer;

	/* Create 2 routes referencing the same peer (only one is
	 * in route_ht).
	 */
	route = homa_route_get(&self->hsk, ip3333);
	EXPECT_FALSE(IS_ERR(route));
	peer = route->peer;
	EXPECT_EQ(1, unit_count_peers(&self->homa));
	EXPECT_EQ(1, refcount_read(&peer->refs));

	homa_route_key_init(&key, &self->hsk, ip3333);
	route2 = homa_route_alloc(&self->hsk, &key);
	route2->peer = peer;
	refcount_inc(&peer->refs);
	EXPECT_EQ(1, unit_count_peers(&self->homa));
	EXPECT_EQ(2, refcount_read(&peer->refs));

	/* First unlink: peer refcount still > 0, so not removed from
	 * peer_ht.
	 */
	homa_peer_unlink(route2);
	EXPECT_EQ(1, unit_count_peers(&self->homa));
	EXPECT_EQ(1, refcount_read(&peer->refs));
	EXPECT_EQ(NULL, route2->peer);

	/* Second unlink: peer refcount becomes 0. */
	homa_peer_unlink(route);
	EXPECT_EQ(0, unit_count_peers(&self->homa));
	EXPECT_EQ(NULL, route->peer);

	/* Third unlink: peer already unlinked. */
	homa_peer_unlink(route);
	EXPECT_EQ(0, unit_count_peers(&self->homa));

	homa_route_free(&route2->rcu_head);
	homa_route_release(route);
}