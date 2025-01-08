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
	struct homa_sock hsk;
	struct homa_peertab peertab;
	struct in6_addr client_ip[1];
	struct in6_addr server_ip[1];
	int server_port;
};
FIXTURE_SETUP(homa_peer)
{
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, &self->homa, 0);
	homa_peertab_init(&self->peertab);
	self->client_ip[0] = unit_get_in_addr("196.168.0.1");
	self->server_ip[0] = unit_get_in_addr("1.2.3.4");
	ip1111[0] = unit_get_in_addr("1::1:1:1");
	ip2222[0] = unit_get_in_addr("2::2:2:2");
	ip3333[0] = unit_get_in_addr("3::3:3:3");
	self->server_port = 99;
}
FIXTURE_TEARDOWN(homa_peer)
{
	homa_peertab_destroy(&self->peertab);
	homa_destroy(&self->homa);
	unit_teardown();
}

static int dead_count(struct homa_peertab *peertab)
{
	struct list_head *pos;
	int count = 0;

	list_for_each(pos, &peertab->dead_dsts)
		count++;
	return count;
}

static void peer_spinlock_hook(char *id)
{
	if (strcmp(id, "spin_lock") != 0)
		return;
	mock_ns += 1000;
}

TEST_F(homa_peer, homa_peer_find__basics)
{
	struct homa_peer *peer, *peer2;

	peer = homa_peer_find(&self->peertab, ip1111, &self->hsk.inet);
	ASSERT_NE(NULL, peer);
	EXPECT_EQ_IP(*ip1111, peer->addr);
	EXPECT_EQ(INT_MAX, peer->unsched_cutoffs[HOMA_MAX_PRIORITIES-2]);
	EXPECT_EQ(0, peer->cutoff_version);

	peer2 = homa_peer_find(&self->peertab, ip1111, &self->hsk.inet);
	EXPECT_EQ(peer, peer2);

	peer2 = homa_peer_find(&self->peertab, ip2222, &self->hsk.inet);
	EXPECT_NE(peer, peer2);

	EXPECT_EQ(2, homa_metrics_per_cpu()->peer_new_entries);
}

static struct _test_data_homa_peer *test_data;
static struct homa_peer *conflicting_peer;
static int peer_lock_hook_invocations;
static void peer_lock_hook(char *id)
{
	if (strcmp(id, "spin_lock") != 0)
		return;
	if (peer_lock_hook_invocations > 0)
		return;
	peer_lock_hook_invocations++;
	/* Creates a peer with the same address as the one being created
	 * by the main test function below.
	 */
	conflicting_peer = homa_peer_find(&test_data->peertab, ip3333,
		&test_data->hsk.inet);
}

TEST_F(homa_peer, homa_peertab_init__vmalloc_failed)
{
	struct homa_peertab table;

	mock_vmalloc_errors = 1;
	EXPECT_EQ(ENOMEM, -homa_peertab_init(&table));

	/* Make sure destroy is safe after failed init. */
	homa_peertab_destroy(&table);
}

TEST_F(homa_peer, homa_peertab_gc_dsts)
{
	struct homa_peer *peer;

	peer = homa_peer_find(&self->peertab, ip3333, &self->hsk.inet);
	mock_ns = 0;
	homa_dst_refresh(&self->peertab, peer, &self->hsk);
	mock_ns = 50000000;
	homa_dst_refresh(&self->peertab, peer, &self->hsk);
	mock_ns = 90000000;
	homa_dst_refresh(&self->peertab, peer, &self->hsk);
	EXPECT_EQ(3, dead_count(&self->peertab));

	homa_peertab_gc_dsts(&self->peertab, 110000000);
	EXPECT_EQ(2, dead_count(&self->peertab));
	homa_peertab_gc_dsts(&self->peertab, ~0);
	EXPECT_EQ(0, dead_count(&self->peertab));
}

TEST_F(homa_peer, homa_peertab_get_peers__not_init)
{
	struct homa_peertab peertab;
	int num_peers = 45;

	memset(&peertab, 0, sizeof(peertab));
	EXPECT_EQ(NULL, homa_peertab_get_peers(&peertab, &num_peers));
	EXPECT_EQ(0, num_peers);
}
TEST_F(homa_peer, homa_peertab_get_peers__table_empty)
{
	int num_peers = 45;

	EXPECT_EQ(NULL, homa_peertab_get_peers(&self->peertab, &num_peers));
	EXPECT_EQ(0, num_peers);
}
TEST_F(homa_peer, homa_peertab_get_peers__kmalloc_fails)
{
	int num_peers = 45;

	mock_kmalloc_errors = 1;
	homa_peer_find(&self->peertab, ip3333, &self->hsk.inet);
	EXPECT_EQ(NULL, homa_peertab_get_peers(&self->peertab, &num_peers));
	EXPECT_EQ(0, num_peers);
}
TEST_F(homa_peer, homa_peertab_get_peers__one_peer)
{
	struct homa_peer **peers;
	struct homa_peer *peer;
	int num_peers = 45;

	peer = homa_peer_find(&self->peertab, ip3333, &self->hsk.inet);
	peers = homa_peertab_get_peers(&self->peertab, &num_peers);
	ASSERT_NE(NULL, peers);
	EXPECT_EQ(1, num_peers);
	EXPECT_EQ(peer, peers[0]);
	kfree(peers);
}
TEST_F(homa_peer, homa_peertab_get_peers__multiple_peers)
{
	struct homa_peer *peer1, *peer2, *peer3;
	struct homa_peer **peers;
	int num_peers = 45;

	peer1 = homa_peer_find(&self->peertab, ip1111, &self->hsk.inet);
	peer2 = homa_peer_find(&self->peertab, ip2222, &self->hsk.inet);
	peer3 = homa_peer_find(&self->peertab, ip3333, &self->hsk.inet);
	peers = homa_peertab_get_peers(&self->peertab, &num_peers);
	ASSERT_NE(NULL, peers);
	EXPECT_EQ(3, num_peers);
	EXPECT_TRUE((peers[0] == peer1) || (peers[1] == peer1)
			|| (peers[2] == peer1));
	EXPECT_TRUE((peers[0] == peer2) || (peers[1] == peer2)
			|| (peers[2] == peer2));
	EXPECT_TRUE((peers[0] == peer3) || (peers[1] == peer3)
			|| (peers[2] == peer3));
	kfree(peers);
}

TEST_F(homa_peer, homa_peer_find__conflicting_creates)
{
	struct homa_peer *peer;

	test_data = self;
	peer_lock_hook_invocations = 0;
	unit_hook_register(peer_lock_hook);
	peer = homa_peer_find(&self->peertab, ip3333, &self->hsk.inet);
	EXPECT_NE(NULL, conflicting_peer);
	EXPECT_EQ(conflicting_peer, peer);
}
TEST_F(homa_peer, homa_peer_find__kmalloc_error)
{
	struct homa_peer *peer;

	mock_kmalloc_errors = 1;
	peer = homa_peer_find(&self->peertab, ip3333, &self->hsk.inet);
	EXPECT_EQ(ENOMEM, -PTR_ERR(peer));

	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_kmalloc_errors);
}
TEST_F(homa_peer, homa_peer_find__route_error)
{
	struct homa_peer *peer;

	mock_route_errors = 1;
	peer = homa_peer_find(&self->peertab, ip3333, &self->hsk.inet);
	EXPECT_EQ(EHOSTUNREACH, -PTR_ERR(peer));

	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_route_errors);
}

TEST_F(homa_peer, homa_dst_refresh__basics)
{
	struct dst_entry *old_dst;
	struct homa_peer *peer;

	peer = homa_peer_find(&self->peertab, ip1111, &self->hsk.inet);
	ASSERT_NE(NULL, peer);
	EXPECT_EQ_IP(*ip1111, peer->addr);

	old_dst = homa_get_dst(peer, &self->hsk);
	homa_dst_refresh(self->homa.peers, peer, &self->hsk);
	EXPECT_NE(old_dst, peer->dst);
	EXPECT_EQ(1, dead_count(self->homa.peers));
}
TEST_F(homa_peer, homa_dst_refresh__malloc_error)
{
	struct dst_entry *old_dst;
	struct homa_peer *peer;

	peer = homa_peer_find(&self->peertab, ip1111, &self->hsk.inet);
	ASSERT_NE(NULL, peer);
	EXPECT_EQ_IP(*ip1111, peer->addr);

	old_dst = homa_get_dst(peer, &self->hsk);
	mock_kmalloc_errors = 1;
	homa_dst_refresh(self->homa.peers, peer, &self->hsk);
	EXPECT_EQ(old_dst, peer->dst);
	EXPECT_EQ(0, dead_count(self->homa.peers));
}
TEST_F(homa_peer, homa_dst_refresh__routing_error)
{
	struct dst_entry *old_dst;
	struct homa_peer *peer;

	peer = homa_peer_find(&self->peertab, ip1111, &self->hsk.inet);
	ASSERT_NE(NULL, peer);
	EXPECT_EQ_IP(*ip1111, peer->addr);

	old_dst = homa_get_dst(peer, &self->hsk);
	mock_route_errors = 1;
	homa_dst_refresh(self->homa.peers, peer, &self->hsk);
	EXPECT_EQ(old_dst, peer->dst);
	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_route_errors);
	EXPECT_EQ(0, dead_count(self->homa.peers));
}
TEST_F(homa_peer, homa_dst_refresh__free_old_dsts)
{
	struct homa_peer *peer;

	peer = homa_peer_find(&self->peertab, ip1111, &self->hsk.inet);
	ASSERT_NE(NULL, peer);
	EXPECT_EQ_IP(*ip1111, peer->addr);

	mock_ns = 0;
	homa_dst_refresh(self->homa.peers, peer, &self->hsk);
	homa_dst_refresh(self->homa.peers, peer, &self->hsk);
	EXPECT_EQ(2, dead_count(self->homa.peers));
	mock_ns = 500000000;
	homa_dst_refresh(self->homa.peers, peer, &self->hsk);
	EXPECT_EQ(1, dead_count(self->homa.peers));
}

TEST_F(homa_peer, homa_unsched_priority)
{
	struct homa_peer peer;

	homa_peer_set_cutoffs(&peer, INT_MAX, 0, 0, INT_MAX, 200, 100, 0, 0);

	EXPECT_EQ(5, homa_unsched_priority(&self->homa, &peer, 10));
	EXPECT_EQ(4, homa_unsched_priority(&self->homa, &peer, 200));
	EXPECT_EQ(3, homa_unsched_priority(&self->homa, &peer, 201));
}

TEST_F(homa_peer, homa_peer_get_dst_ipv4)
{
	struct dst_entry *dst;

	// Make sure the test uses IPv4.
	mock_ipv6 = false;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);

	struct homa_peer *peer = homa_peer_find(&self->peertab,
			&self->client_ip[0], &self->hsk.inet);
	ASSERT_NE(NULL, peer);

	dst = homa_peer_get_dst(peer, &self->hsk.inet);
	ASSERT_NE(NULL, dst);
	dst_release(dst);
	EXPECT_STREQ("196.168.0.1",
				homa_print_ipv4_addr(peer->flow.u.ip4.daddr));
}
TEST_F(homa_peer, homa_peer_get_dst_ipv6)
{
	struct dst_entry *dst;
	char buffer[30];
	__u32 addr;

	// Make sure the test uses IPv6.
	mock_ipv6 = true;
	homa_sock_destroy(&self->hsk);
	mock_sock_init(&self->hsk, &self->homa, 0);

	struct homa_peer *peer = homa_peer_find(&self->peertab, &ip1111[0],
			&self->hsk.inet);
	ASSERT_NE(NULL, peer);

	dst = homa_peer_get_dst(peer, &self->hsk.inet);
	ASSERT_NE(NULL, dst);
	dst_release(dst);
	addr = ntohl(peer->flow.u.ip4.daddr);
	snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", (addr >> 24) & 0xff,
			(addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff);
	EXPECT_STREQ("[1::1:1:1]",
			homa_print_ipv6_addr(&peer->flow.u.ip6.daddr));
}

TEST_F(homa_peer, homa_peer_lock_slow)
{
	struct homa_peer *peer = homa_peer_find(&self->peertab, ip3333,
			&self->hsk.inet);

	ASSERT_NE(NULL, peer);
	mock_ns = 10000;
	homa_peer_lock(peer);
	EXPECT_EQ(0, homa_metrics_per_cpu()->peer_ack_lock_misses);
	EXPECT_EQ(0, homa_metrics_per_cpu()->peer_ack_lock_miss_ns);
	homa_peer_unlock(peer);

	mock_trylock_errors = 1;
	unit_hook_register(peer_spinlock_hook);
	homa_peer_lock(peer);
	EXPECT_EQ(1, homa_metrics_per_cpu()->peer_ack_lock_misses);
	EXPECT_EQ(1000, homa_metrics_per_cpu()->peer_ack_lock_miss_ns);
	homa_peer_unlock(peer);
}

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
	struct homa_peer *peer = homa_peer_find(&self->peertab, ip3333,
			&self->hsk.inet);
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
}
