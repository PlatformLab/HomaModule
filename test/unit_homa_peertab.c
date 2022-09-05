/* Copyright (c) 2019-2022 Stanford University
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

struct in_addr ip1111[1];
struct in_addr ip2222[1];
struct in_addr ip3333[1];

FIXTURE(homa_peertab) {
	struct homa homa;
	struct homa_sock hsk;
	struct homa_peertab peertab;
	struct in_addr client_ip[1];
	struct in_addr server_ip[1];
	int server_port;
};
FIXTURE_SETUP(homa_peertab)
{
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, &self->homa, 0);
	homa_peertab_init(&self->peertab);
	self->client_ip[0] = unit_get_in_addr("196.168.0.1");
	self->server_ip[0] = unit_get_in_addr("1.2.3.4");
	ip1111[0] = unit_get_in_addr("1.1.1.1");
	ip2222[0] = unit_get_in_addr("2.2.2.2");
	ip3333[0] = unit_get_in_addr("3.3.3.3");
	self->server_port = 99;
}
FIXTURE_TEARDOWN(homa_peertab)
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

static void peer_spinlock_hook(void)
{
	mock_cycles += 1000;
}

TEST_F(homa_peertab, homa_peer_find__basics)
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

	EXPECT_EQ(2, homa_cores[cpu_number]->metrics.peer_new_entries);
}

static struct _test_data_homa_peertab *test_data;
static struct homa_peer *conflicting_peer = NULL;
static void peer_lock_hook(void) {
	mock_spin_lock_hook = NULL;
	/* Creates a peer with the same address as the one being created
	 * by the main test function below. */
	conflicting_peer = homa_peer_find(&test_data->peertab, ip3333,
		&test_data->hsk.inet);
}

TEST_F(homa_peertab, homa_peertab_init__vmalloc_failed)
{
	struct homa_peertab table;
	mock_vmalloc_errors = 1;
	EXPECT_EQ(ENOMEM, -homa_peertab_init(&table));

	/* Make sure destroy is safe after failed init. */
	homa_peertab_destroy(&table);
}

TEST_F(homa_peertab, homa_peertab_gc_dsts)
{
	struct homa_peer *peer;
	peer = homa_peer_find(&self->peertab, ip3333, &self->hsk.inet);
	mock_cycles = 0;
	homa_dst_refresh(&self->peertab, peer, &self->hsk);
	mock_cycles = 50000000;
	homa_dst_refresh(&self->peertab, peer, &self->hsk);
	mock_cycles = 100000000;
	homa_dst_refresh(&self->peertab, peer, &self->hsk);
	EXPECT_EQ(3, dead_count(&self->peertab));

	homa_peertab_gc_dsts(&self->peertab, 150000000);
	EXPECT_EQ(2, dead_count(&self->peertab));
	homa_peertab_gc_dsts(&self->peertab, ~0);
	EXPECT_EQ(0, dead_count(&self->peertab));
}

TEST_F(homa_peertab, homa_peer_find__conflicting_creates)
{
	struct homa_peer *peer;

	test_data = self;
	mock_spin_lock_hook = peer_lock_hook;
	peer = homa_peer_find(&self->peertab, ip3333, &self->hsk.inet);
	EXPECT_NE(NULL, conflicting_peer);
	EXPECT_EQ(conflicting_peer, peer);
}
TEST_F(homa_peertab, homa_peer_find__kmalloc_error)
{
	struct homa_peer *peer;

	mock_kmalloc_errors = 1;
	peer = homa_peer_find(&self->peertab, ip3333, &self->hsk.inet);
	EXPECT_EQ(ENOMEM, -PTR_ERR(peer));

	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.peer_kmalloc_errors);
}
TEST_F(homa_peertab, homa_peer_find__route_error)
{
	struct homa_peer *peer;

	mock_route_errors = 1;
	peer = homa_peer_find(&self->peertab, ip3333, &self->hsk.inet);
	EXPECT_EQ(EHOSTUNREACH, -PTR_ERR(peer));

	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.peer_route_errors);
}

TEST_F(homa_peertab, homa_dst_refresh__basics)
{
	struct homa_peer *peer;
	struct dst_entry *old_dst;
	peer = homa_peer_find(&self->peertab, ip1111, &self->hsk.inet);
	ASSERT_NE(NULL, peer);
	EXPECT_EQ_IP(*ip1111, peer->addr);

	old_dst = homa_get_dst(peer, &self->hsk);
	homa_dst_refresh(&self->homa.peers, peer, &self->hsk);
	EXPECT_NE(old_dst, peer->dst);
	EXPECT_EQ(1, dead_count(&self->homa.peers));
}
TEST_F(homa_peertab, homa_dst_refresh__routing_error)
{
	struct homa_peer *peer;
	struct dst_entry *old_dst;
	peer = homa_peer_find(&self->peertab, ip1111, &self->hsk.inet);
	ASSERT_NE(NULL, peer);
	EXPECT_EQ_IP(*ip1111, peer->addr);

	old_dst = homa_get_dst(peer, &self->hsk);
	mock_route_errors = 1;
	homa_dst_refresh(&self->homa.peers, peer, &self->hsk);
	EXPECT_EQ(old_dst, peer->dst);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.peer_route_errors);
	EXPECT_EQ(0, dead_count(&self->homa.peers));
}
TEST_F(homa_peertab, homa_dst_refresh__malloc_error)
{
	struct homa_peer *peer;
	struct dst_entry *old_dst;
	peer = homa_peer_find(&self->peertab, ip1111, &self->hsk.inet);
	ASSERT_NE(NULL, peer);
	EXPECT_EQ_IP(*ip1111, peer->addr);

	old_dst = homa_get_dst(peer, &self->hsk);
	mock_kmalloc_errors = 1;
	homa_dst_refresh(&self->homa.peers, peer, &self->hsk);
	EXPECT_NE(old_dst, peer->dst);
	EXPECT_EQ(0, dead_count(&self->homa.peers));
}
TEST_F(homa_peertab, homa_dst_refresh__free_old_dsts)
{
	struct homa_peer *peer;
	peer = homa_peer_find(&self->peertab, ip1111, &self->hsk.inet);
	ASSERT_NE(NULL, peer);
	EXPECT_EQ_IP(*ip1111, peer->addr);

	mock_cycles = 0;
	homa_dst_refresh(&self->homa.peers, peer, &self->hsk);
	homa_dst_refresh(&self->homa.peers, peer, &self->hsk);
	EXPECT_EQ(2, dead_count(&self->homa.peers));
	mock_cycles = 500000000;
	homa_dst_refresh(&self->homa.peers, peer, &self->hsk);
	EXPECT_EQ(1, dead_count(&self->homa.peers));
}

TEST_F(homa_peertab, homa_unsched_priority)
{
	struct homa_peer peer;
	homa_peer_set_cutoffs(&peer, INT_MAX, 0, 0, INT_MAX, 200, 100, 0, 0);

	EXPECT_EQ(5, homa_unsched_priority(&self->homa, &peer, 10));
	EXPECT_EQ(4, homa_unsched_priority(&self->homa, &peer, 200));
	EXPECT_EQ(3, homa_unsched_priority(&self->homa, &peer, 201));
}

TEST_F(homa_peertab, homa_peer_lock_slow)
{
	mock_cycles = 10000;
	struct homa_peer *peer = homa_peer_find(&self->peertab, ip3333,
			&self->hsk.inet);
	ASSERT_NE(NULL, peer);

	homa_peer_lock(peer);
	EXPECT_EQ(0, homa_cores[cpu_number]->metrics.peer_lock_misses);
	EXPECT_EQ(0, homa_cores[cpu_number]->metrics.peer_lock_miss_cycles);
	homa_peer_unlock(peer);

	mock_trylock_errors = 1;
	mock_spin_lock_hook = peer_spinlock_hook;
	homa_peer_lock(peer);
	mock_spin_lock_hook = peer_spinlock_hook;
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.peer_lock_misses);
	EXPECT_EQ(1000, homa_cores[cpu_number]->metrics.peer_lock_miss_cycles);
	homa_peer_unlock(peer);
}

TEST_F(homa_peertab, homa_peer_add_ack)
{
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk, RPC_OUTGOING,
		self->client_ip, self->server_ip, self->server_port,
		101, 100, 100);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk, RPC_OUTGOING,
		self->client_ip, self->server_ip, self->server_port,
		102, 100, 100);
	struct homa_rpc *crpc3 = unit_client_rpc(&self->hsk, RPC_OUTGOING,
		self->client_ip, self->server_ip, self->server_port,
		103, 100, 100);
	struct homa_peer *peer = crpc1->peer;
	EXPECT_EQ(0, peer->num_acks);

	/* Initialize 3 acks in the peer. */
	peer->acks[0] = (struct homa_ack) {
			.client_port = htons(1000),
			.server_port = htons(self->server_port),
			.client_id = cpu_to_be64(90)};
	peer->acks[1] = (struct homa_ack) {
			.client_port = htons(1001),
			.server_port = htons(self->server_port),
			.client_id = cpu_to_be64(91)};
	peer->acks[2] = (struct homa_ack) {
			.client_port = htons(1002),
			.server_port = htons(self->server_port),
			.client_id = cpu_to_be64(92)};
	peer->num_acks = 3;

	/* Add one RPC to unacked (fits). */
	homa_peer_add_ack(crpc1);
	EXPECT_EQ(4, peer->num_acks);
	EXPECT_STREQ("client_port 32768, server_port 99, client_id 101",
			unit_ack_string(&peer->acks[3]));

	/* Add another RPC to unacked (also fits). */
	homa_peer_add_ack(crpc2);
	EXPECT_EQ(5, peer->num_acks);
	EXPECT_STREQ("client_port 32768, server_port 99, client_id 102",
			unit_ack_string(&peer->acks[4]));

	/* Third RPC overflows, triggers ACK transmission. */
	unit_log_clear();
	mock_xmit_log_verbose = 1;
	homa_peer_add_ack(crpc3);
	EXPECT_EQ(0, peer->num_acks);
	EXPECT_STREQ("xmit ACK from 0.0.0.0:32768, dport 99, id 103, acks "
			"[cp 1000, sp 99, id 90] [cp 1001, sp 99, id 91] "
			"[cp 1002, sp 99, id 92] [cp 32768, sp 99, id 101] "
			"[cp 32768, sp 99, id 102]",
			unit_log_get());
}

TEST_F(homa_peertab, homa_peer_get_acks)
{
	struct homa_peer *peer = homa_peer_find(&self->peertab, ip3333,
			&self->hsk.inet);
	ASSERT_NE(NULL, peer);
	EXPECT_EQ(0, peer->num_acks);

	// First call: nothing available.
	struct homa_ack acks[2];
	EXPECT_EQ(0, homa_peer_get_acks(peer, 2, acks));

	// Second call: retrieve 2 out of 3.
	peer->acks[0] = (struct homa_ack) {
			.client_port = htons(4000),
			.server_port = htons(5000),
			.client_id = cpu_to_be64(100)};
	peer->acks[1] = (struct homa_ack) {
			.client_port = htons(4001),
			.server_port = htons(5001),
			.client_id = cpu_to_be64(101)};
	peer->acks[2] = (struct homa_ack) {
			.client_port = htons(4002),
			.server_port = htons(5002),
			.client_id = cpu_to_be64(102)};
	peer->num_acks = 3;
	EXPECT_EQ(2, homa_peer_get_acks(peer, 2, acks));
	EXPECT_STREQ("client_port 4001, server_port 5001, client_id 101",
			unit_ack_string(&acks[0]));
	EXPECT_STREQ("client_port 4002, server_port 5002, client_id 102",
			unit_ack_string(&acks[1]));
	EXPECT_EQ(1, peer->num_acks);

	// Third call: retrieve final id.
	EXPECT_EQ(1, homa_peer_get_acks(peer, 2, acks));
	EXPECT_STREQ("client_port 4000, server_port 5000, client_id 100",
			unit_ack_string(&acks[0]));
}
