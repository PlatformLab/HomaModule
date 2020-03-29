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

FIXTURE(homa_peertab) {
	struct homa homa;
	struct homa_sock hsk;
	struct homa_peertab peertab;
};
FIXTURE_SETUP(homa_peertab)
{
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, &self->homa, 0, 0);
	homa_peertab_init(&self->peertab);
}
FIXTURE_TEARDOWN(homa_peertab)
{
	homa_peertab_destroy(&self->peertab);
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_peertab, homa_peer_find__basics)
{
	struct homa_peer *peer, *peer2;
	
	peer = homa_peer_find(&self->peertab, 11111, &self->hsk.inet);
	ASSERT_NE(NULL, peer);
	EXPECT_EQ(11111, peer->addr);
	EXPECT_EQ(INT_MAX, peer->unsched_cutoffs[HOMA_MAX_PRIORITIES-2]);
	EXPECT_EQ(0, peer->cutoff_version);
	
	peer2 = homa_peer_find(&self->peertab, 11111, &self->hsk.inet);
	EXPECT_EQ(peer, peer2);
	
	peer2 = homa_peer_find(&self->peertab, 22222, &self->hsk.inet);
	EXPECT_NE(peer, peer2);
	
	EXPECT_EQ(2, homa_cores[cpu_number]->metrics.peer_new_entries);
}

static struct _test_data_homa_peertab *test_data;
static struct homa_peer *conflicting_peer = NULL;
static void peer_lock_hook(void) {
	mock_spin_lock_hook = NULL;
	/* Creates a peer with the same address as the one being created
	 * by the main test function below. */
	conflicting_peer = homa_peer_find(&test_data->peertab, 444,
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

TEST_F(homa_peertab, homa_peer_find__conflicting_creates)
{
	struct homa_peer *peer;
	
	test_data = self;
	mock_spin_lock_hook = peer_lock_hook;
	peer = homa_peer_find(&self->peertab, 444, &self->hsk.inet);
	EXPECT_NE(NULL, conflicting_peer);
	EXPECT_EQ(conflicting_peer, peer);
}

TEST_F(homa_peertab, homa_peer_find__kmalloc_error)
{
	struct homa_peer *peer;
	
	mock_kmalloc_errors = 1;
	peer = homa_peer_find(&self->peertab, 444, &self->hsk.inet);
	EXPECT_EQ(ENOMEM, -PTR_ERR(peer));
	
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.peer_kmalloc_errors);
}

TEST_F(homa_peertab, homa_peer_find__route_error)
{
	struct homa_peer *peer;
	
	mock_route_errors = 1;
	peer = homa_peer_find(&self->peertab, 444, &self->hsk.inet);
	EXPECT_EQ(EHOSTUNREACH, -PTR_ERR(peer));
	
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.peer_route_errors);
}

TEST_F(homa_peertab, homa_unsched_priority)
{
	struct homa_peer peer;
	homa_peer_set_cutoffs(&peer, INT_MAX, 0, 0, INT_MAX, 200, 100, 0, 0);
	
	EXPECT_EQ(5, homa_unsched_priority(&self->homa, &peer, 10));
	EXPECT_EQ(4, homa_unsched_priority(&self->homa, &peer, 200));
	EXPECT_EQ(3, homa_unsched_priority(&self->homa, &peer, 201));
}