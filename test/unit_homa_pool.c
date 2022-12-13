/* Copyright (c) 2022 Stanford University
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
#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#define REGION_SIZE (1024*HOMA_BPAGE_SIZE)

static struct homa_pool *cur_pool;

FIXTURE(homa_pool) {
	struct homa homa;
	struct homa_sock hsk;
	void *buffer_region;
	struct in6_addr client_ip;
	struct in6_addr server_ip;
};
FIXTURE_SETUP(homa_pool)
{
	homa_init(&self->homa);
	mock_sock_init(&self->hsk, &self->homa, 0);
	self->buffer_region = (void *) 0x1000000;
	self->client_ip = unit_get_in_addr("196.168.0.1");
	self->server_ip = unit_get_in_addr("1.2.3.4");
	cur_pool = &self->hsk.buffer_pool;
	ASSERT_NE(NULL, self->buffer_region);
}
FIXTURE_TEARDOWN(homa_pool)
{
	cur_pool = NULL;
	homa_destroy(&self->homa);
	unit_teardown();
}

static void steal_bpages_hook(char *id)
{
	if (strcmp(id, "spin_lock") != 0)
		return;
	if (!cur_pool)
		return;
	switch (atomic_read(&cur_pool->next_scan)) {
	case 1:
		atomic_set(&cur_pool->descriptors[0].refs, 1);
		break;
	case 3:
		cur_pool->descriptors[2].owner = 0;
		cur_pool->descriptors[2].expiration = mock_cycles + 1;
	}
}

TEST_F(homa_pool, homa_pool_init__basics)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	EXPECT_EQ(100, pool->num_bpages);
	EXPECT_EQ(4, atomic_read(&pool->active_pages));
	EXPECT_EQ(0, atomic_read(&pool->next_scan));
	EXPECT_EQ(-1, pool->descriptors[98].owner);
}
TEST_F(homa_pool, homa_pool_init__region_not_page_aligned)
{
	EXPECT_EQ(EINVAL, -homa_pool_init(&self->hsk.buffer_pool, &self->homa,
			((char *) self->buffer_region) + 10,
			100*HOMA_BPAGE_SIZE));
}
TEST_F(homa_pool, homa_pool_init__region_too_small)
{
	EXPECT_EQ(EINVAL, -homa_pool_init(&self->hsk.buffer_pool, &self->homa,
			self->buffer_region, 3*HOMA_BPAGE_SIZE));
}
TEST_F(homa_pool, homa_pool_init__cant_allocate_descriptors)
{
	mock_kmalloc_errors = 1;
	EXPECT_EQ(ENOMEM, -homa_pool_init(&self->hsk.buffer_pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
}
TEST_F(homa_pool, homa_pool_init__cant_allocate_core_info)
{
	mock_kmalloc_errors = 2;
	EXPECT_EQ(ENOMEM, -homa_pool_init(&self->hsk.buffer_pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
}

TEST_F(homa_pool, homa_pool_destroy__idempotent)
{
	EXPECT_EQ(0, -homa_pool_init(&self->hsk.buffer_pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	homa_pool_destroy(&self->hsk.buffer_pool);
	homa_pool_destroy(&self->hsk.buffer_pool);
}

TEST_F(homa_pool, homa_pool_get_pages__basics)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	__u32 pages[10];
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 0));
	EXPECT_EQ(0, pages[0]);
	EXPECT_EQ(1, pages[1]);
	EXPECT_EQ(1, atomic_read(&pool->descriptors[1].refs));
	EXPECT_EQ(-1, pool->descriptors[1].owner);
	EXPECT_EQ(2, atomic_read(&pool->next_scan));
	EXPECT_EQ(2, atomic_read(&pool->free_bpages_found));
}
TEST_F(homa_pool, homa_pool_get_pages__no_buffer_space)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	__u32 pages[10];
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	atomic_set(&pool->active_pages, pool->num_bpages);
	atomic_set(&pool->next_scan, pool->num_bpages);
	atomic_set(&pool->free_bpages_found, 0);
	EXPECT_EQ(-1, homa_pool_get_pages(pool, 2, pages, 0));
}
TEST_F(homa_pool, homa_pool_get_pages__grow_active_pool)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	__u32 pages[10];
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	atomic_set(&pool->active_pages, 5);
	atomic_set(&pool->next_scan, 5);
	atomic_set(&pool->free_bpages_found, 1);
	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 0));
	EXPECT_EQ(5, pages[0]);
	EXPECT_EQ(6, pages[1]);
	EXPECT_EQ(7, atomic_read(&pool->active_pages));
}
TEST_F(homa_pool, homa_pool_get_pages__grow_fails_pool_max_size)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	__u32 pages[10];
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	pool->num_bpages = 5;
	atomic_set(&pool->active_pages, 5);
	atomic_set(&pool->next_scan, 5);
	atomic_set(&pool->free_bpages_found, 1);
	EXPECT_EQ(0, -homa_pool_get_pages(pool, 1, pages, 0));
	EXPECT_EQ(0, pages[0]);
	EXPECT_EQ(5, atomic_read(&pool->active_pages));
}
TEST_F(homa_pool, homa_pool_get_pages__shrink_active_pool)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	__u32 pages[10];
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	atomic_set(&pool->active_pages, 20);
	atomic_set(&pool->next_scan, 22);
	atomic_set(&pool->free_bpages_found, 11);
	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 0));
	EXPECT_EQ(0, pages[0]);
	EXPECT_EQ(1, pages[1]);
	EXPECT_EQ(18, atomic_read(&pool->active_pages));
}
TEST_F(homa_pool, homa_pool_get_pages__dont_shrink_below_MIN_ACTIVE)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	__u32 pages[10];
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	atomic_set(&pool->active_pages, 4);
	atomic_set(&pool->next_scan, 4);
	atomic_set(&pool->free_bpages_found, 3);
	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 0));
	EXPECT_EQ(0, pages[0]);
	EXPECT_EQ(1, pages[1]);
	EXPECT_EQ(4, atomic_read(&pool->active_pages));
}
TEST_F(homa_pool, homa_pool_get_pages__basic_wraparound)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	__u32 pages[10];
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	atomic_set(&pool->active_pages, 10);
	atomic_set(&pool->next_scan, 10);
	atomic_set(&pool->free_bpages_found, 3);
	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 0));
	EXPECT_EQ(0, pages[0]);
	EXPECT_EQ(1, pages[1]);
	EXPECT_EQ(10, atomic_read(&pool->active_pages));
	EXPECT_EQ(2, atomic_read(&pool->free_bpages_found));
}
TEST_F(homa_pool, homa_pool_get_pages__skip_unusable_bpages)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	__u32 pages[10];
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	atomic_set(&pool->active_pages, 10);
	atomic_set(&pool->descriptors[0].refs, 1);
	pool->descriptors[2].owner = 3;
	pool->descriptors[2].expiration = mock_cycles + 1;
        mock_trylock_errors = 2;
	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 0));
	EXPECT_EQ(1, pages[0]);
	EXPECT_EQ(4, pages[1]);
}
TEST_F(homa_pool, homa_pool_get_pages__state_changes_while_locking)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	__u32 pages[10];
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	unit_hook_register(steal_bpages_hook);
	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 0));
	EXPECT_EQ(1, pages[0]);
	EXPECT_EQ(3, pages[1]);
}
TEST_F(homa_pool, homa_pool_get_pages__steal_expired_page)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	__u32 pages[10];
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	pool->descriptors[0].owner = 5;
	mock_cycles = 5000;
	pool->descriptors[0].expiration = mock_cycles - 1;
	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 0));
	EXPECT_EQ(0, pages[0]);
	EXPECT_EQ(1, pages[1]);
	EXPECT_EQ(-1, pool->descriptors[0].owner);
}
TEST_F(homa_pool, homa_pool_get_pages__set_owner)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	__u32 pages[10];
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	self->homa.bpage_lease_cycles = 1000;
	mock_cycles = 5000;
	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 1));
	EXPECT_EQ(1, pool->descriptors[pages[0]].owner);
	EXPECT_EQ(mock_cycles + 1000,
			pool->descriptors[pages[1]].expiration);
}
TEST_F(homa_pool, homa_pool_get_pages__storage_exhausted_after_bpages_allocated)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	__u32 pages[10], i;
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	pool->num_bpages = 5;
	atomic_set(&pool->active_pages, pool->num_bpages);
	for (i = 0; i < pool->num_bpages; i++) {
		if ((i == 2) || (i == 3))
			continue;
		atomic_inc(&pool->descriptors[i].refs);
	}
	EXPECT_EQ(-1, homa_pool_get_pages(pool, 3, pages, 1));
	EXPECT_EQ(1, atomic_read(&pool->descriptors[0].refs));
	EXPECT_EQ(1, atomic_read(&pool->descriptors[1].refs));
	EXPECT_EQ(0, atomic_read(&pool->descriptors[2].refs));
	EXPECT_EQ(0, atomic_read(&pool->descriptors[3].refs));
	EXPECT_EQ(1, atomic_read(&pool->descriptors[4].refs));
	EXPECT_EQ(-1, pool->descriptors[2].owner);
}

TEST_F(homa_pool, homa_pool_allocate__basics)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, &self->client_ip, &self->server_ip,
			4000, 98, 1000,	150000);
	ASSERT_NE(NULL, crpc);

	EXPECT_EQ(0, homa_pool_allocate(crpc));
	EXPECT_EQ(3, crpc->msgin.num_bpages);
	EXPECT_EQ(0, crpc->msgin.bpage_offsets[0]);
	EXPECT_EQ(-1, pool->descriptors[0].owner);
	EXPECT_EQ(2*HOMA_BPAGE_SIZE, crpc->msgin.bpage_offsets[2]);
	EXPECT_EQ(2, pool->cores[cpu_number].page_hint);
	EXPECT_EQ(150000 - 2*HOMA_BPAGE_SIZE,
			pool->cores[cpu_number].allocated);
}
TEST_F(homa_pool, homa_pool_allocate__out_of_buffer_space)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 5*HOMA_BPAGE_SIZE));
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, &self->client_ip, &self->server_ip,
			4000, 98, 1000,	150000);
	ASSERT_NE(NULL, crpc);
	atomic_set(&pool->descriptors[1].refs, 1);
	atomic_set(&pool->descriptors[2].refs, 1);
	atomic_set(&pool->descriptors[3].refs, 1);
	atomic_set(&pool->descriptors[4].refs, 1);

	EXPECT_EQ(1, -homa_pool_allocate(crpc));
	EXPECT_EQ(0, crpc->msgin.num_bpages);
}
TEST_F(homa_pool, homa_pool_allocate__owned_page_locked)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	atomic_set(&pool->next_scan, 2);
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, &self->client_ip, &self->server_ip,
			4000, 98, 1000, 2000);
	ASSERT_NE(NULL, crpc);

	EXPECT_EQ(0, homa_pool_allocate(crpc));
	EXPECT_EQ(2, pool->cores[cpu_number].page_hint);
	crpc->msgin.num_bpages = 0;
        mock_trylock_errors = 1;
	EXPECT_EQ(0, homa_pool_allocate(crpc));
	EXPECT_EQ(1, crpc->msgin.num_bpages);
	EXPECT_EQ(3*HOMA_BPAGE_SIZE, crpc->msgin.bpage_offsets[0]);
	EXPECT_EQ(3, pool->cores[cpu_number].page_hint);
	EXPECT_EQ(2000, pool->cores[cpu_number].allocated);
	EXPECT_EQ(1, pool->descriptors[2].owner);
	EXPECT_EQ(1, pool->descriptors[3].owner);
}
TEST_F(homa_pool, homa_pool_allocate__reuse_owned_page)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	atomic_set(&pool->next_scan, 2);
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, &self->client_ip, &self->server_ip,
			4000, 98, 1000, 2000);
	ASSERT_NE(NULL, crpc1);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, &self->client_ip, &self->server_ip,
			4000, 100, 1000, 3000);
	ASSERT_NE(NULL, crpc2);

	EXPECT_EQ(0, homa_pool_allocate(crpc1));
	EXPECT_EQ(0, homa_pool_allocate(crpc2));
	EXPECT_EQ(1, crpc1->msgin.num_bpages);
	EXPECT_EQ(1, crpc2->msgin.num_bpages);
	EXPECT_EQ(2, atomic_read(&pool->descriptors[2].refs));
	EXPECT_EQ(2, pool->cores[cpu_number].page_hint);
	EXPECT_EQ(5000, pool->cores[cpu_number].allocated);
}
TEST_F(homa_pool, homa_pool_allocate__cant_allocate_partial_bpage)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	pool->num_bpages = 5;
	atomic_set(&pool->active_pages, 5);
	atomic_set(&pool->next_scan, 2);
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, &self->client_ip, &self->server_ip,
			4000, 98, 1000, 5*HOMA_BPAGE_SIZE + 100);
	ASSERT_NE(NULL, crpc);

	EXPECT_EQ(-1, homa_pool_allocate(crpc));
	EXPECT_EQ(0, crpc->msgin.num_bpages);
	EXPECT_EQ(0, atomic_read(&pool->descriptors[0].refs));
	EXPECT_EQ(0, atomic_read(&pool->descriptors[1].refs));
	EXPECT_EQ(0, atomic_read(&pool->descriptors[4].refs));
}
TEST_F(homa_pool, homa_pool_allocate__not_enough_space_in_owned_page)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	atomic_set(&pool->next_scan, 2);
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, &self->client_ip, &self->server_ip,
			4000, 98, 1000, 2000);
	ASSERT_NE(NULL, crpc);

	EXPECT_EQ(0, homa_pool_allocate(crpc));
	EXPECT_EQ(2, pool->cores[cpu_number].page_hint);
	crpc->msgin.num_bpages = 0;
	pool->cores[cpu_number].allocated = HOMA_BPAGE_SIZE-1900;
	EXPECT_EQ(0, homa_pool_allocate(crpc));
	EXPECT_EQ(1, crpc->msgin.num_bpages);
	EXPECT_EQ(3*HOMA_BPAGE_SIZE, crpc->msgin.bpage_offsets[0]);
	EXPECT_EQ(3, pool->cores[cpu_number].page_hint);
	EXPECT_EQ(2000, pool->cores[cpu_number].allocated);
	EXPECT_EQ(-1, pool->descriptors[2].owner);
	EXPECT_EQ(1, pool->descriptors[3].owner);
}
TEST_F(homa_pool, homa_pool_allocate__page_wrap_around)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, &self->client_ip, &self->server_ip,
			4000, 98, 1000, 2000);
	ASSERT_NE(NULL, crpc);
	pool->cores[cpu_number].page_hint = 2;
	pool->cores[cpu_number].allocated = HOMA_BPAGE_SIZE-1900;
	pool->descriptors[2].owner = cpu_number;

	EXPECT_EQ(0, homa_pool_allocate(crpc));
	EXPECT_EQ(2, pool->cores[cpu_number].page_hint);
	EXPECT_EQ(1, crpc->msgin.num_bpages);
	EXPECT_EQ(2*HOMA_BPAGE_SIZE, crpc->msgin.bpage_offsets[0]);
	EXPECT_EQ(2000, pool->cores[cpu_number].allocated);
	EXPECT_EQ(cpu_number, pool->descriptors[2].owner);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.bpage_reuses);
}

TEST_F(homa_pool, homa_pool_get_buffer__basics)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	int available;
	void *buffer;

	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, &self->client_ip, &self->server_ip,
			4000, 98, 1000,	150000);
	ASSERT_NE(NULL, crpc);
	buffer = homa_pool_get_buffer(crpc, HOMA_BPAGE_SIZE + 1000, &available);
	EXPECT_EQ(HOMA_BPAGE_SIZE - 1000, available);
	EXPECT_EQ((void *) (pool->region + HOMA_BPAGE_SIZE + 1000), buffer);
	buffer = homa_pool_get_buffer(crpc, 2*HOMA_BPAGE_SIZE + 100, &available);
	EXPECT_EQ((150000 & (HOMA_BPAGE_SIZE-1)) - 100, available);
	EXPECT_EQ((void *) (pool->region + 2*HOMA_BPAGE_SIZE + 100), buffer);
}
TEST_F(homa_pool, homa_pool_get_buffer__cant_allocate_buffers)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, &self->client_ip, &self->server_ip,
			4000, 98, 1000,	150000);
	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(-1, homa_pool_allocate(crpc));
	EXPECT_EQ(0, crpc->msgin.num_bpages);
}

TEST_F(homa_pool, homa_pool_release_buffers)
{
	struct homa_pool *pool = &self->hsk.buffer_pool;
	char *saved_region;

	EXPECT_EQ(0, -homa_pool_init(pool, &self->homa,
			self->buffer_region, 100*HOMA_BPAGE_SIZE));
	struct homa_rpc *crpc1 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, &self->client_ip, &self->server_ip,
			4000, 98, 1000,	150000);
	ASSERT_NE(NULL, crpc1);
	struct homa_rpc *crpc2 = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, &self->client_ip, &self->server_ip,
			4000, 98, 1000,	2000);
	ASSERT_NE(NULL, crpc2);

	EXPECT_EQ(0, homa_pool_allocate(crpc1));
	EXPECT_EQ(0, homa_pool_allocate(crpc2));
	EXPECT_EQ(1, atomic_read(&pool->descriptors[0].refs));
	EXPECT_EQ(1, atomic_read(&pool->descriptors[1].refs));
	EXPECT_EQ(2, atomic_read(&pool->descriptors[2].refs));

	homa_pool_release_buffers(pool, crpc1->msgin.num_bpages,
			crpc1->msgin.bpage_offsets);
	EXPECT_EQ(0, atomic_read(&pool->descriptors[0].refs));
	EXPECT_EQ(0, atomic_read(&pool->descriptors[1].refs));
	EXPECT_EQ(1, atomic_read(&pool->descriptors[2].refs));

	/* Ignore requests if pool not initialized. */
	saved_region = pool->region;
	pool->region = NULL;
	homa_pool_release_buffers(pool, crpc1->msgin.num_bpages,
			crpc1->msgin.bpage_offsets);
	EXPECT_EQ(0, atomic_read(&pool->descriptors[0].refs));
	pool->region = saved_region;
}