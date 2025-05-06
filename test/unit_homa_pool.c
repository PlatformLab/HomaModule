// SPDX-License-Identifier: BSD-2-Clause

#include "homa_impl.h"
#include "homa_grant.h"
#include "homa_pool.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

static struct homa_pool *cur_pool;

FIXTURE(homa_pool) {
	struct homa homa;
	struct homa_sock hsk;
	struct in6_addr client_ip;
	struct in6_addr server_ip;
};
FIXTURE_SETUP(homa_pool)
{
	homa_init(&self->homa, &mock_net);
	mock_set_homa(&self->homa);
#ifndef __STRIP__ /* See strip.py */
	self->homa.unsched_bytes = 10000;
	self->homa.grant->window = 10000;
#endif /* See strip.py */
	mock_sock_init(&self->hsk, &self->homa, 0);
	self->client_ip = unit_get_in_addr("196.168.0.1");
	self->server_ip = unit_get_in_addr("1.2.3.4");
	cur_pool = self->hsk.buffer_pool;
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
	switch (cur_pool->cores[1].next_candidate) {
	case 1:
		atomic_set(&cur_pool->descriptors[0].refs, 2);
		break;
	case 2:
		atomic_set(&cur_pool->descriptors[1].refs, 1);
		cur_pool->descriptors[1].owner = 3;
		cur_pool->descriptors[1].expiration = mock_ns + 1;
	case 3:
		atomic_set(&cur_pool->descriptors[2].refs, 1);
		cur_pool->descriptors[2].owner = 3;
		cur_pool->descriptors[2].expiration = mock_ns - 1;
	case 4:
		atomic_set(&cur_pool->descriptors[3].refs, 1);
	}
}
static void change_owner_hook(char *id)
{
	if (strcmp(id, "spin_lock") != 0)
		return;
	if (!cur_pool)
		return;
	cur_pool->descriptors[cur_pool->cores[smp_processor_id()]
			.page_hint].owner = -1;
}

TEST_F(homa_pool, set_bpages_needed)
{
	struct homa_pool *pool = self->hsk.buffer_pool;

	atomic_set(&pool->free_bpages, 0);
	unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2*HOMA_BPAGE_SIZE+1);
	ASSERT_FALSE(list_empty(&self->hsk.waiting_for_bufs));
	EXPECT_EQ(3, pool->bpages_needed);
	unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2*HOMA_BPAGE_SIZE);
	EXPECT_EQ(2, pool->bpages_needed);
}

TEST_F(homa_pool, homa_pool_alloc)
{
	struct homa_pool *pool;

	/* Success */
	pool = homa_pool_alloc(&self->hsk);
	EXPECT_FALSE(IS_ERR(pool));
	EXPECT_EQ(pool->hsk, &self->hsk);
	homa_pool_free(pool);

	/* Can't allocate memory. */
	mock_kmalloc_errors = 1;
	pool = homa_pool_alloc(&self->hsk);
	EXPECT_TRUE(IS_ERR(pool));
	EXPECT_EQ(ENOMEM, -PTR_ERR(pool));
}

TEST_F(homa_pool, homa_pool_set_region__basics)
{
	struct homa_pool *pool = homa_pool_alloc(&self->hsk);

	EXPECT_EQ(0, -homa_pool_set_region(pool, (void *) 0x100000,
			78*HOMA_BPAGE_SIZE));
	EXPECT_EQ(78, pool->num_bpages);
	EXPECT_EQ(-1, pool->descriptors[69].owner);
	homa_pool_free(pool);
}
TEST_F(homa_pool, homa_pool_set_region__region_not_page_aligned)
{
	struct homa_pool *pool = homa_pool_alloc(&self->hsk);

	EXPECT_EQ(EINVAL, -homa_pool_set_region(pool,
			((char *) 0x1000000) + 10,
			100*HOMA_BPAGE_SIZE));
	homa_pool_free(pool);
}
TEST_F(homa_pool, homa_pool_set_region__region_too_small)
{
	struct homa_pool *pool = homa_pool_alloc(&self->hsk);

	EXPECT_EQ(EINVAL, -homa_pool_set_region(pool, (void *) 0x1000000,
			HOMA_BPAGE_SIZE));
	homa_pool_free(pool);
}
TEST_F(homa_pool, homa_pool_set_region__cant_allocate_descriptors)
{
	struct homa_pool *pool = homa_pool_alloc(&self->hsk);

	mock_kmalloc_errors = 1;
	EXPECT_EQ(ENOMEM, -homa_pool_set_region(pool, (void *) 0x100000,
			100*HOMA_BPAGE_SIZE));
	homa_pool_free(pool);
}
TEST_F(homa_pool, homa_pool_set_region__cant_allocate_core_info)
{
	struct homa_pool *pool = homa_pool_alloc(&self->hsk);

	mock_kmalloc_errors = 2;
	EXPECT_EQ(ENOMEM, -homa_pool_set_region(pool, (void *) 0x100000,
			100*HOMA_BPAGE_SIZE));
	homa_pool_free(pool);
}

TEST_F(homa_pool, homa_pool_get_rcvbuf)
{
	struct homa_pool *pool = homa_pool_alloc(&self->hsk);
	struct homa_rcvbuf_args args;

	EXPECT_EQ(0, -homa_pool_set_region(pool, (void *)0x40000,
		  10*HOMA_BPAGE_SIZE + 1000));
	homa_pool_get_rcvbuf(pool, &args);
	EXPECT_EQ(0x40000, args.start);
	EXPECT_EQ(10*HOMA_BPAGE_SIZE, args.length);
	homa_pool_free(pool);
}

TEST_F(homa_pool, homa_pool_get_pages__basics)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	u32 pages[10];

	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 0));
	EXPECT_EQ(0, pages[0]);
	EXPECT_EQ(1, pages[1]);
	EXPECT_EQ(1, atomic_read(&pool->descriptors[1].refs));
	EXPECT_EQ(-1, pool->descriptors[1].owner);
	EXPECT_EQ(2, pool->cores[smp_processor_id()].next_candidate);
	EXPECT_EQ(98, atomic_read(&pool->free_bpages));
}
TEST_F(homa_pool, homa_pool_get_pages__not_enough_space)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	u32 pages[10];

	atomic_set(&pool->free_bpages, 1);
	EXPECT_EQ(-1, homa_pool_get_pages(pool, 2, pages, 0));
	atomic_set(&pool->free_bpages, 2);
	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 0));
}
TEST_F(homa_pool, homa_pool_get_pages__set_limit)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	u32 pages[10];

	atomic_set(&pool->free_bpages, 62);
	pool->cores[smp_processor_id()].next_candidate = 49;
	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 0));
	EXPECT_EQ(49, pages[0]);
	EXPECT_EQ(0, pages[1]);
}
TEST_F(homa_pool, homa_pool_get_pages__set_limit_with_MIN_EXTRA)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	u32 pages[10];

	atomic_set(&pool->free_bpages, 92);
	pool->cores[smp_processor_id()].next_candidate = 13;
	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 0));
	EXPECT_EQ(13, pages[0]);
	EXPECT_EQ(0, pages[1]);
}
TEST_F(homa_pool, homa_pool_get_pages__skip_unusable_bpages)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	u32 pages[10];

	mock_ns = 1000;
	atomic_set(&pool->descriptors[0].refs, 2);
	atomic_set(&pool->descriptors[1].refs, 1);
	pool->descriptors[1].owner = 3;
	pool->descriptors[1].expiration = mock_ns + 1;
	atomic_set(&pool->descriptors[2].refs, 1);
	pool->descriptors[2].owner = 3;
	pool->descriptors[2].expiration = mock_ns - 1;
	atomic_set(&pool->descriptors[3].refs, 1);
	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 0));
	EXPECT_EQ(2, pages[0]);
	EXPECT_EQ(4, pages[1]);
}
TEST_F(homa_pool, homa_pool_get_pages__cant_lock_pages)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	u32 pages[10];

	mock_ns = 1000;
	mock_trylock_errors = 3;
	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 0));
	EXPECT_EQ(2, pages[0]);
	EXPECT_EQ(3, pages[1]);
}
TEST_F(homa_pool, homa_pool_get_pages__state_changes_while_locking)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	u32 pages[10];

	mock_ns = 1000;
	unit_hook_register(steal_bpages_hook);
	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 0));
	EXPECT_EQ(2, pages[0]);
	EXPECT_EQ(4, pages[1]);
}
TEST_F(homa_pool, homa_pool_get_pages__steal_expired_page)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	u32 pages[10];

	pool->descriptors[0].owner = 5;
	mock_ns = 5000;
	pool->descriptors[0].expiration = mock_ns - 1;
	atomic_set(&pool->free_bpages, 20);
	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 0));
	EXPECT_EQ(0, pages[0]);
	EXPECT_EQ(1, pages[1]);
	EXPECT_EQ(-1, pool->descriptors[0].owner);
	EXPECT_EQ(19, atomic_read(&pool->free_bpages));
}
TEST_F(homa_pool, homa_pool_get_pages__set_owner)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	u32 pages[10];

	self->homa.bpage_lease_usecs = 1;
	mock_ns = 5000;
	EXPECT_EQ(0, homa_pool_get_pages(pool, 2, pages, 1));
	EXPECT_EQ(1, pool->descriptors[pages[0]].owner);
	EXPECT_EQ(mock_ns + 1000,
			pool->descriptors[pages[1]].expiration);
	EXPECT_EQ(2, atomic_read(&pool->descriptors[1].refs));
}

TEST_F(homa_pool, homa_pool_alloc_msg__basics)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, &self->client_ip, &self->server_ip,
			4000, 98, 1000,	150000);
	struct homa_pool *pool = self->hsk.buffer_pool;

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(3, crpc->msgin.num_bpages);
	EXPECT_EQ(0, crpc->msgin.bpage_offsets[0]);
	EXPECT_EQ(-1, pool->descriptors[0].owner);
	EXPECT_EQ(2*HOMA_BPAGE_SIZE, crpc->msgin.bpage_offsets[2]);
	EXPECT_EQ(2, pool->cores[smp_processor_id()].page_hint);
	EXPECT_EQ(150000 - 2*HOMA_BPAGE_SIZE,
			pool->cores[smp_processor_id()].allocated);
}
TEST_F(homa_pool, homa_pool_alloc_msg__no_buffer_pool)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, &self->client_ip, &self->server_ip,
			4000, 98, 1000,	150000);

	ASSERT_NE(NULL, crpc);

	homa_pool_free(self->hsk.buffer_pool);
	self->hsk.buffer_pool = homa_pool_alloc(&self->hsk);

	EXPECT_EQ(ENOMEM, -homa_pool_alloc_msg(crpc));
}
TEST_F(homa_pool, homa_pool_alloc_msg__cant_allocate_full_bpages)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	atomic_set(&pool->free_bpages, 1);
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 150000);
	ASSERT_NE(NULL, crpc);

	EXPECT_EQ(0, crpc->msgin.num_bpages);
	EXPECT_FALSE(list_empty(&crpc->buf_links));
	EXPECT_EQ(1, atomic_read(&pool->free_bpages));
}
TEST_F(homa_pool, homa_pool_alloc_msg__no_partial_page)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	atomic_set(&pool->free_bpages, 2);
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000,
			2*HOMA_BPAGE_SIZE);
	ASSERT_NE(NULL, crpc);

	EXPECT_EQ(2, crpc->msgin.num_bpages);
	EXPECT_EQ(0, crpc->msgin.bpage_offsets[0]);
	EXPECT_EQ(HOMA_BPAGE_SIZE, crpc->msgin.bpage_offsets[1]);
	EXPECT_EQ(0, atomic_read(&pool->free_bpages));
}
TEST_F(homa_pool, homa_pool_alloc_msg__owned_page_locked_and_page_stolen)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	pool->cores[smp_processor_id()].next_candidate = 2;
	atomic_set(&pool->free_bpages, 40);
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2000);
	ASSERT_NE(NULL, crpc);

	// First allocation just sets up a partially-allocated bpage.
	EXPECT_EQ(2, pool->cores[smp_processor_id()].page_hint);

	// Try a second allocation; the lock hook steals the partial bpage,
	// so a new one has to be allocated.
	crpc->msgin.num_bpages = 0;
	mock_trylock_errors = 1;
	unit_hook_register(change_owner_hook);
	EXPECT_EQ(0, homa_pool_alloc_msg(crpc));
	EXPECT_EQ(1, crpc->msgin.num_bpages);
	EXPECT_EQ(3*HOMA_BPAGE_SIZE, crpc->msgin.bpage_offsets[0]);
	EXPECT_EQ(3, pool->cores[smp_processor_id()].page_hint);
	EXPECT_EQ(2000, pool->cores[smp_processor_id()].allocated);
	EXPECT_EQ(1, -pool->descriptors[2].owner);
	EXPECT_EQ(1, pool->descriptors[3].owner);
	EXPECT_EQ(38, atomic_read(&pool->free_bpages));
}
TEST_F(homa_pool, homa_pool_alloc_msg__page_wrap_around)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	pool->cores[smp_processor_id()].page_hint = 2;
	pool->cores[smp_processor_id()].allocated = HOMA_BPAGE_SIZE-1900;
	atomic_set(&pool->descriptors[2].refs, 1);
	pool->descriptors[2].owner = smp_processor_id();
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2000);
	ASSERT_NE(NULL, crpc);

	EXPECT_EQ(2, pool->cores[smp_processor_id()].page_hint);
	EXPECT_EQ(1, crpc->msgin.num_bpages);
	EXPECT_EQ(2*HOMA_BPAGE_SIZE, crpc->msgin.bpage_offsets[0]);
	EXPECT_EQ(2000, pool->cores[smp_processor_id()].allocated);
	EXPECT_EQ(smp_processor_id(), pool->descriptors[2].owner);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->bpage_reuses);
#endif /* See strip.py */
}
TEST_F(homa_pool, homa_pool_alloc_msg__owned_page_overflow)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	pool->cores[smp_processor_id()].next_candidate = 2;
	atomic_set(&pool->free_bpages, 50);
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2000);
	ASSERT_NE(NULL, crpc);

	EXPECT_EQ(2, pool->cores[smp_processor_id()].page_hint);
	crpc->msgin.num_bpages = 0;
	pool->cores[smp_processor_id()].allocated = HOMA_BPAGE_SIZE-1900;
	EXPECT_EQ(0, homa_pool_alloc_msg(crpc));
	EXPECT_EQ(1, crpc->msgin.num_bpages);
	EXPECT_EQ(3*HOMA_BPAGE_SIZE, crpc->msgin.bpage_offsets[0]);
	EXPECT_EQ(3, pool->cores[smp_processor_id()].page_hint);
	EXPECT_EQ(2000, pool->cores[smp_processor_id()].allocated);
	EXPECT_EQ(-1, pool->descriptors[2].owner);
	EXPECT_EQ(1, atomic_read(&pool->descriptors[2].refs));
	EXPECT_EQ(1, pool->descriptors[3].owner);
	EXPECT_EQ(48, atomic_read(&pool->free_bpages));
}
TEST_F(homa_pool, homa_pool_alloc_msg__reuse_owned_page)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc1, *crpc2;

	pool->cores[smp_processor_id()].next_candidate = 2;
	crpc1 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2000);
	ASSERT_NE(NULL, crpc1);
	crpc2 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 100, 1000, 3000);
	ASSERT_NE(NULL, crpc2);

	EXPECT_EQ(1, crpc1->msgin.num_bpages);
	EXPECT_EQ(2*HOMA_BPAGE_SIZE, crpc1->msgin.bpage_offsets[0]);
	EXPECT_EQ(1, crpc2->msgin.num_bpages);
	EXPECT_EQ(2*HOMA_BPAGE_SIZE + 2000, crpc2->msgin.bpage_offsets[0]);
	EXPECT_EQ(3, atomic_read(&pool->descriptors[2].refs));
	EXPECT_EQ(2, pool->cores[smp_processor_id()].page_hint);
	EXPECT_EQ(5000, pool->cores[smp_processor_id()].allocated);
}
TEST_F(homa_pool, homa_pool_alloc_msg__cant_allocate_partial_bpage)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	atomic_set(&pool->free_bpages, 5);
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000,
			5*HOMA_BPAGE_SIZE + 100);
	ASSERT_NE(NULL, crpc);

	EXPECT_EQ(0, crpc->msgin.num_bpages);
	EXPECT_EQ(0, atomic_read(&pool->descriptors[0].refs));
	EXPECT_EQ(0, atomic_read(&pool->descriptors[1].refs));
	EXPECT_EQ(0, atomic_read(&pool->descriptors[4].refs));
	EXPECT_EQ(5, atomic_read(&pool->free_bpages));
}
TEST_F(homa_pool, homa_pool_alloc_msg__out_of_space)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *rpc;

	/* Queue up several RPCs to make sure they are properly sorted. */
	atomic_set(&pool->free_bpages, 0);
	unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2000);
	unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 100, 1000, 2*HOMA_BPAGE_SIZE);
	unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 102, 1000, 2000);

	ASSERT_EQ(0, atomic_read(&pool->free_bpages));
	ASSERT_FALSE(list_empty(&self->hsk.waiting_for_bufs));
	rpc = list_first_entry(&self->hsk.waiting_for_bufs, struct homa_rpc,
			buf_links);
	EXPECT_EQ(98, rpc->id);
	ASSERT_FALSE(list_is_last(&rpc->buf_links, &self->hsk.waiting_for_bufs));
	rpc = list_next_entry(rpc, buf_links);
	EXPECT_EQ(102, rpc->id);
	ASSERT_FALSE(list_is_last(&rpc->buf_links, &self->hsk.waiting_for_bufs));
	rpc = list_next_entry(rpc, buf_links);
	EXPECT_EQ(100, rpc->id);
	EXPECT_TRUE(list_is_last(&rpc->buf_links, &self->hsk.waiting_for_bufs));
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(3, homa_metrics_per_cpu()->buffer_alloc_failures);
#endif /* See strip.py */
	EXPECT_EQ(1, pool->bpages_needed);
}

TEST_F(homa_pool, homa_pool_get_buffer)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;
	int available;
	void *buffer;

	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 150000);
	ASSERT_NE(NULL, crpc);
	buffer = homa_pool_get_buffer(crpc, HOMA_BPAGE_SIZE + 1000, &available);
	EXPECT_EQ(HOMA_BPAGE_SIZE - 1000, available);
	EXPECT_EQ((void *) (pool->region + HOMA_BPAGE_SIZE + 1000), buffer);
	buffer = homa_pool_get_buffer(crpc, 2*HOMA_BPAGE_SIZE + 100, &available);
	EXPECT_EQ((150000 & (HOMA_BPAGE_SIZE-1)) - 100, available);
	EXPECT_EQ((void *) (pool->region + 2*HOMA_BPAGE_SIZE + 100), buffer);
}
TEST_F(homa_pool, homa_pool_get_buffer__bad_offset)
{
	struct homa_rpc *crpc;
	int available;
	void *buffer;

	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 150000);
	ASSERT_NE(NULL, crpc);
	buffer = homa_pool_get_buffer(crpc, 149900, &available);
	EXPECT_NE(NULL, buffer);
	EXPECT_EQ(100, available);
	buffer = homa_pool_get_buffer(crpc, 150000, &available);
	EXPECT_EQ(NULL, buffer);
	EXPECT_EQ(0, available);
}

TEST_F(homa_pool, homa_pool_release_buffers__basics)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc1, *crpc2;
	char *saved_region;

	crpc1 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 150000);
	ASSERT_NE(NULL, crpc1);
	crpc2 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2000);
	ASSERT_NE(NULL, crpc2);

	EXPECT_EQ(1, atomic_read(&pool->descriptors[0].refs));
	EXPECT_EQ(1, atomic_read(&pool->descriptors[1].refs));
	EXPECT_EQ(3, atomic_read(&pool->descriptors[2].refs));
	EXPECT_EQ(97, atomic_read(&pool->free_bpages));

	homa_pool_release_buffers(pool, crpc1->msgin.num_bpages,
			crpc1->msgin.bpage_offsets);
	EXPECT_EQ(0, atomic_read(&pool->descriptors[0].refs));
	EXPECT_EQ(0, atomic_read(&pool->descriptors[1].refs));
	EXPECT_EQ(2, atomic_read(&pool->descriptors[2].refs));
	EXPECT_EQ(99, atomic_read(&pool->free_bpages));

	/* Ignore requests if pool not initialized. */
	saved_region = pool->region;
	pool->region = NULL;
	homa_pool_release_buffers(pool, crpc1->msgin.num_bpages,
			crpc1->msgin.bpage_offsets);
	EXPECT_EQ(0, atomic_read(&pool->descriptors[0].refs));
	pool->region = saved_region;
}
TEST_F(homa_pool, homa_pool_release_buffers__bogus_offset)
{
	u32 buffer = self->hsk.buffer_pool->num_bpages << HOMA_BPAGE_SHIFT;

	EXPECT_EQ(EINVAL, -homa_pool_release_buffers(self->hsk.buffer_pool,
						       1, &buffer));
}

TEST_F(homa_pool, homa_pool_check_waiting__basics)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc2, *crpc3;

	/* Queue up 2 RPCs that together need a total of 5 bpages. */
	atomic_set(&pool->free_bpages, 0);
	crpc2 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 3*HOMA_BPAGE_SIZE);
	ASSERT_NE(NULL, crpc2);
	EXPECT_EQ(0, crpc2->msgin.num_bpages);
	EXPECT_EQ(3, pool->bpages_needed);

	crpc3 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2*HOMA_BPAGE_SIZE);
	ASSERT_NE(NULL, crpc3);
	EXPECT_EQ(0, crpc3->msgin.num_bpages);
	EXPECT_EQ(2, pool->bpages_needed);

	/* Now free up the allocated pages and make sure that space can be
	 * allocated for the queued RPCs.
	 */
	unit_log_clear();
	atomic_set(&pool->free_bpages, 1);
	homa_pool_check_waiting(pool);
	EXPECT_EQ(0, crpc2->msgin.num_bpages);
	EXPECT_EQ(0, crpc3->msgin.num_bpages);
	atomic_set(&pool->free_bpages, 5);
	homa_pool_check_waiting(pool);
	EXPECT_EQ(3, crpc2->msgin.num_bpages);
	EXPECT_EQ(2, crpc3->msgin.num_bpages);
	EXPECT_EQ(INT_MAX, pool->bpages_needed);
}
TEST_F(homa_pool, homa_pool_check_waiting__pool_not_initialized)
{
	struct homa_pool pool;

	memset(&pool, 0, sizeof(pool));

	/* Without the initialization check, this will crash. */
	homa_pool_check_waiting(&pool);
}
TEST_F(homa_pool, homa_pool_check_waiting__bpages_needed_but_no_queued_rpcs)
{
	struct homa_pool *pool = self->hsk.buffer_pool;

	pool->bpages_needed = 1;
	homa_pool_check_waiting(pool);
	EXPECT_EQ(100, atomic_read(&pool->free_bpages));
	EXPECT_EQ(INT_MAX, pool->bpages_needed);
}
TEST_F(homa_pool, homa_pool_check_waiting__rpc_initially_locked)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	atomic_set(&pool->free_bpages, 0);
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2000);
	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(0, crpc->msgin.num_bpages);

#ifndef __STRIP__ /* See strip.py */
	mock_trylock_errors = 0xa;
#else /* See strip.py */
	mock_trylock_errors = 0x3;
#endif /* See strip.py */
	unit_log_clear();
	atomic_set(&pool->free_bpages, 1);
	homa_pool_check_waiting(pool);
	EXPECT_SUBSTR("rpc lock unavailable in homa_pool_check_waiting; "
			"rpc lock unavailable in homa_pool_check_waiting",
			unit_log_get());
	EXPECT_EQ(1, crpc->msgin.num_bpages);
	EXPECT_TRUE(list_empty(&self->hsk.waiting_for_bufs));
}
TEST_F(homa_pool, homa_pool_check_waiting__reset_bpages_needed)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc1, *crpc2;

	atomic_set(&pool->free_bpages, 0);
	crpc1 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2000);
	ASSERT_NE(NULL, crpc1);
	EXPECT_EQ(0, crpc1->msgin.num_bpages);

	atomic_set(&pool->free_bpages, 0);
	crpc2 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2*HOMA_BPAGE_SIZE - 1);
	ASSERT_NE(NULL, crpc2);
	EXPECT_EQ(0, crpc2->msgin.num_bpages);
	EXPECT_EQ(1, pool->bpages_needed);

	atomic_set(&pool->free_bpages, 1);
	homa_pool_check_waiting(pool);
	EXPECT_EQ(1, crpc1->msgin.num_bpages);
	EXPECT_EQ(0, crpc2->msgin.num_bpages);
	EXPECT_EQ(2, pool->bpages_needed);
}
#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_pool, homa_pool_check_waiting__wake_up_waiting_rpc)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	/* Queue up an RPC that needs 2 bpages. */
	atomic_set(&pool->free_bpages, 0);
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2*HOMA_BPAGE_SIZE);
	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(0, crpc->msgin.num_bpages);
	EXPECT_EQ(2, pool->bpages_needed);

	/* Free the required pages. */
	unit_log_clear();
	atomic_set(&pool->free_bpages, 2);
	homa_pool_check_waiting(pool);
	EXPECT_EQ(2, crpc->msgin.num_bpages);
	EXPECT_EQ(0, crpc->msgin.rank);
	EXPECT_STREQ("xmit GRANT 10000@0 resend_all",
		     unit_log_get());
}
#endif /* See strip.py */
TEST_F(homa_pool, homa_pool_check_waiting__reallocation_fails)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	/* Queue up an RPC that needs 4 bpages. */
	atomic_set(&pool->free_bpages, 0);
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 4*HOMA_BPAGE_SIZE);
	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(0, crpc->msgin.num_bpages);
	pool->bpages_needed = 2;

	unit_log_clear();
	atomic_set(&pool->free_bpages, 2);
	homa_pool_check_waiting(pool);
	EXPECT_EQ(0, crpc->msgin.num_bpages);
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(4, pool->bpages_needed);
}
