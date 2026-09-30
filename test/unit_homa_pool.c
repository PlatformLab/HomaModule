// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

#include "homa_impl.h"
#include "homa_grant.h"
#include "homa_pool.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

static struct homa_pool *cur_pool;

static int hook_index;

/* Used to decrement the reference count of page @hook_index in a race. */
static void rx_pool_race_hook(char *id)
{
	if (strcmp(id, "rx_pool_race") != 0)
		return;
	atomic_dec(&cur_pool->refs[hook_index]);
}

/* Used to steal pages from the buffer pool before homa_pool_wakeup_worker
 * can allocate them to a waiting RPC.
 */
static void rx_wakeup_race_hook(char *id)
{
	if (strcmp(id, "unlock") != 0)
		return;
	if (cur_pool)
		cur_pool->free_bpages = 2;
	cur_pool = NULL;
}

FIXTURE(homa_pool) {
	struct homa homa;
	struct homa_net *hnet;
	struct homa_sock hsk;
	struct in6_addr client_ip;
	struct in6_addr server_ip;
};
FIXTURE_SETUP(homa_pool)
{
	homa_init(&self->homa);
	self->hnet = mock_hnet(0, &self->homa);
#ifndef __STRIP__ /* See strip.py */
	self->homa.unsched_bytes = 10000;
	self->homa.grant->window = 10000;
	self->homa.grant->fifo_fraction = 0;
#endif /* See strip.py */
	mock_sock_init(&self->hsk, self->hnet, 0);
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

TEST_F(homa_pool, homa_pool_set_region__region_not_page_aligned)
{
	homa_pool_free(self->hsk.buffer_pool);
	self->hsk.buffer_pool = homa_pool_alloc(&self->hsk);

	EXPECT_EQ(EINVAL, -homa_pool_set_region(self->hsk.buffer_pool,
						((char *) 0x1000000) + 10,
						100*HOMA_BPAGE_SIZE));
	EXPECT_STREQ("buffer pool is not page aligned", self->hsk.error_msg);
}
TEST_F(homa_pool, homa_pool_set_region__region_too_small)
{
	homa_pool_free(self->hsk.buffer_pool);
	self->hsk.buffer_pool = homa_pool_alloc(&self->hsk);

	EXPECT_EQ(EINVAL, -homa_pool_set_region(self->hsk.buffer_pool,
						(void *) 0x1000000,
		  nr_cpu_ids * HOMA_BPAGE_SIZE));
	EXPECT_STREQ("buffer pool is not large enough", self->hsk.error_msg);
}
TEST_F(homa_pool, homa_pool_set_region__region_too_large)
{
	u64 size;

	homa_pool_free(self->hsk.buffer_pool);
	self->hsk.buffer_pool = homa_pool_alloc(&self->hsk);

	size = 1;
	size <<= 32;
	size++;
	EXPECT_EQ(EINVAL, -homa_pool_set_region(self->hsk.buffer_pool,
						(void *) 0x1000000,
		  size));
	EXPECT_STREQ("buffer pool cannot be larger than 4 GB",
		     self->hsk.error_msg);
}
TEST_F(homa_pool, homa_pool_set_region__cant_allocate_refs_array)
{
	homa_pool_free(self->hsk.buffer_pool);
	self->hsk.buffer_pool = homa_pool_alloc(&self->hsk);

	mock_kmalloc_errors = 1;
	EXPECT_EQ(ENOMEM, -homa_pool_set_region(self->hsk.buffer_pool,
						(void *) 0x100000,
						100*HOMA_BPAGE_SIZE));
}
TEST_F(homa_pool, homa_pool_set_region__cant_allocate_free_stack)
{
	homa_pool_free(self->hsk.buffer_pool);
	self->hsk.buffer_pool = homa_pool_alloc(&self->hsk);

	mock_kmalloc_errors = 2;
	EXPECT_EQ(ENOMEM, -homa_pool_set_region(self->hsk.buffer_pool,
						(void *) 0x100000,
						100*HOMA_BPAGE_SIZE));
}
TEST_F(homa_pool, homa_pool_set_region__cant_allocate_core_info)
{
	homa_pool_free(self->hsk.buffer_pool);
	self->hsk.buffer_pool = homa_pool_alloc(&self->hsk);

	mock_kmalloc_errors = 4;
	EXPECT_EQ(ENOMEM, -homa_pool_set_region(self->hsk.buffer_pool,
						(void *) 0x100000,
						100*HOMA_BPAGE_SIZE));
}
TEST_F(homa_pool, homa_pool_set_region__pool_already_has_region)
{
	EXPECT_EQ(EINVAL, -homa_pool_set_region(self->hsk.buffer_pool,
						(void *) 0x100000,
						100*HOMA_BPAGE_SIZE));
}
TEST_F(homa_pool, homa_pool_set_region__success)
{
	struct homa_pool *pool;

	homa_pool_free(self->hsk.buffer_pool);
	pool = homa_pool_alloc(&self->hsk);
	self->hsk.buffer_pool = pool;

	EXPECT_EQ(0, -homa_pool_set_region(pool, (void *) 0x100000,
					   78*HOMA_BPAGE_SIZE));
	EXPECT_EQ(78, pool->num_bpages);
	EXPECT_EQ(78, pool->free_bpages);
	EXPECT_EQ(77, pool->free_stack[0]);
	EXPECT_EQ(1, pool->free_stack[76]);
	EXPECT_EQ(0, atomic_read(&pool->refs[77]));
	EXPECT_EQ(-1, this_cpu_ptr(pool->cores)->page);
}

TEST_F(homa_pool, homa_pool_get_rcvbuf)
{
	struct homa_rcvbuf_args args;
	int saved_num_bpages;

	homa_pool_free(self->hsk.buffer_pool);
	self->hsk.buffer_pool = homa_pool_alloc(&self->hsk);

	EXPECT_EQ(0, -homa_pool_set_region(self->hsk.buffer_pool,
					   (void *)0x40000,
		  			   100*HOMA_BPAGE_SIZE + 1000));
	homa_pool_get_rcvbuf(self->hsk.buffer_pool, &args);
	EXPECT_EQ(0x40000, args.start);
	EXPECT_EQ(100*HOMA_BPAGE_SIZE, args.length);

	/* Check for proper 64-bit arithmetic. */
	saved_num_bpages = self->hsk.buffer_pool->num_bpages;
	self->hsk.buffer_pool->num_bpages = 0x1000000;
	homa_pool_get_rcvbuf(self->hsk.buffer_pool, &args);
	self->hsk.buffer_pool->num_bpages = saved_num_bpages;
	EXPECT_EQ(0x1000000LLU << HOMA_BPAGE_SHIFT, args.length);

}

TEST_F(homa_pool, homa_pool_get_pages__basics)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;
	u32 pages[10];

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
			       &self->server_ip, 4000, 98, 1000, 150000);
	ASSERT_NE(NULL, crpc);

	mock_check_bpool_leaks = false;
	EXPECT_EQ(0, homa_pool_get_pages(crpc, 2, pages));
	EXPECT_EQ(0, pages[0]);
	EXPECT_EQ(1, pages[1]);
	EXPECT_EQ(1, atomic_read(&pool->refs[1]));
	EXPECT_EQ(98, pool->free_bpages);
}
TEST_F(homa_pool, homa_pool_get_pages__not_enough_space)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;
	u32 pages[10];

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
			       &self->server_ip, 4000, 98, 1000, 150000);
	ASSERT_NE(NULL, crpc);

	mock_check_bpool_leaks = false;
	pool->free_bpages = 1;
	EXPECT_EQ(-1, homa_pool_get_pages(crpc, 2, pages));
	EXPECT_EQ(1, pool->free_bpages);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->buffer_alloc_failures);
#endif /* See strip.py */

	pool->free_bpages = 2;
	EXPECT_EQ(0, homa_pool_get_pages(crpc, 2, pages));
	EXPECT_EQ(0, pool->free_bpages);
}

TEST_F(homa_pool, homa_pool_enqueue__basics)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *rpc;

	mock_check_bpool_leaks = false;

	/* Queue up several RPCs to make sure they are properly sorted. */
	pool->free_bpages = 0;
	unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2000);
	unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 100, 1000, 2*HOMA_BPAGE_SIZE);
	unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 102, 1000, 2000);

	ASSERT_EQ(0, pool->free_bpages);
	ASSERT_FALSE(list_empty(&self->hsk.buffer_pool->waiting_for_bufs));
	rpc = list_first_entry(&self->hsk.buffer_pool->waiting_for_bufs,
			       struct homa_rpc, buf_links);
	EXPECT_EQ(98, rpc->id);
	ASSERT_FALSE(list_is_last(&rpc->buf_links,
				  &self->hsk.buffer_pool->waiting_for_bufs));
	rpc = list_next_entry(rpc, buf_links);
	EXPECT_EQ(102, rpc->id);
	ASSERT_FALSE(list_is_last(&rpc->buf_links,
				  &self->hsk.buffer_pool->waiting_for_bufs));
	rpc = list_next_entry(rpc, buf_links);
	EXPECT_EQ(100, rpc->id);
	EXPECT_TRUE(list_is_last(&rpc->buf_links,
				 &self->hsk.buffer_pool->waiting_for_bufs));
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(3, homa_metrics_per_cpu()->buffer_alloc_failures);
#endif /* See strip.py */
}
TEST_F(homa_pool, homa_pool_enqueue__error_conditions)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
			       &self->server_ip, 4000, 98, 1000, 150000);
	ASSERT_NE(NULL, crpc);

	/* First call: RPC is dead. */
	crpc->state = RPC_DEAD;
	homa_pool_enqueue(pool, crpc);
	EXPECT_TRUE(list_empty(&crpc->buf_links));
	EXPECT_EQ(0, unit_list_length(&pool->waiting_for_bufs));
	crpc->state = RPC_OUTGOING;

	/* Second call: RPC gets linked. */
	crpc->msgin.length = 150000;
	homa_pool_enqueue(pool, crpc);
	EXPECT_FALSE(list_empty(&crpc->buf_links));
	EXPECT_EQ(1, unit_list_length(&pool->waiting_for_bufs));

	/* Third call: RPC already linked. */
	homa_pool_enqueue(pool, crpc);
	EXPECT_FALSE(list_empty(&crpc->buf_links));
	EXPECT_EQ(1, unit_list_length(&pool->waiting_for_bufs));

	crpc->msgin.length = -1;
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
	EXPECT_EQ(2 * HOMA_BPAGE_SIZE, crpc->msgin.bpage_offsets[2]);
	EXPECT_EQ(2, pool->cores[smp_processor_id()].page);
	EXPECT_EQ(150000 - 2*HOMA_BPAGE_SIZE,
			pool->cores[smp_processor_id()].allocated);
}
TEST_F(homa_pool, homa_pool_alloc_msg__no_buffer_pool)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, &self->client_ip, &self->server_ip,
			4000, 98, 1000,	150000);

	ASSERT_NE(NULL, crpc);
	mock_check_bpool_leaks = false;

	homa_pool_free(self->hsk.buffer_pool);
	self->hsk.buffer_pool = homa_pool_alloc(&self->hsk);

	EXPECT_EQ(ENOMEM, -homa_pool_alloc_msg(crpc));
}
TEST_F(homa_pool, homa_pool_alloc_msg__owned_page_wrap_around)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	mock_check_bpool_leaks = false;
	pool->cores[smp_processor_id()].page = 3;
	pool->cores[smp_processor_id()].allocated = HOMA_BPAGE_SIZE-1900;
	atomic_set(&pool->refs[3], 1);
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2000);
	ASSERT_NE(NULL, crpc);

	EXPECT_EQ(3, pool->cores[smp_processor_id()].page);
	EXPECT_EQ(1, crpc->msgin.num_bpages);
	EXPECT_EQ(3 * HOMA_BPAGE_SIZE, crpc->msgin.bpage_offsets[0]);
	EXPECT_EQ(2000, pool->cores[smp_processor_id()].allocated);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->bpage_reuses);
#endif /* See strip.py */
}
TEST_F(homa_pool, homa_pool_alloc_msg__reuse_owned_page)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc1, *crpc2;

	crpc1 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2000);
	ASSERT_NE(NULL, crpc1);
	crpc2 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 100, 1000, 3000);
	ASSERT_NE(NULL, crpc2);

	EXPECT_EQ(1, crpc1->msgin.num_bpages);
	EXPECT_EQ(0, crpc1->msgin.bpage_offsets[0]);
	EXPECT_EQ(1, crpc2->msgin.num_bpages);
	EXPECT_EQ(2000, crpc2->msgin.bpage_offsets[0]);
	EXPECT_EQ(3, atomic_read(&pool->refs[0]));
	EXPECT_EQ(0, pool->cores[smp_processor_id()].page);
	EXPECT_EQ(5000, pool->cores[smp_processor_id()].allocated);
}
TEST_F(homa_pool, homa_pool_alloc_msg__owned_page_overflow)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	mock_check_bpool_leaks = false;
	pool->free_bpages = 40;
	pool->cores[smp_processor_id()].page = 3;
	pool->cores[smp_processor_id()].allocated = HOMA_BPAGE_SIZE-1900;
	atomic_set(&pool->refs[3], 4);

	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2000);
	ASSERT_NE(NULL, crpc);

	EXPECT_EQ(60, pool->cores[smp_processor_id()].page);
	EXPECT_EQ(1, crpc->msgin.num_bpages);
	EXPECT_EQ(60 * HOMA_BPAGE_SIZE, crpc->msgin.bpage_offsets[0]);
	EXPECT_EQ(2000, pool->cores[smp_processor_id()].allocated);
	EXPECT_EQ(3, atomic_read(&pool->refs[3]));
	EXPECT_EQ(2, atomic_read(&pool->refs[60]));
	EXPECT_EQ(39, pool->free_bpages);
}
TEST_F(homa_pool, homa_pool_alloc_msg__ref_count_race_on_owned_page)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	mock_check_bpool_leaks = false;
	pool->free_bpages = 40;
	pool->cores[smp_processor_id()].page = 3;
	pool->cores[smp_processor_id()].allocated = HOMA_BPAGE_SIZE-1900;
	atomic_set(&pool->refs[3], 2);
	hook_index = 3;
	unit_hook_register(rx_pool_race_hook);

	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2000);
	ASSERT_NE(NULL, crpc);

	EXPECT_EQ(3, pool->cores[smp_processor_id()].page);
	EXPECT_EQ(1, crpc->msgin.num_bpages);
	EXPECT_EQ(3*HOMA_BPAGE_SIZE, crpc->msgin.bpage_offsets[0]);
	EXPECT_EQ(2000, pool->cores[smp_processor_id()].allocated);
	EXPECT_EQ(2, atomic_read(&pool->refs[3]));
	EXPECT_EQ(40, pool->free_bpages);
}
TEST_F(homa_pool, homa_pool_alloc_msg__allocation_failure)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc1, *crpc2, *crpc3;
	int saved_free_bpages;

	/* First allocation succeeds. */
	crpc1 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2000);
	ASSERT_NE(NULL, crpc1);
	EXPECT_EQ(1, crpc1->msgin.num_bpages);

	/* Second allocation fails. */
	saved_free_bpages = pool->free_bpages;
	pool->free_bpages = 0;
	crpc2 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 100000);
	ASSERT_NE(NULL, crpc2);
	EXPECT_EQ(0, crpc2->msgin.num_bpages);
	EXPECT_EQ(1, unit_list_length(&pool->waiting_for_bufs));

	/* Third allocation succeeds (only needs space in private page). */
	crpc3 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 1000);
	ASSERT_NE(NULL, crpc3);
	EXPECT_EQ(1, crpc3->msgin.num_bpages);
	EXPECT_EQ(2000, crpc3->msgin.bpage_offsets[0]);
	EXPECT_EQ(1, unit_list_length(&pool->waiting_for_bufs));

	pool->free_bpages = saved_free_bpages;
}
TEST_F(homa_pool, homa_pool_alloc_msg__no_partial_page)
{
	struct homa_rpc *crpc = unit_client_rpc(&self->hsk,
			UNIT_RCVD_ONE_PKT, &self->client_ip, &self->server_ip,
			4000, 98, 1000,	4 * HOMA_BPAGE_SIZE);
	struct homa_pool *pool = self->hsk.buffer_pool;

	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(4, crpc->msgin.num_bpages);
	EXPECT_EQ(0, crpc->msgin.bpage_offsets[0]);
	EXPECT_EQ(HOMA_BPAGE_SIZE, crpc->msgin.bpage_offsets[1]);
	EXPECT_EQ(3 * HOMA_BPAGE_SIZE, crpc->msgin.bpage_offsets[3]);
	EXPECT_EQ(-1, pool->cores[smp_processor_id()].page);
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

TEST_F(homa_pool, homa_pool_free_bufs__basics)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc1, *crpc2;

	mock_check_bpool_leaks = false;
	crpc1 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 150000);
	ASSERT_NE(NULL, crpc1);
	crpc2 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2000);
	ASSERT_NE(NULL, crpc2);

	EXPECT_EQ(1, atomic_read(&pool->refs[0]));
	EXPECT_EQ(1, atomic_read(&pool->refs[1]));
	EXPECT_EQ(3, atomic_read(&pool->refs[2]));
	EXPECT_EQ(97, pool->free_bpages);

	homa_pool_free_bufs(pool, crpc1->msgin.num_bpages,
			    crpc1->msgin.bpage_offsets);
	EXPECT_EQ(0, atomic_read(&pool->refs[0]));
	EXPECT_EQ(0, atomic_read(&pool->refs[1]));
	EXPECT_EQ(2, atomic_read(&pool->refs[2]));
	EXPECT_EQ(99, pool->free_bpages);
}
TEST_F(homa_pool, homa_pool_free_bufs__pool_not_initialized)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc1;
	char *saved_region;

	mock_check_bpool_leaks = false;
	crpc1 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 150000);
	ASSERT_NE(NULL, crpc1);
	EXPECT_EQ(1, atomic_read(&pool->refs[0]));

	saved_region = pool->region;
	pool->region = NULL;
	EXPECT_EQ(EINVAL, -homa_pool_free_bufs(pool, crpc1->msgin.num_bpages,
					       crpc1->msgin.bpage_offsets));
	EXPECT_EQ(1, atomic_read(&pool->refs[0]));
	pool->region = saved_region;
}
TEST_F(homa_pool, homa_pool_free_bufs__bogus_offset)
{
	u32 buffer = self->hsk.buffer_pool->num_bpages << HOMA_BPAGE_SHIFT;

	EXPECT_EQ(EINVAL, -homa_pool_free_bufs(self->hsk.buffer_pool, 1,
					       &buffer));
}
TEST_F(homa_pool, homa_pool_free_bufs__bpage_already_free)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc1;

	mock_check_bpool_leaks = false;
	crpc1 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 150000);
	ASSERT_NE(NULL, crpc1);
	EXPECT_EQ(1, atomic_read(&pool->refs[0]));
	EXPECT_EQ(1, atomic_read(&pool->refs[1]));
	EXPECT_EQ(2, atomic_read(&pool->refs[2]));
	EXPECT_EQ(97, pool->free_bpages);

	atomic_set(&pool->refs[0], 0);
	EXPECT_EQ(EINVAL, -homa_pool_free_bufs(pool, crpc1->msgin.num_bpages,
					       crpc1->msgin.bpage_offsets));
	EXPECT_EQ(0, atomic_read(&pool->refs[0]));
	EXPECT_EQ(0, atomic_read(&pool->refs[1]));
	EXPECT_EQ(1, atomic_read(&pool->refs[2]));
	EXPECT_EQ(98, pool->free_bpages);
}
TEST_F(homa_pool, homa_pool_free_bufs__wakeup_blocked_rpcs)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;
	u32 offset;

	mock_check_bpool_leaks = false;
	atomic_set(&pool->refs[3], 2);
	atomic_set(&pool->refs[7], 1);

	/* Queue up an RPC that needs 2 bpages. */
	pool->free_bpages = 0;
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000,
			HOMA_BPAGE_SIZE + 1000);
	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(0, crpc->msgin.num_bpages);
	EXPECT_EQ(1, unit_list_length(&pool->waiting_for_bufs));
	unit_log_clear();

	/* First call doesn't free any bpages. */
	offset = 3 * HOMA_BPAGE_SIZE;
	EXPECT_EQ(0, homa_pool_free_bufs(pool, 1, &offset));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(1, atomic_read(&pool->refs[3]));

	/* Second call frees one bpage, but that isn't enough. */
	offset = 3 * HOMA_BPAGE_SIZE;
	EXPECT_EQ(0, homa_pool_free_bufs(pool, 1, &offset));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(0, atomic_read(&pool->refs[3]));

	/* Third call frees enough bpages for a wakeup. */
	offset = 7 * HOMA_BPAGE_SIZE;
	EXPECT_EQ(0, homa_pool_free_bufs(pool, 1, &offset));
	EXPECT_STREQ("work queued for system_bh_wq", unit_log_get());
	EXPECT_EQ(0, atomic_read(&pool->refs[7]));
}

TEST_F(homa_pool, homa_pool_check_waiting)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	mock_check_bpool_leaks = false;

	/* Queue up an RPC that needs 2 bpages. */
	pool->free_bpages = 0;
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 3*HOMA_BPAGE_SIZE);
	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(0, crpc->msgin.num_bpages);
	EXPECT_EQ(1, unit_list_length(&pool->waiting_for_bufs));
	unit_log_clear();

	/* First call: not enough free pages. */
	homa_pool_check_waiting(pool);
	EXPECT_STREQ("", unit_log_get());

	/* Second call: enough free pages, but shutting down. */
	pool->free_bpages = 5;
	pool->shutdown = true;
	homa_pool_check_waiting(pool);
	EXPECT_STREQ("", unit_log_get());

	/* Third call: wake up worker. */
	pool->shutdown = false;
	homa_pool_check_waiting(pool);
	EXPECT_STREQ("work queued for system_bh_wq", unit_log_get());
}

TEST_F(homa_pool, homa_pool_wakeup_worker__basics)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	mock_check_bpool_leaks = false;

	/* Queue up an RPC that needs 5 bpages. */
	pool->free_bpages = 0;
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 5 * HOMA_BPAGE_SIZE);
	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(0, crpc->msgin.num_bpages);
	EXPECT_EQ(1, unit_list_length(&pool->waiting_for_bufs));
	unit_log_clear();

	pool->free_bpages = 10;
	homa_pool_wakeup_worker(&pool->wakeup_work);
	EXPECT_EQ(0, unit_list_length(&pool->waiting_for_bufs));
	EXPECT_EQ(5, pool->free_bpages);
	EXPECT_EQ(5, crpc->msgin.num_bpages);
	EXPECT_EQ(90, crpc->msgin.bpage_offsets[0] >> HOMA_BPAGE_SHIFT);
	EXPECT_SUBSTR("xmit RESEND", unit_log_get());
}
TEST_F(homa_pool, homa_pool_wakeup_worker__no_pool)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;
	char *saved_region;

	mock_check_bpool_leaks = false;

	/* Queue up an RPC that needs 1 bpage. */
	pool->free_bpages = 0;
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 1000);
	EXPECT_EQ(1, unit_list_length(&pool->waiting_for_bufs));

	pool->free_bpages = 10;
	saved_region = pool->region;
	pool->region = NULL;
	homa_pool_wakeup_worker(&pool->wakeup_work);
	EXPECT_EQ(0, crpc->msgin.num_bpages);

	pool->region = saved_region;
}
TEST_F(homa_pool, homa_pool_wakeup_worker__pool_shutdown)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	mock_check_bpool_leaks = false;

	/* Queue up an RPC that needs 1 bpage. */
	pool->free_bpages = 0;
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 1000);
	EXPECT_EQ(1, unit_list_length(&pool->waiting_for_bufs));

	pool->free_bpages = 10;
	pool->shutdown = true;
	homa_pool_wakeup_worker(&pool->wakeup_work);
	EXPECT_EQ(0, crpc->msgin.num_bpages);

	pool->shutdown = false;
}
TEST_F(homa_pool, homa_pool_wakeup_worker__wakeup_multiple_rpcs)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc1, *crpc2, *crpc3;

	mock_check_bpool_leaks = false;

	pool->free_bpages = 0;
	crpc1 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 3 * HOMA_BPAGE_SIZE);
	crpc2 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, HOMA_BPAGE_SIZE);
	crpc3 = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2 * HOMA_BPAGE_SIZE);
	EXPECT_EQ(3, unit_list_length(&pool->waiting_for_bufs));

	/* First call wakes up 2 of the 3 RPCs. */
	pool->free_bpages = 5;
	homa_pool_wakeup_worker(&pool->wakeup_work);
	EXPECT_EQ(0, crpc1->msgin.num_bpages);
	EXPECT_EQ(1, crpc2->msgin.num_bpages);
	EXPECT_EQ(2, crpc3->msgin.num_bpages);

	/* Calling again still doesn't wake up the last RPC (still not enough
	 * pages).
	 */
	homa_pool_wakeup_worker(&pool->wakeup_work);
	EXPECT_EQ(0, crpc1->msgin.num_bpages);
}
TEST_F(homa_pool, homa_pool_wakeup_worker__rpc_dead)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;
	int saved_state;

	mock_check_bpool_leaks = false;

	/* Queue up an RPC that needs 5 bpages. */
	pool->free_bpages = 0;
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 5 * HOMA_BPAGE_SIZE);
	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(0, crpc->msgin.num_bpages);
	EXPECT_EQ(1, unit_list_length(&pool->waiting_for_bufs));
	unit_log_clear();

	pool->free_bpages = 10;
	saved_state = crpc->state;
	crpc->state = RPC_DEAD;
	homa_pool_wakeup_worker(&pool->wakeup_work);
	EXPECT_EQ(0, unit_list_length(&pool->waiting_for_bufs));
	EXPECT_EQ(10, pool->free_bpages);
	EXPECT_EQ(0, crpc->msgin.num_bpages);
	crpc->state = saved_state;
}
TEST_F(homa_pool, homa_pool_wakeup_worker__race_steals_needed_pages)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	mock_check_bpool_leaks = false;

	/* Queue up an RPC that needs 5 bpages. */
	pool->free_bpages = 0;
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 5 * HOMA_BPAGE_SIZE);
	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(0, crpc->msgin.num_bpages);
	EXPECT_EQ(1, unit_list_length(&pool->waiting_for_bufs));
	unit_log_clear();

	pool->free_bpages = 10;
	unit_hook_register(rx_wakeup_race_hook);
	homa_pool_wakeup_worker(&pool->wakeup_work);
	EXPECT_EQ(1, unit_list_length(&pool->waiting_for_bufs));
	EXPECT_EQ(2, pool->free_bpages);
	EXPECT_EQ(0, crpc->msgin.num_bpages);
}

#ifndef __STRIP__ /* See strip.py */
TEST_F(homa_pool, homa_pool_wakeup_rpc__scheduled)
{
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_START_MSG, &self->client_ip,
			&self->server_ip, 4000, 101, 20000, 100);
	ASSERT_NE(NULL, srpc);
	srpc->msgin.granted = 0;

	unit_log_clear();
	homa_rpc_lock(srpc);
	homa_pool_wakeup_rpc(srpc);
	EXPECT_STREQ("xmit GRANT 20000@0", unit_log_get());
	homa_rpc_unlock(srpc);
}
#endif /* See strip.py */
TEST_F(homa_pool, homa_pool_wakeup_rpc__unscheduled)
{
	struct homa_rpc *srpc;

	srpc = unit_server_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 101, 200, 100);
	ASSERT_NE(NULL, srpc);

	unit_log_clear();
	homa_rpc_lock(srpc);
	homa_pool_wakeup_rpc(srpc);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_STREQ("xmit RESEND 0, 200 @6", unit_log_get());
#else /* See strip.py */
	EXPECT_STREQ("xmit RESEND 0, 200", unit_log_get());
#endif /* See strip.py */
	homa_rpc_unlock(srpc);
}

TEST_F(homa_pool, homa_pool_avail_bytes__no_region)
{
	struct homa_pool *pool = homa_pool_alloc(&self->hsk);

	EXPECT_EQ(0, homa_pool_avail_bytes(pool));
	homa_pool_free(pool);
}
TEST_F(homa_pool, homa_pool_avail_bytes__a_few_pages_allocated)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;
	u32 pages[10];

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, &self->client_ip,
			       &self->server_ip, 4000, 98, 1000, 150000);
	ASSERT_NE(NULL, crpc);

	mock_check_bpool_leaks = false;
	EXPECT_EQ(100 * HOMA_BPAGE_SIZE, homa_pool_avail_bytes(pool));
	EXPECT_EQ(0, homa_pool_get_pages(crpc, 5, pages));
	EXPECT_EQ(95 * HOMA_BPAGE_SIZE, homa_pool_avail_bytes(pool));
}
TEST_F(homa_pool, homa_pool_avail_bytes__include_free_space_in_core_private_pages)
{
	struct homa_pool *pool = self->hsk.buffer_pool;

	mock_set_core(3);
	EXPECT_EQ(100 * HOMA_BPAGE_SIZE, homa_pool_avail_bytes(pool));
	unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 2000);
	EXPECT_EQ(100 * HOMA_BPAGE_SIZE - 2000, homa_pool_avail_bytes(pool));

	mock_set_core(5);
	unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000, 50000);
	EXPECT_EQ(100 * HOMA_BPAGE_SIZE - 52000, homa_pool_avail_bytes(pool));
}
TEST_F(homa_pool, homa_pool_avail_bytes__private_page_completely_free)
{
	struct homa_rpc *crpc;
	struct homa_pool *pool = self->hsk.buffer_pool;

	mock_set_core(3);
	EXPECT_EQ(100 * HOMA_BPAGE_SIZE, homa_pool_avail_bytes(pool));
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			       &self->server_ip, 4000, 98, 1000, 2000);
	EXPECT_EQ(100 * HOMA_BPAGE_SIZE - 2000, homa_pool_avail_bytes(pool));
	homa_pool_free_bufs(crpc->hsk->buffer_pool, crpc->msgin.num_bpages,
			    crpc->msgin.bpage_offsets);
	crpc->msgin.num_bpages = 0;
	EXPECT_EQ(100 * HOMA_BPAGE_SIZE, homa_pool_avail_bytes(pool));
}

/* Tests for inline functions in homa_pool.h: */

TEST_F(homa_pool, homa_pool_unlink)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;
	int saved_free;

	saved_free = pool->free_bpages;
	pool->free_bpages = 0;
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			       &self->server_ip, 4000, 98, 1000, 50000);
	ASSERT_NE(NULL, crpc);
	EXPECT_FALSE(list_empty(&crpc->buf_links));

	mock_trylock_errors = 1;
	homa_pool_unlink(crpc);
	EXPECT_TRUE(list_empty(&crpc->buf_links));
	EXPECT_TRUE(list_empty(&pool->waiting_for_bufs));
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->bpool_lock_misses);
#endif /* See strip.py */
	pool->free_bpages = saved_free;
}
TEST_F(homa_pool, homa_pool_unlink__not_waiting_for_buffers)
{
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			       &self->server_ip, 4000, 98, 1000, 50000);
	ASSERT_NE(NULL, crpc);
	EXPECT_TRUE(list_empty(&crpc->buf_links));

	mock_trylock_errors = 1;
	homa_pool_unlink(crpc);
	EXPECT_EQ(1, mock_trylock_errors);
	mock_trylock_errors = 0;
}

TEST_F(homa_pool, homa_pool_release)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;
	int pool_size = pool->num_bpages * HOMA_BPAGE_SIZE;

	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			       &self->server_ip, 4000, 98, 1000, 50000);
	ASSERT_NE(NULL, crpc);

	EXPECT_EQ(50000, pool_size - homa_pool_avail_bytes(pool));
	homa_pool_release(crpc);
	EXPECT_EQ(0, pool_size - homa_pool_avail_bytes(pool));
	EXPECT_EQ(0, crpc->msgin.num_bpages);
}

TEST_F(homa_pool, homa_pool_push_free)
{
	struct homa_pool *pool = self->hsk.buffer_pool;

	mock_check_bpool_leaks = false;

	pool->free_bpages = 20;
	homa_pool_push_free(pool, 72);
	homa_pool_push_free(pool, 177);
	EXPECT_EQ(22, pool->free_bpages);
	EXPECT_EQ(72, pool->free_stack[20]);
	EXPECT_EQ(177, pool->free_stack[21]);
}

TEST_F(homa_pool, homa_pool_head_fits)
{
	struct homa_pool *pool = self->hsk.buffer_pool;
	struct homa_rpc *crpc;

	mock_check_bpool_leaks = false;

	/* First call: no RPC waiting. */
	EXPECT_EQ(0, homa_pool_head_fits(pool));

	/* Second call: RPC waiting but not enough free space*/
	pool->free_bpages = 4;
	crpc = unit_client_rpc(&self->hsk, UNIT_RCVD_ONE_PKT, &self->client_ip,
			&self->server_ip, 4000, 98, 1000,
			4 * HOMA_BPAGE_SIZE + 1);
	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(0, homa_pool_head_fits(pool));

	/* Third call: enough space for RPC. */
	pool->free_bpages = 5;
	EXPECT_EQ(1, homa_pool_head_fits(pool));
}
