// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

#include "homa_impl.h"
#include "homa_tx_pool.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

static inline struct homa_tx_pool_core *get_tx_pool_core(int core)
{
	return &per_cpu(homa_tx_pool_core, core);
}

/* Add a given number of pages to the pool for a given core. */
static void add_to_pool(struct homa *homa, int num_pages, int core)
{
	struct homa_tx_pool *pool = get_tx_pool_core(core)->pool;
	int i;

	for (i = 0; i < num_pages; i++) {
		pool->pages[pool->avail] = alloc_pages(GFP_KERNEL,
				HOMA_TX_PAGE_ORDER);
		pool->avail++;
	}
}

static struct homa_tx_pool *hook_pool;

/* Used to remove a page from hook_pool in a race. */
static void page_race_hook(char *id)
{
	if (strcmp(id, "tx_pool_race") != 0)
		return;
	if ((hook_pool == NULL) || (hook_pool->avail == 0))
		return;
	hook_pool->avail--;
	put_page(hook_pool->pages[hook_pool->avail]);
}

FIXTURE(homa_tx_pool) {
	struct homa homa;
};
FIXTURE_SETUP(homa_tx_pool)
{
	homa_init(&self->homa);
}
FIXTURE_TEARDOWN(homa_tx_pool)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_tx_pool, homa_tx_pool_init__success)
{
	homa_tx_pool_cleanup(&self->homa);
	EXPECT_EQ(NULL, self->homa.tx_pools[0]);
	mock_numa_mask = 0x83;
	EXPECT_EQ(0, homa_tx_pool_init(&self->homa));
	EXPECT_NE(NULL, self->homa.tx_pools[0]);
	EXPECT_NE(NULL, self->homa.tx_pools[1]);
	EXPECT_EQ(NULL, self->homa.tx_pools[2]);
	EXPECT_EQ(self->homa.tx_pools[1], get_tx_pool_core(0)->pool);
	EXPECT_EQ(self->homa.tx_pools[1], get_tx_pool_core(1)->pool);
	EXPECT_EQ(self->homa.tx_pools[0], get_tx_pool_core(2)->pool);
	EXPECT_EQ(self->homa.tx_pools[0], get_tx_pool_core(6)->pool);
	EXPECT_EQ(self->homa.tx_pools[1], get_tx_pool_core(7)->pool);
	EXPECT_EQ(1, self->homa.max_numa);
}
TEST_F(homa_tx_pool, homa_tx_pool_init__kmalloc_failure)
{
	homa_tx_pool_cleanup(&self->homa);
	EXPECT_EQ(NULL, self->homa.tx_pools[0]);
	mock_numa_mask = 0x2;
	mock_kmalloc_errors = 0x2;
	EXPECT_EQ(ENOMEM, -homa_tx_pool_init(&self->homa));
	EXPECT_EQ(NULL, self->homa.tx_pools[0]);
	EXPECT_EQ(NULL, self->homa.tx_pools[1]);
	EXPECT_EQ(NULL, self->homa.tx_pools[2]);
}

TEST_F(homa_tx_pool, homa_tx_pool_cleanup)
{
	struct homa_tx_pool_core *tx_core = get_tx_pool_core(2);

	tx_core->page = alloc_pages(GFP_KERNEL, 2);
	add_to_pool(&self->homa, 5, 2);
	add_to_pool(&self->homa, 4, 3);
	mock_set_core(2);
	EXPECT_EQ(5, get_tx_pool_core(2)->pool->avail);
	EXPECT_EQ(4, get_tx_pool_core(3)->pool->avail);

	homa_tx_pool_cleanup(&self->homa);
	EXPECT_EQ(NULL, tx_core->pool);
	EXPECT_EQ(NULL, tx_core->page);

	tx_core = get_tx_pool_core(nr_cpu_ids - 1);
	EXPECT_EQ(NULL, tx_core->pool);

	/* Test for idempotency. */
	homa_tx_pool_cleanup(&self->homa);
}

TEST_F(homa_tx_pool, homa_tx_pool_alloc__single_frag)
{
	skb_frag_t frag;
	skb_frag_t *frags;
	int num_frags;

	num_frags = 1;
	frags = &frag;
	EXPECT_EQ(0, homa_tx_pool_alloc(&self->homa, 100, &num_frags, &frags));
	EXPECT_NE(NULL, skb_frag_page(&frag));
	EXPECT_EQ(1, num_frags);
	EXPECT_EQ(frags, &frag);
	EXPECT_EQ(0, frag.offset);
	EXPECT_EQ(100, skb_frag_size(&frag));

	homa_tx_pool_free(&self->homa, num_frags, &frag);
}
TEST_F(homa_tx_pool, homa_tx_pool_alloc__multiple_frags_reallocate_frags_array)
{
	skb_frag_t frag;
	skb_frag_t *frags;
	int num_frags;

	num_frags = 1;
	frags = &frag;
	EXPECT_EQ(0, homa_tx_pool_alloc(&self->homa,
					500 + 2 * HOMA_TX_PAGE_SIZE,
					&num_frags, &frags));
	EXPECT_NE(NULL, skb_frag_page(&frags[0]));
	EXPECT_EQ(3, num_frags);
	EXPECT_NE(frags, &frag);
	EXPECT_EQ(0, frags[0].offset);
	EXPECT_EQ(HOMA_TX_PAGE_SIZE, skb_frag_size(&frags[0]));
	EXPECT_EQ(0, frags[1].offset);
	EXPECT_EQ(HOMA_TX_PAGE_SIZE, skb_frag_size(&frags[1]));
	EXPECT_EQ(0, frags[2].offset);
	EXPECT_EQ(500, skb_frag_size(&frags[2]));

	homa_tx_pool_free(&self->homa, num_frags, frags);
	kfree(frags);
}
TEST_F(homa_tx_pool, homa_tx_pool_alloc__cant_reallocate_frags_array)
{
	skb_frag_t frag;
	skb_frag_t *frags;
	int num_frags;

	num_frags = 1;
	frags = &frag;
	mock_kmalloc_errors = 1;
	EXPECT_EQ(ENOMEM, -homa_tx_pool_alloc(&self->homa,
					      2 * HOMA_TX_PAGE_SIZE,
					      &num_frags, &frags));
}
TEST_F(homa_tx_pool, homa_tx_pool_alloc__reallocate_frags_array_multiple_times)
{
	skb_frag_t frag;
	skb_frag_t *frags;
	int num_frags;

	num_frags = 1;
	frags = &frag;

	mock_alloc_page_errors = 0x55;
	EXPECT_EQ(0, homa_tx_pool_alloc(&self->homa, 50000, &num_frags,
		  &frags));
	EXPECT_EQ(5, num_frags);
	EXPECT_NE(frags, &frag);
	EXPECT_EQ(0, frags[0].offset);
	EXPECT_EQ(PAGE_SIZE, skb_frag_size(&frags[0]));
	EXPECT_EQ(0, frags[1].offset);
	EXPECT_EQ(PAGE_SIZE, skb_frag_size(&frags[1]));
	EXPECT_EQ(0, frags[2].offset);
	EXPECT_EQ(PAGE_SIZE, skb_frag_size(&frags[2]));
	EXPECT_EQ(0, frags[3].offset);
	EXPECT_EQ(PAGE_SIZE, skb_frag_size(&frags[3]));
	EXPECT_EQ(0, frags[4].offset);
	EXPECT_EQ(50000 - 4 * PAGE_SIZE, skb_frag_size(&frags[4]));

	homa_tx_pool_free(&self->homa, num_frags, frags);
	kfree(frags);
}
TEST_F(homa_tx_pool, homa_tx_pool_alloc__cleanup_after_error)
{
	skb_frag_t frag;
	skb_frag_t *frags;
	int num_frags;

	/* First error doesn't need to free frag array. */
	mock_alloc_page_errors = 0xf;
	num_frags = 1;
	frags = &frag;
	EXPECT_EQ(ENOMEM, -homa_tx_pool_alloc(&self->homa,
						  3 * HOMA_TX_PAGE_SIZE,
						  &num_frags, &frags));
	EXPECT_EQ(0, num_frags);

	/* Second error happens after frag array expansion; must free new
	 * frag array.
	 */
	mock_alloc_page_errors = 0xc;
	num_frags = 1;
	frags = &frag;
	EXPECT_EQ(ENOMEM, -homa_tx_pool_alloc(&self->homa,
						  3 * HOMA_TX_PAGE_SIZE,
						  &num_frags, &frags));
	EXPECT_EQ(0, num_frags);

	/* (Test infrastructure will complain if anything isn't freed) */
}

TEST_F(homa_tx_pool, homa_tx_pool_alloc_frag__basics)
{
	struct homa_tx_pool_core *tx_core = get_tx_pool_core(2);
	skb_frag_t frag, frag2, frag3;

	/* First call allocates cached page. */
	EXPECT_EQ(0, __homa_tx_pool_alloc_frag(tx_core, 100, &frag));
	EXPECT_NE(NULL, skb_frag_page(&frag));
	EXPECT_EQ(0, frag.offset);
	EXPECT_EQ(100, skb_frag_size(&frag));
	EXPECT_EQ(skb_frag_page(&frag), tx_core->page);
	EXPECT_EQ(HOMA_TX_PAGE_SIZE, tx_core->page_size);
	EXPECT_EQ(100, tx_core->allocated);

	/* Second call allocates another frag from cached page. */
	EXPECT_EQ(0, __homa_tx_pool_alloc_frag(tx_core, 500, &frag2));
	EXPECT_EQ(skb_frag_page(&frag), skb_frag_page(&frag2));
	EXPECT_EQ(100, frag2.offset);
	EXPECT_EQ(500, skb_frag_size(&frag2));
	EXPECT_EQ(skb_frag_page(&frag), tx_core->page);
	EXPECT_EQ(600, tx_core->allocated);

	/* Third call doesn't fit; allocate new page (retain old cached). */
	EXPECT_EQ(0, __homa_tx_pool_alloc_frag(tx_core, HOMA_TX_PAGE_SIZE - 200,
		  &frag3));
	EXPECT_NE(skb_frag_page(&frag), skb_frag_page(&frag3));
	EXPECT_EQ(0, frag3.offset);
	EXPECT_EQ(HOMA_TX_PAGE_SIZE - 200, skb_frag_size(&frag3));

	put_page(skb_frag_page(&frag));
	put_page(skb_frag_page(&frag2));
	put_page(skb_frag_page(&frag3));
}
TEST_F(homa_tx_pool, homa_tx_pool_alloc_frag__retain_leftovers_from_new)
{
	struct homa_tx_pool_core *tx_core = get_tx_pool_core(2);
	skb_frag_t frag, frag2;

	/* First call allocates nearly a full page. */
	EXPECT_EQ(0, __homa_tx_pool_alloc_frag(tx_core, HOMA_TX_PAGE_SIZE - 200,
		  &frag));

	/* Second allocation doesn't fit in remnant, but leaves most of its
	 * page unoccupied.
	 */
	EXPECT_EQ(0, __homa_tx_pool_alloc_frag(tx_core, 500, &frag2));
	EXPECT_NE(skb_frag_page(&frag), skb_frag_page(&frag2));
	EXPECT_EQ(0, frag2.offset);
	EXPECT_EQ(500, skb_frag_size(&frag2));
	EXPECT_EQ(skb_frag_page(&frag2), tx_core->page);
	EXPECT_EQ(500, tx_core->allocated);

	put_page(skb_frag_page(&frag));
	put_page(skb_frag_page(&frag2));
}
TEST_F(homa_tx_pool, homa_tx_pool_alloc_frag__reduce_length)
{
	struct homa_tx_pool_core *tx_core = get_tx_pool_core(2);
	skb_frag_t frag;

	EXPECT_EQ(0, __homa_tx_pool_alloc_frag(tx_core, HOMA_TX_PAGE_SIZE + 1,
		  &frag));
	EXPECT_EQ(0, frag.offset);
	EXPECT_EQ(HOMA_TX_PAGE_SIZE, skb_frag_size(&frag));
	EXPECT_EQ(skb_frag_page(&frag), tx_core->page);
	EXPECT_EQ(HOMA_TX_PAGE_SIZE, tx_core->allocated);

	put_page(skb_frag_page(&frag));
}

TEST_F(homa_tx_pool, homa_tx_pool_alloc_page__use_cached_page)
{
	struct homa_tx_pool_core *tx_core = get_tx_pool_core(2);
	struct page *cached_page;
	int length;

	cached_page = alloc_pages(GFP_KERNEL, 2);
	tx_core->page = cached_page;
	tx_core->page_size = HOMA_TX_PAGE_SIZE;
	tx_core->allocated = 1000;
	EXPECT_EQ(cached_page, homa_tx_pool_alloc_page(tx_core, &length));
	EXPECT_EQ(NULL, tx_core->page);
	EXPECT_EQ(0, tx_core->page_size);
	EXPECT_EQ(0, tx_core->allocated);
	put_page(cached_page);
}
TEST_F(homa_tx_pool, homa_tx_pool_alloc_page__cached_page_ref_count_too_high)
{
	struct homa_tx_pool_core *tx_core = get_tx_pool_core(2);
	struct page *cached_page, *page;
	int length;

	cached_page = alloc_pages(GFP_KERNEL, 2);
	tx_core->page = cached_page;
	tx_core->page_size = HOMA_TX_PAGE_SIZE;
	tx_core->allocated = 1000;
	get_page(cached_page);
	page = homa_tx_pool_alloc_page(tx_core, &length);
	EXPECT_NE(cached_page, page);
	put_page(cached_page);
	put_page(page);
}
TEST_F(homa_tx_pool, homa_tx_pool_alloc_page__from_pool)
{
	struct homa_tx_pool_core *tx_core = get_tx_pool_core(smp_processor_id());
	struct page *page;
	int length;

	add_to_pool(&self->homa, 5, smp_processor_id());
	EXPECT_EQ(5, tx_core->pool->avail);
	tx_core->pool->low_mark = 100;
	page = homa_tx_pool_alloc_page(tx_core, &length);
	EXPECT_EQ(tx_core->pool->pages[4], page);
	EXPECT_EQ(4, tx_core->pool->avail);
	EXPECT_EQ(HOMA_TX_PAGE_SIZE, length);
	EXPECT_EQ(4, tx_core->pool->low_mark);
	put_page(page);
}
TEST_F(homa_tx_pool, homa_tx_pool_alloc_page__pool_page_taken_while_locking)
{
	struct homa_tx_pool_core *tx_core = get_tx_pool_core(smp_processor_id());
	int length;

	add_to_pool(&self->homa, 1, smp_processor_id());
	EXPECT_EQ(1, tx_core->pool->avail);
	hook_pool = tx_core->pool;
	unit_hook_register(page_race_hook);
	mock_alloc_page_errors = 3;

	EXPECT_EQ(NULL, homa_tx_pool_alloc_page(tx_core, &length));
	EXPECT_EQ(0, tx_core->pool->avail);
}
TEST_F(homa_tx_pool, homa_tx_pool_alloc_page__new_large_page)
{
	struct homa_tx_pool_core *tx_core = get_tx_pool_core(smp_processor_id());
	struct page *page;
	int length;

	mock_clock_tick = 100;
	EXPECT_EQ(0, tx_core->pool->avail);
	page = homa_tx_pool_alloc_page(tx_core, &length);
	EXPECT_NE(NULL, page);
	EXPECT_EQ(HOMA_TX_PAGE_SIZE, length);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->tx_page_allocs);
	EXPECT_EQ(100, homa_metrics_per_cpu()->tx_page_alloc_cycles);
#endif /* See strip.py */
	put_page(page);
}
TEST_F(homa_tx_pool, homa_tx_pool_alloc_page__high_order_page_not_available)
{
	struct homa_tx_pool_core *tx_core = get_tx_pool_core(2);
	struct page *page;
	int length;

	mock_clock_tick = 50;
	mock_alloc_page_errors = 1;
	page = homa_tx_pool_alloc_page(tx_core, &length);
	EXPECT_NE(NULL, page);
	EXPECT_EQ(PAGE_SIZE, length);
#ifndef __STRIP__ /* See strip.py */
	EXPECT_EQ(1, homa_metrics_per_cpu()->tx_page_allocs);
	EXPECT_EQ(50, homa_metrics_per_cpu()->tx_page_alloc_cycles);
#endif /* See strip.py */
	put_page(page);
}
TEST_F(homa_tx_pool, homa_tx_pool_alloc_page__no_pages_available)
{
	struct homa_tx_pool_core *tx_core = get_tx_pool_core(2);
	struct page *page;
	int length;

	mock_alloc_page_errors = 3;
	page = homa_tx_pool_alloc_page(tx_core, &length);
	EXPECT_EQ(NULL, page);
}

TEST_F(homa_tx_pool, homa_tx_pool_free__basics)
{
	struct homa_tx_pool *tx_pool;
	skb_frag_t *frags;
	int num_frags;

	tx_pool = get_tx_pool_core(smp_processor_id())->pool;
	num_frags = 0;
	frags = NULL;

	mock_alloc_page_errors = 2;
	EXPECT_EQ(0, homa_tx_pool_alloc(&self->homa,
					5000 + 3 * HOMA_TX_PAGE_SIZE,
					&num_frags, &frags));
	EXPECT_EQ(5, num_frags);
	EXPECT_EQ(0, frags[0].offset);
	EXPECT_EQ(HOMA_TX_PAGE_SIZE, skb_frag_size(&frags[0]));
	EXPECT_EQ(0, frags[1].offset);
	EXPECT_EQ(PAGE_SIZE, skb_frag_size(&frags[1]));
	EXPECT_EQ(0, frags[2].offset);
	EXPECT_EQ(HOMA_TX_PAGE_SIZE, skb_frag_size(&frags[2]));
	EXPECT_EQ(0, frags[3].offset);
	EXPECT_EQ(HOMA_TX_PAGE_SIZE, skb_frag_size(&frags[3]));
	EXPECT_EQ(0, frags[4].offset);
	EXPECT_EQ(5000 - PAGE_SIZE, skb_frag_size(&frags[4]));

	get_page(skb_frag_page(&frags[0]));
	EXPECT_EQ(0, tx_pool->avail);
	mock_compound_order_mask = 2;
	homa_tx_pool_free(&self->homa, num_frags, frags);

	EXPECT_EQ(2, tx_pool->avail);
	EXPECT_EQ(skb_frag_page(&frags[2]), tx_pool->pages[0]);
	EXPECT_EQ(skb_frag_page(&frags[3]), tx_pool->pages[1]);

	put_page(skb_frag_page(&frags[0]));
	kfree(frags);
}
TEST_F(homa_tx_pool, homa_tx_pool_free__pool_overflow)
{
	struct homa_tx_pool *tx_pool;
	skb_frag_t *frags;
	int num_frags;

	tx_pool = get_tx_pool_core(smp_processor_id())->pool;
	num_frags = 0;
	frags = NULL;

	EXPECT_EQ(0, homa_tx_pool_alloc(&self->homa,
					3 * HOMA_TX_PAGE_SIZE + 100,
					&num_frags, &frags));
	EXPECT_EQ(4, num_frags);

	EXPECT_EQ(0, tx_pool->avail);
	tx_pool->avail = HOMA_TX_POOL_LIMIT - 2;
	homa_tx_pool_free(&self->homa, num_frags, frags);

	EXPECT_EQ(HOMA_TX_POOL_LIMIT, tx_pool->avail);
	EXPECT_EQ(skb_frag_page(&frags[0]),
		  tx_pool->pages[HOMA_TX_POOL_LIMIT - 2]);
	EXPECT_EQ(skb_frag_page(&frags[1]),
	          tx_pool->pages[HOMA_TX_POOL_LIMIT - 1]);

	put_page(skb_frag_page(&frags[0]));
	put_page(skb_frag_page(&frags[1]));
	tx_pool->avail = 0;
	kfree(frags);
}


TEST_F(homa_tx_pool, homa_tx_pool_gc__basics)
{
	EXPECT_EQ(0UL, self->homa.tx_page_free_time);
	mock_clock = 1000000;
	self->homa.tx_page_free_time = 500000;
	self->homa.tx_page_frees_per_sec = 10;
	self->homa.tx_page_pool_min_kb = 0;
	add_to_pool(&self->homa, 10, 0);
	get_tx_pool_core(0)->pool->low_mark = 7;
	add_to_pool(&self->homa, 3, 1);
	get_tx_pool_core(1)->pool->low_mark = 2;

	homa_tx_pool_gc(&self->homa);
	EXPECT_EQ(5, get_tx_pool_core(0)->pool->avail);
	EXPECT_EQ(3, get_tx_pool_core(1)->pool->avail);
	EXPECT_EQ(5, get_tx_pool_core(0)->pool->low_mark);
	EXPECT_EQ(3, get_tx_pool_core(1)->pool->low_mark);
	EXPECT_EQ(501000000UL, self->homa.tx_page_free_time);
}
TEST_F(homa_tx_pool, homa_tx_pool_gc__not_time_to_free)
{
	EXPECT_EQ(0UL, self->homa.tx_page_free_time);
	mock_clock = 1000000;
	self->homa.tx_page_free_time = 1000001;
	self->homa.tx_page_frees_per_sec = 10;
	self->homa.tx_page_pool_min_kb = 0;
	add_to_pool(&self->homa, 10, 0);
	get_tx_pool_core(0)->pool->low_mark = 7;
	homa_tx_pool_gc(&self->homa);
	EXPECT_EQ(10, get_tx_pool_core(0)->pool->avail);
}
TEST_F(homa_tx_pool, homa_tx_pool_gc__allocate_tx_pages_to_free)
{
	EXPECT_EQ(0, self->homa.tx_pages_to_free_slots);
	mock_clock= 1000000;
	self->homa.tx_page_frees_per_sec = 10;
	self->homa.tx_page_free_time = 500000;

	/* First call: no current allocation. */
	homa_tx_pool_gc(&self->homa);
	EXPECT_EQ(5, self->homa.tx_pages_to_free_slots);

	/* Second call: free current allocation. */
	self->homa.tx_pages_to_free_slots -= 1;
	self->homa.tx_page_free_time = 500000;
	homa_tx_pool_gc(&self->homa);
	EXPECT_EQ(5, self->homa.tx_pages_to_free_slots);
}
TEST_F(homa_tx_pool, homa_tx_pool_gc__cant_reallocate_tx_pages_to_free)
{
	struct homa_tx_pool *pool;

	EXPECT_EQ(0UL, self->homa.tx_page_free_time);
	mock_clock = 1000000;
	self->homa.tx_page_free_time = 500000;
	self->homa.tx_page_frees_per_sec = 20;
	self->homa.tx_page_pool_min_kb = 0;
	add_to_pool(&self->homa, 20, 0);
	pool = get_tx_pool_core(0)->pool;
	pool->low_mark = 15;

	EXPECT_EQ(0, self->homa.tx_pages_to_free_slots);
	self->homa.tx_pages_to_free = kmalloc_array(4, sizeof(struct page *),
						     GFP_ATOMIC);
	self->homa.tx_pages_to_free_slots = 4;

	mock_kmalloc_errors = 1;
	homa_tx_pool_gc(&self->homa);
	EXPECT_EQ(16, pool->avail);
	EXPECT_EQ(4, self->homa.tx_pages_to_free_slots);
}
TEST_F(homa_tx_pool, homa_tx_pool_gc__limited_by_min_kb)
{
	EXPECT_EQ(0UL, self->homa.tx_page_free_time);
	mock_clock = 1000000;
	self->homa.tx_page_free_time = 500000;
	self->homa.tx_page_frees_per_sec = 20;
	self->homa.tx_page_pool_min_kb = (5 * HOMA_TX_PAGE_SIZE) / 1000;
	add_to_pool(&self->homa, 10, 0);
	get_tx_pool_core(0)->pool->low_mark = 9;

	homa_tx_pool_gc(&self->homa);
	EXPECT_EQ(6, get_tx_pool_core(0)->pool->avail);
}
TEST_F(homa_tx_pool, homa_tx_pool_gc__race_invalidates_max_low_mark)
{
	struct homa_tx_pool *tx_pool;

	tx_pool = get_tx_pool_core(0)->pool;
	EXPECT_EQ(0UL, self->homa.tx_page_free_time);
	mock_clock = 1000000;
	self->homa.tx_page_free_time = 500000;
	self->homa.tx_page_frees_per_sec = 6;
	self->homa.tx_page_pool_min_kb = 0;
	add_to_pool(&self->homa, 10, 0);
	tx_pool->low_mark = 10;
	hook_pool = tx_pool;
	unit_hook_register(page_race_hook);

	homa_tx_pool_gc(&self->homa);
	EXPECT_EQ(6, tx_pool->avail);
}
TEST_F(homa_tx_pool, homa_tx_pool_gc__empty_pool)
{
	EXPECT_EQ(0UL, self->homa.tx_page_free_time);
	mock_clock= 2000000;
	self->homa.tx_page_free_time = 500000;
	self->homa.tx_page_frees_per_sec = 1000;
	self->homa.tx_page_pool_min_kb = 0;
	add_to_pool(&self->homa, 5, 0);
	get_tx_pool_core(0)->pool->low_mark = 5;

	homa_tx_pool_gc(&self->homa);
	EXPECT_EQ(0, get_tx_pool_core(0)->pool->avail);
}
TEST_F(homa_tx_pool, homa_tx_pool_gc__min_kb_floor_no_overflow)
{
	/* homa_tx_pool_gc() converts the tx_page_pool_min_kb floor (an int, in
	 * KB) into a page count. Computing it as `min_kb * 1000` in 32-bit int
	 * overflows for large floors, yielding a bogus (often negative)
	 * min_pages and freeing pages that should have been kept. The floor
	 * must be computed in 64-bit.
	 *
	 * Table-driven: each row sets a floor and the resulting post-gc avail.
	 * The corner row's floor overflows a 32-bit `* 1000` but is harmless in
	 * 64-bit, so the pool must be left intact.
	 */
	static const struct {
		const char *name;
		int min_kb;		/* tx_page_pool_min_kb (floor, in KB) */
		int pages;		/* pages loaded into core 0's pool */
		int low_mark;
		int exp_avail;		/* expected avail after gc */
	} cases[] = {
		{"modest_floor_frees_down_to_floor",
			(5 * HOMA_TX_PAGE_SIZE) / 1000, 10, 9, 6},
		{"floor_exceeds_pool_frees_none",
			(50 * HOMA_TX_PAGE_SIZE) / 1000, 10, 10, 10},
		{"huge_floor_no_int_overflow",
			3000000, 10, 10, 10},
	};
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(cases); i++) {
		TH_LOG("case: %s", cases[i].name);

		homa_tx_pool_cleanup(&self->homa);
		EXPECT_EQ(0, homa_tx_pool_init(&self->homa));

		mock_clock = 1000000;
		self->homa.tx_page_free_time = 0;
		self->homa.tx_page_frees_per_sec = 20;
		self->homa.tx_page_pool_min_kb = cases[i].min_kb;

		add_to_pool(&self->homa, cases[i].pages, 0);
		get_tx_pool_core(0)->pool->low_mark = cases[i].low_mark;

		homa_tx_pool_gc(&self->homa);
		EXPECT_EQ(cases[i].exp_avail,
			  get_tx_pool_core(0)->pool->avail);
	}
}

TEST_F(homa_tx_pool, homa_copy_to_frags)
{
	struct homa_frag_filler filler;
	skb_frag_t frags[3];
	u8 data[1000];

	unit_fill_data(data, sizeof(data), 2000);
	unit_alloc_frags(3, frags, 100, 300, 0, 1000, 50, 60);
	homa_frag_filler_init(&filler, 3, frags);

	/** First copy: fill all of first frag, part of second. */
	EXPECT_EQ(0, homa_copy_to_frags(&filler, data, 500));
	EXPECT_EQ(&frags[1], filler.frag);
	EXPECT_EQ(2, filler.num_frags);
	EXPECT_EQ(200, filler.offset);
	unit_log_clear();
	unit_log_data("; ", unit_frag_first_byte(&frags[0]), 300);
	unit_log_data("; ", unit_frag_first_byte(&frags[1]), 200);
	EXPECT_STREQ("2000-2299; 2300-2499", unit_log_get());

	/** Second copy: fill remainder of second frag, all of third. */
	EXPECT_EQ(0, homa_copy_to_frags(&filler, data, 860));
	EXPECT_EQ(&frags[2], filler.frag);
	EXPECT_EQ(1, filler.num_frags);
	EXPECT_EQ(60, filler.offset);
	unit_log_clear();
	unit_log_data("; ", unit_frag_first_byte(&frags[0]), 300);
	unit_log_data("; ", unit_frag_first_byte(&frags[1]), 1000);
	unit_log_data("; ", unit_frag_first_byte(&frags[2]), 60);
	EXPECT_STREQ("2000-2299; 2300-2499 2000-2799; 2800-2859", unit_log_get());

	/** Third copy: no room in frags. */
	EXPECT_EQ(EINVAL, -homa_copy_to_frags(&filler, data, 1));

	homa_tx_pool_free(&self->homa, 3, frags);
}

TEST_F(homa_tx_pool, homa_copy_iter_to_frags)
{
	struct homa_frag_filler filler;
	struct iov_iter *iter;
	skb_frag_t frags[3];
	u8 data[1000];

	unit_fill_data(data, sizeof(data), 5000);
	iter = unit_iov_iter(data, sizeof(data));
	unit_alloc_frags(3, frags, 100, 300, 0, 1000, 50, 60);
	homa_frag_filler_init(&filler, 3, frags);

	/** First copy: fill all of first frag, part of second. */
	EXPECT_EQ(0, homa_copy_iter_to_frags(&filler, iter, 500));
	EXPECT_EQ(&frags[1], filler.frag);
	EXPECT_EQ(2, filler.num_frags);
	EXPECT_EQ(200, filler.offset);
	unit_log_clear();
	unit_log_data("; ", unit_frag_first_byte(&frags[0]), 300);
	unit_log_data("; ", unit_frag_first_byte(&frags[1]), 200);
	EXPECT_STREQ("5000-5299; 5300-5499", unit_log_get());

	/** Second copy: fill remainder of second frag, all of third. */
	iter = unit_iov_iter(data, sizeof(data));
	EXPECT_EQ(0, homa_copy_iter_to_frags(&filler, iter, 860));
	EXPECT_EQ(&frags[2], filler.frag);
	EXPECT_EQ(1, filler.num_frags);
	EXPECT_EQ(60, filler.offset);
	unit_log_clear();
	unit_log_data("; ", unit_frag_first_byte(&frags[0]), 300);
	unit_log_data("; ", unit_frag_first_byte(&frags[1]), 1000);
	unit_log_data("; ", unit_frag_first_byte(&frags[2]), 60);
	EXPECT_STREQ("5000-5299; 5300-5499 5000-5799; 5800-5859",
		     unit_log_get());

	/** Third copy: no room in frags. */
	EXPECT_EQ(EINVAL, -homa_copy_iter_to_frags(&filler, iter, 860));

	homa_tx_pool_free(&self->homa, 3, frags);
}
