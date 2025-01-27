// SPDX-License-Identifier: BSD-2-Clause

#include "homa_impl.h"
#include "homa_skb.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

static inline struct homa_skb_core *get_skb_core(int core)
{
	return &per_cpu(homa_skb_core, core);
}

/* Create an skb with 100 bytes of data in the header and frags of
 * 200, 300, and 400 bytes.
 */
static struct sk_buff *test_skb(struct homa *homa)
{
	struct homa_skb_core *skb_core = get_skb_core(smp_processor_id());
	struct sk_buff *skb = homa_skb_new_tx(100);
	int32_t data[1000];
	char *src;
	int i;

	for (i = 0; i < 1000; i++)
		data[i] = 1000000 + 4*i;
	src = (char *) data;
	memcpy(skb_put(skb, 100), src, 100);

	/* Make sure that the first skb fragment will have a nonzero offset
	 * within its page.
	 */
	homa_skb_page_alloc(homa, skb_core);
	skb_core->page_inuse = 100;

	homa_skb_append_to_frag(homa, skb, src + 100, 200);
	skb_core->page_inuse = skb_core->page_size;
	homa_skb_append_to_frag(homa, skb, src + 300, 300);
	skb_core->page_inuse = skb_core->page_size;
	homa_skb_append_to_frag(homa, skb, src + 600, 400);

	/* Add some data before the transport header, just to make sure
	 * that functions offset from the proper location.
	 */
	skb_push(skb, 8);
	return skb;
}

/* Add a given number of pages to the page pool for a given core. */
static void add_to_pool(struct homa *homa, int num_pages, int core)
{
	struct homa_page_pool *pool = get_skb_core(core)->pool;
	int i;

	for (i = 0; i < num_pages; i++) {
		pool->pages[pool->avail] = alloc_pages(GFP_KERNEL,
				HOMA_SKB_PAGE_ORDER);
		pool->avail++;
	}
}

static struct homa_page_pool *hook_pool;

/* Used to remove a page from hook_pool when a lock is acquired. */
static void spinlock_hook(char *id)
{
	if (strcmp(id, "spin_lock") != 0)
		return;
	if ((hook_pool == NULL) || (hook_pool->avail == 0))
		return;
	hook_pool->avail--;
	put_page(hook_pool->pages[hook_pool->avail]);
}

FIXTURE(homa_skb) {
	struct homa homa;
	struct sk_buff *skb;
};
FIXTURE_SETUP(homa_skb)
{
	homa_init(&self->homa);
	self->skb = alloc_skb_fclone(200, GFP_KERNEL);
	if (!self->skb)
		FAIL("unit_homa_skb setup couldn't allocate skb");
}
FIXTURE_TEARDOWN(homa_skb)
{
	kfree_skb(self->skb);
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_skb, homa_skb_init__success)
{
	homa_skb_cleanup(&self->homa);
	EXPECT_EQ(NULL, self->homa.page_pools[0]);
	mock_numa_mask = 0x83;
	EXPECT_EQ(0, homa_skb_init(&self->homa));
	EXPECT_NE(NULL, self->homa.page_pools[0]);
	EXPECT_NE(NULL, self->homa.page_pools[1]);
	EXPECT_EQ(NULL, self->homa.page_pools[2]);
	EXPECT_EQ(self->homa.page_pools[1], get_skb_core(0)->pool);
	EXPECT_EQ(self->homa.page_pools[1], get_skb_core(1)->pool);
	EXPECT_EQ(self->homa.page_pools[0], get_skb_core(2)->pool);
	EXPECT_EQ(self->homa.page_pools[0], get_skb_core(6)->pool);
	EXPECT_EQ(self->homa.page_pools[1], get_skb_core(7)->pool);
	EXPECT_EQ(1, self->homa.max_numa);
}
TEST_F(homa_skb, homa_skb_init__kmalloc_failure)
{
	homa_skb_cleanup(&self->homa);
	EXPECT_EQ(NULL, self->homa.page_pools[0]);
	mock_numa_mask = 0x2;
	mock_kmalloc_errors = 0x2;
	EXPECT_EQ(ENOMEM, -homa_skb_init(&self->homa));
	EXPECT_NE(NULL, self->homa.page_pools[0]);
	EXPECT_EQ(NULL, self->homa.page_pools[1]);
	EXPECT_EQ(NULL, self->homa.page_pools[2]);
}

TEST_F(homa_skb, homa_skb_cleanup)
{
	struct homa_skb_core *skb_core = get_skb_core(2);

	skb_core->skb_page = alloc_pages(GFP_KERNEL, 2);
	add_to_pool(&self->homa, 5, 2);
	add_to_pool(&self->homa, 4, 3);
	mock_set_core(3);
	homa_skb_stash_pages(&self->homa, 2 * HOMA_SKB_PAGE_SIZE - 100);
	EXPECT_EQ(5, get_skb_core(2)->pool->avail);
	EXPECT_EQ(2, get_skb_core(3)->pool->avail);
	EXPECT_EQ(2, get_skb_core(3)->num_stashed_pages);

	homa_skb_cleanup(&self->homa);
	EXPECT_EQ(NULL, skb_core->pool);
	EXPECT_EQ(NULL, skb_core->skb_page);
	EXPECT_EQ(0, get_skb_core(3)->num_stashed_pages);

	skb_core = get_skb_core(nr_cpu_ids-1);
	EXPECT_EQ(NULL, skb_core->pool);
}

TEST_F(homa_skb, homa_skb_stash_pages)
{
	int id = smp_processor_id();
	struct homa_skb_core *skb_core;

	skb_core = get_skb_core(id);
	add_to_pool(&self->homa, 5, id);
	EXPECT_EQ(5, skb_core->pool->avail);
	EXPECT_EQ(0, skb_core->num_stashed_pages);

	/* First attempt: message too small. */
	homa_skb_stash_pages(&self->homa, 10000);
	EXPECT_EQ(0, skb_core->num_stashed_pages);

	/* Second attempt: stash pages. */
	homa_skb_stash_pages(&self->homa, 3*HOMA_SKB_PAGE_SIZE - 100);
	EXPECT_EQ(3, skb_core->num_stashed_pages);
	EXPECT_EQ(2, skb_core->pool->avail);

	/* Third attempt: existing stash adequate. */
	homa_skb_stash_pages(&self->homa, 3 * HOMA_SKB_PAGE_SIZE - 100);
	EXPECT_EQ(3, skb_core->num_stashed_pages);

	/* Fourth attempt: not enough pages in pool. */
	homa_skb_stash_pages(&self->homa, 8 * HOMA_SKB_PAGE_SIZE - 100);
	EXPECT_EQ(5, skb_core->num_stashed_pages);
}

TEST_F(homa_skb, homa_skb_extend_frags__basics)
{
	struct homa_skb_core *skb_core = get_skb_core(smp_processor_id());
	char *p1, *p2, *p3;
	int length = 100;

	p1 = homa_skb_extend_frags(&self->homa, self->skb, &length);
	EXPECT_EQ(100, length);
	EXPECT_NE(NULL, p1);

	length = 200;
	p2 = homa_skb_extend_frags(&self->homa, self->skb, &length);
	EXPECT_EQ(200, length);
	EXPECT_EQ(p1 + 100, p2);

	length = 300;
	p3 = homa_skb_extend_frags(&self->homa, self->skb, &length);
	EXPECT_EQ(300, length);
	EXPECT_EQ(p2 + 200, p3);

	EXPECT_EQ(600, skb_core->page_inuse);
	EXPECT_EQ(600, self->skb->len);
}
TEST_F(homa_skb, homa_skb_extend_frags__merge_but_reduce_length)
{
	struct homa_skb_core *skb_core = get_skb_core(smp_processor_id());
	int length = 1000;
	char *p1, *p2;

	p1 = homa_skb_extend_frags(&self->homa, self->skb, &length);
	EXPECT_EQ(1000, length);
	EXPECT_NE(NULL, p1);

	skb_core->page_size = 2048;
	length = 2000;
	p2 = homa_skb_extend_frags(&self->homa, self->skb, &length);
	EXPECT_EQ(1048, length);
	EXPECT_EQ(p1 + 1000, p2);

	EXPECT_EQ(2048, skb_core->page_inuse);
}
TEST_F(homa_skb, homa_skb_extend_frags__cant_merge_allocate_new_page)
{
	struct homa_skb_core *skb_core = get_skb_core(smp_processor_id());
	struct sk_buff *skb2 = alloc_skb_fclone(200, GFP_KERNEL);
	char *p1, *p2, *p3;
	int length;

	ASSERT_NE(NULL, skb2);
	length = 1000;
	p1 = homa_skb_extend_frags(&self->homa, self->skb, &length);
	EXPECT_EQ(1000, length);
	EXPECT_NE(NULL, p1);
	EXPECT_EQ(1000, self->skb->len);

	skb_core->page_size = 2048;
	length = 1000;
	p2 = homa_skb_extend_frags(&self->homa, skb2, &length);
	EXPECT_EQ(1000, length);
	EXPECT_EQ(p1 + 1024, p2);
	EXPECT_EQ(1000, skb2->len);

	length = 1000;
	p3 = homa_skb_extend_frags(&self->homa, self->skb, &length);
	EXPECT_NE(NULL, p3);
	EXPECT_EQ(1000, length);
	EXPECT_EQ(2, skb_shinfo(self->skb)->nr_frags);
	EXPECT_EQ(0, skb_shinfo(self->skb)->frags[1].offset);
	EXPECT_EQ(2000, self->skb->len);

	EXPECT_EQ(1000, skb_core->page_inuse);
	kfree_skb(skb2);
}
TEST_F(homa_skb, homa_skb_extend_frags__cant_merge_use_same_page_reduce_length)
{
	struct homa_skb_core *skb_core = get_skb_core(smp_processor_id());
	struct sk_buff *skb2 = alloc_skb_fclone(200, GFP_KERNEL);
	char *p1, *p2, *p3;
	int length;

	ASSERT_NE(NULL, skb2);
	length = 1000;
	p1 = homa_skb_extend_frags(&self->homa, self->skb, &length);
	EXPECT_EQ(1000, length);
	EXPECT_NE(NULL, p1);

	skb_core->page_size = 2048;
	length = 500;
	p2 = homa_skb_extend_frags(&self->homa, skb2, &length);
	EXPECT_EQ(500, length);
	EXPECT_EQ(p1 + 1024, p2);

	length = 2000;
	p3 = homa_skb_extend_frags(&self->homa, self->skb, &length);
	EXPECT_EQ(p2 + 512, p3);
	EXPECT_EQ(512, length);
	EXPECT_EQ(2, skb_shinfo(self->skb)->nr_frags);
	EXPECT_EQ(1536, skb_shinfo(self->skb)->frags[1].offset);

	EXPECT_EQ(2048, skb_core->page_inuse);
	kfree_skb(skb2);
}

TEST_F(homa_skb, homa_skb_page_alloc__free_previous_page)
{
	struct homa_skb_core *skb_core = get_skb_core(2);
	struct page *old_page;

	EXPECT_TRUE(homa_skb_page_alloc(&self->homa, skb_core));
	EXPECT_NE(NULL, skb_core->skb_page);
	old_page = skb_core->skb_page;
	get_page(old_page);
	EXPECT_EQ(2, mock_page_refs(old_page));
	EXPECT_TRUE(homa_skb_page_alloc(&self->homa, skb_core));
	EXPECT_NE(NULL, skb_core->skb_page);
	EXPECT_NE(old_page, skb_core->skb_page);
	EXPECT_EQ(1, mock_page_refs(old_page));
	put_page(old_page);
}
TEST_F(homa_skb, homa_skb_page_alloc__reuse_existing_page)
{
	struct homa_skb_core *skb_core = get_skb_core(smp_processor_id());
	struct sk_buff *skb = homa_skb_new_tx(100);
	struct page *page;
	int length = 100;

	homa_skb_extend_frags(&self->homa, skb, &length);
	EXPECT_EQ(100, skb_core->page_inuse);
	page = skb_core->skb_page;

	homa_skb_free_tx(&self->homa, skb);
	EXPECT_EQ(1, page_ref_count(skb_core->skb_page));
	EXPECT_TRUE(homa_skb_page_alloc(&self->homa, skb_core));
	EXPECT_EQ(page, skb_core->skb_page);
	EXPECT_EQ(0, skb_core->page_inuse);
}
TEST_F(homa_skb, homa_skb_page_alloc__from_stash)
{
	struct homa_skb_core *skb_core = get_skb_core(smp_processor_id());

	add_to_pool(&self->homa, 5, smp_processor_id());
	homa_skb_stash_pages(&self->homa, 3*HOMA_SKB_PAGE_SIZE - 100);
	EXPECT_TRUE(homa_skb_page_alloc(&self->homa, skb_core));
	EXPECT_NE(NULL, skb_core->skb_page);
	EXPECT_EQ(HOMA_SKB_PAGE_SIZE, skb_core->page_size);
	EXPECT_EQ(0, skb_core->page_inuse);
	EXPECT_EQ(2, skb_core->num_stashed_pages);
}
TEST_F(homa_skb, homa_skb_page_alloc__from_pool)
{
	struct homa_skb_core *skb_core = get_skb_core(smp_processor_id());

	add_to_pool(&self->homa, 5, smp_processor_id());
	EXPECT_EQ(5, skb_core->pool->avail);
	EXPECT_EQ(0, skb_core->num_stashed_pages);
	EXPECT_TRUE(homa_skb_page_alloc(&self->homa, skb_core));
	EXPECT_NE(NULL, skb_core->skb_page);
	EXPECT_EQ(4, skb_core->pool->avail);
}
TEST_F(homa_skb, homa_skb_page_alloc__pool_page_taken_while_locking)
{
	struct homa_skb_core *skb_core = get_skb_core(smp_processor_id());

	add_to_pool(&self->homa, 1, smp_processor_id());
	EXPECT_EQ(1, skb_core->pool->avail);
	EXPECT_EQ(0, skb_core->num_stashed_pages);
	hook_pool = skb_core->pool;
	unit_hook_register(spinlock_hook);
	mock_alloc_page_errors = 3;

	EXPECT_FALSE(homa_skb_page_alloc(&self->homa, skb_core));
	EXPECT_EQ(NULL, skb_core->skb_page);
	EXPECT_EQ(0, skb_core->pool->avail);
}
TEST_F(homa_skb, homa_skb_page_alloc__new_large_page)
{
	struct homa_skb_core *skb_core = get_skb_core(smp_processor_id());

	mock_ns_tick = 100;
	EXPECT_EQ(0, skb_core->pool->avail);
	EXPECT_EQ(0, skb_core->num_stashed_pages);
	EXPECT_TRUE(homa_skb_page_alloc(&self->homa, skb_core));
	EXPECT_NE(NULL, skb_core->skb_page);
	EXPECT_EQ(HOMA_SKB_PAGE_SIZE, skb_core->page_size);
	EXPECT_EQ(1, homa_metrics_per_cpu()->skb_page_allocs);
	EXPECT_EQ(100, homa_metrics_per_cpu()->skb_page_alloc_ns);
}
TEST_F(homa_skb, homa_skb_page_alloc__high_order_page_not_available)
{
	struct homa_skb_core *skb_core = get_skb_core(2);

	mock_ns_tick = 50;
	mock_alloc_page_errors = 1;
	EXPECT_TRUE(homa_skb_page_alloc(&self->homa, skb_core));
	EXPECT_NE(NULL, skb_core->skb_page);
	EXPECT_NE(NULL, skb_core->skb_page);
	EXPECT_EQ(PAGE_SIZE, skb_core->page_size);
	EXPECT_EQ(0, skb_core->page_inuse);
	EXPECT_EQ(1, homa_metrics_per_cpu()->skb_page_allocs);
	EXPECT_EQ(50, homa_metrics_per_cpu()->skb_page_alloc_ns);
}
TEST_F(homa_skb, homa_skb_page_alloc__no_pages_available)
{
	struct homa_skb_core *skb_core = get_skb_core(2);

	mock_alloc_page_errors = 3;
	EXPECT_FALSE(homa_skb_page_alloc(&self->homa, skb_core));
	EXPECT_EQ(NULL, skb_core->skb_page);
}

TEST_F(homa_skb, homa_skb_append_to_frag__basics)
{
	struct homa_skb_core *skb_core = get_skb_core(smp_processor_id());
	struct skb_shared_info *shinfo = skb_shinfo(self->skb);
	char *p;

	/* First append fits in a single block. */
	EXPECT_EQ(0, homa_skb_append_to_frag(&self->homa, self->skb, "abcd", 4));

	/* Second append spills into a new frag. */
	skb_core->page_size = 10;
	EXPECT_EQ(0, homa_skb_append_to_frag(&self->homa, self->skb,
			"0123456789ABCDEFGHIJ", 21));

	EXPECT_EQ(2, shinfo->nr_frags);
	EXPECT_EQ(10, skb_frag_size(&shinfo->frags[0]));
	p = ((char *) page_address(skb_frag_page(&shinfo->frags[0])))
			+ shinfo->frags[0].offset;
	p[skb_frag_size(&shinfo->frags[0])] = 0;
	EXPECT_STREQ("abcd012345", p);

	EXPECT_EQ(15, skb_frag_size(&shinfo->frags[1]));
	p = ((char *) page_address(skb_frag_page(&shinfo->frags[1])))
			+ shinfo->frags[1].offset;
	EXPECT_STREQ("6789ABCDEFGHIJ", p);
}
TEST_F(homa_skb, homa_skb_append_to_frag__no_memory)
{
	mock_alloc_page_errors = 3;
	EXPECT_EQ(ENOMEM, -homa_skb_append_to_frag(&self->homa, self->skb,
			"abcd", 4));
}

TEST_F(homa_skb, homa_skb_append_from_iter__basics)
{
	struct homa_skb_core *skb_core = get_skb_core(smp_processor_id());
	struct iov_iter *iter = unit_iov_iter((void *) 1000, 5000);
	struct skb_shared_info *shinfo = skb_shinfo(self->skb);

	/* First append fits in a single block. */
	unit_log_clear();
	EXPECT_EQ(0, homa_skb_append_from_iter(&self->homa, self->skb, iter,
			2000));
	EXPECT_STREQ("_copy_from_iter 2000 bytes at 1000",
			unit_log_get());

	/* Second append spills into a new frag. */
	skb_core->page_size = 4096;
	unit_log_clear();
	EXPECT_EQ(0, homa_skb_append_from_iter(&self->homa, self->skb, iter,
			3000));
	EXPECT_STREQ("_copy_from_iter 2096 bytes at 3000; "
			"_copy_from_iter 904 bytes at 5096",
			unit_log_get());

	EXPECT_EQ(2, shinfo->nr_frags);
	EXPECT_EQ(4096, skb_frag_size(&shinfo->frags[0]));
	EXPECT_EQ(904, skb_frag_size(&shinfo->frags[1]));
}
TEST_F(homa_skb, homa_skb_append_from_iter__no_memory)
{
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);

	mock_alloc_page_errors = 3;
	EXPECT_EQ(ENOMEM, -homa_skb_append_from_iter(&self->homa, self->skb,
			iter, 2000));
}

TEST_F(homa_skb, homa_skb_append_from_skb__header_only)
{
	struct sk_buff *src_skb = test_skb(&self->homa);
	struct sk_buff *dst_skb = homa_skb_new_tx(100);
	int32_t data[500];

	EXPECT_EQ(0, homa_skb_append_from_skb(&self->homa, dst_skb, src_skb,
			20, 60));
	memset(data, 0, sizeof(data));
	homa_skb_get(dst_skb, data, 0, 60);
	EXPECT_EQ(1000020, data[0]);
	EXPECT_EQ(1000076, data[14]);

	kfree_skb(src_skb);
	kfree_skb(dst_skb);
}
TEST_F(homa_skb, homa_skb_append_from_skb__error_copying_header)
{
	struct homa_skb_core *skb_core = get_skb_core(smp_processor_id());
	struct sk_buff *src_skb = test_skb(&self->homa);
	struct sk_buff *dst_skb = homa_skb_new_tx(100);

	mock_alloc_page_errors = -1;
	skb_core->page_inuse = skb_core->page_size;
	EXPECT_EQ(ENOMEM, -homa_skb_append_from_skb(&self->homa, dst_skb,
			src_skb, 20, 60));

	kfree_skb(src_skb);
	kfree_skb(dst_skb);
}
TEST_F(homa_skb, homa_skb_append_from_skb__header_and_first_frag)
{
	struct sk_buff *src_skb = test_skb(&self->homa);
	struct sk_buff *dst_skb = homa_skb_new_tx(100);
	struct skb_shared_info *dst_shinfo;
	int32_t data[500];

	dst_shinfo = skb_shinfo(dst_skb);
	EXPECT_EQ(0, homa_skb_append_from_skb(&self->homa, dst_skb, src_skb,
			80, 100));
	memset(data, 0, sizeof(data));
	homa_skb_get(dst_skb, data, 0, 100);
	EXPECT_EQ(1000080, data[0]);
	EXPECT_EQ(1000176, data[24]);
	EXPECT_EQ(2, dst_shinfo->nr_frags);
	EXPECT_EQ(100, dst_skb->len);

	kfree_skb(src_skb);
	kfree_skb(dst_skb);
}
TEST_F(homa_skb, homa_skb_append_from_skb__multiple_frags)
{
	struct sk_buff *src_skb = test_skb(&self->homa);
	struct sk_buff *dst_skb = homa_skb_new_tx(100);
	struct skb_shared_info *dst_shinfo;
	int32_t data[500];

	dst_shinfo = skb_shinfo(dst_skb);
	EXPECT_EQ(0, homa_skb_append_from_skb(&self->homa, dst_skb, src_skb,
			320, 600));
	memset(data, 0, sizeof(data));
	homa_skb_get(dst_skb, data, 0, 600);
	EXPECT_EQ(1000320, data[0]);
	EXPECT_EQ(1000916, data[149]);
	EXPECT_EQ(2, dst_shinfo->nr_frags);
	EXPECT_EQ(600, dst_skb->len);

	kfree_skb(src_skb);
	kfree_skb(dst_skb);
}
TEST_F(homa_skb, homa_skb_append_from_skb__dst_runs_out_of_frags)
{
	struct sk_buff *src_skb = test_skb(&self->homa);
	struct sk_buff *dst_skb = homa_skb_new_tx(100);
	struct skb_shared_info *dst_shinfo;
	int i, err;

	dst_shinfo = skb_shinfo(dst_skb);
	mock_max_skb_frags = 4;
	for (i = 0; i < 10; i++) {
		err = homa_skb_append_from_skb(&self->homa, dst_skb, src_skb,
				320, 40);
		if (err)
			break;
	}
	EXPECT_EQ(4, i);
	EXPECT_EQ(EINVAL, -err);
	EXPECT_EQ(4, dst_shinfo->nr_frags);

	kfree_skb(src_skb);
	kfree_skb(dst_skb);
}

TEST_F(homa_skb, homa_skb_free_many_tx__basics)
{
	struct sk_buff *skbs[2];
	int i, length;

	skbs[0] = homa_skb_new_tx(100);
	for (i = 0; i < 3; i++) {
		length = 2*HOMA_SKB_PAGE_SIZE;
		homa_skb_extend_frags(&self->homa, skbs[0], &length);
	}
	EXPECT_EQ(HOMA_SKB_PAGE_SIZE, length);

	skbs[1] = homa_skb_new_tx(100);
	length = 2 * HOMA_SKB_PAGE_SIZE;
	homa_skb_extend_frags(&self->homa, skbs[1], &length);

	homa_skb_free_many_tx(&self->homa, skbs, 2);
	EXPECT_EQ(3, self->homa.page_pools[0]->avail);
}
TEST_F(homa_skb, homa_skb_free_many_tx__skb_ref_count_not_one)
{
	struct sk_buff *skb;
	struct page *page;
	int length;

	skb = homa_skb_new_tx(100);
	length = HOMA_SKB_PAGE_SIZE;
	homa_skb_extend_frags(&self->homa, skb, &length);
	EXPECT_EQ(HOMA_SKB_PAGE_SIZE, length);
	page = skb_frag_page(&skb_shinfo(skb)->frags[0]);
	EXPECT_EQ(2, page_ref_count(page));
	skb_get(skb);
	EXPECT_EQ(2, refcount_read(&skb->users));

	homa_skb_free_many_tx(&self->homa, &skb, 1);
	EXPECT_EQ(2, page_ref_count(page));
	EXPECT_EQ(1, refcount_read(&skb->users));
	kfree_skb(skb);
}
TEST_F(homa_skb, homa_skb_free_many_tx__check_page_order)
{
	struct sk_buff *skb;
	int i, length;

	skb = homa_skb_new_tx(100);
	for (i = 0; i < 4; i++) {
		length = 2 * HOMA_SKB_PAGE_SIZE;
		homa_skb_extend_frags(&self->homa, skb, &length);
	}
	EXPECT_EQ(HOMA_SKB_PAGE_SIZE, length);
	struct page *page = skb_frag_page(&skb_shinfo(skb)->frags[2]);

	mock_compound_order_mask = 3;
	homa_skb_free_many_tx(&self->homa, &skb, 1);
	EXPECT_EQ(1, self->homa.page_pools[0]->avail);
	EXPECT_EQ(page, self->homa.page_pools[0]->pages[0]);
}

TEST_F(homa_skb, homa_skb_cache_pages__different_numa_nodes)
{
	struct page *pages[4];
	int i;

	for (i = 0; i < 4; i++)
		pages[i] = alloc_pages(GFP_KERNEL, HOMA_SKB_PAGE_ORDER);
	mock_page_nid_mask = 7;
	homa_skb_cache_pages(&self->homa, pages, 4);
	EXPECT_EQ(1, self->homa.page_pools[0]->avail);
	EXPECT_EQ(3, self->homa.page_pools[1]->avail);
	EXPECT_EQ(pages[3], self->homa.page_pools[0]->pages[0]);
	EXPECT_EQ(pages[1], self->homa.page_pools[1]->pages[1]);
}
TEST_F(homa_skb, homa_skb_cache_pages__pool_size_exceeded)
{
	struct page *pages[6];
	int i;

	for (i = 0; i < 6; i++)
		pages[i] = alloc_pages(GFP_KERNEL, HOMA_SKB_PAGE_ORDER);
	homa_skb_cache_pages(&self->homa, pages, 4);
	EXPECT_EQ(4, self->homa.page_pools[0]->avail);
	put_page(pages[4]);
	put_page(pages[5]);
}

TEST_F(homa_skb, homa_skb_get)
{
	struct sk_buff *skb = test_skb(&self->homa);
	int32_t data[500];

	/* Data is entirely in the head. */
	memset(data, 0, sizeof(data));
	homa_skb_get(skb, data, 20, 40);
	EXPECT_EQ(1000020, data[0]);
	EXPECT_EQ(1000056, data[9]);
	EXPECT_EQ(0, data[10]);

	/* Data spans head and first frag. */
	memset(data, 0, sizeof(data));
	homa_skb_get(skb, data, 80, 60);
	EXPECT_EQ(1000080, data[0]);
	EXPECT_EQ(1000096, data[4]);
	EXPECT_EQ(1000100, data[5]);
	EXPECT_EQ(1000136, data[14]);
	EXPECT_EQ(0, data[15]);

	/* Data spans 3 frags. */
	memset(data, 0, sizeof(data));
	homa_skb_get(skb, data, 280, 500);
	EXPECT_EQ(1000280, data[0]);
	EXPECT_EQ(1000296, data[4]);
	EXPECT_EQ(1000300, data[5]);
	EXPECT_EQ(1000596, data[79]);
	EXPECT_EQ(1000600, data[80]);
	EXPECT_EQ(1000776, data[124]);
	EXPECT_EQ(0, data[125]);

	/* Data extends past end of skb. */
	memset(data, 0, sizeof(data));
	homa_skb_get(skb, data, 960, 100);
	EXPECT_EQ(1000960, data[0]);
	EXPECT_EQ(1000996, data[9]);
	EXPECT_EQ(0, data[10]);

	kfree_skb(skb);
}

TEST_F(homa_skb, homa_skb_release_pages__basics)
{
	EXPECT_EQ(0UL, self->homa.skb_page_free_time);
	mock_ns = 1000000;
	self->homa.skb_page_free_time = 500000;
	self->homa.skb_page_frees_per_sec = 10;
	self->homa.skb_page_pool_min_kb = 0;
	add_to_pool(&self->homa, 10, 0);
	get_skb_core(0)->pool->low_mark = 7;
	add_to_pool(&self->homa, 3, 1);
	get_skb_core(1)->pool->low_mark = 2;

	homa_skb_release_pages(&self->homa);
	EXPECT_EQ(5, get_skb_core(0)->pool->avail);
	EXPECT_EQ(3, get_skb_core(1)->pool->avail);
	EXPECT_EQ(501000000UL, self->homa.skb_page_free_time);
}
TEST_F(homa_skb, homa_skb_release_pages__not_time_to_free)
{
	EXPECT_EQ(0UL, self->homa.skb_page_free_time);
	mock_ns = 1000000;
	self->homa.skb_page_free_time = 1000001;
	self->homa.skb_page_frees_per_sec = 10;
	self->homa.skb_page_pool_min_kb = 0;
	add_to_pool(&self->homa, 10, 0);
	get_skb_core(0)->pool->low_mark = 7;
	homa_skb_release_pages(&self->homa);
	EXPECT_EQ(10, get_skb_core(0)->pool->avail);
}
TEST_F(homa_skb, homa_skb_release_pages__allocate_skb_pages_to_free)
{
	EXPECT_EQ(0, self->homa.pages_to_free_slots);
	mock_ns= 1000000;
	self->homa.skb_page_frees_per_sec = 10;
	self->homa.skb_page_free_time = 500000;

	/* First call: no current allocation. */
	homa_skb_release_pages(&self->homa);
	EXPECT_EQ(5, self->homa.pages_to_free_slots);

	/* Second call: free current allocation. */
	self->homa.pages_to_free_slots -= 1;
	self->homa.skb_page_free_time = 500000;
	homa_skb_release_pages(&self->homa);
	EXPECT_EQ(5, self->homa.pages_to_free_slots);
}
TEST_F(homa_skb, homa_skb_release_pages__cant_reallocate_skb_pages_to_free)
{
	struct homa_page_pool *pool;

	EXPECT_EQ(0UL, self->homa.skb_page_free_time);
	mock_ns = 1000000;
	self->homa.skb_page_free_time = 500000;
	self->homa.skb_page_frees_per_sec = 20;
	self->homa.skb_page_pool_min_kb = 0;
	add_to_pool(&self->homa, 20, 0);
	pool = get_skb_core(0)->pool;
	pool->low_mark = 15;

	EXPECT_EQ(0, self->homa.pages_to_free_slots);
	self->homa.skb_pages_to_free = kmalloc_array(4, sizeof(struct page *),
						     GFP_ATOMIC);
	self->homa.pages_to_free_slots = 4;

	mock_kmalloc_errors = 1;
	homa_skb_release_pages(&self->homa);
	EXPECT_EQ(16, get_skb_core(0)->pool->avail);
	EXPECT_EQ(4, self->homa.pages_to_free_slots);
}
TEST_F(homa_skb, homa_skb_release_pages__limited_by_min_kb)
{
	EXPECT_EQ(0UL, self->homa.skb_page_free_time);
	mock_ns = 1000000;
	self->homa.skb_page_free_time = 500000;
	self->homa.skb_page_frees_per_sec = 20;
	self->homa.skb_page_pool_min_kb = (5 * HOMA_SKB_PAGE_SIZE) / 1000;
	add_to_pool(&self->homa, 10, 0);
	get_skb_core(0)->pool->low_mark = 9;

	homa_skb_release_pages(&self->homa);
	EXPECT_EQ(6, get_skb_core(0)->pool->avail);
}
TEST_F(homa_skb, homa_skb_release_pages__empty_pool)
{
	EXPECT_EQ(0UL, self->homa.skb_page_free_time);
	mock_ns= 2000000;
	self->homa.skb_page_free_time = 500000;
	self->homa.skb_page_frees_per_sec = 1000;
	self->homa.skb_page_pool_min_kb = 0;
	add_to_pool(&self->homa, 5, 0);
	get_skb_core(0)->pool->low_mark = 5;

	homa_skb_release_pages(&self->homa);
	EXPECT_EQ(0, get_skb_core(0)->pool->avail);
}
