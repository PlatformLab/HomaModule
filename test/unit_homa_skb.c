/* Copyright (c) 2022-2023 Homa Developers
 * SPDX-License-Identifier: BSD-1-Clause
 */

#include "homa_impl.h"
#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

/* Create an skb with 100 bytes of data in the header and frags of
 * 200, 300, and 400 bytes.
 */
static struct sk_buff *test_skb(void)
{
	struct sk_buff *skb = homa_skb_new(200);
	struct homa_core *core = homa_cores[raw_smp_processor_id()];

	int32_t data[1000];
	char *src;
	int i;

	for (i = 0; i < 1000; i++)
		data[i] = 1000000 + 4*i;
	src = (char *) data;
	skb_reserve(skb, 100);
	memcpy(skb_put(skb, 100), src, 100);

	/* Make sure that the first skb fragment will have a nonzero offset
	 * within its page.
	 */
	homa_skb_page_alloc(core);
	core->page_inuse = 100;

	homa_skb_append_to_frag(skb, src + 100, 200);
	core->page_inuse = core->page_size;
	homa_skb_append_to_frag(skb, src + 300, 300);
	core->page_inuse = core->page_size;
	homa_skb_append_to_frag(skb, src + 600, 400);
	return skb;
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

TEST_F(homa_skb, homa_skb_cleanup)
{
	struct homa_core *core = homa_cores[2];
	core->skb_page = alloc_pages(GFP_KERNEL, 2);
	homa_skb_cleanup(&self->homa);
	EXPECT_EQ(NULL, core->skb_page);
}

TEST_F(homa_skb, homa_skb_extend_frags__basics)
{
	struct homa_core *core = homa_cores[raw_smp_processor_id()];
	int length = 100;
	char *p1 = homa_skb_extend_frags(self->skb, &length);
	EXPECT_EQ(100, length);
	EXPECT_NE(NULL, p1);

	length = 200;
	char *p2 = homa_skb_extend_frags(self->skb, &length);
	EXPECT_EQ(200, length);
	EXPECT_EQ(p1 + 100, p2);

	length = 300;
	char *p3 = homa_skb_extend_frags(self->skb, &length);
	EXPECT_EQ(300, length);
	EXPECT_EQ(p2 + 200, p3);

	EXPECT_EQ(600, core->page_inuse);
	EXPECT_EQ(600, self->skb->len);
}
TEST_F(homa_skb, homa_skb_extend_frags__merge_but_reduce_length)
{
	struct homa_core *core = homa_cores[raw_smp_processor_id()];
	int length = 1000;
	char *p1 = homa_skb_extend_frags(self->skb, &length);
	EXPECT_EQ(1000, length);
	EXPECT_NE(NULL, p1);

	core->page_size = 2048;
	length = 2000;
	char *p2 = homa_skb_extend_frags(self->skb, &length);
	EXPECT_EQ(1048, length);
	EXPECT_EQ(p1 + 1000, p2);

	EXPECT_EQ(2048, core->page_inuse);
}
TEST_F(homa_skb, homa_skb_extend_frags__cant_merge_allocate_new_page)
{
	struct homa_core *core = homa_cores[raw_smp_processor_id()];
	struct sk_buff *skb2 = alloc_skb_fclone(200, GFP_KERNEL);
	ASSERT_NE(NULL, skb2);

	int length = 1000;
	char *p1 = homa_skb_extend_frags(self->skb, &length);
	EXPECT_EQ(1000, length);
	EXPECT_NE(NULL, p1);
	EXPECT_EQ(1000, self->skb->len);

	core->page_size = 2048;
	length = 1000;
	char *p2 = homa_skb_extend_frags(skb2, &length);
	EXPECT_EQ(1000, length);
	EXPECT_EQ(p1 + 1024, p2);
	EXPECT_EQ(1000, skb2->len);

	length = 1000;
	char *p3 = homa_skb_extend_frags(self->skb, &length);
	EXPECT_NE(NULL, p3);
	EXPECT_EQ(1000, length);
	EXPECT_EQ(2, skb_shinfo(self->skb)->nr_frags);
	EXPECT_EQ(0, skb_shinfo(self->skb)->frags[1].bv_offset);
	EXPECT_EQ(2000, self->skb->len);

	EXPECT_EQ(1000, core->page_inuse);
	kfree_skb(skb2);
}
TEST_F(homa_skb, homa_skb_extend_frags__cant_merge_use_same_page_reduce_length)
{
	struct homa_core *core = homa_cores[raw_smp_processor_id()];
	struct sk_buff *skb2 = alloc_skb_fclone(200, GFP_KERNEL);
	ASSERT_NE(NULL, skb2);

	int length = 1000;
	char *p1 = homa_skb_extend_frags(self->skb, &length);
	EXPECT_EQ(1000, length);
	EXPECT_NE(NULL, p1);

	core->page_size = 2048;
	length = 500;
	char *p2 = homa_skb_extend_frags(skb2, &length);
	EXPECT_EQ(500, length);
	EXPECT_EQ(p1 + 1024, p2);

	length = 2000;
	char *p3 = homa_skb_extend_frags(self->skb, &length);
	EXPECT_EQ(p2 + 512, p3);
	EXPECT_EQ(512, length);
	EXPECT_EQ(2, skb_shinfo(self->skb)->nr_frags);
	EXPECT_EQ(1536, skb_shinfo(self->skb)->frags[1].bv_offset);

	EXPECT_EQ(2048, core->page_inuse);
	kfree_skb(skb2);
}

TEST_F(homa_skb, homa_skb_page_alloc__basics)
{
	struct homa_core *core = homa_cores[2];
	mock_cycles = ~0;
	EXPECT_TRUE(homa_skb_page_alloc(core));
	EXPECT_NE(NULL, core->skb_page);
	EXPECT_EQ(PAGE_SIZE << HOMA_SKB_PAGE_ORDER, core->page_size);
	EXPECT_EQ(0, core->page_inuse);
	EXPECT_EQ(1, homa_cores[cpu_number]->metrics.skb_page_allocs);
	EXPECT_NE(0, homa_cores[cpu_number]->metrics.skb_page_alloc_cycles);
}
TEST_F(homa_skb, homa_skb_page_alloc__free_previous_page)
{
	struct homa_core *core = homa_cores[2];
	struct page *old_page;
	EXPECT_TRUE(homa_skb_page_alloc(core));
	EXPECT_NE(NULL, core->skb_page);
	old_page = core->skb_page;
	EXPECT_EQ(1, mock_page_refs(old_page));
	EXPECT_TRUE(homa_skb_page_alloc(core));
	EXPECT_NE(NULL, core->skb_page);
	EXPECT_NE(old_page, core->skb_page);
	EXPECT_EQ(0, mock_page_refs(old_page));
}
TEST_F(homa_skb, homa_skb_page_alloc__high_order_page_not_available)
{
	struct homa_core *core = homa_cores[2];
	mock_alloc_page_errors = 1;
	EXPECT_TRUE(homa_skb_page_alloc(core));
	EXPECT_NE(NULL, core->skb_page);
	EXPECT_NE(NULL, core->skb_page);
	EXPECT_EQ(PAGE_SIZE, core->page_size);
	EXPECT_EQ(0, core->page_inuse);
}
TEST_F(homa_skb, homa_skb_page_alloc__no_pages_available)
{
	struct homa_core *core = homa_cores[2];
	mock_alloc_page_errors = 3;
	EXPECT_FALSE(homa_skb_page_alloc(core));
	EXPECT_EQ(NULL, core->skb_page);
}

TEST_F(homa_skb, homa_skb_append_to_frag__basics)
{
	struct homa_core *core = homa_cores[raw_smp_processor_id()];
	struct skb_shared_info *shinfo = skb_shinfo(self->skb);

	/* First append fits in a single block. */
	EXPECT_EQ(0, homa_skb_append_to_frag(self->skb, "abcd", 4));

	/* Second append spills into a new frag. */
	core->page_size = 10;
	EXPECT_EQ(0, homa_skb_append_to_frag(self->skb, "0123456789ABCDEFGHIJ",
			21));

	EXPECT_EQ(2, shinfo->nr_frags);
	EXPECT_EQ(10, shinfo->frags[0].bv_len);
	char *p = ((char *) page_address(shinfo->frags[0].bv_page))
			+ shinfo->frags[0].bv_offset;
	p[shinfo->frags[0].bv_len] = 0;
	EXPECT_STREQ("abcd012345", p);

	EXPECT_EQ(15, shinfo->frags[1].bv_len);
	p = ((char *) page_address(shinfo->frags[1].bv_page))
			+ shinfo->frags[1].bv_offset;
	EXPECT_STREQ("6789ABCDEFGHIJ", p);
}
TEST_F(homa_skb, homa_skb_append_to_frag__no_memory)
{
	mock_alloc_page_errors = 3;
	EXPECT_EQ(ENOMEM, -homa_skb_append_to_frag(self->skb, "abcd", 4));
}

TEST_F(homa_skb, homa_skb_append_from_iter__basics)
{
	struct homa_core *core = homa_cores[raw_smp_processor_id()];
	struct skb_shared_info *shinfo = skb_shinfo(self->skb);
	struct iov_iter *iter = unit_iov_iter((void *) 1000, 5000);

	/* First append fits in a single block. */
	unit_log_clear();
	EXPECT_EQ(0, homa_skb_append_from_iter(self->skb, iter, 2000));
	EXPECT_STREQ("_copy_from_iter 2000 bytes at 1000",
		     	unit_log_get());

	/* Second append spills into a new frag. */
	core->page_size = 4096;
	unit_log_clear();
	EXPECT_EQ(0, homa_skb_append_from_iter(self->skb, iter, 3000));
	EXPECT_STREQ("_copy_from_iter 2096 bytes at 3000; "
			"_copy_from_iter 904 bytes at 5096",
		     	unit_log_get());

	EXPECT_EQ(2, shinfo->nr_frags);
	EXPECT_EQ(4096, shinfo->frags[0].bv_len);
	EXPECT_EQ(904, shinfo->frags[1].bv_len);
}
TEST_F(homa_skb, homa_skb_append_from_iter__no_memory)
{
	struct iov_iter *iter = unit_iov_iter((void *)1000, 5000);
	mock_alloc_page_errors = 3;
	EXPECT_EQ(ENOMEM, -homa_skb_append_from_iter(self->skb, iter, 2000));
}

TEST_F(homa_skb, homa_skb_append_from_skb__header_only)
{
	struct sk_buff *src_skb = test_skb();
	struct sk_buff *dst_skb = homa_skb_new(100);
	int32_t data[500];

	EXPECT_EQ(0, homa_skb_append_from_skb(dst_skb, src_skb, 20, 60));
	memset(data, 0, sizeof(data));
	homa_skb_get(dst_skb, data, 0, 60);
	EXPECT_EQ(1000020, data[0]);
	EXPECT_EQ(1000076, data[14]);

	kfree_skb(src_skb);
	kfree_skb(dst_skb);
}
TEST_F(homa_skb, homa_skb_append_from_skb__error_copying_header)
{
	struct sk_buff *src_skb = test_skb();
	struct sk_buff *dst_skb = homa_skb_new(100);
	struct homa_core *core = homa_cores[raw_smp_processor_id()];

	mock_alloc_page_errors = -1;
	core->page_inuse = core->page_size;
	EXPECT_EQ(ENOMEM, -homa_skb_append_from_skb(dst_skb, src_skb, 20, 60));

	kfree_skb(src_skb);
	kfree_skb(dst_skb);
}
TEST_F(homa_skb, homa_skb_append_from_skb__header_and_first_frag)
{
	struct sk_buff *src_skb = test_skb();
	struct sk_buff *dst_skb = homa_skb_new(100);
	struct skb_shared_info *dst_shinfo = skb_shinfo(dst_skb);
	int32_t data[500];

	EXPECT_EQ(0, homa_skb_append_from_skb(dst_skb, src_skb, 80, 100));
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
	struct sk_buff *src_skb = test_skb();
	struct sk_buff *dst_skb = homa_skb_new(100);
	struct skb_shared_info *dst_shinfo = skb_shinfo(dst_skb);
	int32_t data[500];

	EXPECT_EQ(0, homa_skb_append_from_skb(dst_skb, src_skb, 320, 600));
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
	struct sk_buff *src_skb = test_skb();
	struct sk_buff *dst_skb = homa_skb_new(100);
	struct skb_shared_info *dst_shinfo = skb_shinfo(dst_skb);
	int i, err;

	mock_max_skb_frags = 4;
	for (i = 0; i < 10; i++) {
		err = homa_skb_append_from_skb(dst_skb, src_skb, 320, 40);
		if (err)
			break;
	}
	EXPECT_EQ(4, i);
	EXPECT_EQ(EINVAL, -err);
	EXPECT_EQ(4, dst_shinfo->nr_frags);

	kfree_skb(src_skb);
	kfree_skb(dst_skb);
}

TEST_F(homa_skb, homa_skb_get)
{
	struct sk_buff *skb = test_skb();
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