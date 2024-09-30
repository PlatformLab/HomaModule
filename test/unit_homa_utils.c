/* Copyright (c) 2019-2023 Homa Developers
 * SPDX-License-Identifier: BSD-1-Clause
 */

#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#define n(x) htons(x)
#define N(x) htonl(x)

FIXTURE(homa_utils) {
	struct homa homa;
};
FIXTURE_SETUP(homa_utils)
{
	homa_init(&self->homa);
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_utils)
{
	homa_destroy(&self->homa);
	unit_teardown();
}

/**
 * set_cutoffs() - A convenience method to allow all of the values in
 * homa->unsched_cutoffs to be set concisely.
 * @homa:   Contains the unsched_cutoffs to be modified.
 * @c0:     New value for homa->unsched_cutoffs[0]
 * @c1:     New value for homa->unsched_cutoffs[1]
 * @c2:     New value for homa->unsched_cutoffs[2]
 * @c3:     New value for homa->unsched_cutoffs[3]
 * @c4:     New value for homa->unsched_cutoffs[4]
 * @c5:     New value for homa->unsched_cutoffs[5]
 * @c6:     New value for homa->unsched_cutoffs[6]
 * @c7:     New value for homa->unsched_cutoffs[7]
 */
static void set_cutoffs(struct homa *homa, int c0, int c1, int c2,
		int c3, int c4, int c5, int c6, int c7)
{
	homa->unsched_cutoffs[0] = c0;
	homa->unsched_cutoffs[1] = c1;
	homa->unsched_cutoffs[2] = c2;
	homa->unsched_cutoffs[3] = c3;
	homa->unsched_cutoffs[4] = c4;
	homa->unsched_cutoffs[5] = c5;
	homa->unsched_cutoffs[6] = c6;
	homa->unsched_cutoffs[7] = c7;
}

TEST_F(homa_utils, homa_print_ipv4_addr)
{
	char *p1, *p2;
	int i;

	struct in6_addr test_addr1 = unit_get_in_addr("192.168.0.1");
	struct in6_addr test_addr2 = unit_get_in_addr("1.2.3.4");
	struct in6_addr test_addr3 = unit_get_in_addr("5.6.7.8");
	p1 = homa_print_ipv6_addr(&test_addr1);
	p2 = homa_print_ipv6_addr(&test_addr2);
	EXPECT_STREQ("192.168.0.1", p1);
	EXPECT_STREQ("1.2.3.4", p2);

	/* Make sure buffers eventually did reused. */
	for (i = 0; i < 20; i++)
		homa_print_ipv6_addr(&test_addr3);
	EXPECT_STREQ("5.6.7.8", p1);
}

TEST_F(homa_utils, homa_snprintf)
{
	char buffer[50];
	int used = 0;
	used = homa_snprintf(buffer, sizeof32(buffer), used,
			"Test message with values: %d and %d", 100, 1000);
	EXPECT_EQ(38, used);
	EXPECT_STREQ("Test message with values: 100 and 1000", buffer);

	used = homa_snprintf(buffer, sizeof32(buffer), used,
			"; plus: %d", 123456);
	EXPECT_EQ(49, used);
	EXPECT_STREQ("Test message with values: 100 and 1000; plus: 123",
			buffer);

	used = homa_snprintf(buffer, sizeof32(buffer), used,
			"more text, none of which fits");
	EXPECT_EQ(49, used);
	EXPECT_STREQ("Test message with values: 100 and 1000; plus: 123",
			buffer);
}

TEST_F(homa_utils, homa_prios_changed__basics)
{
	set_cutoffs(&self->homa, 90, 80, HOMA_MAX_MESSAGE_LENGTH*2, 60, 50,
			40, 30, 0);
	self->homa.num_priorities = 6;
	homa_prios_changed(&self->homa);
	EXPECT_EQ(0, self->homa.unsched_cutoffs[6]);
	EXPECT_EQ(40, self->homa.unsched_cutoffs[5]);
	EXPECT_EQ(60, self->homa.unsched_cutoffs[3]);
	EXPECT_EQ(HOMA_MAX_MESSAGE_LENGTH*2, self->homa.unsched_cutoffs[2]);
	EXPECT_EQ(80, self->homa.unsched_cutoffs[1]);
	EXPECT_EQ(INT_MAX, self->homa.unsched_cutoffs[0]);
	EXPECT_EQ(1, self->homa.max_sched_prio);
	EXPECT_EQ(1, self->homa.cutoff_version);
}
TEST_F(homa_utils, homa_prios_changed__num_priorities_too_large)
{
	self->homa.num_priorities = 100;
	homa_prios_changed(&self->homa);
	EXPECT_EQ(8, self->homa.num_priorities);
}
TEST_F(homa_utils, homa_prios_changed__share_lowest_priority)
{
	set_cutoffs(&self->homa, 90, 80, 70, 60, 50, 40, 30, 0);
	self->homa.num_priorities = 7;
	homa_prios_changed(&self->homa);
	EXPECT_EQ(30, self->homa.unsched_cutoffs[6]);
	EXPECT_EQ(80, self->homa.unsched_cutoffs[1]);
	EXPECT_EQ(0x7fffffff, self->homa.unsched_cutoffs[0]);
	EXPECT_EQ(0, self->homa.max_sched_prio);
}
