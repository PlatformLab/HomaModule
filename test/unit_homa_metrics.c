// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

FIXTURE(homa_metrics) {
	struct homa homa;
};
FIXTURE_SETUP(homa_metrics)
{
	homa_init(&self->homa);
}
FIXTURE_TEARDOWN(homa_metrics)
{
	homa_destroy(&self->homa);
	homa_metrics_end();
	unit_teardown();
}

TEST_F(homa_metrics, homa_metric_append)
{
	homa_mout.length = 0;
	homa_metric_append("metric1", 12345, "Description 1\n");
	EXPECT_EQ(200, homa_mout.capacity);
	EXPECT_EQ(66, homa_mout.length);
	EXPECT_STREQ("metric1                                       12345 Description 1\n",
		     homa_mout.output);

	homa_metric_append("value with long name", 8, "Value %d, value 2 %08d\n",
			    16, 44);
	EXPECT_EQ(400, homa_mout.capacity);
	EXPECT_EQ(145, homa_mout.length);
	EXPECT_STREQ("metric1                                       12345 Description 1\n"
		     "value with long name                              8 Value 16, value 2 00000044\n",
		     homa_mout.output);
}

TEST_F(homa_metrics, homa_metrics_open)
{
	EXPECT_EQ(0, homa_metrics_open(NULL, NULL));
	EXPECT_NE(NULL, homa_mout.output);

	strcpy(homa_mout.output, "12345");
	EXPECT_EQ(0, homa_metrics_open(NULL, NULL));
	EXPECT_EQ(5, strlen(homa_mout.output));
	EXPECT_EQ(2, homa_mout.active_opens);
}
TEST_F(homa_metrics, homa_metrics_read__basics)
{
	loff_t offset = 10;
	char buffer[1000];

	homa_mout.output = kmalloc(100, GFP_KERNEL);
	homa_mout.capacity = 100;
	strcpy(homa_mout.output, "0123456789abcdefghijklmnop");
	homa_mout.length = 26;
	EXPECT_EQ(5, homa_metrics_read(NULL, buffer, 5, &offset));
	EXPECT_SUBSTR("_copy_to_user copied 5 bytes", unit_log_get());
	EXPECT_EQ(15, offset);

	unit_log_clear();
	EXPECT_EQ(11, homa_metrics_read(NULL, buffer, 1000, &offset));
	EXPECT_SUBSTR("_copy_to_user copied 11 bytes", unit_log_get());
	EXPECT_EQ(26, offset);

	unit_log_clear();
	EXPECT_EQ(0, homa_metrics_read(NULL, buffer, 1000, &offset));
	EXPECT_STREQ("", unit_log_get());
	EXPECT_EQ(26, offset);
}
TEST_F(homa_metrics, homa_metrics_read__error_copying_to_user)
{
	loff_t offset = 10;
	char buffer[1000];

	homa_mout.output = kmalloc(100, GFP_KERNEL);
	homa_mout.capacity = 100;
	strcpy(homa_mout.output, "0123456789abcdefghijklmnop");
	homa_mout.length = 26;
	mock_copy_to_user_errors = 1;
	EXPECT_EQ(EFAULT, -homa_metrics_read(NULL, buffer, 5, &offset));
}

TEST_F(homa_metrics, homa_metrics_release)
{
	homa_mout.active_opens = 2;
	EXPECT_EQ(0, homa_metrics_release(NULL, NULL));
	EXPECT_EQ(1, homa_mout.active_opens);

	EXPECT_EQ(0, homa_metrics_release(NULL, NULL));
	EXPECT_EQ(0, homa_mout.active_opens);
}
