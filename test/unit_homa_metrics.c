// SPDX-License-Identifier: BSD-2-Clause

#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

extern struct homa *homa;

FIXTURE(homa_metrics) {
	struct homa homa;
};
FIXTURE_SETUP(homa_metrics)
{
	homa_init(&self->homa);
	homa = &self->homa;
}
FIXTURE_TEARDOWN(homa_metrics)
{
	homa = NULL;
	homa_destroy(&self->homa);
	unit_teardown();
}

TEST_F(homa_metrics, homa_metric_append)
{
	self->homa.metrics_length = 0;
	homa_metric_append(&self->homa, "x: %d, y: %d", 10, 20);
	EXPECT_EQ(12, self->homa.metrics_length);
	EXPECT_STREQ("x: 10, y: 20", self->homa.metrics);

	homa_metric_append(&self->homa, ", z: %d", 12345);
	EXPECT_EQ(22, self->homa.metrics_length);
	EXPECT_STREQ("x: 10, y: 20, z: 12345", self->homa.metrics);
	EXPECT_EQ(30, self->homa.metrics_capacity);

	homa_metric_append(&self->homa, ", q: %050d", 88);
	EXPECT_EQ(77, self->homa.metrics_length);
	EXPECT_STREQ("x: 10, y: 20, z: 12345, "
			"q: 00000000000000000000000000000000000000000000000088",
			self->homa.metrics);
	EXPECT_EQ(120, self->homa.metrics_capacity);
}
TEST_F(homa_metrics, homa_metrics_open)
{
	EXPECT_EQ(0, homa_metrics_open(NULL, NULL));
	EXPECT_NE(NULL, self->homa.metrics);

	strcpy(self->homa.metrics, "12345");
	EXPECT_EQ(0, homa_metrics_open(NULL, NULL));
	EXPECT_EQ(5, strlen(self->homa.metrics));
	EXPECT_EQ(2, self->homa.metrics_active_opens);
}
TEST_F(homa_metrics, homa_metrics_read__basics)
{
	char buffer[1000];
	loff_t offset = 10;
	self->homa.metrics = kmalloc(100, GFP_KERNEL);
	self->homa.metrics_capacity = 100;
	strcpy(self->homa.metrics, "0123456789abcdefghijklmnop");
	self->homa.metrics_length = 26;
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
	char buffer[1000];
	loff_t offset = 10;
	self->homa.metrics = kmalloc(100, GFP_KERNEL);
	self->homa.metrics_capacity = 100;
	strcpy(self->homa.metrics, "0123456789abcdefghijklmnop");
	self->homa.metrics_length = 26;
	mock_copy_to_user_errors = 1;
	EXPECT_EQ(EFAULT, -homa_metrics_read(NULL, buffer, 5, &offset));
}

TEST_F(homa_metrics, homa_metrics_release)
{
	self->homa.metrics_active_opens = 2;
	EXPECT_EQ(0, homa_metrics_release(NULL, NULL));
	EXPECT_EQ(1, self->homa.metrics_active_opens);

	EXPECT_EQ(0, homa_metrics_release(NULL, NULL));
	EXPECT_EQ(0, self->homa.metrics_active_opens);
}