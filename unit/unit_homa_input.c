#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"

TEST(first) {
	EXPECT_FALSE(0);
	EXPECT_TRUE(0);
	EXPECT_STREQ("abc", "abc");
}

TEST(second) {
	EXPECT_EQ(3+5, 8);
}

//TEST_HARNESS_MAIN