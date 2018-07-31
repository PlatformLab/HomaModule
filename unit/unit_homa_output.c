#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"

TEST(test4) {
	EXPECT_FALSE(0);
	EXPECT_TRUE(0);
	EXPECT_STREQ("abc", "abc");
}

TEST(test5) {
	EXPECT_EQ(3+5, 7);
}
