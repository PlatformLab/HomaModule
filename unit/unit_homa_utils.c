#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "utils.h"

TEST(homa_print_ipv4_addr) {
	char buffer[100];
	__be32 addr = unit_get_in_addr("192.168.0.1");
	homa_print_ipv4_addr(addr, buffer);
	EXPECT_STREQ("192.168.0.1", buffer);
	
	addr = htonl((1<<24) + (2<<16) + (3<<8) + 4);
	homa_print_ipv4_addr(addr, buffer);
	EXPECT_STREQ("1.2.3.4", buffer);
}