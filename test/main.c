/* Copyright (c) 2019-2022 Homa Developers
 * SPDX-License-Identifier: BSD-1-Clause
 */

/* Main program for running Homa unit tests. */

#include "homa_impl.h"
#include "kselftest_harness.h"
#include "mock.h"

static char * helpMessage =
	"This program runs unit tests written in the Linux kernel kselftest "
	"style.\n"
	"    Usage: %s options test_name test_name ...\n"
	"The following options are supported:\n"
	"    --help or -h      Print this message\n"
        "    --ipv4            Simulate IPv4 for all packets (default: "
	"use IPv6)\n"
	"    --verbose or -v   Print the names of all tests as they run "
	"(default:\n"
	"                      print only tests that fail)\n"
	"If one or more test_name arguments are provided, then only those "
	"tests are\n"
	"run; if no test names are provided, then all tests are run.\n"
        "\n"
        "Note: the tests should provide complete coverage of both IPv4 and "
        "IPv6 without\n"
        "using the --ipv4 argument (code that depends on IPv4 vs. IPv6 "
        "already has\n"
        "special test cases for each); --ipv4 is provided for occasional "
        "double-checking.\n";

int main(int argc, char **argv) {
	int i;
	int verbose = 0;
	mock_ipv6_default = true;
	for (i = 1; i < argc; i++) {
		if ((strcmp(argv[i], "-h") == 0) ||
			(strcmp(argv[i], "--help") == 0)) {
			printf(helpMessage, argv[0]);
			return 0;
		} else if (strcmp(argv[i], "--ipv4") == 0) {
			mock_ipv6_default = false;
		} else if ((strcmp(argv[i], "-v") == 0) ||
			(strcmp(argv[i], "--verbose") == 0)) {
			verbose = 1;
		} else if (argv[i][0] == '-') {
			printf("Unknown option %s; type '%s --help' for help\n",
				argv[i], argv[0]);
			return 1;
		} else {
			break;
		}
	}
	test_harness_run(argc-i, argv+i, verbose);
}