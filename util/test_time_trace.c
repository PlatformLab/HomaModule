/* Copyright (c) 2019-2022 Homa Developers
 * SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+
 */

/* This program exercises the Linux kernel time trace mechanism
 * by calling a new system call that creates time traces.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(int argc, char** argv) {
	int i;
	printf("Invoking new 'test_timetrace' syscall.\n");
	for (i = 0; i < 100; i++) {
		int status = syscall(334);
		if (status < 0) {
			printf(" Error in test_timetrace: %s (%d)",
					strerror(errno), errno);
		}
	}
	return 0;
}

