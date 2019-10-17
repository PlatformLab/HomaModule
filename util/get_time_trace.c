/* Copyright (c) 2019, Stanford University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * This program will read timetrace information from the kernel and
 * dump it on stdout. Invoke with no parameters.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdint.h>

#include "test_utils.h"

#define BUF_SIZE 10000000
char buffer[BUF_SIZE];

int main(int argc, char** argv) {
	// Fetch the time trace data from the kernel.
	int length = syscall(333, buffer, BUF_SIZE);
	if (length < 0) {
		printf("Error in get_timetrace: %s (%d)",
				strerror(errno), errno);
		return 1;
	}
	printf("Kernel returned timetrace with %d bytes\n", length);
	if (length == BUF_SIZE) {
		printf("Not enough space in buffer for complete timetrace.\n");
	}
	buffer[length-1] = 0;
	
	double cps = get_cycles_per_sec();
	printf("Cycles per second: %g\n", cps);
	
	// Scan through the records in the buffer. For each record, replace
	// the timestamp with more detailed information in ns, and output
	// the modified record.
	char* current = buffer;
	uint64_t start_time, prev_time;
	start_time = 0;
	while (1) {
		char *stamp_end;
		double ns, delta_ns;
		// printf("Current text: %.50s", current);
		uint64_t stamp = strtoull(current, &stamp_end, 10);
		if (stamp == 0) {
			break;
		}
		if (start_time == 0) {
			start_time = stamp;
			prev_time = stamp;
		}
		ns = (1e09 * (double)(stamp - start_time)) / cps;
		delta_ns = (1e09 * (double)(stamp - prev_time)) / cps;
		printf("%8.1f ns (+%6.1f ns):", ns, delta_ns);
		
		for (current = stamp_end;
				(*current != 0) && (*current != '\n');
				current++) {
			putc(*current, stdout);
		}
		putc('\n', stdout);
		prev_time = stamp;
	}
	return 0;
}

