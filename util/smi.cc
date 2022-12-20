/* Copyright (c) 2022 Stanford University
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

/* This program spawns a collection of threads on different cores to
 * detect SMI interrupts, during which all of the cores are simultaneously
 * paused. It outputs information about the frequency and length of the
 * SMIs.
 *
 * Usage:
 * smi core core ...
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <thread>
#include <vector>

#include "test_utils.h"

#define usecs(x) (to_seconds(x)*1e06)

#define ms(x) (to_seconds(x)*1e03)

/**
 * Holds information about gaps for a single thread (periods of time when
 * that thread was not executing).
 */
#define MAX_GAPS 1000
struct thread_gaps {
	/* Index in gaps of next gap to fill in. */
	int next;

	/* Used only wnen scanning: current gap being considered. */
	int current;

	struct {
		uint64_t start;
		uint64_t end;
	} gaps[MAX_GAPS];

	thread_gaps()
		: next(0), current(0), gaps()
	{}
};

/**
 * Used to collect information about identified gaps, in order to find
 * previous gaps of about the same duration.
 */
struct prev_gap {
	/* Starting time for the gap. */
	uint64_t start;

	/* How long it lasted, in rdtsc units. */
	uint64_t duration;

	prev_gap(uint64_t start, uint64_t duration)
			: start(start), duration(duration)
	{}
};

/* Minimum length (in rdtsc cycles) for a gap to be considered meaningful. */
uint64_t min_gap_length;

/**
 * record_gaps() - Loop infinitely, recording info about execution gaps,
 * until gaps is full.
 * @gaps:    Structure to fill in with gap information.
 * @core:    Core on which to run.
 */
void record_gaps(struct thread_gaps *gaps, int core)
{
	pin_thread(core);
//	printf("Pinned thread to core %d\n", core);
	while (gaps->next < MAX_GAPS) {
		uint64_t start, end;
		start = rdtsc();
		while (1) {
			end = rdtsc();
			if ((end - start) >= min_gap_length) {
				break;
			}
			start = end;
		}
		gaps->gaps[gaps->next].start = start;
		gaps->gaps[gaps->next].end = end;
		gaps->next++;
	}
}

int main(int argc, char** argv) {
	std::vector<int> cores;
	int i, num_cores;
	uint64_t time0;

	/* Minimum gap is 1 usec. */
	min_gap_length = static_cast<uint64_t>(get_cycles_per_sec())/1000000;

	if ((argc == 2) && (strcmp(argv[1], "--help") == 0)) {
		printf("Usage: smi [core core ...]\n");
		printf("With no arguments, runs on a preset group of cores\n");
		exit(0);
	}

	for (i = 1; i < argc; i++) {
		char *end;
		int core = strtol(argv[i], &end, 10);
		if ((*end != 0) || (core < 0)) {
			fprintf(stderr, "Bad core number %s: must be positive "
					"integer\n", argv[i]);
			exit(1);
		}
	}
	if (cores.empty()) {
		for (i = 0; i < 10; i++) {
			cores.push_back(i);
		}
	}
	num_cores = static_cast<int>(cores.size());

	time0 = rdtsc();
	std::vector<struct thread_gaps *> thread_gaps;
	std::vector<std::thread> threads;
	for (int core: cores) {
		struct thread_gaps *g = new struct thread_gaps;
		thread_gaps.push_back(g);
		threads.emplace_back(record_gaps, g, core);
	}
	for (i = 0; i < num_cores; i++) {
		threads[i].join();
	}
	uint64_t overlap = rdtsc() - time0;
	printf("Each line gives the starting time for a gap, plus the elapsed\n");
	printf("time since the previous gap of a similar duration.\n");

	/* Each iteration through this loop checks to see if the current
	 * gaps from all of the cores are concurrent. If so, it records
	 * that gap. Otherwise, it discards the oldest gap.
	 */
	uint64_t total_gaps = 0;
	int num_gaps = 0;
	std::vector<struct prev_gap> found;
	while (true) {
		int oldest = 0;
		uint64_t oldest_start = 0, latest_start = 0, earliest_end = 0;
		for (i = 0; i < num_cores; i++) {
			struct thread_gaps *gaps = thread_gaps[i];
			if (gaps->current >= MAX_GAPS) {
				goto done;
			}
			uint64_t start = gaps->gaps[gaps->current].start;
			uint64_t end = gaps->gaps[gaps->current].end;
//			printf("Gap on core %d [%d]: %.1f .. %.1f\n", i,
//					gaps->current, usecs(start - time0),
//					usecs(end - time0));
			if (i == 0) {
				oldest = 0;
				oldest_start = start;
				latest_start = start;
				earliest_end = end;
			} else {
				if (start < oldest_start) {
					oldest = i;
					oldest_start = start;
				}
				if (start > latest_start) {
					latest_start = start;
				}
				if (end < earliest_end) {
					earliest_end = end;
				}
			}
		}
		uint64_t overlap = (earliest_end > latest_start)
				? earliest_end - latest_start : 0;
//		printf("latest_start %.1f, earliest_end %.1f, overlap %.1f\n",
//				usecs(latest_start - time0),
//				usecs(earliest_end - time0),
//				usecs(overlap));
		if (overlap >= min_gap_length ) {
			/* We have a consistent gap across all cores. */
			num_gaps++;
			total_gaps += overlap;

			/* Find the most recent event of similar duration. */
			uint64_t prev_start = time0;
			for (int j = static_cast<int>(found.size())-1;
					j >= 0; j--) {
//				printf("Checking found[%d]: start %.1f ms, duration %.1f us\n",
//						j, ms(found[j].start - time0),
//						usecs(found[j].duration));
				uint64_t prev = found[j].duration;
				uint64_t delta = prev;
				if (overlap < delta) {
					delta = overlap;
				}
				delta = delta/4;
//				printf("prev %lu, overlap %lu, delta %lu\n",
//						prev, overlap, delta);
				if (((prev + delta) >= overlap)
						&& ((overlap + delta) >= prev)) {
					prev_start = found[j].start;
					break;
				}
			}
			found.emplace_back(latest_start, overlap);
			printf("%5.1f ms [+%5.1f ms] gap of %.1f usec\n",
					ms(latest_start - time0),
					ms(latest_start - prev_start),
					usecs(overlap));
			for (i = 0; i < num_cores; i++) {
				thread_gaps[i]->current++;
			}
		} else {
			/* Nothing consistent; drop the oldest gap. */
//			printf("Dropping gap %d of core %d\n",
//					thread_gaps[oldest]->current, oldest);
			thread_gaps[oldest]->current++;
		}
	}
	done:
	printf("%d gaps (every %.1f ms), total gap time %.1f usec (%.2f%% of all time)\n",
			num_gaps, (usecs(overlap)/1000)/num_gaps,
			usecs(total_gaps),
			100.0*usecs(total_gaps)/usecs(overlap));
	exit(0);
}
