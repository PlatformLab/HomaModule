/* Copyright (c) 2024 Homa Developers
 * SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+
 */

/* This program measures the throughput of atomic increments in the face
 * of many concurrent cores invoking it.
 */

#include <stdio.h>

#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#include <atomic>
#include <thread>
#include <vector>

std::atomic_int value = 0;
std::vector<int> thread_counts;

/**
 * rdtsc(): return the current value of the fine-grain CPU cycle counter
 * (accessed via the RDTSC instruction).
 */
inline static uint64_t rdtsc(void)
{
	uint32_t lo, hi;
	__asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
	return (((uint64_t)hi << 32) | lo);
}

void increment(int index)
{
	while (1) {
		value.fetch_add(1);
		thread_counts[index]++;
	}
}

int main(int argc, char** argv)
{
	int num_threads = 1;
	int i;
	std::vector<int> old_counts;

	if (argc == 2) {
		char *end;
		num_threads = strtol(argv[1], &end, 0);
		if (*end != 0) {
			printf("Illegal argument %s: must be integer\n",
					argv[1]);
			exit(1);
		}
	} else if (argc != 1) {
		printf("Usage: %s [num_threads]\n", argv[0]);
	}

	for (i = 0; i < num_threads; i++) {
		thread_counts.emplace_back(0);
		old_counts.emplace_back(0);
		new std::thread(increment, i);
	}

	struct timeval prev_time, cur_time;
	gettimeofday(&prev_time, nullptr);
	uint64_t old_value = value;
	while (1) {
		sleep(1);
		gettimeofday(&cur_time, nullptr);
		uint64_t new_value = value;
		double diff = new_value - old_value;
		double secs = cur_time.tv_sec - prev_time.tv_sec;
		secs += 1e-6*(cur_time.tv_usec - prev_time.tv_usec);
		printf("%.2f Mops/sec [", (diff/secs)*1e-6);
		const char *sep = "";
		for (i = 0; i < num_threads; i++) {
			int new_count = thread_counts[i];
			diff = new_count - old_counts[i];
			printf("%s%.2f", sep, (diff/secs)*1e-6);
			sep = " ";
			old_counts[i] = new_count;
		}
		printf("]\n");
		prev_time = cur_time;
		old_value = new_value;
	}
}