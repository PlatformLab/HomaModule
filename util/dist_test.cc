/* Copyright (c) 2023 Homa Developers
 * SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+
 */

#include <stdio.h>

#include <algorithm>
#include <chrono>
#include <iostream>
#include <map>

#include "dist.h"
#include "test_utils.h"

/**
 * define HOMA_MAX_MESSAGE_LENGTH - Maximum bytes of payload in a Homa
 * request or response message.
 */
#define HOMA_MAX_MESSAGE_LENGTH 1000000

/** @rand_gen: random number generator. */
static std::mt19937 rand_gen(
		std::chrono::system_clock::now().time_since_epoch().count());

/* This file tests the dist.cc/dist.h files and dist_point_gen class. It will
 * print the CDF for every generated length, a histogram to show how often each
 * length was generated, the sizes of the given distribution, and finally the
 * mean, range, and overhead of the distribution requested.
 *
 * Produced by:
 * ./dist_test workload [number of points] [max message length]
 *
 * @workload: - the distribution requested for the test. Can be workload 1-5
 * or a fixed distribution.
 *
 * @number_of_points: - the number of points that the dist_point_gen will
 * randomly generate for the test. (Default = 10).
 *
 * @max_message_length: - the maximum size of a message.
 */
int main (int argc, char**argv)
{
	int max_message_length = HOMA_MAX_MESSAGE_LENGTH;
	size_t num_points = 10;
	if (argc < 2) {
		fprintf(stderr, "Usage: %s workload [# points] [max_message_length]",
				argv[0]);
	}
	if (argc > 3) {
		max_message_length = atoi(argv[3]);
	}
	if (argc > 2) {
		num_points = atoi(argv[2]);
	}

	dist_point_gen generator(argv[1], max_message_length);
	std::map<int, int> hist;
	std::map<int, float> cdf;

	uint64_t start = rdtsc();
	for (size_t i = 0; i < 1'000'000; i++) {
		generator(rand_gen);
	}
	uint64_t end = rdtsc();
	double avg_ns = double(end-start)/(get_cycles_per_sec()*1e-09)/1'000'000;

	for (size_t i = 0; i < num_points; i++) {
		 hist[generator(rand_gen)]++;
	}

	int count = 0;
	for (std::map<int, int>::const_iterator it = hist.begin();
			it != hist.end(); ++it) {
		count += it->second;
		cdf[it->first] = count;
	}

	printf("\nCDF:\n");
	for (const auto [key, val] : cdf) {
		printf("%7d %6.4f\n", key, val/num_points);
	}

	printf("\nHistogram:\n");
	for (const auto [key, val] : hist) {
		printf("%d %d\n", key, val);
	}

	std::vector<int> sizes = generator.values();
	printf("\nSizes:\n");
	for (const int num : sizes) {
		printf("%d\n", num);
	}

	printf("\nMean: %.1f\n", generator.get_mean());
	printf("Range: min %d, max %d\n", hist.begin()->first, hist.rbegin()->first);
	printf("Overhead (1500B packets): %.3f\n", generator.dist_overhead(1500));
	printf("Average time/sample for generator: %.1f ns\n", avg_ns);
}