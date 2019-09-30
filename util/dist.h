/* This file defines the kernel contains information and supporting
 * functions for the workload distributions from the Homa paper.
 */

#ifndef _DIST_H
#define _DIST_H

#include <random>
#include <vector>

/** struct dist_point - Describes one point in a CDF of message lengths. */
struct dist_point {
	/**
	 * @length: message length, in bytes; must be at least
	 * sizeof(message_header).
	 */
	int length;
	
	/**
	 * @fraction: fraction of all messages that are this size
	 * or smaller.
	 */
	double fraction;
};

extern double   dist_mean(const char *dist);
extern int      dist_sample(const char *dist, std::mt19937 *rand_gen,
			int num_samples, std::vector<int> *sizes);

extern dist_point w1[];
extern dist_point w2[];
extern dist_point w3[];
extern dist_point w4[];
extern dist_point w5[];

#endif /* _DIST_H */