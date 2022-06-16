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
	
	dist_point(int length, double fraction)
		: length(length), fraction(fraction)
	{}
};

extern std::vector<dist_point>
                dist_get(const char *dist, int max_length,
			double min_bucket_frac = .0025,
			double max_size_range = 1.2);
extern double   dist_mean(std::vector<dist_point> &points);
extern int      dist_msg_overhead(int length, int mtu);
extern double   dist_overhead(std::vector<dist_point> &points, int mtu);
extern void     dist_sample(std::vector<dist_point> &points,
			std::mt19937 *rand_gen, int num_samples,
			std::vector<int> &sizes);

extern dist_point w1[];
extern dist_point w2[];
extern dist_point w3[];
extern dist_point w4[];
extern dist_point w5[];

#endif /* _DIST_H */