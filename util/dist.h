/* Copyright (c) 2019-2022 Stanford University
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

struct dist_point;

/* class dist_point_gen - Returns a single CDF based on the specified workload
 * and reference to random number generator
 */
class dist_point_gen {
	public:
	dist_point_gen(const char* workload, size_t max_size,
		double min_bucket_frac = .0025, double max_size_range = 1.2);
	int operator()(std::mt19937 &rand_gen);
	double get_mean() const {return dist_mean;} ;
	double dist_overhead(int mtu) const;
	std::vector<int> sizes() const;

	private:
	/*We do not have span so we are using a raw pointer and size_t to describe
	our distribution.*/
	dist_point* dist_point_ptr = nullptr;
	size_t dist_size = 0;
	double dist_mean = 0;
	double comp_dist_mean();
};
#endif /* _DIST_H */
