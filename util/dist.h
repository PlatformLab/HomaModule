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
#include <memory>

/* class dist_point_gen - Returns a single CDF based on the specified workload
 * and reference to random number generator
 */
class dist_point_gen {
	public:
	dist_point_gen(const char* workload, size_t max_size,
		double min_bucket_frac = .0025, double max_size_range = 1.2);
	int operator()(std::mt19937 &rand_gen);
	double get_mean() const {return dist_mean;}
	double dist_overhead(int mtu) const;
	std::vector<int> sizes() const;

	/** struct dist_point - Describes one point in a CDF of message lengths. */
	struct dist_point {
		/**
		 * @length: message length, in bytes; must be at least
		 * sizeof(message_header).
		 */
		size_t length;

		/**
		 * @fraction: fraction of all messages that are this size
		 * or smaller.
		 */
		double fraction;

		dist_point(size_t length, double fraction)
			: length(length), fraction(fraction)
		{}
	};

	private:
	/*We do not have span so we are using a raw pointer and size_t to describe
	our distribution.*/
	const dist_point* dist_point_ptr = nullptr;
	int dist_size = 0;
	//The maximum size of a message length passed through the constructor
	size_t max_message_length = 0;
	//Computes the mean of the distribution
	double comp_dist_mean();
	double dist_mean = 0;
	//This dist point is used if a fixed size is established
	//(initialized to {1, 1.0} for compile)
	dist_point fixed_dist = {1, 1.0};
};
#endif /* _DIST_H */
