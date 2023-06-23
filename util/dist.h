/* Copyright (c) 2019-2023 Stanford University
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

/**
 * class @dist_point_gen: - Represents a CDF of message lengths and generates
 * randomized lengths according to that CDF.
 */
class dist_point_gen {
	public:
	dist_point_gen(const char* workload, size_t max_size,
		double min_bucket_frac = .0025, double max_size_ratio = 1.2);
	int operator()(std::mt19937 &rand_gen);
	double get_mean() const {return dist_mean;}
	double dist_overhead(int mtu) const;
	std::vector<int> values() const;
	std::vector<double> CDF_fractions() const;

	/**
	 * struct dist_point - Describes one point in a CDF of message lengths.
	 */
	struct cdf_point {
		/** @length: message length, in bytes. */
		size_t length;

		/**
		 * @fraction: fraction of all messages that are this size
		 * or smaller.
		 */
		double fraction;

		cdf_point(size_t length, double fraction)
			: length(length), fraction(fraction)
		{}
	};

	private:
	/**
	 * @dist_points: collection of individual data points that
	 * make up this CDF (in increasing order of length).
	 */
	std::vector<cdf_point> dist_points;

	/**
	 * @dist_mean: the average value of this distribution.
	 */
	double dist_mean;

	/** @uniform_dist: used to generate values in the range [0, 1). */
	std::uniform_real_distribution<double> uniform_dist;

	static int dist_msg_overhead(int length, int mtu);
};
#endif /* _DIST_H */
