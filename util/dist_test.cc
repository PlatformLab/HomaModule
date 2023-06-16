#include "dist.h"
#include <iostream>
#include <chrono>
#include <algorithm>
#include <map>

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
 * ./dist_test [workload] [number of points] [max message length]
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
    if (argc > 3) {
        max_message_length = atoi(argv[3]);
    }
    if (argc > 2) {
        num_points = atoi(argv[2]);
    }

    dist_point_gen generator(argv[1], max_message_length);
    std::map<int, int> hist;
    std::map<int, float> cdf;
    for (size_t i = 0; i < num_points; i++) {
        hist[generator(rand_gen)]++;
    }

    int count = 0;
    for (std::map<int, int>::const_iterator it = hist.begin();
            it != hist.end(); ++it) {
        count += it->second;
        cdf[it->first] = count;
    }

    std::cout << "\nCDF:\n";
    for (const auto [key, val] : cdf) {
        printf("%d %20.19f\n", key, val/num_points);
    }

    std::cout << "\nHistogram:\n";
    for (const auto [key, val] : hist) {
        std::cout << key << " " << val << "\n";
    }

    std::vector<int> sizes = generator.sizes();
    std::cout << "\nSizes:\n";
    for (const auto num : sizes) {
        std::cout << num << '\n';
    }

    std:: cout << "\nMean: " << generator.get_mean() << "\n";
    std::cout << "Range: Min = " << hist.begin()->first << " Max = " <<
    hist.rbegin()->first << "\n";
    std:: cout << "Overhead: " << generator.dist_overhead(1500) << "\n";
}