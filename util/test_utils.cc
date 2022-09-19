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

/* This file contains a collection of functions that are useful in
 * testing.
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <algorithm>
#include <atomic>

#include "test_utils.h"

/**
 * check_buffer() - Checks whether the data in a buffer is consistent with
 * what would have been produced by seed_buffer. If not, an error message
 * is printed.
 * @buffer:   Buffer to check
 * @length:   Number of bytes in buffer
 *
 * Return: the seed value that was used to generate the buffer.
 */
int check_buffer(void *buffer, size_t length)
{
	int *int_buffer = (int *) buffer;
	int num_ints = (length + sizeof(int) - 1)/sizeof(int);
	int seed = int_buffer[0];
	int i;

	for (i = 0; i < num_ints; i++) {
		if (int_buffer[i] != seed + i) {
			printf("Bad value at index %d in "
				"message; expected %d, got %d\n",
				i, seed+i, int_buffer[i]);
			break;
		}
	}
	return seed;
}


/**
 * get_cycles_per_sec(): calibrate the RDTSC timer.
 *
 * Return: the number of RDTSC clock ticks per second.
 */
double get_cycles_per_sec()
{
	static double cps = 0;
	if (cps != 0) {
		return cps;
	}

	// Take parallel time readings using both rdtsc and gettimeofday.
	// After 10ms have elapsed, take the ratio between these readings.

	struct timeval start_time, stop_time;
	uint64_t start_cycles, stop_cycles, micros;
	double old_cps;

	// There is one tricky aspect, which is that we could get interrupted
	// between calling gettimeofday and reading the cycle counter, in which
	// case we won't have corresponding readings.  To handle this (unlikely)
	// case, compute the overall result repeatedly, and wait until we get
	// two successive calculations that are within 0.1% of each other.
	old_cps = 0;
	while (1) {
		if (gettimeofday(&start_time, NULL) != 0) {
			printf("count_cycles_per_sec couldn't read clock: %s",
					strerror(errno));
			exit(1);
		}
		start_cycles = rdtsc();
		while (1) {
			if (gettimeofday(&stop_time, NULL) != 0) {
				printf("count_cycles_per_sec couldn't read clock: %s",
						strerror(errno));
				exit(1);
			}
			stop_cycles = rdtsc();
			micros = (stop_time.tv_usec - start_time.tv_usec) +
				(stop_time.tv_sec - start_time.tv_sec)*1000000;
			if (micros > 10000) {
				cps = (double)(stop_cycles - start_cycles);
				cps = 1000000.0*cps/(double)(micros);
				break;
			}
		}
		double delta = cps/1000.0;
		if ((old_cps > (cps - delta)) && (old_cps < (cps + delta))) {
			return cps;
		}
		old_cps = cps;
	}
}

/**
 * get_int() - Parse an integer from a string, and exit if the parse fails.
 * @s:      String to parse.
 * @msg:    Error message to print (with a single %s specifier) on errors.
 * Return:  The integer value corresponding to @s.
 */
int get_int(const char *s, const char *msg)
{
	int value;
	value = strtol(s, NULL, 10);
	if (value == 0) {
		printf(msg, s);
		exit(1);
	}
	return value;
}

/**
 * print_dist() - Prints information on standard output about the distribution
 * of a collection of interval measurements.
 * @times:  An array containing interval times measured in rdtsc cycles.
 *          This array will be modified by sorting it.
 * @count:  The number of entries in @times.
 */
void print_dist(uint64_t times[], int count)
{
	std::sort(times, times+count);
	printf("Min:  %8.2f us\n", to_seconds(times[0])*1e06);
	for (int i = 1; i <= 9; i++) {
		printf("P%2d:  %8.2f us\n", i*10,
			to_seconds(times[(i*count)/10])*1e06);
	}
	printf("Max:  %8.2f us\n", to_seconds(times[count-1])*1e06);
	double average = 0.0;
	for (int i = 0; i < count; i++)
		average += to_seconds(times[i]);
	average /= count;
	printf("Avg:  %8.2f us\n", average*1e06);
}

/**
 * seed_buffer() - Fills a buffer with data generated from a seed value.
 * @buffer:   Buffer to fill
 * @length:   Number of bytes in buffer
 * @seed:     Different values of this parameter will result in different
 *            data being stored in @buffer.
 */
void seed_buffer(void *buffer, size_t length, int seed)
{
	int *int_buffer = (int *) buffer;
	int num_ints = (length + sizeof(int) - 1)/sizeof(int);
	int i;

	for (i = 0; i < num_ints; i++) {
		int_buffer[i] = seed + i;
	}
}

/**
 * print_address() - Generate a human-readable description of an inet address.
 * @addr:    The address to print
 * @buffer:  Where to store the human readable description.
 * @size:    Number of bytes available in buffer.
 *
 * Return:   The address of the human-readable string (buffer).
 *
 * This function keeps a collection of static buffers to hold the printable
 * strings, so callers don't have to worry about allocating space, even if
 * several addresses are in use at once. This function is also thread-safe.
 */
const char *print_address(sockaddr_in_union *addr)
{

// Avoid cache line conflicts:
#define BUF_SIZE 64
// Must be a power of 2:
#define NUM_BUFFERS (1 << 4)
	// Should use inet_ntop here....
	static char buffers[NUM_BUFFERS][BUF_SIZE];
	static std::atomic<int> next_buffer = 0;

	char *buffer = buffers[next_buffer.fetch_add(1)
		& (NUM_BUFFERS-1)];
	if ((buffer - &buffers[0][0]) > NUM_BUFFERS*BUF_SIZE)
		printf("Buffer pointer corrupted!\n");
	if (addr->in4.sin_family == AF_INET) {
		uint8_t *ipaddr = (uint8_t *) &addr->in4.sin_addr;
		snprintf(buffer, BUF_SIZE, "%u.%u.%u.%u:%u", ipaddr[0], ipaddr[1],
				ipaddr[2], ipaddr[3], ntohs(addr->in4.sin_port));
	} else if (addr->in6.sin6_family == AF_INET6) {
		char port[BUF_SIZE];
		snprintf(port, BUF_SIZE, "]:%u", ntohs(addr->in6.sin6_port));
		inet_ntop(addr->in6.sin6_family, &addr->in6.sin6_addr,
				buffer + 1, sizeof(addr->in6.sin6_addr));
		buffer[0] = '[';
		strncat(buffer, port, BUF_SIZE);
	} else {
		snprintf(buffer, BUF_SIZE, "Unknown family %d",
				addr->in6.sin6_family);
	}
	return buffer;
}


/**
 * to_seconds() - Given an elapsed time measured in cycles, return a
 * floating-point number giving the corresponding time in seconds.
 * @cycles:    Difference between the results of two calls to rdtsc.
 *
 * Return:     The time in seconds corresponding to cycles.
 */
double to_seconds(uint64_t cycles)
{
    return ((double) (cycles))/get_cycles_per_sec();
}
