// This file contains a collection of functions that are useful in
// testing.

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include <algorithm>

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
 * printAddress() - Generate a human-readable description of an inet address.
 * @addr:    The address to print
 * @buffer:  Where to store the human readable description.
 * @size:    Number of bytes available in buffer.
 * 
 * Return:   The address of the human-readable string (buffer).
 * 
 * This function keeps a collection of static buffers to hold the printable
 * strings, so callers don't have to worry about allocating space, even if
 * several addresses are in use at once.
 */
char *print_address(struct sockaddr_in *addr)
{
#define BUF_SIZE 50
#define NUM_BUFFERS 10
	static char buffers[NUM_BUFFERS][BUF_SIZE];
	static int next_buffer = 0;
	
	char *buffer = buffers[next_buffer];
	next_buffer++;
	if (next_buffer >= NUM_BUFFERS)
		next_buffer = 0;
	if (addr->sin_family != AF_INET) {
		snprintf(buffer, BUF_SIZE, "Unknown family %d", addr->sin_family);
		return buffer;
	}
	uint8_t *ipaddr = (uint8_t *) &addr->sin_addr;
	snprintf(buffer, BUF_SIZE, "%u.%u.%u.%u:%u", ipaddr[0], ipaddr[1],
		ipaddr[2], ipaddr[3], ntohs(addr->sin_port));
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