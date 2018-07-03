/**
 * This program will read timetrace information from the kernel and
 * dump it on stdout. Invoke with no parameters.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdint.h>

#define BUF_SIZE 10000000
char buffer[BUF_SIZE];

/**
 * rdtsc(): return the current value of the fine-grain CPU cycle counter
 * (accessed via the RDTSC instruction).
 */
inline uint64_t rdtsc(void)
{
	uint32_t lo, hi;
	__asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
	return (((uint64_t)hi << 32) | lo);
}

/**
 * count_cycles_per_sec(): calibrate the RDTSC timer.
 * 
 * @return: the number of RDTSC clock ticks per second.
 */
double
get_cycles_per_sec() {
    // Take parallel time readings using both rdtsc and gettimeofday.
    // After 10ms have elapsed, take the ratio between these readings.

    struct timeval start_time, stop_time;
    uint64_t start_cycles, stop_cycles, micros;
    double cps, old_cps;

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
        if ((old_cps > (cps - delta)) &&
                (old_cps < (cps + delta))) {
            return cps;
        }
        old_cps = cps;
    }
}

int main(int argc, char** argv) {
	// Fetch the time trace data from the kernel.
	int length = syscall(333, buffer, BUF_SIZE);
	if (length < 0) {
		printf(" Error in gett_timetrace: %s (%d)",
				strerror(errno), errno);
		return 1;
	}
	printf("Kernel returned timetrace with %d bytes\n", length);
	if (length == BUF_SIZE) {
		printf("Not enough space in buffer for complete timetrace.\n");
	}
	buffer[length-1] = 0;
	
	double cps = get_cycles_per_sec();
	printf("Cycles per second: %g\n", cps);
	
	// Scan through the records in the buffer. For each record, replace
	// the timestamp with more detailed information in ns, and output
	// the modified record.
	char* current = buffer;
	uint64_t start_time, prev_time;
	start_time = 0;
	while (1) {
		char *stamp_end;
		double ns, delta_ns;
		// printf("Current text: %.50s", current);
		uint64_t stamp = strtoull(current, &stamp_end, 10);
		if (stamp == 0) {
			break;
		}
		if (start_time == 0) {
			start_time = stamp;
			prev_time = stamp;
		}
		ns = (1e09 * (double)(stamp - start_time)) / cps;
		delta_ns = (1e09 * (double)(stamp - prev_time)) / cps;
		printf("%8.1f ns (+%6.1f ns):", ns, delta_ns);
		
		for (current = stamp_end;
				(*current != 0) && (*current != '\n');
				current++) {
			putc(*current, stdout);
		}
		putc('\n', stdout);
		prev_time = stamp;
	}
	return 0;
}

