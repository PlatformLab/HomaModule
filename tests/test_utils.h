#ifndef _TEST_UTILS_H
#define _TEST_UTILS_H

#include <netinet/in.h>

#ifdef __cplusplus
extern "C"
{
#endif

extern int     check_buffer(void *buffer, size_t length);
extern double  get_cycles_per_sec();
extern void    seed_buffer(void *buffer, size_t length, int seed);
extern char   *print_address(struct sockaddr_in *addr);

/**
 * rdtsc(): return the current value of the fine-grain CPU cycle counter
 * (accessed via the RDTSC instruction).
 */
inline static uint64_t rdtsc(void)
{
	uint32_t lo, hi;
	__asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
	return (((uint64_t)hi << 32) | lo);
}

#ifdef __cplusplus
}
#endif

#endif /* _TEST_UTILS_H */