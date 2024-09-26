/* Copyright (c) 2019-2022 Homa Developers
 * SPDX-License-Identifier: BSD-1-Clause
 */

#ifndef _TEST_UTILS_H
#define _TEST_UTILS_H

#include <netinet/in.h>

#ifdef __cplusplus
#include <string>
#include <vector>
#endif

#include "homa.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define sizeof32(type) static_cast<int>(sizeof(type))

extern int     check_buffer(void *buffer, size_t length);
extern int     check_message(struct homa_recvmsg_args *control,
	           char *region, size_t length, int skip);
extern double  get_cycles_per_sec();
extern int     get_int(const char *s, const char *msg);
extern void    pin_thread(int core);
extern const char*
               print_address(const union sockaddr_in_union *addr);
extern void    print_dist(uint64_t times[], int count);
extern void    seed_buffer(void *buffer, size_t length, int seed);
#ifdef __cplusplus
extern void    split(const char *s, char sep, std::vector<std::string> &dest);
#endif
extern double  to_seconds(uint64_t cycles);

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
