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

#ifndef _TEST_UTILS_H
#define _TEST_UTILS_H

#include <netinet/in.h>

#ifdef __cplusplus
extern "C"
{
#endif
	
#define sizeof32(type) static_cast<int>(sizeof(type))

extern int     check_buffer(void *buffer, size_t length);
extern double  get_cycles_per_sec();
extern int     get_int(const char *s, const char *msg);
extern void    print_dist(uint64_t times[], int count);
extern void    seed_buffer(void *buffer, size_t length, int seed);
extern char   *print_address(struct sockaddr_in *addr);
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