/* SPDX-License-Identifier: BSD-2-Clause */

/* This file defines functions that are useful during Homa development;
 * they are not present in the upstreamed version of Homa in Linux.
 */

#ifndef _HOMA_DEVEL_H
#define _HOMA_DEVEL_H

#include "timetrace.h"

struct homa;
struct homa_rpc;

/**
 * enum homa_freeze_type - The @type argument to homa_freeze must be
 * one of these values.
 */
enum homa_freeze_type {
	RESTART_RPC            = 1,
	PEER_TIMEOUT           = 2,
	SLOW_RPC               = 3,
	SOCKET_CLOSE           = 4,
	PACKET_LOST            = 5,
	NEED_ACK_MISSING_DATA  = 6,
};

/**
 * tt_addr() - Given an address, return a 4-byte id that will (hopefully)
 * provide a unique identifier for the address in a timetrace record.
 * @x:  Address (either IPv6 or IPv4-mapped IPv6)
 * Return: see above
 */
static inline u32 tt_addr(const struct in6_addr x)
{
	return ipv6_addr_v4mapped(&x) ? ntohl(x.in6_u.u6_addr32[3])
			: (x.in6_u.u6_addr32[3] ? ntohl(x.in6_u.u6_addr32[3])
			: ntohl(x.in6_u.u6_addr32[1]));
}

/**
 * addr_valid() - Determine whether a given address is a valid address
 * within kernel memory.
 * @addr:    Address to check
 */
static inline int addr_valid(void *addr)
{
#ifdef __UNIT_TEST__
	return 1;
#else
#define HIGH_BITS 0xffff800000000000
	u64 int_addr = (u64) addr;

	return (int_addr & HIGH_BITS) == HIGH_BITS;
#endif /* __UNIT_TEST__ */
}

static inline void check_addr_valid(void *addr, char *info)
{
#ifndef __UNIT_TEST__
#define HIGH_BITS 0xffff800000000000
	u64 int_addr = (u64) addr;

	if ((int_addr & HIGH_BITS) != HIGH_BITS) {
		pr_err("Bogus address 0x%px (%s))\n", addr, info);
		tt_record("Freezing timetrace because of bogus address");
		tt_record(info);
		tt_freeze();
		tt_printk();
		pr_err("Finished dumping timetrace\n");
		BUG_ON(1);
	}
#endif /* __UNIT_TEST__ */
}

#ifndef __STRIP__ /* See strip.py */
#define IF_NO_STRIP(code) code
#else /* See strip.py */
#define IF_NO_STRIP(code)
#endif /* See strip.py */

#ifndef __STRIP__ /* See strip.py */
void     homa_freeze(struct homa_rpc *rpc, enum homa_freeze_type type,
		     char *format);
void     homa_freeze_peers(struct homa *homa);
#endif /* See strip.py */
char    *homa_print_ipv4_addr(__be32 addr);
char    *homa_print_ipv6_addr(const struct in6_addr *addr);
char    *homa_print_packet(struct sk_buff *skb, char *buffer, int buf_len);
char    *homa_print_packet_short(struct sk_buff *skb, char *buffer,
				  int buf_len);
int      homa_snprintf(char *buffer, int size, int used,
                       const char *format, ...) __printf(4, 5);
char    *homa_symbol_for_type(uint8_t type);
char    *homa_symbol_for_state(struct homa_rpc *rpc);

#endif /* _HOMA_DEVEL_H */
