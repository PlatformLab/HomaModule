/* SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+ */

/* This file defines functions that are useful during Homa development;
 * they are not present in the upstreamed version of Homa in Linux.
 */

#ifndef _HOMA_DEVEL_H
#define _HOMA_DEVEL_H

#ifdef __UNIT_TEST__
#ifndef __NO_KSELFTEST__
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#endif /* __NO_KSELFTEST__ */
#endif /* __UNIT_TEST__ */

#include "timetrace.h"

#ifdef __STRIP__
#define INC_METRIC(...)

#undef LINUX_VERSION_CODE
#define LINUX_VERSION_CODE 100

#undef KERNEL_VERSION
#define KERNEL_VERSION(...) 100
#endif /* __STRIP__ */

struct homa;
struct homa_net;
struct homa_rpc;

/**
 * enum homa_freeze_type - The @type argument to homa_freeze must be
 * one of these values.
 */
enum homa_freeze_type {
	RESTART_RPC            = 1,
	PEER_TIMEOUT           = 2,
	SLOW_RPC               = 3,
	PACKET_LOST            = 4,
	NEED_ACK_MISSING_DATA  = 5,
};

/**
 * struct homa_rpc_snapshot - Captures the state of RPCs (both client and
 * server) on a node at a given point in time.
 */
struct homa_rpc_snapshot {
	/** @clock: homa_clock() value when data was gathered. */
	u64 clock;

	/* Each value below is the sum (across all cores) of the metric with
	 * the same name.
	 */
	u64 client_requests_started;
	u64 client_request_bytes_started;
	u64 client_request_bytes_done;
	u64 client_requests_done;

	u64 client_responses_started;
	u64 client_response_bytes_started;
	u64 client_response_bytes_done;
	u64 client_responses_done;

	u64 server_requests_started;
	u64 server_request_bytes_started;
	u64 server_request_bytes_done;
	u64 server_requests_done;

	u64 server_responses_started;
	u64 server_response_bytes_started;
	u64 server_response_bytes_done;
	u64 server_responses_done;
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

static inline void check_addr_valid(void *addr, char *info)
{
#ifndef __UNIT_TEST__
#define HIGH_BITS 0xffff800000000000
	u64 int_addr = (u64)addr;

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
#define IF_NO_STRIP(...)
#endif /* See strip.py */

void     homa_check_addr(void *p);
void     homa_check_list(struct list_head *list, int max_length);
int      homa_drop_packet(struct homa *homa);
void     homa_freeze(struct homa_rpc *rpc, enum homa_freeze_type type,
		     char *format);
void     homa_freeze_peers(void);
char    *homa_print_ipv4_addr(__be32 addr);
char    *homa_print_ipv6_addr(const struct in6_addr *addr);
char    *homa_print_packet(struct sk_buff *skb, char *buffer, int buf_len);
char    *homa_print_packet_short(struct sk_buff *skb, char *buffer,
				 int buf_len);
void     homa_rpc_log(struct homa_rpc *rpc);
void     homa_rpc_log_active(struct homa *homa, uint64_t id);
void     homa_rpc_log_tt(struct homa_rpc *rpc);
void     homa_rpc_log_active_tt(struct homa *homa, int freeze_count);
void     homa_rpc_snapshot_log_tt(void);
void     homa_rpc_stats_log(void);
void     homa_snapshot_get_stats(struct homa_rpc_snapshot *snap);
void     homa_snapshot_rpcs(void);
int      homa_snprintf(char *buffer, int size, int used,
		       const char *format, ...) __printf(4, 5);
char    *homa_symbol_for_type(uint8_t type);
char    *homa_symbol_for_state(struct homa_rpc *rpc);
int      homa_validate_incoming(struct homa *homa, int verbose,
				int *link_errors);

#ifndef __STRIP__ /* See strip.py */
bool     homa_rpcs_deferred(struct homa *homa);
void     homa_validate_rbtree(struct rb_node *node, int depth, char *message);
#endif /* See strip.py */

#endif /* _HOMA_DEVEL_H */
