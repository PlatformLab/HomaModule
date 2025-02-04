/* SPDX-License-Identifier: BSD-2-Clause */

/* This file defines functions that are useful during Homa development;
 * they are not present in the upstreamed version of Homa in Linux.
 */

#ifndef _HOMA_DEVEL_H
#define _HOMA_DEVEL_H

#include "homa_impl.h"
struct homa_rpc;

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
