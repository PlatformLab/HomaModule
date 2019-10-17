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

/* Utility functions for unit tests, implemented in C. */

struct unit_hash;

/**
 * define UNIT_TEST_DATA_PER_PACKET - bytes of payload to use as the
 * default for packets sent in unit tests.
 */
#define UNIT_TEST_DATA_PER_PACKET 1400

extern struct homa_rpc
                    *unit_client_rpc(struct homa_sock *hsk, int state,
			__be32 client_ip, __be32 server_ip, int server_port,
			int id, int req_length, int resp_length);
extern __be32        unit_get_in_addr(char *s);
extern struct homa_metrics
                    *unit_get_metrics(void);
extern int           unit_list_length(struct list_head *head);
extern void          unit_log_frag_list(struct sk_buff *skb, int verbose);
extern void          unit_log_grantables(struct homa *homa);
extern void          unit_log_message_out_packets(
			struct homa_message_out *message, int verbose);
extern struct homa_rpc
                    *unit_server_rpc(struct homa_sock *hsk, int state,
			__be32 server_ip, __be32 client_ip, int client_port,
			int id, int req_length, int resp_length);
extern void          unit_log_skb_list(struct sk_buff_head *packets,
			int verbose);
extern void          unit_log_throttled(struct homa *homa);
extern void          unit_teardown(void);