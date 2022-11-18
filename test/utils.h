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

/* Utility functions for unit tests, implemented in C. */

struct unit_hash;

/**
 * define UNIT_TEST_DATA_PER_PACKET - bytes of payload to use as the
 * default for packets sent in unit tests.
 */
#define UNIT_TEST_DATA_PER_PACKET 1400

/**
 * enum unit_rpc_state - used as the @state argument to unit_client_rpc
 * and unit_server_rpc.
 * UNIT_OUTGOING -      RPC state is RPC_OUTGOING, no packets have been sent.
 * UNIT_RCVD_ONE_PKT -  RPC state is RPC_INCOMING, a single packet has
 *                      been received.
 * UNIT_RCVD_MSG -      RPC state is RPC_INCOMING, the entire message has
 *                      been received.
 * UNIT_IN_SERVICE -    RPC state is RPC_IN_SERVICE (only valid for
 *                      unit_server_rpc).
 */
enum unit_rpc_state {
	UNIT_OUTGOING       = 21,
	UNIT_RCVD_ONE_PKT   = 22,
	UNIT_RCVD_MSG       = 23,
	UNIT_IN_SERVICE     = 24,
};

extern char         *unit_ack_string(struct homa_ack *ack);
extern struct homa_rpc
                    *unit_client_rpc(struct homa_sock *hsk,
		        enum unit_rpc_state state, struct in6_addr *client_ip,
		        struct in6_addr *server_ip, int server_port, int id,
		        int req_length, int resp_length);
extern struct in6_addr
                     unit_get_in_addr(char *s);
extern void          unit_hook(char *id);
extern void          unit_hook_set(void (*hook_proc)(char *id));
extern struct iov_iter
                    *unit_iov_iter(void *buffer, size_t length);
extern int           unit_list_length(struct list_head *head);
extern void          unit_log_active_ids(struct homa_sock *hsk);
extern void          unit_log_filled_skbs(struct sk_buff *skb, int verbose);
extern void          unit_log_frag_list(struct sk_buff *skb, int verbose);
extern void          unit_log_grantables(struct homa *homa);
extern void          unit_log_hashed_rpcs(struct homa_sock *hsk);
extern void          unit_log_message_out_packets(
                        struct homa_message_out *message, int verbose);
extern struct homa_rpc
                    *unit_server_rpc(struct homa_sock *hsk,
		        enum unit_rpc_state state, struct in6_addr *server_ip,
		        struct in6_addr *client_ip, int client_port, int id,
		        int req_length, int resp_length);
extern void          unit_log_skb_list(struct sk_buff_head *packets,
                        int verbose);
extern void          unit_log_throttled(struct homa *homa);
extern void          unit_teardown(void);
