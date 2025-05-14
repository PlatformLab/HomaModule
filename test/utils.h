/* SPDX-License-Identifier: BSD-2-Clause */

/* Utility functions for unit tests, implemented in C. */

struct homa_message_out;
struct homa_rpc;
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

char        *unit_ack_string(struct homa_ack *ack);
struct homa_rpc
	    *unit_client_rpc(struct homa_sock *hsk,
			     enum unit_rpc_state state, struct in6_addr *client_ip,
			     struct in6_addr *server_ip, int server_port, int id,
			     int req_length, int resp_length);
int          unit_count_peers(struct homa *homa);
struct in6_addr
	     unit_get_in_addr(char *s);
void         unit_homa_destroy(struct homa *homa);
struct iov_iter
	    *unit_iov_iter(void *buffer, size_t length);
int          unit_list_length(struct list_head *head);
void         unit_log_active_ids(struct homa_sock *hsk);
void         unit_log_filled_skbs(struct sk_buff *skb, int verbose);
void         unit_log_frag_list(struct sk_buff *skb, int verbose);
#ifndef __STRIP__ /* See strip.py */
void         unit_log_grantables(struct homa *homa);
#endif /* See strip.py */
void         unit_log_hashed_rpcs(struct homa_sock *hsk);
void         unit_log_message_out_packets(struct homa_message_out *message,
				      int verbose);
const char  *unit_print_gaps(struct homa_rpc *rpc);
struct homa_rpc
	    *unit_server_rpc(struct homa_sock *hsk,
			     enum unit_rpc_state state,
			     struct in6_addr *server_ip,
			     struct in6_addr *client_ip,
			     int client_port, int id, int req_length,
			     int resp_length);
void         unit_log_skb_list(struct sk_buff_head *packets,
			       int verbose);
void         unit_log_throttled(struct homa *homa);
void         unit_teardown(void);

/* Kludge to avoid including arpa/inet.h, which causes definition
 * conflicts with kernel header files.
 */
int inet_pton(int af, const char *src, void *dst);
