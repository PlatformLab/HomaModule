/* Utility functions for unit tests, implemented in C. */

struct unit_hash;

#define sizeof32(type) ((int) (sizeof(type)));

extern struct homa_rpc
                    *unit_client_rpc(struct homa_sock *hsk, int state,
			__be32 client_ip, __be32 server_ip, int server_port,
			int id, int req_length, int resp_length);
extern __be32        unit_get_in_addr(char *s);
extern struct homa_metrics
                    *unit_get_metrics(void);
extern int           unit_list_length(struct list_head *head);
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