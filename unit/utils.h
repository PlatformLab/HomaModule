/* Utility functions for unit tests, implemented in C. */

struct unit_hash;

extern __be32        unit_get_in_addr(char *s);
extern int           unit_list_length(struct list_head *head);
extern void          unit_log_message_out_packets(
			struct homa_message_out *message, int verbose);
extern void          unit_log_skb_list(struct sk_buff_head *packets,
			int verbose);
extern void          unit_teardown(void);