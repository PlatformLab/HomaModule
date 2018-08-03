/* Functions for mocking that are exported to test code. */

extern int         mock_malloc_errors;

extern void        mock_data_ready(struct sock *sk);
extern int         mock_skb_count(void);
extern struct sk_buff *
                   mock_skb_new(__be32 saddr, struct common_header *h,
			int extra_bytes, int first_value);
extern void        mock_sock_destroy(struct homa_sock *hsk);
extern void        mock_sock_init(struct homa_sock *hsk, struct homa *homa);
extern void        mock_teardown(void);