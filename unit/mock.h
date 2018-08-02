/* Functions for mocking that are exported to test code. */

extern struct sk_buff *
                   mock_skb_new(__be32 saddr, struct common_header *h,
			int extra_bytes, int first_value);
extern void        mock_skb_teardown(void);