/* Functions for mocking that are exported to test code. */

extern int         cpu_number;
extern int         mock_alloc_skb_errors;
extern int         mock_copy_data_errors;
extern int         mock_copy_to_user_errors;
extern cycles_t    mock_cycles;
extern int         mock_ip_queue_xmit_errors;
extern int         mock_kmalloc_errors;
extern int         mock_route_errors;
extern void        (*mock_spin_lock_hook)(void);
extern int         mock_vmalloc_errors;
extern int         mock_xmit_log_verbose;

extern int         mock_check_error(int *errorMask);
extern void        mock_data_ready(struct sock *sk);
extern cycles_t    mock_get_cycles(void);
extern void        mock_spin_lock(spinlock_t *lock);
extern void        mock_spin_unlock(spinlock_t *lock);
extern int         mock_skb_count(void);
extern struct sk_buff *
                   mock_skb_new(__be32 saddr, struct common_header *h,
			int extra_bytes, int first_value);
extern void        mock_sock_destroy(struct homa_sock *hsk,
			struct homa_socktab *socktab);
extern void        mock_sock_init(struct homa_sock *hsk, struct homa *homa,
			int client_port, int server_port);
extern void        mock_teardown(void);