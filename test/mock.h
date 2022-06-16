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

/* Functions for mocking that are exported to test code. */

extern int         cpu_number;
extern int         mock_alloc_skb_errors;
extern int         mock_copy_data_errors;
extern int         mock_copy_to_user_errors;
extern int         mock_cpu_idle;
extern cycles_t    mock_cycles;
extern int         mock_import_iovec_errors;
extern int         mock_import_single_range_errors;
extern int         mock_ip_queue_xmit_errors;
extern int         mock_kmalloc_errors;
extern char        mock_xmit_prios[];
extern int         mock_log_rcu_sched;
extern int         mock_max_grants;
extern int         mock_mtu;
extern struct net_device
		   mock_net_device;
extern int         mock_route_errors;
extern void        (*mock_schedule_hook)(void);
extern int         mock_spin_lock_held;
extern void        (*mock_spin_lock_hook)(void);
extern struct task_struct
		   mock_task;
extern int         mock_trylock_errors;
extern int         mock_vmalloc_errors;
extern int         mock_xmit_log_verbose;

extern int         mock_check_error(int *errorMask);
extern void        mock_clear_xmit_prios(void);
extern void        mock_data_ready(struct sock *sk);
extern cycles_t    mock_get_cycles(void);
extern unsigned int
		   mock_get_mtu(const struct dst_entry *dst);
extern void        mock_rcu_read_lock(void);
extern void        mock_rcu_read_unlock(void);
extern void        mock_spin_lock(spinlock_t *lock);
extern void        mock_spin_unlock(spinlock_t *lock);
extern int         mock_skb_count(void);
extern struct sk_buff *
                   mock_skb_new(__be32 saddr, struct common_header *h,
			int extra_bytes, int first_value);
extern void        mock_sock_destroy(struct homa_sock *hsk,
			struct homa_socktab *socktab);
extern void        mock_sock_init(struct homa_sock *hsk, struct homa *homa,
			int port);
extern void        mock_teardown(void);