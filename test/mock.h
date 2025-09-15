/* Copyright (c) 2019-2022 Homa Developers
 * SPDX-License-Identifier: BSD-1-Clause
 */
#ifndef _HOMA_MOCK_H
#define _HOMA_MOCK_H

#include <linux/ethtool.h>

/* Replace various Linux variables and functions with mocked ones. */
#undef alloc_pages
#define alloc_pages mock_alloc_pages

#define atomic64_cmpxchg_relaxed mock_cmpxchg

#undef alloc_percpu_gfp
#define alloc_percpu_gfp(type, flags) mock_kmalloc(10 * sizeof(type), flags)

#define compound_order mock_compound_order

#ifdef cpu_to_node
#undef cpu_to_node
#endif
#define cpu_to_node mock_cpu_to_node

#undef current
#define current current_task

#undef DECLARE_PER_CPU
#define DECLARE_PER_CPU(type, name) extern type name[10]

#undef debug_smp_processor_id
#define debug_smp_processor_id() (pcpu_hot.cpu_number)

#undef DEFINE_PER_CPU
#define DEFINE_PER_CPU(type, name) type name[10]

#undef free_percpu
#define free_percpu(name) kfree(name)

#define get_page mock_get_page

#undef HOMA_MIN_DEFAULT_PORT
#define HOMA_MIN_DEFAULT_PORT mock_min_default_port

#define homa_rpc_hold mock_rpc_hold

#define homa_rpc_put mock_rpc_put

#undef kmalloc
#define kmalloc mock_kmalloc

#undef kmalloc_array
#define kmalloc_array(count, size, type) mock_kmalloc((count) * (size), type)

#define kthread_complete_and_exit(...)

#undef local_irq_save
#define local_irq_save(flags) (flags) = 0

#define net_generic(net, id) mock_net_generic(net, id)

#ifdef page_address
#undef page_address
#endif
#define page_address(page) ((void *)page)

#define page_ref_count mock_page_refs

#define page_to_nid mock_page_to_nid

#undef per_cpu
#define per_cpu(name, core) (name[core])

#undef per_cpu_ptr
#define per_cpu_ptr(name, core) (&name[core])

#undef preempt_disable
#define preempt_disable() mock_preempt_disable()

#undef preempt_enable
#define preempt_enable() mock_preempt_enable()

#define put_page mock_put_page

#define rcu_read_lock mock_rcu_read_lock

#define rcu_read_unlock mock_rcu_read_unlock

#undef register_net_sysctl
#define register_net_sysctl mock_register_net_sysctl

#define signal_pending(...) mock_signal_pending

#undef smp_processor_id
#define smp_processor_id() mock_processor_id()

#define sock_hold(sock) mock_sock_hold(sock)

#define sock_put(sock) mock_sock_put(sock)

#define spin_unlock mock_spin_unlock

#undef this_cpu_ptr
#define this_cpu_ptr(name) (&name[pcpu_hot.cpu_number])

#undef vmalloc
#define vmalloc mock_vmalloc

/* Forward references: */
struct homa;
struct homa_rpc;
struct homa_sock;
struct homa_socktab;

/* Variables and functions for mocking that are exported to test code. */
extern int         mock_alloc_page_errors;
extern int         mock_alloc_skb_errors;
extern int         mock_bpage_size;
extern int         mock_bpage_shift;
extern u64         mock_clock;
extern u64         mock_clock_tick;
extern int         mock_cmpxchg_errors;
extern int         mock_compound_order_mask;
extern int         mock_copy_data_errors;
extern int         mock_copy_to_user_dont_copy;
extern int         mock_copy_to_user_errors;
extern int         mock_cpu_idle;
extern int         mock_dst_check_errors;
extern int         mock_ethtool_ksettings_errors;
extern bool        mock_exit_thread;
extern int         mock_import_iovec_errors;
extern int         mock_import_ubuf_errors;
extern int         mock_ip6_xmit_errors;
extern int         mock_ip_queue_xmit_errors;
extern bool        mock_ipv6;
extern bool        mock_ipv6_default;
extern int         mock_kmalloc_errors;
extern int         mock_kthread_create_errors;
extern int         mock_link_mbps;
extern int         mock_netif_schedule_calls;
extern int         mock_prepare_to_wait_errors;
extern int         mock_register_protosw_errors;
extern int         mock_register_qdisc_errors;
extern int         mock_register_sysctl_errors;
extern int         mock_wait_intr_irq_errors;
extern char        mock_xmit_prios[];
extern int         mock_log_wakeups;
extern int         mock_log_rcu_sched;
extern int         mock_max_grants;
extern int         mock_max_skb_frags;
extern __u16       mock_min_default_port;
extern int         mock_mtu;
extern struct net_device
		   mock_net_device;
extern struct netdev_queue
		   mock_net_queue;
extern struct net  mock_nets[];
extern int         mock_numa_mask;
extern int         mock_page_nid_mask;
extern int         mock_peer_free_no_fail;
extern int         mock_prepare_to_wait_status;
extern char        mock_printk_output[];
extern int         mock_rht_init_errors;
extern int         mock_rht_insert_errors;
extern void      **mock_rht_walk_results;
extern int         mock_rht_num_walk_results;
extern int         mock_route_errors;
extern int         mock_signal_pending;
extern int         mock_sock_holds;
extern int         mock_spin_lock_held;
extern struct task_struct
		   mock_task;
extern int         mock_total_spin_locks;
extern int         mock_trylock_errors;
extern u64         mock_tt_cycles;
extern int         mock_vmalloc_errors;
extern int         mock_xmit_log_verbose;

extern struct task_struct *current_task;

struct page *
	    mock_alloc_pages(gfp_t gfp, unsigned order);
struct homa_net
	   *mock_alloc_hnet(struct homa *homa);
struct Qdisc
	   *mock_alloc_qdisc(struct netdev_queue *dev_queue);
int         mock_check_error(int *errorMask);
void        mock_clear_xmit_prios(void);
s64         mock_cmpxchg(atomic64_t *target, s64 old, s64 new);
unsigned int mock_compound_order(struct page *page);
int         mock_cpu_to_node(int core);
void        mock_data_ready(struct sock *sk);
struct dst_entry
	   *mock_dst_check(struct dst_entry *, __u32 cookie);
cycles_t    mock_get_cycles(void);
int         mock_get_link_ksettings(struct net_device *dev,
				    struct ethtool_link_ksettings *settings);
unsigned int
	    mock_get_mtu(const struct dst_entry *dst);
void        mock_get_page(struct page *page);
void       *mock_kmalloc(size_t size, gfp_t flags);
struct net *mock_net_for_hnet(struct homa_net *hnet);
void       *mock_net_generic(const struct net *net, unsigned int id);
int         mock_page_refs(struct page *page);
int         mock_page_refs(struct page *page);
int         mock_page_to_nid(struct page *page);
void        mock_preempt_disable(void);
void        mock_preempt_enable(void);
int         mock_processor_id(void);
void        mock_put_page(struct page *page);
void        mock_rcu_read_lock(void);
void        mock_rcu_read_unlock(void);
void        mock_record_locked(void *lock);
void        mock_record_unlocked(void *lock);
struct ctl_table_header *
	    mock_register_net_sysctl(struct net *net,
				     const char *path,
				     struct ctl_table *table);
int         mock_rht_init(struct rhashtable *ht,
			  const struct rhashtable_params *params);
void       *mock_rht_lookup_get_insert_fast(struct rhashtable *ht,
					    struct rhash_head *obj,
					    const struct rhashtable_params params);
void       *mock_rht_walk_next(struct rhashtable_iter *iter);
void        mock_rpc_hold(struct homa_rpc *rpc);
void        mock_rpc_put(struct homa_rpc *rpc);
void        mock_set_clock_vals(u64 t, ...);
void        mock_set_core(int num);
void        mock_set_ipv6(struct homa_sock *hsk);
void        mock_spin_lock(spinlock_t *lock);
void        mock_spin_unlock(spinlock_t *lock);
struct sk_buff *
            mock_skb_alloc(struct in6_addr *saddr, struct homa_common_hdr *h,
			 int extra_bytes, int first_value);
int         mock_skb_count(void);
void        mock_sock_destroy(struct homa_sock *hsk,
			      struct homa_socktab *socktab);
void        mock_sock_hold(struct sock *sk);
int         mock_sock_init(struct homa_sock *hsk, struct homa_net *hnet,
			   int port);
void        mock_sock_put(struct sock *sk);
void        mock_teardown(void);
void       *mock_vmalloc(size_t size);

#endif /* _HOMA_MOCK_H */
