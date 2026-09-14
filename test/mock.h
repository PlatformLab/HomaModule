/* Copyright (c) 2019-2022 Homa Developers
 * SPDX-License-Identifier: BSD-1-Clause
 */
#ifndef _HOMA_MOCK_H
#define _HOMA_MOCK_H

/* This file must be the very first #include for every compiled .c file
 * (forced via -include mock.h in the test Makefile, before homa_impl.h and
 * before any real kernel header). <linux/mm.h> -> <linux/bit_spinlock.h>
 * and <linux/lockdep.h> -> <linux/smp.h>, dragged in transitively by many
 * kernel headers homa_impl.h includes (skbuff.h, kthread.h, completion.h,
 * sched/signal.h, proc_fs.h, etc.), use preempt_disable()/preempt_enable()/
 * smp_processor_id()/raw_smp_processor_id()/WARN_ON_ONCE() in inline
 * functions; those inline functions bake in whichever macro definition is
 * active when the header is first parsed. Getting the mocked versions
 * active before any of that runs requires mock.h itself to be included
 * first, standalone. homa_impl.h's own later #include "mock.h" is then a
 * no-op (include guard), but these overrides are already in effect.
 */
#include <linux/bug.h>

#undef WARN
#define WARN(...)

#undef WARN_ON
#define WARN_ON(condition) ({						\
	int __ret_warn_on = !!(condition);				\
	unlikely(__ret_warn_on);					\
})

#undef WARN_ON_ONCE
#define WARN_ON_ONCE(condition) WARN_ON(condition)

#undef WARN_ONCE
#define WARN_ONCE(cond, ...) ({ bool __c = (cond); (void)__c; __c; })

/* Pulling in the real <linux/preempt.h>/<linux/smp.h> here first (before
 * the undef/define below) sets their include guards so later transitive
 * re-inclusion is a no-op and can't clobber these overrides. This must
 * come after the WARN overrides above, since preempt.h drags in
 * <linux/thread_info.h> (via linkage.h), whose inline functions use
 * WARN_ON_ONCE() and must see the mocked (no-op) version.
 */
#include <linux/preempt.h>
#include <linux/smp.h>

/* Forward declarations needed because the overrides below are used by
 * headers included further down in this file, before mock.c's own
 * declarations (later in this file) would otherwise be visible.
 */
void mock_preempt_disable(void);
void mock_preempt_enable(void);
int mock_processor_id(void);

#undef preempt_disable
#define preempt_disable() mock_preempt_disable()

#undef preempt_enable
#define preempt_enable() mock_preempt_enable()

#undef smp_processor_id
#define smp_processor_id() mock_processor_id()

#undef raw_smp_processor_id
#define raw_smp_processor_id() mock_processor_id()

/* <net/tcp.h> (tcp_v4_check/tcp_v6_check), <linux/filter.h> (this_cpu_ptr,
 * via <linux/bpf.h>), <net/icmp.h> (icmp_send), <net/ip6_route.h>
 * (rt6_get_cookie, via <net/ip6_fib.h>) and <net/netns/generic.h>
 * (net_generic) all declare real inline functions/objects whose names this
 * file redirects below via object-style macros; those macros corrupt the
 * real declarations if the real headers are parsed afterward (their
 * include guards would otherwise make a later re-inclusion elsewhere a
 * silent no-op with the corrupted macro baked in). Pulling them in here
 * first, before any of the redirects below, avoids that. homa.h is
 * included here too so the HOMA_BPAGE_SIZE/HOMA_MIN_DEFAULT_PORT/etc.
 * overrides below apply after the real values are already defined, instead
 * of being silently clobbered by a later #include of homa.h from
 * homa_impl.h.
 */
#include <net/tcp.h>
#include <net/ip6_checksum.h>
#include <linux/filter.h>
#include <net/icmp.h>
#include <net/ip6_route.h>
#include <net/netns/generic.h>
#include "homa.h"
#include "homa_wire.h"

#include <linux/ethtool.h>

/* Replace various Linux variables and functions with mocked ones. */
#undef alloc_pages
#define alloc_pages mock_alloc_pages

#define atomic64_cmpxchg_relaxed mock_cmpxchg

#undef alloc_percpu_gfp
#define alloc_percpu_gfp(type, flags) mock_kmalloc(10 * sizeof(type), flags)

#define compound_order mock_compound_order

#undef cpu_relax
#define cpu_relax mock_cpu_relax

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

#undef HOMA_BPAGE_SIZE
#define HOMA_BPAGE_SIZE mock_bpage_size

#undef HOMA_BPAGE_SHIFT
#define HOMA_BPAGE_SHIFT mock_bpage_shift

#undef HOMA_MAX_BPAGES
#define HOMA_MAX_BPAGES 16

#undef HOMA_MIN_DEFAULT_PORT
#define HOMA_MIN_DEFAULT_PORT mock_min_default_port

#define homa_rpc_hold mock_rpc_hold

#define homa_rpc_put mock_rpc_put

#undef kmalloc
#define kmalloc mock_kmalloc

#undef kmalloc_array
#define kmalloc_array(count, size, type) mock_kmalloc((count) * (size), type)

#undef kmap_local_page
#define kmap_local_page(page) ((void *)page)

#define kthread_complete_and_exit(...)

#undef local_bh_disable
#define local_bh_disable() mock_local_bh_disable()

#undef local_bh_enable
#define local_bh_enable() mock_local_bh_enable()

#undef local_irq_save
#define local_irq_save(flags) (flags) = 0

#undef MAX_SKB_FRAGS
#define MAX_SKB_FRAGS mock_max_skb_frags

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

#undef preempt_count_add
#define preempt_count_add(val) mock_preempt_count_add(val)

#undef preempt_count_sub
#define preempt_count_sub(val) mock_preempt_count_sub(val)

#define put_page mock_put_page

#define rcu_read_lock mock_rcu_read_lock

#define rcu_read_lock_bh mock_rcu_read_lock

#define rcu_read_unlock mock_rcu_read_unlock

#define rcu_read_unlock_bh mock_rcu_read_unlock

#define refcount_inc_not_zero mock_refcount_inc_not_zero

#undef register_net_sysctl
#define register_net_sysctl mock_register_net_sysctl

#define rt6_get_cookie(...) 999

#define signal_pending(...) mock_signal_pending

/* Must redefine skb_frag_foreach_page because page pointers are different
 * when unit testing (a page point points to an actual page, rather than
 * a descriptor)
 */
#undef skb_frag_foreach_page
#define skb_frag_foreach_page(f, f_off, f_len, p, p_off, p_len, copied)	\
	for (p = skb_frag_page(f),                      \
	     p_off = (f_off),                           \
	     p_len = f_len,                             \
	     copied = 0;                                \
	     copied < f_len;                            \
	     copied += p_len, p++, p_off = 0,           \
	     p_len = f_len - copied)                    \

#define sock_hold(sock) mock_sock_hold(sock)

#define sock_put(sock) mock_sock_put(sock)

#define spin_unlock mock_spin_unlock

#undef tcp_v4_check
#define tcp_v4_check(...) (~(__force __sum16)444U)

#undef tcp_v6_check
#define tcp_v6_check(...) (~(__force __sum16)666U)

#undef this_cpu_ptr
#define this_cpu_ptr(name) (&name[cpu_number])

#undef __this_cpu_read
#define __this_cpu_read(name) (name)

#undef vmalloc
#define vmalloc mock_vmalloc

/* Forward references: */
struct homa;
struct homa_pool;
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
extern bool        mock_check_bpool_leaks;
extern int         mock_cmpxchg_errors;
extern int         mock_compound_order_mask;
extern int         mock_copy_data_errors;
extern bool        mock_copy_from_iter_no_log;
extern int         mock_copy_to_frags_errors;
extern int         mock_copy_to_user_dont_copy;
extern int         mock_copy_to_user_errors;
extern int         mock_cpu_idle;
extern int         cpu_number;
extern struct net_device
		   mock_devices[];
extern enum skb_drop_reason
		   mock_drop_reasons[];
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
extern int         mock_log_wakeups;
extern int         mock_log_rcu_sched;
extern int         mock_max_grants;
extern int         mock_max_skb_frags;
extern __u16       mock_min_default_port;
extern int         mock_mtu;
extern struct netdev_queue
		   mock_net_queue;
extern int         mock_netif_schedule_calls;
extern struct net  mock_nets[];
extern bool        mock_no_high_order_pages;
extern int         mock_num_drop_reasons;
extern int         mock_numa_mask;
extern int         mock_page_nid_mask;
extern int         mock_peer_free_no_fail;
extern int         mock_prepare_to_wait_errors;
extern int         mock_prepare_to_wait_status;
extern char        mock_printk_output[];
extern int         mock_queue_index;
extern int         mock_register_protosw_errors;
extern int         mock_register_qdisc_errors;
extern int         mock_register_sysctl_errors;
extern int         mock_rht_init_errors;
extern int         mock_rht_insert_errors;
extern void      **mock_rht_walk_results;
extern int         mock_rht_num_walk_results;
extern int         mock_route_errors;
extern int         mock_signal_pending;
extern int         mock_sock_holds;
extern struct task_struct
		   mock_task;
extern int         mock_total_spin_locks;
extern int         mock_trylock_errors;
extern u64         mock_tt_cycles;
extern int         mock_vmalloc_errors;
extern int         mock_wait_intr_irq_errors;
extern int         mock_xmit_log_verbose;
extern int         mock_xmit_log_hijack;
extern char        mock_xmit_prios[];

extern struct task_struct *current_task;

struct page *
	    mock_alloc_pages(gfp_t gfp, unsigned order);
struct Qdisc
	   *mock_alloc_qdisc(struct netdev_queue *dev_queue);
int         mock_check_error(int *errorMask);
void        mock_clear_xmit_prios(void);
s64         mock_cmpxchg(atomic64_t *target, s64 old, s64 new);
unsigned int mock_compound_order(struct page *page);
void        mock_cpu_relax(void);
int         mock_cpu_to_node(int core);
void        mock_data_ready(struct sock *sk);
struct net_device
	   *mock_dev(int index, struct homa *homa);
struct dst_entry
	   *mock_dst_check(struct dst_entry *, __u32 cookie);
void        mock_free_pool(struct homa_pool *pool);
cycles_t    mock_get_cycles(void);
int         mock_get_link_ksettings(struct net_device *dev,
				    struct ethtool_link_ksettings *settings);
unsigned int
	    mock_get_mtu(const struct dst_entry *dst);
void        mock_get_page(struct page *page);
struct homa_net
	   *mock_hnet(int index, struct homa *homa);
bool        mock_is_locked(void *lock);
void       *mock_kmalloc(size_t size, gfp_t flags);
void        mock_local_bh_disable(void);
void        mock_local_bh_enable(void);
struct net *mock_net_for_hnet(struct homa_net *hnet);
void       *mock_net_generic(const struct net *net, unsigned int id);
int         mock_page_refs(struct page *page);
int         mock_page_refs(struct page *page);
int         mock_page_to_nid(struct page *page);
void        mock_preempt_disable(void);
void        mock_preempt_enable(void);
void        mock_preempt_count_add(int val);
void        mock_preempt_count_sub(int val);
int         mock_processor_id(void);
void        mock_put_page(struct page *page);
struct sk_buff *
	    mock_raw_skb(struct in6_addr *saddr, struct in6_addr *daddr,
			 int protocol, int length);
void        mock_rcu_free(void);
void        mock_rcu_read_lock(void);
void        mock_rcu_read_unlock(void);
void        mock_record_locked(void *lock);
void        mock_record_unlocked(void *lock);
bool        mock_refcount_inc_not_zero(refcount_t *r);
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
struct sk_buff *
            mock_skb_alloc(struct in6_addr *saddr, struct in6_addr *daddr,
			   struct homa_common_hdr *h, int extra_bytes,
			   int first_value);
int         mock_skb_count(void);
void        mock_sock_destroy(struct homa_sock *hsk,
			      struct homa_socktab *socktab);
void        mock_sock_hold(struct sock *sk);
int         mock_sock_init(struct homa_sock *hsk, struct homa_net *hnet,
			   int port);
void        mock_sock_put(struct sock *sk);
void        mock_spin_lock(spinlock_t *lock);
void        mock_spin_unlock(spinlock_t *lock);
struct sk_buff *
	    mock_tcp_skb(struct in6_addr *saddr, struct in6_addr *daddr,
			 int sequence, int extra_bytes);
void        mock_teardown(void);
void       *mock_vmalloc(size_t size);

#endif /* _HOMA_MOCK_H */
