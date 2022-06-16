/* Copyright (c) 2019-2021 Stanford University
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

/* This file provides simplified substitutes for many Linux variables and
 * functions, in order to allow Homa unit tests to be run outside a Linux
 * kernel.
 */

#include "homa_impl.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#define KSELFTEST_NOT_MAIN 1m
#include "kselftest_harness.h"

/* It isn't safe to include some header files, such as stdlib, because
 * they conflict with kernel header files. The explicit declarations
 * below replace those header files.
 */

extern void       free(void *ptr);
extern void      *malloc(size_t size);
extern void      *memcpy(void *dest, const void *src, size_t n);

/* The variables below can be set to non-zero values by unit tests in order
 * to simulate error returns from various functions. If bit 0 is set to 1,
 * the next call to the function will fail; bit 1 corresponds to the next
 * call after that, and so on.
 */
int mock_alloc_skb_errors = 0;
int mock_copy_data_errors = 0;
int mock_copy_to_iter_errors = 0;
int mock_copy_to_user_errors = 0;
int mock_cpu_idle = 0;
int mock_import_single_range_errors = 0;
int mock_import_iovec_errors = 0;
int mock_ip_queue_xmit_errors = 0;
int mock_kmalloc_errors = 0;
int mock_route_errors = 0;
int mock_spin_lock_held = 0;
int mock_trylock_errors = 0;
int mock_vmalloc_errors = 0;

/* If a test sets this variable to non-NULL, this function will be invoked
 * during future calls to spin_lock or spin_lock_bh.
 */
void (*mock_spin_lock_hook)(void) = NULL;

/* If a test sets this variable to non-NULL, this function will be invoked
 * during future calls to schedule.
 */
void (*mock_schedule_hook)(void) = NULL;

/* The return value from calls to signal_pending(). */
int mock_signal_pending = 0;

/* Used as current task during tests. */
struct task_struct mock_task;

/* If a test sets this variable to nonzero, ip_queue_xmit will log
 * outgoing packets using the long format rather than short.
 */
int mock_xmit_log_verbose = 0;

/* If a test sets this variable to nonzero, call_rcu_sched will log
 * whenever it is invoked.
 */
int mock_log_rcu_sched = 0;

/* The maximum number of grants that can be issued in one call to
 * homa_send_grants.
 */
int mock_max_grants = 10;

/* Keeps track of all sk_buffs that are alive in the current test.
 * Reset for each test.
 */
static struct unit_hash *buffs_in_use = NULL;

/* Keeps track of all the blocks of memory that have been allocated by
 * kmalloc but not yet freed by kfree. Reset for each test.
 */
static struct unit_hash *kmallocs_in_use = NULL;

/* Keeps track of all the results returned by proc_create that have not
 * yet been closed by calling proc_remove. Reset for each test.
 */
static struct unit_hash *proc_files_in_use = NULL;

/* Keeps track of all the results returned by ip_route_output_flow that
 * have not yet been freed. Reset for each test. */
static struct unit_hash *routes_in_use = NULL;

/* Keeps track of all the blocks of memory that have been allocated by
 * vmalloc but not yet freed by vfree. Reset for each test.
 */
static struct unit_hash *vmallocs_in_use = NULL;

/* The number of locks that have been acquired but not yet released. 
 * Should be 0 at the end of each test.
 */
static int mock_active_locks = 0;

/* The number of times rcu_read_lock has been called minus the number
 * of times rcu_read_unlock has been called. 
 * Should be 0 at the end of each test.
 */
static int mock_active_rcu_locks = 0;

/* Used as the return value for calls to get_cycles. A value of ~0 means
 * return actual clock time.
 */
cycles_t mock_cycles = 0;

/* Linux's idea of the current CPU number. */
int cpu_number = 1;

/* List of priorities for all outbound packets. */
char mock_xmit_prios[1000];
int mock_xmit_prios_offset = 0;

/* Maximum packet size allowed by "network" (see homa_message_out_init;
 * chosen so that data packets will have UNIT_TEST_DATA_PER_PACKET bytes
 * of payload. The variable can be modified if useful in some tests.
 */
#define MOCK_MTU (UNIT_TEST_DATA_PER_PACKET + HOMA_IPV4_HEADER_LENGTH \
		+ sizeof(struct data_header))
int mock_mtu = MOCK_MTU;

struct dst_ops mock_dst_ops = {.mtu = mock_get_mtu};
struct net_device mock_net_device = {
		.gso_max_segs = 1000,
		.gso_max_size = MOCK_MTU};

static struct hrtimer_clock_base clock_base;
unsigned int cpu_khz = 1000000;
struct task_struct *current_task = &mock_task;
unsigned long ex_handler_refcount = 0;
struct net init_net;
unsigned long volatile jiffies = 1100;
unsigned int nr_cpu_ids = 8;
unsigned long page_offset_base = 0;
unsigned long phys_base = 0;
unsigned long vmemmap_base = 0;
int __preempt_count = 0;
char sock_flow_table[RPS_SOCK_FLOW_TABLE_SIZE(1024)];
struct rps_sock_flow_table *rps_sock_flow_table
		= (struct rps_sock_flow_table *) sock_flow_table;
__u32 rps_cpu_mask = 0x1f;

extern void add_wait_queue(struct wait_queue_head *wq_head,
		struct wait_queue_entry *wq_entry) {}

struct sk_buff *__alloc_skb(unsigned int size, gfp_t priority, int flags,
		int node)
{
	int shinfo_size;
	if (mock_check_error(&mock_alloc_skb_errors))
		return NULL;
	struct sk_buff *skb = malloc(sizeof(struct sk_buff));
	if (skb == NULL)
		FAIL("skb malloc failed in __alloc_skb");
	memset(skb, 0, sizeof(*skb));
	if (!buffs_in_use)
		buffs_in_use = unit_hash_new();
	unit_hash_set(buffs_in_use, skb, "used");
	size = SKB_DATA_ALIGN(size);
	shinfo_size = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	skb->head = malloc(size + shinfo_size);
	memset(skb->head, 0, size + shinfo_size);
	if (skb->head == NULL)
		FAIL("data malloc failed in __alloc_skb");
	skb->data = skb->head;
	skb_reset_tail_pointer(skb);
	skb->end = skb->tail + size;
	skb->network_header = 0;
	skb->transport_header = 0;
	skb->data_len = 0;
	skb->len = 0;
	skb->users.refs.counter = 1;
	skb->_skb_refdst = 0;
	ip_hdr(skb)->saddr = 0;
	skb->truesize = size;
	return skb;
}

void call_rcu_sched(struct rcu_head *head, rcu_callback_t func)
{
	if (mock_log_rcu_sched)
		unit_log_printf("; ", "call_rcu_sched");
	func(head);
}

void __check_object_size(const void *ptr, unsigned long n, bool to_user) {}

int _cond_resched(void)
{
	return 0;
}

size_t _copy_from_iter(void *addr, size_t bytes, struct iov_iter *iter)
{
	size_t bytes_left = bytes;
	if (mock_check_error(&mock_copy_data_errors))
		return false;
	if (bytes > iter->count) {
		unit_log_printf("; ", "copy_from_iter needs %lu bytes, but "
				"iov_iter has only %lu", bytes, iter->count);
		return 0;
	}
	while (bytes_left > 0) {
		struct iovec *iov = (struct iovec *) iter->iov;
		__u64 int_base = (__u64) iov->iov_base;
		size_t chunk_bytes = iov->iov_len;
		if (chunk_bytes > bytes_left)
			chunk_bytes = bytes_left;
		unit_log_printf("; ", "_copy_from_iter %lu bytes at %llu",
				chunk_bytes, int_base);
		bytes_left -= chunk_bytes;
		iter->count -= chunk_bytes;
		iov->iov_base = (void *) (int_base + chunk_bytes);
		iov->iov_len -= chunk_bytes;
		if (iov->iov_len == 0)
			iter->iov++;
	}
	return bytes;
}

bool _copy_from_iter_full(void *addr, size_t bytes, struct iov_iter *i)
{
	if (mock_check_error(&mock_copy_data_errors))
		return false;
	unit_log_printf("; ", "_copy_from_iter_full copied %lu bytes", bytes);
	return true;
}

bool _copy_from_iter_full_nocache(void *addr, size_t bytes, struct iov_iter *i)
{
	if (mock_check_error(&mock_copy_data_errors))
		return false;
	unit_log_printf("; ", "_copy_from_iter_full_nocache copid %lu bytes",
			bytes);
	return true;
}

size_t _copy_to_iter(const void *addr, size_t bytes, struct iov_iter *i)
{
	if (mock_check_error(&mock_copy_to_iter_errors))
		return 0;
	unit_log_printf("; ", "_copy_to_iter: %.*s", (int) bytes,
			(char *) addr);
	return bytes;
}

unsigned long _copy_to_user(void __user *to, const void *from, unsigned long n)
{
	if (mock_check_error(&mock_copy_to_user_errors))
		return -1;
	memcpy(to, from, n);
	((char *)(to))[n] = 0;
	unit_log_printf("; ", "_copy_to_user copied %lu bytes", n);
	return 0;
}

bool csum_and_copy_from_iter_full(void *addr, size_t bytes, __wsum *csum,
			       struct iov_iter *i)
{
	if (mock_check_error(&mock_copy_data_errors))
		return false;
	unit_log_printf("; ", "csum_and_copy_from_iter_full copied %lu bytes",
			bytes);
	return true;
}

unsigned long _copy_from_user(void *to, const void __user *from,
		unsigned long n)
{
	__u64 int_from = (__u64) from;
	if (mock_check_error(&mock_copy_data_errors))
		return 1;
	if (int_from > 200000)
		memcpy(to, from, n);
	unit_log_printf("; ", "_copy_from_user %lu bytes at %llu", n, int_from);
	return 0;
}

void do_exit(long error_code)
{
	while(1) {}
}

void dst_release(struct dst_entry *dst)
{
	if (!dst)
		return;
	dst->__refcnt.counter--;
	if (dst->__refcnt.counter > 0)
		return;
	if (!routes_in_use || unit_hash_get(routes_in_use, dst) == NULL) {
		FAIL("dst_release on unknown route");
		return;
	}
	unit_hash_erase(routes_in_use, dst);
	free(dst);
}

void finish_wait(struct wait_queue_head *wq_head,
		struct wait_queue_entry *wq_entry) {}

void get_random_bytes(void *buf, int nbytes)
{
	memset(buf, 0, nbytes);
}

int hrtimer_cancel(struct hrtimer *timer)
{
	return 0;
}

u64 hrtimer_forward(struct hrtimer *timer, ktime_t now,
		ktime_t interval)
{
	return 0;
}

ktime_t hrtimer_get_time(void)
{
	return 0;
}

void hrtimer_init(struct hrtimer *timer, clockid_t clock_id,
		  enum hrtimer_mode mode)
{
	timer->base = &clock_base;
	clock_base.get_time = &hrtimer_get_time;
}

void hrtimer_start_range_ns(struct hrtimer *timer, ktime_t tim,
		u64 range_ns, const enum hrtimer_mode mode) {}

void __icmp_send(struct sk_buff *skb, int type, int code, __be32 info,
		const struct ip_options *opt)
{
	unit_log_printf("; ", "icmp_send type %d, code %d", type, code);
}

int idle_cpu(int cpu)
{
	return mock_check_error(&mock_cpu_idle);
}

ssize_t import_iovec(int type, const struct iovec __user * uvector,
		unsigned nr_segs, unsigned fast_segs,
		struct iovec **iov, struct iov_iter *iter)
{
	ssize_t size;
	unsigned i;

	*iov = (struct iovec *) kmalloc(nr_segs*sizeof(struct iovec), GFP_KERNEL);
	if (mock_check_error(&mock_import_iovec_errors))
		return -EINVAL;
	size = 0;
	for (i = 0; i < nr_segs; i++) {
		size += uvector[i].iov_len;
		(*iov)[i] = uvector[i];
	}
	iov_iter_init(iter, type, *iov, nr_segs, size);
	return size;
}

int import_single_range(int type, void __user *buf, size_t len,
		struct iovec *iov, struct iov_iter *i)
{
	if (mock_check_error(&mock_import_single_range_errors))
		return -EACCES;
	iov->iov_base = buf;
	iov->iov_len = len;
	iov_iter_init(i, type, iov, 1, len);
	return 0;
}

int inet_add_protocol(const struct net_protocol *prot, unsigned char num)
{
	return 0;
}

int inet_add_offload(const struct net_offload *prot, unsigned char protocol)
{
	return 0;
}

int inet_del_protocol(const struct net_protocol *prot, unsigned char num)
{
	return 0;
}

int inet_del_offload(const struct net_offload *prot, unsigned char protocol)
{
	return 0;
}

int inet_dgram_connect(struct socket *sock, struct sockaddr *uaddr,
		       int addr_len, int flags)
{
	return 0;
}

int inet_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	return 0;
}

int inet_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	return 0;
}

int inet_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
		int flags)
{
	return 0;
}

void inet_register_protosw(struct inet_protosw *p) {}

int inet_release(struct socket *sock)
{
	return 0;
}

int inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	return 0;
}

void inet_unregister_protosw(struct inet_protosw *p) {}

void init_wait_entry(struct wait_queue_entry *wq_entry, int flags) {}

void __init_waitqueue_head(struct wait_queue_head *wq_head, const char *name,
		struct lock_class_key *key) {}

void iov_iter_init(struct iov_iter *i, unsigned int direction,
			const struct iovec *iov, unsigned long nr_segs,
			size_t count)
{
	direction &= READ | WRITE;
	i->type = ITER_IOVEC | direction;
	i->iov = iov;
	i->nr_segs = nr_segs;
	i->iov_offset = 0;
	i->count = count;
}

void iov_iter_revert(struct iov_iter *i, size_t bytes)
{
	unit_log_printf("; ", "iov_iter_revert %lu", bytes);
}

int __ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl,
		__u8 tos)
{
	char buffer[200];
	const char *prefix = " ";
	if (mock_check_error(&mock_ip_queue_xmit_errors)) {
		/* Latest data (as of 1/2019) suggests that ip_queue_xmit
		 * frees packets after errors.
		 */
		kfree_skb(skb);
		return -ENETDOWN;
	}
	if (mock_xmit_prios_offset == 0)
		prefix = "";
	mock_xmit_prios_offset += snprintf(
			mock_xmit_prios + mock_xmit_prios_offset,
			sizeof(mock_xmit_prios) - mock_xmit_prios_offset,
			"%s%d", prefix, ((struct inet_sock *) sk)->tos>>5);
	if (mock_xmit_log_verbose)
		homa_print_packet(skb, buffer, sizeof(buffer));
	else
		homa_print_packet_short(skb, buffer, sizeof(buffer));
	unit_log_printf("; ", "xmit %s", buffer);
	kfree_skb(skb);
	return 0;
}

struct rtable *ip_route_output_flow(struct net *net, struct flowi4 *flp4,
		const struct sock *sk)
{
	struct rtable *route;
	if (mock_check_error(&mock_route_errors))
		return ERR_PTR(-EHOSTUNREACH);
	route = malloc(sizeof(struct rtable));
	if (!route) {
		FAIL("malloc failed");
		return ERR_PTR(-ENOMEM);
	}
	route->dst.__refcnt.counter = 1;
	route->dst.ops = &mock_dst_ops;
	route->dst.dev = &mock_net_device;
	route->dst.obsolete = 0;
	if (!routes_in_use)
		routes_in_use = unit_hash_new();
	unit_hash_set(routes_in_use, route, "used");
	return route;
}

int ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr,
		int addr_len)
{
	return 0;
}

void ip4_datagram_release_cb(struct sock *sk) {}

void kfree(const void *block)
{
	if (block == NULL)
		return;
	if (!kmallocs_in_use || unit_hash_get(kmallocs_in_use, block) == NULL) {
		FAIL("kfree on unknown block");
		return;
	}
	unit_hash_erase(kmallocs_in_use, block);
	free((void *) block);
}

void kfree_skb(struct sk_buff *skb)
{
	skb->users.refs.counter--;
	if (skb->users.refs.counter > 0)
		return;
	skb_dst_drop(skb);
	if (!buffs_in_use || unit_hash_get(buffs_in_use, skb) == NULL) {
		FAIL("kfree_skb on unknown sk_buff");
		return;
	}
	unit_hash_erase(buffs_in_use, skb);
	while (skb_shinfo(skb)->frag_list) {
		struct sk_buff *next = skb_shinfo(skb)->frag_list->next;
		kfree_skb(skb_shinfo(skb)->frag_list);
		skb_shinfo(skb)->frag_list = next;
	}
	free(skb->head);
	free(skb);
}

void *__kmalloc(size_t size, gfp_t flags)
{
	if (mock_check_error(&mock_kmalloc_errors))
		return NULL;
	void *block = malloc(size);
	if (!block) {
		FAIL("malloc failed");
		return NULL;
	}
	if (!kmallocs_in_use)
		kmallocs_in_use = unit_hash_new();
	unit_hash_set(kmallocs_in_use, block, "used");
	return block;
}

struct task_struct *kthread_create_on_node(int (*threadfn)(void *data),
					   void *data, int node,
					   const char namefmt[],
					   ...)
{
	return NULL;
}

int kthread_stop(struct task_struct *k)
{
	return 0;
}

void __local_bh_enable_ip(unsigned long ip, unsigned int cnt) {}

void lock_sock_nested(struct sock *sk, int subclass)
{
	mock_active_locks++;
	sk->sk_lock.owned = 1;
}

ssize_t __modver_version_show(struct module_attribute *a,
		struct module_kobject *b, char *c)
{
	return 0;
}

void __mutex_init(struct mutex *lock, const char *name,
			 struct lock_class_key *key)
{
	
}

void mutex_lock(struct mutex *lock)
{
	mock_active_locks++;
}

void mutex_unlock(struct mutex *lock)
{
	mock_active_locks--;
}

int netif_receive_skb(struct sk_buff *skb)
{
	struct data_header *h = (struct data_header *)
			skb_transport_header(skb);
	unit_log_printf("; ", "netif_receive_skb, id %llu, offset %d",
			be64_to_cpu(h->common.sender_id), ntohl(h->seg.offset));
	return 0;
}

long prepare_to_wait_event(struct wait_queue_head *wq_head,
		struct wait_queue_entry *wq_entry, int state)
{
	return 0;
}

int printk(const char *s, ...)
{
	return 0;
}

struct proc_dir_entry *proc_create(const char *name, umode_t mode,
				   struct proc_dir_entry *parent,
				   const struct file_operations *proc_fops)
{
	struct proc_dir_entry *entry = malloc(40);
	if (!entry) {
		FAIL("malloc failed");
		return ERR_PTR(-ENOMEM);
	}
	if (!proc_files_in_use)
		proc_files_in_use = unit_hash_new();
	unit_hash_set(proc_files_in_use, entry, "used");
	return entry;
}

int proc_dointvec(struct ctl_table *table, int write,
		     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return 0;
}

void proc_remove(struct proc_dir_entry *de)
{
	if (!proc_files_in_use
			|| unit_hash_get(proc_files_in_use, de) == NULL) {
		FAIL("proc_remove on unknown dir_entry");
		return;
	}
	unit_hash_erase(proc_files_in_use, de);
	free(de);
	
}

int proto_register(struct proto *prot, int alloc_slab)
{
	return 0;
}

void proto_unregister(struct proto *prot) {}

void *__pskb_pull_tail(struct sk_buff *skb, int delta)
{
	return NULL;
}

void _raw_spin_lock(raw_spinlock_t *lock)
{
	mock_active_locks++;
}

void __lockfunc _raw_spin_lock_bh(raw_spinlock_t *lock)
{
	if (mock_spin_lock_hook) {
		mock_spin_lock_hook();
	}
	mock_active_locks++;
}

int __lockfunc _raw_spin_trylock_bh(raw_spinlock_t *lock)
{
	if (mock_check_error(&mock_trylock_errors))
		return 0;
	if (mock_spin_lock_hook) {
		mock_spin_lock_hook();
	}
	mock_active_locks++;
	return 1;
}

void __lockfunc _raw_spin_unlock_bh(raw_spinlock_t *lock)
{
	mock_active_locks--;
}

int __lockfunc _raw_spin_trylock(raw_spinlock_t *lock)
{
	if (mock_check_error(&mock_spin_lock_held))
		return 0;
	mock_active_locks++;
	return 1;
}

struct ctl_table_header *register_net_sysctl(struct net *net,
	const char *path, struct ctl_table *table)
{
	return NULL;
}

void release_sock(struct sock *sk)
{
	mock_active_locks--;
	sk->sk_lock.owned = 0;
}

void remove_wait_queue(struct wait_queue_head *wq_head,
		struct wait_queue_entry *wq_entry) {}

void schedule(void)
{
	if (mock_schedule_hook)
		mock_schedule_hook();
	else
		unit_log_printf("; ", "schedule");
}

void security_sk_classify_flow(struct sock *sk, struct flowi *fl) {}

void sk_common_release(struct sock *sk) {}

int sk_set_peek_off(struct sock *sk, int val)
{
	return 0;
}

int skb_copy_datagram_iter(const struct sk_buff *from, int offset,
		struct iov_iter *iter, int size)
{
	size_t bytes_left = size;
	if (bytes_left > iter->count) {
		unit_log_printf("; ", "skb_copy_datagram_iter needs %lu bytes, "
				"but iov_iter has only %lu",
				bytes_left, iter->count);
		return 0;
	}
	while (bytes_left > 0) {
		struct iovec *iov = (struct iovec *) iter->iov;
		__u64 int_base = (__u64) iov->iov_base;
		size_t chunk_bytes = iov->iov_len;
		if (chunk_bytes > bytes_left)
			chunk_bytes = bytes_left;
		unit_log_printf("; ",
				"skb_copy_datagram_iter: %lu bytes to %llu: ",
				chunk_bytes, int_base);
		unit_log_data(NULL, from->data + offset + size - bytes_left,
				chunk_bytes);
		bytes_left -= chunk_bytes;
		iter->count -= chunk_bytes;
		iov->iov_base = (void *) (int_base + chunk_bytes);
		iov->iov_len -= chunk_bytes;
		if (iov->iov_len == 0)
			iter->iov++;
	}
	return 0;
}

struct sk_buff *skb_dequeue(struct sk_buff_head *list)
{
	return __skb_dequeue(list);
}

void *skb_pull(struct sk_buff *skb, unsigned int len)
{
	if ((skb_tail_pointer(skb) - skb->data) < len)
		FAIL("sk_buff underflow during pull");
	skb->len -= len;
	return skb->data += len;
}

void *skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *result = skb_tail_pointer(skb);
	skb->tail += len;
	skb->len += len;
	return result;
}

int sock_common_getsockopt(struct socket *sock, int level, int optname,
		char __user *optval, int __user *optlen)
{
	return 0;
}

int sock_common_setsockopt(struct socket *sock, int level, int optname,
		char __user *optval, unsigned int optlen)
{
	return 0;
}

int sock_no_accept(struct socket *sock, struct socket *newsock, int flags,
		bool kern)
{
	return 0;
}

int sock_no_listen(struct socket *sock, int backlog)
{
	return 0;
}

int sock_no_mmap(struct file *file, struct socket *sock,
		struct vm_area_struct *vma)
{
	return 0;
}

int sock_no_shutdown(struct socket *sock, int how)
{
	return 0;
}

ssize_t sock_no_sendpage(struct socket *sock, struct page *page, int offset,
		size_t size, int flags)
{
	return 0;
}

int sock_no_socketpair(struct socket *sock1, struct socket *sock2)
{
	return 0;
}

void synchronize_sched(void) {}

void __tasklet_hi_schedule(struct tasklet_struct *t) {}

void tasklet_init(struct tasklet_struct *t,
		void (*func)(unsigned long), unsigned long data) {}

void tasklet_kill(struct tasklet_struct *t) {}

void unregister_net_sysctl_table(struct ctl_table_header *header) {}

void vfree(const void *block)
{
	if (!vmallocs_in_use || unit_hash_get(vmallocs_in_use, block) == NULL) {
		FAIL("vfree on unknown block");
		return;
	}
	unit_hash_erase(vmallocs_in_use, block);
	free((void *) block);
}

void *vmalloc(size_t size)
{
	if (mock_check_error(&mock_vmalloc_errors))
		return NULL;
	void *block = malloc(size);
	if (!block) {
		FAIL("malloc failed");
		return NULL;
	}
	if (!vmallocs_in_use)
		vmallocs_in_use = unit_hash_new();
	unit_hash_set(vmallocs_in_use, block, "used");
	return block;
}

long wait_woken(struct wait_queue_entry *wq_entry, unsigned mode,
		long timeout)
{
	return 0;
}

void __wake_up(struct wait_queue_head *wq_head, unsigned int mode,
		int nr_exclusive, void *key) {}

int wake_up_process(struct task_struct *tsk)
{
	unit_log_printf("; ", "wake_up_process pid %d", tsk ? tsk->pid : -1);
	return 0;
}

void __warn_printk(const char *s, ...) {}

int woken_wake_function(struct wait_queue_entry *wq_entry, unsigned mode,
		int sync, void *key)
{
	return 0;
}

/**
 * mock_check_error() - Determines whether a method should simulate an error
 * return.
 * @errorMask:  Address of a variable containing a bit mask, indicating
 *              which of the next calls should result in errors.
 * 
 * Return:      zero means the function should behave normally; 1 means return
 *              an eror 
 */
int mock_check_error(int *errorMask)
{
	int result = *errorMask & 1;
	*errorMask = *errorMask >> 1;
	return result;
}

/**
 * mock_clear_xmit_prios() - Remove all information from the list of
 * transmit priorities.
 */
void mock_clear_xmit_prios()
{
	mock_xmit_prios_offset = 0;
	mock_xmit_prios[0] = 0;
}

/**
 * mock_data_ready() - Invoked through sk->sk_data_ready; logs a message
 * to indicate that it was invoked.
 * @sk:    Associated socket; not used here.
 */
void mock_data_ready(struct sock *sk)
{
	unit_log_printf("; ", "sk->sk_data_ready invoked");
}

/**
 * mock_get_cycles() - Replacement for get_cycles; allows time to be
 * hard-while using mock_cycles variable.
 */
cycles_t mock_get_cycles(void)
{
	if (mock_cycles == ~0) {
		uint32_t lo, hi;
		__asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
		return (((uint64_t)hi << 32) | lo);
	} 
	return mock_cycles;
}

/**
 * This function is invoked through dst->dst_ops.mtu. It returns the
 * maximum size of packets that the network can transmit.
 * @dst_entry:   The route whose MTU is desired.
 */
unsigned int mock_get_mtu(const struct dst_entry *dst)
{
	return mock_mtu;
}

/**
 * mock_rcu_read_lock() - Called instead of rcu_read_lock when Homa is compiled
 * for unit testing.
 */
void mock_rcu_read_lock(void)
{
	mock_active_rcu_locks++;
}

/**
 * mock_rcu_read_unlock() - Called instead of rcu_read_unlock when Homa is
 * compiled for unit testing.
 */
void mock_rcu_read_unlock(void)
{
	if (mock_active_rcu_locks == 0)
		FAIL(" rcu_read_unlock called without rcu_read_lock");
	mock_active_rcu_locks--;
}

/**
 * mock_skb_new() - Allocate and return a packet buffer. The buffer is
 * initialized as if it just arrived from the network.
 * @saddr:        IPV4 address to use as the sender of the packet, in
 *                network byte order.
 * @h:            Header for the buffer; actual length and contents depend
 *                on the type.
 * @extra_bytes:  How much additional data to add to the buffer after
 *                the header.
 * @first_value:  Determines the data contents: the first __u32 will have
 *                this value, and each successive __u32 will increment by 4.
 * 
 * Return:        A packet buffer containing the information described above.
 *                The caller owns this buffer and is responsible for freeing it.
 */
struct sk_buff *mock_skb_new(__be32 saddr, struct common_header *h,
		int extra_bytes, int first_value)
{
	int header_size, ip_size, data_size, shinfo_size;
	unsigned char *p;
	
	switch (h->type) {
	case DATA:
		header_size = sizeof(struct data_header);
		break;
	case GRANT:
		header_size = sizeof(struct grant_header);
		break;
	case RESEND:
		header_size = sizeof(struct resend_header);
		break;
	case UNKNOWN:
		header_size = sizeof(struct unknown_header);
		break;
	case BUSY:
		header_size = sizeof(struct busy_header);
		break;
	case CUTOFFS:
		header_size = sizeof(struct cutoffs_header);
		break;
	case FREEZE:
		header_size = sizeof(struct freeze_header);
		break;
	case NEED_ACK:
		header_size = sizeof(struct need_ack_header);
		break;
	case ACK:
		header_size = sizeof(struct ack_header);
		break;
	default:
		header_size = sizeof(struct common_header);
		break;
	}
	struct sk_buff *skb = malloc(sizeof(struct sk_buff));
	memset(skb, 0, sizeof(*skb));
	if (!buffs_in_use)
		buffs_in_use = unit_hash_new();
	unit_hash_set(buffs_in_use, skb, "used");
	
	ip_size = sizeof(struct iphdr);
	data_size = SKB_DATA_ALIGN(ip_size + header_size + extra_bytes);
	shinfo_size = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	skb->head = malloc(data_size + shinfo_size);
	memset(skb->head, 0, data_size + shinfo_size);
	skb->data = skb->head;
	skb_reset_tail_pointer(skb);
	skb->end = skb->tail + data_size;
	skb_reserve(skb, ip_size);
	skb_reset_transport_header(skb);
	p = skb_put(skb, header_size);
	memcpy(skb->data, h, header_size);
	p = skb_put(skb, extra_bytes);
	unit_fill_data(p, extra_bytes, first_value);
	skb->users.refs.counter = 1;
	ip_hdr(skb)->saddr = saddr;
	ip_hdr(skb)->protocol = IPPROTO_HOMA;
	skb->_skb_refdst = 0;
	skb->hash = 3;
	return skb;
}

/**
 * Returns the number of sk_buffs currently in use.
 */
int mock_skb_count(void)
{
	return unit_hash_size(buffs_in_use);
}

/**
 * mock_sock_init() - Constructor for sockets; initializes the Homa-specific
 * part, and mocks out the non-Homa-specific parts.
 * @hsk:          Storage area to be initialized.\
 * @homa:         Overall information about the Homa protocol.
 * @port:         Port number to use for the socket, or 0 to
 *                use default.
 */
void mock_sock_init(struct homa_sock *hsk, struct homa *homa, int port)
{
	struct sock *sk = (struct sock *) hsk;
	int saved_port = homa->next_client_port;
	memset(hsk, 0, sizeof(*hsk));
	if ((port != 0) && (port >= HOMA_MIN_DEFAULT_PORT))
		homa->next_client_port = port;
	homa_sock_init(hsk, homa);
	if (port != 0)
		homa->next_client_port = saved_port;
	if (port < HOMA_MIN_DEFAULT_PORT)
		homa_sock_bind(&homa->port_map, hsk, port);
	sk->sk_data_ready = mock_data_ready;
}

/**
 * mock_spin_unlock() - Called instead of spin_unlock when Homa is compiled
 * for unit testing.
 * @lock:   Lock to be be released (ignored).
 */
void mock_spin_unlock(spinlock_t *lock)
{
	mock_active_locks--;
}

/**
 * mock_teardown() - Invoked at the end of each unit test to check for
 * consistency issues with all of the information managed by this file.
 * This function also cleans up the mocking information, so it is ready
 * for the next unit test.
 */
void mock_teardown(void)
{
	cpu_number = 1;
	cpu_khz = 1000000;
	mock_alloc_skb_errors = 0;
	mock_copy_data_errors = 0;
	mock_copy_to_iter_errors = 0;
	mock_copy_to_user_errors = 0;
	mock_cpu_idle = 0;
	mock_cycles = 0;
	mock_import_single_range_errors = 0;
	mock_import_iovec_errors = 0;
	mock_ip_queue_xmit_errors = 0;
	mock_kmalloc_errors = 0;
	mock_kmalloc_errors = 0;
	mock_max_grants = 10;
	mock_xmit_prios_offset = 0;
	mock_xmit_prios[0] = 0;
	mock_log_rcu_sched = 0;
	mock_route_errors = 0;
	mock_trylock_errors = 0;
	mock_vmalloc_errors = 0;
	memset(&mock_task, 0, sizeof(mock_task));
	mock_schedule_hook = NULL;
	mock_signal_pending = 0;
	mock_spin_lock_hook = NULL;
	mock_xmit_log_verbose = 0;
	mock_mtu = MOCK_MTU;
	mock_net_device.gso_max_size = MOCK_MTU;
	
	int count = unit_hash_size(buffs_in_use);
	if (count > 0)
		FAIL(" %u sk_buff(s) still in use after test", count);
	unit_hash_free(buffs_in_use);
	buffs_in_use = NULL;
	
	count = unit_hash_size(kmallocs_in_use);
	if (count > 0)
		FAIL(" %u kmalloced block(s) still allocated after test", count);
	unit_hash_free(kmallocs_in_use);
	kmallocs_in_use = NULL;
	
	count = unit_hash_size(proc_files_in_use);
	if (count > 0)
		FAIL(" %u proc file(s) still allocated after test", count);
	unit_hash_free(proc_files_in_use);
	proc_files_in_use = NULL;
	
	count = unit_hash_size(routes_in_use);
	if (count > 0)
		FAIL(" %u route(s) still allocated after test", count);
	unit_hash_free(routes_in_use);
	routes_in_use = NULL;
	
	count = unit_hash_size(vmallocs_in_use);
	if (count > 0)
		FAIL(" %u vmalloced block(s) still allocated after test", count);
	unit_hash_free(vmallocs_in_use);
	vmallocs_in_use = NULL;
	
	if (mock_active_locks != 0)
		FAIL(" %d locks still locked after test", mock_active_locks);
	mock_active_locks = 0;
	
	if (mock_active_rcu_locks != 0)
		FAIL(" %d rcu_read_locks still active after test",
				mock_active_rcu_locks);
	mock_active_rcu_locks = 0;
}