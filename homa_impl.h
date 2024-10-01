/* SPDX-License-Identifier: BSD-2-Clause */

/* This file contains definitions that are shared across the files
 * that implement Homa for Linux.
 */

#ifndef _HOMA_IMPL_H
#define _HOMA_IMPL_H

#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic ignored "-Wunused-variable"

#include <linux/bug.h>
#ifdef __UNIT_TEST__
#undef WARN
#define WARN(condition, format...)

#undef WARN_ON
#define WARN_ON(condition) ({						\
	int __ret_warn_on = !!(condition);				\
	unlikely(__ret_warn_on);					\
})

#undef WARN_ON_ONCE
#define WARN_ON_ONCE(condition) WARN_ON(condition)
#endif

#include <linux/audit.h>
#include <linux/icmp.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/proc_fs.h>
#include <linux/sched/signal.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/gro.h>
#include <net/rps.h>
#pragma GCC diagnostic warning "-Wpointer-sign"
#pragma GCC diagnostic warning "-Wunused-variable"

#ifdef __UNIT_TEST__
#undef alloc_pages
#define alloc_pages mock_alloc_pages
extern struct page *mock_alloc_pages(gfp_t gfp, unsigned int order);

#define compound_order mock_compound_order
extern unsigned int mock_compound_order(struct page *page);

#define cpu_to_node mock_cpu_to_node
extern int mock_cpu_to_node(int cpu);

#undef current
#define current current_task
extern struct task_struct *current_task;

#undef get_cycles
#define get_cycles mock_get_cycles
extern cycles_t mock_get_cycles(void);

#define get_page mock_get_page
extern void mock_get_page(struct page *page);

#undef kmalloc
#define kmalloc mock_kmalloc
extern void *mock_kmalloc(size_t size, gfp_t flags);

#undef kmalloc_array
#define kmalloc_array(count, size, type) mock_kmalloc(count*size, type)

#define kthread_complete_and_exit(comp, code)

#ifdef page_address
#undef page_address
#endif
#define page_address(page) ((void *) page)

#define page_ref_count mock_page_refs
extern int mock_page_refs(struct page *page);

#define page_to_nid mock_page_to_nid
extern int mock_page_to_nid(struct page *page);

#define put_page mock_put_page
extern void mock_put_page(struct page *page);

#define rcu_read_lock mock_rcu_read_lock
extern void mock_rcu_read_lock(void);

#define rcu_read_unlock mock_rcu_read_unlock
extern void mock_rcu_read_unlock(void);

#undef register_net_sysctl
#define register_net_sysctl mock_register_net_sysctl
extern struct ctl_table_header *mock_register_net_sysctl(struct net *net,
		const char *path, struct ctl_table *table);

#define signal_pending(xxx) mock_signal_pending
extern int mock_signal_pending;

#define spin_unlock mock_spin_unlock
extern void mock_spin_unlock(spinlock_t *lock);

#undef vmalloc
#define vmalloc mock_vmalloc
extern void *mock_vmalloc(size_t size);

#undef DECLARE_PER_CPU
#define DECLARE_PER_CPU(type, name) extern type name[10];

#undef DEFINE_PER_CPU
#define DEFINE_PER_CPU(type, name) type name[10];

#undef per_cpu
#define per_cpu(name, core) (name[core])
#endif /* __UNIT_TEST__ */

/* Null out things that confuse VSCode Intellisense */
#ifdef __VSCODE__
#define raw_smp_processor_id() 1
#define BUG()
#define BUG_ON(...)
#define set_current_state(...)
#endif

/* Forward declarations. */
struct homa_sock;
struct homa;

#include "homa.h"
#include "timetrace.h"
#include "homa_rpc.h"
#include "homa_wire.h"
#include "homa_metrics.h"

/* Declarations used in this file, so they can't be made at the end. */
extern int      homa_grantable_lock_slow(struct homa *homa, int recalc);
extern void     homa_throttle_lock_slow(struct homa *homa);

extern struct homa_core *homa_cores[];
extern struct homa_numa *homa_numas[];
extern int homa_num_numas;

#define sizeof32(type) ((int) (sizeof(type)))

/** define CACHE_LINE_SIZE - The number of bytes in a cache line. */
#define CACHE_LINE_SIZE 64

/**
 * define HOMA_MAX_GRANTS - Used to size various data structures for grant
 * management; the max_overcommit sysctl parameter must never be greater than
 * this.
 */
#define HOMA_MAX_GRANTS 10

/**
 * define HOMA_PAGE_ORDER: power-of-two exponent determining how
 * many pages to allocate in a high-order page for skb pages (e.g.,
 * 2 means allocate in units of 4 pages).
 */
#define HOMA_SKB_PAGE_ORDER 4

/**
 * define HOMA_PAGE_SIZE: number of bytes corresponding to HOMA_PAGE_ORDER.
 */
#define HOMA_SKB_PAGE_SIZE (PAGE_SIZE << HOMA_SKB_PAGE_ORDER)

/**
 * struct homa_cache_line - An object whose size equals that of a cache line.
 */
struct homa_cache_line {
	char bytes[64];
};

/**
 * struct homa_interest - Contains various information used while waiting
 * for incoming messages (indicates what kinds of messages a particular
 * thread is interested in receiving).
 */
struct homa_interest {
	/**
	 * @thread: Thread that would like to receive a message. Will get
	 * woken up when a suitable message becomes available.
	 */
	struct task_struct *thread;

	/**
	 * @ready_rpc: This is actually a (struct homa_rpc *) identifying the
	 * RPC that was found; NULL if no RPC has been found yet. This
	 * variable is used for synchronization to handoff the RPC, and
	 * must be set only after @locked is set.
	 */
	atomic_long_t ready_rpc;

	/**
	 * @locked: Nonzero means that @ready_rpc is locked; only valid
	 * if @ready_rpc is non-NULL.
	 */
	int locked;

	/**
	 * @core: Core on which @thread was executing when it registered
	 * its interest.  Used for load balancing (see balance.txt).
	 */
	int core;

	/**
	 * @reg_rpc: RPC whose @interest field points here, or
	 * NULL if none.
	 */
	struct homa_rpc *reg_rpc;

	/**
	 * @request_links: For linking this object into
	 * &homa_sock.request_interests. The interest must not be linked
	 * on either this list or @response_links if @id is nonzero.
	 */
	struct list_head request_links;

	/**
	 * @response_links: For linking this object into
	 * &homa_sock.request_interests.
	 */
	struct list_head response_links;
};

/**
 * homa_interest_init() - Fill in default values for all of the fields
 * of a struct homa_interest.
 * @interest:   Struct to initialize.
 */
static inline void homa_interest_init(struct homa_interest *interest)
{
	interest->thread = current;
	atomic_long_set(&interest->ready_rpc, 0);
	interest->locked = 0;
	interest->core = raw_smp_processor_id();
	interest->reg_rpc = NULL;
	interest->request_links.next = LIST_POISON1;
	interest->response_links.next = LIST_POISON1;
}

/**
 * enum homa_freeze_type - The @type argument to homa_freeze must be
 * one of these values.
 */
enum homa_freeze_type {
	RESTART_RPC            = 1,
	PEER_TIMEOUT           = 2,
	SLOW_RPC               = 3,
	SOCKET_CLOSE           = 4,
	PACKET_LOST            = 5,
	NEED_ACK_MISSING_DATA  = 6,
};

/**
 * struct homa_page_pool - A cache of free pages available for use in tx skbs.
 * Each page is of size HOMA_SKB_PAGE_SIZE, and a pool is dedicated for
 * use by a single NUMA node. Access to these objects is synchronized with
 * @homa->page_pool_mutex.
 */
struct homa_page_pool {
	/** @avail: Number of free pages currently in the pool. */
	int avail;

	/**
	 * @low_mark: Low water mark: smallest value of avail since the
	 * last time homa_skb_release_pages reset it.
	 */
	int low_mark;

#define HOMA_PAGE_POOL_SIZE 1000

	/**
	 * @pages: Pointers to pages that are currently free; the ref count
	 * is 1 in each of these pages.
	 */
	struct page *pages[HOMA_PAGE_POOL_SIZE];
};

/**
 * struct homa - Overall information about the Homa protocol implementation.
 *
 * There will typically only exist one of these at a time, except during
 * unit tests.
 */
struct homa {
	/**
	 * @next_outgoing_id: Id to use for next outgoing RPC request.
	 * This is always even: it's used only to generate client-side ids.
	 * Accessed without locks.
	 */
	atomic64_t next_outgoing_id;

	/**
	 * @link_idle_time: The time, measured by get_cycles() at which we
	 * estimate that all of the packets we have passed to Linux for
	 * transmission will have been transmitted. May be in the past.
	 * This estimate assumes that only Homa is transmitting data, so
	 * it could be a severe underestimate if there is competing traffic
	 * from, say, TCP. Access only with atomic ops.
	 */
	atomic64_t link_idle_time __aligned(CACHE_LINE_SIZE);

	/**
	 * @grantable_lock: Used to synchronize access to grant-related
	 * fields below, from @grantable_peers to @last_grantable_change.
	 */
	spinlock_t grantable_lock __aligned(CACHE_LINE_SIZE);

	/**
	 * @grantable_lock_time: get_cycles() time when grantable_lock
	 * was last locked.
	 */
	__u64 grantable_lock_time;

	/**
	 * @grant_recalc_count: Incremented every time homa_grant_recalc
	 * starts a new recalculation; used to avoid unnecessary
	 * recalculations in other threads. If a thread sees this value
	 * change, it knows that someone else is recalculating grants.
	 */
	atomic_t grant_recalc_count;

	/**
	 * @grantable_peers: Contains all peers with entries in their
	 * grantable_rpcs lists. The list is sorted in priority order of
	 * the highest priority RPC for each peer (fewer ungranted bytes ->
	 * higher priority).
	 */
	struct list_head grantable_peers;

	/**
	 * @grantable_rpcs: Contains all RPCs that have not been fully
	 * granted. The list is sorted in priority order (fewer ungranted
	 * bytes -> higher priority).
	 */
	struct list_head grantable_rpcs;

	/** @num_grantable_rpcs: The number of RPCs in grantable_rpcs. */
	int num_grantable_rpcs;

	/** @last_grantable_change: The get_cycles time of the most recent
	 * increment or decrement of num_grantable_rpcs; used for computing
	 * statistics.
	 */
	__u64 last_grantable_change;

	/**
	 * @max_grantable_rpcs: The largest value that has been seen for
	 * num_grantable_rpcs since this value was reset to 0 (it can be
	 * reset externally using sysctl).
	 */
	int max_grantable_rpcs;

	/**
	 * @oldest_rpc: The RPC with incoming data whose start_cycles is
	 * farthest in the past). NULL means either there are no incoming
	 * RPCs or the oldest needs to be recomputed. Must hold grantable_lock
	 * to update.
	 */
	struct homa_rpc *oldest_rpc;

	/**
	 * @grant_window: How many bytes of granted but not yet received data
	 * may exist for an RPC at any given time.
	 */
	int grant_window;

	/**
	 * @num_active_rpcs: number of entries in @active_rpcs and
	 * @active_remaining that are currently used.
	 */
	int num_active_rpcs;

	/**
	 * @active_rpcs: pointers to all of the RPCs that we will grant to
	 * right now. Slot 0 is highest priority.
	 */
	struct homa_rpc *active_rpcs[HOMA_MAX_GRANTS];

	/**
	 * @bytes_remaining: entry i in this array contains a copy of
	 * active_rpcs[i]->msgin.bytes_remaining. These values can be
	 * updated by the corresponding RPCs without holding the grantable
	 * lock. Perfect consistency isn't required; this is used only to
	 * detect when the priority ordering of messages changes.
	 */
	atomic_t active_remaining[HOMA_MAX_GRANTS];

	/**
	 * @grant_nonfifo: How many bytes should be granted using the
	 * normal priority system between grants to the oldest message.
	 */
	int grant_nonfifo;

	/**
	 * @grant_nonfifo_left: Counts down bytes using the normal
	 * priority mechanism. When this reaches zero, it's time to grant
	 * to the old message.
	 */
	int grant_nonfifo_left;

	/**
	 * @pacer_mutex: Ensures that only one instance of homa_pacer_xmit
	 * runs at a time. Only used in "try" mode: never block on this.
	 */
	spinlock_t pacer_mutex __aligned(CACHE_LINE_SIZE);

	/**
	 * @pacer_fifo_fraction: The fraction of time (in thousandths) when
	 * the pacer should transmit next from the oldest message, rather
	 * than the highest-priority message. Set externally via sysctl.
	 */
	int pacer_fifo_fraction;

	/**
	 * @pacer_fifo_count: When this becomes <= zero, it's time for the
	 * pacer to allow the oldest RPC to transmit.
	 */
	int pacer_fifo_count;

	/**
	 * @pacer_start: get_cycles() time when the pacer last woke up
	 * (if the pacer is running) or 0 if the pacer is sleeping.
	 */
	__u64 pacer_wake_time;

	/**
	 * @throttle_lock: Used to synchronize access to @throttled_rpcs. To
	 * insert or remove an RPC from throttled_rpcs, must first acquire
	 * the RPC's socket lock, then this lock.
	 */
	spinlock_t throttle_lock;

	/**
	 * @throttled_rpcs: Contains all homa_rpcs that have bytes ready
	 * for transmission, but which couldn't be sent without exceeding
	 * the queue limits for transmission. Manipulate only with "_rcu"
	 * functions.
	 */
	struct list_head throttled_rpcs;

	/**
	 * @throttle_add: The get_cycles() time when the most recent RPC
	 * was added to @throttled_rpcs.
	 */
	__u64 throttle_add;

	/**
	 * @throttle_min_bytes: If a packet has fewer bytes than this, then it
	 * bypasses the throttle mechanism and is transmitted immediately.
	 * We have this limit because for very small packets we can't keep
	 * up with the NIC (we're limited by CPU overheads); there's no
	 * need for throttling and going through the throttle mechanism
	 * adds overhead, which slows things down. At least, that's the
	 * hypothesis (needs to be verified experimentally!). Set externally
	 * via sysctl.
	 */
	int throttle_min_bytes;

	/**
	 * @total_incoming: the total number of bytes that we expect to receive
	 * (across all messages) even if we don't send out any more grants
	 * (includes granted but unreceived bytes, plus unreceived unscheduled
	 * bytes that we know about). This can potentially be negative, if
	 * a peer sends more bytes than granted (see synchronization note in
	 * homa_send_grants for why we have to allow this possibility).
	 */
	atomic_t total_incoming __aligned(CACHE_LINE_SIZE);

	/**
	 * @next_client_port: A client port number to consider for the
	 * next Homa socket; increments monotonically. Current value may
	 * be in the range allocated for servers; must check before using.
	 * This port may also be in use already; must check.
	 */
	__u16 next_client_port __aligned(CACHE_LINE_SIZE);

	/**
	 * @port_map: Information about all open sockets.
	 */
	struct homa_socktab port_map __aligned(CACHE_LINE_SIZE);

	/**
	 * @peertab: Info about all the other hosts we have communicated with.
	 * Dynamically allocated; must be kfreed.
	 */
	struct homa_peertab *peers;

	/**
	 * @page_pool_mutex: Synchronizes access to any/all of the page_pools
	 * used for outgoing sk_buff data.
	 */
	spinlock_t page_pool_mutex __aligned(CACHE_LINE_SIZE);

	/**
	 * @skb_page_frees_per_sec: Rate at which to return pages from sk_buff
	 * page pools back to Linux. This is the total rate across all pools.
	 * Set externally via sysctl.
	 */
	int skb_page_frees_per_sec;

	/**
	 * @skb_pages_to_free: Space in which to collect pages that are
	 * about to be released. Dynamically allocated.
	 */
	struct page **skb_pages_to_free;

	/**
	 * @pages_to_free_slot: Maximum number of pages that can be
	 * stored in skb_pages_to_free;
	 */
	int pages_to_free_slots;

	/**
	 * @skb_page_free_time: Time (in get_cycles() units) when the
	 * next sk_buff page should be freed. Could be in the past.
	 */
	__u64 skb_page_free_time;

	/**
	 * @skb_page_pool_min_mb: Don't return pages from a pool to Linux
	 * if the amount of cached data in the pool has been less than this
	 * many KBytes at any time in the recent past. Set externally via
	 * sysctl.
	 */
	int skb_page_pool_min_kb;

	/**
	 * @unsched_bytes: The number of bytes that may be sent in a
	 * new message without receiving any grants. There used to be a
	 * variable rtt_bytes that served this purpose, and was also used
	 * for window.  Historically, rtt_bytes was intended to be the amount
	 * of data that can be transmitted over the wire in the time it
	 * takes to send a full-size data packet and receive back a grant.
	 * But, for fast networks that value could result in too much
	 * buffer utilization (and, we wanted to have separate values for
	 * @unsched_bytes and @window). Set externally via sysctl.
	 */
	int unsched_bytes;

	/**
	 * @window_param: Set externally via sysctl to select a policy for
	 * computing homa-grant_window. If 0 then homa->grant_window is
	 * computed dynamically based on the number of RPCs we're currently
	 * granting to. If nonzero then homa->grant_window will always be the
	 * same as @window_param.
	 */
	int window_param;

	/**
	 * @link_bandwidth: The raw bandwidth of the network uplink, in
	 * units of 1e06 bits per second.  Set externally via sysctl.
	 */
	int link_mbps;

	/**
	 * @poll_usecs: Amount of time (in microseconds) that a thread
	 * will spend busy-waiting for an incoming messages before
	 * going to sleep. Set externally via sysctl.
	 */
	int poll_usecs;

	/**
	 * @poll_cycles: The value of @poll_usecs in the units returned
	 * by get_cycles().
	 */
	int poll_cycles;

	/**
	 * @num_priorities: The total number of priority levels available for
	 * Homa's use. Internally, Homa will use priorities from 0 to
	 * num_priorities-1, inclusive. Set externally via sysctl.
	 */
	int num_priorities;

	/**
	 * @priority_map: entry i gives the value to store in the high-order
	 * 3 bits of the DSCP field of IP headers to implement priority level
	 * i. Set externally via sysctl.
	 */
	int priority_map[HOMA_MAX_PRIORITIES];

	/**
	 * @max_sched_prio: The highest priority level currently available for
	 * scheduled packets. Levels above this are reserved for unscheduled
	 * packets.  Set externally via sysctl.
	 */
	int max_sched_prio;

	/**
	 * @unsched_cutoffs: the current priority assignments for incoming
	 * unscheduled packets. The value of entry i is the largest
	 * message size that uses priority i (larger i is higher priority).
	 * If entry i has a value of HOMA_MAX_MESSAGE_SIZE or greater, then
	 * priority levels less than i will not be used for unscheduled
	 * packets. At least one entry in the array must have a value of
	 * HOMA_MAX_MESSAGE_SIZE or greater (entry 0 is usually INT_MAX).
	 * Set externally via sysctl.
	 */
	int unsched_cutoffs[HOMA_MAX_PRIORITIES];

	/**
	 * @cutoff_version: increments every time unsched_cutoffs is
	 * modified. Used to determine when we need to send updates to
	 * peers.  Note: 16 bits should be fine for this: the worst
	 * that happens is a peer has a super-stale value that equals
	 * our current value, so the peer uses suboptimal cutoffs until the
	 * next version change.  Can be set externally via sysctl.
	 */
	int cutoff_version;

	/**
	 * @fifo_grant_increment: how many additional bytes to grant in
	 * a "pity" grant sent to the oldest outstanding message. Set
	 * externally via sysctl.
	 */
	int fifo_grant_increment;

	/**
	 * @grant_fifo_fraction: The fraction (in thousandths) of granted
	 * bytes that should go to the *oldest* incoming message, rather
	 * than the highest priority ones. Set externally via sysctl.
	 */
	int grant_fifo_fraction;

	/**
	 * @max_overcommit: The maximum number of messages to which Homa will
	 * send grants at any given point in time.  Set externally via sysctl.
	 */
	int max_overcommit;

	/**
	 * @max_incoming: Homa will try to ensure that the total number of
	 * bytes senders have permission to send to this host (either
	 * unscheduled bytes or granted bytes) does not exceeds this value.
	 * Set externally via sysctl.
	 */
	int max_incoming;

	/**
	 * @max_rpcs_per_peer: If there are multiple incoming messages from
	 * the same peer, Homa will only issue grants to this many of them
	 * at a time.  Set externally via sysctl.
	 */
	int max_rpcs_per_peer;

	/**
	 * @resend_ticks: When an RPC's @silent_ticks reaches this value,
	 * start sending RESEND requests.
	 */
	int resend_ticks;

	/**
	 * @resend_interval: minimum number of homa timer ticks between
	 * RESENDs for the same RPC.
	 */
	int resend_interval;

	/**
	 * @timeout_ticks: abort an RPC if its silent_ticks reaches this value.
	 */
	int timeout_ticks;

	/**
	 * @timeout_resends: Assume that a server is dead if it has not
	 * responded after this many RESENDs have been sent to it.
	 */
	int timeout_resends;

	/**
	 * @request_ack_ticks: How many timer ticks we'll wait for the
	 * client to ack an RPC before explicitly requesting an ack.
	 * Set externally via sysctl.
	 */
	int request_ack_ticks;

	/**
	 * @reap_limit: Maximum number of packet buffers to free in a
	 * single call to home_rpc_reap.
	 */
	int reap_limit;

	/**
	 * @dead_buffs_limit: If the number of packet buffers in dead but
	 * not yet reaped RPCs is less than this number, then Homa reaps
	 * RPCs in a way that minimizes impact on performance but may permit
	 * dead RPCs to accumulate. If the number of dead packet buffers
	 * exceeds this value, then Homa switches to a more aggressive approach
	 * to reaping RPCs. Set externally via sysctl.
	 */
	int dead_buffs_limit;

	/**
	 * @max_dead_buffs: The largest aggregate number of packet buffers
	 * in dead (but not yet reaped) RPCs that has existed so far in a
	 * single socket.  Readable via sysctl, and may be reset via sysctl
	 * to begin recalculating.
	 */
	int max_dead_buffs;

	/**
	 * @pacer_kthread: Kernel thread that transmits packets from
	 * throttled_rpcs in a way that limits queue buildup in the
	 * NIC.
	 */
	struct task_struct *pacer_kthread;

	/**
	 * @pacer_exit: true means that the pacer thread should exit as
	 * soon as possible.
	 */
	bool pacer_exit;

	/**
	 * @max_nic_queue_ns: Limits the NIC queue length: we won't queue
	 * up a packet for transmission if link_idle_time is this many
	 * nanoseconds in the future (or more). Set externally via sysctl.
	 */
	int max_nic_queue_ns;

	/**
	 * @max_nic_queue_cycles: Same as max_nic_queue_ns, except in units
	 * of get_cycles().
	 */
	int max_nic_queue_cycles;

	/**
	 * @cycles_per_kbyte: the number of cycles, as measured by get_cycles(),
	 * that it takes to transmit 1000 bytes on our uplink. This is actually
	 * a slight overestimate of the value, to ensure that we don't
	 * underestimate NIC queue length and queue too many packets.
	 */
	__u32 cycles_per_kbyte;

	/**
	 * @verbose: Nonzero enables additional logging. Set externally via
	 * sysctl.
	 */
	int verbose;

	/**
	 * @max_gso_size: Maximum number of bytes that will be included
	 * in a single output packet that Homa passes to Linux. Can be set
	 * externally via sysctl to lower the limit already enforced by Linux.
	 */
	int max_gso_size;

	/**
	 * @gso_force_software: A non-zero value will cause Home to perform
	 * segmentation in software using GSO; zero means ask the NIC to
	 * perform TSO. Set externally via sysctl.
	 */
	int gso_force_software;

	/**
	 * @hijack_tcp: Non-zero means encapsulate outgoing Homa packets
	 * as TCP packets (i.e. use TCP as the IP protocol). This makes TSO
	 * and RSS work better. Set externally via sysctl.
	 */
	int hijack_tcp;

	/**
	 * @max_gro_skbs: Maximum number of socket buffers that can be
	 * aggregated by the GRO mechanism.  Set externally via sysctl.
	 */
	int max_gro_skbs;

	/**
	 * @gro_policy: An OR'ed together collection of bits that determine
	 * how Homa packets should be steered for SoftIRQ handling.  A value
	 * of zero will eliminate any Homa-specific behaviors, reverting
	 * to the Linux defaults. Set externally via sysctl (but modifying
	 * it is almost certainly a bad idea; see below).
	 */
	int gro_policy;

	/* Bits that can be specified for gro_policy. These were created for
	 * testing, in order to evaluate various possible policies; you almost
	 * certainly should not use any value other than HOMA_GRO_NORMAL.
	 * HOMA_GRO_SAME_CORE         If isolated packets arrive (not part of
	 *                            a batch) use the GRO core for SoftIRQ also.
	 * HOMA_GRO_IDLE              Use old mechanism for selecting an idle
	 *                            core for SoftIRQ (deprecated).
	 * HOMA_GRO_NEXT              Always use the next core in circular
	 *                            order for SoftIRQ (deprecated).
	 * HOMA_GRO_GEN2              Use the new mechanism for selecting an
	 *                            idle core for SoftIRQ.
	 * HOMA_GRO_FAST_GRANTS       Pass all grants immediately to
	 *                            homa_softirq during GRO (only if the
	 *                            core isn't overloaded).
	 * HOMA_GRO_SHORT_BYPASS      Pass all single-packet messages directly
	 *                            to homa_softirq during GRO (only if the
	 *                            core isn't overloaded).
	 * HOMA_GRO_GEN3              Use the "Gen3" mechanisms for load
	 *                            balancing.
	 */
	#define HOMA_GRO_SAME_CORE         2
	#define HOMA_GRO_IDLE              4
	#define HOMA_GRO_NEXT              8
	#define HOMA_GRO_GEN2           0x10
	#define HOMA_GRO_FAST_GRANTS    0x20
	#define HOMA_GRO_SHORT_BYPASS   0x40
	#define HOMA_GRO_GEN3           0x80
	#define HOMA_GRO_NORMAL      (HOMA_GRO_SAME_CORE|HOMA_GRO_GEN2 \
			|HOMA_GRO_SHORT_BYPASS|HOMA_GRO_FAST_GRANTS)

	/*
	 * @busy_usecs: if there has been activity on a core within the
	 * last @busy_usecs, it is considered to be busy and Homa will
	 * try to avoid scheduling other activities on the core. See
	 * balance.txt for more on load balancing. Set externally via sysctl.
	 */
	int busy_usecs;

	/** @busy_cycles: Same as busy_usecs except in get_cycles() units. */
	int busy_cycles;

	/*
	 * @gro_busy_usecs: if the gap between the completion of
	 * homa_gro_receive and the next call to homa_gro_receive on the same
	 * core is less than this, then GRO on that core is considered to be
	 * "busy", and optimizations such as HOMA_GRO_SHORT_BYPASS will not be
	 * done because they risk overloading the core. Set externally via
	 * sysctl.
	 */
	int gro_busy_usecs;

	/** @gro_busy_cycles: Same as busy_usecs except in get_cycles() units. */
	int gro_busy_cycles;

	/**
	 * @timer_ticks: number of times that homa_timer has been invoked
	 * (may wraparound, which is safe).
	 */
	__u32 timer_ticks;

	/**
	 * @metrics_lock: Used to synchronize accesses to @metrics_active_opens
	 * and updates to @metrics.
	 */
	spinlock_t metrics_lock;

	/*
	 * @metrics: a human-readable string containing recent values
	 * for all the Homa performance metrics, as generated by
	 * homa_append_metric. This string is kmalloc-ed; NULL means
	 * homa_append_metric has never been called.
	 */
	char *metrics;

	/** @metrics_capacity: number of bytes available at metrics. */
	size_t metrics_capacity;

	/**
	 * @metrics_length: current length of the string in metrics,
	 * not including terminating NULL character.
	 */
	size_t metrics_length;

	/**
	 * @metrics_active_opens: number of open struct files that
	 * currently exist for the metrics file in /proc.
	 */
	int metrics_active_opens;

	/**
	 * @flags: a collection of bits that can be set using sysctl
	 * to trigger various behaviors.
	 */
	int flags;

	/**
	 * @freeze_type: determines conditions under which the time trace
	 * should be frozen. Set externally via sysctl.
	 */
	enum homa_freeze_type freeze_type;

	/**
	 * @bpage_lease_usecs: how long a core can own a bpage (microseconds)
	 * before its ownership can be revoked to reclaim the page.
	 */
	int bpage_lease_usecs;

	/**
	 * @bpage_lease_cycles: The value of @bpage_lease_usecs in get_cycles
	 * units.
	 */
	int bpage_lease_cycles;

	/**
	 * @next_id: Set via sysctl; causes next_outgoing_id to be set to
	 * this value; always reads as zero. Typically used while debugging to
	 * ensure that different nodes use different ranges of ids.
	 */
	int next_id;

	/**
	 * @temp: the values in this array can be read and written with sysctl.
	 * They have no officially defined purpose, and are available for
	 * short-term use during testing.
	 */
	int temp[4];
};


/**
 * struct homa_numa - Homa allocates one of these structures for each
 * NUMA node, for information that needs to be kept separately for each
 * NUMA node.
 */
struct homa_numa {
	/** Used to speed up allocation of tx skbs for cores in this node. */
	struct homa_page_pool page_pool;
};

/**
 * struct homa_core - Homa allocates one of these structures for each
 * core, to hold information that needs to be kept on a per-core basis.
 */
struct homa_core {
	/** Information about the NUMA node to which this node belongs. */
	struct homa_numa *numa;

	/**
	 * @last_active: the last time (in get_cycle() units) that
	 * there was system activity, such NAPI or SoftIRQ, on this
	 * core. Used for load balancing.
	 */
	__u64 last_active;

	/**
	 * @last_gro: the last time (in get_cycle() units) that
	 * homa_gro_receive returned on this core. Used to determine
	 * whether GRO is keeping a core busy.
	 */
	__u64 last_gro;

	/**
	 * @softirq_backlog: the number of batches of packets that have
	 * been queued for SoftIRQ processing on this core but haven't
	 * yet been processed.
	 */
	atomic_t softirq_backlog;

	/**
	 * @softirq_offset: used when rotating SoftIRQ assignment among
	 * the next cores; contains an offset to add to the current core
	 * to produce the core for SoftIRQ.
	 */
	int softirq_offset;

	/**
	 * @gen3_softirq_cores: when the Gen3 load balancer is in use,
	 * GRO will arrange for SoftIRQ processing to occur on one of
	 * these cores; -1 values are ignored (see balance.txt for more
	 * on lewd balancing). This information is filled in via sysctl.
	 */
#define NUM_GEN3_SOFTIRQ_CORES 3
	int gen3_softirq_cores[NUM_GEN3_SOFTIRQ_CORES];

	/**
	 * @last_app_active: the most recent time (get_cycles() units)
	 * when an application was actively using Homa on this core (e.g.,
	 * by sending or receiving messages). Used for load balancing
	 * (see balance.txt).
	 */
	__u64 last_app_active;

	/**
	 * held_skb: last packet buffer known to be available for
	 * merging other packets into on this core (note: may not still
	 * be available), or NULL if none.
	 */
	struct sk_buff *held_skb;

	/**
	 * @held_bucket: the index, within napi->gro_hash, of the list
	 * containing @held_skb; undefined if @held_skb is NULL. Used to
	 * verify that @held_skb is still available.
	 */
	int held_bucket;

	/**
	 * @thread: the most recent thread to invoke a Homa system call
	 * on this core, or NULL if none.
	 */
	struct task_struct *thread;

	/**
	 * @syscall_end_time: the time, in get_cycle() units, when the last
	 * Homa system call completed on this core. Meaningless if thread
	 * is NULL.
	 */
	__u64 syscall_end_time;

	/**
	 * @skb_page: a page of data available being used for skb frags.
	 * This pointer is included in the page's reference count.
	 */
	struct page *skb_page;

	/**
	 * @page_inuse: offset of first byte in @skb_page that hasn't already
	 * been allocated.
	 */
	int page_inuse;

	/** @page_size: total number of bytes available in @skb_page. */
	int page_size;

	/**
	 * define HOMA_MAX_STASHED: maximum number of stashed pages that
	 * can be consumed by a message of a given size (assumes page_inuse
	 * is 0). This is a rough guess, since it doesn't consider all of
	 * the data_segments that will be needed for the packets.
	 */
#define HOMA_MAX_STASHED(size) (((size - 1) / HOMA_SKB_PAGE_SIZE) + 1)

	/**
	 * @num_stashed_pages: number of pages currently available in
	 * stashed_pages.
	 */
	int num_stashed_pages;

	/**
	 * @stashed_pages: use to prefetch from the cache all of the pages a
	 * message will need with a single operation, to avoid having to
	 * synchronize separately for each page. Note: these pages are all
	 * HOMA_SKB_PAGE_SIZE in length.
	 */
	struct page *stashed_pages[HOMA_MAX_STASHED(HOMA_MAX_MESSAGE_LENGTH)];
};

/**
 * struct homa_skb_info - Additional information needed by Homa for each
 * DATA packet. Space is allocated for this at the very end of the linear
 * part of the skb.
 */
struct homa_skb_info {
	/**
	 * @next_skb: used to link together all of the skb's for a Homa
	 * message (in order of offset).
	 */
	struct sk_buff *next_skb;

	/**
	 * @wire_bytes: total number of bytes of network bandwidth that
	 * will be consumed by this packet. This includes everything,
	 * including additional headers added by GSO, IP header, Ethernet
	 * header, CRC, preamble, and inter-packet gap.
	 */
	int wire_bytes;

	/**
	 * @data_bytes: total bytes of message data across all of the
	 * segments in this packet.
	 */
	int data_bytes;

	/** @seg_length: maximum number of data bytes in each GSO segment. */
	int seg_length;

	/**
	 * @offset: offset within the message of the first byte of data in
	 * this packet.
	 */
	int offset;
};

/**
 * homa_get_skb_info() - Return the address of Homa's private information
 * for an sk_buff.
 * @skb:     Socket buffer whose info is needed.
 */
static inline struct homa_skb_info *homa_get_skb_info(struct sk_buff *skb)
{
	return (struct homa_skb_info *) (skb_end_pointer(skb)
			- sizeof(struct homa_skb_info));
}

/**
 * homa_is_client(): returns true if we are the client for a particular RPC,
 * false if we are the server.
 * @id:  Id of the RPC in question.
 */
static inline bool homa_is_client(__u64 id)
{
	return (id & 1) == 0;
}

/**
 * homa_local_id(): given an RPC identifier from an input packet (which
 * is network-encoded), return the decoded id we should use for that
 * RPC on this machine.
 * @sender_id:  RPC id from an incoming packet, such as h->common.sender_id
 */
static inline __u64 homa_local_id(__be64 sender_id)
{
	/* If the client bit was set on the sender side, it needs to be
	 * removed here, and conversely.
	 */
	return be64_to_cpu(sender_id) ^ 1;
}

/**
 * homa_next_skb() - Compute address of Homa's private link field in @skb.
 * @skb:     Socket buffer containing private link field.
 *
 * Homa needs to keep a list of buffers in a message, but it can't use the
 * links built into sk_buffs because Homa wants to retain its list even
 * after sending the packet, and the built-in links get used during sending.
 * Thus we allocate extra space at the very end of the packet's data
 * area to hold a forward pointer for a list.
 */
static inline struct sk_buff **homa_next_skb(struct sk_buff *skb)
{
	return (struct sk_buff **) (skb_end_pointer(skb) - sizeof(char *));
}

/**
 * port_hash() - Hash function for port numbers.
 * @port:   Port number being looked up.
 *
 * Return:  The index of the bucket in which this port will be found (if
 *          it exists.
 */
static inline int homa_port_hash(__u16 port)
{
	/* We can use a really simple hash function here because client
	 * port numbers are allocated sequentially and server port numbers
	 * are unpredictable.
	 */
	return port & (HOMA_SOCKTAB_BUCKETS - 1);
}

/**
 * homa_set_doff() - Fills in the doff TCP header field for a Homa packet.
 * @h:     Packet header whose doff field is to be set.
 * @size:  Size of the "header", bytes (must be a multiple of 4). This
 *         information is used only for TSO; it's the number of bytes
 *         that should be replicated in each segment. The bytes after
 *         this will be distributed among segments.
 */
static inline void homa_set_doff(struct data_header *h, int size)
{
	h->common.doff = size << 2;
}

static inline struct homa_sock *homa_sk(const struct sock *sk)
{
	return (struct homa_sock *)sk;
}

/**
 * homa_grantable_lock() - Acquire the grantable lock. If the lock
 * isn't immediately available, record stats on the waiting time.
 * @homa:    Overall data about the Homa protocol implementation.
 * @recalc:  Nonzero means the caller is homa_grant_recalc; if another thread
 *           is already recalculating, can return without waiting for the lock.
 * Return:   Nonzero means this thread now owns the grantable lock. Zero
 *           means the lock was not acquired and there is no need for this
 *           thread to do the work of homa_grant_recalc because some other
 *           thread started a fresh calculation after this method was invoked.
 */
static inline int homa_grantable_lock(struct homa *homa, int recalc)
{
	int result;

	if (spin_trylock_bh(&homa->grantable_lock))
		result = 1;
	else
		result = homa_grantable_lock_slow(homa, recalc);
	homa->grantable_lock_time = get_cycles();
	return result;
}

/**
 * homa_grantable_unlock() - Release the grantable lock.
 * @homa:    Overall data about the Homa protocol implementation.
 */
static inline void homa_grantable_unlock(struct homa *homa)
{
	INC_METRIC(grantable_lock_cycles, get_cycles()
			- homa->grantable_lock_time);
	spin_unlock_bh(&homa->grantable_lock);
}

/**
 * homa_throttle_lock() - Acquire the throttle lock. If the lock
 * isn't immediately available, record stats on the waiting time.
 * @homa:    Overall data about the Homa protocol implementation.
 */
static inline void homa_throttle_lock(struct homa *homa)
{
	if (!spin_trylock_bh(&homa->throttle_lock))
		homa_throttle_lock_slow(homa);
}

/**
 * homa_throttle_unlock() - Release the throttle lock.
 * @homa:    Overall data about the Homa protocol implementation.
 */
static inline void homa_throttle_unlock(struct homa *homa)
{
	spin_unlock_bh(&homa->throttle_lock);
}

/** skb_is_ipv6() - Return true if the packet is encapsulated with IPv6,
 *  false otherwise (presumably it's IPv4).
 */
static inline bool skb_is_ipv6(const struct sk_buff *skb)
{
	return ipv6_hdr(skb)->version == 6;
}

/**
 * Given an IPv4 address, return an equivalent IPv6 address (an IPv4-mapped
 * one)
 * @ip4: IPv4 address, in network byte order.
 */
static inline struct in6_addr ipv4_to_ipv6(__be32 ip4)
{
	struct in6_addr ret = {};

	if (ip4 == INADDR_ANY)
		return in6addr_any;
	ret.in6_u.u6_addr32[2] = htonl(0xffff);
	ret.in6_u.u6_addr32[3] = ip4;
	return ret;
}

/**
 * ipv6_to_ipv4() - Given an IPv6 address produced by ipv4_to_ipv6, return
 * the original IPv4 address (in network byte order).
 * @ip6:  IPv6 address; assumed to be a mapped IPv4 address.
 */
static inline __be32 ipv6_to_ipv4(const struct in6_addr ip6)
{
	return ip6.in6_u.u6_addr32[3];
}

/**
 * skb_canonical_ipv6_addr() - Convert a socket address to the "standard"
 * form used in Homa, which is always an IPv6 address; if the original address
 * was IPv4, convert it to an IPv4-mapped IPv6 address.
 * @addr:   Address to canonicalize.
 */
static inline struct in6_addr canonical_ipv6_addr(const union sockaddr_in_union *addr)
{
	if (addr) {
		return (addr->sa.sa_family == AF_INET6)
			? addr->in6.sin6_addr
			: ipv4_to_ipv6(addr->in4.sin_addr.s_addr);
	} else {
		return in6addr_any;
	}
}

/**
 * skb_canonical_ipv6_saddr() - Given a packet buffer, return its source
 * address in the "standard" form used in Homa, which is always an IPv6
 * address; if the original address was IPv4, convert it to an IPv4-mapped
 * IPv6 address.
 * @skb:   The source address will be extracted from this packet buffer.
 */
static inline struct in6_addr skb_canonical_ipv6_saddr(struct sk_buff *skb)
{
	return skb_is_ipv6(skb) ? ipv6_hdr(skb)->saddr : ipv4_to_ipv6(
			ip_hdr(skb)->saddr);
}

/**
 * is_mapped_ipv4() - Return true if an IPv6 address is actually an
 * IPv4-mapped address, false otherwise.
 * @x:  The address to check.
 */
static inline bool is_mapped_ipv4(const struct in6_addr x)
{
	return ((x.in6_u.u6_addr32[0] == 0) &&
		(x.in6_u.u6_addr32[1] == 0) &&
		(x.in6_u.u6_addr32[2] == htonl(0xffff)));
}

static inline bool is_homa_pkt(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	return ((iph->protocol == IPPROTO_HOMA) ||
			((iph->protocol == IPPROTO_TCP) &&
			(tcp_hdr(skb)->urg_ptr == htons(HOMA_TCP_URGENT))));
}

/**
 * tt_addr() - Given an address, return a 4-byte id that will (hopefully)
 * provide a unique identifier for the address in a timetrace record.
 * @x:  Address (either IPv6 or IPv4-mapped IPv6)
 */
static inline __be32 tt_addr(const struct in6_addr x)
{
	return is_mapped_ipv4(x) ? ntohl(x.in6_u.u6_addr32[3])
			: (x.in6_u.u6_addr32[3] ? ntohl(x.in6_u.u6_addr32[3])
			: ntohl(x.in6_u.u6_addr32[1]));
}

#ifdef __UNIT_TEST__
extern void unit_log_printf(const char *separator, const char *format, ...)
		__printf(2, 3);
#define UNIT_LOG unit_log_printf
extern void unit_hook(char *id);
#define UNIT_HOOK(msg) unit_hook(msg)
#else
#define UNIT_LOG(...)
#define UNIT_HOOK(msg)
#endif

extern void     homa_abort_rpcs(struct homa *homa, const struct in6_addr *addr,
		    int port, int error);
extern void     homa_abort_sock_rpcs(struct homa_sock *hsk, int error);
extern void     homa_ack_pkt(struct sk_buff *skb, struct homa_sock *hsk,
		    struct homa_rpc *rpc);
extern void     homa_add_packet(struct homa_rpc *rpc, struct sk_buff *skb);
extern void     homa_add_to_throttled(struct homa_rpc *rpc);
extern int      homa_backlog_rcv(struct sock *sk, struct sk_buff *skb);
extern int      homa_bind(struct socket *sk, struct sockaddr *addr,
		    int addr_len);
extern int      homa_check_nic_queue(struct homa *homa, struct sk_buff *skb,
		    bool force);
extern struct homa_rpc
	       *homa_choose_fifo_grant(struct homa *homa);
extern struct homa_interest
	       *homa_choose_interest(struct homa *homa, struct list_head *head,
		    int offset);
extern void     homa_close(struct sock *sock, long timeout);
extern int      homa_copy_to_user(struct homa_rpc *rpc);
extern void     homa_cutoffs_pkt(struct sk_buff *skb, struct homa_sock *hsk);
extern void     homa_data_from_server(struct sk_buff *skb,
		    struct homa_rpc *crpc);
extern void     homa_data_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
extern void     homa_destroy(struct homa *homa);
extern int      homa_diag_destroy(struct sock *sk, int err);
extern int      homa_disconnect(struct sock *sk, int flags);
extern void     homa_dispatch_pkts(struct sk_buff *skb, struct homa *homa);
extern int      homa_dointvec(struct ctl_table *table, int write,
		    void __user *buffer, size_t *lenp, loff_t *ppos);
extern int      homa_err_handler_v4(struct sk_buff *skb, u32 info);
extern int      homa_err_handler_v6(struct sk_buff *skb,
		    struct inet6_skb_parm *opt, u8 type,  u8 code,  int offset,
		    __be32 info);
extern int      homa_fill_data_interleaved(struct homa_rpc *rpc,
		    struct sk_buff *skb, struct iov_iter *iter);
extern void     homa_freeze(struct homa_rpc *rpc, enum homa_freeze_type type,
		    char *format);
extern void     homa_freeze_peers(struct homa *homa);
extern struct homa_gap
	       *homa_gap_new(struct list_head *next, int start, int end);
extern void     homa_gap_retry(struct homa_rpc *rpc);
extern int      homa_get_port(struct sock *sk, unsigned short snum);
extern int      homa_getsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int __user *option);
extern void     homa_grant_add_rpc(struct homa_rpc *rpc);
extern void     homa_grant_check_rpc(struct homa_rpc *rpc);
extern void     homa_grant_find_oldest(struct homa *homa);
extern void     homa_grant_free_rpc(struct homa_rpc *rpc);
extern void     homa_grant_log_tt(struct homa *homa);
extern int      homa_grant_outranks(struct homa_rpc *rpc1,
		    struct homa_rpc *rpc2);
extern int      homa_grant_pick_rpcs(struct homa *homa, struct homa_rpc **rpcs,
		    int max_rpcs);
extern void     homa_grant_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
extern void     homa_grant_recalc(struct homa *homa, int locked);
extern void     homa_grant_remove_rpc(struct homa_rpc *rpc);
extern int      homa_grant_send(struct homa_rpc *rpc, struct homa *homa);
extern int      homa_grant_update_incoming(struct homa_rpc *rpc,
		    struct homa *homa);
extern int      homa_gro_complete(struct sk_buff *skb, int thoff);
extern void     homa_gro_gen2(struct sk_buff *skb);
extern void     homa_gro_gen3(struct sk_buff *skb);
extern void     homa_gro_hook_tcp(void);
extern void     homa_gro_unhook_tcp(void);
extern struct sk_buff
	       *homa_gro_receive(struct list_head *gro_list,
		    struct sk_buff *skb);
extern struct sk_buff
	       *homa_gso_segment(struct sk_buff *skb,
		    netdev_features_t features);
extern int      homa_hash(struct sock *sk);
extern enum hrtimer_restart
		homa_hrtimer(struct hrtimer *timer);
extern int      homa_init(struct homa *homa);
extern void     homa_incoming_sysctl_changed(struct homa *homa);
extern int      homa_ioc_abort(struct sock *sk, int *karg);
extern int      homa_ioctl(struct sock *sk, int cmd, int *karg);
extern void     homa_log_throttled(struct homa *homa);
extern int      homa_message_in_init(struct homa_rpc *rpc, int length,
		    int unsched);
extern int      homa_message_out_fill(struct homa_rpc *rpc,
		    struct iov_iter *iter, int xmit);
extern void     homa_message_out_init(struct homa_rpc *rpc, int length);
extern void     homa_need_ack_pkt(struct sk_buff *skb, struct homa_sock *hsk,
		    struct homa_rpc *rpc);
extern struct sk_buff
	       *homa_new_data_packet(struct homa_rpc *rpc,
		    struct iov_iter *iter, int offset, int length,
		    int max_seg_data);
extern int      homa_offload_end(void);
extern int      homa_offload_init(void);
extern void     homa_outgoing_sysctl_changed(struct homa *homa);
extern int      homa_pacer_main(void *transportInfo);
extern void     homa_pacer_stop(struct homa *homa);
extern void     homa_pacer_xmit(struct homa *homa);
extern __poll_t homa_poll(struct file *file, struct socket *sock,
		    struct poll_table_struct *wait);
extern char    *homa_print_ipv4_addr(__be32 addr);
extern char    *homa_print_ipv6_addr(const struct in6_addr *addr);
extern char    *homa_print_packet(struct sk_buff *skb, char *buffer, int buf_len);
extern char    *homa_print_packet_short(struct sk_buff *skb, char *buffer,
		    int buf_len);
extern void     homa_prios_changed(struct homa *homa);
extern int      homa_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		    int flags, int *addr_len);
extern int      homa_register_interests(struct homa_interest *interest,
		    struct homa_sock *hsk, int flags, __u64 id);
extern void     homa_rehash(struct sock *sk);
extern void     homa_remove_from_throttled(struct homa_rpc *rpc);
extern void     homa_resend_data(struct homa_rpc *rpc, int start, int end,
		    int priority);
extern void     homa_resend_pkt(struct sk_buff *skb, struct homa_rpc *rpc,
		    struct homa_sock *hsk);
extern void     homa_rpc_abort(struct homa_rpc *crpc, int error);
extern void     homa_rpc_acked(struct homa_sock *hsk,
		    const struct in6_addr *saddr, struct homa_ack *ack);
extern void     homa_rpc_free(struct homa_rpc *rpc);
extern void     homa_rpc_handoff(struct homa_rpc *rpc);
extern void     homa_send_ipis(void);
extern int      homa_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
extern int      homa_setsockopt(struct sock *sk, int level, int optname,
		    sockptr_t __user optval, unsigned int optlen);
extern int      homa_shutdown(struct socket *sock, int how);
extern int      homa_skb_append_from_iter(struct homa *homa,
		    struct sk_buff *skb, struct iov_iter *iter, int length);
extern int      homa_skb_append_from_skb(struct homa *homa,
		    struct sk_buff *dst_skb, struct sk_buff *src_skb,
		    int offset, int length);
extern int      homa_skb_append_to_frag(struct homa *homa, struct sk_buff *skb,
		    void *buf, int length);
extern void     homa_skb_cache_pages(struct homa *homa, struct page **pages,
		    int count);
extern void     homa_skb_cleanup(struct homa *homa);
extern void    *homa_skb_extend_frags(struct homa *homa, struct sk_buff *skb,
		    int *length);
extern void     homa_skb_free_tx(struct homa *homa, struct sk_buff *skb);
extern void     homa_skb_free_many_tx(struct homa *homa, struct sk_buff **skbs,
		    int count);
extern void     homa_skb_get(struct sk_buff *skb, void *dest, int offset,
				int length);
extern struct sk_buff
	       *homa_skb_new_tx(int length);
extern bool     homa_skb_page_alloc(struct homa *homa, struct homa_core *core);
extern void     homa_skb_page_pool_init(struct homa_page_pool *pool);
extern void     homa_skb_release_pages(struct homa *homa);
extern void     homa_skb_stash_pages(struct homa *homa, int length);
extern int      homa_snprintf(char *buffer, int size, int used,
		    const char *format, ...) __printf(4, 5);
extern int      homa_softirq(struct sk_buff *skb);
extern void     homa_spin(int ns);
extern char    *homa_symbol_for_type(uint8_t type);
extern int      homa_sysctl_softirq_cores(struct ctl_table *table, int write,
		    void __user *buffer, size_t *lenp, loff_t *ppos);
extern struct sk_buff
	       *homa_tcp_gro_receive(struct list_head *held_list,
		    struct sk_buff *skb);
extern void     homa_timer(struct homa *homa);
extern int      homa_timer_main(void *transportInfo);
extern void     homa_unhash(struct sock *sk);
extern void     homa_unknown_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
extern int      homa_unsched_priority(struct homa *homa,
		    struct homa_peer *peer, int length);
extern int      homa_v4_early_demux(struct sk_buff *skb);
extern int      homa_v4_early_demux_handler(struct sk_buff *skb);
extern int      homa_validate_incoming(struct homa *homa, int verbose,
		    int *link_errors);
extern struct homa_rpc
	       *homa_wait_for_message(struct homa_sock *hsk, int flags,
		    __u64 id);
extern int      homa_xmit_control(enum homa_packet_type type, void *contents,
		    size_t length, struct homa_rpc *rpc);
extern int      __homa_xmit_control(void *contents, size_t length,
		    struct homa_peer *peer, struct homa_sock *hsk);
extern void     homa_xmit_data(struct homa_rpc *rpc, bool force);
extern void     __homa_xmit_data(struct sk_buff *skb, struct homa_rpc *rpc,
		    int priority);
extern void     homa_xmit_unknown(struct sk_buff *skb, struct homa_sock *hsk);

/**
 * homa_check_pacer() - This method is invoked at various places in Homa to
 * see if the pacer needs to transmit more packets and, if so, transmit
 * them. It's needed because the pacer thread may get descheduled by
 * Linux, result in output stalls.
 * @homa:    Overall data about the Homa protocol implementation. No locks
 *           should be held when this function is invoked.
 * @softirq: Nonzero means this code is running at softirq (bh) level;
 *           zero means it's running in process context.
 */
static inline void homa_check_pacer(struct homa *homa, int softirq)
{
	if (list_empty(&homa->throttled_rpcs))
		return;

	/* The "/2" in the line below gives homa_pacer_main the first chance
	 * to queue new packets; if the NIC queue becomes more than half
	 * empty, then we will help out here.
	 */
	if ((get_cycles() + homa->max_nic_queue_cycles/2) <
			atomic64_read(&homa->link_idle_time))
		return;
	tt_record("homa_check_pacer calling homa_pacer_xmit");
	homa_pacer_xmit(homa);
	INC_METRIC(pacer_needed_help, 1);
}

extern struct completion homa_pacer_kthread_done;
#endif /* _HOMA_IMPL_H */
