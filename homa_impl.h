/* SPDX-License-Identifier: BSD-2-Clause */

/* This file contains definitions that are shared across the files
 * that implement Homa for Linux.
 */

#ifndef _HOMA_IMPL_H
#define _HOMA_IMPL_H

#include <linux/bug.h>
#ifdef __UNIT_TEST__
#undef WARN
#define WARN(...)

#undef WARN_ON
#define WARN_ON(condition) ({						\
	int __ret_warn_on = !!(condition);				\
	unlikely(__ret_warn_on);					\
})

#undef WARN_ON_ONCE
#define WARN_ON_ONCE(condition) WARN_ON(condition)
#endif /* __UNIT_TEST__ */

#include <linux/audit.h>
#include <linux/icmp.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/proc_fs.h>
#include <linux/sched/clock.h>
#include <linux/sched/signal.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/vmalloc.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/netns/generic.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/gro.h>
#include <net/rps.h>

#ifndef __UPSTREAM__ /* See strip.py */
#include "homa.h"
#include <linux/version.h>
#include "homa_devel.h"
#include "homa_strip.h"
#else /* See strip.py */
#include <linux/homa.h>
#endif /* See strip.py */
#include "homa_wire.h"

#ifdef __UNIT_TEST__
#include "mock.h"
#endif /* __UNIT_TEST__ */

#ifndef __STRIP__ /* See strip.py */
/* Null out things that confuse VSCode Intellisense */
#ifdef __VSCODE__
#define smp_processor_id() 1
#define BUG()
#define BUG_ON(...)
#define set_current_state(...)
#endif
#endif /* See strip.py */

/* Forward declarations. */
struct homa;
struct homa_peer;
struct homa_rpc;
struct homa_sock;

#ifndef __STRIP__ /* See strip.py */
#include "timetrace.h"
#include "homa_metrics.h"

/* Declarations used in this file, so they can't be made at the end. */
void     homa_throttle_lock_slow(struct homa *homa);
#endif /* See strip.py */

#define sizeof32(type) ((int)(sizeof(type)))

#ifndef __STRIP__ /* See strip.py */
/**
 * define HOMA_MAX_GRANTS - Used to size various data structures for grant
 * management; the max_overcommit sysctl parameter must never be greater than
 * this.
 */
#define HOMA_MAX_GRANTS 10
#endif /* See strip.py */

/**
 * union sockaddr_in_union - Holds either an IPv4 or IPv6 address (smaller
 * and easier to use than sockaddr_storage).
 */
union sockaddr_in_union {
	/** @sa: Used to access as a generic sockaddr. */
	struct sockaddr sa;

	/** @in4: Used to access as IPv4 socket. */
	struct sockaddr_in in4;

	/** @in6: Used to access as IPv6 socket.  */
	struct sockaddr_in6 in6;
};

/**
 * struct homa - Stores overall information about an implementation of
 * the Homa transport. One of these objects exists for each network namespace.
 */
struct homa {
	/**
	 * @next_outgoing_id: Id to use for next outgoing RPC request.
	 * This is always even: it's used only to generate client-side ids.
	 * Accessed without locks. Note: RPC ids are unique within a
	 * single client machine.
	 */
	atomic64_t next_outgoing_id;

	/**
	 * @link_idle_time: The time, measured by sched_clock, at which we
	 * estimate that all of the packets we have passed to Linux for
	 * transmission will have been transmitted. May be in the past.
	 * This estimate assumes that only Homa is transmitting data, so
	 * it could be a severe underestimate if there is competing traffic
	 * from, say, TCP. Access only with atomic ops.
	 */
	atomic64_t link_idle_time ____cacheline_aligned_in_smp;

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @grantable_lock: Used to synchronize access to grant-related
	 * fields below. In order to reduce contention, this lock is held
	 * only when making structural changes (e.g. modifying grantable_peers
	 * or active_rpcs). It is not held when computing new grant offsets
	 * and/or sending grant packets. Under some race conditions, it is
	 * possible for RPCs to receive grants out of priority order, or to
	 * receive duplicate grants.
	 */
	spinlock_t grantable_lock ____cacheline_aligned_in_smp;

	/**
	 * @grantable_lock_time: sched_clock() time when grantable_lock
	 * was last locked.
	 */
	u64 grantable_lock_time;

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

	/** @num_grantable_rpcs: The number of RPCs in grantable_peers. */
	int num_grantable_rpcs;

	/** @last_grantable_change: The sched_clock() time of the most recent
	 * increment or decrement of num_grantable_rpcs; used for computing
	 * statistics.
	 */
	u64 last_grantable_change;

	/**
	 * @max_grantable_rpcs: The largest value that has been seen for
	 * num_grantable_rpcs since this value was reset to 0 (it can be
	 * reset externally using sysctl).
	 */
	int max_grantable_rpcs;

	/**
	 * @num_active_rpcs: number of entries in @active_rpcs and
	 * @active_remaining that are currently used.
	 */
	int num_active_rpcs;

	/**
	 * @active_rpcs: Hints about RPCs that we are currently granting to
	 * (lower index in the array means higher priority). Entries may be
	 * NULL or may refer to RPCs that no longer exist, so can't dereference
	 * these pointers.
	 */
	struct homa_rpc *active_rpcs[HOMA_MAX_GRANTS];

	/**
	 * @active_remaining: entry i in this array contains a copy of
	 * active_rpcs[i]->msgin.bytes_remaining. These values can be
	 * updated by the corresponding RPCs without holding the grantable
	 * lock. Perfect consistency isn't required; this are hints used to
	 * detect when the priority ordering of messages changes.
	 */
	atomic_t active_remaining[HOMA_MAX_GRANTS];

	/**
	 * @oldest_rpc: The RPC with incoming data whose start_ns is
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
	 * @total_incoming: the total number of bytes that we expect to receive
	 * (across all messages) even if we don't send out any more grants
	 * (includes granted but unreceived bytes, plus unreceived unscheduled
	 * bytes that we know about). This can potentially be negative, if
	 * a peer sends more bytes than granted (see synchronization note in
	 * homa_send_grants for why we have to allow this possibility).
	 */
	atomic_t total_incoming ____cacheline_aligned_in_smp;

	/**
	 * @incoming_hit_limit: Nonzero means that one or more RPCs could
	 * not be fully granted because @total_incoming exceeded @max_incoming.
	 */
	atomic_t incoming_hit_limit;
#endif /* See strip.py */

	/**
	 * @pacer_mutex: Ensures that only one instance of homa_pacer_xmit
	 * runs at a time. Only used in "try" mode: never block on this.
	 */
	spinlock_t pacer_mutex ____cacheline_aligned_in_smp;

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
	 * @pacer_wake_time: time (in sched_clock units) when the pacer last
	 * woke up (if the pacer is running) or 0 if the pacer is sleeping.
	 */
	u64 pacer_wake_time;

	/**
	 * @throttle_lock: Used to synchronize access to @throttled_rpcs. To
	 * insert or remove an RPC from throttled_rpcs, must first acquire
	 * the RPC's socket lock, then this lock.
	 */
	spinlock_t throttle_lock;

	/**
	 * @throttled_rpcs: Contains all homa_rpcs that have bytes ready
	 * for transmission, but which couldn't be sent without exceeding
	 * the queue limits for transmission.
	 */
	struct list_head throttled_rpcs;

	/**
	 * @throttle_add: The time (in sched_clock() units) when the most
	 * recent RPC was added to @throttled_rpcs.
	 */
	u64 throttle_add;

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
	 * @prev_default_port: The most recent port number assigned from
	 * the range of default ports.
	 */
	__u16 prev_default_port ____cacheline_aligned_in_smp;

	/**
	 * @port_map: Information about all open sockets. Dynamically
	 * allocated; must be kfreed.
	 */
	struct homa_socktab *port_map ____cacheline_aligned_in_smp;

	/**
	 * @peers: Info about all the other hosts we have communicated with.
	 * Dynamically allocated; must be kfreed.
	 */
	struct homa_peertab *peers;

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @page_pool_mutex: Synchronizes access to any/all of the page_pools
	 * used for outgoing sk_buff data.
	 */
	spinlock_t page_pool_mutex ____cacheline_aligned_in_smp;

	/**
	 * @page_pools: One page pool for each NUMA node on the machine.
	 * If there are no cores for node, then this value is NULL.
	 */
	struct homa_page_pool *page_pools[MAX_NUMNODES];
#endif /* See strip.py */

	/** @max_numa: Highest NUMA node id in use by any core. */
	int max_numa;

#ifndef __STRIP__ /* See strip.py */
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
	 * @skb_page_free_time: Time (in sched_clock() units) when the
	 * next sk_buff page should be freed. Could be in the past.
	 */
	u64 skb_page_free_time;

	/**
	 * @skb_page_pool_min_kb: Don't return pages from a pool to Linux
	 * if the amount of unused space in the pool has been less than this
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
#endif /* See strip.py */

	/**
	 * @link_mbps: The raw bandwidth of the network uplink, in
	 * units of 1e06 bits per second.  Set externally via sysctl.
	 */
	int link_mbps;

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @poll_usecs: Amount of time (in microseconds) that a thread
	 * will spend busy-waiting for an incoming messages before
	 * going to sleep. Set externally via sysctl.
	 */
	int poll_usecs;

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
#endif /* See strip.py */

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
	 * @ns_per_mbyte: the number of ns that it takes to transmit
	 * 10**6 bytes on our uplink. This is actually a slight overestimate
	 * of the value, to ensure that we don't underestimate NIC queue
	 * length and queue too many packets.
	 */
	u32 ns_per_mbyte;

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @verbose: Nonzero enables additional logging. Set externally via
	 * sysctl.
	 */
	int verbose;
#endif /* See strip.py */

	/**
	 * @max_gso_size: Maximum number of bytes that will be included
	 * in a single output packet that Homa passes to Linux. Can be set
	 * externally via sysctl to lower the limit already enforced by Linux.
	 */
	int max_gso_size;

	/**
	 * @gso_force_software: A non-zero value will cause Homa to perform
	 * segmentation in software using GSO; zero means ask the NIC to
	 * perform TSO. Set externally via sysctl.
	 */
	int gso_force_software;

	/**
	 * @wmem_max: Limit on the value of sk_sndbuf for any socket. Set
	 * externally via sysctl.
	 */
	int wmem_max;

#ifndef __STRIP__ /* See strip.py */
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
	 * HOMA_GRO_SAME_CORE         If isolated packets arrive (not part of a
	 *                            batch) use the GRO core for SoftIRQ also.
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
	#define HOMA_GRO_NORMAL      (HOMA_GRO_SAME_CORE | HOMA_GRO_GEN2 | \
				      HOMA_GRO_SHORT_BYPASS | HOMA_GRO_FAST_GRANTS)

	/*
	 * @busy_usecs: if there has been activity on a core within the
	 * last @busy_usecs, it is considered to be busy and Homa will
	 * try to avoid scheduling other activities on the core. See
	 * balance.txt for more on load balancing. Set externally via sysctl.
	 */
	int busy_usecs;

	/** @busy_ns: Same as busy_usecs except in sched_clock() units. */
	int busy_ns;

	/*
	 * @gro_busy_usecs: if the gap between the completion of
	 * homa_gro_receive and the next call to homa_gro_receive on the same
	 * core is less than this, then GRO on that core is considered to be
	 * "busy", and optimizations such as HOMA_GRO_SHORT_BYPASS will not be
	 * done because they risk overloading the core. Set externally via
	 * sysctl.
	 */
	int gro_busy_usecs;

	/** @gro_busy_ns: Same as busy_usecs except in sched_clock() units. */
	int gro_busy_ns;
#endif /* See strip.py */

	/**
	 * @timer_ticks: number of times that homa_timer has been invoked
	 * (may wraparound, which is safe).
	 */
	u32 timer_ticks;

	/**
	 * @flags: a collection of bits that can be set using sysctl
	 * to trigger various behaviors.
	 */
	int flags;

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @freeze_type: determines conditions under which the time trace
	 * should be frozen. Set externally via sysctl.
	 */
	enum homa_freeze_type freeze_type;
#endif /* See strip.py */

	/**
	 * @bpage_lease_usecs: how long a core can own a bpage (microseconds)
	 * before its ownership can be revoked to reclaim the page.
	 */
	int bpage_lease_usecs;

	/**
	 * @next_id: Set via sysctl; causes next_outgoing_id to be set to
	 * this value; always reads as zero. Typically used while debugging to
	 * ensure that different nodes use different ranges of ids.
	 */
	int next_id;

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @sysctl_header: Used to remove sysctl values when this structure
	 * is destroyed.
	 */
	struct ctl_table_header *sysctl_header;
#endif /* See strip.py */

#ifndef __UPSTREAM__ /* See strip.py */
	/**
	 * @sysctl_action: This value is set by sysctl to invoke one of
	 * several actions for testing. It is normally zero.
	 */
	int sysctl_action;

	/**
	 * @timer_kthread: Thread that runs timer code to detect lost
	 * packets and crashed peers.
	 */
	struct task_struct *timer_kthread;

	/** @hrtimer: Used to wakeup @timer_kthread at regular intervals. */
	struct hrtimer hrtimer;

	/**
	 * @destroyed: True means that this structure is being destroyed
	 * so everyone should clean up.
	 */
	bool destroyed;

	/**
	 * @temp: the values in this array can be read and written with sysctl.
	 * They have no officially defined purpose, and are available for
	 * short-term use during testing.
	 */
	int temp[4];
#endif /* See strip.py */
};

/**
 * struct homa_skb_info - Additional information needed by Homa for each
 * outbound DATA packet. Space is allocated for this at the very end of the
 * linear part of the skb.
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
 * Return: address of Homa's private information for @skb.
 */
static inline struct homa_skb_info *homa_get_skb_info(struct sk_buff *skb)
{
	return (struct homa_skb_info *)(skb_end_pointer(skb)) - 1;
}

/**
 * homa_set_doff() - Fills in the doff TCP header field for a Homa packet.
 * @h:     Packet header whose doff field is to be set.
 * @size:  Size of the "header", bytes (must be a multiple of 4). This
 *         information is used only for TSO; it's the number of bytes
 *         that should be replicated in each segment. The bytes after
 *         this will be distributed among segments.
 */
static inline void homa_set_doff(struct homa_data_hdr *h, int size)
{
	/* Drop the 2 low-order bits from size and set the 4 high-order
	 * bits of doff from what's left.
	 */
	h->common.doff = size << 2;
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_throttle_lock() - Acquire the throttle lock. If the lock
 * isn't immediately available, record stats on the waiting time.
 * @homa:    Overall data about the Homa protocol implementation.
 */
static inline void homa_throttle_lock(struct homa *homa)
	__acquires(&homa->throttle_lock)
{
	if (!spin_trylock_bh(&homa->throttle_lock))
		homa_throttle_lock_slow(homa);
}
#else /* See strip.py */
/**
 * homa_throttle_lock() - Acquire the throttle lock.
 * @homa:    Overall data about the Homa protocol implementation.
 */
static inline void homa_throttle_lock(struct homa *homa)
	__acquires(&homa->throttle_lock)
{
	spin_lock_bh(&homa->throttle_lock);
}
#endif /* See strip.py */

/**
 * homa_throttle_unlock() - Release the throttle lock.
 * @homa:    Overall data about the Homa protocol implementation.
 */
static inline void homa_throttle_unlock(struct homa *homa)
	__releases(&homa->throttle_lock)
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
 * ipv6_to_ipv4() - Given an IPv6 address produced by ipv4_to_ipv6, return
 * the original IPv4 address (in network byte order).
 * @ip6:  IPv6 address; assumed to be a mapped IPv4 address.
 * Return: IPv4 address stored in @ip6.
 */
static inline __be32 ipv6_to_ipv4(const struct in6_addr ip6)
{
	return ip6.in6_u.u6_addr32[3];
}

/**
 * canonical_ipv6_addr() - Convert a socket address to the "standard"
 * form used in Homa, which is always an IPv6 address; if the original address
 * was IPv4, convert it to an IPv4-mapped IPv6 address.
 * @addr:   Address to canonicalize (if NULL, "any" is returned).
 * Return: IPv6 address corresponding to @addr.
 */
static inline struct in6_addr canonical_ipv6_addr(const union sockaddr_in_union
						  *addr)
{
	struct in6_addr mapped;
	if (addr) {
		if (addr->sa.sa_family == AF_INET6)
			return addr->in6.sin6_addr;
		ipv6_addr_set_v4mapped(addr->in4.sin_addr.s_addr, &mapped);
		return mapped;
	}
	return in6addr_any;
}

/**
 * skb_canonical_ipv6_saddr() - Given a packet buffer, return its source
 * address in the "standard" form used in Homa, which is always an IPv6
 * address; if the original address was IPv4, convert it to an IPv4-mapped
 * IPv6 address.
 * @skb:   The source address will be extracted from this packet buffer.
 * Return: IPv6 address for @skb's source machine.
 */
static inline struct in6_addr skb_canonical_ipv6_saddr(struct sk_buff *skb)
{
	struct in6_addr mapped;

	if (skb_is_ipv6(skb))
		return ipv6_hdr(skb)->saddr;
	ipv6_addr_set_v4mapped(ip_hdr(skb)->saddr, &mapped);
	return mapped;
}

static inline bool is_homa_pkt(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

#ifndef __STRIP__ /* See strip.py */
	return ((iph->protocol == IPPROTO_HOMA) ||
		((iph->protocol == IPPROTO_TCP) &&
		 (tcp_hdr(skb)->urg_ptr == htons(HOMA_TCP_URGENT))));
#else /* See strip.py */
	return (iph->protocol == IPPROTO_HOMA);
#endif /* See strip.py */
}

/**
 * homa_make_header_avl() - Invokes pskb_may_pull to make sure that all the
 * Homa header information for a packet is in the linear part of the skb
 * where it can be addressed using skb_transport_header.
 * @skb:     Packet for which header is needed.
 * Return:   The result of pskb_may_pull (true for success)
 */
static inline bool homa_make_header_avl(struct sk_buff *skb)
{
	int pull_length;

	pull_length = skb_transport_header(skb) - skb->data + HOMA_MAX_HEADER;
	if (pull_length > skb->len)
		pull_length = skb->len;
	return pskb_may_pull(skb, pull_length);
}

#ifdef __UNIT_TEST__
void unit_log_printf(const char *separator, const char *format, ...)
		__printf(2, 3);
#define UNIT_LOG unit_log_printf
void unit_hook(char *id);
#define UNIT_HOOK(msg) unit_hook(msg)
#else /* __UNIT_TEST__ */
#define UNIT_LOG(...)
#define UNIT_HOOK(...)
#endif /* __UNIT_TEST__ */

extern unsigned int homa_net_id;

void     homa_abort_rpcs(struct homa *homa, const struct in6_addr *addr,
			 int port, int error);
void     homa_abort_sock_rpcs(struct homa_sock *hsk, int error);
void     homa_ack_pkt(struct sk_buff *skb, struct homa_sock *hsk,
		      struct homa_rpc *rpc);
void     homa_add_packet(struct homa_rpc *rpc, struct sk_buff *skb);
void     homa_add_to_throttled(struct homa_rpc *rpc);
int      homa_backlog_rcv(struct sock *sk, struct sk_buff *skb);
int      homa_bind(struct socket *sk, struct sockaddr *addr,
		   int addr_len);
int      homa_check_nic_queue(struct homa *homa, struct sk_buff *skb,
			      bool force);
void     homa_close(struct sock *sock, long timeout);
int      homa_copy_to_user(struct homa_rpc *rpc);
void     homa_data_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
void     homa_destroy(struct homa *homa);
int      homa_disconnect(struct sock *sk, int flags);
void     homa_dispatch_pkts(struct sk_buff *skb, struct homa *homa);
int      homa_err_handler_v4(struct sk_buff *skb, u32 info);
int      homa_err_handler_v6(struct sk_buff *skb,
			     struct inet6_skb_parm *opt, u8 type,  u8 code,
			     int offset, __be32 info);
int      homa_fill_data_interleaved(struct homa_rpc *rpc,
				    struct sk_buff *skb, struct iov_iter *iter);
struct homa_gap *homa_gap_new(struct list_head *next, int start, int end);
void     homa_gap_retry(struct homa_rpc *rpc);
int      homa_get_port(struct sock *sk, unsigned short snum);
int      homa_getsockopt(struct sock *sk, int level, int optname,
			 char __user *optval, int __user *optlen);
int      homa_hash(struct sock *sk);
enum hrtimer_restart homa_hrtimer(struct hrtimer *timer);
int      homa_init(struct homa *homa);
int      homa_ioctl(struct sock *sk, int cmd, int *karg);
int      homa_load(void);
int      homa_message_out_fill(struct homa_rpc *rpc,
			       struct iov_iter *iter, int xmit);
void     homa_message_out_init(struct homa_rpc *rpc, int length);
void     homa_need_ack_pkt(struct sk_buff *skb, struct homa_sock *hsk,
			   struct homa_rpc *rpc);
struct sk_buff *homa_new_data_packet(struct homa_rpc *rpc,
				     struct iov_iter *iter, int offset,
				     int length, int max_seg_data);
int      homa_net_init(struct net *net);
void     homa_net_exit(struct net *net);
int      homa_pacer_main(void *transport);
void     homa_pacer_stop(struct homa *homa);
bool     homa_pacer_xmit(struct homa *homa);
__poll_t homa_poll(struct file *file, struct socket *sock,
		   struct poll_table_struct *wait);
int      homa_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		      int flags, int *addr_len);
void     homa_remove_from_throttled(struct homa_rpc *rpc);
void     homa_resend_pkt(struct sk_buff *skb, struct homa_rpc *rpc,
			 struct homa_sock *hsk);
void     homa_rpc_abort(struct homa_rpc *crpc, int error);
void     homa_rpc_acked(struct homa_sock *hsk,
			const struct in6_addr *saddr, struct homa_ack *ack);
void     homa_rpc_end(struct homa_rpc *rpc);
void     homa_rpc_handoff(struct homa_rpc *rpc);
int      homa_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
int      homa_setsockopt(struct sock *sk, int level, int optname,
			 sockptr_t optval, unsigned int optlen);
int      homa_shutdown(struct socket *sock, int how);
int      homa_softirq(struct sk_buff *skb);
void     homa_spin(int ns);
void     homa_timer(struct homa *homa);
int      homa_timer_main(void *transport);
void     homa_unhash(struct sock *sk);
void     homa_rpc_unknown_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
void     homa_unload(void);
int      homa_wait_private(struct homa_rpc *rpc, int nonblocking);
struct homa_rpc
        *homa_wait_shared(struct homa_sock *hsk, int nonblocking);
int      homa_xmit_control(enum homa_packet_type type, void *contents,
			   size_t length, struct homa_rpc *rpc);
int      __homa_xmit_control(void *contents, size_t length,
			     struct homa_peer *peer, struct homa_sock *hsk);
void     homa_xmit_data(struct homa_rpc *rpc, bool force);
void     homa_xmit_unknown(struct sk_buff *skb, struct homa_sock *hsk);

#ifndef __STRIP__ /* See strip.py */
struct homa_rpc
	*homa_choose_fifo_grant(struct homa *homa);
void     homa_cutoffs_pkt(struct sk_buff *skb, struct homa_sock *hsk);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
int      homa_dointvec(struct ctl_table *table, int write,
		       void __user *buffer, size_t *lenp, loff_t *ppos);
#else
int      homa_dointvec(const struct ctl_table *table, int write,
		       void *buffer, size_t *lenp, loff_t *ppos);
#endif
void     homa_incoming_sysctl_changed(struct homa *homa);
int      homa_ioc_abort(struct sock *sk, int *karg);
void     homa_log_throttled(struct homa *homa);
int      homa_message_in_init(struct homa_rpc *rpc, int length,
			      int unsched);
void     homa_outgoing_sysctl_changed(struct homa *homa);
void     homa_prios_changed(struct homa *homa);
void     homa_resend_data(struct homa_rpc *rpc, int start, int end,
			  int priority);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
int      homa_sysctl_softirq_cores(struct ctl_table *table, int write,
				   void __user *buffer, size_t *lenp,
				   loff_t *ppos);
#else
int      homa_sysctl_softirq_cores(const struct ctl_table *table,
				   int write, void *buffer, size_t *lenp,
				   loff_t *ppos);
int      homa_unsched_priority(struct homa *homa, struct homa_peer *peer,
			       int length);
int      homa_validate_incoming(struct homa *homa, int verbose,
				int *link_errors);
void     __homa_xmit_data(struct sk_buff *skb, struct homa_rpc *rpc,
			  int priority);
#endif
#else /* See strip.py */
int      homa_message_in_init(struct homa_rpc *rpc, int unsched);
void     homa_resend_data(struct homa_rpc *rpc, int start, int end);
void     __homa_xmit_data(struct sk_buff *skb, struct homa_rpc *rpc);
#endif /* See strip.py */

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

	/* The ">> 1" in the line below gives homa_pacer_main the first chance
	 * to queue new packets; if the NIC queue becomes more than half
	 * empty, then we will help out here.
	 */
	if ((sched_clock() + (homa->max_nic_queue_ns >> 1)) <
			atomic64_read(&homa->link_idle_time))
		return;
	tt_record("homa_check_pacer calling homa_pacer_xmit");
	homa_pacer_xmit(homa);
	INC_METRIC(pacer_needed_help, 1);
}

/**
 * homa_from_net() - Return the struct homa associated with a particular
 * struct net.
 * @net:     Get the struct homa for this net namespace.
 * Return:   see above
 */
static inline struct homa *homa_from_net(struct net *net)
{
	return (struct homa *) net_generic(net, homa_net_id);
}

/**
 * homa_from_sock() - Return the struct homa associated with a particular
 * struct sock.
 * @sock:    Get the struct homa for this socket.
 * Return:   see above
 */
static inline struct homa *homa_from_sock(struct sock *sock)
{
	return (struct homa *) net_generic(sock_net(sock), homa_net_id);
}

/**
 * homa_from_skb() - Return the struct homa associated with a particular
 * sk_buff.
 * @skb:     Get the struct homa for this packet buffer.
 * Return:   see above
 */
static inline struct homa *homa_from_skb(struct sk_buff *skb)
{
	return (struct homa *) net_generic(dev_net(skb->dev), homa_net_id);
}

extern struct completion homa_pacer_kthread_done;
#endif /* _HOMA_IMPL_H */
