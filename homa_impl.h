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
struct homa_shared;

#ifndef __STRIP__ /* See strip.py */
#include "timetrace.h"
#include "homa_metrics.h"

/* Declarations used in this file, so they can't be made at the end. */
void     homa_throttle_lock_slow(struct homa *homa);
#endif /* See strip.py */

#ifdef __CHECKER__
#define __context__(x, y, z) __attribute__((context(x, y, z)))
#else
#define __context__(...)
#endif /* __CHECKER__ */

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
 * struct homa - Stores overall information about the implementation of
 * Homa for a particular network namespace (there is a logcially separate
 * implementation of Homa for each namespace).
 */
struct homa {
	/**  @shared: information shared across all struct homas. */
	struct homa_shared *shared;

	/** shared_links: used to link this struct into shared->homas. */
	struct list_head shared_links;

	/**
	 * @next_outgoing_id: Id to use for next outgoing RPC request.
	 * This is always even: it's used only to generate client-side ids.
	 * Accessed without locks. Note: RPC ids are unique within a
	 * single client machine.
	 */
	atomic64_t next_outgoing_id;

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @grant: Contains information used by homa_grant.c to manage
	 * grants for incoming messages.
	 */
	struct homa_grant *grant;
#endif /* See strip.py */

	/**
	 * @pacer:  Information related to the pacer; managed by homa_pacer.c.
	 */
	struct homa_pacer *pacer;

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
	 * @pages_to_free_slots: Maximum number of pages that can be
	 * stored in skb_pages_to_free;
	 */
	int pages_to_free_slots;

	/**
	 * @skb_page_free_time: homa_clock() time when the next sk_buff
	 * page should be freed. Could be in the past.
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
	 * @poll_usecs: Amount of time (in microseconds) that a thread
	 * will spend busy-waiting for an incoming messages before
	 * going to sleep. Set externally via sysctl.
	 */
	int poll_usecs;

	/** @poll_cycles: Same as poll_usecs except in homa_clock() units. */
	u64 poll_cycles;

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

	/**
	 * @busy_usecs: if there has been activity on a core within the
	 * last @busy_usecs, it is considered to be busy and Homa will
	 * try to avoid scheduling other activities on the core. See
	 * balance.txt for more on load balancing. Set externally via sysctl.
	 */
	int busy_usecs;

	/** @busy_cycles: Same as busy_usecs except in homa_clock() units. */
	int busy_cycles;

	/**
	 * @gro_busy_usecs: if the gap between the completion of
	 * homa_gro_receive and the next call to homa_gro_receive on the same
	 * core is less than this, then GRO on that core is considered to be
	 * "busy", and optimizations such as HOMA_GRO_SHORT_BYPASS will not be
	 * done because they risk overloading the core. Set externally via
	 * sysctl.
	 */
	int gro_busy_usecs;

	/**
	 * @gro_busy_cycles: Same as busy_usecs except in homa_clock() units.
	 */
	int gro_busy_cycles;
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
	 * @bpage_lease_cycles: same as bpage_lease_usecs except in
	 * homa_clock() units.
	 * */
	int bpage_lease_cycles;

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

#ifndef __UPSTREAM__ /* See strip.py */
	/**
	 * @sysctl_action: This value is set by sysctl to invoke one of
	 * several actions for testing. It is normally zero.
	 */
	int sysctl_action;

	/**
	 * @temp: the values in this array can be read and written with sysctl.
	 * They have no officially defined purpose, and are available for
	 * short-term use during testing.
	 */
	int temp[4];
#endif /* See strip.py */
};

/**
 * struct homa_shared - Contains "global" information that is shared
 * across all instances of struct homa.
 */
struct homa_shared {
	/**
	 * @lock: used when exclusive access is needed, such as when
	 * updating @homas.
	 */
	spinlock_t lock;

	/**
	 * @homas: contains all of the existing struct homas, linked
	 * through their shared_links fields. Managed with RCU.
	 */
	struct list_head homas;
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

#ifndef __STRIP__ /* See strip.py */
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
#endif /* See strip.py */

extern unsigned int homa_net_id;
extern struct homa_shared *homa_shared;

void     homa_ack_pkt(struct sk_buff *skb, struct homa_sock *hsk,
		      struct homa_rpc *rpc);
void     homa_add_packet(struct homa_rpc *rpc, struct sk_buff *skb);
int      homa_bind(struct socket *sk, struct sockaddr *addr,
		   int addr_len);
void     homa_close(struct sock *sock, long timeout);
int      homa_copy_to_user(struct homa_rpc *rpc);
void     homa_data_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
void     homa_destroy(struct homa *homa);
void     homa_dispatch_pkts(struct sk_buff *skb, struct homa *homa);
int      homa_err_handler_v4(struct sk_buff *skb, u32 info);
int      homa_err_handler_v6(struct sk_buff *skb,
			     struct inet6_skb_parm *opt, u8 type,  u8 code,
			     int offset, __be32 info);
int      homa_fill_data_interleaved(struct homa_rpc *rpc,
				    struct sk_buff *skb, struct iov_iter *iter);
struct homa_gap *homa_gap_alloc(struct list_head *next, int start, int end);
void     homa_gap_retry(struct homa_rpc *rpc);
int      homa_getsockopt(struct sock *sk, int level, int optname,
			 char __user *optval, int __user *optlen);
int      homa_hash(struct sock *sk);
enum hrtimer_restart homa_hrtimer(struct hrtimer *timer);
int      homa_init(struct homa *homa, struct net *net);
int      homa_ioctl(struct sock *sk, int cmd, int *karg);
int      homa_load(void);
int      homa_message_out_fill(struct homa_rpc *rpc,
			       struct iov_iter *iter, int xmit);
void     homa_message_out_init(struct homa_rpc *rpc, int length);
void     homa_need_ack_pkt(struct sk_buff *skb, struct homa_sock *hsk,
			   struct homa_rpc *rpc);
int      homa_net_init(struct net *net);
void     homa_net_exit(struct net *net);
__poll_t homa_poll(struct file *file, struct socket *sock,
		   struct poll_table_struct *wait);
int      homa_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		      int flags, int *addr_len);
void     homa_resend_pkt(struct sk_buff *skb, struct homa_rpc *rpc,
			 struct homa_sock *hsk);
void     homa_rpc_handoff(struct homa_rpc *rpc);
int      homa_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
int      homa_setsockopt(struct sock *sk, int level, int optname,
			 sockptr_t optval, unsigned int optlen);
struct homa_shared *homa_shared_alloc(void);
void     homa_shared_free(struct homa_shared *shared);
int      homa_shutdown(struct socket *sock, int how);
int      homa_softirq(struct sk_buff *skb);
void     homa_spin(int ns);
void     homa_timer(struct homa *homa);
void     homa_timer_check_rpc(struct homa_rpc *rpc);
int      homa_timer_main(void *transport);
struct sk_buff *homa_tx_data_pkt_alloc(struct homa_rpc *rpc,
				       struct iov_iter *iter, int offset,
				       int length, int max_seg_data);
void     homa_unhash(struct sock *sk);
void     homa_rpc_unknown_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
void     homa_unload(void);
int      homa_wait_private(struct homa_rpc *rpc, int nonblocking);
struct homa_rpc *homa_wait_shared(struct homa_sock *hsk, int nonblocking);
int      homa_xmit_control(enum homa_packet_type type, void *contents,
			   size_t length, struct homa_rpc *rpc);
int      __homa_xmit_control(void *contents, size_t length,
			     struct homa_peer *peer, struct homa_sock *hsk);
void     homa_xmit_data(struct homa_rpc *rpc, bool force);
void     homa_xmit_unknown(struct sk_buff *skb, struct homa_sock *hsk);

#ifndef __STRIP__ /* See strip.py */
void     homa_cutoffs_pkt(struct sk_buff *skb, struct homa_sock *hsk);
int      homa_dointvec(const struct ctl_table *table, int write,
		       void *buffer, size_t *lenp, loff_t *ppos);
void     homa_incoming_sysctl_changed(struct homa *homa);
int      homa_ioc_abort(struct sock *sk, int *karg);
int      homa_message_in_init(struct homa_rpc *rpc, int length,
			      int unsched);
void     homa_prios_changed(struct homa *homa);
void     homa_resend_data(struct homa_rpc *rpc, int start, int end,
			  int priority);
int      homa_sysctl_softirq_cores(const struct ctl_table *table,
				   int write, void *buffer, size_t *lenp,
				   loff_t *ppos);
int      homa_unsched_priority(struct homa *homa, struct homa_peer *peer,
			       int length);
int      homa_validate_incoming(struct homa *homa, int verbose,
				int *link_errors);
void     __homa_xmit_data(struct sk_buff *skb, struct homa_rpc *rpc,
			  int priority);
#else /* See strip.py */
int      homa_message_in_init(struct homa_rpc *rpc, int unsched);
void     homa_resend_data(struct homa_rpc *rpc, int start, int end);
void     __homa_xmit_data(struct sk_buff *skb, struct homa_rpc *rpc);
#endif /* See strip.py */

/**
 * homa_from_net() - Return the struct homa associated with a particular
 * struct net.
 * @net:     Get the struct homa for this net namespace.
 * Return:   see above.
 */
static inline struct homa *homa_from_net(struct net *net)
{
	return (struct homa *)net_generic(net, homa_net_id);
}

/**
 * homa_from_sock() - Return the struct homa associated with a particular
 * struct sock.
 * @sock:    Get the struct homa for this socket.
 * Return:   see above.
 */
static inline struct homa *homa_from_sock(struct sock *sock)
{
	return (struct homa *)net_generic(sock_net(sock), homa_net_id);
}

/**
 * homa_from_skb() - Return the struct homa associated with a particular
 * sk_buff.
 * @skb:     Get the struct homa for this packet buffer.
 * Return:   see above.
 */
static inline struct homa *homa_from_skb(struct sk_buff *skb)
{
	return (struct homa *)net_generic(dev_net(skb->dev), homa_net_id);
}

/**
 * homa_clock() - Return a fine-grain clock value that is monotonic and
 * consistent across cores.
 * Return: see above.
 */
static inline u64 homa_clock(void)
{
	/* As of May 2025 there does not appear to be a portable API that
	 * meets Homa's needs:
	 * - The Intel X86 TSC works well but is not portable.
	 * - sched_clock() does not guarantee monotonicity or consistency.
	 * - ktime_get_mono_fast_ns and ktime_get_raw_fast_ns are very slow
	 *   (27 ns to read, vs 8 ns for TSC)
	 * Thus we use a hybrid approach that uses TSC (via get_cycles) where
	 * available (which should be just about everywhere Homa runs).
	 */
#ifdef __UNIT_TEST__
	u64 mock_get_clock(void);
	return mock_get_clock();
#else /* __UNIT_TEST__ */
#ifdef CONFIG_X86_TSC
	return get_cycles();
#else
	return ktime_get_mono_fast_ns();
#endif /* CONFIG_X86_TSC */
#endif /* __UNIT_TEST__ */
}

/**
 * homa_clock_khz() - Return the frequency of the values returned by
 * homa_clock, in units of KHz.
 * Return: see above.
 */
static inline u64 homa_clock_khz(void)
{
#ifdef __UNIT_TEST__
	return 1000000;
#else /* __UNIT_TEST__ */
#ifdef CONFIG_X86_TSC
	return cpu_khz;
#else
	return 1000000;
#endif /* CONFIG_X86_TSC */
#endif /* __UNIT_TEST__ */
}

/**
 * homa_ns_to_cycles() - Convert from units of nanoseconds to units of
 * homa_clock().
 * @ns:      A time measurement in nanoseconds
 * Return:   The time in homa_clock() units corresponding to @ns.
 */
static inline u64 homa_ns_to_cycles(u64 ns)
{
#ifdef __UNIT_TEST__
	return ns;
#else /* __UNIT_TEST__ */
#ifdef CONFIG_X86_TSC
	u64 tmp;

	tmp = ns * cpu_khz;
	do_div(tmp, 1000000);
	return tmp;
#else
	return ns;
#endif /* CONFIG_X86_TSC */
#endif /* __UNIT_TEST__ */
}

/**
 * homa_usec_to_cycles() - Convert from units of microseconds to units of
 * homa_clock().
 * @usecs:   A time measurement in microseconds
 * Return:   The time in homa_clock() units corresponding to @usecs.
 */
static inline u64 homa_usecs_to_cycles(u64 usecs)
{
#ifdef __UNIT_TEST__
	return usecs * 1000;
#else /* __UNIT_TEST__ */
#ifdef CONFIG_X86_TSC
	u64 tmp;

	tmp = usecs * cpu_khz;
	do_div(tmp, 1000);
	return tmp;
#else
	return usecs * 1000;
#endif /* CONFIG_X86_TSC */
#endif /* __UNIT_TEST__ */
}

#endif /* _HOMA_IMPL_H */
