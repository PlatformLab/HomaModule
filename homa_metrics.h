/* SPDX-License-Identifier: BSD-2-Clause */

/* This file contains declarations related to Homa's performance metrics.  */

#ifndef _HOMA_METRICS_H
#define _HOMA_METRICS_H

#include <linux/percpu-defs.h>
#include <linux/types.h>

#include "homa_wire.h"

/**
 * struct homa_metrics - various performance counters kept by Homa.
 *
 * There is one of these structures for each core, so counters can
 * be updated without worrying about synchronization or extra cache
 * misses.
 *
 * All counters are free-running: they never reset.
 */
struct homa_metrics {
	/**
	 * @small_msg_bytes: entry i holds the total number of bytes
	 * received in messages whose length is between 64*i and 64*i + 63,
	 * inclusive.
	 */
#define HOMA_NUM_SMALL_COUNTS 64
	u64 small_msg_bytes[HOMA_NUM_SMALL_COUNTS];

	/**
	 * @medium_msg_bytes: entry i holds the total number of bytes
	 * received in messages whose length is between 1024*i and
	 * 1024*i + 1023, inclusive. The first four entries are always 0
	 * (small_msg_counts covers this range).
	 */
#define HOMA_NUM_MEDIUM_COUNTS 128
	u64 medium_msg_bytes[HOMA_NUM_MEDIUM_COUNTS];

	/**
	 * @large_msg_count: the total number of messages received whose
	 * length is too large to appear in medium_msg_bytes.
	 */
	u64 large_msg_count;

	/**
	 * @large_msg_bytes: the total number of bytes received in
	 * messages too large to be counted by medium_msg_bytes.
	 */
	u64 large_msg_bytes;

	/**
	 * @sent_msg_bytes: The total number of bytes in outbound
	 * messages.
	 */
	u64 sent_msg_bytes;

	/**
	 * @packets_sent: total number of packets sent for each packet type
	 * (entry 0 corresponds to DATA, and so on).
	 */
	u64 packets_sent[MAX_OP + 1 - DATA];

	/**
	 * @packets_received: total number of packets received for each
	 * packet type (entry 0 corresponds to DATA, and so on).
	 */
	u64 packets_received[MAX_OP + 1 - DATA];

	/** @priority_bytes: total bytes sent at each priority level. */
	u64 priority_bytes[HOMA_MAX_PRIORITIES];

	/** @priority_packets: total packets sent at each priority level. */
	u64 priority_packets[HOMA_MAX_PRIORITIES];

	/**
	 * @skb_allocs: total number of calls to homa_skb_alloc_tx.
	 */
	u64 skb_allocs;

	/** @skb_alloc_cycles: total time spent in homa_skb_alloc_tx. */
	u64 skb_alloc_cycles;

	/**
	 * @skb_frees: total number of sk_buffs for data packets that have
	 * been freed (counts normal paths only).
	 */
	u64 skb_frees;

	/** @skb_free_cycles: total time spent freeing sk_buffs. */
	u64 skb_free_cycles;

	/**
	 * @skb_page_allocs: total number of calls to homa_skb_page_alloc.
	 */
	u64 skb_page_allocs;

	/** @skb_page_alloc_cycles: total time spent in homa_skb_page_alloc. */
	u64 skb_page_alloc_cycles;

	/**
	 * @requests_received: total number of request messages received.
	 */
	u64 requests_received;

	/**
	 * @responses_received: total number of response messages received.
	 */
	u64 responses_received;

	/**
	 * @wait_none: total number of times that an incoming message was
	 * already waiting when recvmsg was invoked.
	 */
	u64 wait_none;

	/**
	 * @wait_fast: total number of times that a message arrived for
	 * a receiving thread while it was polling (i.e. the message
	 * wasn't immediately available, but the thread never blocked).
	 */
	u64 wait_fast;

	/**
	 * @wait_block: total number of times that a thread blocked at
	 * least once while waiting for an incoming message.
	 */
	u64 wait_block;

	/**
	 * @handoffs_thread_waiting: total number of times that an RPC
	 * was handed off to a waiting thread (vs. being queued).
	 */
	u64 handoffs_thread_waiting;

	/**
	 * @handoffs_alt_thread: total number of times that a thread other
	 * than the first on the list was chosen for a handoff (because the
	 * first thread was on a busy core).
	 */
	u64 handoffs_alt_thread;

	/**
	 * @poll_cycles: total time spent in the polling loop in
	 * homa_wait_for_message.
	 */
	u64 poll_cycles;

	/**
	 * @softirq_calls: total number of calls to homa_softirq (i.e.,
	 * total number of GRO packets processed, each of which could contain
	 * multiple Homa packets.
	 */
	u64 softirq_calls;

	/**
	 * @softirq_cycles: total time spent executing homa_softirq when
	 * invoked under Linux's SoftIRQ handler.
	 */
	u64 softirq_cycles;

	/**
	 * @bypass_softirq_cycles: total time spent executing homa_softirq when
	 * invoked during GRO, bypassing the SoftIRQ mechanism.
	 */
	u64 bypass_softirq_cycles;

	/**
	 * @linux_softirq_cycles: total time spent executing all softirq
	 * activities, as measured by the linux softirq module. Only
	 * available with modified Linux kernels.
	 */
	u64 linux_softirq_cycles;

	/**
	 * @napi_cycles: total time spent executing all NAPI activities, as
	 * measured by the linux softirq module. Only available with modified
	 * Linux kernels.
	 */
	u64 napi_cycles;

	/**
	 * @send_cycles: total time spent executing the homa_sendmsg kernel
	 * call handler to send requests.
	 */
	u64 send_cycles;

	/**
	 * @send_calls: total number of invocations of homa_semdmsg
	 * for requests.
	 */
	u64 send_calls;

	/**
	 * @recv_cycles: total time spent executing homa_recvmsg (including
	 * time when the thread is blocked).
	 */
	u64 recv_cycles;

	/** @recv_calls: total number of invocations of homa_recvmsg. */
	u64 recv_calls;

	/**
	 * @blocked_cycles: total time spent by threads in blocked state
	 * while executing the homa_recvmsg kernel call handler.
	 */
	u64 blocked_cycles;

	/**
	 * @reply_cycles: total time spent executing the homa_sendmsg kernel
	 * call handler to send responses.
	 */
	u64 reply_cycles;

	/**
	 * @reply_calls: total number of invocations of homa_semdmsg
	 * for responses.
	 */
	u64 reply_calls;

	/**
	 * @abort_cycles: total time spent executing the homa_ioc_abort
	 * kernel call handler.
	 */
	u64 abort_cycles;

	/**
	 * @abort_calls: total number of invocations of the homa_ioc_abort
	 * kernel call.
	 */
	u64 abort_calls;

	/**
	 * @so_set_buf_cycles: total time spent executing the homa_ioc_set_buf
	 * kernel call handler.
	 */
	u64 so_set_buf_cycles;

	/**
	 * @so_set_buf_calls: total number of invocations of the homa_ioc_set_buf
	 * kernel call.
	 */
	u64 so_set_buf_calls;

	/**  @grant_lock_cycles: total time spent with the grant lock locked. */
	u64 grant_lock_cycles;

	/** @timer_cycles: total time spent in homa_timer. */
	u64 timer_cycles;

	/**
	 * @timer_reap_cycles: total time spent by homa_timer to reap dead
	 * RPCs. This time is included in @timer_cycles.
	 */
	u64 timer_reap_cycles;

	/**
	 * @data_pkt_reap_cycles: total time spent by homa_data_pkt to reap
	 * dead RPCs.
	 */
	u64 data_pkt_reap_cycles;

	/**
	 * @pacer_cycles: total time spent executing in homa_pacer_main
	 * (not including blocked time).
	 */
	u64 pacer_cycles;

	/**
	 * @pacer_lost_cycles: unnecessary delays in transmitting packets
	 * (i.e. wasted output bandwidth) because the pacer was slow or got
	 * descheduled.
	 */
	u64 pacer_lost_cycles;

	/**
	 * @pacer_bytes: total number of bytes transmitted when
	 * @homa->throttled_rpcs is nonempty.
	 */
	u64 pacer_bytes;

	/**
	 * @pacer_skipped_rpcs: total number of times that the pacer had to
	 * abort because it couldn't lock an RPC.
	 */
	u64 pacer_skipped_rpcs;

	/**
	 * @pacer_needed_help: total number of times that homa_check_pacer
	 * found that the pacer was running behind, so it actually invoked
	 * homa_pacer_xmit.
	 */
	u64 pacer_needed_help;

	/**
	 * @throttled_cycles: total amount of time that @homa->throttled_rpcs
	 * is nonempty.
	 */
	u64 throttled_cycles;

	/**
	 * @resent_packets: total number of data packets issued in response to
	 * RESEND packets.
	 */
	u64 resent_packets;

	/**
	 * @peer_new_entries: total # of new entries created in Homa's
	 * peer table (this value doesn't increment if the desired peer is
	 * found in the entry in its hash chain).
	 */
	u64 peer_new_entries;

	/**
	 * @peer_kmalloc_errors: total number of times homa_peer_find
	 * returned an error because it couldn't allocate memory for a new
	 * peer.
	 */
	u64 peer_kmalloc_errors;

	/**
	 * @peer_route_errors: total number of times homa_peer_find
	 * returned an error because it couldn't create a route to the peer.
	 */
	u64 peer_route_errors;

	/**
	 * @control_xmit_errors: total number of times ip_queue_xmit
	 * failed when transmitting a control packet.
	 */
	u64 control_xmit_errors;

	/**
	 * @data_xmit_errors: total number of times ip_queue_xmit
	 * failed when transmitting a data packet.
	 */
	u64 data_xmit_errors;

	/**
	 * @unknown_rpcs: total number of times an incoming packet was
	 * discarded because it referred to a nonexistent RPC. Doesn't
	 * count grant packets received by servers (since these are
	 * fairly common).
	 */
	u64 unknown_rpcs;

	/**
	 * @server_cant_create_rpcs: total number of times a server discarded
	 * an incoming packet because it couldn't create a homa_rpc object.
	 */
	u64 server_cant_create_rpcs;

	/**
	 * @unknown_packet_types: total number of times a packet was discarded
	 * because its type wasn't one of the supported values.
	 */
	u64 unknown_packet_types;

	/**
	 * @short_packets: total number of times a packet was discarded
	 * because it was too short to hold all the required information.
	 */
	u64 short_packets;

	/**
	 * @packet_discards: total number of times a normal (non-retransmitted)
	 * packet was discarded because all its data had already been received.
	 */
	u64 packet_discards;

	/**
	 * @resent_discards: total number of times a retransmitted packet
	 * was discarded because its data had already been received.
	 */
	u64 resent_discards;

	/**
	 * @resent_packets_used: total number of times a resent packet was
	 * actually incorporated into the message at the target (i.e. it
	 * wasn't redundant).
	 */
	u64 resent_packets_used;

	/**
	 * @rpc_timeouts: total number of times an RPC (either client or
	 * server) was aborted because the peer was nonresponsive.
	 */
	u64 rpc_timeouts;

	/**
	 * @server_rpc_discards: total number of times an RPC was aborted on
	 * the server side because of a timeout.
	 */
	u64 server_rpc_discards;

	/**
	 * @server_rpcs_unknown: total number of times an RPC was aborted on
	 * the server side because it is no longer known to the client.
	 */
	u64 server_rpcs_unknown;

	/**
	 * @client_lock_misses: total number of times that Homa had to wait
	 * to acquire a client bucket lock.
	 */
	u64 client_lock_misses;

	/**
	 * @client_lock_miss_cycles: total time spent waiting for client
	 * bucket lock misses.
	 */
	u64 client_lock_miss_cycles;

	/**
	 * @server_lock_misses: total number of times that Homa had to wait
	 * to acquire a server bucket lock.
	 */
	u64 server_lock_misses;

	/**
	 * @server_lock_miss_cycles: total time spent waiting for server
	 * bucket lock misses.
	 */
	u64 server_lock_miss_cycles;

	/**
	 * @socket_lock_miss_cycles: total time spent waiting for socket
	 * lock misses.
	 */
	u64 socket_lock_miss_cycles;

	/**
	 * @socket_lock_misses: total number of times that Homa had to wait
	 * to acquire a socket lock.
	 */
	u64 socket_lock_misses;

	/**
	 * @throttle_lock_miss_cycles: total time spent waiting for throttle
	 * lock misses.
	 */
	u64 throttle_lock_miss_cycles;

	/**
	 * @throttle_lock_misses: total number of times that Homa had to wait
	 * to acquire the throttle lock.
	 */
	u64 throttle_lock_misses;

	/**
	 * @peer_ack_lock_miss_cycles: total time spent waiting for peer lock misses.
	 */
	u64 peer_ack_lock_miss_cycles;

	/**
	 * @peer_ack_lock_misses: total number of times that Homa had to wait
	 * to acquire the lock used for managing acks for a peer.
	 */
	u64 peer_ack_lock_misses;

	/**
	 * @grant_lock_miss_cycles: total time spent waiting for grant lock
	 * misses.
	 */
	u64 grant_lock_miss_cycles;

	/**
	 * @grant_lock_misses: total number of times that Homa had to wait
	 * to acquire the grant lock.
	 */
	u64 grant_lock_misses;

	/**
	 * @grantable_rpcs_integral: cumulative sum of time_delta*grantable,
	 * where time_delta is in nanoseconds and grantable is the value of
	 * homa->num_grantable_rpcs over that time period.
	 */
	u64 grantable_rpcs_integral;

	/**
	 * @grant_check_calls: cumulative number of times homa_grant_check_rpc
	 * has been invoked.
	 */
	u64 grant_check_calls;

	/**
	 * @grant_check_slow_path: cumulative number of times
	 * homa_grant_check_rpc acquired the grant lock.
	 */
	u64 grant_check_slow_path;

	/**
	 * @grant_priority_bumps: cumulative number of times the grant priority
	 * of an RPC has increased above its next-higher-priority neighbor.
	 */
	u64 grant_priority_bumps;

	/**
	 * @fifo_grants: total number of times that grants were sent to
	 * the oldest message.
	 */
	u64 fifo_grants;

	/**
	 * @fifo_grants_no_incoming: total number of times that, when a
	 * FIFO grant was issued, the message had no outstanding grants
	 * (everything granted had been received).
	 */
	u64 fifo_grants_no_incoming;

	/**
	 * @disabled_reaps: total number of times that the reaper couldn't
	 * run at all because it was disabled.
	 */
	u64 disabled_reaps;

	/**
	 * @deferred_rpc_reaps: total number of times that the reaper skipped
	 * an RPC because it was still in use elsewhere.
	 */
	u64 deferred_rpc_reaps;

	/**
	 * @reaper_calls: total number of times that the reaper was invoked
	 * and was not disabled.
	 */
	u64 reaper_calls;

	/**
	 * @reaper_dead_skbs: incremented by hsk->dead_skbs each time that
	 * reaper_calls is incremented.
	 */
	u64 reaper_dead_skbs;

	/**
	 * @forced_reaps: total number of times that homa_wait_for_message
	 * invoked the reaper because dead_skbs was too high.
	 */
	u64 forced_reaps;

	/**
	 * @throttle_list_adds: total number of calls to homa_add_to_throttled.
	 */
	u64 throttle_list_adds;

	/**
	 * @throttle_list_checks: number of list elements examined in
	 * calls to homa_add_to_throttled.
	 */
	u64 throttle_list_checks;

	/**
	 * @ack_overflows: total number of times that homa_peer_add_ack
	 * found insufficient space for the new id and hence had to send an
	 * ACK message.
	 */
	u64 ack_overflows;

	/**
	 * @ignored_need_acks: total number of times that a NEED_ACK packet
	 * was ignored because the RPC's result hadn't been fully received.
	 */
	u64 ignored_need_acks;

	/**
	 * @bpage_reuses: total number of times that, when an owned page
	 * reached the end, it could be reused because all existing
	 * allocations had been released.
	 */
	u64 bpage_reuses;

	/**
	 * @buffer_alloc_failures: total number of times that
	 * homa_pool_alloc_msg was unable to allocate buffer space for
	 * an incoming message.
	 */
	u64 buffer_alloc_failures;

	/**
	 * @linux_pkt_alloc_bytes: total bytes allocated in new packet buffers
	 * by the NIC driver because of packet cache underflows.
	 */
	u64 linux_pkt_alloc_bytes;

	/**
	 * @dropped_data_no_bufs: total bytes of incoming data dropped because
	 * there was no application buffer space available.
	 */
	u64 dropped_data_no_bufs;

	/**
	 * @gen3_handoffs: total number of handoffs from GRO to SoftIRQ made
	 * by Gen3 load balancer.
	 */
	u64 gen3_handoffs;

	/**
	 * @gen3_alt_handoffs: total number of GRO->SoftIRQ handoffs that
	 * didn't choose the primary SoftIRQ core because it was busy with
	 * app threads.
	 */
	u64 gen3_alt_handoffs;

	/**
	 * @gro_grant_bypasses: total number of GRANT packets passed directly
	 * to homa_softirq by homa_gro_receive, bypassing the normal SoftIRQ
	 * mechanism (triggered by HOMA_GRO_FAST_GRANTS).
	 */
	u64 gro_grant_bypasses;

	/**
	 * @gro_data_bypasses: total number of DATA packets passed directly
	 * to homa_softirq by homa_gro_receive, bypassing the normal SoftIRQ
	 * mechanism (triggered by HOMA_GRO_SHORT_BYPASS).
	 */
	u64 gro_data_bypasses;

	/** @temp: For temporary use during testing. */
#define NUM_TEMP_METRICS 10
	u64 temp[NUM_TEMP_METRICS];
};

DECLARE_PER_CPU(struct homa_metrics, homa_metrics);

/**
 * struct homa_metrics_output - Holds global information used to export metrics
 * information through a file in /proc.
 */
struct homa_metrics_output {
	/**
	 * @mutex: Used to synchronize accesses to @active_opens
	 * and updates to @output.
	 */
	struct mutex mutex;

	/**
	 * @output: a human-readable string containing recent values
	 * for all the Homa performance metrics, as generated by
	 * homa_append_metric. This string is kmalloc-ed; NULL means
	 * homa_append_metric has never been called.
	 */
	char *output;

	/** @capacity: number of bytes available at @output. */
	size_t capacity;

	/**
	 * @length: current length of the string in @output, not including
	 * terminating NULL character.
	 */
	size_t length;

	/**
	 * @active_opens: number of open struct files that currently exist
	 * for the metrics file in /proc.
	 */
	int active_opens;

	/**
	 * @dir_entry: Used to remove /proc/net/homa_metrics when the
	 * module is unloaded.
	 */
	struct proc_dir_entry *dir_entry;
};

/**
 * homa_metrics_per_cpu() - Return the metrics structure for the current core.
 * This is unsynchronized and doesn't guarantee non-preemption.
 * Return: see above
 */
static inline struct homa_metrics *homa_metrics_per_cpu(void)
{
	return &per_cpu(homa_metrics, raw_smp_processor_id());
}

/* It isn't necessary to disable preemption here, because we don't need
 * perfect synchronization: if the invoking thread is moved to a
 * different core and races with an INC_METRIC there, the worst that
 * happens is that one of the INC_METRICs is lost, which isn't a big deal.
 */
#define INC_METRIC(metric, count) (per_cpu(homa_metrics, \
		raw_smp_processor_id()).metric += (count))

extern struct homa_metrics_output homa_mout;

void     homa_metric_append(const char *format, ...);
void     homa_metrics_end(void);
int      homa_metrics_init(void);
loff_t   homa_metrics_lseek(struct file *file, loff_t offset,
			    int whence);
int      homa_metrics_open(struct inode *inode, struct file *file);
char    *homa_metrics_print(void);
ssize_t  homa_metrics_read(struct file *file, char __user *buffer,
			   size_t length, loff_t *offset);
int      homa_metrics_release(struct inode *inode, struct file *file);
int      homa_proc_read_metrics(char *buffer, char **start, off_t offset,
				int count, int *eof, void *data);

#endif /* _HOMA_METRICS_H */
