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
	u64 packets_sent[BOGUS - DATA];

	/**
	 * @packets_received: total number of packets received for each
	 * packet type (entry 0 corresponds to DATA, and so on).
	 */
	u64 packets_received[BOGUS - DATA];

	/** @priority_bytes: total bytes sent at each priority level. */
	u64 priority_bytes[HOMA_MAX_PRIORITIES];

	/** @priority_packets: total packets sent at each priority level. */
	u64 priority_packets[HOMA_MAX_PRIORITIES];

	/**
	 * @skb_allocs: total number of calls to homa_skb_new_tx.
	 */
	u64 skb_allocs;

	/** @skb_alloc_ns: total time spent in homa_skb_new_tx. */
	u64 skb_alloc_ns;

	/**
	 * @skb_frees: total number of sk_buffs for data packets that have
	 * been freed (counts normal paths only).
	 */
	u64 skb_frees;

	/** @skb_free_ns: total time spent freeing sk_buffs. */
	u64 skb_free_ns;

	/**
	 * @skb_page_allocs: total number of calls to homa_skb_page_alloc.
	 */
	u64 skb_page_allocs;

	/** @skb_page_alloc_ns: total time spent in homa_skb_page_alloc. */
	u64 skb_page_alloc_ns;

	/**
	 * @requests_received: total number of request messages received.
	 */
	u64 requests_received;

	/**
	 * @requests_queued: total number of requests that were added to
	 * @homa->ready_requests (no thread was waiting).
	 */
	u64 requests_queued;

	/**
	 * @responses_received: total number of response messages received.
	 */
	u64 responses_received;

	/**
	 * @responses_queued: total number of responses that were added to
	 * @homa->ready_responses (no thread was waiting).
	 */
	u64 responses_queued;

	/**
	 * @fast_wakeups: total number of times that a message arrived for
	 * a receiving thread that was polling in homa_wait_for_message.
	 */
	u64 fast_wakeups;

	/**
	 * @slow_wakeups: total number of times that a receiving thread
	 * had to be put to sleep (no message arrived while it was polling).
	 */
	u64 slow_wakeups;

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
	 * @poll_ns: total time spent in the polling loop in
	 * homa_wait_for_message.
	 */
	u64 poll_ns;

	/**
	 * @softirq_calls: total number of calls to homa_softirq (i.e.,
	 * total number of GRO packets processed, each of which could contain
	 * multiple Homa packets.
	 */
	u64 softirq_calls;

	/**
	 * @softirq_ns: total time spent executing homa_softirq when
	 * invoked under Linux's SoftIRQ handler.
	 */
	u64 softirq_ns;

	/**
	 * @bypass_softirq_ns: total time spent executing homa_softirq when
	 * invoked during GRO, bypassing the SoftIRQ mechanism.
	 */
	u64 bypass_softirq_ns;

	/**
	 * @linux_softirq_ns: total time spent executing all softirq
	 * activities, as measured by the linux softirq module. Only
	 * available with modified Linux kernels.
	 */
	u64 linux_softirq_ns;

	/**
	 * @napi_ns: total time spent executing all NAPI activities, as
	 * measured by the linux softirq module. Only available with modified
	 * Linux kernels.
	 */
	u64 napi_ns;

	/**
	 * @send_ns: total time spent executing the homa_sendmsg kernel
	 * call handler to send requests.
	 */
	u64 send_ns;

	/**
	 * @send_calls: total number of invocations of homa_semdmsg
	 * for requests.
	 */
	u64 send_calls;

	/**
	 * @recv_ns: total time spent executing homa_recvmsg (including
	 * time when the thread is blocked).
	 */
	u64 recv_ns;

	/** @recv_calls: total number of invocations of homa_recvmsg. */
	u64 recv_calls;

	/**
	 * @blocked_ns: total time spent by threads in blocked state
	 * while executing the homa_recvmsg kernel call handler.
	 */
	u64 blocked_ns;

	/**
	 * @reply_ns: total time spent executing the homa_sendmsg kernel
	 * call handler to send responses.
	 */
	u64 reply_ns;

	/**
	 * @reply_calls: total number of invocations of homa_semdmsg
	 * for responses.
	 */
	u64 reply_calls;

	/**
	 * @abort_ns: total time spent executing the homa_ioc_abort
	 * kernel call handler.
	 */
	u64 abort_ns;

	/**
	 * @abort_calls: total number of invocations of the homa_ioc_abort
	 * kernel call.
	 */
	u64 abort_calls;

	/**
	 * @so_set_buf_ns: total time spent executing the homa_ioc_set_buf
	 * kernel call handler.
	 */
	u64 so_set_buf_ns;

	/**
	 * @so_set_buf_calls: total number of invocations of the homa_ioc_set_buf
	 * kernel call.
	 */
	u64 so_set_buf_calls;

	/**
	 * @grantable_lock_ns: total time spent with homa->grantable_lock
	 * locked.
	 */
	u64 grantable_lock_ns;

	/** @timer_ns: total time spent in homa_timer. */
	u64 timer_ns;

	/**
	 * @timer_reap_ns: total time spent by homa_timer to reap dead
	 * RPCs. This time is included in @timer_ns.
	 */
	u64 timer_reap_ns;

	/**
	 * @data_pkt_reap_ns: total time spent by homa_data_pkt to reap
	 * dead RPCs.
	 */
	u64 data_pkt_reap_ns;

	/**
	 * @pacer_ns: total time spent executing in homa_pacer_main
	 * (not including blocked time).
	 */
	u64 pacer_ns;

	/**
	 * @pacer_lost_ns: unnecessary delays in transmitting packets
	 * (i.e. wasted output bandwidth) because the pacer was slow or got
	 * descheduled.
	 */
	u64 pacer_lost_ns;

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
	 * @throttled_ns: total amount of time that @homa->throttled_rpcs
	 * is nonempty.
	 */
	u64 throttled_ns;

	/**
	 * @resent_packets: total number of data packets issued in response to
	 * RESEND packets.
	 */
	u64 resent_packets;

	/**
	 * @peer_hash_links: total # of link traversals in homa_peer_find.
	 */
	u64 peer_hash_links;

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
	 * @client_lock_miss_ns: total time spent waiting for client
	 * bucket lock misses.
	 */
	u64 client_lock_miss_ns;

	/**
	 * @server_lock_misses: total number of times that Homa had to wait
	 * to acquire a server bucket lock.
	 */
	u64 server_lock_misses;

	/**
	 * @server_lock_miss_ns: total time spent waiting for server
	 * bucket lock misses.
	 */
	u64 server_lock_miss_ns;

	/**
	 * @socket_lock_miss_ns: total time spent waiting for socket
	 * lock misses.
	 */
	u64 socket_lock_miss_ns;

	/**
	 * @socket_lock_misses: total number of times that Homa had to wait
	 * to acquire a socket lock.
	 */
	u64 socket_lock_misses;

	/**
	 * @throttle_lock_miss_ns: total time spent waiting for throttle
	 * lock misses.
	 */
	u64 throttle_lock_miss_ns;

	/**
	 * @throttle_lock_misses: total number of times that Homa had to wait
	 * to acquire the throttle lock.
	 */
	u64 throttle_lock_misses;

	/**
	 * @peer_ack_lock_miss_ns: total time spent waiting for peer lock misses.
	 */
	u64 peer_ack_lock_miss_ns;

	/**
	 * @peer_ack_lock_misses: total number of times that Homa had to wait
	 * to acquire the lock used for managing acks for a peer.
	 */
	u64 peer_ack_lock_misses;

	/**
	 * @grantable_lock_miss_ns: total time spent waiting for grantable
	 * lock misses.
	 */
	u64 grantable_lock_miss_ns;

	/**
	 * @grantable_lock_misses: total number of times that Homa had to wait
	 * to acquire the grantable lock.
	 */
	u64 grantable_lock_misses;

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
	 * @grant_recalc_calls: cumulative number of times homa_grant_recalc
	 * has been invoked.
	 */
	u64 grant_recalc_calls;

	/** @grant_recalc_ns: total time spent in homa_grant_recalc. */
	u64 grant_recalc_ns;

	/**
	 * @grant_recalc_loops: cumulative number of times homa_grant_recalc
	 * has looped back to recalculate again.
	 */
	u64 grant_recalc_loops;

	/**
	 * @grant_recalc_skips: cumulative number of times that
	 * homa_grant_recalc skipped its work because in other thread
	 * already did it.
	 */
	u64 grant_recalc_skips;

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
	 * @disabled_rpc_reaps: total number of times that the reaper skipped
	 * an RPC because reaping was disabled for that particular RPC
	 */
	u64 disabled_rpc_reaps;

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
	 * homa_pool_allocate was unable to allocate buffer space for
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
#define INC_METRIC(metric, count) per_cpu(homa_metrics, \
		raw_smp_processor_id()).metric += (count)

void     homa_metric_append(struct homa *homa, const char *format, ...);
loff_t   homa_metrics_lseek(struct file *file, loff_t offset,
			    int whence);
int      homa_metrics_open(struct inode *inode, struct file *file);
char    *homa_metrics_print(struct homa *homa);
ssize_t  homa_metrics_read(struct file *file, char __user *buffer,
			   size_t length, loff_t *offset);
int      homa_metrics_release(struct inode *inode, struct file *file);
int      homa_proc_read_metrics(char *buffer, char **start, off_t offset,
				int count, int *eof, void *data);

#endif /* _HOMA_METRICS_H */
