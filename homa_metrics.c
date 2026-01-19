// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

/* This file contains various functions for managing Homa's performance
 * counters.
 */

#include "homa_impl.h"

DEFINE_PER_CPU(struct homa_metrics, homa_metrics);

/* Describes file operations implemented for /proc/net/homa_metrics. */
static const struct proc_ops homa_metrics_ops = {
	.proc_open         = homa_metrics_open,
	.proc_read         = homa_metrics_read,
	.proc_lseek        = homa_metrics_lseek,
	.proc_release      = homa_metrics_release,
};

/* Global information used to export metrics information through a file in
 * /proc.
 */
struct homa_metrics_output homa_mout;

/**
 * homa_metrics_init() - Initialize global information related to metrics.
 * Return:  0 for success, otherwise a negative errno.
 */
int homa_metrics_init(void)
{
	mutex_init(&homa_mout.mutex);
	homa_mout.output = NULL;
	homa_mout.dir_entry = proc_create("homa_metrics", 0444,
					  init_net.proc_net,
					  &homa_metrics_ops);
	if (!homa_mout.dir_entry) {
		pr_err("couldn't create /proc/net/homa_metrics\n");
		return -ENOMEM;
	}
	return 0;
}

/**
 * homa_metrics_end() - Called to clean up metrics information when the
 * Homa module unloads.
 */
void homa_metrics_end(void)
{
	if (homa_mout.dir_entry)
		proc_remove(homa_mout.dir_entry);
	homa_mout.dir_entry = NULL;
	kfree(homa_mout.output);
	homa_mout.output = NULL;
}

/**
 * homa_metric_append() - Format a metric and append it to homa_mout.output.
 * @name:        Name of the metric
 * @value:       Value of the metric
 * @format:      Standard printf-style format string providing a human-
 *               readable description of the metric. Arguments after this
 *               provide the usual values expected for printf-like functions,
 *               if needed.
 */
void homa_metric_append(const char *name, u64 value, const char *format, ...)
{
	char *new_buffer;
	size_t new_chars;
	va_list ap;

	if (!homa_mout.output) {
#ifdef __UNIT_TEST__
		homa_mout.capacity =  200;
#else
		homa_mout.capacity =  4096;
#endif
		homa_mout.output =  kmalloc(homa_mout.capacity, GFP_KERNEL);
		if (!homa_mout.output)
			return;
		homa_mout.length = 0;
	}

	while (homa_mout.capacity < homa_mout.length + 200) {
		/* Not enough room; expand buffer capacity. */
		homa_mout.capacity *= 2;
		new_buffer = kmalloc(homa_mout.capacity, GFP_KERNEL);
		if (!new_buffer)
			return;
		memcpy(new_buffer, homa_mout.output, homa_mout.length);
		kfree(homa_mout.output);
		homa_mout.output = new_buffer;
	}

	new_chars = snprintf(homa_mout.output + homa_mout.length, 60,
			     "%-30s %20llu ", name, value);
	homa_mout.length += (new_chars > 60) ? 60 : new_chars;
	va_start(ap, format);
	new_chars = vsnprintf(homa_mout.output + homa_mout.length, 120,
			      format, ap);
	va_end(ap);
	homa_mout.length += (new_chars > 120) ? 120 : new_chars;
}

/**
 * homa_metrics_print() - Sample all of the Homa performance metrics and
 * generate a human-readable string describing all of them.
 *
 * Return:   The formatted string.
 */
char *homa_metrics_print(void)
{
	int core, i, lower = 0;
	char name[30];

	homa_mout.length = 0;
#define M(...) homa_metric_append(__VA_ARGS__)
	M("time_cycles", homa_clock(),
	  "homa_clock() time when metrics were gathered\n");
	M("cpu_khz", homa_clock_khz(),
	  "Clock rate in khz\n");
	for (core = 0; core < nr_cpu_ids; core++) {
		struct homa_metrics *m = &per_cpu(homa_metrics, core);
		s64 delta;

		M("core", core,
		  "Core id for following metrics\n");
		for (i = 0; i < HOMA_NUM_SMALL_COUNTS; i++) {
			snprintf(name, sizeof(name), "msg_bytes_%d",
				 (i + 1) * 64);
			M(name, m->small_msg_bytes[i],
			  "Bytes in incoming messages containing %d-%d bytes\n",
			  lower, (i + 1) * 64);
			lower = (i + 1) * 64 + 1;
		}
		for (i = (HOMA_NUM_SMALL_COUNTS * 64) / 1024;
				i < HOMA_NUM_MEDIUM_COUNTS; i++) {
			snprintf(name, sizeof(name), "msg_bytes_%d",
				 (i + 1) * 1024);
			M(name, m->medium_msg_bytes[i],
			  "Bytes in incoming messages containing %d-%d bytes\n",
			  lower, (i + 1) * 1024);
			lower = (i + 1) * 1024 + 1;
		}
		M("large_msg_count", m->large_msg_count,
		  "# of incoming messages >= %d bytes\n", lower);
		M("large_msg_bytes", m->large_msg_bytes,
		  "Bytes in incoming messages >= %d bytes\n", lower);
		M("client_requests_started", m->client_requests_started,
		  "Client RPCs initiated\n");
		M("client_request_bytes_started",
		  m->client_request_bytes_started,
		  "Request bytes in all initiated client RPCs\n");
		M("client_request_bytes_done", m->client_request_bytes_done,
		  "Transmitted request bytes in all client RPCs\n");
		M("client_requests_done", m->client_requests_done,
		  "Client RPC requests fully transmitted\n");

		M("client_responses_started", m->client_responses_started,
		  "Client RPCs for which at least one response pkt recvd\n");
		M("client_response_bytes_started",
		  m->client_response_bytes_started,
		  "Response bytes in all RPCS in client_responses_started\n");
		M("client_response_bytes_done", m->client_response_bytes_done,
		  "Response bytes received for all client RPCs\n");
		M("client_responses_done", m->client_responses_done,
		  "Client RPC responses fully received\n");
		M("server_requests_started", m->server_requests_started,
		  "Server RPCs for which at least one request pkt rcvd\n");
		M("server_request_bytes_started",
		  m->server_request_bytes_started,
		  "Request bytes in all RPCS in server_requests_started\n");
		M("server_request_bytes_done", m->server_request_bytes_done,
		  "Request bytes received for all server RPCs\n");
		M("server_requests_done", m->server_requests_done,
		  "Server RPC requests fully received\n");
		M("server_responses_started", m->server_responses_started,
		  "Server RPCs for which response was initiated\n");
		M("server_response_bytes_started",
		  m->server_response_bytes_started,
		  "Message bytes in all initiated server responses\n");
		M("server_response_bytes_done", m->server_response_bytes_done,
		  "Transmitted response bytes in all server RPCs\n");
		M("server_responses_done", m->server_responses_done,
		  "Server RPC responses fully transmitted\n");
		M("sent_msg_bytes", m->sent_msg_bytes,
		  "Total bytes in all outgoing messages\n");
		for (i = DATA; i <= MAX_OP;  i++) {
			char *symbol = homa_symbol_for_type(i);

			snprintf(name, sizeof(name), "packets_sent_%s", symbol);
			M(name, m->packets_sent[i - DATA],
			  "%s packets sent\n", symbol);
		}
		for (i = DATA; i <= MAX_OP;  i++) {
			char *symbol = homa_symbol_for_type(i);

			snprintf(name, sizeof(name), "packets_rcvd_%s", symbol);
			M(name, m->packets_received[i - DATA],
			  "%s packets received\n", symbol);
		}
		for (i = 0; i < HOMA_MAX_PRIORITIES; i++) {
			snprintf(name, sizeof(name), "priority%d_bytes", i);
			M(name, m->priority_bytes[i],
			  "Bytes sent at priority %d (including headers)\n", i);
		}
		for (i = 0; i < HOMA_MAX_PRIORITIES; i++) {
			snprintf(name, sizeof(name), "priority%d_packets", i);
			M(name, m->priority_packets[i],
			  "Packets sent at priority %d\n", i);
		}
		M("skb_allocs", m->skb_allocs, "sk_buffs allocated\n");
		M("skb_alloc_cycles", m->skb_alloc_cycles,
		  "Time spent allocating sk_buffs\n");
		M("skb_frees", m->skb_frees,
		  "Data sk_buffs freed in normal paths\n");
		M("skb_free_cycles", m->skb_free_cycles,
		  "Time spent freeing data sk_buffs\n");
		M("skb_page_allocs", m->skb_page_allocs,
		  "Pages allocated for sk_buff frags\n");
		M("skb_page_alloc_cycles", m->skb_page_alloc_cycles,
		  "Time spent allocating pages for sk_buff frags\n");
		M("requests_received", m->requests_received,
		  "Incoming request messages\n");
		M("responses_received", m->responses_received,
		  "Incoming response messages\n");
		M("wait_none", m->wait_none,
		  "Messages received without blocking or polling\n");
		M("wait_fast", m->wait_fast,
		  "Messages received while polling\n");
		M("wait_block", m->wait_block,
		  "Messages received after thread went to sleep\n");
		M("handoffs_thread_waiting", m->handoffs_thread_waiting,
		  "RPC handoffs to waiting threads (vs. queue)\n");
		M("handoffs_alt_thread", m->handoffs_alt_thread,
		  "RPC handoffs not to first on list (avoid busy core)\n");
		M("poll_cycles", m->poll_cycles,
		  "Time spent polling for incoming messages\n");
		M("softirq_calls", m->softirq_calls,
		  "Calls to homa_softirq (i.e. # GRO pkts received)\n");
		M("softirq_cycles", m->softirq_cycles,
		  "Time spent in homa_softirq during SoftIRQ\n");
		M("bypass_softirq_cycles", m->bypass_softirq_cycles,
		  "Time spent in homa_softirq during bypass from GRO\n");

		/* Adjust stats gathered in Linux that use rdtsc. */
		M("linux_softirq_cycles", m->linux_softirq_cycles *
		  (homa_clock_khz() / 1000) / (tsc_khz / 1000),
		  "Time spent in all Linux SoftIRQ\n");
		M("napi_cycles", m->napi_cycles * (homa_clock_khz() / 1000) /
		  (tsc_khz / 1000),
		  "Time spent in NAPI-level packet handling\n");
		M("linux_softirqd_actions", m->linux_softirqd_actions,
		  "SoftIRQ actions taken in the background softirqd thread\n");
		M("send_cycles", m->send_cycles,
		  "Time spent in homa_sendmsg for requests\n");
		M("send_calls", m->send_calls,
		  "Total invocations of homa_sendmsg for requests\n");
		// It is possible for us to get here at a time when a
		// thread has been blocked for a long time and has
		// recorded blocked_cycles, but hasn't finished the
		// system call so recv_cycles hasn't been incremented
		// yet. If that happens, just record 0 to prevent
		// underflow errors.
		delta = m->recv_cycles - m->blocked_cycles;
		if (delta < 0)
			delta = 0;
		M("recv_cycles", delta,
		  "Unblocked time spent in recvmsg kernel call\n");
		M("recv_calls", m->recv_calls,
		  "Total invocations of recvmsg kernel call\n");
		M("blocked_cycles", m->blocked_cycles,
		  "Time spent blocked in homa_recvmsg\n");
		M("reply_cycles", m->reply_cycles,
		  "Time spent in homa_sendmsg for responses\n");
		M("reply_calls", m->reply_calls,
		  "Total invocations of homa_sendmsg for responses\n");
		M("abort_cycles", m->reply_cycles,
		  "Time spent in homa_ioc_abort kernel call\n");
		M("abort_calls", m->reply_calls,
		  "Total invocations of abort kernel call\n");
		M("so_set_buf_cycles", m->so_set_buf_cycles,
		  "Time spent in setsockopt SO_HOMA_RCVBUF\n");
		M("so_set_buf_calls", m->so_set_buf_calls,
		  "Total invocations of setsockopt SO_HOMA_RCVBUF\n");
		M("grant_lock_cycles", m->grant_lock_cycles,
		  "Time spent with grant lock locked\n");
		M("timer_cycles", m->timer_cycles,
		  "Time spent in homa_timer\n");
		M("timer_reap_cycles", m->timer_reap_cycles,
		  "Time in homa_timer spent reaping RPCs\n");
		M("data_pkt_reap_cycles", m->data_pkt_reap_cycles,
		  "Time in homa_data_pkt spent reaping RPCs\n");
		M("idle_time_conflicts", m->idle_time_conflicts,
		  "Cache conflicts when updating link_idle_time\n");
		M("nic_backlog_cycles", m->nic_backlog_cycles,
		  "Time when NIC queue was backlogged\n");
		M("pacer_cycles", m->pacer_cycles,
		  "Execution time in pacer thread\n");
		M("pacer_xmit_cycles", m->pacer_xmit_cycles,
		  "Time pacer spent xmitting packets (vs. polling NIC queue)\n");
		M("pacer_homa_packets", m->pacer_homa_packets,
		  "Homa packets transmitted by the pacer\n");
		M("pacer_homa_bytes", m->pacer_homa_bytes,
		  "Homa bytes transmitted by the pacer (including headers)\n");
		M("pacer_fifo_bytes", m->pacer_fifo_bytes,
		  "Homa bytes transmitted using FIFO priority (including headers)\n");
		M("pacer_tcp_packets", m->pacer_tcp_packets,
		  "TCP packets transmitted by the pacer\n");
		M("pacer_tcp_bytes", m->pacer_tcp_bytes,
		  "TCP bytes transmitted by the pacer (including headers)\n");
		M("pacer_help_bytes", m->pacer_help_bytes,
		  "Bytes transmitted via homa_qdisc_pacer_check\n");
		M("qdisc_tcp_packets", m->qdisc_tcp_packets,
		  "TCP packets processed by homa_qdisc\n");
		M("homa_cycles",
		  m->softirq_cycles + m->napi_cycles +
		  m->send_cycles + m->recv_cycles +
		  m->reply_cycles - m->blocked_cycles +
		  m->timer_cycles + m->nic_backlog_cycles,
		  "Total time in all Homa-related functions\n");
		M("resent_packets", m->resent_packets,
		  "DATA packets sent in response to RESENDs\n");
		M("peer_allocs", m->peer_allocs,
		  "New entries created in peer table\n");
		M("peer_kmalloc_errors", m->peer_kmalloc_errors,
		  "kmalloc failures creating peer table entries\n");
		M("peer_route_errors", m->peer_route_errors,
		  "Routing failures creating peer table entries\n");
		M("peer_dst_refreshes", m->peer_dst_refreshes,
		  "Obsolete dsts had to be regenerated\n");
		M("control_xmit_errors", m->control_xmit_errors,
		  "Errors sending control packets\n");
		M("data_xmit_errors", m->data_xmit_errors,
		  "Errors sending data packets\n");
		M("unknown_rpcs", m->unknown_rpcs,
		  "Non-grant packets discarded because RPC unknown\n");
		M("server_cant_create_rpcs", m->server_cant_create_rpcs,
		  "Packets discarded because server couldn't create RPC\n");
		M("unknown_packet_types", m->unknown_packet_types,
		  "Packets discarded because of unsupported type\n");
		M("short_packets", m->short_packets,
		  "Packets discarded because too short\n");
		M("packet_discards", m->packet_discards,
		  "Non-resent packets discarded because data already received\n");
		M("resent_discards", m->resent_discards,
		  "Resent packets discarded because data already received\n");
		M("resent_packets_used", m->resent_packets_used,
		  "Retransmitted packets that were actually used\n");
		M("rpc_timeouts", m->rpc_timeouts,
		  " RPCs aborted because peer was nonresponsive\n");
		M("server_rpc_discards", m->server_rpc_discards,
		  "RPCs discarded by server because of errors\n");
		M("server_rpcs_unknown", m->server_rpcs_unknown,
		  "RPCs aborted by server because unknown to client\n");
		M("client_lock_misses", m->client_lock_misses,
		  "Bucket lock misses for client RPCs\n");
		M("client_lock_miss_cycles", m->client_lock_miss_cycles,
		  "Time lost waiting for client bucket locks\n");
		M("server_lock_misses", m->server_lock_misses,
		  "Bucket lock misses for server RPCs\n");
		M("server_lock_miss_cycles", m->server_lock_miss_cycles,
		  "Time lost waiting for server bucket locks\n");
		M("socket_lock_misses", m->socket_lock_misses,
		  "Socket lock misses\n");
		M("socket_lock_miss_cycles", m->socket_lock_miss_cycles,
		  "Time lost waiting for socket locks\n");
		M("throttle_lock_misses", m->throttle_lock_misses,
		  "Throttle lock misses\n");
		M("throttle_lock_miss_cycles", m->throttle_lock_miss_cycles,
		  "Time lost waiting for throttle locks\n");
		M("peer_ack_lock_misses", m->peer_ack_lock_misses,
		  "Misses on peer ack locks\n");
		M("peer_ack_lock_miss_cycles", m->peer_ack_lock_miss_cycles,
		  "Time lost waiting for peer ack locks\n");
		M("grant_lock_misses", m->grant_lock_misses,
		  "Grant lock misses\n");
		M("grant_lock_miss_cycles", m->grant_lock_miss_cycles,
		  "Time lost waiting for grant lock\n");
		M("grantable_rpcs_integral", m->grantable_rpcs_integral,
		  "Integral of homa->num_grantable_rpcs*dt\n");
		M("grant_check_calls", m->grant_check_calls,
		  "Number of calls to homa_grant_check_rpc\n");
		M("grant_check_locked", m->grant_check_locked,
		  "Number of calls to homa_grant_check_rpc that acquired grant lock\n");
		M("grant_check_others", m->grant_check_others,
		  "Number of times homa_grant_check_rpc checked non-caller RPCs for grants\n");
		M("grant_check_recalcs", m->grant_check_recalcs,
		  "Number of times homa_grant_check_rpc updated grant priority order\n");
		M("grant_priority_bumps", m->grant_priority_bumps,
		  "Number of times an RPC moved up in the grant priority order\n");
		M("fifo_grant_bytes", m->fifo_grant_bytes,
		  "Bytes of grants issued using the FIFO mechanism\n");
		M("disabled_reaps", m->disabled_reaps,
		  "Reaper invocations that were disabled\n");
		M("deferred_rpc_reaps", m->deferred_rpc_reaps,
		  "RPCs skipped by reaper because still in use\n");
		M("reaper_calls", m->reaper_calls,
		  "Reaper invocations that were not disabled\n");
		M("reaper_dead_skbs", m->reaper_dead_skbs,
		  "Sum of hsk->dead_skbs across all reaper calls\n");
		M("reaper_active_skbs", m->reaper_active_skbs,
		  "RPCs skipped by reaper because of active tx skbs\n");
		M("throttle_list_adds", m->throttle_list_adds,
		  "Calls to homa_add_to_throttled\n");
		M("throttle_list_checks", m->throttle_list_checks,
		  "List elements checked in homa_add_to_throttled\n");
		M("ack_overflows", m->ack_overflows,
		  "Explicit ACKs sent because peer->acks was full\n");
		M("ignored_need_acks", m->ignored_need_acks,
		  "NEED_ACKs ignored because RPC result not yet received\n");
		M("bpage_reuses", m->bpage_reuses,
		  "Buffer page could be reused because ref count was zero\n");
		M("buffer_alloc_failures", m->buffer_alloc_failures,
		  "homa_pool_alloc_msg didn't find enough buffer space for an RPC\n");
		M("linux_pkt_alloc_bytes", m->linux_pkt_alloc_bytes,
		  "Bytes allocated for rx packets by NIC driver due to cache overflows\n");
		M("dropped_data_no_bufs", m->dropped_data_no_bufs,
		  "Data bytes dropped because app buffers full\n");
		M("gen3_handoffs", m->gen3_handoffs,
		  "GRO->SoftIRQ handoffs made by Gen3 balancer\n");
		M("gen3_alt_handoffs", m->gen3_alt_handoffs,
		  "Gen3 handoffs to secondary core (primary was busy)\n");
		M("gro_grant_bypasses", m->gro_grant_bypasses,
		  "Grant packets passed directly to homa_softirq by homa_gro_receive\n");
		M("gro_data_bypasses", m->gro_data_bypasses,
		  "Data packets passed directly to homa_softirq by homa_gro_receive\n");
		for (i = 0; i < NUM_TEMP_METRICS;  i++) {
			snprintf(name, sizeof(name), "temp%d", i);
			M(name, m->temp[i], "Temporary use in testing\n");
		}
	}

	return homa_mout.output;
}

/**
 * homa_metrics_open() - This function is invoked when /proc/net/homa_metrics is
 * opened.
 * @inode:    The inode corresponding to the file.
 * @file:     Information about the open file.
 *
 * Return: always 0.
 */
int homa_metrics_open(struct inode *inode, struct file *file)
{
	/* Collect all of the metrics when the file is opened, and save
	 * these for use by subsequent reads (don't want the metrics to
	 * change between reads). If there are concurrent opens on the
	 * file, only read the metrics once, during the first open, and
	 * use this copy for subsequent opens, until the file has been
	 * completely closed.
	 */
	mutex_lock(&homa_mout.mutex);
	if (homa_mout.active_opens == 0)
		homa_metrics_print();
	homa_mout.active_opens++;
	mutex_unlock(&homa_mout.mutex);
	return 0;
}

/**
 * homa_metrics_read() - This function is invoked to handle read kernel calls on
 * /proc/net/homa_homa_mout.
 * @file:    Information about the file being read.
 * @buffer:  Address in user space of the buffer in which data from the file
 *           should be returned.
 * @length:  Number of bytes available at @buffer.
 * @offset:  Current read offset within the file.
 *
 * Return: the number of bytes returned at @buffer. 0 means the end of the
 * file was reached, and a negative number indicates an error (-errno).
 */
ssize_t homa_metrics_read(struct file *file, char __user *buffer,
			  size_t length, loff_t *offset)
{
	size_t copied;

	if (*offset >= homa_mout.length)
		return 0;
	copied = homa_mout.length - *offset;
	if (copied > length)
		copied = length;
	if (copy_to_user(buffer, homa_mout.output + *offset, copied))
		return -EFAULT;
	*offset += copied;
	return copied;
}

/**
 * homa_metrics_lseek() - This function is invoked to handle seeks on
 * /proc/net/homa_homa_mout. Right now seeks are ignored: the file must be
 * read sequentially.
 * @file:    Information about the file being read.
 * @offset:  Distance to seek, in bytes
 * @whence:  Starting point from which to measure the distance to seek.
 * Return: current position within file.
 */
loff_t homa_metrics_lseek(struct file *file, loff_t offset, int whence)
{
	return 0;
}

/**
 * homa_metrics_release() - This function is invoked when the last reference to
 * an open /proc/net/homa_metrics is closed.  It performs cleanup.
 * @inode:    The inode corresponding to the file.
 * @file:     Information about the open file.
 *
 * Return: always 0.
 */
int homa_metrics_release(struct inode *inode, struct file *file)
{
	mutex_lock(&homa_mout.mutex);
	homa_mout.active_opens--;
	mutex_unlock(&homa_mout.mutex);
	return 0;
}
