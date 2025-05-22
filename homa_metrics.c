// SPDX-License-Identifier: BSD-2-Clause

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
 * homa_metric_append() - Formats a new metric and appends it to
 * homa_mout.output.
 * @format:      Standard printf-style format string describing the
 *               new metric. Arguments after this provide the usual
 *               values expected for printf-like functions.
 */
void homa_metric_append(const char *format, ...)
{
	char *new_buffer;
	size_t new_chars;
	va_list ap;

	if (!homa_mout.output) {
#ifdef __UNIT_TEST__
		homa_mout.capacity =  30;
#else
		homa_mout.capacity =  4096;
#endif
		homa_mout.output =  kmalloc(homa_mout.capacity, GFP_KERNEL);
		if (!homa_mout.output)
			return;
		homa_mout.length = 0;
	}

	/* May have to execute this loop multiple times if we run out
	 * of space in homa_mout.output; each iteration expands the storage,
	 * until eventually it is large enough.
	 */
	while (true) {
		va_start(ap, format);
		new_chars = vsnprintf(homa_mout.output + homa_mout.length,
				      homa_mout.capacity -
				      homa_mout.length, format, ap);
		va_end(ap);
		if ((homa_mout.length + new_chars) < homa_mout.capacity)
			break;

		/* Not enough room; expand buffer capacity. */
		homa_mout.capacity *= 2;
		new_buffer = kmalloc(homa_mout.capacity, GFP_KERNEL);
		if (!new_buffer) {
			pr_warn("%s couldn't allocate memory\n", __func__);
			return;
		}
		memcpy(new_buffer, homa_mout.output, homa_mout.length);
		kfree(homa_mout.output);
		homa_mout.output = new_buffer;
	}
	homa_mout.length += new_chars;
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

	homa_mout.length = 0;
#define M(...) homa_metric_append(__VA_ARGS__)
	M("time_cycles          %20llu  homa_clock() time when metrics were gathered\n",
	  homa_clock());
	M("cpu_khz                   %15llu  Clock rate in khz\n",
	  homa_clock_khz());
	for (core = 0; core < nr_cpu_ids; core++) {
		struct homa_metrics *m = &per_cpu(homa_metrics, core);
		s64 delta;

		M("core                      %15d  Core id for following metrics\n",
		  core);
		for (i = 0; i < HOMA_NUM_SMALL_COUNTS; i++) {
			M("msg_bytes_%-9d       %15llu  Bytes in incoming messages containing %d-%d bytes\n",
			  (i + 1) * 64, m->small_msg_bytes[i], lower,
			  (i + 1) * 64);
			lower = (i + 1) * 64 + 1;
		}
		for (i = (HOMA_NUM_SMALL_COUNTS * 64) / 1024;
				i < HOMA_NUM_MEDIUM_COUNTS; i++) {
			M("msg_bytes_%-9d       %15llu  Bytes in incoming messages containing %d-%d bytes\n",
			  (i + 1) * 1024, m->medium_msg_bytes[i], lower,
			  (i + 1) * 1024);
			lower = (i + 1) * 1024 + 1;
		}
		M("large_msg_count           %15llu  # of incoming messages >= %d bytes\n",
		  m->large_msg_count, lower);
		M("large_msg_bytes           %15llu  Bytes in incoming messages >= %d bytes\n",
		  m->large_msg_bytes, lower);
		M("sent_msg_bytes            %15llu  Total bytes in all outgoing messages\n",
		  m->sent_msg_bytes);
		for (i = DATA; i <= MAX_OP;  i++) {
			char *symbol = homa_symbol_for_type(i);

			M("packets_sent_%-7s      %15llu  %s packets sent\n",
			  symbol, m->packets_sent[i - DATA], symbol);
		}
		for (i = DATA; i <= MAX_OP;  i++) {
			char *symbol = homa_symbol_for_type(i);

			M("packets_rcvd_%-7s      %15llu  %s packets received\n",
			  symbol, m->packets_received[i - DATA], symbol);
		}
		for (i = 0; i < HOMA_MAX_PRIORITIES; i++) {
			M("priority%d_bytes        %15llu  Bytes sent at priority %d (including headers)\n",
			  i, m->priority_bytes[i], i);
		}
		for (i = 0; i < HOMA_MAX_PRIORITIES; i++) {
			M("priority%d_packets      %15llu  Packets sent at priority %d\n",
			  i, m->priority_packets[i], i);
		}
		M("skb_allocs                %15llu  sk_buffs allocated\n",
		  m->skb_allocs);
		M("skb_alloc_cycles          %15llu  Time spent allocating sk_buffs\n",
		  m->skb_alloc_cycles);
		M("skb_frees                 %15llu  Data sk_buffs freed in normal paths\n",
		  m->skb_frees);
		M("skb_free_cycles           %15llu  Time spent freeing data sk_buffs\n",
		  m->skb_free_cycles);
		M("skb_page_allocs           %15llu  Pages allocated for sk_buff frags\n",
		  m->skb_page_allocs);
		M("skb_page_alloc_cycles     %15llu  Time spent allocating pages for sk_buff frags\n",
		  m->skb_page_alloc_cycles);
		M("requests_received         %15llu  Incoming request messages\n",
		  m->requests_received);
		M("responses_received        %15llu  Incoming response messages\n",
		  m->responses_received);
		M("wait_none                 %15llu  Messages received without blocking or polling\n",
		  m->wait_none);
		M("wait_fast                 %15llu  Messages received while polling\n",
		  m->wait_fast);
		M("wait_block                %15llu  Messages received after thread went to sleep\n",
		  m->wait_block);
		M("handoffs_thread_waiting   %15llu  RPC handoffs to waiting threads (vs. queue)\n",
		  m->handoffs_thread_waiting);
		M("handoffs_alt_thread       %15llu  RPC handoffs not to first on list (avoid busy core)\n",
		  m->handoffs_alt_thread);
		M("poll_cycles               %15llu  Time spent polling for incoming messages\n",
		  m->poll_cycles);
		M("softirq_calls             %15llu  Calls to homa_softirq (i.e. # GRO pkts received)\n",
		  m->softirq_calls);
		M("softirq_cycles            %15llu  Time spent in homa_softirq during SoftIRQ\n",
		  m->softirq_cycles);
		M("bypass_softirq_cycles     %15llu  Time spent in homa_softirq during bypass from GRO\n",
		  m->bypass_softirq_cycles);
		M("linux_softirq_cycles      %15llu  Time spent in all Linux SoftIRQ\n",
		  m->linux_softirq_cycles);
		M("napi_cycles               %15llu  Time spent in NAPI-level packet handling\n",
		  m->napi_cycles);
		M("send_cycles               %15llu  Time spent in homa_sendmsg for requests\n",
		  m->send_cycles);
		M("send_calls                %15llu  Total invocations of homa_sendmsg for equests\n",
		  m->send_calls);
		// It is possible for us to get here at a time when a
		// thread has been blocked for a long time and has
		// recorded blocked_cycles, but hasn't finished the
		// system call so recv_cycles hasn't been incremented
		// yet. If that happens, just record 0 to prevent
		// underflow errors.
		delta = m->recv_cycles - m->blocked_cycles;
		if (delta < 0)
			delta = 0;
		M("recv_cycles               %15llu  Unblocked time spent in recvmsg kernel call\n",
		  delta);
		M("recv_calls                %15llu  Total invocations of recvmsg kernel call\n",
		  m->recv_calls);
		M("blocked_cycles            %15llu  Time spent blocked in homa_recvmsg\n",
		  m->blocked_cycles);
		M("reply_cycles              %15llu  Time spent in homa_sendmsg for responses\n",
		  m->reply_cycles);
		M("reply_calls               %15llu  Total invocations of homa_sendmsg for responses\n",
		  m->reply_calls);
		M("abort_cycles              %15llu  Time spent in homa_ioc_abort kernel call\n",
		  m->reply_cycles);
		M("abort_calls               %15llu  Total invocations of abort kernel call\n",
		  m->reply_calls);
		M("so_set_buf_cycles         %15llu  Time spent in setsockopt SO_HOMA_RCVBUF\n",
		  m->so_set_buf_cycles);
		M("so_set_buf_calls          %15llu  Total invocations of setsockopt SO_HOMA_RCVBUF\n",
		  m->so_set_buf_calls);
		M("grant_lock_cycles         %15llu  Time spent with grant lock locked\n",
		  m->grant_lock_cycles);
		M("timer_cycles              %15llu  Time spent in homa_timer\n",
		  m->timer_cycles);
		M("timer_reap_cycles         %15llu  Time in homa_timer spent reaping RPCs\n",
		  m->timer_reap_cycles);
		M("data_pkt_reap_cycles      %15llu  Time in homa_data_pkt spent reaping RPCs\n",
		  m->data_pkt_reap_cycles);
		M("pacer_cycles              %15llu  Time spent in homa_pacer_main\n",
		  m->pacer_cycles);
		M("homa_cycles               %15llu  Total time in all Homa-related functions\n",
		  m->softirq_cycles + m->napi_cycles +
		  m->send_cycles + m->recv_cycles +
		  m->reply_cycles - m->blocked_cycles +
		  m->timer_cycles + m->pacer_cycles);
		M("pacer_lost_cycles         %15llu  Lost transmission time because pacer was slow\n",
		  m->pacer_lost_cycles);
		M("pacer_bytes               %15llu  Bytes transmitted when the pacer was active\n",
		  m->pacer_bytes);
		M("pacer_skipped_rpcs        %15llu  Pacer aborts because of locked RPCs\n",
		  m->pacer_skipped_rpcs);
		M("pacer_needed_help         %15llu  homa_pacer_xmit invocations from homa_check_pacer\n",
		  m->pacer_needed_help);
		M("throttled_cycles          %15llu  Time when the throttled queue was nonempty\n",
		  m->throttled_cycles);
		M("resent_packets            %15llu  DATA packets sent in response to RESENDs\n",
		  m->resent_packets);
		M("peer_allocs               %15llu  New entries created in peer table\n",
		  m->peer_allocs);
		M("peer_kmalloc_errors       %15llu  kmalloc failures creating peer table entries\n",
		  m->peer_kmalloc_errors);
		M("peer_route_errors         %15llu  Routing failures creating peer table entries\n",
		  m->peer_route_errors);
		M("peer_dst_refreshes        %15llu  Obsolete dsts had to be regenerated\n",
		  m->peer_dst_refreshes);
		M("control_xmit_errors       %15llu  Errors sending control packets\n",
		  m->control_xmit_errors);
		M("data_xmit_errors          %15llu  Errors sending data packets\n",
		  m->data_xmit_errors);
		M("unknown_rpcs              %15llu  Non-grant packets discarded because RPC unknown\n",
		  m->unknown_rpcs);
		M("server_cant_create_rpcs   %15llu  Packets discarded because server couldn't create RPC\n",
		  m->server_cant_create_rpcs);
		M("unknown_packet_types      %15llu  Packets discarded because of unsupported type\n",
		  m->unknown_packet_types);
		M("short_packets             %15llu  Packets discarded because too short\n",
		  m->short_packets);
		M("packet_discards           %15llu  Non-resent packets discarded because data already received\n",
		  m->packet_discards);
		M("resent_discards           %15llu  Resent packets discarded because data already received\n",
		  m->resent_discards);
		M("resent_packets_used       %15llu  Retransmitted packets that were actually used\n",
		  m->resent_packets_used);
		M("rpc_timeouts             %15llu   RPCs aborted because peer was nonresponsive\n",
		  m->rpc_timeouts);
		M("server_rpc_discards       %15llu  RPCs discarded by server because of errors\n",
		  m->server_rpc_discards);
		M("server_rpcs_unknown       %15llu  RPCs aborted by server because unknown to client\n",
		  m->server_rpcs_unknown);
		M("client_lock_misses        %15llu  Bucket lock misses for client RPCs\n",
		  m->client_lock_misses);
		M("client_lock_miss_cycles   %15llu  Time lost waiting for client bucket locks\n",
		  m->client_lock_miss_cycles);
		M("server_lock_misses        %15llu  Bucket lock misses for server RPCs\n",
		  m->server_lock_misses);
		M("server_lock_miss_cycles   %15llu  Time lost waiting for server bucket locks\n",
		  m->server_lock_miss_cycles);
		M("socket_lock_misses        %15llu  Socket lock misses\n",
		  m->socket_lock_misses);
		M("socket_lock_miss_cycles   %15llu  Time lost waiting for socket locks\n",
		  m->socket_lock_miss_cycles);
		M("throttle_lock_misses      %15llu  Throttle lock misses\n",
		  m->throttle_lock_misses);
		M("throttle_lock_miss_cycles %15llu  Time lost waiting for throttle locks\n",
		  m->throttle_lock_miss_cycles);
		M("peer_ack_lock_misses      %15llu  Misses on peer ack locks\n",
		  m->peer_ack_lock_misses);
		M("peer_ack_lock_miss_cycles %15llu  Time lost waiting for peer ack locks\n",
		  m->peer_ack_lock_miss_cycles);
		M("grant_lock_misses         %15llu  Grant lock misses\n",
		  m->grant_lock_misses);
		M("grant_lock_miss_cycles    %15llu  Time lost waiting for grant lock\n",
		  m->grant_lock_miss_cycles);
		M("grantable_rpcs_integral   %15llu  Integral of homa->num_grantable_rpcs*dt\n",
		  m->grantable_rpcs_integral);
		M("grant_check_calls         %15llu  Number of calls to homa_grant_check_rpc\n",
		  m->grant_check_calls);
		M("grant_check_slow_path     %15llu  Number of times homa_grant_check_rpc acquired grant lock\n",
		  m->grant_check_calls);
		M("grant_priority_bumps      %15llu  Number of times an RPC moved up in the grant priority order\n",
		  m->grant_priority_bumps);
		M("fifo_grants               %15llu  Grants issued using FIFO priority\n",
		  m->fifo_grants);
		M("fifo_grants_no_incoming   %15llu  FIFO grants to messages with no outstanding grants\n",
		  m->fifo_grants_no_incoming);
		M("disabled_reaps            %15llu  Reaper invocations that were disabled\n",
		  m->disabled_reaps);
		M("deferred_rpc_reaps        %15llu  RPCs skipped by reaper because still in use\n",
		  m->deferred_rpc_reaps);
		M("reaper_calls              %15llu  Reaper invocations that were not disabled\n",
		  m->reaper_calls);
		M("reaper_dead_skbs          %15llu  Sum of hsk->dead_skbs across all reaper calls\n",
		  m->reaper_dead_skbs);
		M("throttle_list_adds        %15llu  Calls to homa_add_to_throttled\n",
		  m->throttle_list_adds);
		M("throttle_list_checks      %15llu  List elements checked in homa_add_to_throttled\n",
		  m->throttle_list_checks);
		M("ack_overflows             %15llu  Explicit ACKs sent because peer->acks was full\n",
		  m->ack_overflows);
		M("ignored_need_acks         %15llu  NEED_ACKs ignored because RPC result not yet received\n",
		  m->ignored_need_acks);
		M("bpage_reuses              %15llu  Buffer page could be reused because ref count was zero\n",
		  m->bpage_reuses);
		M("buffer_alloc_failures     %15llu  homa_pool_alloc_msg didn't find enough buffer space for an RPC\n",
		  m->buffer_alloc_failures);
		M("linux_pkt_alloc_bytes     %15llu  Bytes allocated in new packets by NIC driver due to cache overflows\n",
		  m->linux_pkt_alloc_bytes);
		M("dropped_data_no_bufs      %15llu  Data bytes dropped because app buffers full\n",
		  m->dropped_data_no_bufs);
		M("gen3_handoffs             %15llu  GRO->SoftIRQ handoffs made by Gen3 balancer\n",
		  m->gen3_handoffs);
		M("gen3_alt_handoffs         %15llu  Gen3 handoffs to secondary core (primary was busy)\n",
		  m->gen3_alt_handoffs);
		M("gro_grant_bypasses        %15llu  Grant packets passed directly to homa_softirq by homa_gro_receive\n",
		  m->gro_grant_bypasses);
		M("gro_data_bypasses         %15llu  Data packets passed directly to homa_softirq by homa_gro_receive\n",
		  m->gro_data_bypasses);
		for (i = 0; i < NUM_TEMP_METRICS;  i++)
			M("temp%-2d                  %15llu  Temporary use in testing\n",
			  i, m->temp[i]);
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
