// SPDX-License-Identifier: BSD-2-Clause

/* This file implements the Homa pacer, which implements SRPT for packet
 * output. In order to do that, it throttles packet transmission to prevent
 * the buildup of large queues in the NIC.
 */

#include "homa_impl.h"
#include "homa_grant.h"
#include "homa_pacer.h"
#include "homa_rpc.h"

#ifndef __STRIP__ /* See strip.py */
/* Used to enable sysctl access to pacer-specific configuration parameters. The
 * @data fields are actually offsets within a struct homa_pacer; these are
 * converted to pointers into a net-specific struct homa later.
 */
#define OFFSET(field) ((void *)offsetof(struct homa_pacer, field))
static struct ctl_table pacer_ctl_table[] = {
	{
		.procname	= "link_mbps",
		.data		= OFFSET(link_mbps),
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_pacer_dointvec
	},
	{
		.procname	= "max_nic_queue_ns",
		.data		= OFFSET(max_nic_queue_ns),
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_pacer_dointvec
	},
	{
		.procname	= "pacer_fifo_fraction",
		.data		= OFFSET(fifo_fraction),
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_pacer_dointvec
	},
	{
		.procname	= "throttle_min_bytes",
		.data		= OFFSET(throttle_min_bytes),
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= homa_pacer_dointvec
	},
};
#endif /* See strip.py */

/**
 * homa_pacer_alloc() - Allocate and initialize a new pacer object, which
 * will hold pacer-related information for @homa.
 * @homa:   Homa transport that the pacer will be associated with.
 * Return:  A pointer to the new struct pacer, or a negative errno.
 */
struct homa_pacer *homa_pacer_alloc(struct homa *homa)
{
	struct homa_pacer *pacer;
	int err;

	pacer = kzalloc(sizeof(*pacer), GFP_KERNEL);
	if (!pacer)
		return ERR_PTR(-ENOMEM);
	pacer->homa = homa;
	spin_lock_init(&pacer->mutex);
	pacer->fifo_count = 1000;
	spin_lock_init(&pacer->throttle_lock);
	INIT_LIST_HEAD_RCU(&pacer->throttled_rpcs);
	pacer->fifo_fraction = 50;
	pacer->max_nic_queue_ns = 5000;
	pacer->link_mbps = 25000;
	pacer->throttle_min_bytes = 1000;
	pacer->exit = false;
	init_waitqueue_head(&pacer->wait_queue);
	pacer->kthread = kthread_run(homa_pacer_main, pacer, "homa_pacer");
	if (IS_ERR(pacer->kthread)) {
		err = PTR_ERR(pacer->kthread);
		pr_err("Homa couldn't create pacer thread: error %d\n", err);
		goto error;
	}
	init_completion(&pacer->kthread_done);
	atomic64_set(&pacer->link_idle_time, homa_clock());

#ifndef __STRIP__ /* See strip.py */
	pacer->sysctl_header = register_net_sysctl(&init_net, "net/homa",
						   pacer_ctl_table);
	if (!pacer->sysctl_header) {
		err = -ENOMEM;
		pr_err("couldn't register sysctl parameters for Homa pacer\n");
		goto error;
	}
#endif /* See strip.py */
	homa_pacer_update_sysctl_deps(pacer);
	return pacer;

error:
	homa_pacer_free(pacer);
	return ERR_PTR(err);
}

/**
 * homa_pacer_free() - Cleanup and free the pacer object for a Homa
 * transport.
 * @pacer:    Object to destroy; caller must not reference the object
 *            again once this function returns.
 */
void homa_pacer_free(struct homa_pacer *pacer)
{
	pacer->exit = true;
#ifndef __STRIP__ /* See strip.py */
	if (pacer->sysctl_header) {
		unregister_net_sysctl_table(pacer->sysctl_header);
		pacer->sysctl_header = NULL;
	}
#endif /* See strip.py */
	if (pacer->kthread) {
		wake_up(&pacer->wait_queue);
		kthread_stop(pacer->kthread);
		wait_for_completion(&pacer->kthread_done);
		pacer->kthread = NULL;
	}
	kfree(pacer);
}

/**
 * homa_pacer_check_nic_q() - This function is invoked before passing a
 * packet to the NIC for transmission. It serves two purposes. First, it
 * maintains an estimate of the NIC queue length. Second, it indicates to
 * the caller whether the NIC queue is so full that no new packets should be
 * queued (Homa's SRPT depends on keeping the NIC queue short).
 * @pacer:    Pacer information for a Homa transport.
 * @skb:      Packet that is about to be transmitted.
 * @force:    True means this packet is going to be transmitted
 *            regardless of the queue length.
 * Return:    Nonzero is returned if either the NIC queue length is
 *            acceptably short or @force was specified. 0 means that the
 *            NIC queue is at capacity or beyond, so the caller should delay
 *            the transmission of @skb. If nonzero is returned, then the
 *            queue estimate is updated to reflect the transmission of @skb.
 */
int homa_pacer_check_nic_q(struct homa_pacer *pacer, struct sk_buff *skb,
			   bool force)
{
	u64 idle, new_idle, clock, cycles_for_packet;
	int bytes;

	bytes = homa_get_skb_info(skb)->wire_bytes;
	cycles_for_packet = pacer->cycles_per_mbyte;
	cycles_for_packet *= bytes;
	do_div(cycles_for_packet, 1000000);
	while (1) {
		clock = homa_clock();
		idle = atomic64_read(&pacer->link_idle_time);
		if ((clock + pacer->max_nic_queue_cycles) < idle && !force &&
		    !(pacer->homa->flags & HOMA_FLAG_DONT_THROTTLE))
			return 0;
#ifndef __STRIP__ /* See strip.py */
		if (!list_empty(&pacer->throttled_rpcs))
			INC_METRIC(pacer_bytes, bytes);
		if (idle < clock) {
			if (pacer->wake_time) {
				u64 lost = (pacer->wake_time > idle)
						? clock - pacer->wake_time
						: clock - idle;
				INC_METRIC(pacer_lost_cycles, lost);
				tt_record1("pacer lost %d cycles", lost);
			}
			new_idle = clock + cycles_for_packet;
		} else {
			new_idle = idle + cycles_for_packet;
		}
#else /* See strip.py */
		if (idle < clock)
			new_idle = clock + cycles_for_packet;
		else
			new_idle = idle + cycles_for_packet;
#endif /* See strip.py */

		/* This method must be thread-safe. */
		if (atomic64_cmpxchg_relaxed(&pacer->link_idle_time, idle,
					     new_idle) == idle)
			break;
	}
	return 1;
}

/**
 * homa_pacer_main() - Top-level function for the pacer thread.
 * @arg:  Pointer to pacer struct.
 *
 * Return:         Always 0.
 */
int homa_pacer_main(void *arg)
{
	struct homa_pacer *pacer = arg;
	int status;

	while (1) {
		if (pacer->exit)
			break;
		pacer->wake_time = homa_clock();
		homa_pacer_xmit(pacer);
		INC_METRIC(pacer_cycles, homa_clock() - pacer->wake_time);
		pacer->wake_time = 0;
		if (!list_empty(&pacer->throttled_rpcs)) {
			/* NIC queue is full; before calling pacer again,
			 * give other threads a chance to run (otherwise
			 * low-level packet processing such as softirq could
			 * get locked out).
			 */
			schedule();
			continue;
		}

		tt_record("pacer sleeping");
		status = wait_event_interruptible(pacer->wait_queue,
			pacer->exit || !list_empty(&pacer->throttled_rpcs));
		tt_record1("pacer woke up with status %d", status);
		if (status != 0 && status != -ERESTARTSYS)
			break;
	}
	kthread_complete_and_exit(&pacer->kthread_done, 0);
	return 0;
}

/**
 * homa_pacer_xmit() - Transmit packets from  the throttled list until
 * either (a) the throttled list is empty or (b) the NIC queue has
 * reached maximum allowable length. Note: this function may be invoked
 * from either process context or softirq (BH) level. This function is
 * invoked from multiple places, not just in the pacer thread. The reason
 * for this is that (as of 10/2019) Linux's scheduling of the pacer thread
 * is unpredictable: the thread may block for long periods of time (e.g.,
 * because it is assigned to the same CPU as a busy interrupt handler).
 * This can result in poor utilization of the network link. So, this method
 * gets invoked from other places as well, to increase the likelihood that we
 * keep the link busy. Those other invocations are not guaranteed to happen,
 * so the pacer thread provides a backstop.
 * @pacer:    Pacer information for a Homa transport.
 */
void homa_pacer_xmit(struct homa_pacer *pacer)
{
	struct homa_rpc *rpc;
	s64 queue_cycles;

	/* Make sure only one instance of this function executes at a time. */
	if (!spin_trylock_bh(&pacer->mutex))
		return;

	while (1) {
		queue_cycles = atomic64_read(&pacer->link_idle_time) -
					     homa_clock();
		if (queue_cycles >= pacer->max_nic_queue_cycles)
			break;
		if (list_empty(&pacer->throttled_rpcs))
			break;

		/* Lock the first throttled RPC. This may not be possible
		 * because we have to hold throttle_lock while locking
		 * the RPC; that means we can't wait for the RPC lock because
		 * of lock ordering constraints (see "Homa Locking Strategy" in
		 * homa_impl.h). Thus, if the RPC lock isn't available, do
		 * nothing. Holding the throttle lock while locking the RPC
		 * is important because it keeps the RPC from being deleted
		 * before it can be locked.
		 */
		homa_pacer_throttle_lock(pacer);
		pacer->fifo_count -= pacer->fifo_fraction;
		if (pacer->fifo_count <= 0) {
			struct homa_rpc *cur;
			u64 oldest = ~0;

			pacer->fifo_count += 1000;
			rpc = NULL;
			list_for_each_entry(cur, &pacer->throttled_rpcs,
					    throttled_links) {
				if (cur->msgout.init_time < oldest) {
					rpc = cur;
					oldest = cur->msgout.init_time;
				}
			}
		} else {
			rpc = list_first_entry_or_null(&pacer->throttled_rpcs,
						       struct homa_rpc,
						       throttled_links);
		}
		if (!rpc) {
			homa_pacer_throttle_unlock(pacer);
			break;
		}
		if (!homa_rpc_try_lock(rpc)) {
			homa_pacer_throttle_unlock(pacer);
			INC_METRIC(pacer_skipped_rpcs, 1);
			break;
		}
		homa_pacer_throttle_unlock(pacer);

		tt_record4("pacer calling homa_xmit_data for rpc id %llu, port %d, offset %d, bytes_left %d",
			   rpc->id, rpc->hsk->port,
			   rpc->msgout.next_xmit_offset,
			   rpc->msgout.length - rpc->msgout.next_xmit_offset);
		homa_xmit_data(rpc, true);

		/* Note: rpc->state could be RPC_DEAD here, but the code
		 * below should work anyway.
		 */
#ifndef __STRIP__ /* See strip.py */
		if (!*rpc->msgout.next_xmit || rpc->msgout.next_xmit_offset >=
					       rpc->msgout.granted) {
#else /* See strip.py */
		if (!*rpc->msgout.next_xmit) {
#endif /* See strip.py */
			/* No more data can be transmitted from this message
			 * (right now), so remove it from the throttled list.
			 */
			tt_record2("pacer removing id %d from throttled list, offset %d",
				   rpc->id, rpc->msgout.next_xmit_offset);
			homa_pacer_unmanage_rpc(rpc);
		}
		homa_rpc_unlock(rpc);
	}
	spin_unlock_bh(&pacer->mutex);
}

/**
 * homa_pacer_manage_rpc() - Arrange for the pacer to transmit packets
 * from this RPC (make sure that an RPC is on the throttled list and wake up
 * the pacer thread if necessary).
 * @rpc:     RPC with outbound packets that have been granted but can't be
 *           sent because of NIC queue restrictions. Must be locked by caller.
 */
void homa_pacer_manage_rpc(struct homa_rpc *rpc)
	__must_hold(rpc->bucket->lock)
{
	struct homa_pacer *pacer = rpc->hsk->homa->pacer;
	struct homa_rpc *candidate;
	int bytes_left;
	IF_NO_STRIP(int checks = 0);
	IF_NO_STRIP(u64 now);

	if (!list_empty(&rpc->throttled_links))
		return;
	IF_NO_STRIP(now = homa_clock());
#ifndef __STRIP__ /* See strip.py */
	if (!list_empty(&pacer->throttled_rpcs))
		INC_METRIC(throttled_cycles, now - pacer->throttle_add);
	pacer->throttle_add = now;
#endif /* See strip.py */
	bytes_left = rpc->msgout.length - rpc->msgout.next_xmit_offset;
	homa_pacer_throttle_lock(pacer);
	list_for_each_entry(candidate, &pacer->throttled_rpcs,
			    throttled_links) {
		int bytes_left_cand;

		IF_NO_STRIP(checks++);

		/* Watch out: the pacer might have just transmitted the last
		 * packet from candidate.
		 */
		bytes_left_cand = candidate->msgout.length -
				candidate->msgout.next_xmit_offset;
		if (bytes_left_cand > bytes_left) {
			list_add_tail(&rpc->throttled_links,
				      &candidate->throttled_links);
			goto done;
		}
	}
	list_add_tail(&rpc->throttled_links, &pacer->throttled_rpcs);
done:
	homa_pacer_throttle_unlock(pacer);
	wake_up(&pacer->wait_queue);
	INC_METRIC(throttle_list_adds, 1);
	INC_METRIC(throttle_list_checks, checks);
//	tt_record("woke up pacer thread");
}

/**
 * homa_pacer_unmanage_rpc() - Make sure that an RPC is no longer managed
 * by the pacer.
 * @rpc:     RPC of interest.
 */
void homa_pacer_unmanage_rpc(struct homa_rpc *rpc)
	__must_hold(rpc->bucket->lock)
{
	struct homa_pacer *pacer = rpc->hsk->homa->pacer;

	if (unlikely(!list_empty(&rpc->throttled_links))) {
		UNIT_LOG("; ", "removing id %llu from throttled list", rpc->id);
		homa_pacer_throttle_lock(pacer);
		list_del_init(&rpc->throttled_links);
#ifndef __STRIP__ /* See strip.py */
		if (list_empty(&pacer->throttled_rpcs))
			INC_METRIC(throttled_cycles, homa_clock()
					- pacer->throttle_add);
#endif /* See strip.py */
		homa_pacer_throttle_unlock(pacer);
	}
}

/**
 * homa_pacer_update_sysctl_deps() - Update any pacer fields that depend
 * on values set by sysctl. This function is invoked anytime a pacer sysctl
 * value is updated.
 * @pacer:   Pacer to update.
 */
void homa_pacer_update_sysctl_deps(struct homa_pacer *pacer)
{
	u64 tmp;

	pacer->max_nic_queue_cycles =
			homa_ns_to_cycles(pacer->max_nic_queue_ns);

	/* Underestimate link bandwidth (overestimate time) by 1%. */
	tmp = 101 * 8000 * (u64)homa_clock_khz();
	do_div(tmp, pacer->link_mbps * 100);
	pacer->cycles_per_mbyte = tmp;
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_pacer_dointvec() - This function is a wrapper around proc_dointvec. It
 * is invoked to read and write pacer-related sysctl values.
 * @table:    sysctl table describing value to be read or written.
 * @write:    Nonzero means value is being written, 0 means read.
 * @buffer:   Address in user space of the input/output data.
 * @lenp:     Not exactly sure.
 * @ppos:     Not exactly sure.
 *
 * Return: 0 for success, nonzero for error.
 */
int homa_pacer_dointvec(const struct ctl_table *table, int write,
			void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table table_copy;
	struct homa_pacer *pacer;
	int result;

	pacer = homa_net_from_net(current->nsproxy->net_ns)->homa->pacer;

	/* Generate a new ctl_table that refers to a field in the
	 * net-specific struct homa.
	 */
	table_copy = *table;
	table_copy.data = ((char *)pacer) + (uintptr_t)table_copy.data;

	result = proc_dointvec(&table_copy, write, buffer, lenp, ppos);
	if (write) {
		homa_pacer_update_sysctl_deps(pacer);

		/* Grant info depends on link speed. */
		homa_grant_update_sysctl_deps(pacer->homa->grant);
	}
	return result;
}

/**
 * homa_pacer_log_throttled() - Print information to the system log about the
 * RPCs on the throttled list.
 * @pacer:    Pacer information for a Homa transport.
 */
void homa_pacer_log_throttled(struct homa_pacer *pacer)
{
	struct homa_rpc *rpc;
	s64 bytes = 0;
	int rpcs = 0;

	pr_notice("Printing throttled list\n");
	homa_pacer_throttle_lock(pacer);
	list_for_each_entry_rcu(rpc, &pacer->throttled_rpcs, throttled_links) {
		rpcs++;
		if (!homa_rpc_try_lock(rpc)) {
			pr_notice("Skipping throttled RPC: locked\n");
			continue;
		}
		if (*rpc->msgout.next_xmit)
			bytes += rpc->msgout.length
					- rpc->msgout.next_xmit_offset;
		if (rpcs <= 20)
			homa_rpc_log(rpc);
		homa_rpc_unlock(rpc);
	}
	homa_pacer_throttle_unlock(pacer);
	pr_notice("Finished printing throttle list: %d rpcs, %lld bytes\n",
		  rpcs, bytes);
}

/**
 * homa_pacer_throttle_lock_slow() - This function implements the slow path for
 * acquiring the throttle lock. It is invoked when the lock isn't immediately
 * available. It waits for the lock, but also records statistics about
 * the waiting time.
 * @pacer:    Pacer information for a Homa transport.
 */
void homa_pacer_throttle_lock_slow(struct homa_pacer *pacer)
	__acquires(pacer->throttle_lock)
{
	u64 start = homa_clock();

	tt_record("beginning wait for throttle lock");
	spin_lock_bh(&pacer->throttle_lock);
	tt_record("ending wait for throttle lock");
	INC_METRIC(throttle_lock_misses, 1);
	INC_METRIC(throttle_lock_miss_cycles, homa_clock() - start);
}
#endif /* See strip.py */
