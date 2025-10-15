// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

/* This file implements the Homa pacer, which implements SRPT for packet
 * output. In order to do that, it throttles packet transmission to prevent
 * the buildup of large queues in the NIC.
 */

#include "homa_impl.h"
#include "homa_pacer.h"
#include "homa_rpc.h"

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
	init_waitqueue_head(&pacer->wait_queue);
	pacer->kthread = kthread_run(homa_pacer_main, pacer, "homa_pacer");
	if (IS_ERR(pacer->kthread)) {
		err = PTR_ERR(pacer->kthread);
		pr_err("Homa couldn't create pacer thread: error %d\n", err);
		goto error;
	}
	atomic64_set(&pacer->link_idle_time, homa_clock());
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
	if (pacer->kthread) {
		kthread_stop(pacer->kthread);
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
		if ((clock + pacer->homa->qshared->max_nic_queue_cycles) < idle &&
		    !force && !(pacer->homa->flags & HOMA_FLAG_DONT_THROTTLE))
			return 0;
		if (!list_empty(&pacer->throttled_rpcs))
			INC_METRIC(pacer_bytes, bytes);
		if (idle < clock)
			new_idle = clock + cycles_for_packet;
		else
			new_idle = idle + cycles_for_packet;

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
	u64 start;

	while (1) {
		if (kthread_should_stop())
			break;
		start = homa_clock();
		homa_pacer_xmit(pacer);
		INC_METRIC(pacer_cycles, homa_clock() - start);
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
				kthread_should_stop() ||
				!list_empty(&pacer->throttled_rpcs));
		tt_record1("pacer woke up with status %d", status);
		if (status != 0 && status != -ERESTARTSYS)
			break;
	}
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
		if (queue_cycles >= pacer->homa->qshared->max_nic_queue_cycles)
			break;
		if (list_empty(&pacer->throttled_rpcs))
			break;

		/* Select an RPC to transmit (either SRPT or FIFO) and
		 * take a reference on it. Must do this while holding the
		 * throttle_lock to prevent the RPC from being reaped. Then
		 * release the throttle lock and lock the RPC (can't acquire
		 * the RPC lock while holding the throttle lock; see "Homa
		 * Locking Strategy" in homa_impl.h).
		 */
		homa_pacer_throttle_lock(pacer);
		pacer->fifo_count -= pacer->homa->qshared->fifo_fraction;
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
		homa_rpc_hold(rpc);
		homa_pacer_throttle_unlock(pacer);
		homa_rpc_lock(rpc);
		tt_record4("pacer calling homa_xmit_data for rpc id %llu, port %d, offset %d, bytes_left %d",
			   rpc->id, rpc->hsk->port,
			   rpc->msgout.next_xmit_offset,
			   rpc->msgout.length - rpc->msgout.next_xmit_offset);
		homa_xmit_data(rpc, true);

		/* Note: rpc->state could be RPC_DEAD here, but the code
		 * below should work anyway.
		 */
		if (!*rpc->msgout.next_xmit || rpc->msgout.next_xmit_offset >=
					       rpc->msgout.granted) {
			/* No more data can be transmitted from this message
			 * (right now), so remove it from the throttled list.
			 */
			tt_record2("pacer removing id %d from throttled list, offset %d",
				   rpc->id, rpc->msgout.next_xmit_offset);
			homa_pacer_unmanage_rpc(rpc);
		}
		homa_rpc_unlock(rpc);
		homa_rpc_put(rpc);
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
	int checks = 0;
	u64 now;

	if (!list_empty(&rpc->throttled_links))
		return;
	now = homa_clock();
	if (!list_empty(&pacer->throttled_rpcs))
		INC_METRIC(nic_backlog_cycles, now - pacer->throttle_add);
	pacer->throttle_add = now;
	bytes_left = rpc->msgout.length - rpc->msgout.next_xmit_offset;
	homa_pacer_throttle_lock(pacer);
	list_for_each_entry(candidate, &pacer->throttled_rpcs,
			    throttled_links) {
		int bytes_left_cand;

		checks++;

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
		if (list_empty(&pacer->throttled_rpcs))
			INC_METRIC(nic_backlog_cycles, homa_clock()
					- pacer->throttle_add);
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

	/* Underestimate link bandwidth (overestimate time) by 1%. */
	tmp = 101 * 8000 * (u64)homa_clock_khz();
	do_div(tmp, pacer->homa->link_mbps * 100);
	pacer->cycles_per_mbyte = tmp;
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
