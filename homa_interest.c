// SPDX-License-Identifier: BSD-2-Clause

/* This file contains functions for managing homa_interest structs. */

#include "homa_impl.h"
#include "homa_interest.h"
#include "homa_rpc.h"
#include "homa_sock.h"

#ifndef __STRIP__ /* See strip.py */
#include "homa_offload.h"
#endif /* See strip.py */

/**
 * homa_interest_init_shared() - Initialize an interest and queue it up on a socket.
 * @interest:  Interest to initialize
 * @hsk:       Socket on which the interests should be queued. Must be locked
 *             by caller.
 */
void homa_interest_init_shared(struct homa_interest *interest,
			       struct homa_sock *hsk)
	__must_hold(&hsk->lock)
{
	interest->rpc = NULL;
	atomic_set(&interest->ready, 0);
	interest->core = raw_smp_processor_id();
	interest->blocked = 0;
	init_waitqueue_head(&interest->wait_queue);
	interest->hsk = hsk;
	list_add(&interest->links, &hsk->interests);
}

/**
 * homa_interest_init_private() - Initialize an interest that will wait
 * on a particular (private) RPC, and link it to that RPC.
 * @interest:   Interest to initialize.
 * @rpc:        RPC to associate with the interest. Must be private, and
 *              caller must have locked it.
 *
 * Return:      0 for success, otherwise a negative errno.
 */
int homa_interest_init_private(struct homa_interest *interest,
			       struct homa_rpc *rpc)
	__must_hold(&rpc->bucket->lock)
{
	if (rpc->private_interest)
		return -EINVAL;

	interest->rpc = rpc;
	atomic_set(&interest->ready, 0);
	interest->core = raw_smp_processor_id();
	interest->blocked = 0;
	init_waitqueue_head(&interest->wait_queue);
	interest->hsk = rpc->hsk;
	rpc->private_interest = interest;
	return 0;
}

/**
 * homa_interest_wait() - Wait for an interest to have an actionable RPC,
 * or for an error to occur.
 * @interest:     Interest to wait for; must previously have been initialized
 *                and linked to a socket or RPC. On return, the interest
 *                will have been unlinked if its ready flag is set; otherwise
 *                it may still be linked.
 * @nonblocking:  Nonzero means return without blocking if the interest
 *                doesn't become ready immediately.
 *
 * Return: 0 for success (there is an actionable RPC in the interest), or
 * a negative errno.
 */
int homa_interest_wait(struct homa_interest *interest, int nonblocking)
{
	struct homa_sock *hsk = interest->hsk;
	int result = 0;
	int iteration;
	int wait_err;

#ifndef __STRIP__ /* See strip.py */
	u64 start, block_start, blocked_time, now;

	start = sched_clock();
	blocked_time = 0;
#endif /* See strip.py */
	interest->blocked = 0;

	/* This loop iterates in order to poll and/or reap dead RPCS. */
	for (iteration = 0; ; iteration++) {
		if (iteration != 0)
			/* Give NAPI/SoftIRQ tasks a chance to run. */
			schedule();

		if (atomic_read_acquire(&interest->ready) != 0)
			goto done;

		/* See if we can cleanup dead RPCs while waiting. */
		if (homa_rpc_reap(hsk, false) != 0)
			continue;

		if (nonblocking) {
			result = -EAGAIN;
			goto done;
		}

#ifndef __STRIP__ /* See strip.py */
		now = sched_clock();
		per_cpu(homa_offload_core,
			raw_smp_processor_id()).last_app_active = now;
		if (now - start >= 1000 * hsk->homa->poll_usecs)
			break;
#else /* See strip.py */
		break;
#endif /* See strip.py */
	}

	interest->blocked = 1;
	IF_NO_STRIP(block_start = now);
	wait_err = wait_event_interruptible_exclusive(interest->wait_queue,
			atomic_read_acquire(&interest->ready) != 0);
	IF_NO_STRIP(blocked_time = sched_clock() - block_start);
	if (wait_err == -ERESTARTSYS)
		result = -EINTR;

done:
#ifndef __STRIP__ /* See strip.py */
	if (interest->blocked)
		INC_METRIC(blocked_ns, blocked_time);
	INC_METRIC(poll_ns, sched_clock() - start - blocked_time);
#endif /* See strip.py */
	return result;
}

/**
 * homa_interest_notify_private() - If a thread is waiting on the private
 * interest for an RPC, wake it up.
 * @rpc:      RPC that may (potentially) have a private interest. Must be
 *            locked by the caller.
 */
void homa_interest_notify_private(struct homa_rpc *rpc)
	__must_hold(&rpc->bucket->lock)
{
	if (rpc->private_interest) {
		atomic_set_release(&rpc->private_interest->ready, 1);
		wake_up(&rpc->private_interest->wait_queue);
	}
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_choose_interest() - Given all the interests registered for a socket,
 * choose the best one to handle an incoming message.
 * @hsk:         Socket for which message is intended. Must be locked by caller,
 *               and must have at least one queued interest.
 * Return:       The interest to use. This function tries to pick an
 *               interest whose thread is running on a core that isn't
 *               currently busy doing Homa transport work.
 */
struct homa_interest *homa_choose_interest(struct homa_sock *hsk)
	__must_hold(&hsk->lock)
{
	u64 busy_time = sched_clock() - hsk->homa->busy_ns;
	struct homa_interest *interest, *first;

	first = list_first_entry(&hsk->interests, struct homa_interest,
				 links);
	list_for_each_entry(interest, &hsk->interests, links) {
		if (per_cpu(homa_offload_core, interest->core).last_active <
				busy_time) {
			if (interest != first)
				INC_METRIC(handoffs_alt_thread, 1);
			return interest;
		}
	}

	/* All interested threads are on busy cores; return the first,
	 * which is also the most recent one to be registered, hence
	 * most likely to have warm cache state.
	 */
	return first;
}
#endif /* See strip.py */
