// SPDX-License-Identifier: BSD-2-Clause

/* This file contains miscellaneous utility functions for Homa, such
 * as initializing and destroying homa structs.
 */

#include "homa_impl.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#ifndef __STRIP__ /* See strip.py */
#include "homa_skb.h"
#endif /* See strip.py */

#ifdef __STRIP__ /* See strip.py */
#include "homa_stub.h"
#endif /* See strip.py */

struct completion homa_pacer_kthread_done;

/**
 * homa_init() - Constructor for homa objects.
 * @homa:   Object to initialize.
 *
 * Return:  0 on success, or a negative errno if there was an error. Even
 *          if an error occurs, it is safe (and necessary) to call
 *          homa_destroy at some point.
 */
int homa_init(struct homa *homa)
{
	int err;
#ifndef __STRIP__ /* See strip.py */
	int i;

	_Static_assert(HOMA_MAX_PRIORITIES >= 8,
		       "homa_init assumes at least 8 priority levels");
#endif /* See strip.py */

	memset(homa, 0, sizeof(*homa));
	init_completion(&homa_pacer_kthread_done);
	atomic64_set(&homa->next_outgoing_id, 2);
	atomic64_set(&homa->link_idle_time, sched_clock());
#ifndef __STRIP__ /* See strip.py */
	spin_lock_init(&homa->grantable_lock);
	INIT_LIST_HEAD(&homa->grantable_peers);
	INIT_LIST_HEAD(&homa->grantable_rpcs);
	homa->last_grantable_change = sched_clock();
#endif /* See strip.py */
	spin_lock_init(&homa->pacer_mutex);
	homa->pacer_fifo_fraction = 50;
	homa->pacer_fifo_count = 1;
	spin_lock_init(&homa->throttle_lock);
	INIT_LIST_HEAD_RCU(&homa->throttled_rpcs);
	homa->throttle_min_bytes = 200;
	homa->prev_default_port = HOMA_MIN_DEFAULT_PORT - 1;
	homa->port_map = kmalloc(sizeof(*homa->port_map), GFP_KERNEL);
	if (!homa->port_map) {
		pr_err("%s couldn't create port_map: kmalloc failure",
		       __func__);
		return -ENOMEM;
	}
	homa_socktab_init(homa->port_map);
	homa->peers = kmalloc(sizeof(*homa->peers), GFP_KERNEL);
	if (!homa->peers) {
		pr_err("%s couldn't create peers: kmalloc failure", __func__);
		return -ENOMEM;
	}
	err = homa_peertab_init(homa->peers);
	if (err) {
		pr_err("%s couldn't initialize peer table (errno %d)\n",
		       __func__, -err);
		return err;
	}
#ifndef __STRIP__ /* See strip.py */
	err = homa_skb_init(homa);
	if (err) {
		pr_err("Couldn't initialize skb management (errno %d)\n",
		       -err);
		return err;
	}
#endif /* See strip.py */

	/* Wild guesses to initialize configuration values... */
#ifndef __STRIP__ /* See strip.py */
	homa->unsched_bytes = 40000;
	homa->window_param = 100000;
#endif /* See strip.py */
	homa->link_mbps = 25000;
#ifndef __STRIP__ /* See strip.py */
	homa->poll_usecs = 50;
	homa->num_priorities = HOMA_MAX_PRIORITIES;
	for (i = 0; i < HOMA_MAX_PRIORITIES; i++)
		homa->priority_map[i] = i;
	homa->max_sched_prio = HOMA_MAX_PRIORITIES - 5;
	homa->unsched_cutoffs[HOMA_MAX_PRIORITIES - 1] = 200;
	homa->unsched_cutoffs[HOMA_MAX_PRIORITIES - 2] = 2800;
	homa->unsched_cutoffs[HOMA_MAX_PRIORITIES - 3] = 15000;
	homa->unsched_cutoffs[HOMA_MAX_PRIORITIES - 4] = HOMA_MAX_MESSAGE_LENGTH;
#ifdef __UNIT_TEST__
	/* Unit tests won't send CUTOFFS messages unless the test changes
	 * this variable.
	 */
	homa->cutoff_version = 0;
#else
	homa->cutoff_version = 1;
#endif
	homa->fifo_grant_increment = 10000;
	homa->grant_fifo_fraction = 50;
	homa->max_overcommit = 8;
	homa->max_incoming = 400000;
	homa->max_rpcs_per_peer = 1;
#endif /* See strip.py */
	homa->resend_ticks = 5;
	homa->resend_interval = 5;
	homa->timeout_ticks = 100;
	homa->timeout_resends = 5;
	homa->request_ack_ticks = 2;
	homa->reap_limit = 10;
	homa->dead_buffs_limit = 5000;
	homa->pacer_kthread = kthread_run(homa_pacer_main, homa,
					  "homa_pacer");
	if (IS_ERR(homa->pacer_kthread)) {
		err = PTR_ERR(homa->pacer_kthread);
		homa->pacer_kthread = NULL;
		pr_err("couldn't create homa pacer thread: error %d\n", err);
		return err;
	}
	homa->pacer_exit = false;
	homa->max_nic_queue_ns = 5000;
#ifndef __STRIP__ /* See strip.py */
	homa->verbose = 0;
#endif /* See strip.py */
	homa->max_gso_size = 10000;
#ifndef __STRIP__ /* See strip.py */
	homa->max_gro_skbs = 20;
	homa->gro_policy = HOMA_GRO_NORMAL;
	homa->busy_usecs = 100;
	homa->gro_busy_usecs = 5;
	mutex_init(&homa->metrics_mutex);
	homa->metrics = NULL;
#endif /* See strip.py */
	homa->bpage_lease_usecs = 10000;
#ifndef __STRIP__ /* See strip.py */
	homa_outgoing_sysctl_changed(homa);
	homa_incoming_sysctl_changed(homa);
#endif /* See strip.py */
	return 0;
}

/**
 * homa_destroy() -  Destructor for homa objects.
 * @homa:      Object to destroy.
 */
void homa_destroy(struct homa *homa)
{
#ifdef __UNIT_TEST__
#include "utils.h"
	unit_homa_destroy(homa);
#endif /* __UNIT_TEST__ */
	if (homa->pacer_kthread) {
		homa_pacer_stop(homa);
		wait_for_completion(&homa_pacer_kthread_done);
	}

	/* The order of the following statements matters! */
	if (homa->port_map) {
		homa_socktab_destroy(homa->port_map);
		kfree(homa->port_map);
		homa->port_map = NULL;
	}
	if (homa->peers) {
		homa_peertab_destroy(homa->peers);
		kfree(homa->peers);
		homa->peers = NULL;
	}
#ifndef __STRIP__ /* See strip.py */
	homa_skb_cleanup(homa);
	kfree(homa->metrics);
	homa->metrics = NULL;
#endif /* See strip.py */
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_prios_changed() - This function is called whenever configuration
 * information related to priorities, such as @homa->unsched_cutoffs or
 * @homa->num_priorities, is modified. It adjusts the cutoffs if needed
 * to maintain consistency, and it updates other values that depend on
 * this information.
 * @homa: Contains the priority info to be checked and updated.
 */
void homa_prios_changed(struct homa *homa)
{
	int i;

	if (homa->num_priorities > HOMA_MAX_PRIORITIES)
		homa->num_priorities = HOMA_MAX_PRIORITIES;

	/* This guarantees that we will choose priority 0 if nothing else
	 * in the cutoff array matches.
	 */
	homa->unsched_cutoffs[0] = INT_MAX;

	for (i = HOMA_MAX_PRIORITIES - 1; ; i--) {
		if (i >= homa->num_priorities) {
			homa->unsched_cutoffs[i] = 0;
			continue;
		}
		if (i == 0) {
			homa->unsched_cutoffs[i] = INT_MAX;
			homa->max_sched_prio = 0;
			break;
		}
		if (homa->unsched_cutoffs[i] >= HOMA_MAX_MESSAGE_LENGTH) {
			homa->max_sched_prio = i - 1;
			break;
		}
	}
	homa->cutoff_version++;
}
#endif /* See strip.py */

/**
 * homa_spin() - Delay (without sleeping) for a given time interval.
 * @ns:   How long to delay (in nanoseconds)
 */
void homa_spin(int ns)
{
	u64 end;

	end = sched_clock() + ns;
	while (sched_clock() < end)
		/* Empty loop body.*/
		;
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_throttle_lock_slow() - This function implements the slow path for
 * acquiring the throttle lock. It is invoked when the lock isn't immediately
 * available. It waits for the lock, but also records statistics about
 * the waiting time.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_throttle_lock_slow(struct homa *homa)
	__acquires(&homa->throttle_lock)
{
	u64 start = sched_clock();

	tt_record("beginning wait for throttle lock");
	spin_lock_bh(&homa->throttle_lock);
	tt_record("ending wait for throttle lock");
	INC_METRIC(throttle_lock_misses, 1);
	INC_METRIC(throttle_lock_miss_ns, sched_clock() - start);
}
#endif /* See strip.py */
