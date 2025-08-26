// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

/* This file contains miscellaneous utility functions for Homa, such
 * as initializing and destroying homa structs.
 */

#include "homa_impl.h"
#include "homa_pacer.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#ifndef __STRIP__ /* See strip.py */
#include "homa_grant.h"
#include "homa_skb.h"
#endif /* See strip.py */

#ifdef __STRIP__ /* See strip.py */
#include "homa_stub.h"
#endif /* See strip.py */

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

	IF_NO_STRIP(int i);

	memset(homa, 0, sizeof(*homa));

	atomic64_set(&homa->next_outgoing_id, 2);
	homa->link_mbps = 25000;
	homa->pacer = homa_pacer_alloc(homa);
	if (IS_ERR(homa->pacer)) {
		err = PTR_ERR(homa->pacer);
		homa->pacer = NULL;
		return err;
	}
#ifndef __STRIP__ /* See strip.py */
	homa->grant = homa_grant_alloc(homa);
	if (IS_ERR(homa->grant)) {
		err = PTR_ERR(homa->grant);
		homa->grant = NULL;
		return err;
	}
#endif /* See strip.py */
	homa->peertab = homa_peer_alloc_peertab();
	if (IS_ERR(homa->peertab)) {
		err = PTR_ERR(homa->peertab);
		homa->peertab = NULL;
		return err;
	}
	homa->socktab = kmalloc(sizeof(*homa->socktab), GFP_KERNEL);
	if (!homa->socktab)
		return -ENOMEM;
	homa_socktab_init(homa->socktab);
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
#endif /* See strip.py */
	homa->resend_ticks = 5;
	homa->resend_interval = 5;
	homa->timeout_ticks = 100;
	homa->timeout_resends = 5;
	homa->request_ack_ticks = 2;
	homa->reap_limit = 10;
	homa->dead_buffs_limit = 5000;
#ifndef __STRIP__ /* See strip.py */
	homa->verbose = 0;
#endif /* See strip.py */
	homa->max_gso_size = 10000;
	homa->wmem_max = 100000000;
#ifndef __STRIP__ /* See strip.py */
	homa->max_gro_skbs = 20;
	homa->gro_policy = HOMA_GRO_NORMAL;
	homa->busy_usecs = 100;
	homa->gro_busy_usecs = 5;
#endif /* See strip.py */
	homa->bpage_lease_usecs = 10000;
#ifndef __STRIP__ /* See strip.py */
	homa_incoming_sysctl_changed(homa);
#endif /* See strip.py */
	return 0;
}

/**
 * homa_destroy() -  Destructor for homa objects.
 * @homa:      Object to destroy. It is safe if this object has already
 *             been previously destroyed.
 */
void homa_destroy(struct homa *homa)
{
#ifdef __UNIT_TEST__
#include "utils.h"
	unit_homa_destroy(homa);
#endif /* __UNIT_TEST__ */

	/* The order of the following cleanups matters! */
	if (homa->socktab) {
		homa_socktab_destroy(homa->socktab, NULL);
		kfree(homa->socktab);
		homa->socktab = NULL;
	}
#ifndef __STRIP__ /* See strip.py */
	if (homa->grant) {
		homa_grant_free(homa->grant);
		homa->grant = NULL;
	}
#endif /* See strip.py */
	if (homa->pacer) {
		homa_pacer_free(homa->pacer);
		homa->pacer = NULL;
	}
	if (homa->peertab) {
		homa_peer_free_peertab(homa->peertab);
		homa->peertab = NULL;
	}
#ifndef __STRIP__ /* See strip.py */

	homa_skb_cleanup(homa);
#endif /* See strip.py */
}

/**
 * homa_net_init() - Initialize a new struct homa_net as a per-net subsystem.
 * @hnet:    Struct to initialzie.
 * @net:     The network namespace the struct will be associated with.
 * @homa:    The main Homa data structure to use for the net.
 * Return:  0 on success, otherwise a negative errno.
 */
int homa_net_init(struct homa_net *hnet, struct net *net, struct homa *homa)
{
	memset(hnet, 0, sizeof(*hnet));
	hnet->homa = homa;
	hnet->prev_default_port = HOMA_MIN_DEFAULT_PORT - 1;
#ifndef __STRIP__ /* See strip.py */
	INIT_LIST_HEAD(&hnet->qdisc_devs);
	mutex_init(&hnet->qdisc_devs_mutex);
#endif /* See strip.py */
	return 0;
}

/**
 * homa_net_destroy() - Release any resources associated with a homa_net.
 * @hnet:    Object to destroy; must not be used again after this function
 *           returns.
 */
void homa_net_destroy(struct homa_net *hnet)
{
	homa_socktab_destroy(hnet->homa->socktab, hnet);
	homa_peer_free_net(hnet);
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

	end = homa_clock() + homa_ns_to_cycles(ns);
	while (homa_clock() < end)
		/* Empty loop body.*/
		;
}
