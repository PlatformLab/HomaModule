// SPDX-License-Identifier: BSD-2-Clause

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

/* Pointer to the singleton homa_shared object, of NULL if there are
 * currently no struct homa objects in existence.
 */
struct homa_shared *homa_shared;

/**
 * homa_shared_alloc() - Allocate and initialize a new homa_shared
 * object.
 * Return: the new homa_shared object, or ERR_PTR on failure.
 */
struct homa_shared *homa_shared_alloc(void)
{
	struct homa_shared *shared;
	int err;

	shared = kmalloc(sizeof(*homa_shared), GFP_KERNEL);
	if (!shared)
		return ERR_PTR(-ENOMEM);
	spin_lock_init(&shared->lock);
	INIT_LIST_HEAD(&shared->homas);
	shared->peers = homa_peertab_alloc();
	if (IS_ERR(shared->peers)) {
		err = PTR_ERR(shared->peers);
		kfree(shared);
		return ERR_PTR(err);
	}
	return shared;
}

/**
 * homa_shared_free() - Clean up and free a homa_shared object.
 */
void homa_shared_free(struct homa_shared *shared)
{
	homa_peertab_free(shared->peers);
	kfree(shared);
	if (shared == homa_shared)
		homa_shared = NULL;
}

/**
 * homa_init() - Constructor for homa objects.
 * @homa:   Object to initialize.
 * @net:    Network namespace that @homa is associated with.
 *
 * Return:  0 on success, or a negative errno if there was an error. Even
 *          if an error occurs, it is safe (and necessary) to call
 *          homa_destroy at some point.
 */
int homa_init(struct homa *homa, struct net *net)
{
	int err;
#ifndef __STRIP__ /* See strip.py */
	int i;

	_Static_assert(HOMA_MAX_PRIORITIES >= 8,
		       "Homa requires at least 8 priority levels");
#endif /* See strip.py */

	memset(homa, 0, sizeof(*homa));

	if (!homa_shared) {
		homa_shared = homa_shared_alloc();
		if (IS_ERR(homa_shared)) {
			int status = PTR_ERR(homa_shared);

			homa_shared = NULL;
			return status;
		}
	}
	homa->shared = homa_shared;
	spin_lock_bh(&homa_shared->lock);
	list_add_tail(&homa->shared_links, &homa_shared->homas);
	spin_unlock_bh(&homa_shared->lock);

	atomic64_set(&homa->next_outgoing_id, 2);
#ifndef __STRIP__ /* See strip.py */
	homa->grant = homa_grant_alloc(net);
	if (IS_ERR(homa->grant)) {
		err = PTR_ERR(homa->grant);
		homa->grant = NULL;
		return err;
	}
#endif /* See strip.py */
	homa->pacer = homa_pacer_alloc(homa, net);
	if (IS_ERR(homa->pacer)) {
		err = PTR_ERR(homa->pacer);
		homa->pacer = NULL;
		return err;
	}
	homa->prev_default_port = HOMA_MIN_DEFAULT_PORT - 1;
	homa->port_map = kmalloc(sizeof(*homa->port_map), GFP_KERNEL);
	if (!homa->port_map) {
		pr_err("%s couldn't create port_map: kmalloc failure",
		       __func__);
		return -ENOMEM;
	}
	homa_socktab_init(homa->port_map);
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
	struct homa_shared *shared;

	if (!homa_shared)
		/* Already destroyed. */
		return;

#ifdef __UNIT_TEST__
#include "utils.h"
	unit_homa_destroy(homa);
#endif /* __UNIT_TEST__ */

	/* The order of the following cleanups matters! */
	if (homa->port_map) {
		homa_socktab_destroy(homa->port_map);
		kfree(homa->port_map);
		homa->port_map = NULL;
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
#ifndef __STRIP__ /* See strip.py */
	homa_skb_cleanup(homa);
#endif /* See strip.py */
	homa_peertab_free_homa(homa);

	shared = homa->shared;
	spin_lock_bh(&shared->lock);
	__list_del_entry(&homa->shared_links);
	if (list_empty(&homa->shared->homas)) {
		spin_unlock_bh(&shared->lock);
		homa_shared_free(homa->shared);
	} else {
		spin_unlock_bh(&shared->lock);
	}
	homa->shared = NULL;
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
