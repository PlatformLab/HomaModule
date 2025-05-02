/* SPDX-License-Identifier: BSD-2-Clause */

/* This file contains definitions related to homa_offload.c. */

#ifndef _HOMA_OFFLOAD_H
#define _HOMA_OFFLOAD_H

#include <linux/types.h>

/**
 * struct homa_offload_core - Stores core-specific information used during
 * GRO operations.
 */
struct homa_offload_core {
	/**
	 * @last_active: the last time (in sched_clock() units) that
	 * there was system activity, such NAPI or SoftIRQ, on this
	 * core. Used for load balancing.
	 */
	u64 last_active;

	/**
	 * @last_gro: the last time (in sched_clock() units) that
	 * homa_gro_receive returned on this core. Used to determine
	 * whether GRO is keeping a core busy.
	 */
	u64 last_gro;

	/**
	 * @softirq_backlog: the number of batches of packets that have
	 * been queued for SoftIRQ processing on this core but haven't
	 * yet been processed.
	 */
	atomic_t softirq_backlog;

	/**
	 * @softirq_offset: used when rotating SoftIRQ assignment among
	 * the next cores; contains an offset to add to the current core
	 * to produce the core for SoftIRQ.
	 */
	int softirq_offset;

	/**
	 * @gen3_softirq_cores: when the Gen3 load balancer is in use,
	 * GRO will arrange for SoftIRQ processing to occur on one of
	 * these cores; -1 values are ignored (see balance.txt for more
	 * on lewd balancing). This information is filled in via sysctl.
	 */
#define NUM_GEN3_SOFTIRQ_CORES 3
	int gen3_softirq_cores[NUM_GEN3_SOFTIRQ_CORES];

	/**
	 * @last_app_active: the most recent time (sched_clock() units)
	 * when an application was actively using Homa on this core (e.g.,
	 * by sending or receiving messages). Used for load balancing
	 * (see balance.txt).
	 */
	u64 last_app_active;

	/**
	 * @held_skb: last packet buffer known to be available for
	 * merging other packets into on this core (note: may not still
	 * be available), or NULL if none.
	 */
	struct sk_buff *held_skb;

	/**
	 * @held_bucket: the index, within napi->gro_hash, of the list
	 * containing @held_skb; undefined if @held_skb is NULL. Used to
	 * verify that @held_skb is still available.
	 */
	int held_bucket;
};
DECLARE_PER_CPU(struct homa_offload_core, homa_offload_core);

int      homa_gro_complete(struct sk_buff *skb, int thoff);
void     homa_gro_gen2(struct homa *homa, struct sk_buff *skb);
void     homa_gro_gen3(struct homa *homa, struct sk_buff *skb);
#ifndef __STRIP__ /* See strip.py */
void     homa_gro_hook_tcp(void);
void     homa_gro_unhook_tcp(void);
#endif /* See strip.py */
struct sk_buff *homa_gro_receive(struct list_head *gro_list,
				 struct sk_buff *skb);
struct sk_buff *homa_gso_segment(struct sk_buff *skb,
				 netdev_features_t features);
int      homa_offload_end(void);
int      homa_offload_init(void);
void     homa_send_ipis(void);
#ifndef __STRIP__ /* See strip.py */
struct sk_buff *homa_tcp_gro_receive(struct list_head *held_list,
				     struct sk_buff *skb);
#endif /* See strip.py */

#endif /* _HOMA_OFFLOAD_H */
