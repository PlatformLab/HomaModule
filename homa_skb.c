/* Copyright (c) 2024 Homa Developers
 * SPDX-License-Identifier: BSD-1-Clause
 */

/* This file contains functions for allocating and freeing sk_buffs. */

#include "homa_impl.h"

/**
 * homa_skb_new() - Allocate a new sk_buff.
 * @length:       Number of bytes of packet data to allocate.
 * Return:        New sk_buff, or NULL if there was insufficient memory.
 */
struct sk_buff *homa_skb_new(int length)
{
	struct sk_buff *skb;
	__u64 start = get_cycles();
	skb = alloc_skb(length, GFP_KERNEL);
	INC_METRIC(skb_allocs, 1);
	INC_METRIC(skb_alloc_cycles, get_cycles() - start);
	return skb;
}

/**
 * homa_skb_free() - Release the storage for an sk_buff.
 * @skb:       sk_buff to free.
 */
void homa_skb_free(struct sk_buff *skb)
{
	__u64 start = get_cycles();
	kfree_skb(skb);
	INC_METRIC(skb_frees, 1);
	INC_METRIC(skb_free_cycles, get_cycles() - start);
}

/**
 * homa_skb_free_many() - Release the storage for multiple sk_buffs.
 * @skbs:      Pointer to first entry in array of sk_buffs to free.
 * @count:     Total number of sk_buffs to free.
 */
void homa_skb_free_many(struct sk_buff **skbs, int count)
{
	__u64 start = get_cycles();
	int i;

	for (i = 0; i < count; i++)
		kfree_skb(skbs[i]);
	INC_METRIC(skb_frees, count);
	INC_METRIC(skb_free_cycles, get_cycles() - start);
}