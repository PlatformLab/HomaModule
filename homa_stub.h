/* SPDX-License-Identifier: BSD-2-Clause */

/* This file contains stripped-down replacements that have been
 * temporarily removed from Homa during the Linux upstreaming
 * process. By the time upstreaming is complete this file will
 * have gone away.
 */

#ifndef _HOMA_STUB_H
#define _HOMA_STUB_H

#include "homa_impl.h"

static inline int homa_skb_init(struct homa *homa)
{
	return 0;
}

static inline void homa_skb_cleanup(struct homa *homa)
{}

static inline void homa_skb_release_pages(struct homa *homa)
{}

static inline int homa_skb_append_from_iter(struct homa *homa,
					    struct sk_buff *skb,
					    struct iov_iter *iter, int length)
{
	char *dst = skb_put(skb, length);

	if (copy_from_iter(dst, length, iter) != length)
		return -EFAULT;
	return 0;
}

static inline int homa_skb_append_to_frag(struct homa *homa,
					  struct sk_buff *skb, void *buf,
					  int length)
{
	char *dst = skb_put(skb, length);

	memcpy(dst, buf, length);
	return 0;
}

static inline int  homa_skb_append_from_skb(struct homa *homa,
					    struct sk_buff *dst_skb,
					    struct sk_buff *src_skb,
					    int offset, int length)
{
	return homa_skb_append_to_frag(homa, dst_skb,
			skb_transport_header(src_skb) + offset, length);
}

static inline void homa_skb_free_tx(struct homa *homa, struct sk_buff *skb)
{
	kfree_skb(skb);
}

static inline void homa_skb_free_many_tx(struct homa *homa,
					 struct sk_buff **skbs, int count)
{
	int i;

	for (i = 0; i < count; i++)
		kfree_skb(skbs[i]);
}

static inline void homa_skb_get(struct sk_buff *skb, void *dest, int offset,
				int length)
{
	memcpy(dest, skb_transport_header(skb) + offset, length);
}

static inline struct sk_buff *homa_skb_new_tx(int length)
{
	struct sk_buff *skb;

	skb = alloc_skb(HOMA_SKB_EXTRA + HOMA_IPV6_HEADER_LENGTH +
			sizeof(struct homa_skb_info) + length, GFP_ATOMIC);
	if (likely(skb)) {
		skb_reserve(skb, HOMA_SKB_EXTRA + HOMA_IPV6_HEADER_LENGTH);
		skb_reset_transport_header(skb);
	}
	return skb;
}

static inline void homa_skb_stash_pages(struct homa *homa, int length)
{}

#endif /* _HOMA_STUB_H */
