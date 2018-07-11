/* This file contains functions related to the sender side of message
 * transmission. */

#include "homa_impl.h"

/**
 * homa_message_out_init() - Initialize a homa_message_out, including copying
 * message data from user space into sk_buffs.
 * @hmo:       Struct to initialize; current contents are assumed to be garbage.
 * @sk:        Socket from which message will be sent.
 * @id:        Unique identifier for the message.
 * @direction: FROM_CLIENT or FROM_SERVER.
 * @msg:       Describes the message contents in user space.
 * @len:       Total length of the message.
 * @dst:       Where to send the packets of the message.
 * 
 * Return:   Either 0 (for success) or a negative errno value.
 */
int homa_message_out_init(struct homa_message_out *hmo, struct sock *sk,
		struct rpc_id id, __u8 direction, struct msghdr *msg,
		size_t len, struct dst_entry *dst)
{
	int bytes_left;
	struct sk_buff *skb;
	int err;
	
	hmo->length = len;
	__skb_queue_head_init(&hmo->packets);
	hmo->unscheduled_bytes = 7*HOMA_MAX_DATA_PER_PACKET;
	hmo->limit = hmo->unscheduled_bytes;
	hmo->priority = 0;
	
	/* Copy message data from user space and form packet buffers. */
	if (likely(len <= HOMA_MAX_DATA_PER_PACKET)) {
		struct full_message_header *h;
		skb = alloc_skb(HOMA_SKB_SIZE, GFP_KERNEL);
		if (unlikely(!skb)) {
			return -ENOMEM;
		}
		skb_reserve(skb, HOMA_SKB_RESERVE);
		skb_reset_transport_header(skb);
		h = (struct full_message_header *) skb_put(skb, sizeof(*h));
		h->common.rpc_id = id;
		h->common.type = FULL_MESSAGE;
		h->common.direction = direction;
		h->message_length = htons(hmo->length);
		err = skb_add_data_nocache(sk, skb, &msg->msg_iter,
				hmo->length);
		if (err != 0) {
			return err;
		}
		skb_dst_set(skb, dst);
		__skb_queue_tail(&hmo->packets, skb);
	} else if (unlikely(len > HOMA_MAX_MESSAGE_LENGTH)) {
		return -EINVAL;
	} else for (bytes_left = len; bytes_left > 0;
			bytes_left -= HOMA_MAX_DATA_PER_PACKET) {
		struct message_frag_header *h;
		__u32 cur_size = HOMA_MAX_DATA_PER_PACKET;
		if (unlikely(cur_size > bytes_left)) {
			cur_size = bytes_left;
		}
		skb = alloc_skb(HOMA_SKB_SIZE, GFP_KERNEL);
		if (unlikely(!skb)) {
			return -ENOMEM;
		}
		skb_reserve(skb, HOMA_SKB_RESERVE);
		skb_reset_transport_header(skb);
		h = (struct message_frag_header *) skb_put(skb, sizeof(*h));
		h->common.rpc_id = id;
		h->common.type = MESSAGE_FRAG;
		h->common.direction = direction;
		h->message_length = htons(hmo->length);
		h->offset = hmo->length - bytes_left;
		h->unscheduled_bytes = hmo->unscheduled_bytes;
		h->retransmit = 0;
		err = skb_add_data_nocache(sk, skb, &msg->msg_iter, cur_size);
		if (unlikely(err != 0)) {
			return err;
		}
		skb_dst_set(skb, dst);
		__skb_queue_tail(&hmo->packets, skb);
	}
	return 0;
}

/**
 * homa_message_out_destroy() - Destructor for homa_message_out.
 * @hmo:       Structure to clean up.
 * @hsk:       Associated socket.
 */
void homa_message_out_destroy(struct homa_message_out *hmo)
{
	struct sk_buff *skb;
	skb_queue_walk(&hmo->packets, skb) {
		kfree_skb(skb);
	}
}