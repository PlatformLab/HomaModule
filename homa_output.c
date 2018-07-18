/* This file contains functions related to the sender side of message
 * transmission. */

#include "homa_impl.h"

/**
 * homa_message_out_init() - Initialize a homa_message_out, including copying
 * message data from user space into sk_buffs.
 * @hmo:       Struct to initialize; current contents are assumed to be garbage.
 * @sk:        Socket from which message will be sent.
 * @msg:       Describes the message contents in user space.
 * @len:       Total length of the message.
 * @dest:      Describes the destination to which the RPC will be sent.
 * @sport:     Port of the client (source).
 * @id:        Unique identifier for the message's RPC (relative to sport).
 * 
 * Return:   Either 0 (for success) or a negative errno value.
 */
int homa_message_out_init(struct homa_message_out *hmo, struct sock *sk,
		struct msghdr *msg, size_t len, struct homa_addr *dest,
		__u16 sport, __u64 id)
{
	int bytes_left;
	struct sk_buff *skb;
	int err;
	struct sk_buff **last_link = &hmo->packets;
	
	hmo->length = len;
	hmo->packets = NULL;
	hmo->next_packet = NULL;
	hmo->next_offset = 0;
	
	/* This is a temporary guess; must handle better in the future. */
	hmo->unscheduled = 7*HOMA_MAX_DATA_PER_PACKET;
	hmo->limit = hmo->unscheduled;
	hmo->priority = 0;
	
	/* Copy message data from user space and form packet buffers. */
	if (unlikely(len > HOMA_MAX_MESSAGE_LENGTH)) {
		return -EINVAL;
	}
	for (bytes_left = len, last_link = &hmo->packets; bytes_left > 0;
			bytes_left -= HOMA_MAX_DATA_PER_PACKET) {
		struct data_header *h;
		__u32 cur_size = HOMA_MAX_DATA_PER_PACKET;
		if (likely(cur_size > bytes_left)) {
			cur_size = bytes_left;
		}
		skb = alloc_skb(HOMA_SKB_SIZE, GFP_KERNEL);
		if (unlikely(!skb)) {
			return -ENOMEM;
		}
		skb_reserve(skb, HOMA_SKB_RESERVE);
		skb_reset_transport_header(skb);
		h = (struct data_header *) skb_put(skb, sizeof(*h));
		h->common.sport = htons(sport);
		h->common.dport = htons(dest->dport);
		h->common.id = id;
		h->common.type = DATA;
		h->message_length = htonl(hmo->length);
		h->offset = htonl(hmo->length - bytes_left);
		h->unscheduled = htonl(hmo->unscheduled);
		h->retransmit = 0;
		err = skb_add_data_nocache(sk, skb, &msg->msg_iter,
				cur_size);
		if (unlikely(err != 0)) {
			return err;
		}
		dst_hold(dest->dst);
		skb_dst_set(skb, dest->dst);
		*last_link = skb;
		last_link = homa_next_skb(skb);
		*last_link = NULL;
	}
	hmo->next_packet = hmo->packets;
	return 0;
}

/**
 * homa_message_out_destroy() - Destructor for homa_message_out.
 * @hmo:       Structure to clean up.
 */
void homa_message_out_destroy(struct homa_message_out *hmo)
{
	struct sk_buff *skb, *next;
	for (skb = hmo->packets; skb !=  NULL; skb = next) {
		next = *homa_next_skb(skb);
		kfree_skb(skb);
	}
}

/**
 * homa_xmit_packets(): If a message has data packets that are permitted
 * to be transmitted according to the scheduling mechanism, arrange for
 * them to be sent.
 * @hmo:    Message to check for transmittable packets.
 * @sk:     Socket to use for transmission.
 * @dest:   Addressing information about the destination.
 */
void homa_xmit_packets(struct homa_message_out *hmo, struct sock *sk,
		struct homa_addr *dest)
{
	while ((hmo->next_offset < hmo->limit) && hmo->next_packet) {
		int err;
		skb_get(hmo->next_packet);
		err = ip_queue_xmit(sk, hmo->next_packet, &dest->flow);
		if (err) {
			printk(KERN_WARNING 
				"ip_queue_xmit failed in homa_xmit_packets: %d",
				err);
		}
		hmo->next_packet = *homa_next_skb(hmo->next_packet);
		hmo->next_offset += HOMA_MAX_DATA_PER_PACKET; 
	}
}