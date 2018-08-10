/* This file contains functions related to the sender side of message
 * transmission. It also contains utility functions for sending packets.
 */

#include "homa_impl.h"

/**
 * homa_message_out_init() - Initialize a homa_message_out, including copying
 * message data from user space into sk_buffs.
 * @msgout:    Struct to initialize; current contents are assumed to be garbage.
 * @sk:        Socket from which message will be sent.
 * @iter:      Info about the request buffer in user space.
 * @len:       Total length of the message.
 * @dest:      Describes the destination to which the RPC will be sent.
 * @sport:     Port of the client (source).
 * @id:        Unique identifier for the message's RPC (relative to sport).
 * 
 * Return:   Either 0 (for success) or a negative errno value.
 */
int homa_message_out_init(struct homa_message_out *msgout, struct sock *sk,
		struct iov_iter *iter, size_t len, struct homa_addr *dest,
		__u16 sport, __u64 id)
{
	int bytes_left;
	struct sk_buff *skb;
	int err;
	struct sk_buff **last_link = &msgout->packets;
	
	msgout->length = len;
	msgout->packets = NULL;
	msgout->next_packet = NULL;
	msgout->next_offset = 0;
	
	/* This is a temporary guess; must handle better in the future. */
	msgout->unscheduled = 7*HOMA_MAX_DATA_PER_PACKET;
	msgout->granted = msgout->unscheduled;
	msgout->priority = 0;
	
	/* Copy message data from user space and form packet buffers. */
	if (unlikely(len > HOMA_MAX_MESSAGE_LENGTH)) {
		err = -EINVAL;
		goto error;
	}
	for (bytes_left = len, last_link = &msgout->packets; bytes_left > 0;
			bytes_left -= HOMA_MAX_DATA_PER_PACKET) {
		struct data_header *h;
		__u32 cur_size = HOMA_MAX_DATA_PER_PACKET;
		if (likely(cur_size > bytes_left)) {
			cur_size = bytes_left;
		}
		skb = alloc_skb(HOMA_SKB_SIZE, GFP_KERNEL);
		if (unlikely(!skb)) {
			err = -ENOMEM;
			goto error;
		}
		skb_reserve(skb, HOMA_SKB_RESERVE);
		skb_reset_transport_header(skb);
		h = (struct data_header *) skb_put(skb, sizeof(*h));
		h->common.sport = htons(sport);
		h->common.dport = htons(dest->dport);
		h->common.id = id;
		h->common.type = DATA;
		h->message_length = htonl(msgout->length);
		h->offset = htonl(msgout->length - bytes_left);
		h->unscheduled = htonl(msgout->unscheduled);
		h->retransmit = 0;
		err = skb_add_data_nocache(sk, skb, iter, cur_size);
		if (unlikely(err != 0)) {
			kfree_skb(skb);
			goto error;
		}
		dst_hold(dest->dst);
		skb_dst_set(skb, dest->dst);
		*last_link = skb;
		last_link = homa_next_skb(skb);
		*last_link = NULL;
	}
	msgout->next_packet = msgout->packets;
	return 0;
	
    error:
	homa_message_out_destroy(msgout);
	return err;
}

/**
 * homa_message_out_destroy() - Destructor for homa_message_out.
 * @msgout:       Structure to clean up.
 */
void homa_message_out_destroy(struct homa_message_out *msgout)
{
	struct sk_buff *skb, *next;
	for (skb = msgout->packets; skb !=  NULL; skb = next) {
		next = *homa_next_skb(skb);
		kfree_skb(skb);
	}
	msgout->packets = NULL;
}

/**
 * homa_xmit_packets(): If a message has data packets that are permitted
 * to be transmitted according to the scheduling mechanism, arrange for
 * them to be sent.
 * @msgout: Message to check for transmittable packets.
 * @sk:     Socket to use for transmission.
 * @dest:   Addressing information about the destination.
 */
void homa_xmit_packets(struct homa_message_out *msgout, struct sock *sk,
		struct homa_addr *dest)
{
	while ((msgout->next_offset < msgout->granted) && msgout->next_packet) {
		int err;
		skb_get(msgout->next_packet);
		err = ip_queue_xmit(sk, msgout->next_packet, &dest->flow);
		if (err) {
			printk(KERN_WARNING 
				"ip_queue_xmit failed in homa_xmit_packets: %d",
				err);
		}
		msgout->next_packet = *homa_next_skb(msgout->next_packet);
		msgout->next_offset += HOMA_MAX_DATA_PER_PACKET; 
	}
}

/**
 * homa_xmit_to_sender() - Send a packet to the source of a homa_message_in.
 * @skb:      Packet buffer containing the contents of the message, including
 *            a Homa header.
 * @msgin:    Provides information about where to send the packet; addressing
 *            info for the packet, including all of the fields of
 *            common_header except type, will be set from this info.
 */
void homa_xmit_to_sender(struct sk_buff *skb, struct homa_message_in *msgin)
{
	struct homa_addr *peer;
	struct homa_sock *hsk;
	struct common_header *h =
			(struct common_header *) skb_transport_header(skb);
	int err;
	
	if (msgin->request) {
		struct homa_server_rpc *srpc = container_of(msgin,
				struct homa_server_rpc, request);
		hsk = srpc->hsk;
		peer = &srpc->client;
		h->sport = htons(hsk->server_port);
		h->dport = htons(peer->dport);
		h->id = srpc->id;
	} else {
		struct homa_client_rpc *crpc = container_of(msgin,
				struct homa_client_rpc, response);
		hsk = crpc->hsk;
		peer = &crpc->dest;
		h->sport = htons(hsk->client_port);
		h->dport = htons(peer->dport);
		h->id = crpc->id;
	}
	dst_hold(peer->dst);
	skb_dst_set(skb, peer->dst);
	if (skb->len < HOMA_MAX_HEADER) {
		int extra_bytes = HOMA_MAX_HEADER - skb->len;
		memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	}
	err = ip_queue_xmit((struct sock *) hsk, skb, &peer->flow);
	if (err) {
		printk(KERN_WARNING 
			"ip_queue_xmit failed in homa_xmit_to_sender: %d",
			err);
	}
}