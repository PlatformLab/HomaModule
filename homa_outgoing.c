/* This file contains functions related to the sender side of message
 * transmission. It also contains utility functions for sending packets.
 */

#include "homa_impl.h"

/**
 * set_priority() - Arrange for a packet to have a VLAN header that
 * specifies a priority for the packet.
 * @skb:        The packet was priority should be set.
 * @priority:   Priority level for the packet, in the range 0 (for lowest
 *              priority) to 7 ( for highest priority).
 */
inline static void set_priority(struct sk_buff *skb, int priority)
{
	/* The priority values stored in the VLAN header are weird, in that
	 * the value 0 is not the lowest priority; this table maps from
	 * "sensible" values as provided by the @priority argument to the
	 * corresponding value for the VLAN header. See the IEEE P802.1
	 * standard for details.
	 */
	static int tci[] = {
		(1 << VLAN_PRIO_SHIFT) | VLAN_TAG_PRESENT,
		(0 << VLAN_PRIO_SHIFT) | VLAN_TAG_PRESENT,
		(2 << VLAN_PRIO_SHIFT) | VLAN_TAG_PRESENT,
		(3 << VLAN_PRIO_SHIFT) | VLAN_TAG_PRESENT,
		(4 << VLAN_PRIO_SHIFT) | VLAN_TAG_PRESENT,
		(5 << VLAN_PRIO_SHIFT) | VLAN_TAG_PRESENT,
		(6 << VLAN_PRIO_SHIFT) | VLAN_TAG_PRESENT,
		(7 << VLAN_PRIO_SHIFT) | VLAN_TAG_PRESENT
	};
	skb->vlan_proto = htons(0x8100);
	skb->vlan_tci = tci[priority];
}

/**
 * homa_message_out_init() - Initialize a homa_message_out, including copying
 * message data from user space into sk_buffs.
 * @msgout:    Struct to initialize; current contents are assumed to be garbage.
 * @hsk:       Socket from which message will be sent.
 * @iter:      Info about the request buffer in user space.
 * @len:       Total length of the message.
 * @dest:      Describes the host to which the RPC will be sent.
 * @dport:     Port on @dest where the server is listening (destination).
 * @sport:     Port of the client (source).
 * @id:        Unique identifier for the message's RPC (relative to sport).
 * 
 * Return:   Either 0 (for success) or a negative errno value.
 */
int homa_message_out_init(struct homa_message_out *msgout,
		struct homa_sock *hsk, struct iov_iter *iter, size_t len,
		struct homa_peer *dest, __u16 dport, __u16 sport, __u64 id)
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
	msgout->unscheduled = hsk->homa->rtt_bytes;
	msgout->granted = msgout->unscheduled;
	if (msgout->granted > msgout->length)
		msgout->granted = msgout->length;
	msgout->sched_priority = 0;
	
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
		h->common.dport = htons(dport);
		h->common.id = id;
		h->common.type = DATA;
		h->message_length = htonl(msgout->length);
		h->offset = htonl(msgout->length - bytes_left);
		h->unscheduled = htonl(msgout->unscheduled);
		h->cutoff_version = dest->cutoff_version;
		h->retransmit = 0;
		err = skb_add_data_nocache((struct sock *) hsk, skb, iter,
				cur_size);
		if (unlikely(err != 0)) {
			kfree_skb(skb);
			goto error;
		}
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
 * homa_message_out_reset() - Reset a homa_message_out to its initial state,
 * as if no packets had been sent. Data for the message is preserved.
 * @msgout:    Struct to reset. Must have been successfully initialized in
 *             the past, and some packets may have been transmitted since
 *             then.
 */
void homa_message_out_reset(struct homa_message_out *msgout)
{
	msgout->next_packet = msgout->packets;
	msgout->next_offset = 0;
	msgout->granted = msgout->unscheduled;
	if (msgout->granted > msgout->length)
		msgout->granted = msgout->length;
}

/**
 * homa_message_out_destroy() - Destructor for homa_message_out.
 * @msgout:       Structure to clean up.
 */
void homa_message_out_destroy(struct homa_message_out *msgout)
{
	struct sk_buff *skb, *next;
	if (msgout->length < 0)
		return;
	for (skb = msgout->packets; skb !=  NULL; skb = next) {
		next = *homa_next_skb(skb);
		kfree_skb(skb);
	}
	msgout->packets = NULL;
}

/**
 * homa_set_priority() - Arrange for a packet to have a VLAN header that
 * specifies a priority for the packet.
 * @skb:        The packet was priority should be set.
 * @priority:   Priority level for the packet, in the range 0 (for lowest
 *              priority) to 7 ( for highest priority).
 */
void homa_set_priority(struct sk_buff *skb, int priority)
{
	set_priority(skb, priority);
}

/**
 * homa_xmit_control() - Send a control packet to the other end of an RPC.
 * @type:      Packet type, such as DATA.
 * @contents:  Address of buffer containing the contents of the packet.
 *             Only information after the common header must be valid;
 *             the common header will be filled in by this function.
 * @length:    Length of @contents (including the common header).
 * @rpc:       The packet will go to the socket that handles the other end
 *             of this RPC. Addressing info for the packet, including all of
 *             the fields of common_header except type, will be set from this.
 * 
 * Return:     Either zero (for success), or a negative errno value if there
 *             was a problem.
 */
int homa_xmit_control(enum homa_packet_type type, void *contents,
	size_t length, struct homa_rpc *rpc)
{
	struct common_header *h = (struct common_header *) contents;
	h->type = type;
	if (rpc->is_client) {
		h->sport = htons(rpc->hsk->client_port);
	} else {
		h->sport = htons(rpc->hsk->server_port);
	}
	h->dport = htons(rpc->dport);
	h->id = rpc->id;
	return __homa_xmit_control(contents, length, rpc->peer, rpc->hsk);
}

/**
 * __homa_xmit_control() - Lower-level version of homa_xmit_control: sends
 * a control packet.
 * @contents:  Address of buffer containing the contents of the packet.
 *             The caller must have filled in all of the information,
 *             including the common header.
 * @length:    Length of @contents.
 * @peer:      Destination to which the packet will be sent.
 * @hsk:       Socket via which the packet will be sent.
 * 
 * Return:     Either zero (for success), or a negative errno value if there
 *             was a problem.
 */
int __homa_xmit_control(void *contents, size_t length, struct homa_peer *peer,
		struct homa_sock *hsk)
{
	struct common_header *h;
	int extra_bytes;
	int result;
	struct sk_buff *skb = alloc_skb(HOMA_SKB_SIZE, GFP_KERNEL);
	if (unlikely(!skb))
		return -ENOBUFS;
	skb_reserve(skb, HOMA_SKB_RESERVE);
	skb_reset_transport_header(skb);
	h = (struct common_header *) skb_put(skb, length);
	memcpy(h, contents, length);
	extra_bytes = HOMA_MAX_HEADER - length;
	if (extra_bytes > 0)
		memset(skb_put(skb, extra_bytes), 0, extra_bytes);
	set_priority(skb, hsk->homa->max_prio);
	dst_hold(peer->dst);
	skb_dst_set(skb, peer->dst);
	result = ip_queue_xmit((struct sock *) hsk, skb, &peer->flow);
	if (unlikely(result != 0)) {
		INC_METRIC(control_xmit_errors, 1);
		kfree_skb(skb);
	}
	INC_METRIC(packets_sent[h->type - DATA], 1);
	return result;
}

/**
 * homa_xmit_data() - If a message has data packets that are permitted
 * to be transmitted according to the scheduling mechanism, arrange for
 * them to be sent.
 * @msgout: Message to check for transmittable packets.
 * @sk:     Socket to use for transmission.
 * @peer:   Information about the destination.
 */
void homa_xmit_data(struct homa_message_out *msgout, struct sock *sk,
		struct homa_peer *peer)
{
	while ((msgout->next_offset < msgout->granted) && msgout->next_packet) {
		int priority;
		struct sk_buff *skb = msgout->next_packet;
		struct data_header *h = (struct data_header *)
				skb_transport_header(skb);
		
		msgout->next_packet = *homa_next_skb(skb);
		if (msgout->next_offset < msgout->unscheduled) {
			priority = homa_unsched_priority(peer, msgout->length);
		} else {
			priority = msgout->sched_priority;
		}
		msgout->next_offset += HOMA_MAX_DATA_PER_PACKET;
		
		if (skb_shared(skb)) {
			/* The packet is still being transmitted due to a
			 * previous call to this function; no need to do
			 * anything here (and it may not be safe to retransmit
			 * it, or modify it, in this state).
			 */
			continue;
		}
		set_priority(skb, priority);
		
		/* Reset retransmit in case the packet was previously
		 * retransmitted but we're now restarting from the
		 * beginning.
		 */
		h->retransmit = 0;
		
		__homa_xmit_data(skb, sk, peer); 
	}
}

/**
 * __homa_xmit_data() - Handles packet transmission stuff that is common
 * to homa_xmit_data and homa_resend_data.
 * @skb:    Packet to be sent. Will be freed, either by the underlying
 *          transmission code, or by this function if an error occurs.
 * @sk:     Socket over which to send the packet.
 * @peer:   Information about the packet's destination.
 */
void __homa_xmit_data(struct sk_buff *skb, struct sock *sk,
		struct homa_peer *peer)
{
	int err;
	struct data_header *h = (struct data_header *)
			skb_transport_header(skb);

	/* Update cutoff_version in case it has changed since the
	 * message was initially created.
	 */
	h->cutoff_version = peer->cutoff_version;

	skb_get(skb);
	dst_hold(peer->dst);
	skb_dst_set(skb, peer->dst);

	/* Strip headers in front of the transport header (needed if
	 * the packet is being retransmitted).
	 */
	if (skb_transport_offset(skb) > 0)
		skb_pull(skb, skb_transport_offset(skb));
	err = ip_queue_xmit(sk, skb, &peer->flow);
	if (err) {
		INC_METRIC(data_xmit_errors, 1);
		kfree_skb(skb);
	}
	INC_METRIC(packets_sent[0], 1);
}

/**
 * homa_resend_data() - This function is invoked as part of handling RESEND
 * requests. It retransmits the packets containing a given range of bytes
 * from a message.
 * @msgout:   Message containing the packets.
 * @start:    Offset within @msgout of the first byte to retransmit.
 * @end:      Offset within @msgout of the byte just after the last one
 *            to retransmit.
 * @sk:       Socket to use for transmission.
 * @peer:     Information about the destination.
 * @priority: Priority level to use for the retransmitted data packets.
 */
void homa_resend_data(struct homa_message_out *msgout, int start, int end,
		struct sock *sk, struct homa_peer *peer, int priority)
{
	struct sk_buff *skb;
	
	for (skb = msgout->packets; skb !=  NULL; skb = *homa_next_skb(skb)) {
		struct data_header *h = (struct data_header *)
				skb_transport_header(skb);
		int offset = ntohl(h->offset);
		
		if ((offset + HOMA_MAX_DATA_PER_PACKET) <= start)
			continue;
		if (offset >= end)
			break;
		/* See comments in homa_xmit_data for code below. */
		if (skb_shared(skb))
			continue;
		h->retransmit = 1;
		set_priority(skb, priority);
		__homa_xmit_data(skb, sk, peer);
		INC_METRIC(resent_packets, 1);
	}
}