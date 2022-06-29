/* Copyright (c) 2019-2021 Stanford University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* This file contains functions that handle incoming Homa messages, including
 * both receiving information for those messages and sending grants. */

#include "homa_impl.h"

/**
 * homa_message_in_init() - Constructor for homa_message_in.
 * @msgin:        Structure to initialize.
 * @length:       Total number of bytes in message.
 * @incoming:     Initial bytes of message that the sender is already
 *                planning to transmit, even without grants.
 */
void homa_message_in_init(struct homa_message_in *msgin, int length,
		int incoming)
{
	msgin->total_length = length;
	skb_queue_head_init(&msgin->packets);
	msgin->num_skbs = 0;
	msgin->bytes_remaining = length;
	msgin->incoming = incoming;
	if (msgin->incoming > msgin->total_length)
		msgin->incoming = msgin->total_length;
	msgin->extra_incoming = 0;
	msgin->priority = 0;
	msgin->scheduled = length > incoming;
	msgin->possibly_in_grant_queue = msgin->scheduled;
	msgin->xfer_offset = 0;
	msgin->xfer_skb = NULL;
	if (length < HOMA_NUM_SMALL_COUNTS*64) {
		INC_METRIC(small_msg_bytes[(length-1) >> 6], length);
	} else if (length < HOMA_NUM_MEDIUM_COUNTS*1024) {
		INC_METRIC(medium_msg_bytes[(length-1) >> 10], length);
	} else {
		INC_METRIC(large_msg_count, 1);
		INC_METRIC(large_msg_bytes, length);
	}
}

/**
 * homa_message_in_destroy() - Destructor for homa_message_in.
 * @msgin:       Structure to clean up.
 */
void homa_message_in_destroy(struct homa_message_in *msgin)
{
	struct sk_buff *skb, *next;
	if (msgin->total_length < 0)
		return;
	skb_queue_walk_safe(&msgin->packets, skb, next)
		kfree_skb(skb);
	__skb_queue_head_init(&msgin->packets);
	msgin->total_length = -1;
}

/**
 * homa_add_packet() - Add an incoming packet to the contents of a
 * partially received message.
 * @rpc:   Add the packet to the msgin for this RPC.
 * @skb:   The new packet. This function takes ownership of the packet
 *         and will free it, if it doesn't get added to msgin (because
 *         it provides no new data).
 */
void homa_add_packet(struct homa_rpc *rpc, struct sk_buff *skb)
{
	struct data_header *h = (struct data_header *) skb->data;
	int offset = ntohl(h->seg.offset);
	int data_bytes = ntohl(h->seg.segment_length);
	struct sk_buff *skb2;
	
	/* Any data from the packet with offset less than this is
	 * of no value.*/
	int floor = 0;
	
	/* Any data with offset >= this is useless. */
	int ceiling = rpc->msgin.total_length;
	
	/* Figure out where in the list of existing packets to insert the
	 * new one. It doesn't necessarily go at the end, but it almost
	 * always will in practice, so work backwards from the end of the
	 * list.
	 */
	skb_queue_reverse_walk(&rpc->msgin.packets, skb2) {
		struct data_header *h2 = (struct data_header *) skb2->data;
		int offset2 = ntohl(h2->seg.offset);
		int data_bytes2 = skb2->len - sizeof32(struct data_header);
		if (offset2 < offset) {
			floor = offset2 + data_bytes2;
			break;
		}
		ceiling = offset2;
	} 
		
	/* New packet goes right after skb2 (which may refer to the header).
	 * Packets shouldn't overlap in byte ranges, but the code below
	 * assumes they might, so it computes how many non-overlapping bytes
	 * are contributed by the new packet.
	 */
	if (unlikely(floor < offset)) {
		floor = offset;
	}
	if (ceiling > offset + data_bytes) {
		ceiling = offset + data_bytes;
	}
	if (floor >= ceiling) {
		/* This packet is redundant. */
//		char buffer[100];
//		printk(KERN_NOTICE "redundant Homa packet: %s\n",
//			homa_print_packet(skb, buffer, sizeof(buffer)));
		INC_METRIC(redundant_packets, 1);
		kfree_skb(skb);
		return;
	}
	if (h->retransmit) {
		INC_METRIC(resent_packets_used, 1);
		homa_freeze(rpc, PACKET_LOST, "Freezing because of lost "
				"packet, id %d, peer 0x%x");
	}
	__skb_insert(skb, skb2, skb2->next, &rpc->msgin.packets);
	rpc->msgin.bytes_remaining -= (ceiling - floor);
	rpc->msgin.num_skbs++;
}

/**
 * homa_message_in_copy_data() - Extract data from an incoming message
 * and copy it to buffer(s) in user space. If one call does not extract
 * the entire message, the function can be called again to extract the
 * next bytes.
 * @msgin:      The message whose data should be extracted.
 * @iter:       Describes the available buffer space at user-level; message
 *              data gets copied here.
 * @max_bytes:  Total number of bytes of data to extract.
 * 
 * Return:      The number of bytes copied, or a negative errno.
 */
int homa_message_in_copy_data(struct homa_message_in *msgin,
		struct iov_iter *iter, int max_bytes)
{
	int err;
	int remaining = max_bytes;
	
	/* Do the right thing even if packets have overlapping ranges.
	 * In practice, this shouldn't ever be necessary.
	 */
	if (msgin->xfer_offset == 0)
		msgin->xfer_skb = msgin->packets.next;
	skb_queue_walk_from(&msgin->packets, msgin->xfer_skb) {
		struct data_header *h =
				(struct data_header *) msgin->xfer_skb->data;
		int this_offset = ntohl(h->seg.offset);
		int this_size = ntohl(h->seg.segment_length);
		if (msgin->xfer_offset != this_offset) {
			BUG_ON(msgin->xfer_offset < this_offset);
			this_size -= (msgin->xfer_offset - this_offset);
		}
		if (this_size > remaining)
			this_size = remaining;
		if (unlikely(this_size <= 0))
			continue;
		err = skb_copy_datagram_iter(msgin->xfer_skb,
				sizeof(*h) + (msgin->xfer_offset - this_offset),
				iter, this_size);
		if (err) {
			return err;
		}
		remaining -= this_size;
		msgin->xfer_offset += this_size;
		if (remaining == 0) {
			break;
		}
	}
	return max_bytes - remaining;
}

/**
 * homa_get_resend_range() - Given a message for which some input data
 * is missing, find the first range of missing data.
 * @msgin:     Message for which not all granted data has been received.
 * @resend:    The @offset and @length fields of this structure will be
 *             filled in with information about the first missing range
 *             in @msgin.
 */
void homa_get_resend_range(struct homa_message_in *msgin,
		struct resend_header *resend)
{
	struct sk_buff *skb;
	int missing_bytes;
	/* This will eventually be the top of the first missing range. */
	int end_offset;
	
	if (msgin->total_length < 0) {
		/* Haven't received any data for this message; request
		 * retransmission of just the first packet (the sender
		 * will send at least one full packet, regardless of
		 * the length below).
		 */
		resend->offset = 0;
		resend->length = htonl(100);
		return;
	}
	
	missing_bytes = msgin->bytes_remaining
			- (msgin->total_length - msgin->incoming);
	if (missing_bytes == 0) {
		resend->offset = 0;
		resend->length = 0;
		return;
	}
	end_offset = msgin->incoming;
	
	/* Basic idea: walk backwards through the message's packets until
	 * we have accounted for all missing bytes; this will identify
	 * the first missing range.
	 */
	skb_queue_reverse_walk(&msgin->packets, skb) {
		struct data_header *h = (struct data_header *) skb->data;
		int offset = ntohl(h->seg.offset);
		int pkt_length = ntohl(h->seg.segment_length);
		int gap;

		if (pkt_length > (msgin->total_length - offset))
			pkt_length = msgin->total_length - offset;
		gap = end_offset - (offset + pkt_length);
		missing_bytes -= gap;
		if (missing_bytes == 0) {
			resend->offset = htonl(offset + pkt_length);
			resend->length = htonl(gap);
			return;
		}
		end_offset = offset;
	}
	
	/* The first packet(s) are missing. */
	resend->offset = 0;
	resend->length = htonl(missing_bytes);
}

/**
 * homa_pkt_dispatch() - Top-level function for handling an incoming packet.
 * @skb:        The incoming packet. This function takes ownership of the
 *              packet and will ensure that it is eventually freed.
 * @hsk:        Homa socket that owns the packet's destination port. This socket
 *              is not locked, but its existence is ensured for the life
 *              of this method.
 *
 * Return:  None.
 */
void homa_pkt_dispatch(struct sk_buff *skb, struct homa_sock *hsk)
{
	struct common_header *h = (struct common_header *) skb->data;
	struct homa_rpc *rpc;
	__u64 id = homa_local_id(h->sender_id);
	
	/* If there is an ack in the packet, handle it. Must do this
	 * before locking the packet's RPC, since we may need to acquire
	 * (other) RPC locks to handle the acks.
	 */
	if (h->type == DATA) {
		struct data_header *dh = (struct data_header *) h;
		if (dh->seg.ack.client_id != 0)
			homa_rpc_acked(hsk, ip_hdr(skb)->saddr, &dh->seg.ack);
	}
	
	/* Find and lock the RPC for this packet. */
	if (!homa_is_client(id)) {
		/* We are the server for this RPC. */
		if (h->type == DATA) {
			/* Create a new RPC if one doesn't already exist. */
			rpc = homa_rpc_new_server(hsk, ip_hdr(skb)->saddr,
					(struct data_header *) h);
			if (IS_ERR(rpc)) {
				printk(KERN_WARNING "homa_pkt_dispatch "
						"couldn't create server rpc: "
						"error %lu",
						-PTR_ERR(rpc));
				INC_METRIC(server_cant_create_rpcs, 1);
				rpc = NULL;
				goto discard;
			}
		} else
			rpc = homa_find_server_rpc(hsk, ip_hdr(skb)->saddr,
					ntohs(h->sport), id);
			
	} else {
		rpc = homa_find_client_rpc(hsk, id);
	}
	if (unlikely(rpc == NULL)) {
		if ((h->type != CUTOFFS) && (h->type != NEED_ACK)
				&& (h->type != ACK) && (h->type != RESEND)) {
			tt_record4("Discarding packet for unknown RPC, id %u, "
					"type %d, peer 0x%x:%d",
					id, h->type,
					ntohl(ip_hdr(skb)->saddr),
					ntohs(h->sport));
			if ((h->type != GRANT) || homa_is_client(id))
				INC_METRIC(unknown_rpcs, 1);
			goto discard;
		}
	} else {
		if ((h->type == DATA) || (h->type == GRANT)
				|| (h->type == BUSY))
			rpc->silent_ticks = 0;
		rpc->peer->outstanding_resends = 0;
	}
	
	switch (h->type) {
	case DATA:
		if (homa_data_pkt(skb, rpc) != 0)
			return;
		INC_METRIC(packets_received[DATA - DATA], 1);
		if (hsk->dead_skbs >= 2*hsk->homa->dead_buffs_limit) {
			/* We get here if neither homa_wait_for_message
			 * nor homa_timer can keep up with reaping dead
			 * RPCs. See reap.txt for details.
			 */
			uint64_t start = get_cycles();

			/* Must unlock to avoid self-deadlock in rpc_reap. */
			homa_rpc_unlock(rpc);
			rpc = NULL;
			tt_record("homa_data_pkt calling homa_rpc_reap");
			homa_rpc_reap(hsk, hsk->homa->reap_limit);
			INC_METRIC(data_pkt_reap_cycles, get_cycles() - start);
		}
		break;
	case GRANT:
		INC_METRIC(packets_received[GRANT - DATA], 1);
		homa_grant_pkt(skb, rpc);
		break;
	case RESEND:
		INC_METRIC(packets_received[RESEND - DATA], 1);
		homa_resend_pkt(skb, rpc, hsk);
		break;
	case UNKNOWN:
		INC_METRIC(packets_received[UNKNOWN - DATA], 1);
		homa_unknown_pkt(skb, rpc);
		break;
	case BUSY:
		INC_METRIC(packets_received[BUSY - DATA], 1);
		tt_record2("received BUSY for id %d, peer 0x%x",
				id, ntohl(rpc->peer->addr));
		/* Nothing to do for these packets except reset silent_ticks,
		 * which happened above.
		 */
		goto discard;
	case CUTOFFS:
		INC_METRIC(packets_received[CUTOFFS - DATA], 1);
		homa_cutoffs_pkt(skb, hsk);
		break;
	case NEED_ACK:
		INC_METRIC(packets_received[NEED_ACK - DATA], 1);
		homa_need_ack_pkt(skb, hsk, rpc);
		break;
	case ACK:
		INC_METRIC(packets_received[ACK - DATA], 1);
		homa_ack_pkt(skb, hsk, rpc);
		rpc = NULL;
		break;
	default:
		INC_METRIC(unknown_packet_types, 1);
		goto discard;
	}
	goto done;
	
    discard:
	kfree_skb(skb);
    
    done:
	if (rpc)
		homa_rpc_unlock(rpc);
}

/**
 * homa_data_pkt() - Handler for incoming DATA packets
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * @rpc:     Information about the RPC corresponding to this packet.
 * 
 * Return: Zero means the function completed successfully. Nonzero means
 * that the RPC had to be unlocked and deleted because the socket has been
 * shut down; the caller should not access the RPC anymore. Note: this method
 * may change the RPC's state to RPC_READY.
 */
int homa_data_pkt(struct sk_buff *skb, struct homa_rpc *rpc)
{
	struct homa *homa = rpc->hsk->homa;
	struct data_header *h = (struct data_header *) skb->data;
	int incoming = ntohl(h->incoming);
	
	tt_record4("incoming data packet, id %d, peer 0x%x, offset %d/%d",
			homa_local_id(h->common.sender_id),
			ntohl(rpc->peer->addr), ntohl(h->seg.offset),
			ntohl(h->message_length));
	
	if (rpc->state != RPC_INCOMING) {
		if (unlikely(!homa_is_client(rpc->id)
				|| (rpc->state == RPC_READY))) {
			kfree_skb(skb);
			return 0;			
		}
		homa_message_in_init(&rpc->msgin, ntohl(h->message_length),
				incoming);
		INC_METRIC(responses_received, 1);
		rpc->state = RPC_INCOMING;
	}
	homa_add_packet(rpc, skb);
	if (rpc->msgin.scheduled) {
		homa_check_grantable(homa, rpc);
	} else if (!rpc->msgin.extra_incoming  && rpc->msgin.bytes_remaining) {
		rpc->msgin.extra_incoming = rpc->msgin.bytes_remaining;
		atomic_add(rpc->msgin.bytes_remaining, &homa->extra_incoming);
	}
	if (rpc->active_links.next == LIST_POISON1) {
		/* This is the first packet of a server RPC, so we have to
		 * add the RPC to @hsk->active_rpcs. We do it here, rather
		 * than in homa_rpc_new_server, so we can acquire the socket
		 * lock just once to both add the RPC to active_rpcs and
		 * also add the RPC to the ready list, if appropriate.
		 */
		INC_METRIC(requests_received, 1);
		homa_sock_lock(rpc->hsk, "homa_data_pkt (first)");
		if (rpc->hsk->shutdown) {
			/* Unsafe to add new RPCs to a socket after shutdown
			 * has begun; destroy the new RPC.
			 */
			homa_message_in_destroy(&rpc->msgin);
			homa_sock_unlock(rpc->hsk);
			homa_rpc_unlock(rpc);
			kfree(rpc);
			return 1;
		}
			
		list_add_tail_rcu(&rpc->active_links, &rpc->hsk->active_rpcs);
		if (rpc->msgin.bytes_remaining == 0)
			homa_rpc_ready(rpc);
		homa_sock_unlock(rpc->hsk);
	} else {
		if (rpc->msgin.bytes_remaining == 0) {
			homa_remove_from_grantable(homa, rpc);
			homa_sock_lock(rpc->hsk, "homa_data_pkt (not first)");
			if (!rpc->hsk->shutdown)
				homa_rpc_ready(rpc);
			homa_sock_unlock(rpc->hsk);
		}
	}
	if (ntohs(h->cutoff_version) != homa->cutoff_version) {
		/* The sender has out-of-date cutoffs. Note: we may need
		 * to resend CUTOFFS packets if one gets lost, but we don't
		 * want to send multiple CUTOFFS packets when a stream of
		 * packets arrives with stale cutoff_versions. Thus, we
		 * don't send CUTOFFS unless there is a version mismatch
		 * *and* it is been a while since the previous CUTOFFS
		 * packet.
		 */
		if (jiffies != rpc->peer->last_update_jiffies) {
			struct cutoffs_header h2;
			int i;
			
			for (i = 0; i < HOMA_MAX_PRIORITIES; i++) {
				h2.unsched_cutoffs[i] =
						htonl(homa->unsched_cutoffs[i]);
			}
			h2.cutoff_version = htons(homa->cutoff_version);
			homa_xmit_control(CUTOFFS, &h2, sizeof(h2), rpc);
			rpc->peer->last_update_jiffies = jiffies;
		}
	}
	return 0;
}

/**
 * homa_grant_pkt() - Handler for incoming GRANT packets
 * @skb:     Incoming packet; size already verified large enough for header.
 *           This function now owns the packet.
 * @rpc:     Information about the RPC corresponding to this packet.
 */
void homa_grant_pkt(struct sk_buff *skb, struct homa_rpc *rpc)
{
	struct grant_header *h = (struct grant_header *) skb->data;
	
	tt_record3("processing grant for id %llu, offset %d, priority %d",
			homa_local_id(h->common.sender_id), ntohl(h->offset),
			h->priority);
	if (rpc->state == RPC_OUTGOING) {
		int new_offset = ntohl(h->offset);

		if (new_offset > rpc->msgout.granted) {
			rpc->msgout.granted = new_offset;
			if (new_offset > rpc->msgout.length)
				rpc->msgout.granted = rpc->msgout.length;
		}
		rpc->msgout.sched_priority = h->priority;
		homa_xmit_data(rpc, false);
	}
	kfree_skb(skb);
}

/**
 * homa_resend_pkt() - Handler for incoming RESEND packets
 * @skb:     Incoming packet; size already verified large enough for header.
 *           This function now owns the packet.
 * @rpc:     Information about the RPC corresponding to this packet; must
 *           be locked by caller, but may be NULL if there is no RPC matching
 *           this packet
 * @hsk:     Socket on which the packet was received.
 */
void homa_resend_pkt(struct sk_buff *skb, struct homa_rpc *rpc,
		struct homa_sock *hsk)
{
	struct resend_header *h = (struct resend_header *) skb->data;
	struct busy_header busy;
	
	if (rpc == NULL) {
		tt_record4("resend request for unknown id %d, peer 0x%x:%d, "
				"offset %d; responding with UNKNOWN",
				homa_local_id(h->common.sender_id),
				ntohl(ip_hdr(skb)->saddr),
				ntohs(h->common.sport),
				ntohl(h->offset));
		homa_xmit_unknown(skb, hsk);
		goto done;
	}
	tt_record4("resend request for id %llu, offset %d, length %d, prio %d",
			rpc->id, ntohl(h->offset), ntohl(h->length),
			h->priority);

	if (!homa_is_client(rpc->id)) {
		/* We are the server for this RPC. */
		if (rpc->state != RPC_OUTGOING) {
			tt_record2("sending BUSY from resend, id %d, state %d",
					rpc->id, rpc->state);
			homa_xmit_control(BUSY, &busy, sizeof(busy), rpc);
			goto done;
		}
	}
	if (rpc->msgout.next_packet && (homa_data_offset(rpc->msgout.next_packet)
			< rpc->msgout.granted)) {
		/* We have chosen not to transmit data from this message;
		 * send BUSY instead.
		 */
		tt_record3("sending BUSY from resend, id %d, offset %d, "
				"granted %d", rpc->id,
				homa_data_offset(rpc->msgout.next_packet),
				rpc->msgout.granted);
		homa_xmit_control(BUSY, &busy, sizeof(busy), rpc);
	} else {
		if (ntohl(h->length) == 0) {
			/* This RESEND is from a server just trying to determine
			 * whether the client still cares about the RPC; return
			 * BUSY so the server doesn't time us out.
			 */
			homa_xmit_control(BUSY, &busy, sizeof(busy), rpc);
		}
		homa_resend_data(rpc, ntohl(h->offset),
				ntohl(h->offset) + ntohl(h->length),
				h->priority);
	}
		
    done:
	kfree_skb(skb);
}

/**
 * homa_unknown_pkt() - Handler for incoming UNKNOWN packets.
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * @rpc:     Information about the RPC corresponding to this packet.
 */
void homa_unknown_pkt(struct sk_buff *skb, struct homa_rpc *rpc)
{
	tt_record3("Received unknown for id %llu, peer %x:%d",
			rpc->id, ntohl(rpc->peer->addr), rpc->dport);
	if (homa_is_client(rpc->id)) {
		if ((rpc->state == RPC_READY) || (rpc->state == RPC_DEAD)) {
			/* The missing data packets apparently arrived while
			 * the UNKNOWN was being transmitted.
			 */
			goto done;
		}
		
		if (rpc->state == RPC_OUTGOING) {
			/* It appears that everything we've already transmitted
			 * has been lost; retransmit it.
			 */
			tt_record4("Restarting id %d to server 0x%x:%d, "
					"lost %d bytes",
					rpc->id, ntohl(rpc->peer->addr),
					rpc->dport,
					homa_rpc_send_offset(rpc));
			homa_freeze(rpc, RESTART_RPC, "Freezing because of "
					"RPC restart, id %d, peer 0x%x");
			homa_resend_data(rpc, 0, homa_rpc_send_offset(rpc),
					homa_unsched_priority(rpc->hsk->homa,
					rpc->peer, rpc->msgout.length));
			goto done;
		}
		
		printk(KERN_ERR "Received unknown for RPC id %llu, peer %s:%d "
				"in bogus state %d; discarding unknown\n",
				rpc->id, homa_print_ipv4_addr(rpc->peer->addr),
				rpc->dport, rpc->state);
		tt_record4("Discarding unknown for RPC id %d, peer 0x%x:%d: "
				"bad state %d",
				rpc->id, ntohl(rpc->peer->addr), rpc->dport,
				rpc->state);
	} else {
		if (rpc->hsk->homa->verbose)
			printk(KERN_NOTICE "Freeing rpc id %llu from client "
					"%s:%d: unknown to client",
					rpc->id,
					homa_print_ipv4_addr(rpc->peer->addr),
					rpc->dport);
		homa_rpc_free(rpc);
		INC_METRIC(server_rpcs_unknown, 1);
	}
done:
	kfree_skb(skb);
}

/**
 * homa_cutoffs_pkt() - Handler for incoming CUTOFFS packets
 * @skb:     Incoming packet; size already verified large enough for header.
 *           This function now owns the packet.
 * @hsk:     Socket on which the packet was received.
 */
void homa_cutoffs_pkt(struct sk_buff *skb, struct homa_sock *hsk)
{
	int i;
	struct cutoffs_header *h = (struct cutoffs_header *) skb->data;
	struct homa_peer *peer = homa_peer_find(&hsk->homa->peers,
		ip_hdr(skb)->saddr, &hsk->inet);
	
	if (!IS_ERR(peer)) {
		peer->unsched_cutoffs[0] = INT_MAX;
		for (i = 1; i <HOMA_MAX_PRIORITIES; i++)
			peer->unsched_cutoffs[i] = ntohl(h->unsched_cutoffs[i]);
		peer->cutoff_version = h->cutoff_version;
	}
	kfree_skb(skb);
}

/**
 * homa_need_ack_pkt() - Handler for incoming NEED_ACK packets
 * @skb:     Incoming packet; size already verified large enough for header.
 *           This function now owns the packet.
 * @hsk:     Socket on which the packet was received.
 * @rpc:     The RPC named in the packet header, or NULL if no such
 *           RPC exists. The RPC has been locked by the caller.
 */
void homa_need_ack_pkt(struct sk_buff *skb, struct homa_sock *hsk,
		struct homa_rpc *rpc)
{
	struct common_header *h = (struct common_header *) skb->data;
	struct ack_header ack;
	struct homa_peer *peer;
	
	/* Return if it's not safe for the peer to purge its state
	 * for this RPC, or if we can't find peer info.
	 */
	if (rpc != NULL) {
		if (rpc->state != RPC_READY) {
			tt_record4("Ignoring NEED_ACK for id %d, peer 0x%x,"
					"state %d, bytes_remaining %d",
					rpc->id, ntohl(rpc->peer->addr),
					rpc->state, rpc->msgin.bytes_remaining);
			goto done;
		}
		peer = rpc->peer;
	} else {
		peer = homa_peer_find(&hsk->homa->peers, ip_hdr(skb)->saddr,
				&hsk->inet);
		if (IS_ERR(peer))
			goto done;
	}
	
	/* Send an ACK for this RPC. At the same time, include all of the
	 * other acks available for the peer. Note: can't use rpc below,
	 * since it may be NULL.
	 */
	ack.common.type = ACK;
	ack.common.sport = h->dport;
	ack.common.dport = h->sport;
	ack.common.sender_id = be64_to_cpu(homa_local_id(h->sender_id));
	ack.num_acks = htons(homa_peer_get_acks(peer,
			NUM_PEER_UNACKED_IDS, ack.acks));
	__homa_xmit_control(&ack, sizeof(ack), peer, hsk);
	tt_record3("Responded to NEED_ACK for id %d, peer %0x%x with %d "
			"other acks", homa_local_id(h->sender_id),
			ntohl(ip_hdr(skb)->saddr), ntohs(ack.num_acks));
	
    done:
	kfree_skb(skb);
}

/**
 * homa_ack_pkt() - Handler for incoming ACK packets
 * @skb:     Incoming packet; size already verified large enough for header.
 *           This function now owns the packet.
 * @hsk:     Socket on which the packet was received.
 * @rpc:     The RPC named in the packet header, or NULL if no such
 *           RPC exists. The RPC has been locked by the caller; this
 *           method takes ownership of the RPC and both frees and unlocks it.
 */
void homa_ack_pkt(struct sk_buff *skb, struct homa_sock *hsk,
		struct homa_rpc *rpc)
{
	struct ack_header *h = (struct ack_header *) skb->data;
	int i, count;
	
	if (rpc != NULL) {
		homa_rpc_free(rpc);
		
		/* It's awkward to unlock the RPC here, since we didn't
		 * lock it, but this is necessary because homa_rpc_acked
		 * may lock additional RPCs below and it isn't safe to hold
		 * multiple RPC locks at once.
		 */
		homa_rpc_unlock(rpc);
	}
	
	count = ntohs(h->num_acks);
	for (i = 0; i < count; i++)
		homa_rpc_acked(hsk, ip_hdr(skb)->saddr, &h->acks[i]);
	tt_record3("ACK received for id %d, peer 0x%x, with %d other acks",
			homa_local_id(h->common.sender_id),
			ntohl(ip_hdr(skb)->saddr), count);
	kfree_skb(skb);
}

/**
 * homa_check_grantable() - This function ensures that an RPC is on a
 * grantable list if appropriate, and not on one otherwise. It also adjusts
 * the position of the RPC upward on its list, if needed.
 * @homa:    Overall data about the Homa protocol implementation.
 * @rpc:     RPC to check; typically the status of this RPC has changed
 *           in a way that may affect its grantability (e.g. a packet
 *           just arrived for it). Must be locked.
 */
void homa_check_grantable(struct homa *homa, struct homa_rpc *rpc)
{
	struct homa_rpc *candidate;
	struct homa_peer *peer = rpc->peer;
	struct homa_peer *peer_cand;
	struct homa_message_in *msgin = &rpc->msgin;
	
	/* No need to do anything unless this message is ready for more
	 * grants.
	 */
	if (((rpc->msgin.incoming - (rpc->msgin.total_length
			- rpc->msgin.bytes_remaining)) >= homa->rtt_bytes)
			|| (rpc->msgin.incoming >= rpc->msgin.total_length))
		return;
	
	homa_grantable_lock(homa);
	/* Note: must check incoming again: it might have changed. */
	if ((rpc->state == RPC_DEAD) || (rpc->msgin.incoming
			>= rpc->msgin.total_length)) {
		homa_grantable_unlock(homa);
		return;
	}
	
	/* Make sure this message is in the right place in the grantable_rpcs
	 * list for its peer.
	 */
	if (list_empty(&rpc->grantable_links)) {
		/* Message not yet tracked; add it in priority order to
		 * the peer's list.
		 */
		rpc->msgin.birth = get_cycles();
		list_for_each_entry(candidate, &peer->grantable_rpcs,
				grantable_links) {
			if (candidate->msgin.bytes_remaining
					> msgin->bytes_remaining) {
				list_add_tail(&rpc->grantable_links,
						&candidate->grantable_links);
				goto position_peer;
			}
		}
		list_add_tail(&rpc->grantable_links, &peer->grantable_rpcs);
	} else while (rpc != list_first_entry(&peer->grantable_rpcs,
			struct homa_rpc, grantable_links)) {
		/* Message is on the list, but its priority may have
		 * increased because of the recent packet arrival. If so,
		 * adjust its position in the list.
		 */
		candidate = list_prev_entry(rpc, grantable_links);
		if (candidate->msgin.bytes_remaining <= msgin->bytes_remaining)
			goto position_peer;
		__list_del_entry(&candidate->grantable_links);
		list_add(&candidate->grantable_links, &rpc->grantable_links);
	}
	
    position_peer:
	/* At this point rpc is positioned correctly on the list for its peer.
	 * However, the peer may need to be added to, or moved upward on,
	 * homa->grantable_peers.
	 */
	if (list_empty(&peer->grantable_links)) {
		/* Must add peer to the overall Homa list. */
		homa->num_grantable_peers++;
		list_for_each_entry(peer_cand, &homa->grantable_peers,
				grantable_links) {
			candidate = list_first_entry(&peer_cand->grantable_rpcs,
					struct homa_rpc, grantable_links);
			if (candidate->msgin.bytes_remaining
					> msgin->bytes_remaining) {
				list_add_tail(&peer->grantable_links,
						&peer_cand->grantable_links);
				goto done;
			}
		}
		list_add_tail(&peer->grantable_links, &homa->grantable_peers);
		goto done;
	}
        /* The peer is on Homa's list, but it may need to move upward. */
        while (peer != list_first_entry(&homa->grantable_peers,
			struct homa_peer, grantable_links)) {
		struct homa_peer *prev_peer = list_prev_entry(
			peer, grantable_links);
		candidate = list_first_entry(&prev_peer->grantable_rpcs,
				struct homa_rpc, grantable_links);
		if (candidate->msgin.bytes_remaining <= msgin->bytes_remaining)
			goto done;
		__list_del_entry(&prev_peer->grantable_links);
		list_add(&prev_peer->grantable_links, &peer->grantable_links);
	}
				
    done:
	homa_grantable_unlock(homa);
}

/**
 * homa_send_grants() - This function checks to see whether it is
 * appropriate to send grants and, if so, it sends them.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_send_grants(struct homa *homa)
{
	/* The overall goal is to keep homa->max_incoming bytes of data on
	 * their way to us at any given time. Ideally, each message should use
	 * a different priority level, determined by bytes_remaining (fewest
	 * bytes_remaining gets the highest priority). If there aren't enough
	 * scheduled priority levels for all of the messages, then the lowest
	 * level gets shared by multiple messages. If there are fewer messages
	 * than priority levels, then we use the lowest available levels
	 * (new higher-priority messages can use the higher levels to achieve
	 * instantaneous preemption).
	 */
	struct homa_rpc *candidate;
	struct homa_peer *peer, *temp;
	int rank, i;
	__u64 start;
	
	/* The variables below keep track of grants we need to send;
	 * don't send any until the very end, and release the lock
	 * first.
	 */
	/* How many more bytes of incoming are available below the limit. */
	int available = homa->max_incoming - atomic_read(&homa->extra_incoming);
#ifdef __UNIT_TEST__
	extern int mock_max_grants;
#define MAX_GRANTS mock_max_grants
#else
#define MAX_GRANTS 10
#endif
	struct grant_header grants[MAX_GRANTS];
	struct homa_rpc *rpcs[MAX_GRANTS];
	int num_grants = 0;
	
	/* Make a local copy of homa->grantable_peers, since that variable
	 * could change during this function.
	 */
	int num_grantable_peers = homa->num_grantable_peers;
	
	if (list_empty(&homa->grantable_peers))
		return;
	
	start = get_cycles();
	homa_grantable_lock(homa);
	
	/* See if there are any messages that deserve a grant (they have
	 * fewer than homa->rtt_bytes of data in transit). Consider only
	 * a single (highest-priority) entry for each peer.
	 */
	rank = 0;
	list_for_each_entry_safe(peer, temp, &homa->grantable_peers,
			grantable_links) {
		int extra_levels, priority;
		int received, new_grant, on_the_way;
		int old_incoming;
		struct grant_header *grant;

		rank++;
		candidate = list_first_entry(&peer->grantable_rpcs,
				struct homa_rpc, grantable_links);
		
		/* Invariant: candidate msgin's incoming < total_length
		 * (otherwise it won't be on this list).
		 */
		received = (candidate->msgin.total_length
				- candidate->msgin.bytes_remaining);
		on_the_way = candidate->msgin.incoming - received;
		available -= on_the_way;
		if (on_the_way >= homa->grant_threshold)
			continue;
		old_incoming = candidate->msgin.incoming;
		new_grant = old_incoming + homa->grant_increment;
		if ((received + homa->rtt_bytes) > new_grant)
			new_grant = received + homa->rtt_bytes;
		if (new_grant > candidate->msgin.total_length)
			new_grant = candidate->msgin.total_length;
		available -= new_grant - candidate->msgin.incoming;
		if (available < 0)
			break;
		
		/* The following line is needed to prevent spurious resends.
		 * Without it, if the timer fires right after we send the
		 * grant, it might think the RPC is slow and request a
		 * resend (until we send the grant, timeouts won't occur
		 * because there's no granted data).
		 */
		candidate->silent_ticks = 0;
		
		/* Send a grant for this message. */
		candidate->msgin.incoming = new_grant;
		homa->grant_nonfifo_left -= (new_grant - old_incoming);
		atomic_inc(&candidate->grants_in_progress);
		rpcs[num_grants] = candidate;
		grant = &grants[num_grants];
		num_grants++;
		grant->offset = htonl(new_grant);
		priority = homa->max_sched_prio - (rank - 1);
		extra_levels = homa->max_sched_prio + 1 - num_grantable_peers;
		if (extra_levels >= 0)
			priority -= extra_levels;
		if (priority < 0)
			priority = 0;
		grant->priority = priority;
		tt_record3("sending grant for id %llu, offset %d, priority %d",
				candidate->id, new_grant, priority);
		if (new_grant == candidate->msgin.total_length) {
			BUG_ON(candidate->msgin.extra_incoming != 0);
			candidate->msgin.extra_incoming =
					candidate->msgin.bytes_remaining;
			atomic_add(candidate->msgin.extra_incoming,
					&homa->extra_incoming);
			homa_remove_grantable_locked(homa, candidate);
		}
		if (num_grants == MAX_GRANTS)
			break;
	}
	
	if (homa->grant_nonfifo_left <= 0) {
		homa->grant_nonfifo_left += homa->grant_nonfifo;
		if ((num_grantable_peers > homa->max_overcommit)
				&& homa->grant_fifo_fraction)
			homa_grant_fifo(homa);
	}
	
	homa_grantable_unlock(homa);
	
	/* By sending grants without holding grantable_lock here, we reduce
	 * contention on that lock significantly. This only works because
	 * rpc->grants_in_progress keeps the RPC from being deleted out from
	 * under us.
	 */
	for (i = 0; i < num_grants; i++) {
		/* Send any accumulated grants (ignore errors). */
		BUG_ON(rpcs[i]->magic != HOMA_RPC_MAGIC);
		homa_xmit_control(GRANT, &grants[i], sizeof(grants[i]),
			rpcs[i]);
		atomic_dec(&rpcs[i]->grants_in_progress);
	}
	INC_METRIC(grant_cycles, get_cycles() - start);
}

/**
 * homa_grant_fifo() - This function is invoked occasionally to give
 * a high-priority grant to the oldest incoming message. We do this in
 * order to reduce the starvation that SRPT can cause for long messages.
 * @homa:    Overall data about the Homa protocol implementation. The
 *           grantable_lock must be held by the caller.
 */
void homa_grant_fifo(struct homa *homa)
{
	struct homa_rpc *candidate, *oldest;
	__u64 oldest_birth;
	struct homa_peer *peer;
	struct grant_header grant;
	
	oldest = NULL;
	oldest_birth = ~0;
	
	/* Find the oldest message that doesn't currently have an
	 * outstanding "pity grant".
	 */
	list_for_each_entry(peer, &homa->grantable_peers, grantable_links) {
		list_for_each_entry(candidate, &peer->grantable_rpcs,
				grantable_links) {
			int received, on_the_way;
			
			if (candidate->msgin.birth >= oldest_birth)
				continue;
			
			received = (candidate->msgin.total_length
					- candidate->msgin.bytes_remaining);
			on_the_way = candidate->msgin.incoming - received;
			if (on_the_way >= (homa->rtt_bytes
					+ homa->grant_increment)) {
				/* The last "pity" grant hasn't been used
				 * up yet.
				 */
				continue;
			}
			oldest = candidate;
			oldest_birth = candidate->msgin.birth;
		}
	}
	if (oldest == NULL)
		return;
	INC_METRIC(fifo_grants, 1);
	if ((oldest->msgin.total_length - oldest->msgin.bytes_remaining)
			== oldest->msgin.incoming)
		INC_METRIC(fifo_grants_no_incoming, 1);
	
	oldest->silent_ticks = 0;
	oldest->msgin.incoming += homa->grant_increment;
	if (oldest->msgin.incoming >= oldest->msgin.total_length) {
		oldest->msgin.incoming = oldest->msgin.total_length;
		oldest->msgin.extra_incoming =
				oldest->msgin.bytes_remaining;
		atomic_add(oldest->msgin.extra_incoming,
				&homa->extra_incoming);
		homa_remove_grantable_locked(homa, oldest);
	}
	grant.offset = htonl(oldest->msgin.incoming);
	grant.priority = homa->max_sched_prio;
	tt_record3("sending fifo grant for id %llu, offset %d, priority %d",
			oldest->id, oldest->msgin.incoming,
			homa->max_sched_prio);
	homa_xmit_control(GRANT, &grant, sizeof(grant), oldest);
}

/**
 * homa_remove_grantable_locked() - This method does all the real work of
 * homa_remove_from_grantable, but it assumes that the caller holds the
 * grantable lock, so it can be used by other functions that already
 * hold the lock.
 * @homa:    Overall data about the Homa protocol implementation.
 * @rpc:     RPC that is no longer grantable. Must be locked, and must
 *           currently be linked into grantable lists.
 */
void homa_remove_grantable_locked(struct homa *homa, struct homa_rpc *rpc)
{
	struct homa_rpc *head;
	struct homa_peer *peer = rpc->peer;
	struct homa_rpc *candidate;

	rpc->msgin.possibly_in_grant_queue = 0;
	head =  list_first_entry(&peer->grantable_rpcs,
			struct homa_rpc, grantable_links);
	list_del_init(&rpc->grantable_links);
	if (rpc != head)
		return;
	
	/* The removed RPC was at the front of the peer's list. This means
	 * we may have to adjust the position of the peer in Homa's list,
	 * or perhaps remove it.
	 */
	if (list_empty(&peer->grantable_rpcs)) {
		homa->num_grantable_peers--;
		list_del_init(&peer->grantable_links);
		return;
	}
	
	/* The peer may have to move down in Homa's list (removal of
	 * an RPC can't cause the peer to move up).
	 */
	head =  list_first_entry(&peer->grantable_rpcs,
			struct homa_rpc, grantable_links);
        while (peer != list_last_entry(&homa->grantable_peers, struct homa_peer,
			grantable_links)) {
		struct homa_peer *next_peer = list_next_entry(
				peer, grantable_links);
		candidate = list_first_entry(&next_peer->grantable_rpcs,
				struct homa_rpc, grantable_links);
		if (candidate->msgin.bytes_remaining
				> head->msgin.bytes_remaining)
			break;
		__list_del_entry(&peer->grantable_links);
		list_add(&peer->grantable_links, &next_peer->grantable_links);
	}
}

/**
 * homa_remove_from_grantable() - This method ensures that an RPC
 * is no longer linked into peer->grantable_rpcs (i.e. it won't be
 * visible to homa_manage_grants).
 * @homa:    Overall data about the Homa protocol implementation.
 * @rpc:     RPC that is being destroyed. Must be locked.
 */
void homa_remove_from_grantable(struct homa *homa, struct homa_rpc *rpc)
{
	UNIT_LOG("; ", "homa_remove_from_grantable invoked");
	if (rpc->msgin.total_length >= 0) {
		if (rpc->msgin.possibly_in_grant_queue) {
			homa_grantable_lock(homa);
			if (!list_empty(&rpc->grantable_links)) {
				homa_remove_grantable_locked(homa, rpc);
				homa_grantable_unlock(homa);
				homa_send_grants(homa);
			} else
				homa_grantable_unlock(homa);
		}
		if (rpc->msgin.extra_incoming) {
			atomic_sub(rpc->msgin.extra_incoming,
					&homa->extra_incoming);
			BUG_ON(atomic_read(&homa->extra_incoming) < 0);
			rpc->msgin.extra_incoming = 0;
		}
	}
}

/**
 * homa_log_grantable_list() - Print information about the entries on the
 * grantable list to the kernel log. This is intended for debugging use
 * via the log_topic sysctl parameter.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_log_grantable_list(struct homa *homa)
{
	int bucket, count;
	struct homa_peer *peer, *peer2;
	struct homa_rpc *rpc;
	
	printk(KERN_NOTICE "Logging Homa grantable list\n");
	homa_grantable_lock(homa);
	for (bucket = 0; bucket < HOMA_PEERTAB_BUCKETS; bucket++) {
		hlist_for_each_entry_rcu(peer, &homa->peers.buckets[bucket],
				peertab_links) {
			printk(KERN_NOTICE "Checking peer %s\n",
					homa_print_ipv4_addr(peer->addr));
			if (list_empty(&peer->grantable_rpcs))
				continue;
			count = 0;
			list_for_each_entry(rpc, &peer->grantable_rpcs,
					grantable_links) {
				count++;
				if (count > 10)
					continue;
				homa_rpc_log(rpc);
			}
			printk(KERN_NOTICE "Peer %s has %d grantable RPCs\n",
					homa_print_ipv4_addr(peer->addr),
					count);
			list_for_each_entry(peer2, &homa->grantable_peers,
					grantable_links) {
				if (peer2 == peer)
					goto next_peer;
			}
			printk(KERN_NOTICE "Peer %s has grantable RPCs but "
					"isn't on homa->grantable_peers\n",
					homa_print_ipv4_addr(peer->addr));
			next_peer:
			continue;
		}
	}
	homa_grantable_unlock(homa);
	printk(KERN_NOTICE "Finished logging Homa grantable list\n");
}

/**
 * homa_rpc_abort() - Terminate an RPC and arrange for an error to be returned
 * to the application.
 * @crpc:    RPC to be terminated. Must be a client RPC.
 * @error:   A negative errno value indicating the error that caused the abort.
 */
void homa_rpc_abort(struct homa_rpc *crpc, int error)
{
	homa_remove_from_grantable(crpc->hsk->homa, crpc);
	crpc->error = error;
	homa_sock_lock(crpc->hsk, "homa_rpc_abort");
	if (!crpc->hsk->shutdown)
		homa_rpc_ready(crpc);
	homa_sock_unlock(crpc->hsk);
}

/**
 * homa_abort_rpcs() - Abort all RPCs to/from a particular peer.
 * @homa:    Overall data about the Homa protocol implementation.
 * @addr:    Address (network order) of the destination whose RPCs are
 *           to be aborted.
 * @port:    If nonzero, then RPCs will only be aborted if they were
 *	     targeted at this server port.
 * @error:   Negative errno value indicating the reason for the abort.
 */
void homa_abort_rpcs(struct homa *homa, __be32 addr, int port, int error)
{
	struct homa_socktab_scan scan;
	struct homa_sock *hsk;
	struct homa_rpc *rpc, *tmp;
	
	rcu_read_lock();
	for (hsk = homa_socktab_start_scan(&homa->port_map, &scan);
			hsk !=  NULL; hsk = homa_socktab_next(&scan)) {
		/* Skip the (expensive) lock acquisition if there's no
		 * work to do.
		 */
		if (list_empty(&hsk->active_rpcs))
			continue;
		if (!homa_protect_rpcs(hsk))
			continue;
		list_for_each_entry_safe(rpc, tmp, &hsk->active_rpcs,
				active_links) {
			if (rpc->peer->addr != addr)
				continue;
			if ((port != 0) && (rpc->dport != port))
				continue;
			homa_rpc_lock(rpc);
			if ((rpc->state == RPC_DEAD)
					|| (rpc->state == RPC_READY)) {
				homa_rpc_unlock(rpc);
				continue;
			}
			if (homa_is_client(rpc->id)) {
				tt_record3("aborting client RPC: peer 0x%x, "
						"id %u, error %d",
						ntohl(rpc->peer->addr),
						rpc->id, error);
				homa_rpc_abort(rpc, error);
			} else {
				INC_METRIC(server_rpc_discards, 1);
				tt_record3("discarding server RPC: peer 0x%x, "
						"id %d, error %d",
						ntohl(rpc->peer->addr),
						rpc->id, error);
				homa_rpc_free(rpc);
			}
			homa_rpc_unlock(rpc);
		}
		homa_unprotect_rpcs(hsk);
	}
	rcu_read_unlock();
}

/**
 * homa_register_interests() - Records information in various places so
 * that a thread will be woken up if an RPC that it cares about becomes
 * available.
 * @interest:     Used to record information about the messages this thread is
 *                waiting on. The initial contents of the structure are
 *                assumed to be undefined.
 * @hsk:          Socket on which relevant messages will arrive.  Must not be
 *                locked.
 * @flags:        Flags parameter from homa_recv; see manual entry for details. 
 * @id:           If non-zero, then a message will not be returned unless its
 *                RPC id matches this.
 * @client_addr:  Used in conjunction with @id to select a specific message
 *                if we are server for id. If we're the client for id, then
 *                id is already unique, so this argument is ignored.
 * Return:        Either zero or a negative errno value. If a matching RPC
 *                is already available, information about it will be stored in
 *                interest.
 */
int homa_register_interests(struct homa_interest *interest,
		struct homa_sock *hsk, int flags, __u64 id,
		struct sockaddr_in *client_addr)
{
	struct homa_rpc *rpc = NULL;
	
	interest->thread = current;
	interest->ready_rpc = NULL;
	atomic_long_set(&interest->id, 0);
	interest->reg_rpc = NULL;
	interest->request_links.next = LIST_POISON1;
	interest->response_links.next = LIST_POISON1;
	
	/* Need both the RPC lock and the socket lock to avoid races. */
	if (id != 0) {
		if (homa_is_client(id))
			rpc = homa_find_client_rpc(hsk, id);
		else
			rpc = homa_find_server_rpc(hsk,
					client_addr->sin_addr.s_addr,
					ntohs(client_addr->sin_port), id);
		if (rpc == NULL)
			return -EINVAL;
		if ((rpc->interest != NULL) && (rpc->interest != interest)) {
			homa_rpc_unlock(rpc);
			return -EINVAL;
		}
	}
	homa_sock_lock(hsk, "homa_register_interests");
	if (hsk->shutdown) {
		homa_sock_unlock(hsk);
		if (rpc)
			homa_rpc_unlock(rpc);
		return -ESHUTDOWN;
	}
	
	if (id != 0) {
		if ((rpc->state == RPC_READY)|| (rpc->state == RPC_IN_SERVICE)) {
			interest->ready_rpc = rpc;
			
			/* Must also fill in interest->id; otherwise, some
			 * other RPC might also get assigned to this interest
			 * when we release the socket lock.
			 */
			goto claim_rpc;
		}
		rpc->interest = interest;
		interest->reg_rpc = rpc;
		homa_rpc_unlock(rpc);
	}
	
	if (flags & HOMA_RECV_RESPONSE) {
		if (!list_empty(&hsk->ready_responses)) {
			rpc = list_first_entry(
					&hsk->ready_responses,
					struct homa_rpc,
					ready_links);
			goto claim_rpc;
		}
		/* Insert this thread at the *front* of the list;
		 * we'll get better cache locality if we reuse
		 * the same thread over and over, rather than
		 * round-robining between threads.  Same below.
		 */
		list_add(&interest->response_links,
				&hsk->response_interests);
	}
	if (flags & HOMA_RECV_REQUEST) {
		if (!list_empty(&hsk->ready_requests)) {
			rpc = list_first_entry(&hsk->ready_requests,
					struct homa_rpc, ready_links);
			/* Make sure the interest isn't on the response list;
			 * otherwise it might receive a second RPC.
			 */
			if (interest->response_links.next != LIST_POISON1)
				list_del(&interest->response_links);
			goto claim_rpc;
		}
		list_add(&interest->request_links, &hsk->request_interests);
	}
	goto done;
	
    claim_rpc:
	homa_interest_set(interest, rpc);
	list_del_init(&rpc->ready_links);
	if (!list_empty(&hsk->ready_requests) ||
			!list_empty(&hsk->ready_responses)) {
		// There are still more RPCs available, so let Linux know.
		struct sock *sk = (struct sock *) hsk;
		sk->sk_data_ready(sk);
	}
	
    done:
	homa_sock_unlock(hsk);
	return 0;
}

/**
 * @homa_wait_for_message() - Wait for an appropriate incoming message.
 * @hsk:          Socket where messages will arrive.
 * @flags:        Flags parameter from homa_recv; see manual entry for details.
 * @id:           If non-zero, then a response message will not be returned
 *                unless its RPC id matches this.
 * @client_addr:  Used in conjunction with @id to select a specific message.
 *                If the host address is zero, then @id refers to an
 *                outgoing request where we are the client; otherwise the
 *                desired RPC is one where we are the server and this
 *                identifies the client for the request.
 *
 * Return:   Pointer to an RPC that matches @flags and @id, or a negative
 *           errno value. The RPC will be locked; the caller must unlock.
 */
struct homa_rpc *homa_wait_for_message(struct homa_sock *hsk, int flags,
		__u64 id, struct sockaddr_in *client_addr)
{
	struct homa_rpc *result = NULL;
	struct homa_interest interest;
	uint64_t poll_start, now;
	int error;
	
	/* Normally this loop only gets executed once, but we may have
	 * to start again under various special cases such as a "found"
	 * RPC gets deleted from underneath us.
	 */
	while (1) {
		error = homa_register_interests(&interest, hsk, flags, id,
				client_addr);
		if (atomic_long_read(&interest.id)) {
			goto got_error_or_rpc;
		}
		if (error < 0) {
			result = ERR_PTR(error);
			goto got_error_or_rpc;
		}
		
//		tt_record3("Preparing to poll, socket %d, flags 0x%x, pid %d",
//				hsk->client_port, flags, current->pid);
		
	        /* There is no ready RPC so far. Clean up dead RPCs before
		 * going to sleep (or returning, if in nonblocking mode).
		 */
		while (1) {
			int reaper_result;
			if (atomic_long_read(&interest.id)) {
				tt_record1("received message while reaping, "
						"id %d",
						atomic_long_read(&interest.id));
				goto got_error_or_rpc;
			}
			reaper_result = homa_rpc_reap(hsk,
					hsk->homa->reap_limit);
			if (reaper_result == 0)
				break;
			
			/* Give NAPI and SoftIRQ tasks a chance to run. */
			schedule();
		}
		if (flags & HOMA_RECV_NONBLOCKING) {
			result = ERR_PTR(-EAGAIN);
			goto got_error_or_rpc;
		}
		
		/* Busy-wait for a while before going to sleep; this avoids
		 * context-switching overhead to wake up.
		 */
		poll_start = get_cycles();
		while (1) {
			now = get_cycles();
			if (atomic_long_read(&interest.id)) {
				tt_record3("received message while polling, "
						"id %d, socket %d, pid %d",
						atomic_long_read(&interest.id),
						hsk->port, current->pid);
				INC_METRIC(fast_wakeups, 1);
				INC_METRIC(poll_cycles, now - poll_start);
				goto got_error_or_rpc;
			}
			if (now >= (poll_start + hsk->homa->poll_cycles))
				break;
			schedule();
		}
		tt_record2("Poll ended unsuccessfully on socket %d, pid %d",
				hsk->port, current->pid);
		INC_METRIC(poll_cycles, now - poll_start);
		
		/* Now it's time to sleep. */
		set_current_state(TASK_INTERRUPTIBLE);
		tt_record1("homa_wait_for_message sleeping, pid %d",
				current->pid);
		if (!atomic_long_read(&interest.id) && !hsk->shutdown) {
			__u64 start = get_cycles();
			schedule();
			INC_METRIC(blocked_cycles, get_cycles() - start);
		}
		__set_current_state(TASK_RUNNING);
		INC_METRIC(slow_wakeups, 1);
		tt_record2("homa_wait_for_message woke up, id %d, "
				"pid %d",
				atomic_long_read(&interest.id),
				current->pid);
		
got_error_or_rpc:
		/* If we get here, it means we are probably ready to return,
		 * either with an RPC or with an error.
		 * 
		 * First, clean up all of the interests. Must do this before
		 * making any other decisions, because until we do, an incoming
		 * message could still be passed to us. Note: if we went to
		 * sleep, then this info was already cleaned up by whoever
		 * woke us up. Also, values in the interest may change between
		 * when we test them below and when we acquire the socket lock.
		 */
		if ((interest.reg_rpc)
				|| (interest.request_links.next != LIST_POISON1)
				|| (interest.response_links.next
				!= LIST_POISON1)) {
			homa_sock_lock(hsk, "homa_wait_for_message");
			if (interest.reg_rpc)
				interest.reg_rpc->interest = NULL;
			if (interest.request_links.next != LIST_POISON1)
				list_del(&interest.request_links);
			if (interest.response_links.next != LIST_POISON1)
				list_del(&interest.response_links);
			homa_sock_unlock(hsk);
		}
		
		/* Now check to see if we got a message to return (note that
		 * the message could have arrived anytime up until we
		 * reset the interest above).
		 */
		if (interest.ready_rpc)
			return interest.ready_rpc;
		if (atomic_long_read(&interest.id)) {
			/* RPC isn't currently locked; lock it now. */
			struct homa_rpc *rpc;
			if (homa_is_client(atomic_long_read(&interest.id)))
				rpc = homa_find_client_rpc(hsk,
						atomic_long_read(&interest.id));
			else
				rpc = homa_find_server_rpc(hsk,
						interest.peer_addr,
						interest.peer_port,
						atomic_long_read(&interest.id));
			if (rpc)
				return rpc;
			
			/* If we get here, it means the RPC was deleted after
			 * it was passed to us, so we don't have an RPC after
			 * all.
			 */
			UNIT_LOG("; ", "RPC appears to have been deleted");
		}

		/* No message available: see if there is an error condition. */
		if (IS_ERR(result))
			return result;
		if (signal_pending(current))
			return ERR_PTR(-EINTR);

                /* No message and no error after all (perhaps RPC was deleted);
		 * try again.
		 */
	}
}

/**
 * @homa_rpc_ready: This function is called when the input message for
 * an RPC becomes complete. It marks the RPC as READY and either notifies
 * a waiting reader or queues the RPC. It also starts the process of acking
 * the RPC to its server.
 * @rpc:                RPC that now has a complete input message;
 *                      must be locked. The caller must also have
 *                      locked the socket for this RPC.
 */
void homa_rpc_ready(struct homa_rpc *rpc)
{
	struct homa_interest *interest;
	struct homa_sock *hsk = rpc->hsk;
	struct sock *sk;
	
	rpc->state = RPC_READY;
	
	/* First, see if someone is interested in this RPC specifically.
	 */
	if (rpc->interest) {
		interest = rpc->interest;
		goto handoff;
	}
	
	/* Second, check the interest list for this type of RPC. */
	if (homa_is_client(rpc->id)) {
		interest = list_first_entry_or_null(
				&hsk->response_interests,
				struct homa_interest, response_links);
		if (interest)
			goto handoff;
		list_add_tail(&rpc->ready_links, &hsk->ready_responses);
		INC_METRIC(responses_queued, 1);
	} else {
		interest = list_first_entry_or_null(
				&hsk->request_interests,
				struct homa_interest, request_links);
		if (interest)
			goto handoff;
		list_add_tail(&rpc->ready_links, &hsk->ready_requests);
		INC_METRIC(requests_queued, 1);
	}
	
	/* If we get here, no-one is waiting for the RPC, so it has been
	 * queued.
	 */
	
	/* Notify the poll mechanism. */
	sk = (struct sock *) hsk;
	sk->sk_data_ready(sk);
	tt_record2("homa_rpc_ready finished queuing id %d for port %d",
			rpc->id, hsk->port);
	goto done;
	
handoff:
	/* We found a waiting thread. Wakeup the thread and cleanup its
	 * interest info, so it won't have to acquire the socket lock
	 * again. This is also needed so no-one else attempts to give
	 * this interest an RPC.
	 */
		
	/* The following line must be here, before resetting the interests,
	 * in order to avoid a race with homa_wait_for_message (which
	 * may not acquire the socket lock).
	 */
	homa_interest_set(interest, rpc);
	wake_up_process(interest->thread);
	if (interest->reg_rpc) {
		interest->reg_rpc->interest = NULL;
		interest->reg_rpc = NULL;
	}
	if (interest->request_links.next != LIST_POISON1)
		list_del(&interest->request_links);
	if (interest->response_links.next != LIST_POISON1)
		list_del(&interest->response_links);
	tt_record3("homa_rpc_ready handed off id %d to pid %d on core %d",
			rpc->id, interest->thread->pid,
			task_cpu(interest->thread));

done:
	/* It's now safe to ACK this RPC. */
	if (homa_is_client(rpc->id))
		homa_peer_add_ack(rpc);
}

/**
 * homa_incoming_sysctl_changed() - Invoked whenever a sysctl value is changed;
 * any input-related parameters that depend on sysctl-settable values.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_incoming_sysctl_changed(struct homa *homa)
{
	__u64 tmp;
	
	homa->max_incoming = homa->max_overcommit * homa->rtt_bytes;
	
	if (homa->grant_fifo_fraction > 500)
		homa->grant_fifo_fraction = 500;
	tmp = homa->grant_fifo_fraction;
	if (tmp != 0)
		tmp = (1000*homa->grant_increment)/tmp - homa->grant_increment;
	homa->grant_nonfifo = tmp;
		
	/* Code below is written carefully to avoid integer underflow or
	 * overflow under expected usage patterns. Be careful when changing!
	 */
	tmp = homa->poll_usecs;
	tmp = (tmp*cpu_khz)/1000;
	homa->poll_cycles = tmp;
	
	tmp = homa->rtt_bytes * homa->duty_cycle;
	homa->grant_threshold = tmp/1000;
	if (homa->grant_threshold > homa->rtt_bytes)
		homa->grant_threshold = homa->rtt_bytes;
}