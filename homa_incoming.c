/* Copyright (c) 2019-2020 Stanford University
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
	msgin->priority = 0;
	msgin->scheduled = length > incoming;
	msgin->possibly_in_grant_queue = msgin->scheduled;
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
 * @msgin: Overall information about the incoming message.
 * @skb:   The new packet. This function takes ownership of the packet
 *         and will free it, if it doesn't get added to msgin (because
 *         it provides no new data).
 */
void homa_add_packet(struct homa_message_in *msgin, struct sk_buff *skb)
{
	struct data_header *h = (struct data_header *) skb->data;
	int offset = ntohl(h->seg.offset);
	int data_bytes = ntohl(h->seg.segment_length);
	struct sk_buff *skb2;
	
	/* Any data from the packet with offset less than this is
	 * of no value.*/
	int floor = 0;
	
	/* Any data with offset >= this is useless. */
	int ceiling = msgin->total_length;
	
	/* Figure out where in the list of existing packets to insert the
	 * new one. It doesn't necessarily go at the end, but it almost
	 * always will in practice, so work backwards from the end of the
	 * list.
	 */
	skb_queue_reverse_walk(&msgin->packets, skb2) {
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
	__skb_insert(skb, skb2, skb2->next, &msgin->packets);
	msgin->bytes_remaining -= (ceiling - floor);
	msgin->num_skbs++;
}

/**
 * homa_message_in_copy_data() - Extract the data from an incoming message
 * and copy it to buffer(s) in user space.
 * @msgin:      The message whose data should be extracted.
 * @iter:       Describes the available buffer space at user-level; message
 *              data gets copied here.
 * @max_bytes:  Total amount of space available via iter.
 * 
 * Return:      The number of bytes copied, or a negative errno.
 */
int homa_message_in_copy_data(struct homa_message_in *msgin,
		struct iov_iter *iter, int max_bytes)
{
	struct sk_buff *skb;
	int offset;
	int err;
	int remaining = max_bytes;
	
	/* Do the right thing even if packets have overlapping ranges.
	 * In practice, this shouldn't ever be necessary.
	 */
	offset = 0;
	skb_queue_walk(&msgin->packets, skb) {
		struct data_header *h = (struct data_header *) skb->data;
		int this_offset = ntohl(h->seg.offset);
		int data_in_packet;
		int this_size = msgin->total_length - offset;
		
		data_in_packet = skb->len - sizeof32(struct data_header);
		if (this_size > data_in_packet) {
			this_size = data_in_packet;
		}
		if (offset > this_offset) {
			this_size -= (offset - this_offset);
		}
		if (this_size > remaining) {
			this_size =  remaining;
		}
		err = skb_copy_datagram_iter(skb,
				sizeof(*h) + (offset - this_offset),
				iter, this_size);
		if (err) {
			return err;
		}
		remaining -= this_size;
		offset += this_size;
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
	
	/* Find and lock the RPC for this packet. */
	if (ntohs(h->dport) < HOMA_MIN_CLIENT_PORT) {
		/* We are the server for this RPC. */
		if ((h->type == DATA)
				&& !((struct data_header *) h)->retransmit) {
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
					ntohs(h->sport), h->id);
			
	} else {
		rpc = homa_find_client_rpc(hsk, h->id);
	}
	if (unlikely(rpc == NULL)) {
		if (hsk->homa->verbose) {
			char buffer[200];
			printk(KERN_NOTICE
					"Incoming packet for unknown RPC: %s\n",
					homa_print_packet(skb, buffer,
					sizeof(buffer)));
		}
		if (h->type != CUTOFFS) {
			if (h->type == RESEND)
				homa_xmit_unknown(skb, hsk);
			tt_record4("Discarding packet for unknown RPC, id %u, "
					"type %d, peer 0x%x:%d",
					h->id & 0xffffffff, h->type,
					ntohl(ip_hdr(skb)->saddr),
					ntohs(h->sport));
			if ((h->type != GRANT) || (ntohs(h->dport)
					>= HOMA_MIN_CLIENT_PORT))
				INC_METRIC(unknown_rpcs, 1);
			goto discard;
		}
	} else {
		__u16 pkt_generation = ntohs(h->generation);
		BUG_ON(rpc->state == RPC_DEAD);
		if (pkt_generation != rpc->generation) {
			if (!rpc->is_client && (pkt_generation
					> rpc->generation))
				rpc->generation = pkt_generation;
			else {
				tt_record4("Discarding packet because of "
						"stale generation: id %d, "
						"peer 0x%x:%d, type %d",
						rpc->id, ntohl(rpc->peer->addr),
						ntohs(h->sport), h->type);
				INC_METRIC(stale_generations, 1);
				goto discard;
			}
		}
		rpc->silent_ticks = 0;
		rpc->peer->outstanding_resends = 0;
	}
	
	switch (h->type) {
	case DATA:
		INC_METRIC(packets_received[DATA - DATA], 1);
		if (homa_data_pkt(skb, rpc) != 0)
			return;
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
				h->id, ntohl(rpc->peer->addr));
		/* Nothing to do for these packets except reset silent_ticks,
		 * which happened above.
		 */
		goto discard;
	case CUTOFFS:
		INC_METRIC(packets_received[CUTOFFS - DATA], 1);
		homa_cutoffs_pkt(skb, hsk);
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
			h->common.id, ntohl(rpc->peer->addr),
			ntohl(h->seg.offset), ntohl(h->message_length));

	if (rpc->state != RPC_INCOMING) {
		if (unlikely(!rpc->is_client || (rpc->state == RPC_READY))) {
			
			kfree_skb(skb);
			return 0;			
		}
		homa_message_in_init(&rpc->msgin, ntohl(h->message_length),
				incoming);
		INC_METRIC(responses_received, 1);
		rpc->state = RPC_INCOMING;
	} else {
		if (incoming > rpc->msgin.incoming) {
			if (incoming > rpc->msgin.total_length)
				rpc->msgin.incoming = rpc->msgin.total_length;
			else
				rpc->msgin.incoming = incoming;
		}
	}
	homa_add_packet(&rpc->msgin, skb);
	if (rpc->msgin.scheduled)
		homa_check_grantable(homa, rpc);
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
			h->common.id, ntohl(h->offset), h->priority);
	if (rpc->state == RPC_OUTGOING) {
		int new_offset = ntohl(h->offset);

		if (new_offset > rpc->msgout.granted) {
			rpc->msgout.granted = new_offset;
			if (new_offset > rpc->msgout.length)
				rpc->msgout.granted = rpc->msgout.length;
		}
		rpc->msgout.sched_priority = h->priority;
		homa_xmit_data(rpc, false);
		if (!rpc->msgout.next_packet && !rpc->is_client) {
			/* This is a server RPC that has been completely sent;
			 * time to delete the RPC.
			 */
			homa_rpc_free(rpc);
		}
	}
	kfree_skb(skb);
}

/**
 * homa_resend_pkt() - Handler for incoming RESEND packets
 * @skb:     Incoming packet; size already verified large enough for header.
 *           This function now owns the packet.
 * @rpc:     Information about the RPC corresponding to this packet; must
 *           be locked by caller.
 * @hsk:     Socket on which the packet was received.
 */
void homa_resend_pkt(struct sk_buff *skb, struct homa_rpc *rpc,
		struct homa_sock *hsk)
{
	struct resend_header *h = (struct resend_header *) skb->data;
	struct busy_header busy;
	tt_record4("resend request for id %llu, offset %d, length %d, prio %d",
			h->common.id, ntohl(h->offset), ntohl(h->length),
			h->priority);

	if (!rpc->is_client) {
		/* We are the server for this RPC. */
		if (rpc->state != RPC_OUTGOING) {
			tt_record1("sending BUSY from resend, state %d",
					rpc->state);
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
	int err;
	tt_record3("Received unknown for id %llu, peer %x:%d", rpc->id,
			ntohl(rpc->peer->addr), rpc->dport);\
	if (rpc->is_client) {
		if (rpc->hsk->homa->verbose)
			printk(KERN_NOTICE "Restarting rpc to server %s:%d, "
					"id %llu",
					homa_print_ipv4_addr(rpc->peer->addr),
					rpc->dport, rpc->id);
		tt_record3("Restarting id %d to server 0x%x:%d",
				rpc->id, ntohl(rpc->peer->addr), rpc->dport);
		INC_METRIC(restarted_rpcs, 1);
		if (rpc->state != RPC_READY) {
			homa_remove_from_grantable(rpc->hsk->homa, rpc);
			homa_message_in_destroy(&rpc->msgin);
			err = homa_message_out_reset(rpc);
			rpc->generation++;
			if (rpc->generation == 0) {
				INC_METRIC(generation_overflows, 1);
				printk(KERN_WARNING "Aborting Homa RPC id %llu "
						"to server %s:%d: generation "
						"overflowed (EOVERFLOW)\n",
						rpc->id,
						homa_print_ipv4_addr(
							rpc->peer->addr),
						rpc->dport);
				err = -EOVERFLOW;
			}
			if (err) {
				homa_rpc_abort(rpc, err);
			} else {
				rpc->state = RPC_OUTGOING;
				homa_xmit_data(rpc, false);
			}
		}
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
	BUG_ON(rpc->state == RPC_DEAD);
	
	/* Make sure this message is in the right place in the grantable_rpcs
	 * list for its peer.
	 */
	if (list_empty(&rpc->grantable_links)) {
		/* Message not yet tracked; add it in priority order to
		 * the peer's list.
		 */
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
	/* The overall goal is to grant simultaneously to up to
	 * homa->max_overcommit messages. Ideally, each message should use
	 * a different priority level, determined by bytes_remaining (fewest
	 * bytes_remaining gets the highest priority). If there aren't enough
	 * scheduled priority levels for all of the messages, then the lowest
	 * level gets shared by multiple messages. If there are fewer messages
	 * than priority levels, then we use the lowest available levels
	 * (new higher-priority messages can use the higher levels to achieve
	 * instantaneous preemption).
	 */
	struct homa_rpc *candidate;
	struct homa_peer *peer;
	int rank, i;
	
	/* The variables below keep track of grants we need to send;
	 * don't send any until the very end, and release the lock
	 * first.
	 */
	/* Copy homa->max_overcommit in case it changes. */
	int max_grants = homa->max_overcommit;
	struct grant_header grants[max_grants];
	struct homa_rpc *rpcs[max_grants];
	int num_grants = 0;
	
	if (list_empty(&homa->grantable_peers))
		return;
	
	homa_grantable_lock(homa);
	
	/* See if there are any messages that deserve a grant (they have
	 * fewer than homa->rtt_bytes of data in transit). Consider only
	 * a single (highest-priority) entry for each peer.
	 */
	rank = 0;
	list_for_each_entry(peer, &homa->grantable_peers, grantable_links) {
		int extra_levels, priority;
		int received, new_grant;
		struct grant_header *grant;
		
		rank++;
		if (rank > max_grants)
			break;
		candidate = list_first_entry(&peer->grantable_rpcs,
				struct homa_rpc, grantable_links);
		BUG_ON(candidate->state == RPC_DEAD);
		
		/* Invariant: candidate msgin's incoming < total_length
		 * (otherwise it won't be on this list). Yikes! This isn't
		 * true anymore...
		 */
		if (candidate->msgin.incoming >= candidate->msgin.total_length)
			continue;
		received = (candidate->msgin.total_length
				- candidate->msgin.bytes_remaining);
		if ((candidate->msgin.incoming - received) >= homa->rtt_bytes)
			continue;
		new_grant = candidate->msgin.incoming + homa->grant_increment;
		if ((received + homa->rtt_bytes) > new_grant)
			new_grant = received + homa->rtt_bytes;
		if (new_grant > candidate->msgin.total_length)
			new_grant = candidate->msgin.total_length;
		
		/* The following line is needed to prevent spurious resends.
		 * Without it, if the timer fires right after we send the
		 * grant, it might think the RPC is slow and request a
		 * resend (until we send the grant, timeouts won't occur
		 * because there's no granted data).
		 */
		candidate->silent_ticks = 0;
		
		/* Send a grant for this message. */
		candidate->msgin.incoming = new_grant;
		atomic_inc(&candidate->grants_in_progress);
		rpcs[num_grants] = candidate;
		grant = &grants[num_grants];
		num_grants++;
		grant->offset = htonl(new_grant);
		priority = homa->max_sched_prio - (rank - 1);
		extra_levels = homa->max_sched_prio + 1
				- homa->num_grantable_peers;
		if (extra_levels >= 0)
			priority -= extra_levels;
		else if (priority < 0)
			priority = 0;
		grant->priority = priority;
		tt_record3("sent grant for id %llu, offset %d, priority %d",
				candidate->id, new_grant, priority);
	}
	
	homa_grantable_unlock(homa);
	
	/* By sending grants without holding grantable_lock here, we reduce
	 * contention on that lock significantly. This only works because
	 * rpc->grants_in_progress keeps the RPC from being deleted out from
	 * under us.
	 */
	for (i = 0; i < num_grants; i++) {
		/* Send any accumulated grants (ignore errors). */
		homa_xmit_control(GRANT, &grants[i], sizeof(grants[i]),
			rpcs[i]);
		atomic_dec(&rpcs[i]->grants_in_progress);
	}
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
	if (rpc->msgin.possibly_in_grant_queue
			&& (rpc->msgin.total_length >= 0)) {
		homa_grantable_lock(homa);
		if (!list_empty(&rpc->grantable_links)) {
			homa_remove_grantable_locked(homa, rpc);
			homa_grantable_unlock(homa);
			homa_send_grants(homa);
			return;
		}
		homa_grantable_unlock(homa);
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
 * @crpc:    RPC to be terminated. Must be a client RPC (@is_client != 0).
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
 * homa_peer_abort() - Abort all client RPCs to a particular host.
 * @homa:    Overall data about the Homa protocol implementation.
 * @addr:    Address (network order) of the destination whose RPCs are
 *           to be aborted.
 * @error:   Negative errno value indicating the reason for the abort.
 */
void homa_peer_abort(struct homa *homa, __be32 addr, int error)
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
			homa_rpc_lock(rpc);
			if ((rpc->state == RPC_DEAD)
					|| (rpc->state == RPC_READY)) {
				homa_rpc_unlock(rpc);
				continue;
			}
			if (rpc->is_client) {
				homa_rpc_abort(rpc, error);
			}
			homa_rpc_unlock(rpc);
		}
		homa_unprotect_rpcs(hsk);
	}
	rcu_read_unlock();
}

/**
 * @homa_wait_for_message() - Wait for an appropriate incoming message.
 * @hsk:     Socket where messages will arrive.
 * @flags:   Flags parameter from homa_recv; see manual entry for details.
 * @id:      If non-zero, then a response message will not be returned
 *           unless its RPC id matches this.
 *
 * Return:   Pointer to an RPC that matches @flags and @id, or a negative
 *           errno value. The RPC will be locked; the caller must unlock.
 */
struct homa_rpc *homa_wait_for_message(struct homa_sock *hsk, int flags,
		__u64 id)
{
	struct homa_rpc *rpc = NULL;
	struct homa_rpc *result = NULL;
	struct homa_interest interest;
	int sock_locked = 0;
	uint64_t stop_polling;
	
	/* Normally this loop only gets executed once, but we may have
	 * to start again if a "found" RPC gets deleted from underneath us.
	 */
	while (1) {
		while (hsk->dead_skbs > hsk->homa->max_dead_buffs) {
			/* Way too many dead RPCs; must cleanup immediately. */
			if (!homa_rpc_reap(hsk))
				break;
			
			/* Give NAPI and SoftIRQ tasks a chance to run. */
			schedule();
		}
		
		/* Check to see if there is an appropriate RPC already
		 * available, and at the same time register interests
		 * so we'll be notified if an RPC becomes available in
		 * the future.
		 */
		interest.thread = current;
		atomic_long_set(&interest.id, 0);
		interest.reg_rpc = NULL;
		interest.request_links.next = LIST_POISON1;
		interest.response_links.next = LIST_POISON1;
		
		if (id != 0) {
			rpc = homa_find_client_rpc(hsk, id);
			if (rpc == NULL) {
				result = ERR_PTR(-EINVAL);
				goto done;
			}
			if (rpc->interest != NULL) {
				homa_rpc_unlock(rpc);
				result = ERR_PTR(-EINVAL);
				goto done;
			}
			if (rpc->state == RPC_READY) {
				list_del_init(&rpc->ready_links);
				result = rpc;
				goto done;
			}
			rpc->interest = &interest;
			interest.reg_rpc = rpc;
			homa_rpc_unlock(rpc);
		}
		if (!sock_locked) {
			homa_sock_lock(hsk, "homa_wait_for_message #2");
			sock_locked = 1;
			if (hsk->shutdown) {
				result = ERR_PTR(-ESHUTDOWN);
				goto done;
			}
		}
		if ((id == 0) && (flags & HOMA_RECV_RESPONSE)) {
			if (!list_empty(&hsk->ready_responses)) {
				rpc = list_first_entry(
						&hsk->ready_responses,
						struct homa_rpc,
						ready_links);
				homa_interest_set(&interest, rpc);
				list_del_init(&rpc->ready_links);
				goto lock_rpc;
			}
			/* Insert this thread at the *front* of the list;
			 * we'll get better cache locality if we reuse
			 * the same thread over and over, rather than
			 * round-robining between threads.  Same below.*/
			list_add(&interest.response_links,
					&hsk->response_interests);
		}
		if (flags & HOMA_RECV_REQUEST) {
			if (!list_empty(&hsk->ready_requests)) {
				rpc = list_first_entry(&hsk->ready_requests,
						struct homa_rpc, ready_links);
				homa_interest_set(&interest, rpc);
				list_del_init(&rpc->ready_links);
				goto lock_rpc;
			}
			list_add(&interest.request_links,
					&hsk->request_interests);
		}
		
	        /* There is no ready RPC so far. Clean up dead RPCs before
		 * going to sleep (do at least a little cleanup even in
		 * nonblocking mode).
		 */
		homa_sock_unlock(hsk);
		sock_locked = 0;
		while (1) {
			int reaper_result;
			if (atomic_long_read(&interest.id)) {
				tt_record1("received message while reaping, "
						"id %d",
						atomic_long_read(&interest.id));
				goto lock_rpc;
			}
			reaper_result = homa_rpc_reap(hsk);
			if (flags & HOMA_RECV_NONBLOCKING) {
				result = ERR_PTR(-EAGAIN);
				goto done;
			}
			if (reaper_result == 0)
				break;
			
			/* Give NAPI and SoftIRQ tasks a chance to run. */
			schedule();
		}
		
		/* Busy-wait for a while before going to sleep; this avoids
		 * context-switching overhead to wake up.
		 */
		stop_polling = get_cycles() + hsk->homa->poll_cycles;
		while (get_cycles() < stop_polling) {
			if (atomic_long_read(&interest.id)) {
				tt_record1("received message while polling, "
						"id %d",
						atomic_long_read(&interest.id));
				INC_METRIC(fast_wakeups, 1);
				goto lock_rpc;
			}
			schedule();
		}
		INC_METRIC(slow_wakeups, 1);
		
		/* Now it's time to sleep. */
		set_current_state(TASK_INTERRUPTIBLE);
		if (!atomic_long_read(&interest.id) && !hsk->shutdown) {
			__u64 start = get_cycles();
			schedule();
			INC_METRIC(blocked_cycles, get_cycles() - start);
		}
		__set_current_state(TASK_RUNNING);
		if (atomic_long_read(&interest.id) != 0)
			tt_record2("homa_wait_for_message woke up, id %d, pid %d",
					atomic_long_read(&interest.id),
					current->pid);
		else
			tt_record("homa_wait_for_message woke up, rpc NULL");
		
		if (hsk->shutdown) {
			result = ERR_PTR(-ESHUTDOWN);
			goto done;
		}
		if (atomic_long_read(&interest.id))
			goto lock_rpc;
		if (signal_pending(current)) {
			result = ERR_PTR(-EINTR);
			goto done;
		}

		/* Nothing happened (perhaps the RPC we were waiting for
		 * was deleted?). Start over. */
		continue;
		
lock_rpc:
		/* We need to lookup and lock the RPC we're going to return,
		 * but we have to release the socket lock first. The RPC
		 * could go away as soon as we release the socket lock;
		 * be careful (see sync.txt for details)!
		 */
		if (sock_locked) {
			homa_sock_unlock(hsk);
			sock_locked = 0;
		}
		if (interest.is_client)
			result = homa_find_client_rpc(hsk,
					atomic_long_read(&interest.id));
		else
			result = homa_find_server_rpc(hsk, interest.peer_addr,
					interest.peer_port,
					atomic_long_read(&interest.id));
		if (result)
			goto done;

		/* Looks like the RPC got deleted? Try again.*/
		UNIT_LOG("; ", "RPC appears to have been deleted");
		continue;
	}

done:
	/* Note: if we went to sleep, then this info was already cleaned
	 * up by whoever woke us up. Also, values in the interest may
	 * change between when we test them below and when we acquire
	 * the socket lock.
	 */
	if ((interest.reg_rpc) || (interest.request_links.next != LIST_POISON1)
			|| (interest.response_links.next != LIST_POISON1)) {
		if (!sock_locked) {
			homa_sock_lock(hsk, "homa_wait_for_message #3");
			sock_locked = 1;
		}
		if (interest.reg_rpc)
			interest.reg_rpc->interest = NULL;
		if (interest.request_links.next != LIST_POISON1)
			list_del(&interest.request_links);
		if (interest.response_links.next != LIST_POISON1)
			list_del(&interest.response_links);
	}
	if (sock_locked)
		homa_sock_unlock(hsk);
	return result;
}

/**
 * @homa_rpc_ready: This function is called when the input message for
 * an RPC becomes complete. It marks the RPC as READY and either notifies
 * a waiting reader or queues the RPC.
 * @rpc:                RPC that now has a complete input message;
 *                      must be locked. The caller must also have
 *                      locked the socket for this RPC.
 */
void homa_rpc_ready(struct homa_rpc *rpc)
{
	struct homa_interest *interest;
	struct sock *sk;
	
	rpc->state = RPC_READY;
	
	/* First, see if someone is interested in this RPC specifically.
	 */
	if (rpc->interest) {
		interest = rpc->interest;
		goto handoff;
	}
	
	/* Second, check the interest list for this type of RPC. */
	if (rpc->is_client) {
		interest = list_first_entry_or_null(
				&rpc->hsk->response_interests,
				struct homa_interest, response_links);
		if (interest)
			goto handoff;
		list_add_tail(&rpc->ready_links, &rpc->hsk->ready_responses);
		INC_METRIC(responses_queued, 1);
	} else {
		interest = list_first_entry_or_null(
				&rpc->hsk->request_interests,
				struct homa_interest, request_links);
		if (interest)
			goto handoff;
		list_add_tail(&rpc->ready_links, &rpc->hsk->ready_requests);
		INC_METRIC(requests_queued, 1);
	}
	
	/* If we get here, no-one is waiting for the RPC, so it has been
	 * queued.
	 */
	
	/* Notify the poll mechanism. */
	sk = (struct sock *) rpc->hsk;
	sk->sk_data_ready(sk);
	tt_record1("homa_rpc_ready finished queuing id %d", rpc->id);
	return;
	
handoff:
	/* We found a waiting thread. Wakeup the thread and cleanup its
	 * interest info, so it won't have to acquire the socket lock
	 * again.
	 */
	homa_interest_set(interest, rpc);
	if (interest->reg_rpc) {
		interest->reg_rpc->interest = NULL;
		interest->reg_rpc = NULL;
	}
	if (interest->request_links.next != LIST_POISON1) {
		list_del(&interest->request_links);
		interest->request_links.next = LIST_POISON1;
	}
	if (interest->response_links.next != LIST_POISON1) {
		list_del(&interest->response_links);
		interest->response_links.next = LIST_POISON1;
	}
	wake_up_process(interest->thread);
	tt_record1("homa_rpc_ready handed off id %d", rpc->id);
}

/**
 * homa_incoming_sysctl_changed() - Invoked whenever a sysctl value is changed;
 * any input-related parameters that depend on sysctl-settable values.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_incoming_sysctl_changed(struct homa *homa)
{
	__u64 tmp;
		
	/* Code below is written carefully to avoid integer underflow or
	 * overflow under expected usage patterns. Be careful when changing!
	 */
	tmp = homa->poll_usecs;
	tmp = (tmp*cpu_khz)/1000;
	homa->poll_cycles = tmp;
}