/* Copyright (c) 2019-2023 Stanford University
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
#include "homa_lcache.h"

/**
 * Used to size stack-allocated arrays for grant management; the
 * max_overcommit sysctl parameter cannot be greater than this.
 */
#define MAX_GRANTS 10

/**
 * homa_message_in_init() - Constructor for homa_message_in.
 * @msgin:        Structure to initialize.
 * @length:       Total number of bytes in message.
 * @incoming:     The number of unscheduled bytes the sender is planning
 *                to transmit.
 */
void homa_message_in_init(struct homa_message_in *msgin, int length,
		int incoming)
{
	msgin->total_length = length;
	skb_queue_head_init(&msgin->packets);
	msgin->num_skbs = 0;
	msgin->bytes_remaining = length;
	msgin->incoming = (incoming > length) ? length : incoming;
	msgin->priority = 0;
	msgin->scheduled = length > incoming;
	if (length < HOMA_NUM_SMALL_COUNTS*64) {
		INC_METRIC(small_msg_bytes[(length-1) >> 6], length);
	} else if (length < HOMA_NUM_MEDIUM_COUNTS*1024) {
		INC_METRIC(medium_msg_bytes[(length-1) >> 10], length);
	} else {
		INC_METRIC(large_msg_count, 1);
		INC_METRIC(large_msg_bytes, length);
	}
	msgin->copied_out = 0;
	msgin->num_bpages = 0;
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
	int floor = rpc->msgin.copied_out;

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
		int data_bytes2 = ntohl(h2->seg.segment_length);
		if (offset2 < offset) {
			floor = offset2 + data_bytes2;
			break;
		}
		ceiling = offset2;
	}

	/* New packet goes right after skb2. If this packet overlaps either
	 * of its neighbors, then it is discarded (partial overlaps are
	 * not permitted).
	 */
	if ((offset < floor) || ((offset + data_bytes) > ceiling)) {
		/* This packet is redundant. */
//		char buffer[100];
//		printk(KERN_NOTICE "redundant Homa packet: %s\n",
//			homa_print_packet(skb, buffer, sizeof(buffer)));
		INC_METRIC(redundant_packets, 1);
		tt_record4("homa_add_packet discarding packet for id %d, "
				"offset %d, copied_out %d, remaining %d",
				rpc->id, offset, rpc->msgin.copied_out,
				rpc->msgin.total_length);
		kfree_skb(skb);
		return;
	}
	if (h->retransmit) {
		INC_METRIC(resent_packets_used, 1);
		homa_freeze(rpc, PACKET_LOST, "Freezing because of lost "
				"packet, id %d, peer 0x%x");
	}
	__skb_insert(skb, skb2, skb2->next, &rpc->msgin.packets);
	rpc->msgin.bytes_remaining -= data_bytes;
	rpc->msgin.num_skbs++;
}

/**
 * homa_copy_to_user() - Copy as much data as possible from incoming
 * packet buffers to buffers in user space.
 * @rpc:     RPC for which data should be copied. Must be locked by caller.
 * Return:   Zero for success or a negative errno if there is an error.
 */
int homa_copy_to_user(struct homa_rpc *rpc)
{
#ifdef __UNIT_TEST__
#define MAX_SKBS 3
#else
#define MAX_SKBS 20
#endif
	struct sk_buff *skbs[MAX_SKBS];
	int n = 0;             /* Number of filled entries in skbs. */
	int error = 0;
	int count;

	/* Number of bytes that have already been copied to user space
	 * from the current packet.
	 */
	int copied_from_seg;

	/* Tricky note: we can't hold the RPC lock while we're actually
	 * copying to user space, because (a) it's illegal to hold a spinlock
	 * while copying to user space and (b) we'd like for homa_softirq
	 * to add more packets to the RPC while we're copying these out.
	 * So, collect a bunch of chunks to copy, then release the lock,
	 * copy them, and reacquire the lock.
	 */
	while (true) {
		struct sk_buff *skb = skb_peek(&rpc->msgin.packets);
		struct data_header *h;
		int i, seg_offset;

		if (!skb || (rpc->msgin.copied_out >= rpc->msgin.total_length))
			goto copy_out;
		h = (struct data_header *) skb->data;
		seg_offset = ntohl(h->seg.offset);
		if (rpc->msgin.copied_out < seg_offset) {
			/* The next data to copy hasn't yet been received;
			 * wait for more packets to arrive.
			 */
			goto copy_out;
		}
		BUG_ON(rpc->msgin.copied_out != seg_offset);
		skbs[n] = skb;
		n++;
		skb_dequeue(&rpc->msgin.packets);
		rpc->msgin.num_skbs--;
		rpc->msgin.copied_out = seg_offset + ntohl(h->seg.segment_length);
		if (n < MAX_SKBS)
			continue;

copy_out:
		if (n == 0)
			break;
		atomic_or(RPC_COPYING_TO_USER, &rpc->flags);
		homa_rpc_unlock(rpc);

		tt_record1("starting copy to user space for id %d",
				rpc->id);

		/* Each iteration of this loop copies (part of?) an skb
		 * to a contiguous range of buffer space.
		 */
		count = 0;
		copied_from_seg = 0;
		for (i = 0; i < n && !error; ) {
			int skb_bytes, buf_bytes, next_copied;
			char *dst;
			struct iovec iov;
			struct iov_iter iter;

			skb = skbs[i];
			h = (struct data_header *) skb->data;
			skb_bytes = ntohl(h->seg.segment_length) - copied_from_seg;
			dst = homa_pool_get_buffer(rpc,
					ntohl(h->seg.offset) + copied_from_seg,
					&buf_bytes);
			if (buf_bytes < skb_bytes) {
				if (buf_bytes == 0) {
					/* skb seems to have data beyond the
					 * end of the message.
					 */
					break;
				}
				skb_bytes = buf_bytes;
				next_copied = copied_from_seg + skb_bytes;
			} else {
				i++;
				next_copied = 0;
			}
			BUG_ON(skb_bytes <= 0);
			error = import_single_range(READ, dst, skb_bytes, &iov,
					&iter);
			if (error)
				break;
			error = skb_copy_datagram_iter(skb,
					sizeof(*h) + copied_from_seg, &iter,
					skb_bytes);
			copied_from_seg = next_copied;
			count += skb_bytes;
		}
		tt_record4("finished copying %d bytes for id %d, copied_out "
				"%d, last offset %d",
				count, rpc->id, ntohl(h->seg.offset)
					+ ntohl(h->seg.segment_length),
				ntohl(h->seg.offset));

		/* Free skbs. */
		for (i = 0; i < n; i++)
			kfree_skb(skbs[i]);
		tt_record2("finished freeing %d skbs for id %d",
				n, rpc->id);
		n = 0;
		homa_rpc_lock(rpc);
		atomic_andnot(RPC_COPYING_TO_USER, &rpc->flags);
		if (error)
			break;
	}
	if (error)
		tt_record2("homa_copy_to_user returning error %d for id %d",
				-error, rpc->id);
	return error;
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

	end_offset = msgin->incoming;

	/* The code below handles the case where we've received data past
	 * msgin->incoming. In this case, end_offset should start off at
	 * the offset just after the last byte received.
	 */
	skb = skb_peek_tail(&msgin->packets);
	if (skb) {
		struct data_header *h = (struct data_header *) skb->data;
		int data_end = ntohl(h->seg.offset)
				+ ntohl(h->seg.segment_length);
		if (data_end > end_offset)
			end_offset = data_end;
	}

	missing_bytes = msgin->bytes_remaining
			- (msgin->total_length - end_offset);
	if (missing_bytes == 0) {
		resend->offset = 0;
		resend->length = 0;
		return;
	}

	/* Basic idea: walk backwards through the message's packets until
	 * we have accounted for all missing bytes; this will identify
	 * the first missing range.
	 */
	skb_queue_reverse_walk(&msgin->packets, skb) {
		struct data_header *h = (struct data_header *) skb->data;
		int offset = ntohl(h->seg.offset);
		int pkt_length = ntohl(h->seg.segment_length);
		int gap;

		if (pkt_length > (end_offset - offset))
			pkt_length = end_offset - offset;
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
	tt_record4("first packets missing, missing_bytes %d, copied_out %d, "
			"incoming %d, length %d",
			missing_bytes, msgin->copied_out, msgin->incoming,
			msgin->total_length);
	resend->offset = htonl(msgin->copied_out);
	resend->length = htonl(missing_bytes);
}

/**
 * homa_advance_input() - This is an "odds and ends" function that
 * helps an incoming rpc to progress by arranging for grants, if
 * appropriate, and waking up a waiting process, if appropriate.
 * @rpc:  RPC to process
 */
void homa_advance_input(struct homa_rpc *rpc)
{
	struct data_header *first_hdr;

	if (rpc->msgin.num_bpages == 0)
		return;
	first_hdr = (struct data_header *) (skb_peek(&rpc->msgin.packets)->data);
	if ((ntohl(first_hdr->seg.offset) == rpc->msgin.copied_out)
			&& !(atomic_read(&rpc->flags) & RPC_PKTS_READY)) {
		atomic_or(RPC_PKTS_READY, &rpc->flags);
		homa_sock_lock(rpc->hsk, "homa_advance_input");
		homa_rpc_handoff(rpc);
		homa_sock_unlock(rpc->hsk);
	}
	if (rpc->msgin.scheduled )
		homa_check_grantable(rpc);
}

/**
 * homa_pkt_dispatch() - Top-level function for handling an incoming packet.
 * @skb:        The incoming packet. This function takes ownership of the
 *              packet and will ensure that it is eventually freed.
 * @hsk:        Homa socket that owns the packet's destination port. This socket
 *              is not locked, but its existence is ensured for the life
 *              of this method.
 * @lcache:     Used to manage RPC locks; must be properly initialized by
 *              the caller, may be modified here.
 * @delta:      Pointer to a value that will be incremented or decremented
 *              to accumulate changes that need to be made to
 *              homa->total_incoming.
 *
 * Return:  None.
 */
void homa_pkt_dispatch(struct sk_buff *skb, struct homa_sock *hsk,
		struct homa_lcache *lcache, int *delta)
{
	struct common_header *h = (struct common_header *) skb->data;
	const struct in6_addr saddr = skb_canonical_ipv6_saddr(skb);
	struct homa_rpc *rpc;
	__u64 id = homa_local_id(h->sender_id);

	/* If there is an ack in the packet, handle it. Must do this
	 * before locking the packet's RPC, since we may need to acquire
	 * (other) RPC locks to handle the acks.
	 */
	if (h->type == DATA) {
		struct data_header *dh = (struct data_header *) h;
		if (dh->seg.ack.client_id != 0) {
			/* homa_rpc_acked may attempt to lock the RPC, so
			 * make sure we don't have an RPC locked.
			 */
			homa_lcache_release(lcache);
			homa_rpc_acked(hsk, &saddr, &dh->seg.ack);
		}
	}

	/* Find and lock the RPC for this packet. */
	rpc = homa_lcache_get(lcache, id, &saddr, ntohs(h->sport));
	if (!rpc) {
		/* To avoid deadlock, must release old RPC before locking new. */
		homa_lcache_release(lcache);
		if (!homa_is_client(id)) {
			/* We are the server for this RPC. */
			if (h->type == DATA) {
				/* Create a new RPC if one doesn't already exist. */
				rpc = homa_rpc_new_server(hsk, &saddr,
						(struct data_header *) h);
				if (IS_ERR(rpc)) {
					printk(KERN_WARNING "homa_pkt_dispatch "
							"couldn't create "
							"server rpc: error %lu",
							-PTR_ERR(rpc));
					INC_METRIC(server_cant_create_rpcs, 1);
					rpc = NULL;
					goto discard;
				}
			} else
				rpc = homa_find_server_rpc(hsk, &saddr,
						ntohs(h->sport), id);

		} else {
			rpc = homa_find_client_rpc(hsk, id);
		}
		if (rpc)
			homa_lcache_save(lcache, rpc);
	}
	if (unlikely(!rpc)) {
		if ((h->type != CUTOFFS) && (h->type != NEED_ACK)
				&& (h->type != ACK) && (h->type != RESEND)) {
			tt_record4("Discarding packet for unknown RPC, id %u, "
					"type %d, peer 0x%x:%d",
					id, h->type,
					tt_addr(saddr),
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
		if (hsk->homa->sync_freeze) {
			hsk->homa->sync_freeze = 0;
			if (!tt_frozen) {
				struct freeze_header freeze;
				tt_record2("Freezing timetrace because of "
						"sync_freeze, id %d, peer 0x%x",
						rpc->id,
						tt_addr(rpc->peer->addr));
				tt_freeze();
				homa_xmit_control(FREEZE, &freeze,
						sizeof(freeze), rpc);
			}
		}
	}

	switch (h->type) {
	case DATA:
		homa_data_pkt(skb, rpc, lcache, delta);
		INC_METRIC(packets_received[DATA - DATA], 1);
		if (hsk->dead_skbs >= 2*hsk->homa->dead_buffs_limit) {
			/* We get here if neither homa_wait_for_message
			 * nor homa_timer can keep up with reaping dead
			 * RPCs. See reap.txt for details.
			 */
			uint64_t start = get_cycles();

			/* Must unlock to avoid self-deadlock in rpc_reap. */
			homa_lcache_release(lcache);
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
				id, tt_addr(rpc->peer->addr));
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
		homa_ack_pkt(skb, hsk, rpc, lcache);
		break;
	default:
		INC_METRIC(unknown_packet_types, 1);
		goto discard;
	}
	return;

    discard:
	kfree_skb(skb);
}

/**
 * homa_data_pkt() - Handler for incoming DATA packets
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * @rpc:     Information about the RPC corresponding to this packet.
 *           Must be locked by the caller.
 * @lcache:  @rpc must be stored here; released if needed to unlock @rpc.
 * @delta:   Pointer to a value that will be incremented or decremented
 *           to accumulate changes that need to be made to homa->total_incoming.
 *
 * Return: Zero means the function completed successfully. Nonzero means
 * that the RPC had to be unlocked and deleted because the socket has been
 * shut down; the caller should not access the RPC anymore.
 */
void homa_data_pkt(struct sk_buff *skb, struct homa_rpc *rpc,
		struct homa_lcache *lcache, int *delta)
{
	struct homa *homa = rpc->hsk->homa;
	struct data_header *h = (struct data_header *) skb->data;
	int old_remaining;

	tt_record4("incoming data packet, id %d, peer 0x%x, offset %d/%d",
			homa_local_id(h->common.sender_id),
			tt_addr(rpc->peer->addr), ntohl(h->seg.offset),
			ntohl(h->message_length));

	if ((rpc->state != RPC_INCOMING) && homa_is_client(rpc->id)) {
		if (unlikely(rpc->state != RPC_OUTGOING))
			goto discard;
		INC_METRIC(responses_received, 1);
		rpc->state = RPC_INCOMING;
		tt_record2("Incoming message for id %d has %d unscheduled bytes",
				rpc->id, ntohl(h->incoming));
		homa_message_in_init(&rpc->msgin, ntohl(h->message_length),
				ntohl(h->incoming));
		if (homa_pool_allocate(rpc) != 0)
			goto discard;
	} else if (rpc->state != RPC_INCOMING) {
		/* Must be server; note that homa_rpc_new_server already
		 * initialized msgin and allocated buffers.
		 */
		if (unlikely(rpc->msgin.total_length >= 0))
			goto discard;
	}

	if (skb_peek(&rpc->msgin.packets) == NULL)
		*delta += rpc->msgin.incoming;

	old_remaining = rpc->msgin.bytes_remaining;
	homa_add_packet(rpc, skb);
	*delta -= old_remaining - rpc->msgin.bytes_remaining;

	homa_advance_input(rpc);

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
	return;

    discard:
	kfree_skb(skb);
	UNIT_LOG("; ", "homa_data_pkt discarded packet");
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
	const struct in6_addr saddr = skb_canonical_ipv6_saddr(skb);
	struct busy_header busy;

	if (rpc == NULL) {
		tt_record4("resend request for unknown id %d, peer 0x%x:%d, "
				"offset %d; responding with UNKNOWN",
				homa_local_id(h->common.sender_id),
				tt_addr(saddr), ntohs(h->common.sport),
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
	if (rpc->msgout.next_xmit_offset < rpc->msgout.granted) {
		/* We have chosen not to transmit data from this message;
		 * send BUSY instead.
		 */
		tt_record3("sending BUSY from resend, id %d, offset %d, "
				"granted %d", rpc->id,
				rpc->msgout.next_xmit_offset,
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
			rpc->id, tt_addr(rpc->peer->addr), rpc->dport);
	if (homa_is_client(rpc->id)) {
		if (rpc->state == RPC_OUTGOING) {
			/* It appears that everything we've already transmitted
			 * has been lost; retransmit it.
			 */
			tt_record4("Restarting id %d to server 0x%x:%d, "
					"lost %d bytes",
					rpc->id, tt_addr(rpc->peer->addr),
					rpc->dport,
					rpc->msgout.next_xmit_offset);
			homa_freeze(rpc, RESTART_RPC, "Freezing because of "
					"RPC restart, id %d, peer 0x%x");
			homa_resend_data(rpc, 0, rpc->msgout.next_xmit_offset,
					homa_unsched_priority(rpc->hsk->homa,
					rpc->peer, rpc->msgout.length));
			goto done;
		}

		printk(KERN_ERR "Received unknown for RPC id %llu, peer %s:%d "
				"in bogus state %d; discarding unknown\n",
				rpc->id, homa_print_ipv6_addr(&rpc->peer->addr),
				rpc->dport, rpc->state);
		tt_record4("Discarding unknown for RPC id %d, peer 0x%x:%d: "
				"bad state %d",
				rpc->id, tt_addr(rpc->peer->addr), rpc->dport,
				rpc->state);
	} else {
		if (rpc->hsk->homa->verbose)
			printk(KERN_NOTICE "Freeing rpc id %llu from client "
					"%s:%d: unknown to client",
					rpc->id,
					homa_print_ipv6_addr(&rpc->peer->addr),
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
	const struct in6_addr saddr = skb_canonical_ipv6_saddr(skb);
	int i;
	struct cutoffs_header *h = (struct cutoffs_header *) skb->data;
	struct homa_peer *peer = homa_peer_find(&hsk->homa->peers,
		&saddr, &hsk->inet);

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
	const struct in6_addr saddr = skb_canonical_ipv6_saddr(skb);
	__u64 id = homa_local_id(h->sender_id);
	struct ack_header ack;
	struct homa_peer *peer;

	tt_record1("Received NEED_ACK for id %d", id);

	/* Return if it's not safe for the peer to purge its state
	 * for this RPC (the RPC still exists and we haven't received
	 * the entire response), or if we can't find peer info.
	 */
	if ((rpc != NULL) && ((rpc->state != RPC_INCOMING)
			|| rpc->msgin.bytes_remaining)) {
		goto done;
	} else {
		peer = homa_peer_find(&hsk->homa->peers, &saddr, &hsk->inet);
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
	ack.common.sender_id = cpu_to_be64(id);
	ack.num_acks = htons(homa_peer_get_acks(peer,
			NUM_PEER_UNACKED_IDS, ack.acks));
	__homa_xmit_control(&ack, sizeof(ack), peer, hsk);
	tt_record3("Responded to NEED_ACK for id %d, peer %0x%x with %d "
			"other acks", id, tt_addr(saddr), ntohs(ack.num_acks));

    done:
	kfree_skb(skb);
}

/**
 * homa_ack_pkt() - Handler for incoming ACK packets
 * @skb:     Incoming packet; size already verified large enough for header.
 *           This function now owns the packet.
 * @hsk:     Socket on which the packet was received.
 * @rpc:     The RPC named in the packet header, or NULL if no such
 *           RPC exists. The RPC has been locked by the caller and
 *           recorded in @lcache.
 * @lcache:  Will be released here to unlock the RPC.
 */
void homa_ack_pkt(struct sk_buff *skb, struct homa_sock *hsk,
		struct homa_rpc *rpc, struct homa_lcache *lcache)
{
	struct ack_header *h = (struct ack_header *) skb->data;
	const struct in6_addr saddr = skb_canonical_ipv6_saddr(skb);
	int i, count;

	if (rpc != NULL) {
		homa_rpc_free(rpc);
		homa_lcache_release(lcache);
	}

	count = ntohs(h->num_acks);
	for (i = 0; i < count; i++)
		homa_rpc_acked(hsk, &saddr, &h->acks[i]);
	tt_record3("ACK received for id %d, peer 0x%x, with %d other acks",
			homa_local_id(h->common.sender_id),
			tt_addr(saddr), count);
	kfree_skb(skb);
}

/**
 * homa_check_grantable() - This function ensures that an RPC is on the
 * grantable list if appropriate. It also adjusts the position of the RPC
 * upward on the list, if needed.
 * @rpc:     RPC to check; typically the status of this RPC has changed
 *           in a way that may affect its grantability (e.g. a packet
 *           just arrived for it). Must be locked.
 */
void homa_check_grantable(struct homa_rpc *rpc)
{
	struct homa_rpc *candidate;
	struct homa_message_in *msgin = &rpc->msgin;
	struct homa *homa = rpc->hsk->homa;

	/* No need to do anything unless this message needs more grants. */
	if (rpc->msgin.incoming >= rpc->msgin.total_length)
		return;

	homa_grantable_lock(homa);
	/* Note: must check incoming again: it might have changed. */
	if ((rpc->state == RPC_DEAD) || (rpc->msgin.incoming
			>= rpc->msgin.total_length)) {
		homa_grantable_unlock(homa);
		return;
	}

	/* Make sure this message is in the right place in the grantable_rpcs
	 * list.
	 */
	if (list_empty(&rpc->grantable_links)) {
		/* Message not yet tracked; add it in priority order. */
		__u64 time = get_cycles();
		INC_METRIC(grantable_rpcs_integral, homa->num_grantable_rpcs
				* (time - homa->last_grantable_change));
		homa->last_grantable_change = time;
		homa->num_grantable_rpcs++;
		tt_record1("incremented num_grantable_rpcs to %d",
				homa->num_grantable_rpcs);
		if (homa->num_grantable_rpcs > homa->max_grantable_rpcs)
			homa->max_grantable_rpcs = homa->num_grantable_rpcs;
		rpc->msgin.birth = get_cycles();
		list_for_each_entry(candidate, &homa->grantable_rpcs,
				grantable_links) {
			if (candidate->msgin.bytes_remaining
					> msgin->bytes_remaining) {
				list_add_tail(&rpc->grantable_links,
						&candidate->grantable_links);
				goto done;
			}
		}
		list_add_tail(&rpc->grantable_links, &homa->grantable_rpcs);
	} else while (rpc != list_first_entry(&homa->grantable_rpcs,
			struct homa_rpc, grantable_links)) {
		/* Message is on the list, but its priority may have
		 * increased because of a recent packet arrival. If so,
		 * adjust its position in the list.
		 */
		candidate = list_prev_entry(rpc, grantable_links);
		/* Fewer remaining bytes wins: */
		if (candidate->msgin.bytes_remaining < msgin->bytes_remaining)
			goto done;
		/* Tie-breaker: oldest wins */
		if (candidate->msgin.bytes_remaining == msgin->bytes_remaining) {
			if (candidate->msgin.birth <= msgin->birth) {
				goto done;
			}
		}
		__list_del_entry(&candidate->grantable_links);
		list_add(&candidate->grantable_links, &rpc->grantable_links);
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
	/* Some overall design notes:
	 * - Grant to multiple messages, as long as we can keep
	 *   homa->total_incoming under homa->max_incoming bytes.
	 * - Ideally, each message should use a different priority level,
	 *   determined by bytes_remaining (fewest bytes_remaining gets the
	 *   highest priority). If there aren't enough scheduled priority
	 *   levels for all of the messages, then the lowest level gets
	 *   shared by multiple messages.
	 * - If there are fewer messages than priority levels, then we use
	 *   the lowest available levels (new higher-priority messages can
	 *   use the higher levels to achieve instantaneous preemption).
	 */
	int i, num_grants;
	__u64 start;

	/* RPCs that are candidates for grants; if we eventually decide
	 * not to grant for an RPC, the array will be compacted to
	 * remove that RPC.
	 */
	struct homa_rpc *rpcs[MAX_GRANTS];

	/* Number of valid entries in rpcs. */
	int num_rpcs = 0;

	/* For each valid entry in rpcs, a GRANT packet header to
	 * send for that RPC.
	 */
	struct grant_header grants[MAX_GRANTS];

	/* How many more bytes we can grant before hitting the limit. */
	int available = homa->max_incoming - atomic_read(&homa->total_incoming);

	if (list_empty(&homa->grantable_rpcs) || (available <= 0)) {
		return;
	}

	start = get_cycles();
	homa_grantable_lock(homa);

	num_rpcs = homa_choose_rpcs_to_grant(homa, rpcs, homa->max_overcommit);

	/* Compute grants but don't actually send them; we want to release
	 * grantable_lock before sending.
	 */
	num_grants = homa_create_grants(homa, rpcs, num_rpcs, grants,
			available);

	if (homa->grant_nonfifo_left <= 0) {
		homa->grant_nonfifo_left += homa->grant_nonfifo;
		if (homa->grant_fifo_fraction)
			homa_grant_fifo(homa);
	}
	homa_grantable_unlock(homa);

	/* By sending grants without holding grantable_lock here, we reduce
	 * contention on that lock significantly. This only works because
	 * rpc->grants_in_progress keeps RPCs from being deleted out from
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
 * homa_choose_rpcs_to_grant() - Scans homa->grantable_rpcs and picks
 * a set that are candidates for granting, considering factors such
 * as homa->max_peers_per_rpc. The caller must hold homa->grantable_lock.
 * @homa:      Overall data about the Homa protocol implementation.
 * @rpcs:      The selected RPCs will be stored in this array, in
 *             decreasing priority order.
 * @max_rpcs:  Maximum number of RPCs to return in @rpcs (must be <=
 *             MAX_GRANTS).
 * Return:     The number of RPCs actually stored in @rpcs.
 */
int homa_choose_rpcs_to_grant(struct homa *homa, struct homa_rpc **rpcs,
		int max_rpcs)
{
	struct homa_rpc *rpc, *temp;
	int num_rpcs = 0;

	/* The variables below allow us to limit how many messages we
	 * will grant for a single peer. Peers contains one entry for
	 * each of the num_peers distinct peers we have encountered so
	 * far in grantable_rpcs and rpc_count indicates how many
	 * different RPCs are destined for that peer.
	 */
	struct homa_peer *peers[MAX_GRANTS];
	int rpc_count[MAX_GRANTS];
	int num_peers = 0;

	list_for_each_entry_safe(rpc, temp, &homa->grantable_rpcs,
			grantable_links) {
		/* Keep track of how many RPCs we have seen from each
		 * distinct peer.
		 */
		int i;
		for (i = 0; i < num_peers; i++) {
			if (peers[i] == rpc->peer) {
				rpc_count[i]++;
				if (rpc_count[i] > homa->max_rpcs_per_peer)
					goto next_rpc;
				goto peer_count_done;
			}
		}
		peers[num_peers] = rpc->peer;
		rpc_count[num_peers] = 1;
		num_peers++;

    peer_count_done:
		rpcs[num_rpcs] = rpc;
		num_rpcs++;
		if (num_rpcs >= max_rpcs)
			break;
    next_rpc:
	}
	return num_rpcs;
}

/**
 * Given a set of RPCs, this function computes additional grants for
 * each of them. It doesn't actually send the grants.
 * @homa:      Overall data about the Homa protocol implementation.
 * @rpcs:      Array containing @num_rpcs RPCs to consider for granting,
 *             in decreasing priority order. The array will be modified
 *             to leave only the RPCs for which grants were actually
 *             created, so its size may be less than @num_rpcs when the
 *             function returns.
 * @num_rpcs:  Number of RPCs initially in @rpcs.
 * @grants:    An array to fill in with headers for GRANT packets. These
 *             entries correspond to the (final) entries in @rpcs.
 * @available: Maximum number of bytes of new grants that we can issue.
 * Return:     The final size of @rpcs and @grants (<= @num_rpcs). Note:
 *             grants_in_progress will be incremented for each of the
 *             returned RPCs.
 */
int homa_create_grants(struct homa *homa, struct homa_rpc **rpcs,
		int num_rpcs, struct grant_header *grants, int available)
{
	int rank;
	int num_grants = 0;

	/* Total bytes in additional grants that we've given out so far. */
	int granted_bytes = 0;

	/* Compute the maximum window size for any RPC. Dynamic window
	 * sizing uses the approach inspired by the paper "Dynamic Queue
	 * Length Thresholds for Shared-Memory Packet Switches" with an
	 * alpha value of 1. The idea is to maintain unused incoming capacity
	 * (for new RPC arrivals) equal to the amount of incoming
	 * allocated to each of the current RPCs.
	 */
	int window = homa->unsched_bytes;
	if (homa->dynamic_windows)
	    window = homa->max_incoming/(num_rpcs+1);

	for (rank = 0; rank < num_rpcs; rank++) {
		int extra_levels, priority;
		int received, new_grant, increment;
		struct grant_header *grant;
		struct homa_rpc *rpc = rpcs[rank];

		/* Tricky synchronization issue: homa_data_pkt may be
		 * updating bytes_remaining while we're working here.
		 * So, we only read it once, right now, and we only
		 * make updates to total_incoming based on changes
		 * to msgin.incoming (not bytes_remaining). homa_data_pkt
		 * will update total_incoming based on bytes_remaining
		 * but not incoming.
		 */
		received = (rpc->msgin.total_length
				- rpc->msgin.bytes_remaining);

		/* Compute how many bytes of additional grants (increment)
		 * to give this RPC.
		 */
		new_grant = received + window;
		if (new_grant > rpc->msgin.total_length)
			new_grant = rpc->msgin.total_length;
		increment = new_grant - rpc->msgin.incoming;
		tt_record3("grant info: id %d, received %d, incoming %d",
				rpc->id, received,
				rpc->msgin.incoming);
		if (increment <= 0)
			continue;
		if (available <= 0)
			break;
		if (increment > available) {
			increment = available;
			new_grant = rpc->msgin.incoming + increment;
		}

		/* The following line is needed to prevent spurious resends.
		 * Without it, if the timer fires right after we send the
		 * grant, it might think the RPC is slow and request a
		 * resend (until we send the grant, timeouts won't occur
		 * because there's no granted data).
		 */
		rpc->silent_ticks = 0;

		/* Create a grant for this message. */
		rpc->msgin.incoming = new_grant;
		granted_bytes += increment;
		available -= increment;
		atomic_inc(&rpc->grants_in_progress);
		grant = &grants[num_grants];
		grant->offset = htonl(new_grant);
		priority = homa->max_sched_prio - rank;

		/* If there aren't enough RPCs to consume all of the priority
		 * levels, use only the lower levels; this allows faster
		 * preemption if a new high-priority message appears.
		 */
		extra_levels = homa->max_sched_prio + 1 - num_rpcs;
		if (extra_levels >= 0)
			priority -= extra_levels;
		if (priority < 0)
			priority = 0;
		grant->priority = priority;
		tt_record4("sending grant for id %llu, offset %d, priority %d, "
				"increment %d",
				rpc->id, new_grant, priority, increment);
		if (new_grant == rpc->msgin.total_length)
			homa_remove_grantable_locked(homa, rpc);
		rpcs[num_grants] = rpc;
		num_grants++;
	}
	homa->grant_nonfifo_left -= granted_bytes;
	atomic_add(granted_bytes, &homa->total_incoming);
	return num_grants;
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
	struct homa_rpc *rpc, *oldest;
	__u64 oldest_birth;
	struct grant_header grant;
	int granted;

	oldest = NULL;
	oldest_birth = ~0;

	/* Find the oldest message that doesn't currently have an
	 * outstanding "pity grant".
	 */
	list_for_each_entry(rpc, &homa->grantable_rpcs, grantable_links) {
		int received, on_the_way;

		if (rpc->msgin.birth >= oldest_birth)
			continue;

		received = (rpc->msgin.total_length
				- rpc->msgin.bytes_remaining);
		on_the_way = rpc->msgin.incoming - received;
		if (on_the_way > homa->unsched_bytes) {
			/* The last "pity" grant hasn't been used
			 * up yet.
			 */
			continue;
		}
		oldest = rpc;
		oldest_birth = rpc->msgin.birth;
	}
	if (oldest == NULL)
		return;
	INC_METRIC(fifo_grants, 1);
	if ((oldest->msgin.total_length - oldest->msgin.bytes_remaining)
			== oldest->msgin.incoming)
		INC_METRIC(fifo_grants_no_incoming, 1);

	oldest->silent_ticks = 0;
	granted = homa->fifo_grant_increment;
	oldest->msgin.incoming += granted;
	if (oldest->msgin.incoming >= oldest->msgin.total_length) {
		granted -= oldest->msgin.incoming - oldest->msgin.total_length;
		oldest->msgin.incoming = oldest->msgin.total_length;
		homa_remove_grantable_locked(homa, oldest);
	}
	grant.offset = htonl(oldest->msgin.incoming);
	grant.priority = homa->max_sched_prio;
	tt_record3("sending fifo grant for id %llu, offset %d, priority %d",
			oldest->id, oldest->msgin.incoming,
			homa->max_sched_prio);
	homa_xmit_control(GRANT, &grant, sizeof(grant), oldest);
	atomic_add(granted, &homa->total_incoming);
}

/**
 * homa_remove_grantable_locked() - This method does all the real work of
 * homa_remove_from_grantable, but it assumes that the caller holds the
 * grantable lock, so it can be used by other functions that already
 * hold the lock.
 * @homa:    Overall data about the Homa protocol implementation.
 * @rpc:     RPC that is no longer grantable. Must be locked, and must
 *           currently be linked into homa->grantable_rpcs.
 */
void homa_remove_grantable_locked(struct homa *homa, struct homa_rpc *rpc)
{
	__u64 time = get_cycles();
	INC_METRIC(grantable_rpcs_integral, homa->num_grantable_rpcs
			* (time - homa->last_grantable_change));
	homa->last_grantable_change = time;
	list_del_init(&rpc->grantable_links);
	homa->num_grantable_rpcs--;
	tt_record1("decremented num_grantable_rpcs to %d",
			homa->num_grantable_rpcs);
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
	/* In order to determine for sure whether an RPC is in the
	 * grantable_rpcs we would need to acquire homa_grantable_lock,
	 * which is expensive because it's global. Howevever, we can
	 * check whether the RPC is queued without acquiring the lock,
	 * and if it's not, then we don't need to acquire the lock (the
	 * RPC can't get added to the queue without locking it, and we own
	 * the RPC's lock). If it is in the queue, then we have to require
	 * homa_grantable_lock and check again (it could have gotten
	 * removed in the meantime).
	 */
	if (list_empty(&rpc->grantable_links))
		return;
	homa_grantable_lock(homa);
	if (!list_empty(&rpc->grantable_links)) {
		homa_remove_grantable_locked(homa, rpc);
		homa_grantable_unlock(homa);
		homa_send_grants(homa);
	} else
		homa_grantable_unlock(homa);
}

/**
 * homa_log_grantable_list() - Print information about the entries on the
 * grantable list to the kernel log. This is intended for debugging use
 * via the log_topic sysctl parameter.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_log_grantable_list(struct homa *homa)
{
	int count;
	struct homa_rpc *rpc, *temp;

	printk(KERN_NOTICE "Logging Homa grantable_rpcs list\n");
	homa_grantable_lock(homa);
	count = 0;
	list_for_each_entry_safe(rpc, temp, &homa->grantable_rpcs,
			grantable_links) {
		homa_rpc_log(rpc);
		count++;
		if (count > 100)
			break;
	}
	homa_grantable_unlock(homa);
	printk(KERN_NOTICE "Finished logging Homa grantable_rpcs list\n");
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
		homa_rpc_handoff(crpc);
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
void homa_abort_rpcs(struct homa *homa, const struct in6_addr *addr,
		int port, int error)
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
			if (!ipv6_addr_equal(&rpc->peer->addr, addr))
				continue;
			if ((port != 0) && (rpc->dport != port))
				continue;
			homa_rpc_lock(rpc);
			if (homa_is_client(rpc->id)) {
				tt_record3("aborting client RPC: peer 0x%x, "
						"id %u, error %d",
						tt_addr(rpc->peer->addr),
						rpc->id, error);
				homa_rpc_abort(rpc, error);
			} else {
				INC_METRIC(server_rpc_discards, 1);
				tt_record3("discarding server RPC: peer 0x%x, "
						"id %d, error %d",
						tt_addr(rpc->peer->addr),
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
 * homa_abort_rpcs() - Abort all outgoing (client-side) RPCs on a given socket.
 * @hsk:         Socket whose RPCs should be aborted.
 * @error:       Zero means that the aborted RPCs should be freed immediately.
 *               A nonzero value means that the RPCs should be marked
 *               complete, so that they can be returned to the application;
 *               this value (a negative errno) will be returned from
 *               recvmsg.
 */
void homa_abort_sock_rpcs(struct homa_sock *hsk, int error)
{
	struct homa_rpc *rpc, *tmp;

	rcu_read_lock();
	if (list_empty(&hsk->active_rpcs))
		goto done;
	if (!homa_protect_rpcs(hsk))
		goto done;
	list_for_each_entry_safe(rpc, tmp, &hsk->active_rpcs, active_links) {
		if (!homa_is_client(rpc->id))
			continue;
		homa_rpc_lock(rpc);
		if (rpc->state == RPC_DEAD) {
			homa_rpc_unlock(rpc);
			continue;
		}
		tt_record4("homa_abort_sock_rpcs aborting id %u on port %d, "
				"peer 0x%x, error %d",
				rpc->id, hsk->port,
				tt_addr(rpc->peer->addr), error);
		if (error) {
			homa_rpc_abort(rpc, error);
		} else
			homa_rpc_free(rpc);
		homa_rpc_unlock(rpc);
	}
	homa_unprotect_rpcs(hsk);
	done:
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
 * @flags:        Flags field from homa_recvmsg_args; see manual entry for
 *                details.
 * @id:           If non-zero, then the caller is interested in receiving
 *                the response for this RPC (@id must be a client request).
 * Return:        Either zero or a negative errno value. If a matching RPC
 *                is already available, information about it will be stored in
 *                interest.
 */
int homa_register_interests(struct homa_interest *interest,
		struct homa_sock *hsk, int flags, __u64 id)
{
	struct homa_rpc *rpc = NULL;

	homa_interest_init(interest);
	interest->locked = 1;
	if (id != 0) {
		if (!homa_is_client(id))
			return -EINVAL;
		rpc = homa_find_client_rpc(hsk, id);
		if (rpc == NULL)
			return -EINVAL;
		if ((rpc->interest != NULL) && (rpc->interest != interest)) {
			homa_rpc_unlock(rpc);
			return -EINVAL;
		}
	}

	/* Need both the RPC lock (acquired above) and the socket lock to
	 * avoid races.
	 */
	homa_sock_lock(hsk, "homa_register_interests");
	if (hsk->shutdown) {
		homa_sock_unlock(hsk);
		if (rpc)
			homa_rpc_unlock(rpc);
		return -ESHUTDOWN;
	}

	if (id != 0) {
		if ((atomic_read(&rpc->flags) & RPC_PKTS_READY) || rpc->error)
			goto claim_rpc;
		rpc->interest = interest;
		interest->reg_rpc = rpc;
		homa_rpc_unlock(rpc);
	}

	interest->locked = 0;
	if (flags & HOMA_RECVMSG_RESPONSE) {
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
	if (flags & HOMA_RECVMSG_REQUEST) {
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
	homa_sock_unlock(hsk);
	return 0;

    claim_rpc:
	list_del_init(&rpc->ready_links);
	if (!list_empty(&hsk->ready_requests) ||
			!list_empty(&hsk->ready_responses)) {
		// There are still more RPCs available, so let Linux know.
		hsk->sock.sk_data_ready(&hsk->sock);
	}

	/* This flag is needed to keep the RPC from being reaped during the
	 * gap between when we release the socket lock and we acquire the
	 * RPC lock.*/
	atomic_or(RPC_HANDING_OFF, &rpc->flags);
	homa_sock_unlock(hsk);
	if (!interest->locked) {
		homa_rpc_lock(rpc);
		interest->locked = 1;
	}
	atomic_andnot(RPC_HANDING_OFF, &rpc->flags);
	atomic_long_set_release(&interest->ready_rpc, (long) rpc);
	return 0;
}

/**
 * @homa_wait_for_message() - Wait for receipt of an incoming message
 * that matches the parameters. Various other activities can occur while
 * waiting, such as reaping dead RPCs and copying data to user space.
 * @hsk:          Socket where messages will arrive.
 * @flags:        Flags field from homa_recvmsg_args; see manual entry for
 *                details.
 * @id:           If non-zero, then a response message matching this id may
 *                be returned (@id must refer to a client request).
 *
 * Return:   Pointer to an RPC that matches @flags and @id, or a negative
 *           errno value. The RPC will be locked; the caller must unlock.
 */
struct homa_rpc *homa_wait_for_message(struct homa_sock *hsk, int flags,
		__u64 id)
{
	struct homa_rpc *result = NULL;
	struct homa_interest interest;
	struct homa_rpc *rpc = NULL;
	uint64_t poll_start, now;
	int error, blocked = 0, polled = 0;

	/* Each iteration of this loop finds an RPC, but it might not be
	 * in a state where we can return it (e.g., there might be packets
	 * ready to transfer to user space, but the incoming message isn't yet
	 * complete). Thus it could take many iterations of this loop
	 * before we have an RPC with a complete message.
	 */
	while (1) {
		error = homa_register_interests(&interest, hsk, flags, id);
		rpc = (struct homa_rpc *) atomic_long_read(&interest.ready_rpc);
		if (rpc) {
			goto found_rpc;
		}
		if (error < 0) {
			result = ERR_PTR(error);
			goto found_rpc;
		}

//		tt_record3("Preparing to poll, socket %d, flags 0x%x, pid %d",
//				hsk->client_port, flags, current->pid);

	        /* There is no ready RPC so far. Clean up dead RPCs before
		 * going to sleep (or returning, if in nonblocking mode).
		 */
		while (1) {
			int reaper_result;
			rpc = (struct homa_rpc *) atomic_long_read(
					&interest.ready_rpc);
			if (rpc) {
				tt_record1("received RPC handoff while reaping, id %d",
						rpc->id);
				goto found_rpc;
			}
			reaper_result = homa_rpc_reap(hsk,
					hsk->homa->reap_limit);
			if (reaper_result == 0)
				break;

			/* Give NAPI and SoftIRQ tasks a chance to run. */
			schedule();
		}
		tt_record1("Checking nonblocking, flags %d", flags);
		if (flags & HOMA_RECVMSG_NONBLOCKING) {
			result = ERR_PTR(-EAGAIN);
			goto found_rpc;
		}

		/* Busy-wait for a while before going to sleep; this avoids
		 * context-switching overhead to wake up.
		 */
		poll_start = now = get_cycles();
		while (1) {
			__u64 blocked;
			rpc = (struct homa_rpc *) atomic_long_read(
					&interest.ready_rpc);
			if (rpc) {
				tt_record3("received RPC handoff while polling, id %d, socket %d, pid %d",
						rpc->id, hsk->port,
						current->pid);
				polled = 1;
				INC_METRIC(poll_cycles, now - poll_start);
				goto found_rpc;
			}
			if (now >= (poll_start + hsk->homa->poll_cycles))
				break;
			blocked = get_cycles();
			schedule();
			now = get_cycles();
			blocked = now - blocked;
			if (blocked > 5000) {
				/* Looks like another thread ran (or perhaps
				 * SoftIRQ). Count this time as blocked.
				 */
				INC_METRIC(blocked_cycles, blocked);
				poll_start += blocked;
			}
		}
		tt_record2("Poll ended unsuccessfully on socket %d, pid %d",
				hsk->port, current->pid);
		INC_METRIC(poll_cycles, now - poll_start);

		/* Now it's time to sleep. */
		set_current_state(TASK_INTERRUPTIBLE);
		rpc = (struct homa_rpc *) atomic_long_read(&interest.ready_rpc);
		if (!rpc && !hsk->shutdown) {
			__u64 end;
			__u64 start = get_cycles();
			tt_record1("homa_wait_for_message sleeping, pid %d",
					current->pid);
			schedule();
			end = get_cycles();
			blocked = 1;
			INC_METRIC(blocked_cycles, end - start);
		}
		__set_current_state(TASK_RUNNING);

found_rpc:
		/* If we get here, it means either an RPC is ready for our
		 * attention or an error occurred.
		 *
		 * First, clean up all of the interests. Must do this before
		 * making any other decisions, because until we do, an incoming
		 * message could still be passed to us. Note: if we went to
		 * sleep, then this info was already cleaned up by whoever
		 * woke us up. Also, values in the interest may change between
		 * when we test them below and when we acquire the socket lock,
		 * so they have to be checked again after locking the socket.
		 */
		UNIT_HOOK("found_rpc");
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

		/* Now check to see if we received an RPC handoff (note that
		 * this could have happened anytime up until we reset the
		 * interests above).
		 */
		rpc = (struct homa_rpc *) atomic_long_read(&interest.ready_rpc);
		if (rpc) {
			tt_record2("homa_wait_for_message found rpc id %d, pid %d",
					rpc->id, current->pid);
			if (!interest.locked)
				homa_rpc_lock(rpc);
			atomic_andnot(RPC_HANDING_OFF, &rpc->flags);
			if (rpc->state == RPC_DEAD) {
				homa_rpc_unlock(rpc);
				continue;
			}
			if (!rpc->error)
				rpc->error = homa_copy_to_user(rpc);
			if (rpc->error)
				goto done;
			atomic_andnot(RPC_PKTS_READY, &rpc->flags);
			if (rpc->msgin.copied_out == rpc->msgin.total_length)
				goto done;
			homa_rpc_unlock(rpc);
		}

		/* A complete message isn't available: check for errors. */
		if (IS_ERR(result))
			return result;
		if (signal_pending(current))
			return ERR_PTR(-EINTR);

                /* No message and no error; try again. */
	}

done:
	if (blocked)
		INC_METRIC(slow_wakeups, 1);
	else if (polled)
		INC_METRIC(fast_wakeups, 1);
	return rpc;

}

/**
 * @homa_rpc_handoff: This function is called when the input message for
 * an RPC is ready for attention from a user thread. It either notifies
 * a waiting reader or queues the RPC.
 * @rpc:                RPC to handoff; must be locked. The caller must
 *			also have locked the socket for this RPC.
 */
void homa_rpc_handoff(struct homa_rpc *rpc)
{
	struct homa_interest *interest;
	struct homa_sock *hsk = rpc->hsk;

	if ((atomic_read(&rpc->flags) & RPC_HANDING_OFF)
			|| !list_empty(&rpc->ready_links))
		return;

	/* First, see if someone is interested in this RPC specifically.
	 */
	if (rpc->interest) {
		interest = rpc->interest;
		goto thread_waiting;
	}

	/* Second, check the interest list for this type of RPC. */
	if (homa_is_client(rpc->id)) {
		interest = list_first_entry_or_null(
				&hsk->response_interests,
				struct homa_interest, response_links);
		if (interest)
			goto thread_waiting;
		list_add_tail(&rpc->ready_links, &hsk->ready_responses);
		INC_METRIC(responses_queued, 1);
	} else {
		interest = list_first_entry_or_null(
				&hsk->request_interests,
				struct homa_interest, request_links);
		if (interest)
			goto thread_waiting;
		list_add_tail(&rpc->ready_links, &hsk->ready_requests);
		INC_METRIC(requests_queued, 1);
	}

	/* If we get here, no-one is waiting for the RPC, so it has been
	 * queued.
	 */

	/* Notify the poll mechanism. */
	hsk->sock.sk_data_ready(&hsk->sock);
	tt_record2("homa_rpc_handoff finished queuing id %d for port %d",
			rpc->id, hsk->port);
	return;

thread_waiting:
	/* We found a waiting thread. The following 3 lines must be here,
	 * before clearing the interest, in order to avoid a race with
	 * homa_wait_for_message (which won't acquire the socket lock if
	 * the interest is clear).
	 */
	atomic_or(RPC_HANDING_OFF, &rpc->flags);
	interest->locked = 0;
	atomic_long_set_release(&interest->ready_rpc, (long) rpc);

	/* Clear the interest. This serves two purposes. First, it saves
	 * the waking thread from acquiring the socket lock again, which
	 * reduces contention on that lock). Second, it ensures that
	 * no-one else attempts to give this interest a different RPC.
	 */
	if (interest->reg_rpc) {
		interest->reg_rpc->interest = NULL;
		interest->reg_rpc = NULL;
	}
	if (interest->request_links.next != LIST_POISON1)
		list_del(&interest->request_links);
	if (interest->response_links.next != LIST_POISON1)
		list_del(&interest->response_links);
	wake_up_process(interest->thread);
	tt_record3("homa_rpc_handoff handed off id %d to pid %d on core %d",
			rpc->id, interest->thread->pid,
			task_cpu(interest->thread));
}

/**
 * homa_incoming_sysctl_changed() - Invoked whenever a sysctl value is changed;
 * any input-related parameters that depend on sysctl-settable values.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_incoming_sysctl_changed(struct homa *homa)
{
	__u64 tmp;

	if (homa->grant_fifo_fraction > 500)
		homa->grant_fifo_fraction = 500;
	tmp = homa->grant_fifo_fraction;
	if (tmp != 0)
		tmp = (1000*homa->fifo_grant_increment)/tmp
				- homa->fifo_grant_increment;
	homa->grant_nonfifo = tmp;

	if (homa->max_overcommit > MAX_GRANTS)
		homa->max_overcommit = MAX_GRANTS;

	/* Code below is written carefully to avoid integer underflow or
	 * overflow under expected usage patterns. Be careful when changing!
	 */
	tmp = homa->poll_usecs;
	tmp = (tmp*cpu_khz)/1000;
	homa->poll_cycles = tmp;

	tmp = homa->gro_busy_usecs;
	tmp = (tmp*cpu_khz)/1000;
	homa->gro_busy_cycles = tmp;

	tmp = homa->bpage_lease_usecs;
	tmp = (tmp*cpu_khz)/1000;
	homa->bpage_lease_cycles = tmp;
}
