// SPDX-License-Identifier: BSD-2-Clause

/* This file contains functions that handle incoming Homa messages, including
 * both receiving information for those messages and sending grants.
 */

#include "homa_impl.h"
#include "homa_grant.h"
#include "homa_offload.h"
#include "homa_peer.h"
#include "homa_pool.h"

/**
 * homa_message_in_init() - Constructor for homa_message_in.
 * @rpc:          RPC whose msgin structure should be initialized.
 * @length:       Total number of bytes in message.
 * @unsched:      The number of unscheduled bytes the sender is planning
 *                to transmit.
 * Return:        Zero for successful initialization, or a negative errno
 *                if rpc->msgin could not be initialized.
 */
int homa_message_in_init(struct homa_rpc *rpc, int length, int unsched)
{
	int err;

	if (length > HOMA_MAX_MESSAGE_LENGTH)
		return -EINVAL;

	rpc->msgin.length = length;
	skb_queue_head_init(&rpc->msgin.packets);
	rpc->msgin.recv_end = 0;
	INIT_LIST_HEAD(&rpc->msgin.gaps);
	rpc->msgin.bytes_remaining = length;
	rpc->msgin.granted = (unsched > length) ? length : unsched;
	rpc->msgin.rec_incoming = 0;
	atomic_set(&rpc->msgin.rank, -1);
	rpc->msgin.priority = 0;
	rpc->msgin.resend_all = 0;
	rpc->msgin.num_bpages = 0;
	err = homa_pool_allocate(rpc);
	if (err != 0)
		return err;
	if (rpc->msgin.num_bpages == 0) {
		/* The RPC is now queued waiting for buffer space, so we're
		 * going to discard all of its packets.
		 */
		rpc->msgin.granted = 0;
	}
	if (length < HOMA_NUM_SMALL_COUNTS * 64) {
		INC_METRIC(small_msg_bytes[(length - 1) >> 6], length);
	} else if (length < HOMA_NUM_MEDIUM_COUNTS * 1024) {
		INC_METRIC(medium_msg_bytes[(length - 1) >> 10], length);
	} else {
		INC_METRIC(large_msg_count, 1);
		INC_METRIC(large_msg_bytes, length);
	}
	return 0;
}

/**
 * homa_gap_new() - Create a new gap and add it to a list.
 * @next:   Add the new gap just before this list element.
 * @start:  Offset of first byte covered by the gap.
 * @end:    Offset of byte just after the last one covered by the gap.
 * Return:  Pointer to the new gap, or NULL if memory couldn't be allocated
 *          for the gap object.
 */
struct homa_gap *homa_gap_new(struct list_head *next, int start, int end)
{
	struct homa_gap *gap;

	gap = kmalloc(sizeof(*gap), GFP_ATOMIC);
	if (!gap)
		return NULL;
	gap->start = start;
	gap->end = end;
	gap->time = sched_clock();
	list_add_tail(&gap->links, next);
	return gap;
}

/**
 * homa_gap_retry() - Send RESEND requests for all of the unreceived
 * gaps in a message.
 * @rpc:     RPC to check; must be locked by caller.
 */
void homa_gap_retry(struct homa_rpc *rpc)
{
	struct homa_resend_hdr resend;
	struct homa_gap *gap;

	list_for_each_entry(gap, &rpc->msgin.gaps, links) {
		resend.offset = htonl(gap->start);
		resend.length = htonl(gap->end - gap->start);
		resend.priority = rpc->hsk->homa->num_priorities - 1;
		tt_record3("homa_gap_retry sending RESEND for id %d, start %d, end %d",
			   rpc->id, gap->start, gap->end);
		homa_xmit_control(RESEND, &resend, sizeof(resend), rpc);
	}
}

/**
 * homa_add_packet() - Add an incoming packet to the contents of a
 * partially received message.
 * @rpc:   Add the packet to the msgin for this RPC.
 * @skb:   The new packet. This function takes ownership of the packet
 *         (the packet will either be freed or added to rpc->msgin.packets).
 */
void homa_add_packet(struct homa_rpc *rpc, struct sk_buff *skb)
{
	struct homa_data_hdr *h = (struct homa_data_hdr *)skb->data;
	struct homa_gap *gap, *dummy, *gap2;
	int start = ntohl(h->seg.offset);
	int length = homa_data_len(skb);
	int end = start + length;

	if ((start + length) > rpc->msgin.length) {
		tt_record3("Packet extended past message end; id %d, offset %d, length %d",
			   rpc->id, start, length);
		goto discard;
	}

	if (start == rpc->msgin.recv_end) {
		/* Common case: packet is sequential. */
		rpc->msgin.recv_end += length;
		goto keep;
	}

	if (start > rpc->msgin.recv_end) {
		/* Packet creates a new gap. */
		if (!homa_gap_new(&rpc->msgin.gaps,
				  rpc->msgin.recv_end, start)) {
			pr_err("Homa couldn't allocate gap: insufficient memory\n");
			tt_record2("Couldn't allocate gap for id %d (start %d): no memory",
				   rpc->id, start);
			goto discard;
		}
		rpc->msgin.recv_end = end;
		goto keep;
	}

	/* Must now check to see if the packet fills in part or all of
	 * an existing gap.
	 */
	list_for_each_entry_safe(gap, dummy, &rpc->msgin.gaps, links) {
		/* Is packet at the start of this gap? */
		if (start <= gap->start) {
			if (end <= gap->start)
				continue;
			if (start < gap->start) {
				tt_record4("Packet overlaps gap start: id %d, start %d, end %d, gap_start %d",
					   rpc->id, start, end, gap->start);
				goto discard;
			}
			if (end > gap->end) {
				tt_record4("Packet overlaps gap end: id %d, start %d, end %d, gap_end %d",
					   rpc->id, start, end, gap->start);
				goto discard;
			}
			gap->start = end;
			if (gap->start >= gap->end) {
				list_del(&gap->links);
				kfree(gap);
			}
			goto keep;
		}

		/* Is packet at the end of this gap? BTW, at this point we know
		 * the packet can't cover the entire gap.
		 */
		if (end >= gap->end) {
			if (start >= gap->end)
				continue;
			if (end > gap->end) {
				tt_record4("Packet overlaps gap end: id %d, start %d, end %d, gap_end %d",
					   rpc->id, start, end, gap->start);
				goto discard;
			}
			gap->end = start;
			goto keep;
		}

		/* Packet is in the middle of the gap; must split the gap. */
		gap2 = homa_gap_new(&gap->links, gap->start, start);
		if (!gap2) {
			pr_err("Homa couldn't allocate gap for split: insufficient memory\n");
			tt_record2("Couldn't allocate gap for split for id %d (start %d): no memory",
				   rpc->id, end);
			goto discard;
		}
		gap2->time = gap->time;
		gap->start = end;
		goto keep;
	}

discard:
	if (h->retransmit)
		INC_METRIC(resent_discards, 1);
	else
		INC_METRIC(packet_discards, 1);
	tt_record4("homa_add_packet discarding packet for id %d, offset %d, length %d, retransmit %d",
		   rpc->id, start, length, h->retransmit);
	kfree_skb(skb);
	return;

keep:
	if (h->retransmit)
		INC_METRIC(resent_packets_used, 1);
	__skb_queue_tail(&rpc->msgin.packets, skb);
	rpc->msgin.bytes_remaining -= length;
}

/**
 * homa_copy_to_user() - Copy as much data as possible from incoming
 * packet buffers to buffers in user space.
 * @rpc:     RPC for which data should be copied. Must be locked by caller.
 * Return:   Zero for success or a negative errno if there is an error.
 *           It is possible for the RPC to be freed while this function
 *           executes (it releases and reacquires the RPC lock). If that
 *           happens, -EINVAL will be returned and the state of @rpc
 *           will be RPC_DEAD.
 */
int homa_copy_to_user(struct homa_rpc *rpc)
	__releases(rpc->bucket_lock)
	__acquires(rpc->bucket_lock)
{
#ifdef __UNIT_TEST__
#define MAX_SKBS 3
#else /* __UNIT_TEST__ */
#define MAX_SKBS 20
#endif /* __UNIT_TEST__ */
	struct sk_buff *skbs[MAX_SKBS];
#ifndef __STRIP__ /* See strip.py */
	int start_offset = 0;
	int end_offset = 0;
#endif /* See strip.py */
	int error = 0;
	u64 start;
	int n = 0;             /* Number of filled entries in skbs. */
	int i;

	/* Tricky note: we can't hold the RPC lock while we're actually
	 * copying to user space, because (a) it's illegal to hold a spinlock
	 * while copying to user space and (b) we'd like for homa_softirq
	 * to add more packets to the RPC while we're copying these out.
	 * So, collect a bunch of packets to copy, then release the lock,
	 * copy them, and reacquire the lock.
	 */
	while (true) {
		struct sk_buff *skb;

		if (rpc->state == RPC_DEAD) {
			error = -EINVAL;
			break;
		}

		skb = __skb_dequeue(&rpc->msgin.packets);
		if (skb) {
			skbs[n] = skb;
			n++;
			if (n < MAX_SKBS)
				continue;
		}
		if (n == 0)
			break;

		/* At this point we've collected a batch of packets (or
		 * run out of packets); copy any available packets out to
		 * user space.
		 */
		atomic_or(RPC_COPYING_TO_USER, &rpc->flags);
		homa_rpc_unlock(rpc);

		tt_record1("starting copy to user space for id %d",
			   rpc->id);

		/* Each iteration of this loop copies out one skb. */
		for (i = 0; i < n; i++) {
			struct homa_data_hdr *h = (struct homa_data_hdr *)
					skbs[i]->data;
			int pkt_length = homa_data_len(skbs[i]);
			int offset = ntohl(h->seg.offset);
			int buf_bytes, chunk_size;
			struct iov_iter iter;
			int copied = 0;
			char *dst;

			/* Each iteration of this loop copies to one
			 * user buffer.
			 */
			while (copied < pkt_length) {
				chunk_size = pkt_length - copied;
				dst = homa_pool_get_buffer(rpc, offset + copied,
							   &buf_bytes);
				if (buf_bytes < chunk_size) {
					if (buf_bytes == 0) {
						/* skb has data beyond message
						 * end?
						 */
						break;
					}
					chunk_size = buf_bytes;
				}
				error = import_ubuf(READ, (void __user *)dst,
						    chunk_size, &iter);
				if (error)
					goto free_skbs;
				error = skb_copy_datagram_iter(skbs[i],
							       sizeof(*h) +
							       copied,  &iter,
							       chunk_size);
				if (error)
					goto free_skbs;
				copied += chunk_size;
			}
#ifndef __STRIP__ /* See strip.py */
			if (end_offset == 0) {
				start_offset = offset;
			} else if (end_offset != offset) {
				tt_record3("copied out bytes %d-%d for id %d",
					   start_offset, end_offset, rpc->id);
				start_offset = offset;
			}
			end_offset = offset + pkt_length;
#endif /* See strip.py */
		}

free_skbs:
#ifndef __STRIP__ /* See strip.py */
		if (end_offset != 0) {
			tt_record3("copied out bytes %d-%d for id %d",
				   start_offset, end_offset, rpc->id);
			end_offset = 0;
		}
#endif /* See strip.py */
		start = sched_clock();
		for (i = 0; i < n; i++)
			kfree_skb(skbs[i]);
		INC_METRIC(skb_free_ns, sched_clock() - start);
		INC_METRIC(skb_frees, n);
		tt_record2("finished freeing %d skbs for id %d",
			   n, rpc->id);
		n = 0;
		atomic_or(APP_NEEDS_LOCK, &rpc->flags);
		homa_rpc_lock(rpc);
		atomic_andnot(APP_NEEDS_LOCK | RPC_COPYING_TO_USER,
			      &rpc->flags);
		if (error)
			break;
	}
	if (error)
		tt_record2("homa_copy_to_user returning error %d for id %d",
			   -error, rpc->id);
	return error;
}

/**
 * homa_dispatch_pkts() - Top-level function that processes a batch of packets,
 * all related to the same RPC.
 * @skb:       First packet in the batch, linked through skb->next.
 * @homa:      Overall information about the Homa transport.
 */
void homa_dispatch_pkts(struct sk_buff *skb, struct homa *homa)
{
#ifdef __UNIT_TEST__
#define MAX_ACKS 2
#else /* __UNIT_TEST__ */
#define MAX_ACKS 10
#endif /* __UNIT_TEST__ */
	const struct in6_addr saddr = skb_canonical_ipv6_saddr(skb);
	struct homa_data_hdr *h = (struct homa_data_hdr *)skb->data;
	u64 id = homa_local_id(h->common.sender_id);
	int dport = ntohs(h->common.dport);

	/* Used to collect acks from data packets so we can process them
	 * all at the end (can't process them inline because that may
	 * require locking conflicting RPCs). If we run out of space just
	 * ignore the extra acks; they'll be regenerated later through the
	 * explicit mechanism.
	 */
	struct homa_ack acks[MAX_ACKS];
	struct homa_rpc *rpc = NULL;
	struct homa_sock *hsk;
	struct sk_buff *next;
	int num_acks = 0;

	/* Find the appropriate socket.*/
	hsk = homa_sock_find(homa->port_map, dport);
	if (!hsk) {
		if (skb_is_ipv6(skb))
			icmp6_send(skb, ICMPV6_DEST_UNREACH,
				   ICMPV6_PORT_UNREACH, 0, NULL, IP6CB(skb));
		else
			icmp_send(skb, ICMP_DEST_UNREACH,
				  ICMP_PORT_UNREACH, 0);
		tt_record3("Discarding packet(s) for unknown port %u, id %llu, type %d",
			   dport, homa_local_id(h->common.sender_id),
			   h->common.type);
		while (skb) {
			next = skb->next;
			kfree_skb(skb);
			skb = next;
		}
		return;
	}

	/* Each iteration through the following loop processes one packet. */
	for (; skb; skb = next) {
		h = (struct homa_data_hdr *)skb->data;
		next = skb->next;

		/* Relinquish the RPC lock temporarily if it's needed
		 * elsewhere.
		 */
		if (rpc) {
			int flags = atomic_read(&rpc->flags);

			if (flags & APP_NEEDS_LOCK) {
				homa_rpc_unlock(rpc);
				tt_record2("softirq released lock for id %d, flags 0x%x", rpc->id, flags);
				homa_spin(200);
				rpc = NULL;
			}
		}

		/* Find and lock the RPC if we haven't already done so. */
		if (!rpc) {
			if (!homa_is_client(id)) {
				/* We are the server for this RPC. */
				if (h->common.type == DATA) {
					int created;

					/* Create a new RPC if one doesn't
					 * already exist.
					 */
					rpc = homa_rpc_new_server(hsk, &saddr,
								  h, &created);
					if (IS_ERR(rpc)) {
						pr_warn("homa_pkt_dispatch couldn't create server rpc: error %lu",
							-PTR_ERR(rpc));
						INC_METRIC(server_cant_create_rpcs, 1);
						rpc = NULL;
						goto discard;
					}
				} else {
					rpc = homa_find_server_rpc(hsk, &saddr,
								   id);
				}
			} else {
				rpc = homa_find_client_rpc(hsk, id);
			}
		}
		if (unlikely(!rpc)) {
			if (h->common.type != CUTOFFS &&
			    h->common.type != NEED_ACK &&
			    h->common.type != ACK &&
			    h->common.type != RESEND) {
				tt_record4("Discarding packet for unknown RPC, id %u, type %d, peer 0x%x:%d",
					   id, h->common.type, tt_addr(saddr),
					   ntohs(h->common.sport));
				if (h->common.type != GRANT ||
				    homa_is_client(id))
					INC_METRIC(unknown_rpcs, 1);
				goto discard;
			}
		} else {
			if (h->common.type == DATA ||
			    h->common.type == GRANT ||
			    h->common.type == BUSY ||
			    h->common.type == NEED_ACK)
				rpc->silent_ticks = 0;
#ifndef __STRIP__ /* See strip.py */
			rpc->peer->outstanding_resends = 0;
#endif /* See strip.py */
		}

		switch (h->common.type) {
		case DATA:
			if (h->ack.client_id) {
				/* Save the ack for processing later, when we
				 * have released the RPC lock.
				 */
				if (num_acks < MAX_ACKS) {
					acks[num_acks] = h->ack;
					num_acks++;
				}
			}
			homa_data_pkt(skb, rpc);
			INC_METRIC(packets_received[DATA - DATA], 1);
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
			/* Nothing to do for these packets except reset
			 * silent_ticks, which happened above.
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

			/* It isn't safe to process more packets once we've
			 * released the RPC lock (this should never happen).
			 */
			while (next) {
				WARN_ONCE(next, "%s found extra packets after AC<\n",
					  __func__);
				skb = next;
				next = skb->next;
				kfree_skb(skb);
			}
			break;
		default:
			INC_METRIC(unknown_packet_types, 1);
			goto discard;
		}
		continue;

discard:
		kfree_skb(skb);
	}
	if (rpc)
		homa_grant_check_rpc(rpc); /* Unlocks rpc. */

	while (num_acks > 0) {
		num_acks--;
		homa_rpc_acked(hsk, &saddr, &acks[num_acks]);
	}

	if (hsk->dead_skbs >= 2 * hsk->homa->dead_buffs_limit) {
		/* We get here if neither homa_wait_for_message
		 * nor homa_timer can keep up with reaping dead
		 * RPCs. See reap.txt for details.
		 */
		u64 start = sched_clock();

		tt_record("homa_data_pkt calling homa_rpc_reap");
		homa_rpc_reap(hsk, false);
		INC_METRIC(data_pkt_reap_ns, sched_clock() - start);
	}
}

/**
 * homa_data_pkt() - Handler for incoming DATA packets
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * @rpc:     Information about the RPC corresponding to this packet.
 *           Must be locked by the caller.
 */
void homa_data_pkt(struct sk_buff *skb, struct homa_rpc *rpc)
{
	struct homa_data_hdr *h = (struct homa_data_hdr *)skb->data;
	struct homa *homa = rpc->hsk->homa;

	tt_record4("incoming data packet, id %d, peer 0x%x, offset %d/%d",
		   homa_local_id(h->common.sender_id),
		   tt_addr(rpc->peer->addr), ntohl(h->seg.offset),
		   ntohl(h->message_length));

	if (rpc->state != RPC_INCOMING && homa_is_client(rpc->id)) {
		if (unlikely(rpc->state != RPC_OUTGOING))
			goto discard;
		INC_METRIC(responses_received, 1);
		rpc->state = RPC_INCOMING;
		tt_record2("Incoming message for id %d has %d unscheduled bytes",
			   rpc->id, ntohl(h->incoming));
		if (homa_message_in_init(rpc, ntohl(h->message_length),
					 ntohl(h->incoming)) != 0)
			goto discard;
	} else if (rpc->state != RPC_INCOMING) {
		/* Must be server; note that homa_rpc_new_server already
		 * initialized msgin and allocated buffers.
		 */
		if (unlikely(rpc->msgin.length >= 0))
			goto discard;
	}

	if (rpc->msgin.num_bpages == 0) {
		/* Drop packets that arrive when we can't allocate buffer
		 * space. If we keep them around, packet buffer usage can
		 * exceed available cache space, resulting in poor
		 * performance.
		 */
		tt_record4("Dropping packet because no buffer space available: id %d, offset %d, length %d, old incoming %d",
			   rpc->id, ntohl(h->seg.offset), homa_data_len(skb),
			   rpc->msgin.granted);
		INC_METRIC(dropped_data_no_bufs, homa_data_len(skb));
		goto discard;
	}

	homa_add_packet(rpc, skb);

	if (skb_queue_len(&rpc->msgin.packets) != 0 &&
	    !(atomic_read(&rpc->flags) & RPC_PKTS_READY)) {
		atomic_or(RPC_PKTS_READY, &rpc->flags);
		homa_sock_lock(rpc->hsk);
		homa_rpc_handoff(rpc);
		homa_sock_unlock(rpc->hsk);
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
			struct homa_cutoffs_hdr h2;
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
	struct homa_grant_hdr *h = (struct homa_grant_hdr *)skb->data;
	int new_offset = ntohl(h->offset);

	tt_record4("processing grant for id %llu, offset %d, priority %d, increment %d",
		   homa_local_id(h->common.sender_id), ntohl(h->offset),
		   h->priority, new_offset - rpc->msgout.granted);
	if (rpc->state == RPC_OUTGOING) {
		if (h->resend_all)
			homa_resend_data(rpc, 0, rpc->msgout.next_xmit_offset,
					 h->priority);

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
	struct homa_resend_hdr *h = (struct homa_resend_hdr *)skb->data;
#ifndef __STRIP__ /* See strip.py */
	const struct in6_addr saddr = skb_canonical_ipv6_saddr(skb);
#endif /* See strip.py */
	struct homa_busy_hdr busy;

	if (!rpc) {
		tt_record4("resend request for unknown id %d, peer 0x%x:%d, offset %d; responding with UNKNOWN",
			   homa_local_id(h->common.sender_id), tt_addr(saddr),
			   ntohs(h->common.sport), ntohl(h->offset));
		homa_xmit_unknown(skb, hsk);
		goto done;
	}
	tt_record4("resend request for id %llu, offset %d, length %d, prio %d",
		   rpc->id, ntohl(h->offset), ntohl(h->length), h->priority);

	if (!homa_is_client(rpc->id) && rpc->state != RPC_OUTGOING) {
		/* We are the server for this RPC and don't yet have a
		 * response packet, so just send BUSY.
		 */
		tt_record2("sending BUSY from resend, id %d, state %d",
			   rpc->id, rpc->state);
		homa_xmit_control(BUSY, &busy, sizeof(busy), rpc);
		goto done;
	}
	if (rpc->msgout.next_xmit_offset < rpc->msgout.granted) {
		/* We have chosen not to transmit data from this message;
		 * send BUSY instead.
		 */
		tt_record3("sending BUSY from resend, id %d, offset %d, granted %d",
			   rpc->id, rpc->msgout.next_xmit_offset,
			   rpc->msgout.granted);
		homa_xmit_control(BUSY, &busy, sizeof(busy), rpc);
	} else {
		if (ntohl(h->length) == 0)
			/* This RESEND is from a server just trying to determine
			 * whether the client still cares about the RPC; return
			 * BUSY so the server doesn't time us out.
			 */
			homa_xmit_control(BUSY, &busy, sizeof(busy), rpc);
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
			tt_record4("Restarting id %d to server 0x%x:%d, lost %d bytes",
				   rpc->id, tt_addr(rpc->peer->addr),
				   rpc->dport, rpc->msgout.next_xmit_offset);
			homa_freeze(rpc, RESTART_RPC,
				    "Freezing because of RPC restart, id %d, peer 0x%x");
			homa_resend_data(rpc, 0, rpc->msgout.next_xmit_offset,
					 homa_unsched_priority(rpc->hsk->homa,
							       rpc->peer,
							       rpc->msgout.length));
			goto done;
		}

		pr_err("Received unknown for RPC id %llu, peer %s:%d in bogus state %d; discarding unknown\n",
		       rpc->id, homa_print_ipv6_addr(&rpc->peer->addr),
		       rpc->dport, rpc->state);
		tt_record4("Discarding unknown for RPC id %d, peer 0x%x:%d: bad state %d",
			   rpc->id, tt_addr(rpc->peer->addr), rpc->dport,
			   rpc->state);
	} else {
		if (rpc->hsk->homa->verbose)
			pr_notice("Ending rpc id %llu from client %s:%d: unknown to client",
				  rpc->id,
				  homa_print_ipv6_addr(&rpc->peer->addr),
				  rpc->dport);
		homa_rpc_end(rpc);
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
	struct homa_cutoffs_hdr *h = (struct homa_cutoffs_hdr *)skb->data;
	const struct in6_addr saddr = skb_canonical_ipv6_saddr(skb);
	struct homa_peer *peer;
	int i;

	peer = homa_peer_find(hsk->homa->peers, &saddr, &hsk->inet);
	if (!IS_ERR(peer)) {
		peer->unsched_cutoffs[0] = INT_MAX;
		for (i = 1; i < HOMA_MAX_PRIORITIES; i++)
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
	struct homa_common_hdr *h = (struct homa_common_hdr *)skb->data;
	const struct in6_addr saddr = skb_canonical_ipv6_saddr(skb);
	u64 id = homa_local_id(h->sender_id);
	struct homa_peer *peer;
	struct homa_ack_hdr ack;

	tt_record1("Received NEED_ACK for id %d", id);

	/* Return if it's not safe for the peer to purge its state
	 * for this RPC (the RPC still exists and we haven't received
	 * the entire response), or if we can't find peer info.
	 */
	if (rpc && (rpc->state != RPC_INCOMING ||
		    rpc->msgin.bytes_remaining)) {
#ifndef __STRIP__ /* See strip.py */
		tt_record3("NEED_ACK arrived for id %d before message received, state %d, remaining %d",
			   rpc->id, rpc->state, rpc->msgin.bytes_remaining);
		homa_freeze(rpc, NEED_ACK_MISSING_DATA,
			    "Freezing because NEED_ACK received before message complete, id %d, peer 0x%x");
#endif /* See strip.py */
		goto done;
	} else {
		peer = homa_peer_find(hsk->homa->peers, &saddr, &hsk->inet);
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
	ack.common.flags = HOMA_TCP_FLAGS;
	ack.common.urgent = htons(HOMA_TCP_URGENT);
	ack.common.sender_id = cpu_to_be64(id);
	ack.num_acks = htons(homa_peer_get_acks(peer,
						HOMA_MAX_ACKS_PER_PKT,
						ack.acks));
	__homa_xmit_control(&ack, sizeof(ack), peer, hsk);
	tt_record3("Responded to NEED_ACK for id %d, peer %0x%x with %d other acks",
		   id, tt_addr(saddr), ntohs(ack.num_acks));

done:
	kfree_skb(skb);
}

/**
 * homa_ack_pkt() - Handler for incoming ACK packets
 * @skb:     Incoming packet; size already verified large enough for header.
 *           This function now owns the packet.
 * @hsk:     Socket on which the packet was received.
 * @rpc:     The RPC named in the packet header, or NULL if no such
 *           RPC exists. The RPC has been locked by the caller but will
 *           be unlocked here.
 */
void homa_ack_pkt(struct sk_buff *skb, struct homa_sock *hsk,
		  struct homa_rpc *rpc)
	__releases(rpc->bucket_lock)
{
	const struct in6_addr saddr = skb_canonical_ipv6_saddr(skb);
	struct homa_ack_hdr *h = (struct homa_ack_hdr *)skb->data;
	int i, count;

	if (rpc) {
		tt_record1("homa_ack_pkt freeing rpc id %d", rpc->id);
		homa_rpc_end(rpc);
		homa_rpc_unlock(rpc);
	}

	count = ntohs(h->num_acks);
	for (i = 0; i < count; i++)
		homa_rpc_acked(hsk, &saddr, &h->acks[i]);
	tt_record3("ACK received for id %d, peer 0x%x, with %d other acks",
		   homa_local_id(h->common.sender_id), tt_addr(saddr), count);
	kfree_skb(skb);
}

/**
 * homa_choose_fifo_grant() - This function is invoked occasionally to give
 * a high-priority grant to the oldest incoming message. We do this in
 * order to reduce the starvation that SRPT can cause for long messages.
 * Note: this method is obsolete and should never be invoked; it's code is
 * being retained until fifo grants are reimplemented using the new grant
 * mechanism.
 * @homa:    Overall data about the Homa protocol implementation. The
 *           grantable_lock must be held by the caller.
 * Return: An RPC to which to send a FIFO grant, or NULL if there is
 *         no appropriate RPC. This method doesn't actually send a grant,
 *         but it updates @msgin.granted to reflect the desired grant.
 *         Also updates homa->total_incoming.
 */
struct homa_rpc *homa_choose_fifo_grant(struct homa *homa)
{
	struct homa_rpc *rpc, *oldest;
	u64 oldest_birth;
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

		received = (rpc->msgin.length
				- rpc->msgin.bytes_remaining);
		on_the_way = rpc->msgin.granted - received;
		if (on_the_way > homa->unsched_bytes) {
			/* The last "pity" grant hasn't been used
			 * up yet.
			 */
			continue;
		}
		oldest = rpc;
		oldest_birth = rpc->msgin.birth;
	}
	if (!oldest)
		return NULL;
	INC_METRIC(fifo_grants, 1);
	if ((oldest->msgin.length - oldest->msgin.bytes_remaining)
			== oldest->msgin.granted)
		INC_METRIC(fifo_grants_no_incoming, 1);

	oldest->silent_ticks = 0;
	granted = homa->fifo_grant_increment;
	oldest->msgin.granted += granted;
	if (oldest->msgin.granted >= oldest->msgin.length) {
		granted -= oldest->msgin.granted - oldest->msgin.length;
		oldest->msgin.granted = oldest->msgin.length;
		// homa_remove_grantable_locked(homa, oldest);
	}

	/* Try to update homa->total_incoming; if we can't lock
	 * the RPC, just skip it (waiting could deadlock), and it
	 * will eventually get updated elsewhere.
	 */
	if (homa_rpc_try_lock(oldest)) {
		homa_grant_update_incoming(oldest, homa);
		homa_rpc_unlock(oldest);
	}

	if (oldest->msgin.granted < (oldest->msgin.length
				- oldest->msgin.bytes_remaining)) {
		/* We've already received all of the bytes in the new
		 * grant; most likely this means that the sender sent extra
		 * data after the last fifo grant (e.g. by rounding up to a
		 * TSO packet). Don't send this grant.
		 */
		return NULL;
	}
	return oldest;
}

/**
 * homa_rpc_abort() - Terminate an RPC.
 * @rpc:     RPC to be terminated.  Must be locked by caller.
 * @error:   A negative errno value indicating the error that caused the abort.
 *           If this is a client RPC, the error will be returned to the
 *           application; if it's a server RPC, the error is ignored and
 *           we just free the RPC.
 */
void homa_rpc_abort(struct homa_rpc *rpc, int error)
{
	if (!homa_is_client(rpc->id)) {
		INC_METRIC(server_rpc_discards, 1);
		tt_record3("aborting server RPC: peer 0x%x, id %d, error %d",
			   tt_addr(rpc->peer->addr), rpc->id, error);
		homa_rpc_end(rpc);
		return;
	}
	tt_record3("aborting client RPC: peer 0x%x, id %d, error %d",
		   tt_addr(rpc->peer->addr), rpc->id, error);
	rpc->error = error;
	homa_sock_lock(rpc->hsk);
	if (!rpc->hsk->shutdown)
		homa_rpc_handoff(rpc);
	homa_sock_unlock(rpc->hsk);
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
	struct homa_rpc *rpc, *tmp;
	struct homa_sock *hsk;

	rcu_read_lock();
	for (hsk = homa_socktab_start_scan(homa->port_map, &scan); hsk;
	     hsk = homa_socktab_next(&scan)) {
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
			if (port && rpc->dport != port)
				continue;
			homa_rpc_lock(rpc);
			homa_rpc_abort(rpc, error);
			homa_rpc_unlock(rpc);
		}
		homa_unprotect_rpcs(hsk);
	}
	homa_socktab_end_scan(&scan);
	rcu_read_unlock();
}

/**
 * homa_abort_sock_rpcs() - Abort all outgoing (client-side) RPCs on a given
 * socket.
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
		tt_record4("homa_abort_sock_rpcs aborting id %u on port %d, peer 0x%x, error %d",
			   rpc->id, hsk->port,
			   tt_addr(rpc->peer->addr), error);
		if (error)
			homa_rpc_abort(rpc, error);
		else
			homa_rpc_end(rpc);
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
			    struct homa_sock *hsk, int flags, u64 id)
{
	struct homa_rpc *rpc = NULL;
	int locked = 1;

	homa_interest_init(interest);
	if (id != 0) {
		if (!homa_is_client(id))
			return -EINVAL;
		rpc = homa_find_client_rpc(hsk, id); /* Locks rpc. */
		if (!rpc)
			return -EINVAL;
		if (rpc->interest && rpc->interest != interest) {
			homa_rpc_unlock(rpc);
			return -EINVAL;
		}
	}

	/* Need both the RPC lock (acquired above) and the socket lock to
	 * avoid races.
	 */
	homa_sock_lock(hsk);
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

	locked = 0;
	if (flags & HOMA_RECVMSG_RESPONSE) {
		if (!list_empty(&hsk->ready_responses)) {
			rpc = list_first_entry(&hsk->ready_responses,
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
			if (!list_empty(&interest->response_links))
				list_del_init(&interest->response_links);
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
	 * RPC lock.
	 */
	atomic_or(RPC_HANDING_OFF, &rpc->flags);
	homa_sock_unlock(hsk);
	if (!locked) {
		atomic_or(APP_NEEDS_LOCK, &rpc->flags);
		homa_rpc_lock(rpc);
		atomic_andnot(APP_NEEDS_LOCK, &rpc->flags);
		locked = 1;
	}
	atomic_andnot(RPC_HANDING_OFF, &rpc->flags);
	homa_interest_set_rpc(interest, rpc, locked);
	return 0;
}

/**
 * homa_wait_for_message() - Wait for receipt of an incoming message
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
				       u64 id)
	__acquires(&rpc->bucket_lock)
{
	u64 poll_start, poll_end, now;
	int error, blocked = 0, polled = 0;
	struct homa_rpc *result = NULL;
	struct homa_interest interest;
	struct homa_rpc *rpc = NULL;

	/* Each iteration of this loop finds an RPC, but it might not be
	 * in a state where we can return it (e.g., there might be packets
	 * ready to transfer to user space, but the incoming message isn't yet
	 * complete). Thus it could take many iterations of this loop
	 * before we have an RPC with a complete message.
	 */
	while (1) {
		error = homa_register_interests(&interest, hsk, flags, id);
		rpc = homa_interest_get_rpc(&interest);
		if (rpc)
			goto found_rpc;
		if (error < 0) {
			result = ERR_PTR(error);
			goto found_rpc;
		}

		/* There is no ready RPC so far. Clean up dead RPCs before
		 * going to sleep (or returning, if in nonblocking mode).
		 */
		while (1) {
			int reaper_result;

			rpc = homa_interest_get_rpc(&interest);
			if (rpc) {
				tt_record1("received RPC handoff while reaping, id %d",
					   rpc->id);
				goto found_rpc;
			}
			reaper_result = homa_rpc_reap(hsk, false);
			if (reaper_result == 0)
				break;

			/* Give NAPI and SoftIRQ tasks a chance to run. */
			schedule();
		}
		if (flags & HOMA_RECVMSG_NONBLOCKING) {
			result = ERR_PTR(-EAGAIN);
			goto found_rpc;
		}

		// tt_record4("Preparing to poll, socket %d, flags 0x%x, pid %d, poll_usecs %d",
		// 	   hsk->port, flags, current->pid,
		// 	   hsk->homa->poll_usecs);

		/* Busy-wait for a while before going to sleep; this avoids
		 * context-switching overhead to wake up.
		 */
		now = sched_clock();
		poll_start = now;
		poll_end = now + (1000 * hsk->homa->poll_usecs);
		while (1) {
			u64 blocked;

			rpc = homa_interest_get_rpc(&interest);
			if (rpc) {
				tt_record3("received RPC handoff while polling, id %d, socket %d, pid %d",
					   rpc->id, hsk->port,
					   current->pid);
				polled = 1;
				INC_METRIC(poll_ns, now - poll_start);
				goto found_rpc;
			}
			if (now >= poll_end) {
				INC_METRIC(poll_ns, now - poll_start);
				break;
			}
			blocked = sched_clock();
			schedule();
			now = sched_clock();
			blocked = now - blocked;
			INC_METRIC(blocked_ns, blocked);
			poll_start += blocked;
		}
		tt_record2("Poll ended unsuccessfully on socket %d, pid %d",
			   hsk->port, current->pid);
		INC_METRIC(poll_ns, now - poll_start);

		/* Now it's time to sleep. */
		per_cpu(homa_offload_core, interest.core).last_app_active = now;
		set_current_state(TASK_INTERRUPTIBLE);
		rpc = homa_interest_get_rpc(&interest);
		if (!rpc && !hsk->shutdown) {
			u64 end;
			u64 start = sched_clock();

			tt_record1("homa_wait_for_message sleeping, pid %d",
				   current->pid);
			schedule();
			end = sched_clock();
			blocked = 1;
			INC_METRIC(blocked_ns, end - start);
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
		if (interest.reg_rpc ||
		    !list_empty(&interest.request_links) ||
		    !list_empty(&interest.response_links)) {
			homa_sock_lock(hsk);
			if (interest.reg_rpc)
				interest.reg_rpc->interest = NULL;
			if (!list_empty(&interest.request_links))
				list_del_init(&interest.request_links);
			if (!list_empty(&interest.response_links))
				list_del_init(&interest.response_links);
			homa_sock_unlock(hsk);
		}

		/* Now check to see if we received an RPC handoff (note that
		 * this could have happened anytime up until we reset the
		 * interests above).
		 */
		rpc = homa_interest_get_rpc(&interest);
		if (rpc) {
			tt_record2("homa_wait_for_message found rpc id %d, pid %d",
				   rpc->id, current->pid);
			if (!interest.locked) {
				atomic_or(APP_NEEDS_LOCK, &rpc->flags);
				homa_rpc_lock(rpc);
				atomic_andnot(APP_NEEDS_LOCK | RPC_HANDING_OFF,
					      &rpc->flags);
			} else {
				atomic_andnot(RPC_HANDING_OFF, &rpc->flags);
			}
			if (!rpc->error)
				rpc->error = homa_copy_to_user(rpc);
			if (rpc->state == RPC_DEAD) {
				homa_rpc_unlock(rpc);
				continue;
			}
			if (rpc->error)
				goto done;
			atomic_andnot(RPC_PKTS_READY, &rpc->flags);
			if (rpc->msgin.bytes_remaining == 0 &&
			    !skb_queue_len(&rpc->msgin.packets))
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
 * homa_choose_interest() - Given a list of interests for an incoming
 * message, choose the best one to handle it (if any).
 * @homa:        Overall information about the Homa transport.
 * @head:        Head pointers for the list of interest: either
 *		 hsk->request_interests or hsk->response_interests.
 * @offset:      Offset of "next" pointers in the list elements (either
 *               offsetof(request_links) or offsetof(response_links).
 * Return:       An interest to use for the incoming message, or NULL if none
 *               is available. If possible, this function tries to pick an
 *               interest whose thread is running on a core that isn't
 *               currently busy doing Homa transport work.
 */
struct homa_interest *homa_choose_interest(struct homa *homa,
					   struct list_head *head, int offset)
{
	u64 busy_time = sched_clock() - homa->busy_ns;
	struct homa_interest *backup = NULL;
	struct homa_interest *interest;
	struct list_head *pos;

	list_for_each(pos, head) {
		interest = (struct homa_interest *)(((char *)pos) - offset);
		if (per_cpu(homa_offload_core, interest->core).last_active <
				busy_time) {
			if (backup)
				INC_METRIC(handoffs_alt_thread, 1);
			return interest;
		}
		if (!backup)
			backup = interest;
	}

	/* All interested threads are on busy cores; return the first. */
	return backup;
}

/**
 * homa_rpc_handoff() - This function is called when the input message for
 * an RPC is ready for attention from a user thread. It either notifies
 * a waiting reader or queues the RPC.
 * @rpc:                RPC to handoff; must be locked. The caller must
 *			also have locked the socket for this RPC.
 */
void homa_rpc_handoff(struct homa_rpc *rpc)
{
	struct homa_sock *hsk = rpc->hsk;
	struct homa_interest *interest;

	if ((atomic_read(&rpc->flags) & RPC_HANDING_OFF) ||
	    !list_empty(&rpc->ready_links))
		return;

	/* First, see if someone is interested in this RPC specifically.
	 */
	if (rpc->interest) {
		interest = rpc->interest;
		goto thread_waiting;
	}

	/* Second, check the interest list for this type of RPC. */
	if (homa_is_client(rpc->id)) {
		interest = homa_choose_interest(hsk->homa,
						&hsk->response_interests,
						offsetof(struct homa_interest,
							 response_links));
		if (interest)
			goto thread_waiting;
		list_add_tail(&rpc->ready_links, &hsk->ready_responses);
		INC_METRIC(responses_queued, 1);
	} else {
		interest = homa_choose_interest(hsk->homa,
						&hsk->request_interests,
						offsetof(struct homa_interest,
							 request_links));
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
	INC_METRIC(handoffs_thread_waiting, 1);
	tt_record3("homa_rpc_handoff handing off id %d to pid %d on core %d",
		   rpc->id, interest->thread->pid, task_cpu(interest->thread));
	homa_interest_set_rpc(interest, rpc, 0);

	/* Update the last_app_active time for the thread's core, so Homa
	 * will try to avoid doing any work there.
	 */
	per_cpu(homa_offload_core, interest->core).last_app_active =
			sched_clock();

	/* Clear the interest. This serves two purposes. First, it saves
	 * the waking thread from acquiring the socket lock again, which
	 * reduces contention on that lock). Second, it ensures that
	 * no-one else attempts to give this interest a different RPC.
	 */
	if (interest->reg_rpc) {
		interest->reg_rpc->interest = NULL;
		interest->reg_rpc = NULL;
	}
	if (!list_empty(&interest->request_links))
		list_del_init(&interest->request_links);
	if (!list_empty(&interest->response_links))
		list_del_init(&interest->response_links);
	wake_up_process(interest->thread);
}

/**
 * homa_incoming_sysctl_changed() - Invoked whenever a sysctl value is changed;
 * any input-related parameters that depend on sysctl-settable values.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_incoming_sysctl_changed(struct homa *homa)
{
	u64 tmp;

	if (homa->grant_fifo_fraction > 500)
		homa->grant_fifo_fraction = 500;
	tmp = homa->grant_fifo_fraction;
	if (tmp != 0)
		tmp = (1000 * homa->fifo_grant_increment) / tmp -
				homa->fifo_grant_increment;
	homa->grant_nonfifo = tmp;

	if (homa->max_overcommit > HOMA_MAX_GRANTS)
		homa->max_overcommit = HOMA_MAX_GRANTS;

	homa->busy_ns = homa->busy_usecs * 1000;
	homa->gro_busy_ns = homa->gro_busy_usecs * 1000;
}
