// SPDX-License-Identifier: BSD-2-Clause

#ifndef __STRIP__ /* See strip.py */
/* This file contains functions that handle incoming Homa messages, including
 * both receiving information for those messages and sending grants.
 */
#else /* See strip.py */
/* This file contains functions that handle incoming Homa messages. */
#endif /* See strip.py */

#include "homa_impl.h"
#include "homa_interest.h"
#include "homa_peer.h"
#include "homa_pool.h"

#ifndef __STRIP__ /* See strip.py */
#include "homa_grant.h"
#include "homa_offload.h"
#endif /* See strip.py */

#ifndef __STRIP__ /* See strip.py */
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
#else /* See strip.py */
/**
 * homa_message_in_init() - Constructor for homa_message_in.
 * @rpc:          RPC whose msgin structure should be initialized. The
 *                msgin struct is assumed to be zeroes.
 * @length:       Total number of bytes in message.
 * Return:        Zero for successful initialization, or a negative errno
 *                if rpc->msgin could not be initialized.
 */
int homa_message_in_init(struct homa_rpc *rpc, int length)
#endif /* See strip.py */
{
	int err;

	if (length > HOMA_MAX_MESSAGE_LENGTH)
		return -EINVAL;

	rpc->msgin.length = length;
	skb_queue_head_init(&rpc->msgin.packets);
	INIT_LIST_HEAD(&rpc->msgin.gaps);
	rpc->msgin.bytes_remaining = length;
#ifndef __STRIP__ /* See strip.py */
	rpc->msgin.granted = (unsched > length) ? length : unsched;
	atomic_set(&rpc->msgin.rank, 0);
#endif /* See strip.py */
	err = homa_pool_allocate(rpc);
	if (err != 0)
		return err;
#ifndef __STRIP__ /* See strip.py */
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
#endif /* See strip.py */
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
#ifndef __STRIP__ /* See strip.py */
		resend.priority = rpc->hsk->homa->num_priorities - 1;
#endif /* See strip.py */
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
#ifndef __STRIP__ /* See strip.py */
	if (h->retransmit)
		INC_METRIC(resent_discards, 1);
	else
		INC_METRIC(packet_discards, 1);
#endif /* See strip.py */
	tt_record4("homa_add_packet discarding packet for id %d, offset %d, length %d, retransmit %d",
		   rpc->id, start, length, h->retransmit);
	kfree_skb(skb);
	return;

keep:
#ifndef __STRIP__ /* See strip.py */
	if (h->retransmit)
		INC_METRIC(resent_packets_used, 1);
#endif /* See strip.py */
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
 *           will be RPC_DEAD. Clears the RPC_PKTS_READY bit in @rpc->flags
 *           if all available packets have been copied out.
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
#ifndef __UPSTREAM__ /* See strip.py */
	int start_offset = 0;
	int end_offset = 0;
#endif /* See strip.py */
	int error = 0;
#ifndef __STRIP__ /* See strip.py */
	u64 start;
#endif /* See strip.py */
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
		if (n == 0) {
			atomic_andnot(RPC_PKTS_READY, &rpc->flags);
			break;
		}

		/* At this point we've collected a batch of packets (or
		 * run out of packets); copy any available packets out to
		 * user space.
		 */
		homa_rpc_hold(rpc);
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
#ifndef __UPSTREAM__ /* See strip.py */
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
#ifndef __UPSTREAM__ /* See strip.py */
		if (end_offset != 0) {
			tt_record3("copied out bytes %d-%d for id %d",
				   start_offset, end_offset, rpc->id);
			end_offset = 0;
		}
#endif /* See strip.py */
#ifndef __STRIP__ /* See strip.py */
		start = sched_clock();
#endif /* See strip.py */
		for (i = 0; i < n; i++)
			kfree_skb(skbs[i]);
		INC_METRIC(skb_free_ns, sched_clock() - start);
		INC_METRIC(skb_frees, n);
		tt_record2("finished freeing %d skbs for id %d",
			   n, rpc->id);
		n = 0;
		atomic_or(APP_NEEDS_LOCK, &rpc->flags);
		homa_rpc_lock(rpc);
		atomic_andnot(APP_NEEDS_LOCK, &rpc->flags);
		homa_rpc_put(rpc);
		if (error)
			break;
	}
#ifndef __STRIP__ /* See strip.py */
	if (error)
		tt_record2("homa_copy_to_user returning error %d for id %d",
			   -error, rpc->id);
#endif /* See strip.py */
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
	if (!hsk || (!homa_is_client(id) && !hsk->is_server)) {
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
		if (hsk)
			sock_put(&hsk->sock);
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

				/* This short spin is needed to ensure that the
				 * other thread gets the lock before this thread
				 * grabs it again below (the need for this
				 * was confirmed experimentally in 2/2025;
				 * without it, the handoff fails 20-25% of the
				 * time). Furthermore, the call to homa_spin
				 * seems to allow the other thread to acquire
				 * the lock more quickly.
				 */
				homa_spin(100);
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
#ifndef __STRIP__ /* See strip.py */
			if (h->common.type != CUTOFFS &&
			    h->common.type != NEED_ACK &&
#else /* See strip.py */
			if (h->common.type != NEED_ACK &&
#endif /* See strip.py */
			    h->common.type != ACK &&
			    h->common.type != RESEND) {
				tt_record4("Discarding packet for unknown RPC, id %u, type %d, peer 0x%x:%d",
					   id, h->common.type, tt_addr(saddr),
					   ntohs(h->common.sport));
#ifndef __STRIP__ /* See strip.py */
				if (h->common.type != GRANT ||
				    homa_is_client(id))
					INC_METRIC(unknown_rpcs, 1);
#endif /* See strip.py */
				goto discard;
			}
		} else {
			tt_record1("homa_dispatch_pkts has rpc lock for id %d",
				   rpc->id);
			if (h->common.type == DATA ||
#ifndef __STRIP__ /* See strip.py */
			    h->common.type == GRANT ||
#endif /* See strip.py */
			    h->common.type == BUSY ||
			    h->common.type == NEED_ACK)
				rpc->silent_ticks = 0;
			rpc->peer->outstanding_resends = 0;
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
#ifndef __STRIP__ /* See strip.py */
		case GRANT:
			INC_METRIC(packets_received[GRANT - DATA], 1);
			homa_grant_pkt(skb, rpc);
			break;
#endif /* See strip.py */
		case RESEND:
			INC_METRIC(packets_received[RESEND - DATA], 1);
			homa_resend_pkt(skb, rpc, hsk);
			break;
		case RPC_UNKNOWN:
			INC_METRIC(packets_received[RPC_UNKNOWN - DATA], 1);
			homa_rpc_unknown_pkt(skb, rpc);
			break;
		case BUSY:
			INC_METRIC(packets_received[BUSY - DATA], 1);
			tt_record2("received BUSY for id %d, peer 0x%x",
				   id, tt_addr(rpc->peer->addr));
			/* Nothing to do for these packets except reset
			 * silent_ticks, which happened above.
			 */
			goto discard;
#ifndef __STRIP__ /* See strip.py */
		case CUTOFFS:
			INC_METRIC(packets_received[CUTOFFS - DATA], 1);
			homa_cutoffs_pkt(skb, hsk);
			break;
#endif /* See strip.py */
		case NEED_ACK:
			INC_METRIC(packets_received[NEED_ACK - DATA], 1);
			homa_need_ack_pkt(skb, hsk, rpc);
			break;
		case ACK:
			INC_METRIC(packets_received[ACK - DATA], 1);
			homa_ack_pkt(skb, hsk, rpc);
			break;
		default:
			INC_METRIC(unknown_packet_types, 1);
			goto discard;
		}
		continue;

discard:
		kfree_skb(skb);
	}
	if (rpc) {
#ifndef __STRIP__ /* See strip.py */
		homa_rpc_hold(rpc);
		homa_rpc_unlock(rpc);
		homa_grant_check_rpc(rpc);
		homa_rpc_put(rpc);
#else /* See strip.py */
		homa_rpc_unlock(rpc);
#endif /* See strip.py */
	}

	while (num_acks > 0) {
		num_acks--;
		homa_rpc_acked(hsk, &saddr, &acks[num_acks]);
	}

	if (hsk->dead_skbs >= 2 * hsk->homa->dead_buffs_limit) {
		/* We get here if neither homa_wait_for_message
		 * nor homa_timer can keep up with reaping dead
		 * RPCs. See reap.txt for details.
		 */
#ifndef __STRIP__ /* See strip.py */
		u64 start = sched_clock();
#endif /* See strip.py */

		tt_record("homa_data_pkt calling homa_rpc_reap");
		homa_rpc_reap(hsk, false);
		INC_METRIC(data_pkt_reap_ns, sched_clock() - start);
	}
	sock_put(&hsk->sock);
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
#ifndef __STRIP__ /* See strip.py */
	struct homa *homa = rpc->hsk->homa;
#endif /* See strip.py */

	tt_record4("incoming data packet, id %d, peer 0x%x, offset %d/%d",
		   homa_local_id(h->common.sender_id),
		   tt_addr(rpc->peer->addr), ntohl(h->seg.offset),
		   ntohl(h->message_length));

	if (rpc->state != RPC_INCOMING && homa_is_client(rpc->id)) {
		if (unlikely(rpc->state != RPC_OUTGOING))
			goto discard;
		INC_METRIC(responses_received, 1);
		rpc->state = RPC_INCOMING;
#ifndef __STRIP__ /* See strip.py */
		tt_record2("Incoming message for id %d has %d unscheduled bytes",
			   rpc->id, ntohl(h->incoming));
#endif /* See strip.py */
#ifndef __STRIP__ /* See strip.py */
		if (homa_message_in_init(rpc, ntohl(h->message_length),
					 ntohl(h->incoming)) != 0)
#else /* See strip.py */
		if (homa_message_in_init(rpc, ntohl(h->message_length)) != 0)
#endif /* See strip.py */
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
#ifndef __STRIP__ /* See strip.py */
		tt_record4("Dropping packet because no buffer space available: id %d, offset %d, length %d, old incoming %d",
			   rpc->id, ntohl(h->seg.offset), homa_data_len(skb),
			   rpc->msgin.granted);
#else /* See strip.py */
		tt_record3("Dropping packet because no buffer space available: id %d, offset %d, length %d",
			   rpc->id, ntohl(h->seg.offset), homa_data_len(skb));
#endif /* See strip.py */
		INC_METRIC(dropped_data_no_bufs, homa_data_len(skb));
		goto discard;
	}

	homa_add_packet(rpc, skb);

	if (skb_queue_len(&rpc->msgin.packets) != 0 &&
	    !(atomic_read(&rpc->flags) & RPC_PKTS_READY)) {
		atomic_or(RPC_PKTS_READY, &rpc->flags);
		homa_rpc_handoff(rpc);
	}

#ifndef __STRIP__ /* See strip.py */
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
#endif /* See strip.py */
	return;

discard:
	kfree_skb(skb);
	UNIT_LOG("; ", "homa_data_pkt discarded packet");
}

#ifndef __STRIP__ /* See strip.py */
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
#endif /* See strip.py */

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
	struct homa_busy_hdr busy;

	if (!rpc) {
		tt_record4("resend request for unknown id %d, peer 0x%x:%d, offset %d; responding with RPC_UNKNOWN",
			   homa_local_id(h->common.sender_id),
			   tt_addr(skb_canonical_ipv6_saddr(skb)),
			   ntohs(h->common.sport), ntohl(h->offset));
		homa_xmit_unknown(skb, hsk);
		goto done;
	}
#ifndef __STRIP__ /* See strip.py */
	tt_record4("resend request for id %llu, offset %d, length %d, prio %d",
		   rpc->id, ntohl(h->offset), ntohl(h->length), h->priority);
#else /* See strip.py */
	tt_record3("resend request for id %llu, offset %d, length %d",
		   rpc->id, ntohl(h->offset), ntohl(h->length));
#endif /* See strip.py */

	if (!homa_is_client(rpc->id) && rpc->state != RPC_OUTGOING) {
		/* We are the server for this RPC and don't yet have a
		 * response packet, so just send BUSY.
		 */
		tt_record2("sending BUSY from resend, id %d, state %d",
			   rpc->id, rpc->state);
		homa_xmit_control(BUSY, &busy, sizeof(busy), rpc);
		goto done;
	}
#ifndef __STRIP__ /* See strip.py */
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
#else /* See strip.py */
	if (ntohl(h->length) == 0)
		/* This RESEND is from a server just trying to determine
		 * whether the client still cares about the RPC; return
		 * BUSY so the server doesn't time us out.
		 */
		homa_xmit_control(BUSY, &busy, sizeof(busy), rpc);
	homa_resend_data(rpc, ntohl(h->offset),
			 ntohl(h->offset) + ntohl(h->length));
#endif /* See strip.py */

done:
	kfree_skb(skb);
}

/**
 * homa_rpc_unknown_pkt() - Handler for incoming RPC_UNKNOWN packets.
 * @skb:     Incoming packet; size known to be large enough for the header.
 *           This function now owns the packet.
 * @rpc:     Information about the RPC corresponding to this packet.
 */
void homa_rpc_unknown_pkt(struct sk_buff *skb, struct homa_rpc *rpc)
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
#ifndef __STRIP__ /* See strip.py */
			homa_freeze(rpc, RESTART_RPC,
				    "Freezing because of RPC restart, id %d, peer 0x%x");
			homa_resend_data(rpc, 0, rpc->msgout.next_xmit_offset,
					 homa_unsched_priority(rpc->hsk->homa,
							       rpc->peer,
							       rpc->msgout.length));
#else /* See strip.py */
			homa_resend_data(rpc, 0, rpc->msgout.next_xmit_offset);
#endif /* See strip.py */
			goto done;
		}
#ifndef __STRIP__ /* See strip.py */
		pr_err("Received unknown for RPC id %llu, peer %s:%d in bogus state %d; discarding unknown\n",
		       rpc->id, homa_print_ipv6_addr(&rpc->peer->addr),
		       rpc->dport, rpc->state);
#endif /* See strip.py */
		tt_record4("Discarding unknown for RPC id %d, peer 0x%x:%d: bad state %d",
			   rpc->id, tt_addr(rpc->peer->addr), rpc->dport,
			   rpc->state);
#ifndef __STRIP__ /* See strip.py */
	} else {
		if (rpc->hsk->homa->verbose)
			pr_notice("Ending rpc id %llu from client %s:%d: unknown to client",
				  rpc->id,
				  homa_print_ipv6_addr(&rpc->peer->addr),
				  rpc->dport);
		homa_rpc_end(rpc);
		INC_METRIC(server_rpcs_unknown, 1);
#else /* See strip.py */
	} else {
		homa_rpc_end(rpc);
#endif /* See strip.py */
	}
done:
	kfree_skb(skb);
}

#ifndef __STRIP__ /* See strip.py */
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
#endif /* See strip.py */

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
#ifndef __STRIP__ /* See strip.py */
		    rpc->msgin.bytes_remaining)) {
		tt_record3("NEED_ACK arrived for id %d before message received, state %d, remaining %d",
			   rpc->id, rpc->state, rpc->msgin.bytes_remaining);
		homa_freeze(rpc, NEED_ACK_MISSING_DATA,
			    "Freezing because NEED_ACK received before message complete, id %d, peer 0x%x");
#else /* See strip.py */
		    rpc->msgin.bytes_remaining)) {
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
#ifndef __STRIP__ /* See strip.py */
	ack.common.flags = HOMA_TCP_FLAGS;
	ack.common.urgent = htons(HOMA_TCP_URGENT);
#endif /* See strip.py */
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
 *           RPC exists. The RPC lock will be dead on return.
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
	}

	count = ntohs(h->num_acks);
	if (count > 0) {
		if (rpc) {
			/* Must temporarily release rpc's lock because
			 * homa_rpc_acked needs to acquire RPC locks.
			 */
			homa_rpc_hold(rpc);
			homa_rpc_unlock(rpc);
		}
		for (i = 0; i < count; i++)
			homa_rpc_acked(hsk, &saddr, &h->acks[i]);
		if (rpc) {
			homa_rpc_lock(rpc);
			homa_rpc_put(rpc);
		}
	}
	tt_record3("ACK received for id %d, peer 0x%x, with %d other acks",
		   homa_local_id(h->common.sender_id), tt_addr(saddr), count);
	kfree_skb(skb);
}

#ifndef __STRIP__ /* See strip.py */
#if 0
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
#endif
#endif /* See strip.py */

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
	homa_rpc_handoff(rpc);
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
	struct homa_rpc *rpc;
	struct homa_sock *hsk;

	for (hsk = homa_socktab_start_scan(homa->port_map, &scan); hsk;
	     hsk = homa_socktab_next(&scan)) {
		/* Skip the (expensive) lock acquisition if there's no
		 * work to do.
		 */
		if (list_empty(&hsk->active_rpcs))
			continue;
		if (!homa_protect_rpcs(hsk))
			continue;
		rcu_read_lock();
		list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
			if (!ipv6_addr_equal(&rpc->peer->addr, addr))
				continue;
			if (port && rpc->dport != port)
				continue;
			homa_rpc_lock(rpc);
			homa_rpc_abort(rpc, error);
			homa_rpc_unlock(rpc);
		}
		rcu_read_unlock();
		homa_unprotect_rpcs(hsk);
	}
	homa_socktab_end_scan(&scan);
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
	struct homa_rpc *rpc;

	if (list_empty(&hsk->active_rpcs))
		return;
	if (!homa_protect_rpcs(hsk))
		return;
	rcu_read_lock();
	list_for_each_entry_rcu(rpc, &hsk->active_rpcs, active_links) {
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
	rcu_read_unlock();
	homa_unprotect_rpcs(hsk);
}

/**
 * homa_wait_private() - Waits until the response has been received for
 * a specific RPC or the RPC has failed with an error.
 * @rpc:          RPC to wait for; an error will be returned if the RPC is
 *                not a client RPC or not private. Must be locked by caller.
 * @nonblocking:  Nonzero means return immediately if @rpc not ready.
 * Return:  0 if the response has been successfully received, otherwise
 *          a negative errno.
 */
int homa_wait_private(struct homa_rpc *rpc, int nonblocking)
	__must_hold(&rpc->bucket->lock)
{
	struct homa_interest interest;
#ifndef __STRIP__ /* See strip.py */
	int avail_immediately = 1;
	int blocked = 0;
#endif /* See strip.py */
	int result = 0;

	if (!(atomic_read(&rpc->flags) & RPC_PRIVATE))
		return -EINVAL;

	homa_rpc_hold(rpc);

	/* Each iteration through this loop waits until rpc needs attention
	 * in some way (e.g. packets have arrived), then deals with that need
	 * (e.g. copy to user space). It may take many iterations until the
	 * RPC is ready for the application.
	 */
	while (1) {
		if (!rpc->error)
			rpc->error = homa_copy_to_user(rpc);
		if (rpc->error) {
			result = rpc->error;
			break;
		}
		if (rpc->msgin.length >= 0 &&
		    rpc->msgin.bytes_remaining == 0 &&
		    skb_queue_len(&rpc->msgin.packets) == 0) {
			tt_record2("homa_wait_private found rpc id %d, pid %d via null, blocked 0",
					rpc->id, current->pid);
			break;
		}

		result = homa_interest_init_private(&interest, rpc);
		if (result != 0)
			break;

		homa_rpc_unlock(rpc);
		result = homa_interest_wait(&interest, nonblocking);
#ifndef __STRIP__ /* See strip.py */
		avail_immediately = 0;
		blocked |= interest.blocked;
#endif /* See strip.py */

		atomic_or(APP_NEEDS_LOCK, &rpc->flags);
		homa_rpc_lock(rpc);
		atomic_andnot(APP_NEEDS_LOCK, &rpc->flags);
		homa_interest_unlink_private(&interest);
		tt_record3("homa_wait_private found rpc id %d, pid %d via handoff, blocked %d",
				rpc->id, current->pid, interest.blocked);

		/* If homa_interest_wait returned an error but the interest
		 * actually got ready, then ignore the error.
		 */
		if (result != 0 && atomic_read(&interest.ready) == 0)
			break;
	}

#ifndef __STRIP__ /* See strip.py */
	if (avail_immediately)
		INC_METRIC(wait_none, 1);
	else if (blocked)
		INC_METRIC(wait_block, 1);
	else
		INC_METRIC(wait_fast, 1);
#endif /* See strip.py */
	homa_rpc_put(rpc);
	return result;
}

/**
 * homa_wait_shared() - Wait for the completion of any non-private
 * incoming message on a socket.
 * @hsk:          Socket on which to wait. Must not be locked.
 * @nonblocking:  Nonzero means return immediately if no RPC is ready.
 *
 * Return:    Pointer to an RPC with a complete incoming message or nonzero
 *            error field, or a negative errno (usually -EINTR). If an RPC
 *            is returned it will be locked and the caller must unlock.
 */
struct homa_rpc *homa_wait_shared(struct homa_sock *hsk, int nonblocking)
{
	struct homa_interest interest;
	struct homa_rpc *rpc;
#ifndef __STRIP__ /* See strip.py */
	int avail_immediately = 1;
	int blocked = 0;
#endif /* See strip.py */
	int result;

	/* Each iteration through this loop waits until an RPC needs attention
	 * in some way (e.g. packets have arrived), then deals with that need
	 * (e.g. copy to user space). It may take many iterations until an
	 * RPC is ready for the application.
	 */
	while (1) {
		homa_sock_lock(hsk);
		if (hsk->shutdown) {
			rpc = ERR_PTR(-ESHUTDOWN);
			homa_sock_unlock(hsk);
			goto done;
		}
		if (!list_empty(&hsk->ready_rpcs)) {
			rpc = list_first_entry(&hsk->ready_rpcs,
					       struct homa_rpc,
					       ready_links);
			tt_record2("homa_wait_shared found rpc id %d, pid %d via ready_rpcs, blocked 0",
				   rpc->id, current->pid);
			homa_rpc_hold(rpc);
			list_del_init(&rpc->ready_links);
			if (!list_empty(&hsk->ready_rpcs)) {
				/* There are still more RPCs available, so
				 * let Linux know.
				 */
				hsk->sock.sk_data_ready(&hsk->sock);
			}
			homa_sock_unlock(hsk);
		} else {
			homa_interest_init_shared(&interest, hsk);
			homa_sock_unlock(hsk);
			result = homa_interest_wait(&interest, nonblocking);
#ifndef __STRIP__ /* See strip.py */
			avail_immediately = 0;
			blocked |= interest.blocked;
#endif /* See strip.py */
			homa_interest_unlink_shared(&interest);

			if (result != 0) {
				/* If homa_interest_wait returned an error
				 * (e.g. -EAGAIN) but in the meantime the
				 * interest received a handoff, ignore the
				 * error.
				 */
				if (atomic_read(&interest.ready) == 0) {
					rpc = ERR_PTR(result);
					goto done;
				}
			}

			rpc = interest.rpc;
			if (!rpc) {
				rpc = ERR_PTR(-ESHUTDOWN);
				goto done;
			}
			tt_record3("homa_wait_shared found rpc id %d, pid %d via handoff, blocked %d",
				   rpc->id, current->pid, interest.blocked);
		}

		atomic_or(APP_NEEDS_LOCK, &rpc->flags);
		homa_rpc_lock(rpc);
		atomic_andnot(APP_NEEDS_LOCK, &rpc->flags);
		homa_rpc_put(rpc);
		if (!rpc->error)
			rpc->error = homa_copy_to_user(rpc);
		if (rpc->error) {
			if (rpc->state != RPC_DEAD)
				break;
		} else if (rpc->msgin.bytes_remaining == 0 &&
		    skb_queue_len(&rpc->msgin.packets) == 0)
			break;
		homa_rpc_unlock(rpc);
	}

done:
#ifndef __STRIP__ /* See strip.py */
	if (avail_immediately)
		INC_METRIC(wait_none, 1);
	else if (blocked)
		INC_METRIC(wait_block, 1);
	else
		INC_METRIC(wait_fast, 1);
#endif /* See strip.py */
	return rpc;
}

/**
 * homa_rpc_handoff() - This function is called when the input message for
 * an RPC is ready for attention from a user thread. It notifies a waiting
 * reader and/or queues the RPC, as appropriate.
 * @rpc:                RPC to handoff; must be locked.
 */
void homa_rpc_handoff(struct homa_rpc *rpc)
{
	struct homa_sock *hsk = rpc->hsk;
	struct homa_interest *interest;

	if (atomic_read(&rpc->flags) & RPC_PRIVATE) {
		homa_interest_notify_private(rpc);
		return;
	}

	/* Shared RPC; if there is a waiting thread, hand off the RPC;
	 * otherwise enqueue it.
	 */
	homa_sock_lock(hsk);
	if (!list_empty(&hsk->interests)) {
#ifndef __STRIP__ /* See strip.py */
		interest = homa_choose_interest(hsk);
#else /* See strip.py */
		interest = list_first_entry(&hsk->interests,
					    struct homa_interest, links);
#endif /* See strip.py */
		list_del_init(&interest->links);
		interest->rpc = rpc;
		homa_rpc_hold(rpc);
		tt_record1("homa_rpc_handoff handing off id %d", rpc->id);
		atomic_set_release(&interest->ready, 1);
		wake_up(&interest->wait_queue);
		INC_METRIC(handoffs_thread_waiting, 1);

#ifndef __STRIP__ /* See strip.py */
		/* Update the last_app_active time for the thread's core, so
		 * Homa will try to avoid assigning any work there.
		 */
		per_cpu(homa_offload_core, interest->core).last_app_active =
				sched_clock();
#endif /* See strip.py */
	} else if (list_empty(&rpc->ready_links)) {
		list_add_tail(&rpc->ready_links, &hsk->ready_rpcs);
		hsk->sock.sk_data_ready(&hsk->sock);
		tt_record2("homa_rpc_handoff queued id %d for port %d",
			   rpc->id, hsk->port);
	}
	homa_sock_unlock(hsk);
}

#ifndef __STRIP__ /* See strip.py */
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
#endif /* See strip.py */
