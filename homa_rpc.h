/* SPDX-License-Identifier: BSD-2-Clause */

/* This file defines homa_rpc and related structs.  */

#ifndef _HOMA_RPC_H
#define _HOMA_RPC_H

#include <linux/percpu-defs.h>
#include <linux/skbuff.h>
#include <linux/types.h>

#include "homa_sock.h"
#include "homa_wire.h"

/* Forward references. */
struct homa_ack;

/**
 * struct homa_message_out - Describes a message (either request or response)
 * for which this machine is the sender.
 */
struct homa_message_out {
	/**
	 * @length: Total bytes in message (excluding headers).  A value
	 * less than 0 means this structure is uninitialized and therefore
	 * not in use (all other fields will be zero in this case).
	 */
	int length;

	/** @num_skbs: Total number of buffers currently in @packets. */
	int num_skbs;

	/**
	 * @copied_from_user: Number of bytes of the message that have
	 * been copied from user space into skbs in @packets.
	 */
	int copied_from_user;

	/**
	 * @packets: Singly-linked list of all packets in message, linked
	 * using homa_next_skb. The list is in order of offset in the message
	 * (offset 0 first); each sk_buff can potentially contain multiple
	 * data_segments, which will be split into separate packets by GSO.
	 * This list grows gradually as data is copied in from user space,
	 * so it may not be complete.
	 */
	struct sk_buff *packets;

	/**
	 * @next_xmit: Pointer to pointer to next packet to transmit (will
	 * either refer to @packets or homa_next_skb(skb) for some skb
	 * in @packets).
	 */
	struct sk_buff **next_xmit;

	/**
	 * @next_xmit_offset: All bytes in the message, up to but not
	 * including this one, have been transmitted.
	 */
	int next_xmit_offset;

	/**
	 * @active_xmits: The number of threads that are currently
	 * transmitting data packets for this RPC; can't reap the RPC
	 * until this count becomes zero.
	 */
	atomic_t active_xmits;

	/**
	 * @unscheduled: Initial bytes of message that we'll send
	 * without waiting for grants.
	 */
	int unscheduled;

	/**
	 * @granted: Total number of bytes we are currently permitted to
	 * send, including unscheduled bytes; must wait for grants before
	 * sending bytes at or beyond this position. Never larger than
	 * @length.
	 */
	int granted;

	/**
	 * @sched_priority: Priority level to use for future scheduled
	 * packets.
	 */
	__u8 sched_priority;

	/**
	 * @init_ns: Time in sched_clock units when this structure was
	 * initialized.  Used to find the oldest outgoing message.
	 */
	__u64 init_ns;
};

/**
 * struct homa_gap - Represents a range of bytes within a message that have
 * not yet been received.
 */
struct homa_gap {
	/** @start: offset of first byte in this gap. */
	int start;

	/** @end: offset of byte just after last one in this gap. */
	int end;

	/**
	 * @time: time (in sched_clock units) when the gap was first detected.
	 * As of 7/2024 this isn't used for anything.
	 */
	__u64 time;

	/** @links: for linking into list in homa_message_in. */
	struct list_head links;
};

/**
 * struct homa_message_in - Holds the state of a message received by
 * this machine; used for both requests and responses.
 */
struct homa_message_in {
	/**
	 * @length: Payload size in bytes. A value less than 0 means this
	 * structure is uninitialized and therefore not in use.
	 */
	int length;

	/**
	 * @packets: DATA packets for this message that have been received but
	 * not yet copied to user space (no particular order).
	 */
	struct sk_buff_head packets;

	/**
	 * @recv_end: Offset of the byte just after the highest one that
	 * has been received so far.
	 */
	int recv_end;

	/**
	 * @gaps: List of homa_gaps describing all of the bytes with
	 * offsets less than @recv_end that have not yet been received.
	 */
	struct list_head gaps;

	/**
	 * @bytes_remaining: Amount of data for this message that has
	 * not yet been received; will determine the message's priority.
	 */
	int bytes_remaining;

	/**
	 * @granted: Total # of bytes (starting from offset 0) that the sender
	 * may transmit without additional grants, includes unscheduled bytes.
	 * Never larger than @length. Note: once initialized, this
	 * may not be modified without holding @homa->grantable_lock.
	 */
	int granted;

	/**
	 * @rec_incoming: Number of bytes in homa->total_incoming currently
	 * contributed ("recorded") from this RPC.
	 */
	int rec_incoming;

	/**
	 * @rank: The index of this RPC in homa->active_rpcs and
	 * homa->active_remaining, or -1 if this RPC is not in those arrays.
	 * Set by homa_grant, read-only to the RPC.
	 */
	atomic_t rank;

	/** @priority: Priority level to include in future GRANTS. */
	int priority;

	/** @resend_all: if nonzero, set resend_all in the next grant packet. */
	__u8 resend_all;

	/**
	 * @birth: sched_clock() time when this RPC was added to the grantable
	 * list. Invalid if RPC isn't in the grantable list.
	 */
	__u64 birth;

	/**
	 * @num_bpages: The number of entries in @bpage_offsets used for this
	 * message (0 means buffers not allocated yet).
	 */
	__u32 num_bpages;

	/**
	 * @bpage_offsets: Describes buffer space allocated for this message.
	 * Each entry is an offset from the start of the buffer region.
	 * All but the last pointer refer to areas of size HOMA_BPAGE_SIZE.
	 */
	__u32 bpage_offsets[HOMA_MAX_BPAGES];
};

/**
 * struct homa_rpc - One of these structures exists for each active
 * RPC. The same structure is used to manage both outgoing RPCs on
 * clients and incoming RPCs on servers.
 */
struct homa_rpc {
	/** @hsk:  Socket that owns the RPC. */
	struct homa_sock *hsk;

	/**
	 * @bucket: Pointer to the bucket in hsk->client_rpc_buckets or
	 * hsk->server_rpc_buckets where this RPC is linked. Used primarily
	 * for locking the RPC (which is done by locking its bucket).
	 */
	struct homa_rpc_bucket *bucket;

	/**
	 * @state: The current state of this RPC:
	 *
	 * @RPC_OUTGOING:     The RPC is waiting for @msgout to be transmitted
	 *                    to the peer.
	 * @RPC_INCOMING:     The RPC is waiting for data @msgin to be received
	 *                    from the peer; at least one packet has already
	 *                    been received.
	 * @RPC_IN_SERVICE:   Used only for server RPCs: the request message
	 *                    has been read from the socket, but the response
	 *                    message has not yet been presented to the kernel.
	 * @RPC_DEAD:         RPC has been deleted and is waiting to be
	 *                    reaped. In some cases, information in the RPC
	 *                    structure may be accessed in this state.
	 *
	 * Client RPCs pass through states in the following order:
	 * RPC_OUTGOING, RPC_INCOMING, RPC_DEAD.
	 *
	 * Server RPCs pass through states in the following order:
	 * RPC_INCOMING, RPC_IN_SERVICE, RPC_OUTGOING, RPC_DEAD.
	 */
	enum {
		RPC_OUTGOING            = 5,
		RPC_INCOMING            = 6,
		RPC_IN_SERVICE          = 8,
		RPC_DEAD                = 9
	} state;

	/**
	 * @flags: Additional state information: an OR'ed combination of
	 * various single-bit flags. See below for definitions. Must be
	 * manipulated with atomic operations because some of the manipulations
	 * occur without holding the RPC lock.
	 */
	atomic_t flags;

	/* Valid bits for @flags:
	 * RPC_PKTS_READY -        The RPC has input packets ready to be
	 *                         copied to user space.
	 * RPC_COPYING_FROM_USER - Data is being copied from user space into
	 *                         the RPC; the RPC must not be reaped.
	 * RPC_COPYING_TO_USER -   Data is being copied from this RPC to
	 *                         user space; the RPC must not be reaped.
	 * RPC_HANDING_OFF -       This RPC is in the process of being
	 *                         handed off to a waiting thread; it must
	 *                         not be reaped.
	 * APP_NEEDS_LOCK -        Means that code in the application thread
	 *                         needs the RPC lock (e.g. so it can start
	 *                         copying data to user space) so others
	 *                         (e.g. SoftIRQ processing) should relinquish
	 *                         the lock ASAP. Without this, SoftIRQ can
	 *                         lock out the application for a long time,
	 *                         preventing data copies to user space from
	 *                         starting (and they limit throughput at
	 *                         high network speeds).
	 */
#define RPC_PKTS_READY        1
#define RPC_COPYING_FROM_USER 2
#define RPC_COPYING_TO_USER   4
#define RPC_HANDING_OFF       8
#define APP_NEEDS_LOCK       16

#define RPC_CANT_REAP (RPC_COPYING_FROM_USER | RPC_COPYING_TO_USER \
		| RPC_HANDING_OFF)

	/**
	 * @grants_in_progress: Count of active grant sends for this RPC;
	 * it's not safe to reap the RPC unless this value is zero.
	 * This variable is needed so that grantable_lock can be released
	 * while sending grants, to reduce contention.
	 */
	atomic_t grants_in_progress;

	/**
	 * @peer: Information about the other machine (the server, if
	 * this is a client RPC, or the client, if this is a server RPC).
	 */
	struct homa_peer *peer;

	/** @dport: Port number on @peer that will handle packets. */
	__u16 dport;

	/**
	 * @id: Unique identifier for the RPC among all those issued
	 * from its port. The low-order bit indicates whether we are
	 * server (1) or client (0) for this RPC.
	 */
	__u64 id;

	/**
	 * @completion_cookie: Only used on clients. Contains identifying
	 * information about the RPC provided by the application; returned to
	 * the application with the RPC's result.
	 */
	__u64 completion_cookie;

	/**
	 * @error: Only used on clients. If nonzero, then the RPC has
	 * failed and the value is a negative errno that describes the
	 * problem.
	 */
	int error;

	/**
	 * @msgin: Information about the message we receive for this RPC
	 * (for server RPCs this is the request, for client RPCs this is the
	 * response).
	 */
	struct homa_message_in msgin;

	/**
	 * @msgout: Information about the message we send for this RPC
	 * (for client RPCs this is the request, for server RPCs this is the
	 * response).
	 */
	struct homa_message_out msgout;

	/**
	 * @hash_links: Used to link this object into a hash bucket for
	 * either @hsk->client_rpc_buckets (for a client RPC), or
	 * @hsk->server_rpc_buckets (for a server RPC).
	 */
	struct hlist_node hash_links;

	/**
	 * @ready_links: Used to link this object into
	 * @hsk->ready_requests or @hsk->ready_responses.
	 */
	struct list_head ready_links;

	/**
	 * @buf_links: Used to link this RPC into @hsk->waiting_for_bufs.
	 * If the RPC isn't on @hsk->waiting_for_bufs, this is an empty
	 * list pointing to itself.
	 */
	struct list_head buf_links;

	/**
	 * @active_links: For linking this object into @hsk->active_rpcs.
	 * The next field will be LIST_POISON1 if this RPC hasn't yet been
	 * linked into @hsk->active_rpcs. Access with RCU.
	 */
	struct list_head active_links;

	/** @dead_links: For linking this object into @hsk->dead_rpcs. */
	struct list_head dead_links;

	/**
	 * @interest: Describes a thread that wants to be notified when
	 * msgin is complete, or NULL if none.
	 */
	struct homa_interest *interest;

	/**
	 * @grantable_links: Used to link this RPC into peer->grantable_rpcs.
	 * If this RPC isn't in peer->grantable_rpcs, this is an empty
	 * list pointing to itself.
	 */
	struct list_head grantable_links;

	/**
	 * @throttled_links: Used to link this RPC into homa->throttled_rpcs.
	 * If this RPC isn't in homa->throttled_rpcs, this is an empty
	 * list pointing to itself.
	 */
	struct list_head throttled_links;

	/**
	 * @silent_ticks: Number of times homa_timer has been invoked
	 * since the last time a packet indicating progress was received
	 * for this RPC, so we don't need to send a resend for a while.
	 */
	int silent_ticks;

	/**
	 * @resend_timer_ticks: Value of homa->timer_ticks the last time
	 * we sent a RESEND for this RPC.
	 */
	__u32 resend_timer_ticks;

	/**
	 * @done_timer_ticks: The value of homa->timer_ticks the first
	 * time we noticed that this (server) RPC is done (all response
	 * packets have been transmitted), so we're ready for an ack.
	 * Zero means we haven't reached that point yet.
	 */
	__u32 done_timer_ticks;

	/**
	 * @magic: when the RPC is alive, this holds a distinct value that
	 * is unlikely to occur naturally. The value is cleared when the
	 * RPC is reaped, so we can detect accidental use of an RPC after
	 * it has been reaped.
	 */
#define HOMA_RPC_MAGIC 0xdeadbeef
	int magic;

	/**
	 * @start_ns: time (from sched_clock()) when this RPC was created.
	 * Used (sometimes) for testing.
	 */
	u64 start_ns;
};

void     homa_check_rpc(struct homa_rpc *rpc);
struct homa_rpc
	       *homa_find_client_rpc(struct homa_sock *hsk, __u64 id);
struct homa_rpc
	       *homa_find_server_rpc(struct homa_sock *hsk,
				     const struct in6_addr *saddr, __u64 id);
void     homa_rpc_acked(struct homa_sock *hsk, const struct in6_addr *saddr,
			struct homa_ack *ack);
void     homa_rpc_free(struct homa_rpc *rpc);
void     homa_rpc_log(struct homa_rpc *rpc);
void     homa_rpc_log_active(struct homa *homa, uint64_t id);
void     homa_rpc_log_active_tt(struct homa *homa, int freeze_count);
void     homa_rpc_log_tt(struct homa_rpc *rpc);
struct homa_rpc
	       *homa_rpc_new_client(struct homa_sock *hsk,
				    const union sockaddr_in_union *dest);
struct homa_rpc
	       *homa_rpc_new_server(struct homa_sock *hsk,
				    const struct in6_addr *source,
				    struct homa_data_hdr *h, int *created);
int      homa_rpc_reap(struct homa_sock *hsk, int count);
char    *homa_symbol_for_state(struct homa_rpc *rpc);
int      homa_validate_incoming(struct homa *homa, int verbose,
				int *link_errors);

/**
 * homa_rpc_lock() - Acquire the lock for an RPC.
 * @rpc:    RPC to lock. Note: this function is only safe under
 *          limited conditions (in most cases homa_bucket_lock should be
 *          used). The caller must ensure that the RPC cannot be reaped
 *          before the lock is acquired. It cannot do that by acquirin
 *          the socket lock, since that violates lock ordering constraints.
 *          One approach is to use homa_protect_rpcs. Don't use this function
 *          unless you are very sure what you are doing!  See sync.txt for
 *          more info on locking.
 * @locker: Static string identifying the locking code. Normally ignored,
 *          but used occasionally for diagnostics and debugging.
 */
static inline void homa_rpc_lock(struct homa_rpc *rpc, const char *locker)
{
	homa_bucket_lock(rpc->bucket, rpc->id, locker);
}

/**
 * homa_rpc_try_lock() - Acquire the lock for an RPC if it is available.
 * @rpc:       RPC to lock.
 * @locker:    Static string identifying the locking code. Normally ignored,
 *             but used when debugging deadlocks.
 * Return:     Nonzero if lock was successfully acquired, zero if it is
 *             currently owned by someone else.
 */
static inline int homa_rpc_try_lock(struct homa_rpc *rpc, const char *locker)
{
	if (!spin_trylock_bh(&rpc->bucket->lock))
		return 0;
	return 1;
}

/**
 * homa_rpc_unlock() - Release the lock for an RPC.
 * @rpc:   RPC to unlock.
 */
static inline void homa_rpc_unlock(struct homa_rpc *rpc)
{
	homa_bucket_unlock(rpc->bucket, rpc->id);
}

/**
 * homa_protect_rpcs() - Ensures that no RPCs will be reaped for a given
 * socket until homa_sock_unprotect is called. Typically used by functions
 * that want to scan the active RPCs for a socket without holding the socket
 * lock.  Multiple calls to this function may be in effect at once.
 * @hsk:    Socket whose RPCs should be protected. Must not be locked
 *          by the caller; will be locked here.
 *
 * Return:  1 for success, 0 if the socket has been shutdown, in which
 *          case its RPCs cannot be protected.
 */
static inline int homa_protect_rpcs(struct homa_sock *hsk)
{
	int result;

	homa_sock_lock(hsk, __func__);
	result = !hsk->shutdown;
	if (result)
		atomic_inc(&hsk->protect_count);
	homa_sock_unlock(hsk);
	return result;
}

/**
 * homa_unprotect_rpcs() - Cancel the effect of a previous call to
 * homa_sock_protect(), so that RPCs can once again be reaped.
 * @hsk:    Socket whose RPCs should be unprotected.
 */
static inline void homa_unprotect_rpcs(struct homa_sock *hsk)
{
	atomic_dec(&hsk->protect_count);
}

/**
 * homa_is_client(): returns true if we are the client for a particular RPC,
 * false if we are the server.
 * @id:  Id of the RPC in question.
 * Return: true if we are the client for RPC id, false otherwise
 */
static inline bool homa_is_client(__u64 id)
{
	return (id & 1) == 0;
}

#endif /* _HOMA_RPC_H */
