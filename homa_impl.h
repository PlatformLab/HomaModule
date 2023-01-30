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

/* This file contains definitions that are shared across the files
 * that implement Homa for Linux.
 */

#ifndef _HOMA_IMPL_H
#define _HOMA_IMPL_H

#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic ignored "-Wunused-variable"

#include <linux/bug.h>
#ifdef __UNIT_TEST__
#undef WARN
#define WARN(condition, format...)

#undef WARN_ON
#define WARN_ON(condition) ({						\
	int __ret_warn_on = !!(condition);				\
	unlikely(__ret_warn_on);					\
})

#undef WARN_ON_ONCE
#define WARN_ON_ONCE(condition) WARN_ON(condition)
#endif

#include <linux/audit.h>
#include <linux/icmp.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/proc_fs.h>
#include <linux/sched/signal.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/socket.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/gro.h>
#pragma GCC diagnostic warning "-Wpointer-sign"
#pragma GCC diagnostic warning "-Wunused-variable"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,16,0)
typedef unsigned int __poll_t;
#endif

#ifdef __UNIT_TEST__
#define spin_unlock mock_spin_unlock
extern void mock_spin_unlock(spinlock_t *lock);

#undef get_cycles
#define get_cycles mock_get_cycles
extern cycles_t mock_get_cycles(void);

#define signal_pending(xxx) mock_signal_pending
extern int mock_signal_pending;

#define rcu_read_lock mock_rcu_read_lock
extern void mock_rcu_read_lock(void);

#define rcu_read_unlock mock_rcu_read_unlock
extern void mock_rcu_read_unlock(void);

#undef current
#define current current_task

#define kthread_complete_and_exit(comp, code)

#define kmalloc mock_kmalloc
extern void *mock_kmalloc(size_t size, gfp_t flags);
#endif

#include "homa.h"
#include "timetrace.h"

/* Forward declarations. */
struct homa_sock;
struct homa_rpc;
struct homa;
struct homa_peer;
struct homa_lcache;

/* Declarations used in this file, so they can't be made at the end. */
extern void     homa_grantable_lock_slow(struct homa *homa);
extern void     homa_peer_lock_slow(struct homa_peer *peer);
extern void     homa_rpc_lock_slow(struct homa_rpc *rpc);
extern void     homa_sock_lock_slow(struct homa_sock *hsk);
extern void     homa_throttle_lock_slow(struct homa *homa);

/**
 * enum homa_packet_type - Defines the possible types of Homa packets.
 *
 * See the xxx_header structs below for more information about each type.
 */
enum homa_packet_type {
	DATA               = 0x10,
	GRANT              = 0x11,
	RESEND             = 0x12,
	UNKNOWN            = 0x13,
	BUSY               = 0x14,
	CUTOFFS            = 0x15,
	FREEZE             = 0x16,
	NEED_ACK           = 0x17,
	ACK                = 0x18,
	BOGUS              = 0x19,      /* Used only in unit tests. */
	/* If you add a new type here, you must also do the following:
	 * 1. Change BOGUS so it is the highest opcode
	 * 2. Add support for the new opcode in homa_print_packet,
	 *    homa_print_packet_short, homa_symbol_for_type, and mock_skb_new.
	 * 3. Add the header length to header_lengths in homa_plumbing.c.
	 */
};

/** define HOMA_IPV6_HEADER_LENGTH - Size of IP header (V6). */
#define HOMA_IPV6_HEADER_LENGTH 40

/** define HOMA_IPV4_HEADER_LENGTH - Size of IP header (V4). */
#define HOMA_IPV4_HEADER_LENGTH 20

/**
 * define HOMA_SKB_EXTRA - How many bytes of additional space to allow at the
 * beginning of each sk_buff, before the IP header. This includes room for a
 * VLAN header and also includes some extra space, "just to be safe" (not
 * really sure if this is needed).
 */
#define HOMA_SKB_EXTRA 40

/**
 * define HOMA_ETH_OVERHEAD - Number of bytes per Ethernet packet for CRC,
 * preamble, and inter-packet gap.
 */
#define HOMA_ETH_OVERHEAD 24

/**
 * define HOMA_MIN_PKT_LENGTH - Every Homa packet must be padded to at least
 * this length to meet Ethernet frame size limitations. This number includes
 * Homa headers and data, but not IP or Ethernet headers.
 */
#define HOMA_MIN_PKT_LENGTH 26

/**
 * define HOMA_MAX_HEADER - Number of bytes in the largest Homa header.
 */
#define HOMA_MAX_HEADER 90

/**
 * define ETHERNET_MAX_PAYLOAD - Maximum length of an Ethernet packet,
 * excluding preamble, frame delimeter, VLAN header, CRC, and interpacket gap;
 * i.e. all of this space is available for Homa.
 */
#define ETHERNET_MAX_PAYLOAD 1500

/**
 * define HOMA_MAX_PRIORITIES - The maximum number of priority levels that
 * Homa can use (the actual number can be restricted to less than this at
 * runtime). Changing this value will affect packet formats.
 */
#define HOMA_MAX_PRIORITIES 8

#define sizeof32(type) ((int) (sizeof(type)))

/** define CACHE_LINE_SIZE - The number of bytes in a cache line. */
#define CACHE_LINE_SIZE 64

/**
 * define NUM_PEER_UNACKED_IDS - The number of ids for unacked RPCs that
 * can be stored in a struct homa_peer.
 */
#define NUM_PEER_UNACKED_IDS 5

/**
 * struct homa_cache_line - An object whose size equals that of a cache line.
 */
struct homa_cache_line {
	char bytes[64];
};

/**
 * struct common_header - Wire format for the first bytes in every Homa
 * packet. This must partially match the format of a TCP header so that
 * Homa can piggyback on TCP segmentation offload (and possibly other
 * features, such as RSS).
 */
struct common_header {
	/**
	 * @sport: Port on source machine from which packet was sent.
	 * Must be in the same position as in a TCP header.
	 */
	__be16 sport;

	/**
	 * @dport: Port on destination that is to receive packet. Must be
	 * in the same position as in a TCP header.
	 */
	__be16 dport;

	/**
	 * @unused1: corresponds to the sequence number field in TCP headers;
	 * must not be used by Homa, in case it gets incremented during TCP
	 * offload.
	 */
	__be32 unused1;

	__be32 unused2;

	/**
	 * @doff: High order 4 bits holds the number of 4-byte chunks in a
	 * data_header (low-order bits unused). Used only for DATA packets;
	 * must be in the same position as the data offset in a TCP header.
	 */
	__u8 doff;

	/** @type: One of the values of &enum packet_type. */
	__u8 type;

	__u16 unused3;

	/**
	 * @checksum: not used by Homa, but must occupy the same bytes as
	 * the checksum in a TCP header (TSO may modify this?).*/
	__be16 checksum;

	__u16 unused4;

	/**
	 * @sender_id: the identifier of this RPC as used on the sender (i.e.,
	 * if the low-order bit is set, then the sender is the server for
	 * this RPC).
	 */
	__be64 sender_id;
} __attribute__((packed));

/**
 * struct homa_ack - Identifies an RPC that can be safely deleted by its
 * server. After sending the response for an RPC, the server must retain its
 * state for the RPC until it knows that the client has successfully
 * received the entire response. An ack indicates this. Clients will
 * piggyback acks on future data packets, but if a client doesn't send
 * any data to the server, the server will eventually request an ack
 * explicitly with a NEED_ACK packet, in which case the client will
 * return an explicit ACK.
 */
struct homa_ack {
	/**
	 * @id: The client's identifier for the RPC. 0 means this ack
	 * is invalid.
	 */
	__be64 client_id;

	/** @client_port: The client-side port for the RPC. */
	__be16 client_port;

	/** @server_port: The server-side port for the RPC. */
	__be16 server_port;
} __attribute__((packed));

/**
 * struct data_segment - Wire format for a chunk of data that is part of
 * a DATA packet. A single sk_buff can hold multiple data_segments in order
 * to enable send and receive offload (the idea is to carry many network
 * packets of info in a single traversal of the Linux networking stack).
 * A DATA sk_buff contains a data_header followed by any number of
 * data_segments.
 */
struct data_segment {
	/**
	 * @offset: Offset within message of the first byte of data in
	 * this segment. Segments within an sk_buff are not guaranteed
	 * to be in order.
	 */
	__be32 offset;

	/** @segment_length: Number of bytes of data in this segment. */
	__be32 segment_length;

	/** @ack: If the @client_id field is nonzero, provides info about
	 * an RPC that the recipient can now safely free.
	 */
	struct homa_ack ack;

	/** @data: the payload of this segment. */
	char data[0];
} __attribute__((packed));

/* struct data_header - Overall header format for a DATA sk_buff, which
 * contains this header followed by any number of data_segments.
 */
struct data_header {
	struct common_header common;

	/** @message_length: Total #bytes in the *message* */
	__be32 message_length;

	/**
	 * @incoming: The receiver can expect the sender to send all of the
	 * bytes in the message up to at least this offset (exclusive),
	 * even without additional grants. This includes unscheduled
	 * bytes, granted bytes, plus any additional bytes the sender
	 * transmits unilaterally (e.g., to send batches, such as with GSO).
	 */
	__be32 incoming;

	/**
	 * @cutoff_version: The cutoff_version from the most recent
	 * CUTOFFS packet that the source of this packet has received
	 * from the destination of this packet, or 0 if the source hasn't
	 * yet received a CUTOFFS packet.
	 */
	__be16 cutoff_version;

	/**
	 * @retransmit: 1 means this packet was sent in response to a RESEND
	 * (it has already been sent previously).
	 */
	__u8 retransmit;

	__u8 pad;

	/** @seg: First of possibly many segments */
	struct data_segment seg;
} __attribute__((packed));
_Static_assert(sizeof(struct data_header) <= HOMA_MAX_HEADER,
		"data_header too large for HOMA_MAX_HEADER; must "
		"adjust HOMA_MAX_HEADER");
_Static_assert(sizeof(struct data_header) >= HOMA_MIN_PKT_LENGTH,
		"data_header too small: Homa doesn't currently have code"
		"to pad data packets");
_Static_assert(((sizeof(struct data_header) - sizeof(struct data_segment))
		& 0x3) == 0,
		" data_header length not a multiple of 4 bytes (required "
		"for TCP/TSO compatibility");

/**
 * struct grant_header - Wire format for GRANT packets, which are sent by
 * the receiver back to the sender to indicate that the sender may transmit
 * additional bytes in the message.
 */
struct grant_header {
	/** @common: Fields common to all packet types. */
	struct common_header common;

	/**
	 * @offset: Byte offset within the message.
	 *
	 * The sender should now transmit all data up to (but not including)
	 * this offset ASAP, if it hasn't already.
	 */
	__be32 offset;

	/**
	 * @priority: The sender should use this priority level for all future
	 * MESSAGE_FRAG packets for this message, until a GRANT is received
	 * with higher offset. Larger numbers indicate higher priorities.
	 */
	__u8 priority;
} __attribute__((packed));
_Static_assert(sizeof(struct grant_header) <= HOMA_MAX_HEADER,
		"grant_header too large for HOMA_MAX_HEADER; must "
		"adjust HOMA_MAX_HEADER");

/**
 * struct resend_header - Wire format for RESEND packets.
 *
 * A RESEND is sent by the receiver when it believes that message data may
 * have been lost in transmission (or if it is concerned that the sender may
 * have crashed). The receiver should resend the specified portion of the
 * message, even if it already sent it previously.
 */
struct resend_header {
	/** @common: Fields common to all packet types. */
	struct common_header common;

	/**
	 * @offset: Offset within the message of the first byte of data that
	 * should be retransmitted.
	 */
	__be32 offset;

	/**
	 * @length: Number of bytes of data to retransmit; this could specify
	 * a range longer than the total message size. Zero is a special case
	 * used by servers; in this case, there is no need to actually resend
	 * anything; the purpose of this packet is to trigger an UNKNOWN
	 * response if the client no longer cares about this RPC.
	 */
	__be32 length;

	/**
	 * @priority: Packet priority to use.
	 *
	 * The sender should transmit all the requested data using this
	 * priority.
	 */
	__u8 priority;
} __attribute__((packed));
_Static_assert(sizeof(struct resend_header) <= HOMA_MAX_HEADER,
		"resend_header too large for HOMA_MAX_HEADER; must "
		"adjust HOMA_MAX_HEADER");

/**
 * struct unknown_header - Wire format for UNKNOWN packets.
 *
 * An UNKNOWN packet is sent by either server or client when it receives a
 * packet for an RPC that is unknown to it. When a client receives an
 * UNKNOWN packet it will typically restart the RPC from the beginning;
 * when a server receives an UNKNOWN packet it will typically discard its
 * state for the RPC.
 */
struct unknown_header {
	/** @common: Fields common to all packet types. */
	struct common_header common;
} __attribute__((packed));
_Static_assert(sizeof(struct unknown_header) <= HOMA_MAX_HEADER,
		"unknown_header too large for HOMA_MAX_HEADER; must "
		"adjust HOMA_MAX_HEADER");

/**
 * struct busy_header - Wire format for BUSY packets.
 *
 * These packets tell the recipient that the sender is still alive (even if
 * it isn't sending data expected by the recipient).
 */
struct busy_header {
	/** @common: Fields common to all packet types. */
	struct common_header common;
} __attribute__((packed));
_Static_assert(sizeof(struct busy_header) <= HOMA_MAX_HEADER,
		"busy_header too large for HOMA_MAX_HEADER; must "
		"adjust HOMA_MAX_HEADER");

/**
 * struct cutoffs_header - Wire format for CUTOFFS packets.
 *
 * These packets tell the recipient how to assign priorities to
 * unscheduled packets.
 */
struct cutoffs_header {
	/** @common: Fields common to all packet types. */
	struct common_header common;

	/**
	 * @unsched_cutoffs: priorities to use for unscheduled packets
	 * sent to the sender of this packet. See documentation for
	 * @homa.unsched_cutoffs for the meanings of these values.
	 */
	__be32 unsched_cutoffs[HOMA_MAX_PRIORITIES];

	/**
	 * @cutoff_version: unique identifier associated with @unsched_cutoffs.
	 * Must be included in future DATA packets sent to the sender of
	 * this packet.
	 */
	__be16 cutoff_version;
} __attribute__((packed));
_Static_assert(sizeof(struct cutoffs_header) <= HOMA_MAX_HEADER,
		"cutoffs_header too large for HOMA_MAX_HEADER; must "
		"adjust HOMA_MAX_HEADER");

/**
 * struct freeze_header - Wire format for FREEZE packets.
 *
 * These packets tell the recipient to freeze its timetrace; used
 * for debugging.
 */
struct freeze_header {
	/** @common: Fields common to all packet types. */
	struct common_header common;
} __attribute__((packed));
_Static_assert(sizeof(struct freeze_header) <= HOMA_MAX_HEADER,
		"freeze_header too large for HOMA_MAX_HEADER; must "
		"adjust HOMA_MAX_HEADER");

/**
 * struct need_ack_header - Wire format for NEED_ACK packets.
 *
 * These packets ask the recipient (a client) to return an ACK message if
 * the packet's RPC is no longer active.
 */
struct need_ack_header {
	/** @common: Fields common to all packet types. */
	struct common_header common;
} __attribute__((packed));
_Static_assert(sizeof(struct need_ack_header) <= HOMA_MAX_HEADER,
		"need_ack_header too large for HOMA_MAX_HEADER; must "
		"adjust HOMA_MAX_HEADER");

/**
 * struct ack_header - Wire format for ACK packets.
 *
 * These packets are sent from a client to a server to indicate that
 * a set of RPCs is no longer active on the client, so the server can
 * free any state it may have for them.
 */
struct ack_header {
	/** @common: Fields common to all packet types. */
	struct common_header common;

	/** @num_acks: number of (leading) elements in @acks that are valid. */
	__be16 num_acks;

	struct homa_ack acks[NUM_PEER_UNACKED_IDS];
} __attribute__((packed));
_Static_assert(sizeof(struct ack_header) <= HOMA_MAX_HEADER,
		"ack_header too large for HOMA_MAX_HEADER; must "
		"adjust HOMA_MAX_HEADER");

/**
 * struct homa_message_out - Describes a message (either request or response)
 * for which this machine is the sender.
 */
struct homa_message_out {
	/** @length: Total bytes in message (excluding headers).  A value
	 * less than 0 means this structure is uninitialized and therefore
	 * not in use.*/
	int length;

	/**
	 * @num_skbs:  Total number of buffers currently in @packets. Will
	 * be 0 if @length is less than 0.
	 */
	int num_skbs;

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

	/** @gso_pkt_data: Number of bytes of message data in each packet
	 * of @packets except possibly the last.
	 */
	int gso_pkt_data;

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

	/** @priority: Priority level to use for future scheduled packets. */
	__u8 sched_priority;

	/**
	 * @init_cycles: Time in get_cycles units when this structure was
	 * initialized.  Used to find the oldest outgoing message.
	 */
	__u64 init_cycles;
};

/**
 * struct homa_message_in - Holds the state of a message received by
 * this machine; used for both requests and responses.
 */
struct homa_message_in {
	/**
	 * @total_length: Size of the entire message, in bytes. A value
	 * less than 0 means this structure is uninitialized and therefore
	 * not in use.
	 */
	int total_length;

	/**
	 * @packets: DATA packets received for this message so far. The list
	 * is sorted in order of offset (head is lowest offset), but
	 * packets can be received out of order, so there may be times
	 * when there are holes in the list. Packets in this list contain
	 * exactly one data_segment. Packets on this list are removed from
	 * this list and freed once all of their data has been copied
	 * out to a user buffer.
	 */
	struct sk_buff_head packets;

	/**
	 * @num_skbs: Number of buffers currently in @packets. Will be 0 if
	 * @total_length is less than 0.
	 */
	int num_skbs;

	/**
	 * @bytes_remaining: Amount of data for this message that has
	 * not yet been received; will determine the message's priority.
	 */
	int bytes_remaining;

	/**
	 * @incoming: Total # of bytes of the message that the sender will
	 * transmit without additional grants. Initialized to the number of
	 * unscheduled bytes; after that, updated only when grants are sent.
	 * Never larger than @total_length. Note: once initialized, this
	 * may not be modified without holding @homa->grantable_lock.
	 */
        int incoming;

	/** @priority: Priority level to include in future GRANTS. */
	int priority;

	/**
	 * @scheduled: True means some of the bytes of this message
	 * must be scheduled with grants.
	 */
	bool scheduled;

	/**
	 * @birth: get_cycles time when this RPC was added to the grantable
	 * list. Invalid if RPC isn't in the grantable list.
	 */
	__u64 birth;

	/**
	 * @copied_out: All of the bytes of the message with offset less
	 * than this value have been copied to user-space buffers.
	 */
	int copied_out;

	/**
	 * @num_bpages: The number of entries in @bpage_offsets used for this
	 * message (0 means buffers not allocated yet).
	 */
	__u32 num_bpages;

	/** @bpage_offsets: Describes buffer space allocated for this message.
	 * Each entry is an offset from the start of the buffer region.
	 * All but the last pointer refer to areas of size HOMA_BPAGE_SIZE.
	 */
	__u32 bpage_offsets[HOMA_MAX_BPAGES];
};

/**
 * struct homa_interest - Contains various information used while waiting
 * for incoming messages (indicates what kinds of messages a particular
 * thread is interested in receiving).
 */
struct homa_interest {
	/**
	 * @thread: Thread that would like to receive a message. Will get
	 * woken up when a suitable message becomes available.
	 */
	struct task_struct *thread;

	/**
	 * @ready_rpc: This is actually a (struct homa_rpc *) identifying the
	 * RPC that was found; NULL if no RPC has been found yet. This
	 * variable is used for synchronization to handoff the RPC, and
	 * must be set only after @locked is set.
	 */
	atomic_long_t ready_rpc;

	/**
	 * @locked: Nonzero means that @ready_rpc is locked; only valid
	 * if @ready_rpc is non-NULL.
	 */
	int locked;

	/**
	 * @reg_rpc: RPC whose @interest field points here, or
	 * NULL if none.
	 */
	struct homa_rpc *reg_rpc;

	/**
	 * @request_links: For linking this object into
	 * &homa_sock.request_interests. The interest must not be linked
	 * on either this list or @response_links if @id is nonzero.
	 */
	struct list_head request_links;

	/**
	 * @response_links: For linking this object into
	 * &homa_sock.request_interests.
	 */
	struct list_head response_links;
};

/**
 * homa_interest_init() - Fill in default values for all of the fields
 * of a struct homa_interest.
 * @interest:   Struct to initialize.
 */
static void inline homa_interest_init(struct homa_interest *interest)
{
	interest->thread = current;
	atomic_long_set(&interest->ready_rpc, 0);
	interest->locked = 0;
	interest->reg_rpc = NULL;
	interest->request_links.next = LIST_POISON1;
	interest->response_links.next = LIST_POISON1;
}

/**
 * struct homa_rpc - One of these structures exists for each active
 * RPC. The same structure is used to manage both outgoing RPCs on
 * clients and incoming RPCs on servers.
 */
struct homa_rpc {
	/** @hsk:  Socket that owns the RPC. */
	struct homa_sock *hsk;

	/** @lock: Used to synchronize modifications to this structure;
	 * points to the lock in hsk->client_rpc_buckets or
	 * hsk->server_rpc_buckets.
	 */
	struct spinlock *lock;

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
	 * RPC_XMITTING -          homa_xmit_data is actively transmitting
	 *                         packets for this RPC, so it must not be
	 *                         reaped.
	 */
#define RPC_PKTS_READY        1
#define RPC_COPYING_FROM_USER 2
#define RPC_COPYING_TO_USER   4
#define RPC_HANDING_OFF       8
#define RPC_XMITTING          0x10

#define RPC_CANT_REAP (RPC_COPYING_FROM_USER | RPC_COPYING_TO_USER \
		| RPC_HANDING_OFF | RPC_XMITTING)

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
	 * &homa_sock.ready_requests or &homa_sock.ready_responses.
	 */
	struct list_head ready_links;

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
	 * @start_cycles: time (from get_cycles()) when this RPC was created.
	 * Used (sometimes) for testing.
	 */
	uint64_t start_cycles;
};

/**
 * homa_rpc_lock() - Acquire the lock for an RPC.
 * @rpc:   RPC to lock. Note: this function is only safe under
 *         limited conditions. The caller must ensure that the RPC
 *         cannot be reaped before the lock is acquired. It cannot
 *         do that by acquiring the socket lock, since that violates
 *         lock ordering constraints. One approach is to increment
 *         rpc->hsk->reap_disable. Don't use this function unless you
 *         are very sure what you are doing!  See sync.txt for more
 *         info on locking.
 */
inline static void homa_rpc_lock(struct homa_rpc *rpc) {
	if (!spin_trylock_bh(rpc->lock))
		homa_rpc_lock_slow(rpc);
}

/**
 * homa_rpc_unlock() - Release the lock for an RPC.
 * @rpc:   RPC to unlock.
 */
inline static void homa_rpc_unlock(struct homa_rpc *rpc) {
	spin_unlock_bh(rpc->lock);
}

/**
 * homa_rpc_validate() - Check to see if an RPC has been reaped (which
 * would mean it is no longer valid); if so, crash the kernel with a stack
 * trace.
 * @rpc:   RPC to validate.
 */
inline static void homa_rpc_validate(struct homa_rpc *rpc) {
	if (rpc->magic == HOMA_RPC_MAGIC)
		return;
	printk(KERN_ERR "Accessing reaped Homa RPC!\n");
	BUG();
}

/**
 * define HOMA_SOCKTAB_BUCKETS - Number of hash buckets in a homa_socktab.
 * Must be a power of 2.
 */
#define HOMA_SOCKTAB_BUCKETS 1024

/**
 * struct homa_socktab - A hash table that maps from port numbers (either
 * client or server) to homa_sock objects.
 *
 * This table is managed exclusively by homa_socktab.c, using RCU to
 * minimize synchronization during lookups.
 */
struct homa_socktab {
	/**
	 * @mutex: Controls all modifications to this object; not needed
	 * for socket lookups (RCU is used instead). Also used to
	 * synchronize port allocation.
	 */
	struct spinlock write_lock;

	/**
	 * @buckets: Heads of chains for hash table buckets. Chains
	 * consist of homa_socktab_link objects.
	 */
	struct hlist_head buckets[HOMA_SOCKTAB_BUCKETS];
};

/**
 * struct homa_socktab_links - Used to link homa_socks into the hash chains
 * of a homa_socktab.
 */
struct homa_socktab_links {
	/* Must be the first element of the struct! */
	struct hlist_node hash_links;
	struct homa_sock *sock;
};

/**
 * struct homa_socktab_scan - Records the state of an iteration over all
 * the entries in a homa_socktab, in a way that permits RCU-safe deletion
 * of entries.
 */
struct homa_socktab_scan {
	/** @socktab: The table that is being scanned. */
	struct homa_socktab *socktab;

	/**
	 * @current_bucket: the index of the bucket in socktab->buckets
	 * currently being scanned. If >= HOMA_SOCKTAB_BUCKETS, the scan
	 * is complete.
	 */
	int current_bucket;

	/**
	 * @next: the next socket to return from homa_socktab_next (this
	 * socket has not yet been returned). NULL means there are no
	 * more sockets in the current bucket.
	 */
	struct homa_socktab_links *next;
};

/**
 * define HOMA_CLIENT_RPC_BUCKETS - Number of buckets in hash tables for
 * client RPCs. Must be a power of 2.
 */
#define HOMA_CLIENT_RPC_BUCKETS 1024

/**
 * define HOMA_SERVER_RPC_BUCKETS - Number of buckets in hash tables for
 * server RPCs. Must be a power of 2.
 */
#define HOMA_SERVER_RPC_BUCKETS 1024

struct homa_rpc_bucket {
	/**
	 * @lock: serves as a lock both for this bucket (e.g., when
	 * adding and removing RPCs) and also for all of the RPCs in
	 * the bucket. Must be held whenever manipulating an RPC in
	 * this bucket. This dual purpose permits clean and safe
	 * deletion and garbage collection of RPCs.
	 */
	struct spinlock lock;

	/** @rpcs: list of RPCs that hash to this bucket. */
	struct hlist_head rpcs;
};

/**
 * struct homa_bpage - Contains information about a single page in
 * a buffer pool. Note: this information is stored in user memory, so
 * it needs to be managed so that a misbehaving user program can't cause
 * kernel crashes (it's OK if a misbehaving program causes the buffer pool
 * to misbehave, such as running out of space, as long as it doesn't cause
 * a kernel crash).
 */
struct homa_bpage {
	union {
		/**
		 * @cache_line: Ensures that each homa_bpage object
		 * is exactly one cache line long.
		 */
		struct homa_cache_line cache_line;
		struct {
			/** @lock: to synchronize shared access. Must never
			 * wait for this lock, since a faulty user program
			 * could leave it locked.
			 */
			struct spinlock lock;

			/**
			 * @refs: Number of messages with data in this page.
			 * The kernel increments this when allocating buffer
			 * space for a message, and the app decrements it when
			 * done with a message.
			 */
			atomic_t refs;

			/**
			 * @owner: kernel core that currently owns this page
			 * (< 0 if none).
			 */
			int owner;

			/**
			 * @expiration: time (in get_cycles units) after
			 * which it's OK to steal this page from its current
			 * owner.
			 */
			__u64 expiration;
		};
	};
};
_Static_assert(sizeof(struct homa_bpage) == sizeof(struct homa_cache_line),
		"homa_bpage overflowed a cache line");

/**
 * struct homa_pool_core - Holds core-specific data for a homa_pool (a bpage
 * out of which that core is allocating small chunks).
 */
struct homa_pool_core {
	union {
		/**
		 * @cache_line: Ensures that each object is exactly one
		 * cache line long.
		 */
		struct homa_cache_line cache_line;
		struct {
			/**
			 * @page_hint: Index of bpage in pool->descriptors,
			 * which may be owned by this core. If so, we'll use it
			 * for allocating partial pages.
			 */
			int page_hint;

			/**
			 * @allocated: if the page given by @page_hint is
			 * owned by this core, this variable gives the number of
			 * (initial) bytes that have already been allocated
			 * from the page.
			 */
			int allocated;
		};
	};
};
_Static_assert(sizeof(struct homa_pool_core) == sizeof(struct homa_cache_line),
		"homa_pool_core overflowed a cache line");

/**
 * struct homa_pool - Describes a pool of buffer space for incoming
 * messages for a particular socket; managed by homa_pool.c. The pool is
 * divided up into "bpages", which are a multiple of the hardware page size.
 * A bpage may be owned by a particular core so that it can more efficiently
 * allocate space for small messages.
 */
struct homa_pool {
	/**
	 * @region: beginning of the pool's region (in the app's virtual
	 * memory). Initial portion is used for bpage metadata shared
	 * with the application, and the remainder is divided into pages.
	 * 0 means the pool hasn't yet been initialized.
	 */
	char *region;

	/** @num_bpages: total number of bpages in the pool. */
	int num_bpages;

	/**
	 * @homa: shared information about the Homa driver.
	 */
	struct homa *homa;

	/** @descriptors: kmalloced area containing one entry for each bpage. */
	struct homa_bpage *descriptors;

	/**
	 * @active_pages: the number of bpages (always the lowest ones)
	 * that are currently being used for allocation.  Varies slowly
	 * depending on active buffer usage. The goal is to keep this
	 * number small to minimize memory footprint, while keeping it
	 * large enough so that many pages are free at any given time
	 * (so allocation is efficient).
	 */
	atomic_t active_pages;

	/**
	 * @next_scan: index of the next page to check while searching for
	 * a free bpage.
	 */
	atomic_t next_scan;

	/**
	 * @free_bpages_found: the number of pages successfully allocated
	 * so far in the current scan (i.e. since @next_scan was set to 0).
	 */
	atomic_t free_bpages_found;

	/** @cores: core-specific info; dynamically allocated. */
	struct homa_pool_core *cores;

	/** @num_cores: number of elements in @cores. */
	int num_cores;
};

/**
 * struct homa_sock - Information about an open socket.
 */
struct homa_sock {
	/* Info for other network layers. Note: IPv6 info (struct ipv6_pinfo
	 * comes at the very end of the struct, *after* Homa's data, if this
	 * socket uses IPv6).
	 */
	union {
		/** @sock: generic socket data; must be the first field. */
		struct sock sock;

		/**
		 * @inet: generic Internet socket data; must also be the
		 first field (contains sock as its first member).
		 */
		struct inet_sock inet;
	};

	/**
	 * @lock: Must be held when modifying fields such as interests
	 * and lists of RPCs. This lock is used in place of sk->sk_lock
	 * because it's used differently (it's always used as a simple
	 * spin lock).  See sync.txt for more on Homa's synchronization
	 * strategy.
	 */
	struct spinlock lock;

	/**
	 * @last_locker: identifies the code that most recently acquired
	 * @lock successfully. Occasionally used for debugging. */
	char *last_locker;

	/**
	 * @protect_count: counts the number of calls to homa_protect_rpcs
	 * for which there have not yet been calls to homa_unprotect_rpcs.
	 * See sync.txt for more info.
	 */
	atomic_t protect_count;

	/**
	 * @homa: Overall state about the Homa implementation. NULL
	 * means this socket has been deleted.
	 */
	struct homa *homa;

	/** @shutdown: True means the socket is no longer usable. */
	bool shutdown;

	/**
	 * @port: Port number: identifies this socket uniquely among all
	 * those on this node.
	 */
	__u16 port;

	/**
	 * @ip_header_length: Length of IP headers for this socket (depends
	 * on IPv4 vs. IPv6).
	 */
	int ip_header_length;

	/**
	 * @client_socktab_links: Links this socket into the homa_socktab
	 * based on @port.
	 */
	struct homa_socktab_links socktab_links;

	/**
	 * @active_rpcs: List of all existing RPCs related to this socket,
	 * including both client and server RPCs. This list isn't strictly
	 * needed, since RPCs are already in one of the hash tables below,
	 * but it's more efficient for homa_timer to have this list
	 * (so it doesn't have to scan large numbers of hash buckets).
	 * The list is sorted, with the oldest RPC first. Manipulate with
	 * RCU so timer can access without locking.
	 */
	struct list_head active_rpcs;

	/**
	 * @dead_rpcs: Contains RPCs for which homa_rpc_free has been
	 * called, but their packet buffers haven't yet been freed.
	 */
	struct list_head dead_rpcs;

	/** @dead_skbs: Total number of socket buffers in RPCs on dead_rpcs. */
	int dead_skbs;

	/**
	 * @ready_requests: Contains server RPCs whose request message is
	 * in a state requiring attention from  a user process. The head is
	 * oldest, i.e. next to return.
	 */
	struct list_head ready_requests;

	/**
	 * @ready_responses: Contains client RPCs whose response message is
	 * in a state requiring attention from a user process. The head is
	 * oldest, i.e. next to return.
	 */
	struct list_head ready_responses;

	/**
	 * @request_interests: List of threads that want to receive incoming
	 * request messages.
	 */
	struct list_head request_interests;

	/**
	 * @response_interests: List of threads that want to receive incoming
	 * response messages.
	 */
	struct list_head response_interests;

	/**
	 * @client_rpc_buckets: Hash table for fast lookup of client RPCs.
	 * Modifications are synchronized with bucket locks, not
	 * the socket lock.
	 */
	struct homa_rpc_bucket client_rpc_buckets[HOMA_CLIENT_RPC_BUCKETS];

	/**
	 * @server_rpc_buckets: Hash table for fast lookup of server RPCs.
	 * Modifications are synchronized with bucket locks, not
	 * the socket lock.
	 */
	struct homa_rpc_bucket server_rpc_buckets[HOMA_SERVER_RPC_BUCKETS];

	/**
	 * @buffer_pool: used to allocate buffer space for incoming messages.
	 */
	struct homa_pool buffer_pool;
};

/**
 * struct homa_dead_dst - Used to retain dst_entries that are no longer
 * needed, until it is safe to delete them (I'm not confident that the RCU
 * mechanism will be safe for these: the reference count could get incremented
 * after it's on the RCU list?).
 */
struct homa_dead_dst {
	/** @dst: Entry that is no longer used by a struct homa_peer. */
	struct dst_entry *dst;

	/**
	 * @gc_time: Time (in units of get_cycles) when it is safe
	 * to free @dst.
	 */
	__u64 gc_time;

	/** @dst_links: Used to link together entries in peertab->dead_dsts. */
	struct list_head dst_links;
};

/**
 * define HOMA_PEERTAB_BUCKETS - Number of bits in the bucket index for a
 * homa_peertab.  Should be large enough to hold an entry for every server
 * in a datacenter without long hash chains.
 */
#define HOMA_PEERTAB_BUCKET_BITS 20

/** define HOME_PEERTAB_BUCKETS - Number of buckets in a homa_peertab. */
#define HOMA_PEERTAB_BUCKETS (1 << HOMA_PEERTAB_BUCKET_BITS)

/**
 * struct homa_peertab - A hash table that maps from IPv6 addresses
 * to homa_peer objects. IPv4 entries are encapsulated as IPv6 addresses.
 * Entries are gradually added to this table, but they are never removed
 * except when the entire table is deleted. We can't safely delete because
 * results returned by homa_peer_find may be retained indefinitely.
 *
 * This table is managed exclusively by homa_peertab.c, using RCU to
 * permit efficient lookups.
 */
struct homa_peertab {
	/**
	 * @write_lock: Synchronizes addition of new entries; not needed
	 * for lookups (RCU is used instead).
	 */
	struct spinlock write_lock;

	/**
	 * @dead_dsts: List of dst_entries that are waiting to be deleted.
	 * Hold @write_lock when manipulating.
	 */
	struct list_head dead_dsts;

	/**
	 * @buckets: Pointer to heads of chains of homa_peers for each bucket.
	 * Malloc-ed, and must eventually be freed. NULL means this structure
	 * has not been initialized.
	 */
	struct hlist_head *buckets;
};

/**
 * struct homa_peer - One of these objects exists for each machine that we
 * have communicated with (either as client or server).
 */
struct homa_peer {
	/**
	 * @addr: IPv6 address for the machine (IPv4 addresses are stored
	 * as IPv4-mapped IPv6 addresses).
	 */
	struct in6_addr addr;

	/** @flow: Addressing info needed to send packets. */
	struct flowi flow;

	/**
	 * @dst: Used to route packets to this peer; we own a reference
	 * to this, which we must eventually release.
	 */
	struct dst_entry *dst;

	/**
	 * @unsched_cutoffs: priorities to use for unscheduled packets
	 * sent to this host, as specified in the most recent CUTOFFS
	 * packet from that host. See documentation for @homa.unsched_cutoffs
	 * for the meanings of these values.
	 */
	int unsched_cutoffs[HOMA_MAX_PRIORITIES];

	/**
	 * @cutoff_version: value of cutoff_version in the most recent
	 * CUTOFFS packet received from this peer.  0 means we haven't
	 * yet received a CUTOFFS packet from the host. Note that this is
	 * stored in network byte order.
	 */
	__be16 cutoff_version;

	/**
	 * last_update_jiffies: time in jiffies when we sent the most
	 * recent CUTOFFS packet to this peer.
	 */
	unsigned long last_update_jiffies;

	/**
	 * grantable_rpcs: Contains all homa_rpcs (both requests and
	 * responses) involving this peer whose msgins require (or required
	 * them in the past) and have not been fully received. The list is
	 * sorted in priority order (head has fewest bytes_remaining).
	 * Locked with homa->grantable_lock.
	 */
	struct list_head grantable_rpcs;

	/**
	 * @grantable_links: Used to link this peer into homa->grantable_peers,
	 * if there are entries in grantable_rpcs. If grantable_rpcs is empty,
	 * this is an empty list pointing to itself.
	 */
	struct list_head grantable_links;

	/**
	 * @peertab_links: Links this object into a bucket of its
	 * homa_peertab.
	 */
	struct hlist_node peertab_links;

	/**
	 * @outstanding_resends: the number of resend requests we have
	 * sent to this server (spaced @homa.resend_interval apart) since
	 * we received a packet from this peer.
	 */
	int outstanding_resends;

	/**
	 * @most_recent_resend: @homa->timer_ticks when the most recent
	 * resend was sent to this peer.
	 */
	int most_recent_resend;

	/**
	 * @least_recent_rpc: of all the RPCs for this peer scanned at
	 * @current_ticks, this is the RPC whose @resend_timer_ticks
	 * is farthest in the past.
	 */
	struct homa_rpc *least_recent_rpc;

	/**
	 * @least_recent_ticks: the @resend_timer_ticks value for
	 * @least_recent_rpc.
	 */
	__u32 least_recent_ticks;

	/**
	 * @current_ticks: the value of @homa->timer_ticks the last time
	 * that @least_recent_rpc and @least_recent_ticks were computed.
	 * Used to detect the start of a new homa_timer pass.
	 */
	__u32 current_ticks;

	/**
	 * @resend_rpc: the value of @least_recent_rpc computed in the
	 * previous homa_timer pass. This RPC will be issued a RESEND
	 * in the current pass, if it still needs one.
	 */
	struct homa_rpc *resend_rpc;

	/**
	 * @num_acks: the number of (initial) entries in @acks that
	 * currently hold valid information.
	 */
	int num_acks;

	/**
	 * @acks: info about client RPCs whose results have been completely
	 * received.
	 */
	struct homa_ack acks[NUM_PEER_UNACKED_IDS];

	/**
	 * @ack_lock: used to synchronize access to @num_acks and @acks.
	 */
	struct spinlock ack_lock;
};

/**
 * enum homa_freeze_type - The @type argument to homa_freeze must be
 * one of these values.
 */
enum homa_freeze_type {
	RESTART_RPC        = 1,
	PEER_TIMEOUT       = 2,
	SLOW_RPC           = 3,
	SOCKET_CLOSE       = 4,
	PACKET_LOST        = 5,
};

/**
 * struct homa - Overall information about the Homa protocol implementation.
 *
 * There will typically only exist one of these at a time, except during
 * unit tests.
 */
struct homa {
	/**
	 * @next_outgoing_id: Id to use for next outgoing RPC request.
	 * This is always even: it's used only to generate client-side ids.
	 * Accessed without locks.
	 */
	atomic64_t next_outgoing_id;

	/**
	 * @link_idle_time: The time, measured by get_cycles() at which we
	 * estimate that all of the packets we have passed to Linux for
	 * transmission will have been transmitted. May be in the past.
	 * This estimate assumes that only Homa is transmitting data, so
	 * it could be a severe underestimate if there is competing traffic
	 * from, say, TCP. Access only with atomic ops.
	 */
	atomic64_t link_idle_time __attribute__((aligned(CACHE_LINE_SIZE)));

	/**
	 * @grantable_lock: Used to synchronize access to @grantable_peers and
	 * @num_grantable_peers.
	 */
	struct spinlock grantable_lock __attribute__((aligned(CACHE_LINE_SIZE)));

	/**
	 * @grantable_peers: Contains all homa_peers for which there are
	 * RPCs that have not been fully granted. The list is sorted in
	 * priority order (the rpc with the fewest bytes_remaining is the
	 * first one on the first peer's list).
	 */
	struct list_head grantable_peers;

	/** @num_grantable_peers: The number of peers in grantable_peers. */
	int num_grantable_peers;

	/**
	 * @grant_nonfifo: How many bytes should be granted using the
	 * normal priority system between grants to the oldest message.
	 */
	int grant_nonfifo;

	/**
	 * @grant_nonfifo_left: Counts down bytes using the normal
	 * priority mechanism. When this reaches zero, it's time to grant
	 * to the old message.
	 */
	int grant_nonfifo_left;

	/**
	 * @pacer_mutex: Ensures that only one instance of homa_pacer_xmit
	 * runs at a time. Only used in "try" mode: never block on this.
	 */
	struct spinlock pacer_mutex __attribute__((aligned(CACHE_LINE_SIZE)));

	/**
	 * @pacer_fifo_fraction: The fraction of time (in thousandths) when
	 * the pacer should transmit next from the oldest message, rather
	 * than the highest-priority message. Set externally via sysctl.
	 */
	int pacer_fifo_fraction;

	/**
	 * @pacer_fifo_count: When this becomes <= zero, it's time for the
	 * pacer to allow the oldest RPC to transmit.
	 */
	int pacer_fifo_count;

	/**
	 * @pacer_start: get_cycles() time when the pacer last woke up
	 * (if the pacer is running) or 0 if the pacer is sleeping.
	 */
	__u64 pacer_wake_time;

	/**
	 * @throttle_lock: Used to synchronize access to @throttled_rpcs. To
	 * insert or remove an RPC from throttled_rpcs, must first acquire
	 * the RPC's socket lock, then this lock.
	 */
	struct spinlock throttle_lock;

	/**
	 * @throttled_rpcs: Contains all homa_rpcs that have bytes ready
	 * for transmission, but which couldn't be sent without exceeding
	 * the queue limits for transmission. Manipulate only with "_rcu"
	 * functions.
	 */
	struct list_head throttled_rpcs;

	/**
	 * @throttle_add: The get_cycles() time when the most recent RPC
	 * was added to @throttled_rpcs.
	 */
	__u64 throttle_add;

	/**
	 * @throttle_min_bytes: If a packet has fewer bytes than this, then it
	 * bypasses the throttle mechanism and is transmitted immediately.
	 * We have this limit because for very small packets we can't keep
	 * up with the NIC (we're limited by CPU overheads); there's no
	 * need for throttling and going through the throttle mechanism
	 * adds overhead, which slows things down. At least, that's the
	 * hypothesis (needs to be verified experimentally!). Set externally
	 * via sysctl.
	 */
	int throttle_min_bytes;

	/**
	 * @total_incoming: the total number of bytes that we expect to receive
	 * (across all messages) even if we don't send out any more grants
	 * (includes granted but unreceived bytes, plus unreceived unscheduled
	 * bytes that we know about). This can potentially be negative, if
	 * a peer sends more bytes than granted (see synchronization note in
	 * homa_send_grants for why we have to allow this possibility).
	 */
	atomic_t total_incoming __attribute__((aligned(CACHE_LINE_SIZE)));

	/**
	 * @next_client_port: A client port number to consider for the
	 * next Homa socket; increments monotonically. Current value may
	 * be in the range allocated for servers; must check before using.
	 * This port may also be in use already; must check.
	 */
	__u16 next_client_port __attribute__((aligned(CACHE_LINE_SIZE)));

	/**
	 * @port_map: Information about all open sockets.
	 */
	struct homa_socktab port_map __attribute__((aligned(CACHE_LINE_SIZE)));

	/**
	 * @peertab: Info about all the other hosts we have communicated with.
	 */
	struct homa_peertab peers;

	/**
	 * @rtt_bytes: An estimate of the amount of data that can be transmitted
         * over the wire in the time it takes to send a full-size data packet
         * and receive back a grant. Used to ensure full utilization of
         * uplink bandwidth. Set externally via sysctl.
	 */
	int rtt_bytes;

	/**
	 * @max_grant_window: if nonzero, determines the maximum number
	 * of granted-but-not-yet-received bytes for a message (may be
	 * greater than rtt_bytes). This feature is currently for
	 * experimentation only. Set externally via sysctl.*/
	int max_grant_window;

	/**
	 * @link_bandwidth: The raw bandwidth of the network uplink, in
	 * units of 1e06 bits per second.  Set externally via sysctl.
	 */
	int link_mbps;

	/**
	 * @poll_usecs: Amount of time (in microseconds) that a thread
	 * will spend busy-waiting for an incoming messages before
	 * going to sleep. Set externally via sysctl.
	 */
	int poll_usecs;

	/**
	 * @poll_cycles: The value of @poll_usecs in the units returned
	 * by get_cycles().
	 */
	int poll_cycles;

	/**
	 * @num_priorities: The total number of priority levels available for
	 * Homa's use. Internally, Homa will use priorities from 0 to
	 * num_priorities-1, inclusive. Set externally via sysctl.
	 */
	int num_priorities;

	/**
	 * @priority_map: entry i gives the value to store in the high-order
	 * 3 bits of the DSCP field of IP headers to implement priority level
	 * i. Set externally via sysctl.
	 */
	int priority_map[HOMA_MAX_PRIORITIES];

	/**
	 * @max_sched_prio: The highest priority level currently available for
	 * scheduled packets. Levels above this are reserved for unscheduled
	 * packets.  Set externally via sysctl.
	 */
	int max_sched_prio;

	/**
	 * @unsched_cutoffs: the current priority assignments for incoming
	 * unscheduled packets. The value of entry i is the largest
	 * message size that uses priority i (larger i is higher priority).
	 * If entry i has a value of HOMA_MAX_MESSAGE_SIZE or greater, then
	 * priority levels less than i will not be used for unscheduled
	 * packets. At least one entry in the array must have a value of
	 * HOMA_MAX_MESSAGE_SIZE or greater (entry 0 is usually INT_MAX).
	 * Set externally via sysctl.
	 */
	int unsched_cutoffs[HOMA_MAX_PRIORITIES];

	/**
	 * @cutoff_version: increments every time unsched_cutoffs is
	 * modified. Used to determine when we need to send updates to
	 * peers.  Note: 16 bits should be fine for this: the worst
	 * that happens is a peer has a super-stale value that equals
	 * our current value, so the peer uses suboptimal cutoffs until the
	 * next version change.  Can be set externally via sysctl.
	 */
	int cutoff_version;

	/**
	 * @fifo_grant_increment: how many additional bytes to grant in
	 * a "pity" grant sent to the oldest outstanding message. Set
	 * externally via sysctl.
	 */
	int fifo_grant_increment;

	/**
	 * @grant_fifo_fraction: The fraction (in thousandths) of granted
	 * bytes that should go to the *oldest* incoming message, rather
	 * than the highest priority ones. Set externally via sysctl.
	 */
	int grant_fifo_fraction;

	/**
	 * @duty_cycle: Sets a limit on the fraction of network bandwidth that
	 * may be consumed by a single RPC in units of one-thousandth (1000
	 * means a single RPC can consume all of the incoming network
	 * bandwidth, 500 means half, and so on). This also determines the
	 * fraction of a core that can be consumed by NAPI when a large
	 * message is being received. Its main purpose is to keep NAPI from
	 * monopolizing a core so much that user threads starve. Set externally
	 * via sysctl.
	 */
	int duty_cycle;

	/**
	 * @grant_threshold: A grant will not be sent for an RPC until
	 * the number of incoming bytes drops below this threshold. Computed
	 * from @rtt_bytes and @duty_cycle.
	 */
	int grant_threshold;

	/**
	 * @max_overcommit: The maximum number of messages to which Homa will
	 * send grants at any given point in time.  Set externally via sysctl.
	 */
	int max_overcommit;

	/**
	 * @max_incoming: This value is computed from max_overcommit, and
	 * is the limit on how many bytes are currently permitted to be
	 * granted but not yet received, cumulative across all messages.
	 */
	int max_incoming;

	/**
	 * @resend_ticks: When an RPC's @silent_ticks reaches this value,
	 * start sending RESEND requests.
	 */
	int resend_ticks;

	/**
	 * @resend_interval: minimum number of homa timer ticks between
	 * RESENDs to the same peer.
	 */
	int resend_interval;

	/**
	 * @timeout_resends: Assume that a server is dead if it has not
	 * responded after this many RESENDs have been sent to it.
	 */
	int timeout_resends;

	/**
	 * @request_ack_ticks: How many timer ticks we'll wait for the
	 * client to ack an RPC before explicitly requesting an ack.
	 * Set externally via sysctl.
	 */
	int request_ack_ticks;

	/**
	 * @reap_limit: Maximum number of packet buffers to free in a
	 * single call to home_rpc_reap.
	 */
	int reap_limit;

	/**
	 * @dead_buffs_limit: If the number of packet buffers in dead but
	 * not yet reaped RPCs is less than this number, then Homa reaps
	 * RPCs in a way that minimizes impact on performance but may permit
	 * dead RPCs to accumulate. If the number of dead packet buffers
	 * exceeds this value, then Homa switches to a more aggressive approach
	 * to reaping RPCs. Set externally via sysctl.
	 */
	int dead_buffs_limit;

	/**
	 * @max_dead_buffs: The largest aggregate number of packet buffers
	 * in dead (but not yet reaped) RPCs that has existed so far in a
	 * single socket.  Readable via sysctl, and may be reset via sysctl
	 * to begin recalculating.
	 */
	int max_dead_buffs;

	/**
	 * @pacer_kthread: Kernel thread that transmits packets from
	 * throttled_rpcs in a way that limits queue buildup in the
	 * NIC.
	 */
	struct task_struct *pacer_kthread;

	/**
	 * @pacer_exit: true means that the pacer thread should exit as
	 * soon as possible.
	 */
	bool pacer_exit;

	/**
	 * @max_nic_queue_ns: Limits the NIC queue length: we won't queue
	 * up a packet for transmission if link_idle_time is this many
	 * nanoseconds in the future (or more). Set externally via sysctl.
	 */
	int max_nic_queue_ns;

	/**
	 * @max_nic_queue_cycles: Same as max_nic_queue_ns, except in units
	 * of get_cycles().
	 */
	int max_nic_queue_cycles;

	/**
	 * @cycles_per_kbyte: the number of cycles, as measured by get_cycles(),
	 * that it takes to transmit 1000 bytes on our uplink. This is actually
	 * a slight overestimate of the value, to ensure that we don't
	 * underestimate NIC queue length and queue too many packets.
	 */
	__u32 cycles_per_kbyte;

	/**
	 * @verbose: Nonzero enables additional logging. Set externally via
	 * sysctl.
	 */
	int verbose;

	/**
	 * @max_gso_size: Maximum number of bytes that will be included
	 * in a single output packet that Homa passes to Linux. Can be set
	 * externally via sysctl to lower the limit already enforced by Linux.
	 */
	int max_gso_size;

	/**
	 * @max_gro_skbs: Maximum number of socket buffers that can be
	 * aggregated by the GRO mechanism.  Set externally via sysctl.
	 */
	int max_gro_skbs;

	/**
	 * @gro_policy: An OR'ed together collection of bits that determine
	 * how Homa packets should be steered for SoftIRQ handling.  A value
	 * of zero will eliminate any Homa-specific behaviors, reverting
	 * to the Linux defaults. Set externally via sysctl (but modifying
	 * it is almost certainly a bad idea; see below).
	 */
	int gro_policy;

	/* Bits that can be specified for gro_policy. These were created for
	 * testing, in order to evaluate various possible policies; you almost
	 * certainly should not use any value other than HOMA_GRO_NORMAL.
	 * HOMA_GRO_BYPASS:           Pass all incoming packets directly to
	 *                            homa_softirq during GRO; this bypasses
	 *                            the SoftIRQ dispatching mechanism as well
	 *                            as the network and IP stack layers.
	 * HOMA_GRO_SAME_CORE         If isolated packets arrive (not part of
	 *                            a batch) use the GRO core for SoftIRQ also.
	 * HOMA_GRO_IDLE              Use old mechanism for selecting an idle
	 *                            core for SoftIRQ (deprecated).
	 * HOMA_GRO_NEXT              Always use the next core in circular
	 *                            order for SoftIRQ (deprecated).
	 * HOMA_GRO_IDLE_NEW          Use the new mechanism for selecting an
	 *                            idle core for SoftIRQ.
	 * HOMA_GRO_FAST_GRANTS       Pass all grant I can see immediately to
	 *                            homa_softirq during GRO.
	 * HOMA_GRO_SHORT_BYPASS      Pass all short packets directly to
	 *                            homa_softirq during GR).
	 */
	#define HOMA_GRO_BYPASS          1
	#define HOMA_GRO_SAME_CORE       2
	#define HOMA_GRO_IDLE            4
	#define HOMA_GRO_NEXT            8
	#define HOMA_GRO_IDLE_NEW       16
	#define HOMA_GRO_FAST_GRANTS    32
	#define HOMA_GRO_SHORT_BYPASS   64
	#define HOMA_GRO_NORMAL      (HOMA_GRO_SAME_CORE|HOMA_GRO_IDLE_NEW \
			|HOMA_GRO_SHORT_BYPASS)

	/*
	 * @gro_busy_usecs: try not to schedule SoftIRQ processing on a core
	 * if it has handled Homa packets at GRO level in the last
	 * gro_busy_us microseconds (improve load balancing by avoiding
	 * hot spots). Set externally via sysctl.
	 */
	int gro_busy_usecs;

	/**
	 * @gro_busy_cycles: Same as gro_busy_usecs, except in units
	 * of get_cycles().
	 */
	int gro_busy_cycles;

	/**
	 * @timer_ticks: number of times that homa_timer has been invoked
	 * (may wraparound, which is safe).
	 */
	__u32 timer_ticks;

	/**
	 * @metrics_lock: Used to synchronize accesses to @metrics_active_opens
	 * and updates to @metrics.
	 */
	struct spinlock metrics_lock;

	/*
	 * @metrics: a human-readable string containing recent values
	 * for all the Homa performance metrics, as generated by
	 * homa_append_metric. This string is kmalloc-ed; NULL means
	 * homa_append_metric has never been called.
	 */
	char* metrics;

	/** @metrics_capacity: number of bytes available at metrics. */
	size_t metrics_capacity;

	/**
	 * @metrics_length: current length of the string in metrics,
	 * not including terminating NULL character.
	 */
	size_t metrics_length;

	/**
	 * @metrics_active_opens: number of open struct files that
	 * currently exist for the metrics file in /proc.
	 */
	int metrics_active_opens;

	/**
	 * @flags: a collection of bits that can be set using sysctl
	 * to trigger various behaviors.
	 */
	int flags;

	/**
	 * @freeze_type: determines conditions under which the time trace
	 * should be frozen. Set externally via sysctl.
	 */
	enum homa_freeze_type freeze_type;

	/**
	 * @sync_freeze: nonzero means that on completion of the next
	 * client RPC we should freeze our timetrace and also the peer's.
	 * Then clear this back to zero again. Set externally via sysctl.
	 */
	int sync_freeze;

	/**
	 * @bpage_lease_usecs: how long a core can own a bpage (microseconds)
	 * before its ownership can be revoked to reclaim the page.
	 */
	int bpage_lease_usecs;

	/**
	 * @bpage_lease_cycles: The value of @bpage_lease_usecs in get_cycles
	 * units.
	 */
	int bpage_lease_cycles;

	/**
	 * @temp: the values in this array can be read and written with sysctl.
	 * They have no officially defined purpose, and are available for
	 * short-term use during testing.
	 */
	int temp[4];
};

/**
 * struct homa_metrics - various performance counters kept by Homa.
 *
 * There is one of these structures for each core, so counters can
 * be updated without worrying about synchronization or extra cache
 * misses. This isn't quite perfect (it's conceivable that a process
 * could move from one CPU to another in the middle of updating a counter),
 * but this is unlikely, and we can tolerate the occasional miscounts
 * that might result.
 *
 * All counters are free-running: they never reset.
 */
#define HOMA_NUM_SMALL_COUNTS 64
#define HOMA_NUM_MEDIUM_COUNTS 128
struct homa_metrics {
	/**
	 * @small_msg_bytes: entry i holds the total number of bytes
	 * received in messages whose length is between 64*i and 64*i + 63,
	 * inclusive.
	 */
	__u64 small_msg_bytes[HOMA_NUM_SMALL_COUNTS];

	/**
	 * @medium_msg_bytes: entry i holds the total number of bytes
	 * received in messages whose length is between 1024*i and
	 * 1024*i + 1023, inclusive. The first four entries are always 0
	 * (small_msg_counts covers this range).
	 */
	__u64 medium_msg_bytes[HOMA_NUM_MEDIUM_COUNTS];

	/**
	 * @large_msg_count: the total number of messages received whose
	 * length is too large to appear in medium_msg_bytes.
	 */
	__u64 large_msg_count;

	/**
	 * @large_msg_bytes: the total number of bytes received in
	 * messages too large to be counted by medium_msg_bytes.
	 */
	__u64 large_msg_bytes;

	/**
	 * @sent_msg_bytes: The total number of bytes in outbound
	 * messages.
	 */
	__u64 sent_msg_bytes;

	/**
	 * @packets_sent: total number of packets sent for each packet type
	 * (entry 0 corresponds to DATA, and so on).
	 */
	__u64 packets_sent[BOGUS-DATA];

	/**
	 * @packets_received: total number of packets received for each
	 * packet type (entry 0 corresponds to DATA, and so on).
	 */
	__u64 packets_received[BOGUS-DATA];

	/** @priority_bytes: total bytes sent at each priority level. */
	__u64 priority_bytes[HOMA_MAX_PRIORITIES];

	/** @priority_packets: total packets sent at each priority level. */
	__u64 priority_packets[HOMA_MAX_PRIORITIES];

	/**
	 * @requests_received: total number of request messages received.
	 */
	__u64 requests_received;

	/**
	 * @requests_queued: total number of requests that were added to
	 * @homa->ready_requests (no thread was waiting).
	 */
	__u64 requests_queued;

	/**
	 * @responses_received: total number of response messages received.
	 */
	__u64 responses_received;

	/**
	 * @responses_queued: total number of responses that were added to
	 * @homa->ready_responses (no thread was waiting).
	 */
	__u64 responses_queued;

	/**
	 * @fast_wakeups: total number of times that a message arrived for
	 * a receiving thread that was polling in homa_wait_for_message.
	 */
	__u64 fast_wakeups;

	/**
	 * @slow_wakeups: total number of times that a receiving thread
	 * had to be put to sleep (no message arrived while it was polling).
	 */
	__u64 slow_wakeups;

	/**
	 * @poll_cycles: total time spent in the polling loop in
	 * homa_wait_for_message, as measured with get_cycles().
	 */
	__u64 poll_cycles;

	/**
	 * @softirq_calls: total number of calls to homa_softirq (i.e.,
	 * total number of GRO packets processed, each of which could contain
	 * multiple Homa packets.
	 */
	__u64 softirq_calls;

	/**
	 * @softirq_cycles: total time spent executing homa_softirq when
	 * invoked under Linux's SoftIRQ handler, as measured with get_cycles().
	 */
	__u64 softirq_cycles;

	/**
	 * @bypass_softirq_cycles: total time spent executing homa_softirq when
	 * invoked during GRO, bypassing the SoftIRQ mechanism.
	 */
	__u64 bypass_softirq_cycles;

	/**
	 * @linux_softirq_cycles: total time spent executing all softirq
	 * activities, as measured by the linux softirq module, in get_cycles()
	 * units. Only available with modified Linux kernels.
	 */
	__u64 linux_softirq_cycles;

	/**
	 * @napi_cycles: total time spent executing all NAPI activities,
	 * as measured by the linux softirq module, in get_cycles() units.
	 * Only available with modified Linux kernels.
	 */
	__u64 napi_cycles;

	/**
	 * @send_cycles: total time spent executing the homa_ioc_send
	 * kernel call handler, as measured with get_cycles().
	 */
	__u64 send_cycles;

	/** @send_calls: total number of invocations of the send kernel call. */
	__u64 send_calls;

	/**
	 * @recv_cycles: total time spent executing homa_recvmsg (including
	 * time when the thread is blocked), as measured with get_cycles().
	 */
	__u64 recv_cycles;

	/** @recv_calls: total number of invocations of homa_recvmsg. */
	__u64 recv_calls;

	/**
	 * @blocked_cycles: total time threads spend in blocked state
	 * while executing the homa_recvmsg kernel call handler.
	 */
	__u64 blocked_cycles;

	/**
	 * @reply_cycles: total time spent executing the homa_ioc_reply
	 * kernel call handler, as measured with get_cycles().
	 */
	__u64 reply_cycles;

	/** @reply_calls: total number of invocations of the reply kernel call. */
	__u64 reply_calls;

	/**
	 * @abort_cycles: total time spent executing the homa_ioc_abort
	 * kernel call handler, as measured with get_cycles().
	 */
	__u64 abort_cycles;

	/**
	 * @abort_calls: total number of invocations of the homa_ioc_abort
	 * kernel call.
	 */
	__u64 abort_calls;

	/**
	 * @so_set_buf_cycles: total time spent executing the homa_ioc_set_buf
	 * kernel call handler, as measured with get_cycles().
	 */
	__u64 so_set_buf_cycles;

	/**
	 * @so_set_buf_calls: total number of invocations of the homa_ioc_set_buf
	 * kernel call.
	 */
	__u64 so_set_buf_calls;

	/**
	 * @grant_cycles: total time spent in homa_send_grants, as measured
	 * with get_cycles().
	 */
	__u64 grant_cycles;

	/**
	 * @timer_cycles: total time spent in homa_timer, as measured with
	 * get_cycles().
	 */
	__u64 timer_cycles;

	/**
	 * @timer_reap_cycles: total time spent by homa_timer to reap dead
	 * RPCs, as measured with get_cycles(). This time is included in
	 * @timer_cycles.
	 */
	__u64 timer_reap_cycles;

	/**
	 * @data_pkt_reap_cycles: total time spent by homa_data_pkt to reap
	 * dead RPCs, as measured with get_cycles().
	 */
	__u64 data_pkt_reap_cycles;

	/**
	 * @pacer_cycles: total time spent executing in homa_pacer_main
	 * (not including blocked time), as measured with get_cycles().
	 */
	__u64 pacer_cycles;

	/**
	 * @pacer_lost_cycles: unnecessary delays in transmitting packets
	 * (i.e. wasted output bandwidth) because the pacer was slow or got
	 * descheduled.
	 */
	__u64 pacer_lost_cycles;

	/**
	 * @pacer_bytes: total number of bytes transmitted when
	 * @homa->throttled_rpcs is nonempty.
	 */
	__u64 pacer_bytes;

	/**
	 * @pacer_skipped_rpcs: total number of times that the pacer had to
	 * abort because it couldn't lock an RPC.
	 */
	__u64 pacer_skipped_rpcs;

	/**
	 * @pacer_needed_help: total number of times that homa_check_pacer
	 * found that the pacer was running behind, so it actually invoked
	 * homa_pacer_xmit.
	 */
	__u64 pacer_needed_help;

	/**
	 * @throttled_cycles: total amount of time that @homa->throttled_rpcs
	 * is nonempty, as measured with get_cycles().
	 */
	__u64 throttled_cycles;

	/**
	 * @resent_packets: total number of data packets issued in response to
	 * RESEND packets.
	 */
	__u64 resent_packets;

	/**
	 * @peer_hash_links: total # of link traversals in homa_peer_find.
	 */
	__u64 peer_hash_links;

	/**
	 * @peer_new_entries: total # of new entries created in Homa's
	 * peer table (this value doesn't increment if the desired peer is
	 * found in the entry in its hash chain).
	 */
	__u64 peer_new_entries;

	/**
	 * @peer_kmalloc errors: total number of times homa_peer_find
	 * returned an error because it couldn't allocate memory for a new
	 * peer.
	 */
	__u64 peer_kmalloc_errors;

	/**
	 * @peer_route errors: total number of times homa_peer_find
	 * returned an error because it couldn't create a route to the peer.
	 */
	__u64 peer_route_errors;

	/**
	 * @control_xmit_errors errors: total number of times ip_queue_xmit
	 * failed when transmitting a control packet.
	 */
	__u64 control_xmit_errors;

	/**
	 * @data_xmit_errors errors: total number of times ip_queue_xmit
	 * failed when transmitting a data packet.
	 */
	__u64 data_xmit_errors;

	/**
	 * @unknown_rpc: total number of times an incoming packet was
	 * discarded because it referred to a nonexistent RPC. Doesn't
	 * count grant packets received by servers (since these are
	 * fairly common).
	 */
	__u64 unknown_rpcs;

	/**
	 * @cant_create_server_rpc: total number of times a server discarded
	 * an incoming packet because it couldn't create a homa_rpc object.
	 */
	__u64 server_cant_create_rpcs;

	/**
	 * @unknown_packet_type: total number of times a packet was discarded
	 * because its type wasn't one of the supported values.
	 */
	__u64 unknown_packet_types;

	/**
	 * @short_packets: total number of times a packet was discarded
	 * because it was too short to hold all the required information.
	 */
	__u64 short_packets;

	/**
	 * @redundant_packets: total number of times a packet was discarded
	 * because all of its they had already been received (perhaps a
	 * resent packet that turned out to be unnecessary?).
	 */
	__u64 redundant_packets;

	/**
	 * @resent_packets_used: total number of times a resent packet was
	 * actually incorporated into the message at the target (i.e. it
	 * wasn't redundant).
	 */
	__u64 resent_packets_used;

	/**
	 * @peer_timeouts: total number of times a peer (either client or
	 * server) was found to be nonresponsive, resulting in RPC aborts.
	 */
	__u64 peer_timeouts;

	/**
	 * @server_rpc_discards: total number of times an RPC was aborted on
	 * the server side because of a timeout.
	 */
	__u64 server_rpc_discards;

	/**
	 * @server_rpcs_unknown: total number of times an RPC was aborted on
	 * the server side because it is no longer known to the client.
	 */
	__u64 server_rpcs_unknown;

	/**
	 * @client_lock_misses: total number of times that Homa had to wait
	 * to acquire a client bucket lock.
	 */
	__u64 client_lock_misses;

	/**
	 * @client_lock_miss_cycles: total time spent waiting for client
	 * bucket lock misses, measured by get_cycles().
	 */
	__u64 client_lock_miss_cycles;

	/**
	 * @server_lock_misses: total number of times that Homa had to wait
	 * to acquire a server bucket lock.
	 */
	__u64 server_lock_misses;

	/**
	 * @server_lock_miss_cycles: total time spent waiting for server
	 * bucket lock misses, measured by get_cycles().
	 */
	__u64 server_lock_miss_cycles;

	/**
	 * @socket_lock_miss_cycles: total time spent waiting for socket
	 * lock misses, measured by get_cycles().
	 */
	__u64 socket_lock_miss_cycles;

	/**
	 * @socket_lock_misses: total number of times that Homa had to wait
	 * to acquire a socket lock.
	 */
	__u64 socket_lock_misses;

	/**
	 * @throttle_lock_miss_cycles: total time spent waiting for throttle
	 * lock misses, measured by get_cycles().
	 */
	__u64 throttle_lock_miss_cycles;

	/**
	 * @throttle_lock_misses: total number of times that Homa had to wait
	 * to acquire the throttle lock.
	 */
	__u64 throttle_lock_misses;

	/**
	 * @grantable_lock_miss_cycles: total time spent waiting for grantable
	 * lock misses, measured by get_cycles().
	 */
	__u64 grantable_lock_miss_cycles;

	/**
	 * @grantable_lock_misses: total number of times that Homa had to wait
	 * to acquire the grantable lock.
	 */
	__u64 grantable_lock_misses;

	/**
	 * @peer_acklock_miss_cycles: total time spent waiting for peer
	 * lock misses, measured by get_cycles().
	 */
	__u64 peer_ack_lock_miss_cycles;

	/**
	 * @peer_ack_lock_misses: total number of times that Homa had to wait
	 * to acquire the lock used for managing acks for a peer.
	 */
	__u64 peer_ack_lock_misses;

	/**
	 * @disabled_reaps: total number of times that the reaper couldn't
	 * run at all because it was disabled.
	 */
	__u64 disabled_reaps;

	/**
	 * @disabled_rpc_reaps: total number of times that the reaper skipped
	 * an RPC because reaping was disabled for that particular RPC
	 */
	__u64 disabled_rpc_reaps;

	/**
	 * @reaper_runs: total number of times that the reaper was invoked
	 * and was not disabled.
	 */
	__u64 reaper_calls;

	/**
	 * @reaper_dead_skbs: incremented by hsk->dead_skbs each time that
	 * reaper_calls is incremented.
	 */
	__u64 reaper_dead_skbs;

	/**
	 * @forced_reaps: total number of times that homa_wait_for_message
	 * invoked the reaper because dead_skbs was too high.
	 */
	__u64 forced_reaps;

	/**
	 * @throttle_list_adds: total number of calls to homa_add_to_throttled.
	 */
	__u64 throttle_list_adds;

	/**
	 * @throttle_list_checks: number of list elements examined in
	 * calls to homa_add_to_throttled.
	 */
	__u64 throttle_list_checks;

	/**
	 * @fifo_grants: total number of times that grants were sent to
	 * the oldest message.
	 */
	__u64 fifo_grants;

	/**
	 * @fifo_grants_no_incoming: total number of times that, when a
	 * FIFO grant was issued, the message had no outstanding grants
	 * (everything granted had been received).
	 */
	__u64 fifo_grants_no_incoming;

	/**
	 * @unacked_overflows: total number of times that homa_peer_add_ack
	 * found insufficient space for the new id and hence had to send an
	 * ACK message.
	 */
	__u64 ack_overflows;

	/**
	 * @ignored_need_acks: total number of times that a NEED_ACK packet
	 * was ignored because the RPC's result hadn't been fully received.
	 */
	__u64 ignored_need_acks;

	/**
	 * @bpage_resuses: total number of times that, when an owned page
	 * reached the end, it could be reused because all existing
	 * allocations had been released.
	 */
	__u64 bpage_reuses;

	/** @temp: For temporary use during testing. */
#define NUM_TEMP_METRICS 10
	__u64 temp[NUM_TEMP_METRICS];
};

/**
 * struct homa_core - Homa allocates one of these structures for each
 * core, to hold information that needs to be kept on a per-core basis.
 */
struct homa_core {

	/**
	 * @last_active: the last time (in get_cycle() units) that
	 * there was system activity, such NAPI or SoftIRQ, on this
	 * core. Used to pick a less-busy core for assigning SoftIRQ
	 * handlers.
	 */
	__u64 last_active;

	/**
	 * @last_gro: the last time (in get_cycle() units) that Homa
	 * processed packets at GRO(NAPI) level on this core. Used to
	 * avoid assigning SoftIRQ handlers to this core when it has
	 * been used recently for GRO.
	 */
	__u64 last_gro;

	/**
	 * @softirq_backlog: the number of batches of packets that have
	 * been queued for SoftIRQ processing on this core but haven't
	 * yet been processed.
	 */
	atomic_t softirq_backlog;

	/**
	 * @softirq_offset: used when rotating SoftIRQ assignment among
	 * the next cores; contains an offset to add to the current core
	 * to produce the core for SoftIRQ.
	 */
	int softirq_offset;

        /**
         * held_skb: last packet buffer known to be available for
         * merging other packets into on this core (note: may not still
         * be available), or NULL if none.
         */
        struct sk_buff *held_skb;

	/**
	 * @held_bucket: the index, within napi->gro_hash, of the list
         * containing @held_skb; undefined if @held_skb is NULL. Used to
         * verify that @held_skb is still available.
	 */
	int held_bucket;

	/**
	 * @thread: the most recent thread to invoke a Homa system call
	 * on this core, or NULL if none.
	 */
	struct task_struct *thread;

	/**
	 * @syscall_end_time: the time, in get_cycle() units, when the last
	 * Homa system call completed on this core. Meaningless if thread
	 * is NULL.
	 */
	__u64 syscall_end_time;

	/** @metrics: performance statistics for this core. */
	struct homa_metrics metrics;
};

/**
 * homa_is_client(): returns true if we are the client for a particular RPC,
 * false if we are the server.
 * @id:  Id of the RPC in question.
 */
static inline bool homa_is_client(__u64 id)
{
	return (id & 1) == 0;
}

/**
 * homa_local_id(): given an RPC identifier from an input packet (which
 * is network-encoded), return the decoded id we should use for that
 * RPC on this machine.
 * @sender_id:  RPC id from an incoming packet, such as h->common.sender_id
 */
static inline __u64 homa_local_id(__be64 sender_id)
{
	/* If the client bit was set on the sender side, it needs to be
	 * removed here, and conversely.
	 */
	return be64_to_cpu(sender_id) ^ 1;
}

#define homa_bucket_lock(bucket, type)                      \
	if (unlikely(!spin_trylock_bh(&bucket->lock))) {    \
		__u64 start = get_cycles();                 \
		INC_METRIC(type##_lock_misses, 1);        \
		spin_lock_bh(&bucket->lock);                \
		INC_METRIC(type##_lock_miss_cycles, get_cycles() - start); \
	}

/**
 * homa_client_rpc_bucket() - Find the bucket containing a given
 * client RPC.
 * @hsk:      Socket associated with the RPC.
 * @id:       Id of the desired RPC.
 *
 * Return:    The bucket in which this RPC will appear, if the RPC exists.
 */
static inline struct homa_rpc_bucket *homa_client_rpc_bucket(
		struct homa_sock *hsk, __u64 id)
{
	/* We can use a really simple hash function here because RPC ids
	 * are allocated sequentially.
	 */
	return &hsk->client_rpc_buckets[(id >> 1)
			& (HOMA_CLIENT_RPC_BUCKETS - 1)];
}

/**
 * homa_next_skb() - Compute address of Homa's private link field in @skb.
 * @skb:     Socket buffer containing private link field.
 *
 * Homa needs to keep a list of buffers in a message, but it can't use the
 * links built into sk_buffs because Homa wants to retain its list even
 * after sending the packet, and the built-in links get used during sending.
 * Thus we allocate extra space at the very end of the packet's data
 * area to hold a forward pointer for a list.
 */
static inline struct sk_buff **homa_next_skb(struct sk_buff *skb)
{
	return (struct sk_buff **) (skb_end_pointer(skb) - sizeof(char*));
}

/**
 * port_hash() - Hash function for port numbers.
 * @port:   Port number being looked up.
 *
 * Return:  The index of the bucket in which this port will be found (if
 *          it exists.
 */
static inline int homa_port_hash(__u16 port)
{
	/* We can use a really simple hash function here because client
	 * port numbers are allocated sequentially and server port numbers
	 * are unpredictable.
	 */
	return port & (HOMA_SOCKTAB_BUCKETS - 1);
}

/**
 * homa_server_rpc_bucket() - Find the bucket containing a given
 * server RPC.
 * @hsk:         Socket associated with the RPC.
 * @id:          Id of the desired RPC.
 *
 * Return:    The bucket in which this RPC will appear, if the RPC exists.
 */
static inline struct homa_rpc_bucket *homa_server_rpc_bucket(
		struct homa_sock *hsk, __u64 id)
{
	/* Each client allocates RPC ids sequentially, so they will
	 * naturally distribute themselves across the hash space.
	 * Thus we can use the id directly as hash.
	 */
	return &hsk->server_rpc_buckets[(id >> 1)
			& (HOMA_SERVER_RPC_BUCKETS - 1)];
}

/**
 * homa_set_doff() - Fills in the doff TCP header field for a Homa packet.
 * @h:   Packet header whose doff field is to be set.
 */
static inline void homa_set_doff(struct data_header *h)
{
	h->common.doff = (sizeof(struct data_header)
			- sizeof(struct data_segment)) << 2;
}

static inline struct homa_sock *homa_sk(const struct sock *sk)
{
	return (struct homa_sock *)sk;
}

/**
 * homa_sock_lock() - Acquire the lock for a socket. If the socket
 * isn't immediately available, record stats on the waiting time.
 * @hsk:     Socket to lock.
 * @locker:  Static string identifying where the socket was locked;
 *           used to track down deadlocks.
 */
static inline void homa_sock_lock(struct homa_sock *hsk, char *locker) {
	if (!spin_trylock_bh(&hsk->lock)) {
//		printk(KERN_NOTICE "Slow path for socket %d, last locker %s",
//				hsk->client_port, hsk->last_locker);
		homa_sock_lock_slow(hsk);
	}
//	hsk->last_locker = locker;
}

/**
 * homa_sock_unlock() - Release the lock for a socket.
 * @hsk:   Socket to lock.
 */
static inline void homa_sock_unlock(struct homa_sock *hsk) {
	spin_unlock_bh(&hsk->lock);
}

/**
 * homa_peer_lock() - Acquire the lock for a peer's @unacked_lock. If the lock
 * isn't immediately available, record stats on the waiting time.
 * @peer:    Peer to lock.
 */
static inline void homa_peer_lock(struct homa_peer *peer)
{
	if (!spin_trylock_bh(&peer->ack_lock)) {
		homa_peer_lock_slow(peer);
	}
}

/**
 * homa_peer_unlock() - Release the lock for a peer's @unacked_lock.
 * @peer:   Peer to lock.
 */
static inline void homa_peer_unlock(struct homa_peer *peer)
{
	spin_unlock_bh(&peer->ack_lock);
}

/**
 * homa_protect_rpcs() - Ensures that no RPCs will be reaped for a given
 * socket until until homa_sock_unprotect is called. Typically
 * used by functions that want to scan the active RPCs for a socket
 * without holding the socket lock.  Multiple calls to this function may
 * be in effect at once.
 * @hsk:    Socket whose RPCs should be protected. Must not be locked
 *          by the caller; will be locked here.
 *
 * Return:  1 for success, 0 if the socket has been shutdown, in which
 *          case its RPCs cannot be protected.
 */
static inline int homa_protect_rpcs(struct homa_sock *hsk)
{
	int result;
	homa_sock_lock(hsk, "homa_sock_protect");
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
 * homa_grantable_lock() - Acquire the grantable lock. If the lock
 * isn't immediately available, record stats on the waiting time.
 * @homa:    Overall data about the Homa protocol implementation.
 */
static inline void homa_grantable_lock(struct homa *homa)
{
	if (!spin_trylock_bh(&homa->grantable_lock)) {
		homa_grantable_lock_slow(homa);
	}
}

/**
 * homa_grantable_unlock() - Release the grantable lock.
 * @homa:    Overall data about the Homa protocol implementation.
 */
static inline void homa_grantable_unlock(struct homa *homa)
{
	spin_unlock_bh(&homa->grantable_lock);
}

/**
 * homa_throttle_lock() - Acquire the throttle lock. If the lock
 * isn't immediately available, record stats on the waiting time.
 * @homa:    Overall data about the Homa protocol implementation.
 */
static inline void homa_throttle_lock(struct homa *homa)
{
	if (!spin_trylock_bh(&homa->throttle_lock)) {
		homa_throttle_lock_slow(homa);
	}
}

/**
 * homa_throttle_unlock() - Release the throttle lock.
 * @homa:    Overall data about the Homa protocol implementation.
 */
static inline void homa_throttle_unlock(struct homa *homa)
{
	spin_unlock_bh(&homa->throttle_lock);
}

/** skb_is_ipv6() - Return true if the packet is encapsulated with IPv6,
 *  false otherwise (presumably it's IPv4).
 */
static inline bool skb_is_ipv6(const struct sk_buff *skb)
{
	return ipv6_hdr(skb)->version == 6;
}

/**
 * Given an IPv4 address, return an equivalent IPv6 address (an IPv4-mapped
 * one)
 * @ip4: IPv4 address, in network byte order.
 */
static inline struct in6_addr ipv4_to_ipv6(__be32 ip4)
{
	struct in6_addr ret = {};
	if (ip4 == INADDR_ANY) return in6addr_any;
	ret.in6_u.u6_addr32[2] = htonl(0xffff);
	ret.in6_u.u6_addr32[3] = ip4;
	return ret;
}

/**
 * ipv6_to_ipv4() - Given an IPv6 address produced by ipv4_to_ipv6, return
 * the original IPv4 address (in network byte order).
 * @ip6:  IPv6 address; assumed to be a mapped IPv4 address.
 */
static inline __be32 ipv6_to_ipv4(const struct in6_addr ip6)
{
	return ip6.in6_u.u6_addr32[3];
}

/**
 * skb_canonical_ipv6_addr() - Convert a socket address to the "standard"
 * form used in Homa, which is always an IPv6 address; if the original address
 * was IPv4, convert it to an IPv4-mapped IPv6 address.
 * @addr:   Address to canonicalize.
 */
static inline struct in6_addr canonical_ipv6_addr(const sockaddr_in_union *addr)
{
	if (addr) {
		return (addr->sa.sa_family == AF_INET6)
			? addr->in6.sin6_addr
			: ipv4_to_ipv6(addr->in4.sin_addr.s_addr);
	} else {
		return in6addr_any;
	}
}

/**
 * skb_canonical_ipv6_saddr() - Given a packet buffer, return its source
 * address in the "standard" form used in Homa, which is always an IPv6
 * address; if the original address was IPv4, convert it to an IPv4-mapped
 * IPv6 address.
 * @skb:   The source address will be extracted from this packet buffer.
 */
static inline struct in6_addr skb_canonical_ipv6_saddr(struct sk_buff *skb)
{
	return skb_is_ipv6(skb) ? ipv6_hdr(skb)->saddr : ipv4_to_ipv6(
			ip_hdr(skb)->saddr);
}

/**
 * is_mapped_ipv4() - Return true if an IPv6 address is actually an
 * IPv4-mapped address, false otherwise.
 * @x:  The address to check.
 */
static inline bool is_mapped_ipv4(const struct in6_addr x)
{
	return ((x.in6_u.u6_addr32[0] == 0) &&
		(x.in6_u.u6_addr32[1] == 0) &&
		(x.in6_u.u6_addr32[2] == htonl(0xffff)));
}

/**
 * tt_addr() - Given an address, return a 4-byte id that will (hopefully)
 * provide a unique identifier for the address in a timetrace record.
 * @x:  Address (either IPv6 or IPv4-mapped IPv6)
 */
static inline __be32 tt_addr(const struct in6_addr x)
{
	return is_mapped_ipv4(x) ? ntohl(x.in6_u.u6_addr32[3])
			: (x.in6_u.u6_addr32[3] ? ntohl(x.in6_u.u6_addr32[3])
			: ntohl(x.in6_u.u6_addr32[1]));
}

#define INC_METRIC(metric, count) \
		(homa_cores[raw_smp_processor_id()]->metrics.metric) += (count)

extern struct homa_core *homa_cores[];

#ifdef __UNIT_TEST__
extern void unit_log_printf(const char *separator, const char* format, ...)
		__attribute__((format(printf, 2, 3)));
#define UNIT_LOG unit_log_printf
extern void unit_hook(char *id);
#define UNIT_HOOK(msg) unit_hook(msg)
#else
#define UNIT_LOG(...)
#define UNIT_HOOK(msg)
#endif

extern void     homa_abort_rpcs(struct homa *homa, const struct in6_addr *addr,
		    int port, int error);
extern void     homa_abort_sock_rpcs(struct homa_sock *hsk, int error);
extern void     homa_ack_pkt(struct sk_buff *skb, struct homa_sock *hsk,
		    struct homa_rpc *rpc, struct homa_lcache *lcache);
extern void     homa_add_packet(struct homa_rpc *rpc, struct sk_buff *skb);
extern void     homa_add_to_throttled(struct homa_rpc *rpc);
extern void     homa_append_metric(struct homa *homa, const char* format, ...);
extern int      homa_backlog_rcv(struct sock *sk, struct sk_buff *skb);
extern int      homa_bind(struct socket *sk, struct sockaddr *addr,
                    int addr_len);
extern void     homa_check_grantable(struct homa *homa, struct homa_rpc *rpc);
extern int      homa_check_rpc(struct homa_rpc *rpc);
extern int      homa_check_nic_queue(struct homa *homa, struct sk_buff *skb,
                    bool force);
extern void     homa_close(struct sock *sock, long timeout);
extern int      homa_copy_to_user(struct homa_rpc *rpc);
extern void     homa_cutoffs_pkt(struct sk_buff *skb, struct homa_sock *hsk);
extern void     homa_data_from_server(struct sk_buff *skb,
                    struct homa_rpc *crpc);
extern void     homa_data_pkt(struct sk_buff *skb, struct homa_rpc *rpc,
		    struct homa_lcache *lcache, int *delta);
extern void     homa_destroy(struct homa *homa);
extern int      homa_diag_destroy(struct sock *sk, int err);
extern int      homa_disconnect(struct sock *sk, int flags);
extern int      homa_dointvec(struct ctl_table *table, int write,
                    void __user *buffer, size_t *lenp, loff_t *ppos);
extern void     homa_dst_refresh(struct homa_peertab *peertab,
                    struct homa_peer *peer, struct homa_sock *hsk);
extern int      homa_err_handler_v4(struct sk_buff *skb, u32 info);
extern int      homa_err_handler_v6(struct sk_buff *skb, struct inet6_skb_parm *
                    , u8,  u8,  int,  __be32);
extern struct homa_rpc
               *homa_find_client_rpc(struct homa_sock *hsk, __u64 id);
extern struct homa_rpc
               *homa_find_server_rpc(struct homa_sock *hsk,
		const struct in6_addr *saddr, __u16 sport, __u64 id);
extern void     homa_free_skbs(struct sk_buff *skb);
extern void     homa_freeze(struct homa_rpc *rpc, enum homa_freeze_type type,
		    char *format);
extern int      homa_get_port(struct sock *sk, unsigned short snum);
extern void     homa_get_resend_range(struct homa_message_in *msgin,
                    struct resend_header *resend);
extern int      homa_getsockopt(struct sock *sk, int level, int optname,
                    char __user *optval, int __user *option);
extern int      homa_grant_fifo(struct homa *homa);
extern void     homa_grant_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
extern int      homa_gro_complete(struct sk_buff *skb, int thoff);
extern struct sk_buff
               *homa_gro_receive(struct list_head *gro_list,
                    struct sk_buff *skb);
extern struct sk_buff
               *homa_gso_segment(struct sk_buff *skb,
		    netdev_features_t features);
extern int      homa_hash(struct sock *sk);
extern enum hrtimer_restart
                homa_hrtimer(struct hrtimer *timer);
extern int      homa_init(struct homa *homa);
extern void     homa_incoming_sysctl_changed(struct homa *homa);
extern int      homa_ioc_abort(struct sock *sk, unsigned long arg);
extern int      homa_ioctl(struct sock *sk, int cmd, unsigned long arg);
extern void     homa_log_grantable_list(struct homa *homa);
extern void     homa_log_throttled(struct homa *homa);
extern void     homa_message_in_init(struct homa_message_in *msgin, int length,
		    int incoming);
extern int      homa_message_out_init(struct homa_rpc *rpc,
		    struct iov_iter *iter, int xmit);
extern loff_t   homa_metrics_lseek(struct file *file, loff_t offset,
		    int whence);
extern int      homa_metrics_open(struct inode *inode, struct file *file);
extern ssize_t  homa_metrics_read(struct file *file, char __user *buffer,
                    size_t length, loff_t *offset);
extern int      homa_metrics_release(struct inode *inode, struct file *file);
extern void     homa_need_ack_pkt(struct sk_buff *skb, struct homa_sock *hsk,
		    struct homa_rpc *rpc);
extern int      homa_offload_end(void);
extern int      homa_offload_init(void);
extern void     homa_outgoing_sysctl_changed(struct homa *homa);
extern int      homa_pacer_main(void *transportInfo);
extern void     homa_pacer_stop(struct homa *homa);
extern void     homa_pacer_xmit(struct homa *homa);
extern void     homa_peertab_destroy(struct homa_peertab *peertab);
extern int      homa_peertab_init(struct homa_peertab *peertab);
extern void     homa_peer_add_ack(struct homa_rpc *rpc);
extern struct homa_peer
               *homa_peer_find(struct homa_peertab *peertab,
			const struct in6_addr *addr, struct inet_sock *inet);
extern int      homa_peer_get_acks(struct homa_peer *peer, int count,
		    struct homa_ack *dst);
extern struct dst_entry
               *homa_peer_get_dst(struct homa_peer *peer,
			struct inet_sock *inet);
extern void     homa_peer_set_cutoffs(struct homa_peer *peer, int c0, int c1,
                    int c2, int c3, int c4, int c5, int c6, int c7);
extern void     homa_peertab_gc_dsts(struct homa_peertab *peertab, __u64 now);
extern void     homa_pkt_dispatch(struct sk_buff *skb, struct homa_sock *hsk,
		    struct homa_lcache *lcache, int *delta);
extern __poll_t homa_poll(struct file *file, struct socket *sock,
                    struct poll_table_struct *wait);
extern int      homa_pool_allocate(struct homa_rpc *rpc);
extern void     homa_pool_destroy(struct homa_pool *pool);
extern void    *homa_pool_get_buffer(struct homa_rpc *rpc, int offset,
		    int *available);
extern int      homa_pool_get_pages(struct homa_pool *pool, int num_pages,
		    __u32 *pages, int leave_locked);
extern int      homa_pool_init(struct homa_pool *pool, struct homa *homa,
		    void *buf_region, __u64 region_size);
extern void     homa_pool_release_buffers(struct homa_pool *pool,
		    int num_buffers, __u32 *buffers);
extern char    *homa_print_ipv4_addr(__be32 addr);
extern char    *homa_print_ipv6_addr(const struct in6_addr *addr);
extern char    *homa_print_metrics(struct homa *homa);
extern char    *homa_print_packet(struct sk_buff *skb, char *buffer, int buf_len);
extern char    *homa_print_packet_short(struct sk_buff *skb, char *buffer,
                    int buf_len);
extern void     homa_prios_changed(struct homa *homa);
extern int      homa_proc_read_metrics(char *buffer, char **start, off_t offset,
                    int count, int *eof, void *data);
extern int      homa_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
                    int noblock, int flags, int *addr_len);
extern int      homa_register_interests(struct homa_interest *interest,
                    struct homa_sock *hsk, int flags, __u64 id);
extern void     homa_rehash(struct sock *sk);
extern void     homa_remove_grantable_locked(struct homa *homa,
                    struct homa_rpc *rpc);
extern void     homa_remove_from_grantable(struct homa *homa,
                    struct homa_rpc *rpc);
extern void     homa_remove_from_throttled(struct homa_rpc *rpc);
extern void     homa_resend_data(struct homa_rpc *rpc, int start, int end,
                    int priority);
extern void     homa_resend_pkt(struct sk_buff *skb, struct homa_rpc *rpc,
                    struct homa_sock *hsk);
extern void     homa_rpc_abort(struct homa_rpc *crpc, int error);
extern void     homa_rpc_acked(struct homa_sock *hsk,
			const struct in6_addr *saddr, struct homa_ack *ack);
extern void     homa_rpc_free(struct homa_rpc *rpc);
extern void     homa_rpc_free_rcu(struct rcu_head *rcu_head);
extern void     homa_rpc_handoff(struct homa_rpc *rpc);
extern void     homa_rpc_log(struct homa_rpc *rpc);
extern void     homa_rpc_log_active(struct homa *homa, uint64_t id);
extern struct homa_rpc
               *homa_rpc_new_client(struct homa_sock *hsk,
                    const sockaddr_in_union *dest);
extern struct homa_rpc
               *homa_rpc_new_server(struct homa_sock *hsk,
			const struct in6_addr *source, struct data_header *h);
extern int      homa_rpc_reap(struct homa_sock *hsk, int count);
extern void     homa_send_grants(struct homa *homa);
extern int      homa_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
extern int      homa_sendpage(struct sock *sk, struct page *page, int offset,
                    size_t size, int flags);
extern int      homa_setsockopt(struct sock *sk, int level, int optname,
                    sockptr_t __user optval, unsigned int optlen);
extern int      homa_shutdown(struct socket *sock, int how);
extern int      homa_snprintf(char *buffer, int size, int used,
                    const char* format, ...)
                    __attribute__((format(printf, 4, 5)));
extern int      homa_sock_bind(struct homa_socktab *socktab,
                    struct homa_sock *hsk, __u16 port);
extern void     homa_sock_destroy(struct homa_sock *hsk);
extern struct homa_sock *
                    homa_sock_find(struct homa_socktab *socktab, __u16 port);
extern void     homa_sock_init(struct homa_sock *hsk, struct homa *homa);
extern void     homa_sock_shutdown(struct homa_sock *hsk);
extern int      homa_socket(struct sock *sk);
extern void     homa_socktab_destroy(struct homa_socktab *socktab);
extern void     homa_socktab_init(struct homa_socktab *socktab);
extern struct homa_sock
               *homa_socktab_next(struct homa_socktab_scan *scan);
extern struct homa_sock
               *homa_socktab_start_scan(struct homa_socktab *socktab,
                    struct homa_socktab_scan *scan);
extern int      homa_softirq(struct sk_buff *skb);
extern void     homa_spin(int usecs);
extern char    *homa_symbol_for_state(struct homa_rpc *rpc);
extern char    *homa_symbol_for_type(uint8_t type);
extern void     homa_timer(struct homa *homa);
extern int      homa_timer_main(void *transportInfo);
extern void     homa_unhash(struct sock *sk);
extern void     homa_unknown_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
extern int      homa_unsched_priority(struct homa *homa,
                    struct homa_peer *peer, int length);
extern int      homa_v4_early_demux(struct sk_buff *skb);
extern int      homa_v4_early_demux_handler(struct sk_buff *skb);
extern struct homa_rpc
               *homa_wait_for_message(struct homa_sock *hsk, int flags,
                    __u64 id);
extern int      homa_xmit_control(enum homa_packet_type type, void *contents,
                    size_t length, struct homa_rpc *rpc);
extern int      __homa_xmit_control(void *contents, size_t length,
                    struct homa_peer *peer, struct homa_sock *hsk);
extern void     homa_xmit_data(struct homa_rpc *rpc, bool force);
extern void     __homa_xmit_data(struct sk_buff *skb, struct homa_rpc *rpc,
                    int priority);
extern void     homa_xmit_unknown(struct sk_buff *skb, struct homa_sock *hsk);

/**
 * homa_check_pacer() - This method is invoked at various places in Homa to
 * see if the pacer needs to transmit more packets and, if so, transmit
 * them. It's needed because the pacer thread may get descheduled by
 * Linux, result in output stalls.
 * @homa:    Overall data about the Homa protocol implementation. No locks
 *           should be held when this function is invoked.
 * @softirq: Nonzero means this code is running at softirq (bh) level;
 *           zero means it's running in process context.
 */
static inline void homa_check_pacer(struct homa *homa, int softirq)
{
	if (list_empty(&homa->throttled_rpcs))
		return;

	/* The "/2" in the line below gives homa_pacer_main the first chance
	 * to queue new packets; if the NIC queue becomes more than half
	 * empty, then we will help out here.
	 */
	if ((get_cycles() + homa->max_nic_queue_cycles/2) <
			atomic64_read(&homa->link_idle_time))
		return;
	tt_record("homa_check_pacer calling homa_pacer_xmit");
	homa_pacer_xmit(homa);
	INC_METRIC(pacer_needed_help, 1);
}

/**
 * homa_get_dst() - Returns destination information associated with a peer,
 * updating it if the cached information is stale.
 * @peer:   Peer whose destination information is desired.
 * @hsk:    Homa socket; needed by lower-level code to recreate the dst.
 * Return   Up-to-date destination for peer.
 */
static inline struct dst_entry *homa_get_dst(struct homa_peer *peer,
	struct homa_sock *hsk)
{
	if (unlikely(peer->dst->obsolete > 0))
		homa_dst_refresh(&hsk->homa->peers, peer, hsk);
	return peer->dst;
}

extern struct completion homa_pacer_kthread_done;
#endif /* _HOMA_IMPL_H */
