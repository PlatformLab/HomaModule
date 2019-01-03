/* This file contains definitions that are shared across the files
 * that implement Homa for Linux.
 */

#ifndef _HOMA_IMPL_H
#define _HOMA_IMPL_H

#include <linux/audit.h>
#include <linux/icmp.h>
#include <linux/if_vlan.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched/signal.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/socket.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/inet_common.h>

#include "homa.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,16,0)
typedef unsigned int __poll_t;
#endif

#ifdef __UNIT_TEST__
#define spin_unlock mock_spin_unlock
extern void mock_spin_unlock(spinlock_t *lock);
#endif

extern struct homa *homa;

/* Forward declarations. */
struct homa_sock;

/**
 * enum homa_packet_type - Defines the possible types of Homa packets.
 * 
 * See the xxx_header structs below for more information about each type.
 */
enum homa_packet_type {
	DATA               = 20,
	GRANT              = 21,
	RESEND             = 22,
	RESTART            = 23,
	BUSY               = 24,
	CUTOFFS            = 25,
	BOGUS              = 26,      /* Used only in unit tests. */
	/* If you add a new type here, you must also do the following:
	 * 1. Change BOGUS so it is the highest opcode
	 * 2. Add support for the new opcode in homa_print_packet,
	 *    homa_print_packet_short, homa_symbol_for_type, and mock_skb_new.
	 * 3. Add support in new_buff in unit/unit_utils.cc
	 */
};

/**
 * define HOMA_MAX_MESSAGE_SIZE - Largest permissible message size, in bytes.
 */
#define HOMA_MAX_MESSAGE_SIZE 1000000

/**
 * define HOMA_MAX_DATA_PER_PACKET - The maximum amount of message data
 * that a single packet can hold (not including Homa's header, IP header,
 * etc.). This assumes Ethernet packet frames.
 */
#define HOMA_MAX_DATA_PER_PACKET 1400

/** define HOMA_MAX_IPV4_HEADER - Size of largest IP header (V4). */
#define HOMA_MAX_IPV4_HEADER 60

/**
 * define HOMA_MAX_HEADER - Largest allowable Homa header.  All Homa packets
 * must be at least this long.
 */
#define HOMA_MAX_HEADER 48

/**
 * define ETHERNET_MAX_PAYLOAD - A maximum length of an Ethernet packet,
 * excluding preamble, frame delimeter, VLAN header, CRC, and interpacket gap;
 * i.e. all of this space is available for Homa.
 */
#define ETHERNET_MAX_PAYLOAD 1500

/**
 * define HOMA_NUM_PRIORITIES - The total number of priority levels available
 * for Homa (the actual number can be restricted to less than this at runtime).
 * Changing this value is a big deal: it will affect packet formats.
 */
#define HOMA_NUM_PRIORITIES 8

/**
 * define HOMA_SKB_RESERVE - How much space to reserve at the beginning
 * of sk_buffs for headers other than Homa's (IPV4, and Ethernet VLAN).
 */
#define HOMA_SKB_RESERVE (HOMA_MAX_IPV4_HEADER + 20)

/**
 * define HOMA_SKB_SIZE - Total allocated size for Homa packet buffers
 * (we always allocate this size, even for small packets). The
 * "sizeof(void*)" is for the pointer used by homa_next_skb.
 */
#define HOMA_SKB_SIZE (HOMA_MAX_DATA_PER_PACKET + HOMA_MAX_HEADER \
				+ HOMA_SKB_RESERVE + sizeof(void*))

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
	return (struct sk_buff **) (skb->head + HOMA_MAX_DATA_PER_PACKET
			+ HOMA_MAX_HEADER + HOMA_SKB_RESERVE);
}

/**
 * struct common_header - Wire format for the first bytes in every Homa
 * packet.
 */
struct common_header {
	/** @sport: Port on source machine from which packet was sent. */
	__be16 sport;
	
	/** @dport: Port on destination that is to receive packet. */
	__be16 dport;
	
	/**
	 * @id: Identifier for the RPC associated with this packet; must
	 * be unique among all those issued from the client port.
	 */
	__be64 id;

	/** @type: One of the values of &enum packet_type. */
	__u8 type;
} __attribute__((packed));

/**
 * struct data_header - Wire format for a DATA packet, which contains a
 * contiguous range of bytes from a request or response message. The
 * amount of data in the packet is either all the remaining data in
 * the message or HOMA_MAX_DATA_PER_PACKET, whichever is smaller.
 */
struct data_header {
	/** @common: Fields common to all packet types. */
	struct common_header common;
	
	/** @message_length: Total #bytes in the *message* */
	__be32 message_length;
	
	/**
	 * @offset: Offset within message of the first byte of data in
	 * this packet
	 */
	__be32 offset;
	
	/**
	 * @unscheduled: The number of initial bytes in the message that
	 * the sender will transmit without grants; bytes after these
	 * will be sent only in response to GRANT packets.
	 */
	__be32 unscheduled;
	
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

	/* The remaining packet bytes after the header constitute message
	 * data starting at the given offset.
	 */
} __attribute__((packed));
_Static_assert(sizeof(struct data_header) <= HOMA_MAX_HEADER,
		"data_header too large");
_Static_assert(ETHERNET_MAX_PAYLOAD >= (HOMA_MAX_DATA_PER_PACKET
	+ HOMA_MAX_IPV4_HEADER + sizeof(struct data_header)),
	"Homa messages don't fit in Ethernet frames");

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
		"grant_header too large");

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
	 * a range longer than the total message size.
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
		"resend_header too large");

/**
 * struct restart_header - Wire format for RESTART packets.
 *
 * A RESTART is sent by a server when it receives a RESEND request for
 * an RPC that is unknown to it. This can occur in two situations. The first
 * situation is when all of the request packets sent by the client were lost.
 * The second situation is when the server received the entire request,
 * processed it, transmitted the response, and discarded its RPC state, but
 * some of the response packets were lost. A RESTART request indicates to the
 * client that it should restart the RPC from the beginning, discarding any
 * partial response received so far and reinitiating transmission of the
 * request. Note that this can cause an RPC to be executed multiple times
 * on the server; this is explicitly allowed by the Homa protocol.
 */
struct restart_header {
	/** @common: Fields common to all packet types. */
	struct common_header common;
} __attribute__((packed));
_Static_assert(sizeof(struct restart_header) <= HOMA_MAX_HEADER,
		"restart_header too large");

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
		"busy_header too large");

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
	__be32 unsched_cutoffs[HOMA_NUM_PRIORITIES];
	
	/**
	 * @cutoff_version: unique identifier associated with @unsched_cutoffs.
	 * Must be included in future DATA packets sent to the sender of
	 * this packet.
	 */
	__be16 cutoff_version;
} __attribute__((packed));
_Static_assert(sizeof(struct cutoffs_header) <= HOMA_MAX_HEADER,
		"cutoffs_header too large");

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
	 * @packets: singly-linked list of all packets in message, linked
	 * using homa_next_skb. The list is in order of offset in the message
	 * (offset 0 first); each packet (except possibly the last) contains
	 * exactly HOMA_MAX_DATA_PER_PACKET of payload.
	 */
	struct sk_buff *packets;
	
	/**
	 * @next_packet: Pointer within @request of the next packet to transmit.
	 * 
	 * All packets before this one have already been sent. NULL means
	 * the entire message has been sent.
	 */
	struct sk_buff *next_packet;
	
	/**
	 * @next_offset: Offset within message of first byte in next_packet.
	 * If all packets have been sent, will be >= @length.
	 */
	int next_offset;
	
	/**
	 * @unscheduled: Initial bytes of message that we'll send
	 * without waiting for grants. May be larger than @length;
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
	 * when there are holes in the list.
	 */
	struct sk_buff_head packets;
	
	/**
	 * @bytes_remaining: Amount of data for this message that has
	 * not yet been received; will determine the message's priority.
	 */
	int bytes_remaining;

        /**
	 * @granted: Total # of bytes sender has been authorized to transmit
	 * (including unscheduled bytes). Never larger than @total_length.
	 */
        int granted;
	
	/** @priority: Priority level to include in future GRANTS. */
	int priority;
	
	/**
	 * @scheduled: Nonzero means some of the bytes of this message
	 * must be scheduled with grants.
	 */
	int scheduled;
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
	 * @peer: Information about the other machine (the server, if
	 * this is a client RPC, or the client, if this is a server RPC).
	 */
	struct homa_peer *peer;
	
	/** @dport: Port number on @peer that will handle packets. */
	__u16 dport;
	
	/**
	 * @id: Unique identifier for the RPC among all those issued
	 * from its port. Selected by the client.
	 */
	__u64 id;
	
	/**
	 * @state: The current state of this RPC:
	 * 
	 * @RPC_OUTGOING:     The RPC is waiting for @msgout to be transmitted
	 *                    to the peer.
	 * @RPC_INCOMING:     The RPC is waiting for data @msgin to be received
	 *                    from the peer; at least one packet has already
	 *                    been received.
	 * @RPC_READY:        @msgin is now complete; the next step is for
	 *                    the message to be read from the socket by the
	 *                    application.
	 * @RPC_IN_SERVICE:   Used only for server RPCs: the request message
	 *                    has been read from the socket, but the response
	 *                    message has not yet been presented to the kernel.
	 * @RPC_CLIENT_DONE:  Used only on clients: indicates that a response
	 *                    has been received and returned to the application.
	 * 
	 * Client RPCs pass through states in the following order:
	 * RPC_OUTGOING, RPC_INCOMING, RPC_READY, RPC_CLIENT_DONE.
	 * 
	 * Server RPCs pass through states in the following order:
	 * RPC_INCOMING, RPC_READY, RPC_IN_SERVICE, RPC_OUTGOING.
	 */
	enum {
		RPC_OUTGOING            = 5,
		RPC_INCOMING            = 6,
		RPC_READY               = 7,
		RPC_IN_SERVICE          = 8,
		RPC_CLIENT_DONE         = 9
	} state;
	
	/** @is_client: True means this is a client RPC, false means server. */
	bool is_client;
	
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
	 * @rpc_links: For linking this object into &homa_sock.client_rpcs
	 * (for a client RPC) or &homa_sock.server_rpcs (for a server RPC).
	 */
	struct list_head rpc_links;
	
	/**
	 * @ready_links: If state == RPC_READY, this is used to link this
	 * object into &homa_sock.ready_client_rpcs or
	 * &homa_sock.ready_server_rpcs.
	 */
	struct list_head ready_links;
	
	/**
	 * @grantable_links: Used to link this RPC into homa->grantable_rpcs.
	 * If this RPC isn't in homa_grantable_rpcs, this is an empty
	 * list pointing to itself.
	 */
	struct list_head grantable_links;
	
	/**
	 * @silent_ticks: Number of times homa_timer has been invoked
	 * since the last time a packet was received for this RPC.
	 */
	int silent_ticks;
};

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
	struct mutex write_lock;
	
	/**
	 * @buckets: Heads of chains for hash table buckets. Chains
	 * consist of homa_sock_link objects.
	 */
	struct hlist_head buckets[HOMA_SOCKTAB_BUCKETS];
};

/**
 * struct homa_sock_links - Used to link homa_socks into the hash chains
 * of a homa_socktab.
 */
struct homa_socktab_links {
	/* Must be the first element of the struct! */
	struct hlist_node hash_links;
	struct homa_sock *sock;
};

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
 * struct homa_sock - Information about an open socket.
 */
struct homa_sock {
	/** @inet: Generic socket data; must be the first field. */
	struct inet_sock inet;
	
	/**
	 * @homa: Overall state about the Homa implementation. NULL
	 * means this socket has been deleted.
	 */
	struct homa *homa;
	
	/**
	 * @server_port: Port number for receiving incoming RPC requests.
	 * Must be assigned explicitly with bind; 0 means not bound yet.
	 */
	__u16 server_port;
	
	/** @client_port: Port number to use for outgoing RPC requests. */
	__u16 client_port;
	
	/** @next_outgoing_id: Id to use for next outgoing RPC request. */
	__u64 next_outgoing_id;
	
	/**
	 * @client_socktab_links: Links this socket into the homa_socktab
	 * based on client_port.
	 */
	struct homa_socktab_links client_links; 
	
	/**
	 * @client_socktab_links: Links this socket into the homa_socktab
	 * based on server_port. Invalid/unused if server_port is 0.
	 */
	struct homa_socktab_links server_links;
	
	/** @client_rpcs: List of active RPCs originating from this socket. */
	struct list_head client_rpcs;
	
	/** @server_rpcs: Contains all active RPCs sent to this socket. */
	struct list_head server_rpcs;
	
	/**
	 * @ready_rpcs: Contains all RPCs (both client and server) in RPC_READY
	 * state. The head is oldest, i.e. next to return.
	 */
	struct list_head ready_rpcs;
};
static inline struct homa_sock *homa_sk(const struct sock *sk)
{
	return (struct homa_sock *)sk;
}

/**
 * define HOMA_PEERTAB_BUCKETS - Number of bits in the bucket index for a
 * homa_peertab.  Should be large enough to hold an entry for every server
 * in a datacenter without long hash chains.
 */
#define HOMA_PEERTAB_BUCKET_BITS 20

/** define HOME_PEERTAB_BUCKETS - Number of buckets in a homa_peertab. */
#define HOMA_PEERTAB_BUCKETS (1 << HOMA_PEERTAB_BUCKET_BITS)

/**
 * struct homa_peertab - A hash table that maps from IPV4 addresses
 * to homa_peer objects. Entries are gradually added to this table,
 * but they are never removed except when the entire table is deleted.
 * We can't safely delete because results returned by homa_peer_find
 * may be retained indefinitely.
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
	 * @buckets: Pointer to heads of chains of homa_peers for each bucket.
	 * Malloc-ed, and must eventually be freed. NULL means this structure
	 * has not been initialized.
	 */
	struct hlist_head *buckets;
};

/**
 * struct peer - One of these objects exists for each machine that we
 * have communicated with (either as client or server). 
 */
struct homa_peer {
	/** @daddr: IPV4 address for the machine. */
	__be32 addr;
	
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
	int unsched_cutoffs[HOMA_NUM_PRIORITIES];
	
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
	 * @peertab_links: Links this object into a bucket of its
	 * homa_peertab.
	 */
	struct hlist_node peertab_links;
};

/**
 * struct homa - Overall information about the Homa protocol implementation.
 * 
 * There will typically only exist one of these at a time, except during
 * unit tests.
 */
struct homa {
	/**
	 * @next_client_port: A client port number to consider for the
	 * next Homa socket; increments monotonically. Current value may
	 * be in the range allocated for servers; must check before using.
	 * This port may also be in use already; must check.
	 */
	__u16 next_client_port;
	
	/**
	 * @port_map: Information about all open sockets; indexed by
	 * port number.
	 */
	struct homa_socktab port_map;
	
	/**
	 * @peertab: Info about all the other hosts we have communicated
	 * with; indexed by host IPV4 address.
	 */
	struct homa_peertab peers;
	
	/**
	 * @rtt_bytes: A conservative estimate of the amount of data that
	 * can be sent over the wire in the time it takes to send a full-size
	 * data packet and receive back a grant. Homa tries to ensure
	 * that there is at least this much data in transit (or authorized
	 * via grants) for an incoming message at all times.
	 */
	int rtt_bytes;
	
	/**
	 * @max_prio: The highest priority level available for Homa's use.
	 */
	int max_prio;
	
	/**
	 * @min_prio: The lowest priority level available for Homa's use.
	 */
	int min_prio;
	
	/**
	 * @max_sched_prio: The highest priority level currently available for
	 * scheduled packets. Must be no less than min_prio. Levels above this
	 * are reserved for unscheduled packets.
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
	 */
	int unsched_cutoffs[HOMA_NUM_PRIORITIES];
	
	/**
	 * @cutoff_version: increments every time unsched_cutoffs is
	 * modified. Used to determine when we need to send updates to
	 * peers.  Note: 16 bits should be fine for this: the worst
	 * that happens is a peer has a super-stale value that equals
	 * our current value, so the peer uses suboptimal cutoffs until the
	 * next version change.
	 */
	int cutoff_version;
	
	/**
	 * @max_overcommit: The maximum number of messages to which Homa will
	 * send grants at any given point in time.
	 */
	int max_overcommit;
	
	/**
	 * @retry_ticks: When an RPC's @silent_ticks reaches this value,
	 * we start sending RESEND requests.
	 */
	int resend_ticks;
	
	/**
	 * @abort_ticks: Abort an RPC if its @silent_ticks reaches
	 * this value.
	 */
	int abort_ticks;
	
	/**
	 * @grantable_lock: Used to synchronize access to @grantable_rpcs and
	 * @num_grantable.
	 */
	struct spinlock grantable_lock;
	
	/**
	 * @grantable_rpcs: Contains all homa_rpcs (both requests and
	 * responses) whose msgins require additional grants before they can
	 * complete. The list is sorted in priority order (head has fewest
	 * bytes_remaining).
	 */
	struct list_head grantable_rpcs;
	
	/** @num_grantable: The number of messages in grantable_msgs. */
	int num_grantable;
	
	/**
	 * @metrics_lock: Used to synchronize accesses to @metrics_active_opens
	 * and updates to @metrics.
	 */
	struct spinlock metrics_lock;
	
	/*
	 * @metrics: a human-readable string containing recent values
	 * for all the Homa performance metrics, as generated by
	 * homa_compile_metrics. This string is kmalloc-ed; NULL means
	 * homa_compile_metrics has never been called.
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
 * but this is extremely unlikely, and we can tolerate the occasional
 * miscounts that might result.
 * 
 * All counters are free-running: they never reset.
 */
#define HOMA_NUM_SMALL_COUNTS 64
#define HOMA_NUM_MEDIUM_COUNTS 64
struct homa_metrics {	
	/**
	 * @small_msg_counts: entry i holds the total number of bytes
	 * received in messages whose length is between 64*i and 64*i + 63,
	 * inclusive.
	 */
	__u64 small_msg_bytes[HOMA_NUM_SMALL_COUNTS];
	
	/**
	 * @medium_msg_counts: entry i holds the total number of bytes
	 * received in messages whose length is between 1024*i and
	 * 1024*i + 1023, inclusive. The first four entries are always 0
	 * (small_msg_counts covers this range).
	 */
	__u64 medium_msg_bytes[HOMA_NUM_MEDIUM_COUNTS];
	
	/**
	 * @large_msg_count: the total number of messages received whose
	 * length is 0x100 or greater.
	 */
	__u64 large_msg_bytes;
	
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
	
	/**
	 * @requests_received: total number of request messages received.
	 */
	__u64 requests_received;
	
	/**
	 * @responses_received: total number of response messages received.
	 */
	__u64 responses_received;
	
	/**
	 * @timer_cycles: total time spent in homa_timer, as measured with
	 * get_cycles().
	 */
	__u64 timer_cycles;

	/**
	 * @resent_packets: total number of data packets issued in response to
	 * RESEND packets.
	 */
	__u64 resent_packets;
	
	/**
	 * @peer_hash_links: total # of link traversals in homa_peer_find
	 * (
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
	 * discarded because it referred to a nonexistent RPC.
	 */
	__u64 unknown_rpcs;
	
	/**
	 * @cant_create_server_rpc: total number of times a server discarded
	 * incoming packet because it couldn't create a homa_rpc object.
	 */
	__u64 server_cant_create_rpcs;
	
	/**
	 * @unknown_packet_type: total number of times a packet was discarded
	 * because its type wasn't one of the supported values.
	 */
	__u64 unknown_packet_types;
	
	/**
	 * @client_rpc_timeouts: total number of times an RPC was aborted on
	 * the client side because of a timeout.
	 */
	
	__u64 client_rpc_timeouts;
	
	/**
	 * @server_rpc_timeouts: total number of times an RPC was aborted on
	 * the server side because of a timeout.
	 */
	
	__u64 server_rpc_timeouts;
	
	/**
	 * @temp1: this value, and the others below it, are reserved for
	 * temporary use during testing.
	 */
	__u64 temp1;
	__u64 temp2;
	__u64 temp3;
	__u64 temp4;
};

#define INC_METRIC(metric, count) \
		(homa_metrics[smp_processor_id()]->metric) += (count)

extern struct homa_metrics *homa_metrics[NR_CPUS];

extern void     homa_add_packet(struct homa_message_in *msgin,
			struct sk_buff *skb);
extern void     homa_append_metric(struct homa *homa, const char* format, ...);
extern int      homa_bind(struct socket *sk, struct sockaddr *addr, int addr_len);
extern void     homa_prios_changed(struct homa *homa);
extern void     homa_close(struct sock *sock, long timeout);
extern void     homa_compile_metrics(struct homa_metrics *m);
extern void     homa_cutoffs_pkt(struct sk_buff *skb, struct homa_sock *hsk);
extern void     homa_data_from_server(struct sk_buff *skb,
			struct homa_rpc *crpc);
extern void     homa_data_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
extern void     homa_destroy(struct homa *homa);
extern int      homa_diag_destroy(struct sock *sk, int err);
extern int      homa_disconnect(struct sock *sk, int flags);
extern int      homa_dointvec_prio(struct ctl_table *table, int write,
			void __user *buffer, size_t *lenp, loff_t *ppos);
extern void     homa_err_handler(struct sk_buff *skb, u32 info);
extern struct homa_rpc
               *homa_find_client_rpc(struct homa_sock *hsk, __u16 sport,
			__u64 id);
extern struct homa_rpc
	       *homa_find_server_rpc(struct homa_sock *hsk, __be32 saddr,
			__u16 sport, __u64 id);
extern int      homa_get_port(struct sock *sk, unsigned short snum);
extern void     homa_get_resend_range(struct homa_message_in *msgin,
			struct resend_header *resend);
extern int      homa_getsockopt(struct sock *sk, int level, int optname,
			char __user *optval, int __user *option);
extern void     homa_grant_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
extern int      homa_hash(struct sock *sk);
extern enum hrtimer_restart
		homa_hrtimer(struct hrtimer *timer);
extern int      homa_init(struct homa *homa);
extern int      homa_ioc_recv(struct sock *sk, unsigned long arg);
extern int      homa_ioc_reply(struct sock *sk, unsigned long arg);
extern int      homa_ioc_send(struct sock *sk, unsigned long arg);
extern int      homa_ioctl(struct sock *sk, int cmd, unsigned long arg);
extern void     homa_manage_grants(struct homa *homa, struct homa_rpc *rpc);
extern int      homa_message_in_copy_data(struct homa_message_in *msgin,
			struct iov_iter *iter, int max_bytes);
extern void     homa_message_in_destroy(struct homa_message_in *msgin);
extern void     homa_message_in_init(struct homa_message_in *msgin, int length,
			int unscheduled);
extern void     homa_message_out_destroy(struct homa_message_out *msgout);
extern int      homa_message_out_init(struct homa_message_out *msgout,
			struct homa_sock *hsk, struct iov_iter *iter,
			size_t len, struct homa_peer *dest, __u16 dport,
			__u16 sport, __u64 id);
extern void     homa_message_out_reset(struct homa_message_out *msgout);
extern int      homa_metrics_open(struct inode *inode, struct file *file);
extern ssize_t  homa_metrics_read(struct file *file, char __user *buffer,
			size_t length, loff_t *offset);
extern int      homa_metrics_release(struct inode *inode, struct file *file);
extern void     homa_peertab_destroy(struct homa_peertab *peertab);
extern int      homa_peertab_init(struct homa_peertab *peertab);
extern struct homa_peer
               *homa_peer_find(struct homa_peertab *peertab, __be32 addr,
			struct inet_sock *inet);
extern void     homa_peer_set_cutoffs(struct homa_peer *peer, int c0, int c1,
			int c2, int c3, int c4, int c5, int c6, int c7);
extern int      homa_pkt_dispatch(struct sock *sk, struct sk_buff *skb);
extern int      homa_pkt_recv(struct sk_buff *skb);
extern __poll_t homa_poll(struct file *file, struct socket *sock,
			struct poll_table_struct *wait);
extern char    *homa_print_ipv4_addr(__be32 addr, char *buffer);
extern char    *homa_print_metrics(struct homa *homa);
extern char    *homa_print_packet(struct sk_buff *skb, char *buffer, int length);
extern char    *homa_print_packet_short(struct sk_buff *skb, char *buffer,
			int length);
extern int      homa_proc_read_metrics(char *buffer, char **start, off_t offset,
			int count, int *eof, void *data);
extern int      homa_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			int noblock, int flags, int *addr_len);
extern void     homa_rehash(struct sock *sk);
extern void     homa_remove_from_grantable(struct homa *homa,
			struct homa_rpc *rpc);
extern void     homa_resend_data(struct homa_message_out *msgout, int start,
			int end, struct sock *sk, struct homa_peer *peer,
			int priority);
extern void     homa_resend_pkt(struct sk_buff *skb, struct homa_rpc *rpc,
			struct homa_sock *hsk);
extern void     homa_restart_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
extern void     homa_rpc_abort(struct homa_rpc *crpc, int error);
extern void     homa_rpc_free(struct homa_rpc *rpc);
extern struct homa_rpc
               *homa_rpc_new_client(struct homa_sock *hsk,
			struct sockaddr_in *dest, size_t length,
			struct iov_iter *iter);
extern struct homa_rpc
               *homa_rpc_new_server(struct homa_sock *hsk, __be32 source,
			struct data_header *h);
extern int      homa_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
extern int      homa_sendpage(struct sock *sk, struct page *page, int offset,
			size_t size, int flags);
extern void     homa_set_priority(struct sk_buff *skb, int priority);
extern int      homa_setsockopt(struct sock *sk, int level, int optname,
			char __user *optval, unsigned int optlen);
extern int      homa_sock_bind(struct homa_socktab *socktab,
			struct homa_sock *hsk, __u16 port);
extern void     homa_sock_destroy(struct homa_sock *hsk);
extern struct homa_sock *
	        homa_sock_find(struct homa_socktab *socktab, __u16 port);
extern void     homa_sock_init(struct homa_sock *hsk, struct homa *homa);
extern int      homa_socket(struct sock *sk);
extern void     homa_socktab_destroy(struct homa_socktab *socktab);
extern void     homa_socktab_init(struct homa_socktab *socktab);
extern struct homa_sock
               *homa_socktab_next(struct homa_socktab_scan *scan);
extern struct homa_sock
               *homa_socktab_start_scan(struct homa_socktab *socktab,
			struct homa_socktab_scan *scan);
extern char    *homa_symbol_for_type(uint8_t type);
extern void     homa_tasklet_handler(unsigned long data);
extern void	homa_timer(struct homa *homa);
extern void     homa_unhash(struct sock *sk);
extern int      homa_unsched_priority(struct homa_peer *peer, int length);
extern int      homa_v4_early_demux(struct sk_buff *skb);
extern int      homa_v4_early_demux_handler(struct sk_buff *skb);
extern void     homa_validate_grantable_list(struct homa *homa, char *message);
extern int      homa_wait_ready_msg(struct sock *sk, long *timeo);
extern int      homa_xmit_control(enum homa_packet_type type, void *contents,
			size_t length, struct homa_rpc *rpc);
extern int      __homa_xmit_control(void *contents, size_t length,
			struct homa_peer *peer, struct homa_sock *hsk);
extern void     homa_xmit_data(struct homa_message_out *hmo, struct sock *sk,
			struct homa_peer *peer);
extern void     __homa_xmit_data(struct sk_buff *skb, struct sock *sk,
		struct homa_peer *peer);

#endif /* _HOMA_IMPL_H */
