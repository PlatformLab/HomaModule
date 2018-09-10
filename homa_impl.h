/* This file contains definitions that are shared across the files
 * that implement Homa for Linux.
 */

#ifndef _HOMA_IMPL_H
#define _HOMA_IMPL_H

#include <linux/audit.h>
#include <linux/if_vlan.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/inet_common.h>

#include "homa.h"

#ifdef __UNIT_TEST__
#define spin_unlock mock_spin_unlock
extern void mock_spin_unlock(spinlock_t *lock);
#endif

extern struct homa *homa;

/* Forward declarations. */
struct homa_sock;

/**
 * struct homa_addr - Collects in one place the information needed to send
 * packets to a Homa peer.
 */
struct homa_addr {
	/** @daddr: IP address for the destination machine. */
	__be32 daddr;
	
	/**
	 * @dport: Port number on the destination machine that will
	 * handle packets.
	 */
	__u16 dport;
	
	/** @flow: Addressing info needed to send packets. */
	struct flowi flow;
	
	/**
	 * @dst: Used to route packets to the destination; we own a reference
	 * to this, which we must eventually release.
	 */
	struct dst_entry *dst;
};

/**
 * enum homa_packet_type - Defines the possible types of Homa packets.
 * 
 * See the xxx_header structs below for more information about each type.
 */
enum homa_packet_type {
	DATA               = 20,
	GRANT              = 21,
	RESEND             = 22,
	BUSY               = 23,
	BOGUS              = 24,      /* Used only in unit tests. */
	/* If you add a new type here, you must also do the following:
	 * 1. Change BOGUS so it is the highest opcode
	 * 2. Add support for the new opcode in op_symbol and header_to_string
	 * 3. Add support in new_buff in unit/unit_utils.cc
	 */
};

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
#define HOMA_MAX_HEADER 40

_Static_assert(1500 >= (HOMA_MAX_DATA_PER_PACKET + HOMA_MAX_IPV4_HEADER
	+ HOMA_MAX_HEADER), "Message length constants overflow Etheret frame");

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
	 * a range longer than the total message size. Ignored if restart is
	 * non-zero.
	 */
	__be32 length;
	
	/**
	 * @priority: Packet priority to use.
	 * 
	 * The sender should transmit all the requested data using this
	 * priority unless the RESTART flag is present (in which case this
	 * field is ignored and the sender computes the priority in the
	 * normal way for unscheduled bytes).
	 */
	__u8 priority;
	
	/**
	 * @restart: 1 means the server has no knowledge of this request,
	 * so the client should reset its state and restart the message
	 * from the beginning.
	 */
	__u8 restart;
} __attribute__((packed));
_Static_assert(sizeof(struct resend_header) <= HOMA_MAX_HEADER,
		"resend_header too large");

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
	 * without waiting for grants.
	 */
	int unscheduled;
	
	/** 
	 * @granted: Total number of bytes we are currently permitted to
	 * send, including unscheduled bytes; must wait for grants before
	 * sending bytes at or beyond this position. */
	int granted;
	
	/** @priority: Packet priority to use for future transmissions. */
	__u8 priority;
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
	 * (including unscheduled bytes).
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
	 * @peer: Address information for the other machine (the server,
	 * if this is a client RPC, or the client, if this is a server RPC).
	 */
	struct homa_addr peer;	
	
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
 * permit efficient lookups.
 */
struct homa_socktab {
	/**
	 * @mutex: Controls all modifications to this object; not needed
	 * for socket lookups (RCU is used instead). Also used to
	 * synchronize port allocation.
	 */
	struct mutex writeLock;
	
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
 * struct homa_sock - Information about an open socket.
 */
struct homa_sock {
	/** @inet: Generic socket data; must be the first field. */
	struct inet_sock inet;
	
	/** @homa: Overall state about the Homa implementation. */
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
	
	/** @port_map: Maps from port numbers to sockets. */
	struct homa_socktab port_map;
	
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
	 * @min_unsched_prio: The lowest priority level currently available for
	 * unscheduled messages. All priority levels higher than this are also
	 * use for unscheduled messages; prior levels lower than this are used
	 * for scheduled messages
	 */
	int min_unsched_prio;
	
	/**
	 * @max_overcommit: The maximum number of messages to which Homa will
	 * send grants at any given point in time.
	 */
	int max_overcommit;
	
	/**
	 * @lock: Used to synchronize access to all of the fields below,
	 * which may be accessed concurrently by different sockets.
	 */
	struct spinlock lock;
	
	/**
	 * @grantable_rpcs: Contains all homa_rpcs (both requests and
	 * responses) whose msgins require additional grants before they can
	 * complete. The list is sorted in priority order (head has fewest
	 * bytes_remaining).
	 */
	struct list_head grantable_rpcs;
	
	/** @num_grantable: The number of messages in grantable_msgs. */
	int num_grantable;
};

extern void   homa_add_packet(struct homa_message_in *msgin,
		struct sk_buff *skb);
extern void   homa_addr_destroy(struct homa_addr *addr);
extern int    homa_addr_init(struct homa_addr *addr, struct sock *sk,
		__be32 saddr, __u16 sport, __be32 daddr, __u16 dport);
extern int    homa_bind(struct socket *sk, struct sockaddr *addr, int addr_len);
extern void   homa_close(struct sock *sock, long timeout);
extern void   homa_data_from_server(struct sk_buff *skb,
		struct homa_rpc *crpc);
extern void   homa_data_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
extern void   homa_destroy(struct homa *homa);
extern int    homa_diag_destroy(struct sock *sk, int err);
extern int    homa_disconnect(struct sock *sk, int flags);
extern void   homa_err_handler(struct sk_buff *skb, u32 info);
extern struct homa_rpc *homa_find_client_rpc(struct homa_sock *hsk,
		__u16 sport, __u64 id);
extern struct homa_rpc *homa_find_server_rpc(struct homa_sock *hsk,
		__be32 saddr, __u16 sport, __u64 id);
extern int    homa_get_port(struct sock *sk, unsigned short snum);
extern int    homa_getsockopt(struct sock *sk, int level, int optname,
		char __user *optval, int __user *option);
extern void   homa_grant_pkt(struct sk_buff *skb, struct homa_rpc *rpc);
extern int    homa_hash(struct sock *sk);
extern void   homa_init(struct homa *homa);
extern int    homa_ioc_recv(struct sock *sk, unsigned long arg);
extern int    homa_ioc_reply(struct sock *sk, unsigned long arg);
extern int    homa_ioc_send(struct sock *sk, unsigned long arg);
extern int    homa_ioctl(struct sock *sk, int cmd, unsigned long arg);
extern void   homa_manage_grants(struct homa *homa, struct homa_rpc *rpc);
extern int    homa_message_in_copy_data(struct homa_message_in *msgin,
		struct iov_iter *iter, int max_bytes);
extern void   homa_message_in_destroy(struct homa_message_in *msgin);
extern void   homa_message_in_init(struct homa_message_in *msgin, int length,
		int unscheduled);
extern void   homa_message_out_destroy(struct homa_message_out *msgout);
extern int    homa_message_out_init(struct homa_message_out *msgout,
		struct sock *sk, struct iov_iter *iter, size_t len,
		struct homa_addr *dest, __u16 sport, __u64 id);
extern int    homa_pkt_dispatch(struct sock *sk, struct sk_buff *skb);
extern int    homa_pkt_recv(struct sk_buff *skb);
extern __poll_t
	      homa_poll(struct file *file, struct socket *sock,
		struct poll_table_struct *wait);
extern char  *homa_print_ipv4_addr(__be32 addr, char *buffer);
extern char  *homa_print_packet(struct sk_buff *skb, char *buffer, int length);
extern char  *homa_print_packet_short(struct sk_buff *skb, char *buffer,
		int length);
extern int    homa_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		int noblock, int flags, int *addr_len);
extern void   homa_rehash(struct sock *sk);
extern void   homa_remove_from_grantable(struct homa *homa,
		struct homa_rpc *rpc);
extern void   homa_rpc_free(struct homa_rpc *rpc);
extern struct homa_rpc
             *homa_rpc_new_client(struct homa_sock *hsk,
		struct sockaddr_in *dest, size_t length, struct iov_iter *iter);
extern struct homa_rpc
             *homa_rpc_new_server(struct homa_sock *hsk,
		__be32 source, struct data_header *h);
extern int    homa_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
extern int    homa_sendpage(struct sock *sk, struct page *page, int offset,
		size_t size, int flags);
extern int    homa_setsockopt(struct sock *sk, int level, int optname,
		char __user *optval, unsigned int optlen);
extern int    homa_sock_bind(struct homa_socktab *socktab,
		struct homa_sock *hsk, __u16 port);
extern void   homa_sock_destroy(struct homa_sock *hsk,
		struct homa_socktab *socktab);
extern struct homa_sock *
	      homa_sock_find(struct homa_socktab *socktab, __u16 port);
extern void   homa_sock_init(struct homa_sock *hsk, struct homa *homa);
extern int    homa_socket(struct sock *sk);
extern void   homa_socktab_destroy(struct homa_socktab *socktab);
extern void   homa_socktab_init(struct homa_socktab *socktab);
extern char  *homa_symbol_for_type(uint8_t type);
extern void   homa_unhash(struct sock *sk);
extern int    homa_v4_early_demux(struct sk_buff *skb);
extern int    homa_v4_early_demux_handler(struct sk_buff *skb);
extern int    homa_wait_ready_msg(struct sock *sk, long *timeo);
extern int    homa_xmit_control(enum homa_packet_type type, void *contents,
		size_t length, struct homa_rpc *rpc);
extern void   homa_xmit_data(struct homa_message_out *hmo, struct sock *sk,
		struct homa_addr *dest);

#endif /* _HOMA_IMPL_H */