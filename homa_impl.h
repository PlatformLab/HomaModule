/* This file contains definitions that are shared across the files
 * that implement Homa for Linux.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/inet_common.h>

extern struct homa homa;

/* Homa's protocol number within the IP protocol space (this is not an
 * officially allocated slot).
 */
#define IPPROTO_HOMA 140

/**
 * define HOMA_MAX_MESSAGE_LENGTH - Maximum bytes of payload in a Homa
 * request or response message.
 */
#define HOMA_MAX_MESSAGE_LENGTH 1000000

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
	
	/** @fl: Addressing info needed to send packets. */
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

/** define HOMA_MAX_HEADER - Largest allowable Homa header. */
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
 * define HOMA_MIN_CLIENT_PORT - The 16-bit port space is divided into
 * two nonoverlapping regions. Ports 1-32767 are reserved exclusively
 * for well-defined server ports. The remaining ports are used for client
 * ports; these are allocated automatically by Homa. Port 0 is reserved.
 */
#define HOMA_MIN_CLIENT_PORT 0x8000

/**
 * homa_next_skb() - Compute address of Homa's private link field in @skb.
 * @skb        Socket buffer containing private link field.
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
	struct common_header common;
} __attribute__((packed));
_Static_assert(sizeof(struct busy_header) <= HOMA_MAX_HEADER,
		"busy_header too large");

/**
 * struct homa_message_out - Describes a message (either request or response)
 * for which this machine is the sender.
 */
struct homa_message_out {
	/** @length: Total bytes in message (excluding headers). */
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
	
	/*
	 * @offset: Offset within message of first byte in next_packet. If
	 * all packets have been sent, will be >= @length.
	 */
	int next_offset;
	
	/**
	 * @unscheduled: Initial bytes of message that we'll send
	 * without waiting for grants.
	 */
	int unscheduled;
	
	/** @limit: Need grant before sending offsets >= this. */
	int limit;
	
	/** @priority: Packet priority to use for future transmissions. */
	__u8 priority;
};

/**
 * struct homa_client_rpc - One of these structures exists for each active
 * RPC initiated from this machine.
 */
struct homa_client_rpc {	
	/**
	 * @id: Unique identifier for the RPC among all those issued
	 * from its port. */
	__u64 id;
	
	/** @dest: Address information for server. */
	struct homa_addr dest;
	
	/**
	 * @client_rpcs_links: For linking this object into
	 * &homa_sock.client_rpcs.
	 */
	struct list_head client_rpc_links;
	
	/** @request: Information about the request message. */
	struct homa_message_out request;
};

/**
 * struct homa_message_in - Holds the state of a message received by
 * this machine; used for both requests and responses.
 */
struct homa_message_in {
	/**
	 * @packets: Packets received for this message so far. The list
	 * is sorted in order of offset (head is lowest offset), but
	 * packets can be received out of order, so there may be times
	 * when there are holes in the list.
	 */
	struct sk_buff_head packets;
	
	/** @total_length: Size of the entire message, in bytes. */
	int total_length;
	
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
};

/**
 * struct homa_server_rpc - One of these structures exists for each active
 * RPC for which this machine is the server. 
 */
struct homa_server_rpc {
	/** @saddr: IP address of the client (source). */
	__be32 saddr;
	
	/** @sport: Port from which RPC was sent on saddr. */
	__u16 sport;
	
	/** @id: Identifier for the RPC (unique from saddr/sport). */
	__u64 id;
	
	/** @request: Information about the request message. */
	struct homa_message_in request;
	
	/** @response: Information about the response message. */
	struct homa_message_out response;
	
	/**
	 * @server_rpcs_links: For linking this object into
	 * &homa_sock.server_rpcs.
	 */
	struct list_head server_rpc_links;
};

/**
 * struct homa_sock - Information about an open socket.
 */
struct homa_sock {
	/** @inet: Generic socket data; must be the first field. */
	struct inet_sock inet;
	
	/**
	 * @server_port: Port number for receiving incoming RPC requests.
	 * Must be assigned explicitly with bind; 0 means not bound yet.
	 */
	__u16 server_port;
	
	/** @client_port: Port number to use for outgoing RPC requests. */
	__u16 client_port;
	
	/** @next_outgoing_id: Id to use for next outgoing RPC request. */
	__u64 next_outgoing_id;
	
	/** @socket_links: For linking this socket into &homa.sockets. */
	struct list_head socket_links;
	
	/** @client_rpcs: List of active RPCs originating from this socket. */
	struct list_head client_rpcs;
	
	/** @client_rpcs: List of active RPCs sent to this socket. */
	struct list_head server_rpcs;
};
static inline struct homa_sock *homa_sk(const struct sock *sk)
{
	return (struct homa_sock *)sk;
}

/**
 * struct homa - Overall information about the Homa protocol implementation.
 * 
 * There will typically only exist one of these at a time, except for
 * unit testing.
 */
struct homa {
	/**
	 * @next_client_report: A client port number to consider for the
	 * next Homa socket; increments monotonically. Current value may
	 * be in the range allocated for servers; must check before using.
	 * This port may also be in use already; must check.
	 */
	__u16 next_client_port;
	
	/** @sockets: All existing sockets. */
	struct list_head sockets;
};

extern void   homa_addr_destroy(struct homa_addr *addr);
extern int    homa_addr_init(struct homa_addr *addr, struct sock *sk,
		__be32 saddr, __u16 sport, __be32 daddr, __u16 dport);
extern int    homa_bind(struct socket *sk, struct sockaddr *addr, int addr_len);
extern void   homa_client_rpc_destroy(struct homa_client_rpc *crpc);
extern void   homa_close(struct sock *sock, long timeout);
extern void   homa_data_from_client(struct homa *homa, struct sk_buff *skb,
		struct homa_sock *hsk, struct homa_server_rpc *srpc);
extern int    homa_diag_destroy(struct sock *sk, int err);
extern int    homa_disconnect(struct sock *sk, int flags);
extern void   homa_err_handler(struct sk_buff *skb, u32 info);
extern struct homa_server_rpc *homa_find_server_rpc(struct homa_sock *hsk,
		__be32 saddr, __u16 sport, __u64 id);
extern struct homa_sock *
	      homa_find_socket(struct homa *homa, __u16 port);
extern int    homa_get_port(struct sock *sk, unsigned short snum);
extern int    homa_getsockopt(struct sock *sk, int level, int optname,
		char __user *optval, int __user *option);
extern int    homa_handler(struct sk_buff *skb);
extern int    homa_hash(struct sock *sk);
extern void   homa_message_in_destroy(struct homa_message_in *hmi);
extern void   homa_message_out_destroy(struct homa_message_out *hmo);
extern int    homa_setsockopt(struct sock *sk, int level, int optname,
		char __user *optval, unsigned int optlen);
extern int    homa_ioctl(struct sock *sk, int cmd, unsigned long arg);
extern void   homa_message_in_init(struct homa_message_in *hmi, int length,
		int unscheduled);
extern void   homa_message_out_destroy(struct homa_message_out *hmo);
extern int    homa_message_out_init(struct homa_message_out *hmo,
		struct sock *sk, struct msghdr *msg, size_t len,
		struct homa_addr *dest, __u16 sport, __u64 id);
extern __poll_t
	      homa_poll(struct file *file, struct socket *sock,
		struct poll_table_struct *wait);
extern char  *homa_print_header(struct sk_buff *skb, char *buffer, int length);
extern int    homa_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		int noblock, int flags, int *addr_len);
extern void   homa_rehash(struct sock *sk);
extern int    homa_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
extern int    homa_sendpage(struct sock *sk, struct page *page, int offset,
		size_t size, int flags);
extern void   homa_server_rpc_destroy(struct homa_server_rpc *srpc);
extern int    homa_sock_init(struct sock *sk);
extern char  *homa_symbol_for_type(uint8_t type);
extern void   homa_unhash(struct sock *sk);
extern int    homa_v4_early_demux(struct sk_buff *skb);
extern int    homa_v4_early_demux_handler(struct sk_buff *skb);
extern void   homa_xmit_packets(struct homa_message_out *hmo, struct sock *sk,
		struct homa_addr *dest);