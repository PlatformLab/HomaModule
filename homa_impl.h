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
 * struct rpc_id - Unique identifier for RPC (within client).
 * 
 * Must be unique among all RPCs from a given client that are active
 * at any given instant (including delayed packets floating around in
 * the network). The server adds in the client's network address to
 * produce a globally unique identifier.
 */
struct rpc_id {
	/** @port: &homa_socket.client_port from which RPC was issued. */
	__u32 port;
	
	/** @sequence: Distinguishes RPCs from @socket. */
	__u64 sequence;
} __attribute__((packed));

/**
 * enum homa_packet_type - Defines the possible types of Homa packets.
 * 
 * See the xxx_header structs below for more information about each type.
 */
enum homa_packet_type {
    FULL_MESSAGE           = 20,
    MESSAGE_FRAG           = 21,
    GRANT                  = 22,
    RESEND                 = 23,
    BUSY                   = 24,
    ABORT                  = 25,
    BOGUS                  = 26,      /* Used only in unit tests. */
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
 * Total allocated size of all Homa packet buffers.
 */
#define HOMA_SKB_SIZE (HOMA_MAX_DATA_PER_PACKET + HOMA_MAX_HEADER \
				+ HOMA_SKB_RESERVE)

/**
 * struct common_header - Wire format for the first bytes in every Homa
 * packet.
 */
struct common_header {
	struct rpc_id rpc_id;

	/** @type: One of the values of &enum packet_type. */
	__u8 type;
	
	/** @direction: Who sent the packet: FROM_CLIENT or FROM_SERVER. */
	__u8 direction;
} __attribute__((packed));
static const __u8 FROM_CLIENT = 1;
static const __u8 FROM_SERVER = 2;

/**
 * struct full_message_header - Wire format for a FULL_MESSAGE packet, which
 * contains an entire request or response message.
 */
struct full_message_header {
	struct common_header common;
	
	/** @message_length: Total # bytes of data following this header. */
	__be16 message_length; 

	/* The remaining packet bytes after the header constitute the
	 * entire request or response message.
	 */
} __attribute__((packed));
_Static_assert(sizeof(struct full_message_header) <= HOMA_MAX_HEADER,
		"full_message_header too large");

/**
 * struct message_frag_header - Wire format for a MESSAGE_FRAG packet, which
 * contains a contiguous range of bytes from a request or response message.
 */
struct message_frag_header {
	struct common_header common;
	
	/** @message_length: Total #bytes in the *message* */
	__be32 message_length;
	
	/**
	 * @offset: Offset within message of the first byte of data in
	 * this packet
	 */
	__be32 offset;
	
	/**
	 * @unscheduled_bytes: The number of initial bytes in the message
	 * that the sender will transmit without grants; bytes after these
	 * will be sent only in response to GRANT packets.
	 */
	__be32 unscheduled_bytes;

	/**
	 * @retransmit: 1 means this packet was sent in response to a RESEND
	 * (it has already been sent previously).
	 */
	__u8 retransmit;

	/* The remaining packet bytes after the header constitute message
	 * data starting at the given offset.
	 */
} __attribute__((packed));
_Static_assert(sizeof(struct message_frag_header) <= HOMA_MAX_HEADER,
		"message_frag_header too large");

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
	__u32 length;
	
	/**
	 * @packets: Message contents, packaged into sk_buffs that are ready
	 * for transmission. The list is in order of offset in the message
	 * (offset 0 first); each packet (except possibly the last) contains
	 * exactly HOMA_MAX_DATA_PER_PACKET of payload. Note: we don't use
	 * the lock here.
	 */
	struct sk_buff_head packets;
	
	/**
	 * @next_packet: Pointer within @request of the next packet to transmit.
	 * 
	 * All packets before this one have already been sent. NULL means
	 * the entire message has been sent.
	 */
	struct sk_buff *next_packet;
	
	/**
	 * @unscheduled_bytes: Initial bytes of message that we'll send
	 * without waiting for grants.
	 */
	__u32 unscheduled_bytes;
	
	/** @limit: Need grant before sending offsets >= this. */
	__u32 limit;
	
	/** @priority: Packet priority to use for future transmissions. */
	__u8 priority;
};

/**
 * struct homa_client_rpc - One of these structures exists for each active
 * RPC initiated from this machine.
 */
struct homa_client_rpc {
	/** @id: Unique identifier for the RPC. */
	struct rpc_id id;
	
	/**
	 * @client_rpcs_links: For linking this object into
	 * &homa_sock.client_rpcs.
	 */
	struct list_head client_rpcs_links;
	
	/**
	 * @request: Information about the request message.
	 */
	struct homa_message_out request;
};

/**
 * struct homa_sock - Information about an open socket.
 */
struct homa_sock {
	/** @inet: Generic socket data; must be the first field. */
	struct inet_sock inet;
	
	/** @client_port: Port number to use for outgoing RPC requests. */
	__u32 client_port;
	
	/** @next_outgoing_id: Id to use for next outgoing RPC request. */
	__u64 next_outgoing_id;
	
	/**
	 * @server_port: Port number for receiving incoming RPC requests.
	 * Must be assigned explicitly with bind; 0 means not bound yet.
	 */
	__u32 server_port;
	
	/** @socket_links: For linking this socket into &homa.sockets. */
	struct list_head socket_links;
	
	/** @client_rpcs: List of active RPCs originating from this socket. */
	struct list_head client_rpcs;
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
	 * @next_client_report: Use this as the client port number for the
	 * next Homa socket; increments monotonically. */
	__u32 next_client_port;
	
	/** @sockets: All existing sockets. */
	struct list_head sockets;
};

extern void homa_client_rpc_destroy(struct homa_client_rpc *crpc);
extern void homa_close(struct sock *sk, long timeout);
extern int homa_diag_destroy(struct sock *sk, int err);
extern int homa_disconnect(struct sock *sk, int flags);
extern void homa_err_handler(struct sk_buff *skb, u32 info);
extern int homa_get_port(struct sock *sk, unsigned short snum);
extern int homa_getsockopt(struct sock *sk, int level, int optname,
		char __user *optval, int __user *option);
extern int homa_handler(struct sk_buff *skb);
extern int homa_hash(struct sock *sk);
extern int homa_setsockopt(struct sock *sk, int level, int optname,
		char __user *optval, unsigned int optlen);
extern int homa_ioctl(struct sock *sk, int cmd, unsigned long arg);
extern void homa_message_out_destroy(struct homa_message_out *hmo);
extern int homa_message_out_init(struct homa_message_out *hmo, struct sock *sk,
		struct rpc_id id, __u8 direction, struct msghdr *msg,
		size_t len, struct dst_entry *dst);
extern __poll_t homa_poll(struct file *file, struct socket *sock,
		struct poll_table_struct *wait);
extern int homa_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		int noblock, int flags, int *addr_len);
extern void homa_rehash(struct sock *sk);
extern int homa_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
extern int homa_sendpage(struct sock *sk, struct page *page, int offset,
		size_t size, int flags);
extern int homa_sock_init(struct sock *sk);
extern void homa_unhash(struct sock *sk);
extern int homa_v4_early_demux(struct sk_buff *skb);
extern int homa_v4_early_demux_handler(struct sk_buff *skb);