/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */

/* This file defines the on-the-wire format of Homa packets. */

#ifndef _HOMA_WIRE_H
#define _HOMA_WIRE_H

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

/* Defines the possible types of Homa packets.
 *
 * See the xxx_header structs below for more information about each type.
 */
enum homa_packet_type {
	DATA               = 0x10,
	GRANT              = 0x11,
	RESEND             = 0x12,
	RPC_UNKNOWN        = 0x13,
	BUSY               = 0x14,
	CUTOFFS            = 0x15,
	FREEZE             = 0x16,
	NEED_ACK           = 0x17,
	ACK                = 0x18,
	START_MSG         = 0x19,
	MAX_OP             = 0x19,
	/* If you add a new type here, you must also do the following:
	 * 1. Change MAX_OP so it is the highest valid opcode
	 * 2. Add support for the new opcode in homa_print_packet,
	 *    homa_print_packet_short, homa_symbol_for_type, and mock_skb_alloc.
	 * 3. Add the header length to header_lengths in homa_plumbing.c.
	 * 4. Add length validation for the header in homa_load.
	 */
};

/**
 * define HOMA_SKB_EXTRA - How many bytes of additional space to allow at the
 * beginning of each sk_buff, before the Homa header. This includes room for
 * UDP, the largest fixed IP header, and the link-layer reserved space, so
 * the kernel UDP tunnel helpers can prepend their headers in place.
 */
#define HOMA_SKB_EXTRA (LL_MAX_HEADER + sizeof(struct ipv6hdr) + \
		       sizeof(struct udphdr))

/**
 * define HOMA_ETH_FRAME_OVERHEAD - Additional overhead bytes for each
 * Ethernet packet that are not included in the packet header (preamble,
 * start frame delimiter, CRC, and inter-packet gap).
 */
#define HOMA_ETH_FRAME_OVERHEAD 24

/**
 * define HOMA_ETH_OVERHEAD - Number of bytes per Ethernet packet for Ethernet
 * header, CRC, preamble, and inter-packet gap.
 */
#define HOMA_ETH_OVERHEAD (18 + HOMA_ETH_FRAME_OVERHEAD)

/**
 * define HOMA_MIN_PKT_LENGTH - Every Homa packet must be padded to at least
 * this length to meet Ethernet frame size limitations. This number includes
 * Homa headers and data, but not UDP, IP or Ethernet headers. The IPv4
 * minimum frame has 46 bytes after Ethernet: 20 IP + 8 UDP + 18 Homa.
 */
#define HOMA_MIN_PKT_LENGTH 18

/**
 * define HOMA_MAX_HEADER - Number of bytes in the largest Homa header.
 */
#define HOMA_MAX_HEADER 65

/**
 * define HOMA_MAX_PRIORITIES - The maximum number of priority levels that
 * Homa can use (the actual number can be restricted to less than this at
 * runtime). Changing this value will affect packet formats.
 */
#define HOMA_MAX_PRIORITIES 8

/**
 * define HOMA_MIN_SEG_DATA - Homa will consider a host unreachable if
 * there isn't room for at least this many bytes of message data in DATA
 * packets for that host (the exact number is somewhat arbitrary; what's
 * absolutely essential is that the value must be greater than zero).
 */
#define HOMA_MIN_SEG_DATA 100

/**
 * struct homa_common_hdr - Wire format for the first bytes in every Homa
 * packet. Application ports are independent of the outer UDP tunnel ports.
 */
struct homa_common_hdr {
	/**
	 * @sport: Port on source machine from which packet was sent.
	 */
	__be16 sport;

	/**
	 * @dport: Port on destination that is to receive packet.
	 */
	__be16 dport;

	/**
	 * @type: Homa packet type (one of the values of the homa_packet_type
	 * enum).
	 */
	u8 type;

	/**
	 * @sender_id: the identifier of this RPC as used on the sender (i.e.,
	 * if the low-order bit is set, then the sender is the server for
	 * this RPC).
	 */
	__be64 sender_id;
} __packed;

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
	 * @client_id: The client's identifier for the RPC. 0 means this ack
	 * is invalid.
	 */
	__be64 client_id;

	/** @server_port: The server-side port for the RPC. */
	__be16 server_port;
} __packed;

/* struct homa_data_hdr - Contains data for part or all of a Homa message.
 * An incoming packet consists of a homa_data_hdr followed by message data.
 * An outgoing packet can have this simple format as well, or it can be
 * structured as a GSO packet with the following format:
 *
 *    |-----------------------|
 *    |                       |
 *    |     data_header       |
 *    |                       |
 *    |---------------------- |
 *    |                       |
 *    |                       |
 *    |     segment data      |
 *    |                       |
 *    |                       |
 *    |-----------------------|
 *    |      data_header      |
 *    |-----------------------|
 *    |                       |
 *    |                       |
 *    |     segment data      |
 *    |                       |
 *    |                       |
 *    |-----------------------|
 *    |      data_header      |
 *    |-----------------------|
 *    |                       |
 *    |                       |
 *    |     segment data      |
 *    |                       |
 *    |                       |
 *    |-----------------------|
 *
 * Each UDP GSO chunk contains a complete, independently mutable DATA header
 * and its payload. Only the outer IP and UDP headers are replicated by GSO.
 * The tx pool's internal homa_seg_hdr placeholders are not sent separately.
 *
 * If the first packet that a receiver sees for an incoming message is DATA
 * (rather than START_MSG) it means that this message is unscheduled: the
 * sender will transmit all of its packets without waiting for grants.
 */
struct homa_seg_hdr {
	/**
	 * @offset: Offset within message of the first byte of data in
	 * this segment.
	 */
	__be32 offset;
} __packed;

struct homa_data_hdr {
	struct homa_common_hdr common;

	/** @msg_length: Total #bytes in the message. */
	__be32 msg_length;

	/** @reserved1: Reserved DATA field; transmitted as zero. */
	__be32 reserved1;

	/** @ack: If the @client_id field of this is nonzero, provides info
	 * about an RPC that the recipient can now safely free. Note: in
	 * UDP GSO packets only the first chunk carries a piggybacked ack.
	 */
	struct homa_ack ack;

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
	u8 retransmit;

	char pad[3];

	/** @seg: Offset of the payload in this UDP datagram. */
	struct homa_seg_hdr seg;
} __packed;

/**
 * homa_data_len() - Returns the total number of bytes in a DATA packet
 * after the homa_data_hdr. Note: if the packet is a GSO packet, the result
 * may include metadata as well as packet data.
 * @skb:   Incoming data packet
 * Return: see above
 */
static inline u32 homa_data_len(struct sk_buff *skb)
{
	return skb->len - skb_transport_offset(skb) -
			sizeof(struct homa_data_hdr);
}

/**
 * struct homa_grant_hdr - Wire format for GRANT packets, which are sent by
 * the receiver back to the sender to indicate that the sender may transmit
 * additional bytes in the message.
 */
struct homa_grant_hdr {
	/** @common: Fields common to all packet types. */
	struct homa_common_hdr common;

	/**
	 * @offset: Byte offset within the message. The sender should transmit
	 * all data packets with starting offsets less than this that haven't
	 * already been transmitted.
	 */
	__be32 offset;

	/**
	 * @priority: The sender should use this priority level for all future
	 * DATA packets for this message, until a GRANT is received with higher
	 * offset. Larger numbers indicate higher priorities.
	 */
	u8 priority;
} __packed;

/**
 * struct homa_resend_hdr - Wire format for RESEND packets.
 *
 * A RESEND is sent by the receiver when it believes that message data may
 * have been lost in transmission (or if it is concerned that the sender may
 * have crashed). The receiver should resend the specified portion of the
 * message, even if it already sent it previously.
 */
struct homa_resend_hdr {
	/** @common: Fields common to all packet types. */
	struct homa_common_hdr common;

	/**
	 * @offset: Offset within the message of the first byte of data that
	 * should be retransmitted.
	 */
	__be32 offset;

	/**
	 * @length: Number of bytes of data to retransmit. -1 means no data
	 * has been received for the message, so everything sent previously
	 * should be retransmitted.
	 */
	__be32 length;

	/**
	 * @priority: Packet priority to use.
	 *
	 * The sender should transmit all the requested data using this
	 * priority.
	 */
	u8 priority;
} __packed;

/**
 * struct homa_rpc_unknown_hdr - Wire format for RPC_UNKNOWN packets.
 *
 * An RPC_UNKNOWN packet is sent by either server or client when it receives a
 * packet for an RPC that is unknown to it. When a client receives an
 * RPC_UNKNOWN packet it will typically restart the RPC from the beginning;
 * when a server receives an RPC_UNKNOWN packet it will typically discard its
 * state for the RPC.
 */
struct homa_rpc_unknown_hdr {
	/** @common: Fields common to all packet types. */
	struct homa_common_hdr common;
} __packed;

/**
 * struct homa_busy_hdr - Wire format for BUSY packets.
 *
 * These packets tell the recipient that the sender is still alive (even if
 * it isn't sending data expected by the recipient).
 */
struct homa_busy_hdr {
	/** @common: Fields common to all packet types. */
	struct homa_common_hdr common;
} __packed;

/**
 * struct homa_cutoffs_hdr - Wire format for CUTOFFS packets.
 *
 * These packets tell the recipient how to assign priorities to
 * unscheduled packets.
 */
struct homa_cutoffs_hdr {
	/** @common: Fields common to all packet types. */
	struct homa_common_hdr common;

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
} __packed;

/**
 * struct homa_freeze_hdr - Wire format for FREEZE packets.
 *
 * These packets tell the recipient to freeze its timetrace; used
 * for debugging.
 */
struct homa_freeze_hdr {
	/** @common: Fields common to all packet types. */
	struct homa_common_hdr common;
} __packed;

/**
 * struct homa_need_ack_hdr - Wire format for NEED_ACK packets.
 *
 * These packets ask the recipient (a client) to return an ACK message if
 * the packet's RPC is no longer active.
 */
struct homa_need_ack_hdr {
	/** @common: Fields common to all packet types. */
	struct homa_common_hdr common;
} __packed;

/**
 * struct homa_ack_hdr - Wire format for ACK packets.
 *
 * These packets are sent from a client to a server to indicate that
 * a set of RPCs is no longer active on the client, so the server can
 * free any state it may have for them.
 */
struct homa_ack_hdr {
	/** @common: Fields common to all packet types. */
	struct homa_common_hdr common;

	/** @num_acks: Number of (leading) elements in @acks that are valid. */
	__be16 num_acks;

#define HOMA_MAX_ACKS_PER_PKT 5
	/** @acks: Info about RPCs that are no longer active. */
	struct homa_ack acks[HOMA_MAX_ACKS_PER_PKT];
} __packed;

/**
 * struct homa_start_msg_hdr - Wire format for START_MSG packets.
 *
 * A START_MSG packet is sent to begin the transmission of a scheduled
 * message, so that the receiver knows that the message exists and can begin
 * sending GRANTs for the message. The client will not sent any DATA packets
 * for the message until it receives GRANTs. START_MSG packets are not used for
 * unscheduled messages: the sender sends DATA packets without waiting for
 * GRANTs.
 */
struct homa_start_msg_hdr {
	/** @common: Fields common to all packet types. */
	struct homa_common_hdr common;

	/** @msg_length: Number of bytes in the message. */
	__be32 msg_length;
} __packed;

/**
 * homa_local_id(): given an RPC identifier from an input packet (which
 * is network-encoded), return the decoded id we should use for that
 * RPC on this machine.
 * @sender_id:  RPC id from an incoming packet, such as h->common.sender_id
 * Return: see above
 */
static inline u64 homa_local_id(__be64 sender_id)
{
	/* If the client bit was set on the sender side, it needs to be
	 * removed here, and conversely.
	 */
	return be64_to_cpu(sender_id) ^ 1;
}

#endif /* _HOMA_WIRE_H */
