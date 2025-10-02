/* SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+ */

/* This file defines the on-the-wire format of Homa packets. */

#ifndef _HOMA_WIRE_H
#define _HOMA_WIRE_H

#include <linux/skbuff.h>
#ifdef __UNIT_TEST__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif /* __UNIT_TEST__ */
#include <net/tcp.h>
#ifdef __UNIT_TEST__
#pragma GCC diagnostic pop
#endif /* __UNIT_TEST__ */

/* Defines the possible types of Homa packets.
 *
 * See the xxx_header structs below for more information about each type.
 */
enum homa_packet_type {
	DATA               = 0x10,
#ifndef __STRIP__ /* See strip.py */
	GRANT              = 0x11,
#endif /* See strip.py */
	RESEND             = 0x12,
	RPC_UNKNOWN        = 0x13,
	BUSY               = 0x14,
#ifndef __STRIP__ /* See strip.py */
	CUTOFFS            = 0x15,
#endif /* See strip.py */
#ifndef __UPSTREAM__ /* See strip.py */
	FREEZE             = 0x16,
#endif /* See strip.py */
	NEED_ACK           = 0x17,
	ACK                = 0x18,
	MAX_OP             = 0x18,
	/* If you add a new type here, you must also do the following:
	 * 1. Change MAX_OP so it is the highest valid opcode
	 * 2. Add support for the new opcode in homa_print_packet,
	 *    homa_print_packet_short, homa_symbol_for_type, and mock_skb_alloc.
	 * 3. Add the header length to header_lengths in homa_plumbing.c.
	 */
};

/**
 * define HOMA_SKB_EXTRA - How many bytes of additional space to allow at the
 * beginning of each sk_buff, before the Homa header. This includes room for
 * either an IPV4 or IPV6 header, Ethernet header, VLAN header, etc. This is
 * a bit of an overestimate, since it also includes space for a TCP header.
 */
#define HOMA_SKB_EXTRA MAX_TCP_HEADER

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
 * Homa headers and data, but not IP or Ethernet headers.
 */
#define HOMA_MIN_PKT_LENGTH 26

/**
 * define HOMA_MAX_HEADER - Number of bytes in the largest Homa header.
 */
#define HOMA_MAX_HEADER 90

#ifndef __STRIP__ /* See strip.py */
/**
 * define HOMA_MAX_PRIORITIES - The maximum number of priority levels that
 * Homa can use (the actual number can be restricted to less than this at
 * runtime). Changing this value will affect packet formats.
 */
#define HOMA_MAX_PRIORITIES 8
#endif /* See strip.py */

/**
 * struct homa_common_hdr - Wire format for the first bytes in every Homa
 * packet. This must (mostly) match the format of a TCP header to enable
 * Homa packets to actually be transmitted as TCP packets (and thereby
 * take advantage of TSO and other features).
 */
struct homa_common_hdr {
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
	 * @sequence: corresponds to the sequence number field in TCP headers;
	 * used in DATA packets to hold the offset in the message of the first
	 * byte of data. However, when TSO is used without TCP hijacking, this
	 * value will only be correct in the first segment of a GSO packet.
	 */
	__be32 sequence;

	/**
	 * @ack: Corresponds to the high-order bits of the acknowledgment
	 * field in TCP headers; not used by Homa.
	 */
	char ack[3];

	/**
	 * @type: Homa packet type (one of the values of the homa_packet_type
	 * enum). Corresponds to the low-order byte of the ack in TCP.
	 */
	u8 type;

	/**
	 * @doff: High order 4 bits corespond to the Data Offset field of a
	 * TCP header. In DATA packets they hold the number of 4-byte chunks
	 * in a homa_data_hdr; used by TSO to determine where the replicated
	 * header portion ends. For other packets the offset is always 5
	 * (standard TCP header length); other values may cause some NICs
	 * (such as Intel E810-C) to drop outgoing packets when TCP hijacking
	 * is enabled. The low-order bits are always 0.
	 */
	u8 doff;

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @flags: Holds TCP flags such as URG, ACK, etc. The special value
	 * HOMA_TCP_FLAGS is stored here to distinguish Homa-over-TCP packets
	 * from real TCP packets. It includes the SYN and RST flags,
	 * which TCP would never use together; must not include URG or FIN
	 * (TSO will turn off FIN for all but the last segment).
	 */
	u8 flags;
#define HOMA_TCP_FLAGS 6
#else /* See strip.py */
	/** @reserved1: Not used (corresponds to TCP flags). */
	u8 reserved1;
#endif /* See strip.py */

	/**
	 * @window: Corresponds to the window field in TCP headers. Not used
	 * by HOMA.
	 */
	__be16 window;

	/**
	 * @checksum: Not used by Homa, but must occupy the same bytes as
	 * the checksum in a TCP header (TSO may modify this?).
	 */
	__be16 checksum;

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @urgent: occupies the same bytes as the urgent pointer in a TCP
	 * header. When Homa packets are transmitted over TCP, this has the
	 * special value HOMA_TCP_URGENT (which is set even though URG is
	 * not set) to indicate that the packet is actually a Homa packet.
	 */
	__be16 urgent;
#define HOMA_TCP_URGENT 0xb97d
#else /* See strip.py */
	/** @reserved2: Not used (corresponds to TCP urgent field). */
	__be16 reserved2;
#endif /* See strip.py */

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

#ifndef __STRIP__ /* See strip.py */
/* struct homa_data_hdr - Contains data for part or all of a Homa message.
 * An incoming packet consists of a homa_data_hdr followed by message data.
 * An outgoing packet can have this simple format as well, or it can be
 * structured as a GSO packet. Homa supports two different formats for GSO
 * packets, depending on whether TCP hijacking is enabled:
 *
 *    No hijacking:                          TCP hijacking:
 *
 *    |-----------------------|              |-----------------------|
 *    |                       |              |                       |
 *    |     homa_data_hdr     |              |     homa_data_hdr     |
 *    |                       |              |                       |
 *    |---------------------- |              |-----------------------|
 *    |                       |              |                       |
 *    |                       |              |                       |
 *    |     segment data      |              |     segment data      |
 *    |                       |              |                       |
 *    |                       |              |                       |
 *    |-----------------------|              |-----------------------|
 *    |     homa_seg_hdr      |              |                       |
 *    |-----------------------|              |                       |
 *    |                       |              |     segment data      |
 *    |                       |              |                       |
 *    |     segment data      |              |                       |
 *    |                       |              |-----------------------|
 *    |                       |              |                       |
 *    |-----------------------|              |                       |
 *    |     homa_seg_hdr      |              |     segment data      |
 *    |-----------------------|              |                       |
 *    |                       |              |                       |
 *    |                       |              |-----------------------|
 *    |     segment data      |
 *    |                       |
 *    |                       |
 *    |-----------------------|
 *
 * With TCP hijacking, TSO will automatically adjust @common.sequence in
 * the segments, so that value can be used as the offset of the data within
 * the message. Without TCP hijacking, TSO will not adjust @common.sequence
 * in the segments, so Homa sprinkles correct offsets (in homa_seg_hdrs)
 * throughout the segment data; TSO/GSO will include a different homa_seg_hdr
 * in each generated packet.
 */
#else /* See strip.py */
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
 *    |      seg_header       |
 *    |-----------------------|
 *    |                       |
 *    |                       |
 *    |     segment data      |
 *    |                       |
 *    |                       |
 *    |-----------------------|
 *    |      seg_header       |
 *    |-----------------------|
 *    |                       |
 *    |                       |
 *    |     segment data      |
 *    |                       |
 *    |                       |
 *    |-----------------------|
 *
 * TSO will not adjust @homa_common_hdr.sequence in the segments, so Homa
 * sprinkles correct offsets (in homa_seg_hdrs) throughout the segment data;
 * TSO/GSO will include a different homa_seg_hdr in each generated packet.
 */
#endif /* See strip.py */

struct homa_seg_hdr {
#ifndef __STRIP__ /* See strip.py */
	/**
	 * @offset: Offset within message of the first byte of data in
	 * this segment.  If this field is -1 it means that the packet was
	 * generated by GSO with TCP hijacking. In this case the true offset
	 * is in @common.sequence. homa_gro_receive detects this situation
	 * and updates this value from @common.sequence if needed, so the
	 * value will always be valid once the packet reaches homa_softirq.
	 */
#else /* See strip.py */
	/**
	 * @offset: Offset within message of the first byte of data in
	 * this segment.
	 */
#endif /* See strip.py */
	__be32 offset;
} __packed;

struct homa_data_hdr {
	struct homa_common_hdr common;

	/** @message_length: Total #bytes in the message. */
	__be32 message_length;

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @incoming: The receiver can expect the sender to send all of the
	 * bytes in the message up to at least this offset (exclusive),
	 * even without additional grants. This includes unscheduled
	 * bytes, granted bytes, plus any additional bytes the sender
	 * transmits unilaterally (e.g., to round up to a full GSO batch).
	 */
	__be32 incoming;
#else /* See strip.py */
	__be32 reserved1;
#endif /* See strip.py */

	/** @ack: If the @client_id field of this is nonzero, provides info
	 * about an RPC that the recipient can now safely free. Note: in
	 * TSO packets this will get duplicated in each of the segments;
	 * in order to avoid repeated attempts to ack the same RPC,
	 * homa_gro_receive will clear this field in all segments but the
	 * first.
	 */
	struct homa_ack ack;

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @cutoff_version: The cutoff_version from the most recent
	 * CUTOFFS packet that the source of this packet has received
	 * from the destination of this packet, or 0 if the source hasn't
	 * yet received a CUTOFFS packet.
	 */
	__be16 cutoff_version;
#else /* See strip.py */
	__be16 reserved2;
#endif /* See strip.py */

	/**
	 * @retransmit: 1 means this packet was sent in response to a RESEND
	 * (it has already been sent previously).
	 */
	u8 retransmit;

	char pad[3];

	/** @seg: First of possibly many segments. */
	struct homa_seg_hdr seg;
} __packed;

/**
 * homa_data_len() - Returns the total number of bytes in a DATA packet
 * after the homa_data_hdr. Note: if the packet is a GSO packet, the result
 * may include metadata as well as packet data.
 * @skb:   Incoming data packet
 * Return: see above
 */
static inline int homa_data_len(struct sk_buff *skb)
{
	return skb->len - skb_transport_offset(skb) -
			sizeof(struct homa_data_hdr);
}

#ifndef __STRIP__ /* See strip.py */
/**
 * struct homa_grant_hdr - Wire format for GRANT packets, which are sent by
 * the receiver back to the sender to indicate that the sender may transmit
 * additional bytes in the message.
 */
struct homa_grant_hdr {
	/** @common: Fields common to all packet types. */
	struct homa_common_hdr common;

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
	u8 priority;
} __packed;
#endif /* See strip.py */

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

#ifndef __STRIP__ /* See strip.py */
	/**
	 * @priority: Packet priority to use.
	 *
	 * The sender should transmit all the requested data using this
	 * priority.
	 */
	u8 priority;
#endif /* See strip.py */
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

#ifndef __STRIP__ /* See strip.py */
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
#endif /* See strip.py */

#ifndef __UPSTREAM__ /* See strip.py */
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
#endif /* See strip.py */

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
