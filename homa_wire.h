/* SPDX-License-Identifier: BSD-2-Clause */

/* This file defines the on-the-wire format of Homa packets. */

#ifndef _HOMA_WIRE_H
#define _HOMA_WIRE_H

#include <linux/skbuff.h>

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
 * define HOMA_ETH_OVERHEAD - Number of bytes per Ethernet packet for Ethernet
 * header, CRC, preamble, and inter-packet gap.
 */
#define HOMA_ETH_OVERHEAD 42

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

/**
 * struct common_header - Wire format for the first bytes in every Homa
 * packet. This must (mostly) match the format of a TCP header to enable
 * Homa packets to actually be transmitted as TCP packets (and thereby
 * take advantage of TSO and other features).
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
	 * @sequence: corresponds to the sequence number field in TCP headers;
	 * used in DATA packets to hold the offset in the message of the first
	 * byte of data. However, when TSO is used without TCP hijacking, this
	 * value will only be correct in the first segment of a GSO packet.
	 */
	__be32 sequence;

	/* The fields below correspond to the acknowledgment field in TCP
	 * headers; not used by Homa, except for the low-order 8 bits, which
	 * specify the Homa packet type (one of the values in the
	 * homa_packet_type enum).
	 */
	__be16 ack1;
	__u8 ack2;
	__u8 type;

	/**
	 * @doff: High order 4 bits holds the number of 4-byte chunks in a
	 * data_header (low-order bits unused). Used only for DATA packets;
	 * must be in the same position as the data offset in a TCP header.
	 * Used by TSO to determine where the replicated header portion ends.
	 */
	__u8 doff;

	/**
	 * @flags: Holds TCP flags such as URG, ACK, etc. The special value
	 * HOMA_TCP_FLAGS is stored here to distinguish Homa-over-TCP packets
	 * from real TCP packets. It includes the SYN and RST flags,
	 * which TCP would never use together; must not include URG or FIN
	 * (TSO will turn off FIN for all but the last segment).
	 */
	__u8 flags;
#define HOMA_TCP_FLAGS 6

	/**
	 * @window: Corresponds to the window field in TCP headers. Not used
	 * by HOMA.
	 */
	__be16 window;

	/**
	 * @checksum: not used by Homa, but must occupy the same bytes as
	 * the checksum in a TCP header (TSO may modify this?).
	 */
	__be16 checksum;

	/**
	 * @urgent: occupies the same bytes as the urgent pointer in a TCP
	 * header. When Homa packets are transmitted over TCP, this has the
	 * special value HOMA_TCP_URGENT (which is set even though URG is
	 * not set) to indicate that the packet is actually a Homa packet.
	 */
	__be16 urgent;
#define HOMA_TCP_URGENT 0xb97d

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

/* struct data_header - Contains data for part or all of a Homa message.
 * An incoming packet consists of a data_header followed by message data.
 * An outgoing packet can have this simple format as well, or it can be
 * structured as a GSO packet. Homa supports two different formats for GSO
 * packets, depending on whether TCP hijacking is enabled:
 *
 *    No hijacking:                          TCP hijacking:
 *
 *    |-----------------------|              |-----------------------|
 *    |                       |              |                       |
 *    |     data_header       |              |     data_header       |
 *    |                       |              |                       |
 *    |---------------------- |              |-----------------------|
 *    |                       |              |                       |
 *    |                       |              |                       |
 *    |     segment data      |              |     segment data      |
 *    |                       |              |                       |
 *    |                       |              |                       |
 *    |-----------------------|              |-----------------------|
 *    |      seg_header       |              |                       |
 *    |-----------------------|              |                       |
 *    |                       |              |     segment data      |
 *    |                       |              |                       |
 *    |     segment data      |              |                       |
 *    |                       |              |-----------------------|
 *    |                       |              |                       |
 *    |-----------------------|              |                       |
 *    |      seg_header       |              |     segment data      |
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
 * in the segments, so Homa sprinkles correct offsets (in seg_headers)
 * throughout the segment data; TSO/GSO will include a different seg_header
 * in each generated packet.
 */

struct seg_header {
	/**
	 * @offset: Offset within message of the first byte of data in
	 * this segment.  If this field is -1 it means that the packet was
	 * generated by GSO with TCP hijacking. In this case the true offset
	 * is in @common.sequence. homa_gro_receive detects this situation
	 * and updates this value from @common.sequence if needed, so the
	 * value will always be valid once the packet reaches homa_softirq.
	 */
	__be32 offset;
} __packed;

struct data_header {
	struct common_header common;

	/** @message_length: Total #bytes in the message. */
	__be32 message_length;

	/**
	 * @incoming: The receiver can expect the sender to send all of the
	 * bytes in the message up to at least this offset (exclusive),
	 * even without additional grants. This includes unscheduled
	 * bytes, granted bytes, plus any additional bytes the sender
	 * transmits unilaterally (e.g., to round up to a full GSO batch).
	 */
	__be32 incoming;

	/** @ack: If the @client_id field of this is nonzero, provides info
	 * about an RPC that the recipient can now safely free. Note: in
	 * TSO packets this will get duplicated in each of the segments;
	 * in order to avoid repeated attempts to ack the same RPC,
	 * homa_gro_receive will clear this field in all segments but the
	 * first.
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
	__u8 retransmit;

	char pad[3];

	/** @seg: First of possibly many segments. */
	struct seg_header seg;
} __packed;
_Static_assert(sizeof(struct data_header) <= HOMA_MAX_HEADER,
	       "data_header too large for HOMA_MAX_HEADER; must adjust HOMA_MAX_HEADER");
_Static_assert(sizeof(struct data_header) >= HOMA_MIN_PKT_LENGTH,
	       "data_header too small: Homa doesn't currently have code to pad data packets");
_Static_assert(((sizeof(struct data_header) - sizeof(struct seg_header)) &
		0x3) == 0,
	       " data_header length not a multiple of 4 bytes (required for TCP/TSO compatibility");

/**
 * homa_data_len() - Returns the total number of bytes in a DATA packet
 * after the data_header. Note: if the packet is a GSO packet, the result
 * may include metadata as well as packet data.
 * @skb:   Incoming data packet
 */
static inline int homa_data_len(struct sk_buff *skb)
{
	return skb->len - skb_transport_offset(skb) -
			sizeof(struct data_header);
}

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

	/**
	 * @resend_all: Nonzero means that the sender should resend all previously
	 * transmitted data, starting at the beginning of the message (assume
	 * that no packets have been successfully received).
	 */
	__u8 resend_all;
} __packed;
_Static_assert(sizeof(struct grant_header) <= HOMA_MAX_HEADER,
	       "grant_header too large for HOMA_MAX_HEADER; must adjust HOMA_MAX_HEADER");

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
} __packed;
_Static_assert(sizeof(struct resend_header) <= HOMA_MAX_HEADER,
	       "resend_header too large for HOMA_MAX_HEADER; must adjust HOMA_MAX_HEADER");

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
} __packed;
_Static_assert(sizeof(struct unknown_header) <= HOMA_MAX_HEADER,
	       "unknown_header too large for HOMA_MAX_HEADER; must adjust HOMA_MAX_HEADER");

/**
 * struct busy_header - Wire format for BUSY packets.
 *
 * These packets tell the recipient that the sender is still alive (even if
 * it isn't sending data expected by the recipient).
 */
struct busy_header {
	/** @common: Fields common to all packet types. */
	struct common_header common;
} __packed;
_Static_assert(sizeof(struct busy_header) <= HOMA_MAX_HEADER,
	       "busy_header too large for HOMA_MAX_HEADER; must adjust HOMA_MAX_HEADER");

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
} __packed;
_Static_assert(sizeof(struct cutoffs_header) <= HOMA_MAX_HEADER,
	       "cutoffs_header too large for HOMA_MAX_HEADER; must adjust HOMA_MAX_HEADER");

/**
 * struct freeze_header - Wire format for FREEZE packets.
 *
 * These packets tell the recipient to freeze its timetrace; used
 * for debugging.
 */
struct freeze_header {
	/** @common: Fields common to all packet types. */
	struct common_header common;
} __packed;
_Static_assert(sizeof(struct freeze_header) <= HOMA_MAX_HEADER,
	       "freeze_header too large for HOMA_MAX_HEADER; must adjust HOMA_MAX_HEADER");

/**
 * struct need_ack_header - Wire format for NEED_ACK packets.
 *
 * These packets ask the recipient (a client) to return an ACK message if
 * the packet's RPC is no longer active.
 */
struct need_ack_header {
	/** @common: Fields common to all packet types. */
	struct common_header common;
} __packed;
_Static_assert(sizeof(struct need_ack_header) <= HOMA_MAX_HEADER,
	       "need_ack_header too large for HOMA_MAX_HEADER; must adjust HOMA_MAX_HEADER");

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

	/** @num_acks: Number of (leading) elements in @acks that are valid. */
	__be16 num_acks;

#define HOMA_MAX_ACKS_PER_PKT 5
	/** @acks: Info about RPCs that are no longer active. */
	struct homa_ack acks[HOMA_MAX_ACKS_PER_PKT];
} __packed;
_Static_assert(sizeof(struct ack_header) <= HOMA_MAX_HEADER,
	       "ack_header too large for HOMA_MAX_HEADER; must adjust HOMA_MAX_HEADER");

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

#endif /* _HOMA_WIRE_H */
