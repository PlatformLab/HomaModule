/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */

#ifndef RAW_HOMA_H
#define RAW_HOMA_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "../homa.h"

/*
 * Userspace mirror of the packed layout in ../homa_wire.h, which includes
 * kernel-only headers. All offsets below are relative to Homa content, not
 * UDP. Keep this table synchronized with that file; never cast unaligned
 * packet bytes to host structs.
 *
 * Common: sport[0:2], dport[2:4], type[4], sender_id[5:13].
 * DATA: msg_length[13:17], reserved1[17:21], ack[21:31],
 * cutoff_version[31:33], retransmit[33], pad[34:37], offset[37:41].
 * GRANT: offset[13:17], priority[17].
 * RESEND: offset[13:17], length[17:21], priority[21].
 * CUTOFFS: eight u32 cutoffs[13:45], version[45:47].
 * ACK: count[13:15], five (u64 client_id, u16 server_port) entries[15:65].
 * START_MSG: msg_length[13:17]. Other controls contain only common.
 */
enum {
	RAW_UDP_HEADER = 8,
	RAW_UDP_MAX = 65535,
	RAW_IPV4_HEADER = 20,
	RAW_COMMON_HEADER = 13,
	RAW_DATA_HEADER = 41,
	RAW_SPORT = 0,
	RAW_DPORT = 2,
	RAW_TYPE = 4,
	RAW_RPC = 5,
	RAW_MSG_LENGTH = 13,
	RAW_DATA_ACK = 21,
	RAW_DATA_ACK_PORT = 29,
	RAW_DATA_VERSION = 31,
	RAW_RETRANSMIT = 33,
	RAW_DATA_OFFSET = 37,
	RAW_CONTROL_OFFSET = 13,
	RAW_GRANT_PRIORITY = 17,
	RAW_RESEND_LENGTH = 17,
	RAW_RESEND_PRIORITY = 21,
	RAW_CUTOFFS = 13,
	RAW_CUTOFF_VERSION = 45,
	RAW_ACK_COUNT = 13,
	RAW_ACKS = 15,
	RAW_ACK_SIZE = 10,
	RAW_MAX_ACKS = 5,
	RAW_DATA = 0x10,
	RAW_GRANT,
	RAW_RESEND,
	RAW_RPC_UNKNOWN,
	RAW_BUSY,
	RAW_CUTOFF,
	RAW_FREEZE,
	RAW_NEED_ACK,
	RAW_ACK,
	RAW_START_MSG
};

static inline uint16_t raw_get16(const uint8_t *p)
{
	return ((uint16_t)p[0] << 8) | p[1];
}

static inline uint32_t raw_get32(const uint8_t *p)
{
	return ((uint32_t)raw_get16(p) << 16) | raw_get16(p + 2);
}

static inline uint64_t raw_get64(const uint8_t *p)
{
	return ((uint64_t)raw_get32(p) << 32) | raw_get32(p + 4);
}

static inline void raw_put16(uint8_t *p, uint16_t value)
{
	p[0] = value >> 8;
	p[1] = value;
}

/* Each checksum part before the final UDP part has an even byte count. */
static inline uint32_t raw_sum(uint32_t sum, const uint8_t *p, size_t length)
{
	while (length >= 2) {
		sum += raw_get16(p);
		p += 2;
		length -= 2;
	}
	if (length)
		sum += (uint32_t)p[0] << 8;
	return sum;
}

static inline uint16_t raw_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

/*
 * Returns zero when verifying a valid packet (including its checksum).
 * When generating a checksum, callers must replace a zero result with ffff.
 * Source and destination are address bytes in network order.
 */
static inline uint16_t raw_udp_checksum(int ipv6, const uint8_t *source,
		const uint8_t *dest, const uint8_t *udp, size_t length)
{
	uint32_t sum = raw_sum(0, source, ipv6 ? 16 : 4);

	sum = raw_sum(sum, dest, ipv6 ? 16 : 4);
	/* UDP length is <=65535: IPv6's upper length word is zero. */
	sum += 17 + length;
	return raw_fold(raw_sum(sum, udp, length));
}

static inline const char *raw_type_name(unsigned int type)
{
	static const char *const names[] = {
		"DATA", "GRANT", "RESEND", "RPC_UNKNOWN", "BUSY",
		"CUTOFFS", "FREEZE", "NEED_ACK", "ACK", "START_MSG"
	};

	if (type < RAW_DATA || type > RAW_START_MSG)
		return "UNKNOWN";
	return names[type - RAW_DATA];
}

static inline size_t raw_header_length(unsigned int type)
{
	static const uint8_t lengths[] = {
		41, 18, 22, 13, 13, 47, 13, 13, 65, 17
	};

	if (type < RAW_DATA || type > RAW_START_MSG)
		return 0;
	return lengths[type - RAW_DATA];
}

/* Structural validation, not RPC-state or Homa scheduling validation. */
static inline const char *raw_homa_error(const uint8_t *h, size_t length)
{
	size_t minimum;

	if (length < RAW_COMMON_HEADER)
		return "short_common";
	minimum = raw_header_length(h[RAW_TYPE]);
	if (!minimum)
		return "unknown_type";
	if (length < minimum)
		return "short_type_header";
	/* ACK's fixed wire header is 65 bytes, even when count is zero. */
	if (h[RAW_TYPE] == RAW_ACK &&
			raw_get16(h + RAW_ACK_COUNT) > RAW_MAX_ACKS)
		return "ack_count";
	return NULL;
}

static inline void raw_print_hex(const uint8_t *p, size_t length)
{
	size_t i;

	for (i = 0; i < length; i++)
		printf("%02x", p[i]);
}

/* Only call after raw_homa_error has accepted the entire Homa content. */
static inline void raw_print_homa(const uint8_t *h, size_t length, int payload)
{
	unsigned int type = h[RAW_TYPE];
	size_t header = raw_header_length(type);
	unsigned int i, count;

	printf(" type=%s type_code=0x%02x sport=%u dport=%u rpc=%" PRIu64
		" homa_length=%zu", raw_type_name(type), type,
		raw_get16(h + RAW_SPORT), raw_get16(h + RAW_DPORT),
		raw_get64(h + RAW_RPC), length);
	switch (type) {
	case RAW_DATA:
		printf(" offset=%" PRIu32 " length=%zu message_length=%" PRIu32
			" ack_rpc=%" PRIu64 " ack_port=%u cutoff_version=%u"
			" retransmit=%u",
			raw_get32(h + RAW_DATA_OFFSET), length - header,
			raw_get32(h + RAW_MSG_LENGTH),
			raw_get64(h + RAW_DATA_ACK),
			raw_get16(h + RAW_DATA_ACK_PORT),
			raw_get16(h + RAW_DATA_VERSION), h[RAW_RETRANSMIT]);
		break;
	case RAW_GRANT:
		printf(" offset=%" PRIu32 " priority=%u",
			raw_get32(h + RAW_CONTROL_OFFSET), h[RAW_GRANT_PRIORITY]);
		break;
	case RAW_RESEND:
		printf(" offset=%" PRIu32 " length=%" PRIu32 " priority=%u",
			raw_get32(h + RAW_CONTROL_OFFSET),
			raw_get32(h + RAW_RESEND_LENGTH), h[RAW_RESEND_PRIORITY]);
		break;
	case RAW_CUTOFF:
		printf(" cutoff_version=%u cutoffs=",
			raw_get16(h + RAW_CUTOFF_VERSION));
		for (i = 0; i < 8; i++)
			printf("%s%" PRIu32, i ? "," : "",
				raw_get32(h + RAW_CUTOFFS + 4 * i));
		break;
	case RAW_ACK:
		count = raw_get16(h + RAW_ACK_COUNT);
		printf(" ack_count=%u", count);
		for (i = 0; i < count; i++)
			printf(" ack%u_rpc=%" PRIu64 " ack%u_port=%u", i,
				raw_get64(h + RAW_ACKS + i * RAW_ACK_SIZE), i,
				raw_get16(h + RAW_ACKS + i * RAW_ACK_SIZE + 8));
		break;
	case RAW_START_MSG:
		printf(" message_length=%" PRIu32,
			raw_get32(h + RAW_MSG_LENGTH));
		break;
	}
	if (payload) {
		printf(" payload_hex=");
		raw_print_hex(h + header, length - header);
	}
}

#endif /* RAW_HOMA_H */
