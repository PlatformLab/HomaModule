#!/usr/bin/env python3
# Validate captured Homa-over-UDP packets, including tunnel ports,
# lengths, checksums, and inner Homa headers.

import argparse
from collections import Counter
import json
import socket
import struct
import sys


UDP_PORT = 54321
HOMA_MIN_TYPE = 0x10
HOMA_MAX_TYPE = 0x19
HOMA_HEADER_LENGTHS = {
    0x10: 56,  # DATA
    0x11: 33,  # GRANT
    0x12: 37,  # RESEND
    0x13: 28,  # RPC_UNKNOWN
    0x14: 28,  # BUSY
    0x15: 62,  # CUTOFFS
    0x16: 28,  # FREEZE
    0x17: 28,  # NEED_ACK
    0x18: 80,  # ACK
    0x19: 32,  # START_MSG
}


def checksum_sum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def checksum_valid(data):
    return checksum_sum(data) == 0xFFFF


def ipv6_transport(packet, offset, packet_end):
    next_header = packet[offset + 6]
    cursor = offset + 40
    while next_header in (0, 43, 44, 51, 60):
        if cursor + 2 > packet_end:
            raise ValueError("truncated IPv6 extension header")
        if next_header == 44:
            raise ValueError("fragmented IPv6 packet")
        elif next_header == 51:
            header_length = (packet[cursor + 1] + 2) * 4
        else:
            header_length = (packet[cursor + 1] + 1) * 8
        if cursor + header_length > packet_end:
            raise ValueError("truncated IPv6 extension header")
        next_header = packet[cursor]
        cursor += header_length
    return next_header, cursor


def parse_udp(frame):
    if len(frame) < 14:
        return None
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    while ethertype in (0x8100, 0x88A8):
        ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4

    if ethertype == 0x0800:
        if len(frame) < offset + 20:
            return None
        header_length = (frame[offset] & 0x0F) * 4
        total_length = struct.unpack_from("!H", frame, offset + 2)[0]
        fragment = struct.unpack_from("!H", frame, offset + 6)[0]
        if header_length < 20 or total_length < header_length:
            raise ValueError("invalid IPv4 length")
        if fragment & 0x3FFF:
            raise ValueError("fragmented IPv4 packet")
        packet_end = offset + total_length
        if len(frame) < packet_end:
            raise ValueError("truncated IPv4 packet")
        if frame[offset + 9] != socket.IPPROTO_UDP:
            return None
        source = frame[offset + 12:offset + 16]
        destination = frame[offset + 16:offset + 20]
        udp_offset = offset + header_length
        family = "ipv4"
        outer_length = total_length
    elif ethertype == 0x86DD:
        if len(frame) < offset + 40:
            return None
        payload_length = struct.unpack_from("!H", frame, offset + 4)[0]
        packet_end = offset + 40 + payload_length
        if len(frame) < packet_end:
            raise ValueError("truncated IPv6 packet")
        protocol, udp_offset = ipv6_transport(frame, offset, packet_end)
        if protocol != socket.IPPROTO_UDP:
            return None
        source = frame[offset + 8:offset + 24]
        destination = frame[offset + 24:offset + 40]
        family = "ipv6"
        outer_length = 40 + payload_length
    else:
        return None

    if len(frame) < udp_offset + 8:
        raise ValueError("truncated UDP header")
    source_port, destination_port, udp_length, checksum = struct.unpack_from(
        "!HHHH", frame, udp_offset)
    if udp_length < 8:
        raise ValueError("invalid UDP length")
    if udp_offset + udp_length != packet_end:
        raise ValueError("UDP length does not match IP payload")
    if len(frame) < udp_offset + udp_length:
        raise ValueError("truncated UDP datagram")
    datagram = frame[udp_offset:udp_offset + udp_length]
    payload = datagram[8:]
    if family == "ipv4":
        pseudo_header = source + destination + struct.pack(
            "!BBH", 0, socket.IPPROTO_UDP, udp_length)
    else:
        pseudo_header = source + destination + struct.pack(
            "!I3xB", udp_length, socket.IPPROTO_UDP)
    return {
        "checksum": checksum,
        "checksum_partial": checksum == checksum_sum(pseudo_header),
        "checksum_valid": checksum_valid(pseudo_header + datagram),
        "destination_port": destination_port,
        "family": family,
        "homa_offset": udp_offset + 8,
        "outer_length": outer_length,
        "payload": payload,
        "source_port": source_port,
        "udp_length": udp_length,
    }


def validate_homa_packet(parsed, allow_partial_checksum=False):
    if (parsed["source_port"] != UDP_PORT or
            parsed["destination_port"] != UDP_PORT):
        raise ValueError("UDP tunnel packet used an unexpected port")
    payload = parsed["payload"]
    if parsed["udp_length"] != len(payload) + 8:
        raise ValueError("UDP length does not match captured payload")
    if parsed["checksum"] == 0 and not (
            allow_partial_checksum and parsed["checksum_partial"]):
        raise ValueError("UDP checksum is disabled")
    if not parsed["checksum_valid"] and not (
            allow_partial_checksum and parsed["checksum_partial"]):
        raise ValueError("UDP checksum is invalid")
    if len(payload) < 28:
        raise ValueError("UDP payload is shorter than a Homa common header")
    packet_type = payload[11]
    if not HOMA_MIN_TYPE <= packet_type <= HOMA_MAX_TYPE:
        raise ValueError("UDP payload does not start with a Homa header")
    header_length = HOMA_HEADER_LENGTHS[packet_type]
    if len(payload) < header_length:
        raise ValueError("Homa packet is shorter than its type-specific header")
    if packet_type == 0x10:
        message_length = struct.unpack_from("!I", payload, 28)[0]
        segment_offset = struct.unpack_from("!I", payload, 52)[0]
        segment_length = len(payload) - header_length
        if segment_offset > message_length or (
                segment_length > message_length - segment_offset):
            raise ValueError("Homa DATA segment exceeds message bounds")
    return packet_type


def read_pcap(path):
    with open(path, "rb") as capture:
        header = capture.read(24)
        if len(header) != 24:
            raise ValueError("pcap header is missing or truncated")
        magic = header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            byte_order = "<"
            timestamp_scale = 1_000_000
        elif magic == b"\x4d\x3c\xb2\xa1":
            byte_order = "<"
            timestamp_scale = 1_000_000_000
        elif magic == b"\xa1\xb2\xc3\xd4":
            byte_order = ">"
            timestamp_scale = 1_000_000
        elif magic == b"\xa1\xb2\x3c\x4d":
            byte_order = ">"
            timestamp_scale = 1_000_000_000
        else:
            raise ValueError("unsupported pcap magic")
        link_type = struct.unpack_from(byte_order + "I", header, 20)[0]
        if link_type != 1:
            raise ValueError("expected Ethernet pcap link type")
        while True:
            packet_header = capture.read(16)
            if not packet_header:
                return
            if len(packet_header) != 16:
                raise ValueError("truncated pcap packet header")
            seconds, fraction, captured_length, _ = struct.unpack_from(
                byte_order + "IIII", packet_header)
            frame = capture.read(captured_length)
            if len(frame) != captured_length:
                raise ValueError("truncated pcap packet")
            yield seconds + fraction / timestamp_scale, frame


def main():
    parser = argparse.ArgumentParser(
        description="Validate Homa UDP tunnel packets in a classic pcap")
    parser.add_argument("pcap")
    parser.add_argument("--json", action="store_true",
                        help="write the validation summary as JSON")
    parser.add_argument(
        "--allow-partial-checksum", action="store_true",
        help="accept a valid CHECKSUM_PARTIAL pseudo-header seed")
    args = parser.parse_args()

    packet_count = 0
    checksum_ffff = 0
    partial_checksums = 0
    families = Counter()
    homa_offsets = set()
    max_outer_length = 0
    packet_types = Counter()
    timestamps = []
    for timestamp, frame in read_pcap(args.pcap):
        parsed = parse_udp(frame)
        if parsed is None:
            continue
        packet_type = validate_homa_packet(
            parsed, allow_partial_checksum=args.allow_partial_checksum)

        checksum_ffff += parsed["checksum"] == 0xFFFF
        partial_checksums += (not parsed["checksum_valid"] and
                              parsed["checksum_partial"])
        families[parsed["family"]] += 1
        homa_offsets.add(parsed["homa_offset"])
        max_outer_length = max(max_outer_length, parsed["outer_length"])
        packet_types[packet_type] += 1
        timestamps.append(timestamp)
        packet_count += 1

    if packet_count == 0:
        raise ValueError("capture contains no Homa UDP tunnel packets")
    gaps = [later - earlier for earlier, later in zip(timestamps, timestamps[1:])]
    summary = {
        "checksum_ffff": checksum_ffff,
        "families": dict(sorted(families.items())),
        "homa_header_offsets": sorted(homa_offsets),
        "max_outer_length": max_outer_length,
        "max_timestamp_gap_us": round(max(gaps, default=0) * 1_000_000, 3),
        "packet_count": packet_count,
        "packet_types": {
            "0x%02x" % packet_type: count
            for packet_type, count in sorted(packet_types.items())
        },
        "partial_checksums": partial_checksums,
    }
    if args.json:
        print(json.dumps(summary, sort_keys=True))
    else:
        print("validated %d Homa UDP packets" % packet_count)
        print("families: %s" % ", ".join(
            "%s=%d" % item for item in sorted(families.items())))
        print("types: %s" % ", ".join(
            "0x%02x=%d" % item for item in sorted(packet_types.items())))
        print("maximum outer packet length: %d" % max_outer_length)
        print("wire checksums equal to 0xffff: %d" % checksum_ffff)
        print("partial checksum seeds: %d" % partial_checksums)
        print("Homa header offsets: %s" % ", ".join(
            str(offset) for offset in sorted(homa_offsets)))
        print("maximum timestamp gap: %.3f us" % summary["max_timestamp_gap_us"])


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        print("pcap validation failed: %s" % error, file=sys.stderr)
        sys.exit(1)