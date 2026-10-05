#!/usr/bin/env python3
# Classify captured packets as native Homa or Homa-over-UDP and verify
# that the capture contains the expected transport.

import argparse
from collections import Counter
import json
import socket
import struct
import sys

import verify_udp_pcap


IPPROTO_HOMA = 146
UDP_PORT = 54321
TRANSPORTS = ("native", "udp")


def classify_transport(frame):
    if len(frame) < 14:
        return None
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    while ethertype in (0x8100, 0x88A8):
        if len(frame) < offset + 4:
            return None
        ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4

    if ethertype == 0x0800:
        if len(frame) < offset + 20:
            return None
        header_length = (frame[offset] & 0x0F) * 4
        if header_length < 20 or len(frame) < offset + header_length:
            return None
        protocol = frame[offset + 9]
        transport_offset = offset + header_length
    elif ethertype == 0x86DD:
        if len(frame) < offset + 40:
            return None
        payload_length = struct.unpack_from("!H", frame, offset + 4)[0]
        packet_end = min(len(frame), offset + 40 + payload_length)
        protocol, transport_offset = verify_udp_pcap.ipv6_transport(
            frame, offset, packet_end)
    else:
        return None

    if protocol == IPPROTO_HOMA:
        return "native"
    if protocol == socket.IPPROTO_UDP and len(frame) >= transport_offset + 8:
        source_port, destination_port = struct.unpack_from(
            "!HH", frame, transport_offset)
        if source_port == UDP_PORT and destination_port == UDP_PORT:
            return "udp"
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Verify the selected outer transport in a Homa pcap")
    parser.add_argument("pcap")
    parser.add_argument("--expect", required=True, choices=TRANSPORTS)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    counts = Counter()
    for _, frame in verify_udp_pcap.read_pcap(args.pcap):
        transport = classify_transport(frame)
        if transport is not None:
            counts[transport] += 1
    if counts[args.expect] == 0:
        raise ValueError("capture contains no %s Homa packets" % args.expect)
    unexpected = {name: counts[name] for name in TRANSPORTS
                  if name != args.expect and counts[name]}
    if unexpected:
        raise ValueError("capture contains unexpected transports: %s" %
                         ", ".join("%s=%d" % item
                                   for item in sorted(unexpected.items())))

    summary = {name: counts[name] for name in TRANSPORTS}
    if args.json:
        print(json.dumps(summary, sort_keys=True))
    else:
        print("validated %s transport: %d packets" %
              (args.expect, counts[args.expect]))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        print("transport validation failed: %s" % error, file=sys.stderr)
        sys.exit(1)