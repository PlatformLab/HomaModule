#!/usr/bin/env python3
# Verify repeated Homa DATA identities and required control packet classes
# in a UDP tunnel retransmission capture.

import argparse
from collections import Counter
import json
import struct
import sys

import verify_udp_pcap


DATA = 0x10
RESEND = 0x12
RPC_UNKNOWN = 0x13
ACK = 0x18


def data_identity(parsed):
	payload = parsed["payload"]
	if len(payload) < verify_udp_pcap.HOMA_HEADER_LENGTHS[DATA] or \
			payload[11] != DATA:
		return None
	sender_id = struct.unpack_from("!Q", payload, 20)[0]
	segment_offset = struct.unpack_from("!I", payload, 52)[0]
	return sender_id, segment_offset


def summarize(parsed_packets):
	packet_types = Counter()
	retransmitted_segments = Counter()
	resend_requests = []
	for parsed in parsed_packets:
		packet_type = verify_udp_pcap.validate_homa_packet(parsed)
		packet_types[packet_type] += 1
		identity = data_identity(parsed)
		if identity is not None and parsed["payload"][48] != 0:
			retransmitted_segments[identity] += 1
		if packet_type == RESEND:
			payload = parsed["payload"]
			sender_id = struct.unpack_from("!Q", payload, 20)[0]
			offset, length = struct.unpack_from("!II", payload, 28)
			resend_requests.append((sender_id, offset, length))
	retransmissions = {
		"%d:%d" % identity: count
		for identity, count in sorted(retransmitted_segments.items())
	}
	return {
		"packet_types": {
			"0x%02x" % packet_type: count
			for packet_type, count in sorted(packet_types.items())
		},
		"resend_requests": [
			"%d:%d:%d" % request for request in resend_requests
		],
		"retransmitted_segments": retransmissions,
	}


def has_matching_resend(summary):
	for identity in summary["retransmitted_segments"]:
		sender_id, segment_offset = (int(value)
									 for value in identity.split(":"))
		for request in summary["resend_requests"]:
			resend_id, offset, length = (int(value)
										 for value in request.split(":"))
			if resend_id != sender_id ^ 1:
				continue
			if length == 0xFFFFFFFF or (
					offset <= segment_offset < offset + length):
				return True
	return False


def main():
	parser = argparse.ArgumentParser(
		description="Verify deterministic Homa-over-UDP retransmission")
	parser.add_argument("pcap")
	args = parser.parse_args()

	packets = []
	for _, frame in verify_udp_pcap.read_pcap(args.pcap):
		parsed = verify_udp_pcap.parse_udp(frame)
		if parsed is not None:
			packets.append(parsed)
	summary = summarize(packets)
	if not summary["retransmitted_segments"]:
		raise ValueError("capture contains no retransmit-marked DATA segment")
	if not has_matching_resend(summary):
		raise ValueError("no RESEND request matches a retransmitted DATA segment")
	for packet_type, name in ((RPC_UNKNOWN, "RPC_UNKNOWN"), (ACK, "ACK")):
		if summary["packet_types"].get("0x%02x" % packet_type, 0) == 0:
			raise ValueError("capture contains no %s packet" % name)
	print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
	try:
		main()
	except (OSError, ValueError, struct.error) as error:
		print("retransmission validation failed: %s" % error,
			  file=sys.stderr)
		sys.exit(1)
