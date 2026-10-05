#!/usr/bin/env python3
# Unit-test UDP tunnel packet validation and checksum construction
# using synthetic valid and malformed packets.

import struct
import unittest

import inject_udp_checksum
import verify_udp_pcap


def internet_checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    checksum = (~total) & 0xFFFF
    return checksum or 0xFFFF


def homa_data_payload(message_length=100, segment_offset=0,
                      segment_length=100):
    payload = bytearray(56 + segment_length)
    payload[11] = 0x10
    struct.pack_into("!I", payload, 28, message_length)
    struct.pack_into("!I", payload, 52, segment_offset)
    return bytes(payload)


def ipv4_udp_frame(payload, fragment=0, udp_length=None, partial=False):
    source = b"\x0a\x00\x00\x01"
    destination = b"\x0a\x00\x00\x02"
    actual_udp_length = 8 + len(payload)
    wire_udp_length = actual_udp_length if udp_length is None else udp_length
    udp_header = struct.pack("!HHHH", verify_udp_pcap.UDP_PORT,
                             verify_udp_pcap.UDP_PORT, wire_udp_length, 0)
    pseudo_header = source + destination + struct.pack(
        "!BBH", 0, 17, actual_udp_length)
    if partial:
        checksum = verify_udp_pcap.checksum_sum(pseudo_header)
    else:
        checksum = internet_checksum(pseudo_header + udp_header + payload)
    udp_header = struct.pack("!HHHH", verify_udp_pcap.UDP_PORT,
                             verify_udp_pcap.UDP_PORT, wire_udp_length,
                             checksum)
    ip_header = bytearray(20)
    ip_header[0] = 0x45
    struct.pack_into("!H", ip_header, 2, 20 + actual_udp_length)
    struct.pack_into("!H", ip_header, 6, fragment)
    ip_header[8] = 64
    ip_header[9] = 17
    ip_header[12:16] = source
    ip_header[16:20] = destination
    ethernet = b"\0" * 12 + b"\x08\x00"
    return ethernet + bytes(ip_header) + udp_header + payload


class VerifyUdpPcapTest(unittest.TestCase):
    def test_injected_ipv4_checksum(self):
        frame = inject_udp_checksum.build_frame(
            4, "10.0.0.1", "10.0.0.2", "02:00:00:00:00:01",
            "02:00:00:00:00:02")
        parsed = verify_udp_pcap.parse_udp(frame)

        self.assertTrue(parsed["checksum_valid"])
        self.assertEqual(0x14, verify_udp_pcap.validate_homa_packet(parsed))

        corrupted = inject_udp_checksum.build_frame(
            4, "10.0.0.1", "10.0.0.2", "02:00:00:00:00:01",
            "02:00:00:00:00:02", invalid=True)
        self.assertFalse(
            verify_udp_pcap.parse_udp(corrupted)["checksum_valid"])

        zero_checksum = inject_udp_checksum.build_frame(
            4, "10.0.0.1", "10.0.0.2", "02:00:00:00:00:01",
            "02:00:00:00:00:02", zero_checksum=True)
        parsed = verify_udp_pcap.parse_udp(zero_checksum)
        self.assertTrue(parsed["checksum_valid"])
        self.assertEqual(0xFFFF, parsed["checksum"])

    def test_injected_ipv6_checksum(self):
        frame = inject_udp_checksum.build_frame(
            6, "fd00::1", "fd00::2", "02:00:00:00:00:01",
            "02:00:00:00:00:02")
        parsed = verify_udp_pcap.parse_udp(frame)

        self.assertTrue(parsed["checksum_valid"])
        self.assertEqual(0x14, verify_udp_pcap.validate_homa_packet(parsed))

        corrupted = inject_udp_checksum.build_frame(
            6, "fd00::1", "fd00::2", "02:00:00:00:00:01",
            "02:00:00:00:00:02", invalid=True)
        self.assertFalse(
            verify_udp_pcap.parse_udp(corrupted)["checksum_valid"])

        zero_checksum = inject_udp_checksum.build_frame(
            6, "fd00::1", "fd00::2", "02:00:00:00:00:01",
            "02:00:00:00:00:02", zero_checksum=True)
        parsed = verify_udp_pcap.parse_udp(zero_checksum)
        self.assertTrue(parsed["checksum_valid"])
        self.assertEqual(0xFFFF, parsed["checksum"])

    def test_injected_data_packet(self):
        frame = inject_udp_checksum.build_frame(
            4, "10.0.0.1", "10.0.0.2", "02:00:00:00:00:01",
            "02:00:00:00:00:02", data_packet=True)
        parsed = verify_udp_pcap.parse_udp(frame)

        self.assertTrue(parsed["checksum_valid"])
        self.assertEqual(0x10, verify_udp_pcap.validate_homa_packet(parsed))
        self.assertEqual(184, parsed["outer_length"])

    def test_injected_control_packets(self):
        for control_type, expected_type, expected_length in (
                ("resend", 0x12, 37), ("need-ack", 0x17, 28)):
            frame = inject_udp_checksum.build_frame(
                4, "10.0.0.1", "10.0.0.2", "02:00:00:00:00:01",
                "02:00:00:00:00:02", control_type=control_type,
                source_port=4100, destination_port=4200)
            parsed = verify_udp_pcap.parse_udp(frame)

            self.assertTrue(parsed["checksum_valid"])
            self.assertEqual(expected_type,
                             verify_udp_pcap.validate_homa_packet(parsed))
            self.assertEqual(expected_length, len(parsed["payload"]))
            self.assertEqual((4100, 4200), struct.unpack_from(
                "!HH", parsed["payload"], 0))

    def test_valid_data_packet(self):
        parsed = verify_udp_pcap.parse_udp(
            ipv4_udp_frame(homa_data_payload()))

        self.assertEqual("ipv4", parsed["family"])
        self.assertEqual(184, parsed["outer_length"])
        self.assertTrue(parsed["checksum_valid"])
        self.assertEqual(0x10, verify_udp_pcap.validate_homa_packet(parsed))

    def test_ipv4_fragment_rejected(self):
        with self.assertRaisesRegex(ValueError, "fragmented IPv4"):
            verify_udp_pcap.parse_udp(
                ipv4_udp_frame(homa_data_payload(), fragment=0x2000))

    def test_partial_checksum_requires_explicit_opt_in(self):
        parsed = verify_udp_pcap.parse_udp(
            ipv4_udp_frame(homa_data_payload(), partial=True))

        self.assertTrue(parsed["checksum_partial"])
        self.assertFalse(parsed["checksum_valid"])
        with self.assertRaisesRegex(ValueError, "checksum is invalid"):
            verify_udp_pcap.validate_homa_packet(parsed)
        self.assertEqual(
            0x10, verify_udp_pcap.validate_homa_packet(
                parsed, allow_partial_checksum=True))

    def test_udp_length_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError, "UDP length"):
            verify_udp_pcap.parse_udp(
                ipv4_udp_frame(homa_data_payload(), udp_length=20))

    def test_short_type_specific_header_rejected(self):
        parsed = verify_udp_pcap.parse_udp(
            ipv4_udp_frame(homa_data_payload(segment_length=0)[:55]))

        with self.assertRaisesRegex(ValueError, "type-specific header"):
            verify_udp_pcap.validate_homa_packet(parsed)

    def test_data_segment_outside_message_rejected(self):
        parsed = verify_udp_pcap.parse_udp(ipv4_udp_frame(
            homa_data_payload(message_length=100, segment_offset=80,
                              segment_length=40)))

        with self.assertRaisesRegex(ValueError, "exceeds message bounds"):
            verify_udp_pcap.validate_homa_packet(parsed)


if __name__ == "__main__":
    unittest.main()