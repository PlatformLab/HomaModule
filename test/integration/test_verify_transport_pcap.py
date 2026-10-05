#!/usr/bin/env python3
# Unit-test native Homa and UDP tunnel capture classification
# using synthetic Ethernet/IP packets without live network traffic.

import socket
import struct
import unittest

import verify_transport_pcap


def ipv4_frame(protocol, source_port=0, destination_port=0):
    payload = bytearray(28)
    if protocol == socket.IPPROTO_UDP:
        struct.pack_into("!HH", payload, 0, source_port, destination_port)
    ip_header = bytearray(20)
    ip_header[0] = 0x45
    struct.pack_into("!H", ip_header, 2, 20 + len(payload))
    ip_header[9] = protocol
    return b"\0" * 12 + b"\x08\x00" + bytes(ip_header) + bytes(payload)


def ipv6_frame(protocol, source_port=0, destination_port=0):
    payload = bytearray(28)
    if protocol == socket.IPPROTO_UDP:
        struct.pack_into("!HH", payload, 0, source_port, destination_port)
    ip_header = struct.pack("!IHBB16s16s", 6 << 28, len(payload), protocol,
                            64, b"\0" * 16, b"\0" * 16)
    return b"\0" * 12 + b"\x86\xdd" + ip_header + bytes(payload)


class VerifyTransportPcapTest(unittest.TestCase):
    def test_native_ipv4_and_ipv6(self):
        self.assertEqual(
            "native", verify_transport_pcap.classify_transport(
                ipv4_frame(verify_transport_pcap.IPPROTO_HOMA)))
        self.assertEqual(
            "native", verify_transport_pcap.classify_transport(
                ipv6_frame(verify_transport_pcap.IPPROTO_HOMA)))

    def test_udp_requires_fixed_tunnel_ports(self):
        self.assertEqual(
            "udp", verify_transport_pcap.classify_transport(
                ipv4_frame(socket.IPPROTO_UDP, 54321, 54321)))
        self.assertIsNone(verify_transport_pcap.classify_transport(
            ipv6_frame(socket.IPPROTO_UDP, 54321, 4000)))


if __name__ == "__main__":
    unittest.main()