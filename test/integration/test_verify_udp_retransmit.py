#!/usr/bin/env python3
# Unit-test retransmitted DATA identity and Homa control packet detection
# using synthetic UDP tunnel packets.

import struct
import unittest

import test_verify_udp_pcap
import verify_udp_pcap
import verify_udp_retransmit


class VerifyUdpRetransmitTest(unittest.TestCase):
    def test_repeated_data_identity_and_packet_types(self):
        data = bytearray(test_verify_udp_pcap.homa_data_payload())
        struct.pack_into("!Q", data, 20, 42)
        data[48] = 1
        parsed_data = verify_udp_pcap.parse_udp(
            test_verify_udp_pcap.ipv4_udp_frame(bytes(data)))
        resend = bytearray(37)
        resend[11] = verify_udp_retransmit.RESEND
        struct.pack_into("!QII", resend, 20, 43, 0, 100)
        parsed_resend = verify_udp_pcap.parse_udp(
            test_verify_udp_pcap.ipv4_udp_frame(bytes(resend)))
        rpc_unknown = bytearray(28)
        rpc_unknown[11] = verify_udp_retransmit.RPC_UNKNOWN
        ack = bytearray(80)
        ack[11] = verify_udp_retransmit.ACK

        summary = verify_udp_retransmit.summarize(
            [parsed_data, parsed_resend,
             verify_udp_pcap.parse_udp(
                 test_verify_udp_pcap.ipv4_udp_frame(bytes(rpc_unknown))),
             verify_udp_pcap.parse_udp(
                 test_verify_udp_pcap.ipv4_udp_frame(bytes(ack)))])

        self.assertEqual({"42:0": 1}, summary["retransmitted_segments"])
        self.assertTrue(verify_udp_retransmit.has_matching_resend(summary))
        self.assertEqual(1, summary["packet_types"]["0x10"])
        self.assertEqual(1, summary["packet_types"]["0x12"])
        self.assertEqual(1, summary["packet_types"]["0x13"])
        self.assertEqual(1, summary["packet_types"]["0x18"])

    def test_unique_data_is_not_retransmission(self):
        first = bytearray(test_verify_udp_pcap.homa_data_payload())
        struct.pack_into("!Q", first, 20, 42)

        summary = verify_udp_retransmit.summarize([
            verify_udp_pcap.parse_udp(
                test_verify_udp_pcap.ipv4_udp_frame(bytes(first))),
        ])

        self.assertEqual({}, summary["retransmitted_segments"])
        self.assertFalse(verify_udp_retransmit.has_matching_resend(summary))


if __name__ == "__main__":
    unittest.main()
