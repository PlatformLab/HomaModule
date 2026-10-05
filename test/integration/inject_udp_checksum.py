#!/usr/bin/env python3
# Construct and inject Homa-over-UDP packets with selected checksum cases
# for the live UDP checksum integration test.

import argparse
import ipaddress
import socket
import struct


UDP_PORT = 54321


def checksum_sum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def internet_checksum(data):
    checksum = (~checksum_sum(data)) & 0xFFFF
    return checksum or 0xFFFF


def mac_bytes(address):
    octets = address.split(":")
    if len(octets) != 6:
        raise ValueError("invalid MAC address: %s" % address)
    return bytes(int(octet, 16) for octet in octets)


def homa_payload(data_packet=False, control_type=None, source_port=4000,
                 destination_port=4000):
    payload_length = 156 if data_packet else 28
    if control_type == "resend":
        payload_length = 37
    payload = bytearray(payload_length)
    struct.pack_into("!HH", payload, 0, source_port, destination_port)
    if data_packet:
        payload[11] = 0x10
        payload[12] = 14 << 4
        struct.pack_into("!Q", payload, 20, 10000)
        struct.pack_into("!I", payload, 28, 100)
        struct.pack_into("!I", payload, 52, 0)
    elif control_type == "resend":
        payload[11] = 0x12
        struct.pack_into("!QII", payload, 20, 0xD00DFEED, 0, 100)
    elif control_type == "need-ack":
        payload[11] = 0x17
        struct.pack_into("!Q", payload, 20, 0xD00DFEED)
    else:
        payload[11] = 0x14  # BUSY: the shortest Homa header.
    return bytes(payload)


def udp_datagram(source, destination, family, invalid, zero_checksum,
                 data_packet=False, control_type=None, source_port=4000,
                 destination_port=4000):
    payload = bytearray(homa_payload(data_packet, control_type, source_port,
                                     destination_port))
    udp_length = 8 + len(payload)
    header = struct.pack("!HHHH", UDP_PORT, UDP_PORT, udp_length, 0)
    if family == 4:
        pseudo_header = source + destination + struct.pack(
            "!BBH", 0, socket.IPPROTO_UDP, udp_length)
    else:
        pseudo_header = source + destination + struct.pack(
            "!I3xB", udp_length, socket.IPPROTO_UDP)
    if zero_checksum:
        adjustment = 0xFFFF - checksum_sum(pseudo_header + header + payload)
        struct.pack_into("!H", payload, len(payload) - 2, adjustment)
    checksum = internet_checksum(pseudo_header + header + payload)
    if invalid:
        checksum ^= 1
        if checksum == 0:
            checksum = 1
    return struct.pack("!HHHH", UDP_PORT, UDP_PORT, udp_length,
                       checksum) + payload


def build_frame(family, source_ip, destination_ip, source_mac,
                destination_mac, invalid=False, zero_checksum=False,
                data_packet=False, control_type=None, source_port=4000,
                destination_port=4000):
    source = ipaddress.ip_address(source_ip)
    destination = ipaddress.ip_address(destination_ip)
    if source.version != family or destination.version != family:
        raise ValueError("IP address family does not match --family")

    source_packed = source.packed
    destination_packed = destination.packed
    datagram = udp_datagram(source_packed, destination_packed, family,
                            invalid, zero_checksum, data_packet, control_type,
                            source_port, destination_port)
    if family == 4:
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(datagram),
                             0, 0x4000, 64, socket.IPPROTO_UDP, 0,
                             source_packed, destination_packed)
        header = header[:10] + struct.pack(
            "!H", internet_checksum(header)) + header[12:]
        ethertype = 0x0800
    else:
        header = struct.pack("!IHBB16s16s", 6 << 28, len(datagram),
                             socket.IPPROTO_UDP, 64, source_packed,
                             destination_packed)
        ethertype = 0x86DD
    ethernet = (mac_bytes(destination_mac) + mac_bytes(source_mac) +
                struct.pack("!H", ethertype))
    return ethernet + header + datagram


def main():
    parser = argparse.ArgumentParser(
        description="Inject a valid or corrupted Homa UDP Ethernet frame")
    parser.add_argument("--interface", required=True)
    parser.add_argument("--family", required=True, type=int,
                        choices=(4, 6))
    parser.add_argument("--source-ip", required=True)
    parser.add_argument("--destination-ip", required=True)
    parser.add_argument("--source-mac", required=True)
    parser.add_argument("--destination-mac", required=True)
    checksum_mode = parser.add_mutually_exclusive_group()
    checksum_mode.add_argument("--invalid", action="store_true")
    checksum_mode.add_argument("--zero-checksum", action="store_true")
    packet_type = parser.add_mutually_exclusive_group()
    packet_type.add_argument("--data", action="store_true",
                             help="inject a complete 100-byte DATA request")
    packet_type.add_argument("--resend", action="store_true",
                             help="inject RESEND for a nonexistent RPC")
    packet_type.add_argument("--need-ack", action="store_true",
                             help="inject NEED_ACK for a nonexistent RPC")
    parser.add_argument("--homa-source-port", type=int, default=4000)
    parser.add_argument("--homa-destination-port", type=int, default=4000)
    args = parser.parse_args()

    control_type = "resend" if args.resend else (
        "need-ack" if args.need_ack else None)
    frame = build_frame(args.family, args.source_ip, args.destination_ip,
                        args.source_mac, args.destination_mac, args.invalid,
                        args.zero_checksum, args.data, control_type,
                        args.homa_source_port, args.homa_destination_port)
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                               socket.htons(0x0003))
    try:
        raw_socket.bind((args.interface, 0))
        raw_socket.send(frame)
    finally:
        raw_socket.close()


if __name__ == "__main__":
    main()