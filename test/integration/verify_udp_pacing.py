#!/usr/bin/env python3
# Measure captured UDP tunnel traffic rates and verify sustained pacing
# and burst limits for the 100 Mbit/s integration scenario.

import argparse
from collections import deque
import json
import sys

import verify_udp_pcap


WINDOW_SECONDS = 0.1
RATE_BITS_PER_SECOND = 100_000_000
MAX_RATE_BITS_PER_SECOND = RATE_BITS_PER_SECOND * 1.2
MIN_RATE_BITS_PER_SECOND = RATE_BITS_PER_SECOND * 0.7


def rate_summary(samples):
    if len(samples) < 2:
        raise ValueError("capture has too few packets for a rate measurement")
    active = deque()
    active_bytes = 0
    max_window_bytes = 0
    for timestamp, packet_bytes in samples:
        active.append((timestamp, packet_bytes))
        active_bytes += packet_bytes
        while active and timestamp - active[0][0] >= WINDOW_SECONDS:
            active_bytes -= active.popleft()[1]
        max_window_bytes = max(max_window_bytes, active_bytes)

    steady_start = samples[0][0] + WINDOW_SECONDS
    steady_end = samples[-1][0] - WINDOW_SECONDS
    if steady_end <= steady_start:
        raise ValueError("capture is too short for steady-state measurement")
    steady_bytes = sum(packet_bytes for timestamp, packet_bytes in samples
                       if steady_start <= timestamp <= steady_end)
    steady_rate = steady_bytes * 8 / (steady_end - steady_start)
    max_window_rate = max_window_bytes * 8 / WINDOW_SECONDS
    return {
        "max_100ms_mbps": round(max_window_rate / 1_000_000, 3),
        "steady_mbps": round(steady_rate / 1_000_000, 3),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Validate Homa-over-UDP pacing from an ingress capture")
    parser.add_argument("pcap")
    args = parser.parse_args()

    samples = []
    for timestamp, frame in verify_udp_pcap.read_pcap(args.pcap):
        parsed = verify_udp_pcap.parse_udp(frame)
        if parsed is None:
            continue
        verify_udp_pcap.validate_homa_packet(parsed)
        samples.append((timestamp, parsed["outer_length"] + 14))
    summary = rate_summary(samples)
    if summary["max_100ms_mbps"] * 1_000_000 > MAX_RATE_BITS_PER_SECOND:
        raise ValueError("100 ms traffic window exceeded 120 Mbit/s")
    if summary["steady_mbps"] * 1_000_000 < MIN_RATE_BITS_PER_SECOND:
        raise ValueError("steady traffic rate was below 70 Mbit/s")
    summary["packet_count"] = len(samples)
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print("pacing validation failed: %s" % error, file=sys.stderr)
        sys.exit(1)
