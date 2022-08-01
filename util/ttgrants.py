#!/usr/bin/python3

"""
Scans a timetrace to compute grant lag: how long it takes after a
grant is issued for the granted packet to arrive. Also computes
statistics on when grants arrive compared to when they are needed
to transmit at full bandwidth.
Usage: ttgrant.py [tt_file]

The existing timetrace is in tt_file (or stdin in tt_file is omitted).
"""

from __future__ import division, print_function
from glob import glob
from optparse import OptionParser
import math
import os
import re
import string
import sys
from statistics import median

def percentile(list, pct, format):
    """
    Finds the element of list corresponding to a given percentile pct
    (0 is first, 100 or more is last), formats it according to format,
    and returns the result. Returns "N/A" if the list is empty.
    """
    if len(list) == 0:
        return "N/A"
    i = int(pct*len(list)/100)
    if i >= len(list):
        i = len(list) - 1
    return format % (list[i])

verbose = False
if (len(sys.argv) >= 2) and (sys.argv[1] == "--verbose"):
  verbose = True
  sys.argv.pop(1)
if len(sys.argv) == 2:
    f = open(sys.argv[1])
elif len(sys.argv) == 1:
    f = sys.stdin
else:
    print("Usage: %s [--verbose] [tt_file]" % (sys.argv[0]))
    sys.exit(1)

# Network link speed in Gbps.
gbps = 25

# Collects all the observed grant latencies (time from sending grant
# to receiving first data packet enabled by grant), in microseconds
latencies = []

# Keys are RPC ids. Each value is a list of lists, one per outstanding
# grant, where each sublist consists of an <offset, time> pair identifying
# one outgoing grant.
out_grants = {}

# Eventually holds the largest amount of data that can be sent in one packet.
packet_size = 1000

# Keys are RPC ids; each value is a list of lists, one per grant received
# for that RPC, and each entry is an <offset, time> pair describing that
# grant.
in_grants = {}

# Keys are RPC ids; each value is a list of lists, one per data packet
# sent for that RPC, and each entry is an <offset, time> pair describing
# that data packet.
out_data = {}

for line in f:
    # Collect info about outgoing grants
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
          'sending grant for id ([0-9.]+), offset ([0-9.]+)', line)
    if match:
        time = float(match.group(1))
        id = int(match.group(4))
        offset = int(match.group(5))
        if not id in out_grants:
            out_grants[id] = []
        out_grants[id].append([offset, time])
        # print("%9.3f: grant offset %d for id %d" % (time, offset, id))

    # Collect info about incoming data packets
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
          'incoming data packet, id ([0-9]+), .*, offset ([0-9.]+)', line)
    if match:
        time = float(match.group(1))
        id = int(match.group(4))
        offset = int(match.group(5))

        # Update grant latencies
        if not id in out_grants:
            continue
        g = out_grants[id]
        for i in range(len(g)):
            if g[i][0] < (offset + packet_size):
                if verbose:
                    print("%9.3f: grant lag %.1f us, id %d, offset %d" % (time,
                            time - g[i][1], id, offset))
                latencies.append(time - g[i][1])
                g.pop(i)
                break

    # Collect info about incoming grants
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
            'processing grant for id ([0-9]+), offset ([0-9]+)', line)
    if match:
        time = float(match.group(1))
        id = int(match.group(4))
        offset = int(match.group(5))
        if not id in in_grants:
            if not id in out_data:
                # The trace doesn't include any outgoing data packets
                continue
            in_grants[id] = []
        in_grants[id].append([offset, time])
        # print("%9.3f: incoming grant for id %d, offset %d" % (
        #         time, id, offset))

    # Collect info about outgoing data packets (and also the packet size)
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
            'calling ip_queue_xmit: skb->len ([0-9]+).* id ([0-9]+), '
            'offset ([0-9]+)', line)
    if match:
        time = float(match.group(1))
        size = int(match.group(4))
        id = int(match.group(5))
        offset = int(match.group(6))
        if size > packet_size:
            packet_size = size
          # print("Setting packet size to %d" % (packet_size))
        if not id in out_data:
            if offset != 0:
                # The trace doesn't include all outgoing data packets
                continue
            out_data[id] = []
        out_data[id].append([offset, time])
        # print("%9.3f: outgoing data for id %d, offset %d" % (
        #         time, id, offset))

# Get statistics about the time from first data packet to first
# incoming grant
first_grants = []
for id in out_data:
    if not id in in_grants:
        continue
    delay = in_grants[id][0][1] - out_data[id][0][1]
    first_grants.append(in_grants[id][0][1] - out_data[id][0][1])
    # print("Grant lag for id %d: %.1f us" % (id, first_grants[-1]))

# Time to transmit a full-size packet, in microseconds.
xmit_time = (packet_size * 8)/(gbps * 1000)
print("Data bytes per packet: %d" % (packet_size))
print("Packet xmit time: %.1f us" % (xmit_time))

# Collect info for all incoming grants about how much additional data
# is authorized by each grant. We can't do this for the first grant for
# each message, because we don't know how much unscheduled data there is.
in_deltas = []
for key in in_grants:
    rpc_grants = in_grants[key]
    for i in range(1, len(rpc_grants)):
        delta = rpc_grants[i][0] - rpc_grants[i-1][0]
        if (delta < 0) and verbose:
            print("%9.3f: out of order grant for id %s: (%d, then %d)" % (
                    rpc_grants[i][1], key, rpc_grants[i-1][0],
                    rpc_grants[i][0]))
        in_deltas.append(delta)

# Compute lag in incoming grants (when the grant arrives relative to
# when we need it). For this, we only consider second and later grants
# for an RPC (assume the first one may be delayed by SRPT).
in_lags = []
total_lag = 0
for id in out_data:
    if not id in in_grants:
        continue
    data = out_data[id]
    grants = in_grants[id]
    # For each grant, find the last data packet that could be sent
    # without needing that grant
    d = 0
    prev_data_time = 0
    for g in range(1, len(in_grants[id])):
        grant = grants[g]
        grant_offset = grants[g-1][0]
        time = grant[1]
        if d >= len(data):
            print("Ran out of data packets for id %d" % (id))
            break
        while (data[d][0] < grant_offset) and (d < (len(data)-1)):
            prev_data_time = data[d][1]
            d += 1
        if data[d][0] < grant_offset:
            break
        lag = grant[1] - prev_data_time - xmit_time
        in_lags.append(lag)
        if (lag > 0):
            total_lag += lag
        # print("%9.3f: grant offset %d arrived for id %d, data time %9.3f" % (
        #         grant[1], grant_offset, id, prev_data_time))

latencies = sorted(latencies)
first_grants = sorted(first_grants)
in_lags = sorted(in_lags)
print("\nLatency:         time from sending grant for an incoming message")
print("                 (in homa_send_grants) to receiving first granted")
print("                 data in Homa SoftIRQ")
print("First Lag:       time from calling ip_queue_xmit for first data packet")
print("                 until receiving first grant in Homa SoftIRQ")
print("In Lag:          time when a grant arrived, relative to time when")
print("                 it was needed to send message at full bandwidth")
print("                 (skips first grant for each message)")
print("Pctile        Latency     First Lag      In Lag")
for p in [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 99, 100]:
    print("%3d         %s     %s   %s" %(p, percentile(latencies, p, "%6.1f us"),
            percentile(first_grants, p, "%6.1f us"),
            percentile(in_lags, p, "%6.1f us")))

if len(latencies) == 0:
    out_avg = "N/A"
else:
    out_avg = "%.1f us" % (sum(latencies)/len(latencies))
if len(first_grants) == 0:
    in_avg = "N/A"
else:
    in_avg = "%.1f us" %  (sum(first_grants)/len(first_grants))
if len(in_lags) == 0:
    in_lags_avg = "N/A"
else:
    in_lags_avg = "%.1f us" %  (sum(in_lags)/len(in_lags))
print("Average:    %9s     %9s   %9s" % (out_avg, in_avg, in_lags_avg))

print("\nTotal data packet xmit delays because grants were slow:\n"
        "%.1f us (%.1f%% of total elapsed time)" % (
        total_lag, 100.0*total_lag/time))

in_deltas = sorted(in_deltas)
print("\nSizes of incoming grants (additional authorized data;")
print("excludes first grant for each message)")
print("Pctile       Size")
for p in [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 99, 100]:
    print("%3d      %8s" %(p, percentile(in_deltas, p, "%d")))

if len(in_deltas) == 0:
    in_avg = "N/A"
else:
    in_avg = "%.0f" %  (sum(in_deltas)/len(in_deltas))
print("Average  %8s" % (in_avg))
