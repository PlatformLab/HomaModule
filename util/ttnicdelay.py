#!/usr/bin/python3

"""
This program looks for evidence suggesting that NICs are configured to
delay interrupts. It scans two timetraces for the same time interval, one
from a client and one from a server, looking for situations where the
server experiences a significant gap between two consecutive clients
even though the client transmitted them back-to-back.

Usage: ttgap.py [--verbose] [client [server]]

The "client" and "server" arguments give the names of the two timetrace
files; they default to client.tt and server.tt. One way to collect these
traces is by running "cp_node client --one-way --workload 500000" on the
client.
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

client_trace = "client.tt"
server_trace = "server.tt"
verbose = False
if (len(sys.argv) >= 2) and (sys.argv[1] == "--help"):
    print("Usage: %s [--verbose] [client_trace [server_trace]]" % (sys.argv[0]))
    sys.exit(0)
if (len(sys.argv) >= 2) and (sys.argv[1] == "--verbose"):
  verbose = True
  sys.argv.pop(1)
if len(sys.argv) >= 2:
  client_trace = sys.argv[1]
  sys.argv.pop(1)
if len(sys.argv) >= 2:
  server_trace = sys.argv[1]

# Information about each data packet sent by the client: the key has the
# form "id:offset", identifying a particular data packet. The value is
# a list of <time, gap> where time is the time when the packet was sent
# and gap is the elapsed time since the previous packet was sent.
client_packets = {}

last_xmit = 0.0
total_xmit_gap = 0.0

for line in open(client_trace):
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
            'Finished queueing packet: rpc id ([0-9]+), offset ([0-9]+)', line)
    if match:
        time = float(match.group(1))
        id = match.group(4)
        offset = match.group(5)
        key = id + ":" + offset
        gap = time-last_xmit
        if 0:
            print("%9.3f: xmit %s, gap %.1f" % (time, key, gap))
        if (offset != "0") and (gap > 10.0):
            total_xmit_gap += gap
        if last_xmit > 0:
            client_packets[id + ":" + offset] = [time, gap]
        last_xmit = time

last_recv = 0.0
total_gap = 0.0
num_gaps = 0
num_pkts = 0
last_gap_pkt = 0
gap_offsets = []

for line in open(server_trace):
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
            'homa_gro_receive got packet .* id ([0-9]+), offset ([0-9]+)', line)
    if match:
        time = float(match.group(1))
        id = int(match.group(4))
        offset = match.group(5)
        key = "%d:%s" % (id-1, offset)
        gap = time - last_recv
        last_recv = time
        if (offset != "0") and (key in client_packets):
            num_pkts += 1
            client_time, client_gap = client_packets[key]
            if (gap > 20) and (client_gap < 5):
                if verbose:
                    print("%9.3f: recv %s, gap %.1f, xmit_gap %.1f "
                            "(sent at %.3f), pkts since last gap %d" % (
                            time, key, gap, client_gap, client_time,
                            num_pkts - last_gap_pkt))
                num_gaps += 1
                total_gap += gap - client_gap
                last_gap_pkt = num_pkts
                gap_offsets.append(int(offset))

print("%d unexpected gaps over %d packets" % (num_gaps, num_pkts))
print("Total recv gap %.1f us (%.1f%% of elapsed time)" % (total_gap,
        100.0*total_gap/last_xmit))
print("Average interval between gaps: %.1f packets" % (num_pkts/num_gaps))
print("Average gap length: %.1f us" % (total_gap/num_gaps))

if verbose:
    print("Total xmit gap %.1fus (%.1f%% of elapsed time)" % (total_xmit_gap,
            100.0*total_xmit_gap/last_xmit))

if 0:
    gap_offsets = sorted(gap_offsets)
    cur_offset = -1
    count = 0
    for offset in gap_offsets:
        if offset != cur_offset:
            if cur_offset >= 0:
                print("%6d   %d" % (cur_offset, count))
            cur_offset = offset
            count = 0
        count += 1
    print("%6d   %d" % (cur_offset, count))