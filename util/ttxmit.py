#!/usr/bin/python3

"""
Analyzes packet transmissions in a timetrace to find gaps where the
uplink was unnecessarily idle.

Usage: ttxmit.py [--verbose] [--gbps n] [trace]

If no timetrace file is given, this script reads timetrace info from stdin.
"""

from __future__ import division, print_function
from glob import glob
from optparse import OptionParser
import math
from operator import itemgetter
import os
import re
import string
import sys
from statistics import median

# Parse command line options
parser = OptionParser(description=
        'Read a timetrace and output information about gaps in data packet '
        'transmissions.',
        usage='%prog [options] [trace]',
        conflict_handler='resolve')
parser.add_option('--verbose', '-v', action='store_true', default=False,
        dest='verbose',
        help='print lots of output')
parser.add_option('--gbps', type='int', dest='gbps', default=25,
        help='network speed in Gbps')

(options, extra) = parser.parse_args()
f = sys.stdin
if len(extra) > 0:
    f = open(extra[0])
    if len(extra) > 1:
      print("Unrecognized argument %s" % (extra[1]))
      exit(1)

# Time when all of the output packets presented to the NIC will have
# been fully transmitted.
idle_time = 0

# Will eventually hold the amount of data in a full-sized output
# packet (before GSO chops it up).
packet_size = 1000

# Dictionary holding one entry for each RPC that is currently active
# (some of its bytes have been transmitted, but not all). Index is
# RPC id, value is a list <time, offset> giving time when most recent
# packet was transmitted for the RPC, offset of the packet's data.
active_rpcs = {}

# Total time when there was at least one active RPC.
active_usecs = 0

# Total time in all gaps
gap_usecs = 0

# Time when len(total_active_time) went from 0 to 1.
active_start = 0

# Time when len(total_active_time) become 0.
active_end = 0

# Total number of data packets sent.
total_packets = 0

# Total number of packets that experienced gaps >= long_gap.
long_gaps = 0

# Threshold length for a gap to be considered "long".
long_gap = 2.0

# One entry for each period of time when the uplink was idle yet there
# were active outgoing RPCs. Value is a list <duration, start, end, active, id,
# offset>: duration is the length of the gap, start end end give the range of
# the idle period, active counts the number of active RPCs at the end of the
# interval, and id and offset identify the packet whose transmission ended
# the gap.
gaps = []

# One entry for each period of time when there were no active RPCS.
# Each entry is a list <duration, start, end, id>: duration is the length
# of the gap, start and end give the range, and id identifies the RPC that
# ended the gap.
inactive_gaps = []

for line in f:
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
            'calling ip_queue_xmit: skb->len ([0-9]+), .* id ([0-9]+), '
            'offset ([0-9]+)', line)
    if not match:
        continue

    time = float(match.group(1))
    core = match.group(3)
    length = int(match.group(4))
    id = int(match.group(5))
    offset = int(match.group(6))

    total_packets += 1
    if packet_size < length:
        packet_size = length

    if (idle_time < time) and (len(active_rpcs) > 0):
        gap_length = time - idle_time
        gaps.append([gap_length, idle_time, time, len(active_rpcs), id, offset])
        gap_usecs += gap_length
        if gap_length >= long_gap:
            long_gaps += 1

    if len(active_rpcs) == 0:
        if idle_time < time:
            active_start = time
            if active_end != 0:
                inactive_gaps.append([time - active_end, active_end, time, id])
        else:
            active_start = idle_time

    xmit_time = (length * 8)/(options.gbps * 1000)
    if (idle_time < time):
        idle_time = time + xmit_time
    else:
        idle_time += xmit_time

    if length < packet_size:
        active_rpcs.pop(id, None)
    else:
        active_rpcs[id] = [time, id]

    if len(active_rpcs) == 0:
        active_usecs += idle_time - active_start
        active_end = idle_time

if len(active_rpcs):
    active_usecs += time - active_start

print("RPC active time: %9.1f us (%.1f%% of elapsed time)" % (active_usecs,
        100.0*active_usecs/time))
print("Total xmit gaps: %9.1f us (%.1f%% of active time)" % (gap_usecs,
        100.0*gap_usecs/active_usecs))
print('%d data packets (%.1f%% of all packets) were delayed by gaps '
                '>= %.1f us' % (long_gaps, 100*long_gaps/ total_packets,
                long_gap))

gaps = sorted(gaps, key=itemgetter(0), reverse=True)
print("\nLongest gaps:")
count = 0
for gap in gaps:
    print("%9.3f: gap of %5.1f us (starting at %9.3f), id %d, offset %d" % (
            gap[2], gap[0], gap[1], gap[4], gap[5]))
    count += 1
    if count >= 10:
        break

print("\nGap CDF (% of total gap time in gaps > given size):")
print("Percent    Gap")
pctl = 0
total_usecs = 0
for gap in gaps:
    total_usecs += gap[0]
    if (total_usecs >= pctl*gap_usecs/100):
        print("%5d   %5.1f us" % (pctl, gap[0]))
        pctl += 10

if inactive_gaps:
    inactive_gaps = sorted(inactive_gaps, key=itemgetter(0), reverse=True)
    print("\nLongest intervals with no active RPCs:")
    count = 0
    for gap in inactive_gaps:
        print("%9.3f: %5.1f us starting at %9.3f, ending with id %d" % (
                gap[2], gap[0], gap[1], gap[3]))
        count += 1
        if count >= 10:
            break