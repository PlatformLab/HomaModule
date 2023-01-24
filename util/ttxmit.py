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

# Total number of RPCs that completed during the trace.
total_rpcs = 0

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

# Total amount of data transmitted.
total_bytes = 0

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

# Holds the duration of all the gaps that were caused by lack of grants.
grant_gaps = []

# One entry for each period of time when there were no active RPCS.
# Each entry is a list <duration, start, end, id>: duration is the length
# of the gap, start and end give the range, and id identifies the RPC that
# ended the gap.
inactive_gaps = []

# Keys are RPC ids; each value is the total number of bytes granted for
# that RPC (i.e. the index of the first byte not yet granted).
granted = {}

# Keys are RPC ids, values are meaningless. If an entry is present, it
# means that the most recently transmitted packet used up all of the
# granted bytes, so the next packet will have to wait for a grant.
needs_grant = {}

for line in f:
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
            'calling .*_xmit: skb->len ([0-9]+), .* id ([0-9]+), '
            'offset ([0-9]+)', line)
    if match:
        time = float(match.group(1))
        core = match.group(3)
        length = int(match.group(4))
        id = match.group(5)
        offset = int(match.group(6))

        total_packets += 1
        total_bytes += length
        if packet_size < length:
            packet_size = length

        if (idle_time < time) and (len(active_rpcs) > 0):
            gap_length = time - idle_time
            gaps.append([gap_length, idle_time, time, len(active_rpcs), id, offset])
            gap_usecs += gap_length
            if gap_length >= long_gap:
                long_gaps += 1
            if id in needs_grant:
                grant_gaps.append(gap_length)

        if (id in granted) and ((offset + length) >= granted[id]):
            needs_grant[id] = True
        else:
            needs_grant.pop(id, None)

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
            total_rpcs += 1
        else:
            active_rpcs[id] = [time, id]

        if len(active_rpcs) == 0:
            active_usecs += idle_time - active_start
            active_end = idle_time

    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
            'processing grant for id ([0-9]+), offset ([0-9]+)', line)
    if match:
        id = match.group(4)
        offset = int(match.group(5))
        granted[id] = offset

    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
            'data copied into request .* id ([0-9]+), .* unscheduled ([0-9]+)',
            line)
    if match:
        id = match.group(4)
        unsched = int(match.group(5))
        granted[id] = unsched

if len(active_rpcs):
    active_usecs += time - active_start

print("RPC active time:               %9.1f us (%.1f%% of elapsed time)" % (
        active_usecs, 100.0*active_usecs/time))
print("Total xmit gaps:               %9.1f us (%.1f%% of active time)" % (
        gap_usecs, 100.0*gap_usecs/active_usecs))
print("Average xmit gap:              %9.1f us" % (gap_usecs/total_packets))
grant_gap_usecs = sum(grant_gaps)
print("Gaps caused by delayed grants: %9.1f us (%.1f%% of all gap time)" % (
        grant_gap_usecs, 100.0*grant_gap_usecs/gap_usecs))
print("%d data packets (%.1f%% of all packets) were delayed waiting for grants"
        % (len(grant_gaps), 100*len(grant_gaps)/total_packets))
print('%d data packets (%.1f%% of all packets) were delayed by gaps '
                '>= %.1f us' % (long_gaps, 100*long_gaps/ total_packets,
                long_gap))
print("Transmit rate when RPCs active: %.1f Gbps" % (
        total_bytes*8.0/(active_usecs*1e03)))
if (total_rpcs > 0):
    print("Average delay/RPC caused by missing grants: %.1f usec" % (
            grant_gap_usecs/total_rpcs))

gaps = sorted(gaps, key=itemgetter(0), reverse=True)
print("\nLongest gaps:")
count = 0
for gap in gaps:
    print("%9.3f: gap of %5.1f us (starting at %9.3f), id %s, offset %d" % (
            gap[2], gap[0], gap[1], gap[4], gap[5]))
    count += 1
    if count >= 10:
        break

gaps.reverse()
print("\nGap CDF (% of total gap time in gaps <= given size):")
print("Percent    Gap")
pctl = 0
total_usecs = 0
for gap in gaps:
    total_usecs += gap[0]
    if (total_usecs >= pctl*gap_usecs/100):
        print("%5d   %5.1f us" % (pctl, gap[0]))
        pctl += 10
if pctl <= 100:
    print("%5d   %5.1f us" % (100, gaps[-1][0]))

if len(grant_gaps) > 0:
    grant_gaps = sorted(grant_gaps)
    print("\nCDF of gaps caused by grants (% of total grant gap time "
            "in gaps <= given size):")
    print("Percent    Gap")
    pctl = 0
    total_usecs = 0
    for gap in grant_gaps:
        total_usecs += gap
        if (total_usecs >= pctl*grant_gap_usecs/100):
            print("%5d   %5.1f us" % (pctl, gap))
            pctl += 10
    if pctl <= 100:
        print("%5d   %5.1f us" % (100, grant_gaps[-1]))

if inactive_gaps:
    inactive_gaps = sorted(inactive_gaps, key=itemgetter(0), reverse=True)
    print("\nLongest intervals with no active RPCs:")
    count = 0
    for gap in inactive_gaps:
        print("%9.3f: %5.1f us starting at %9.3f, ending with id %s" % (
                gap[2], gap[0], gap[1], gap[3]))
        count += 1
        if count >= 10:
            break