#!/usr/bin/python3

"""
Analyzes throughput of message arrivals in a timetrace.
Usage: tput.py [tt_file]

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

if len(sys.argv) == 2:
    f = open(sys.argv[1])
elif len(sys.argv) == 1:
    f = sys.stdin
else:
    print("Usage: %s [tt_file]" % (sys.argv[0]))
    sys.exit(1)

# Info for each RPC, keyed by id:
# start: time offset 0 received
# end: time last packet received
# offset: offset of the last packet
rpcs = {}

# For each core, time of the last trace record seen, if it was a
# gro_receive, otherwise no entry.
last_gro = {}

# Time gap between gro_receive traces that are consecutive in trace
# for a given core
gaps = []

for line in f:
    match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\]', line)
    if not match:
        continue
    time = float(match.group(1))
    core = match.group(2)

    match = re.match('.*homa_gro_receive got packet .* id ([0-9]+), '
            'offset ([0-9]+)', line)
    if match:
        id = match.group(1)
        offset = int(match.group(2))
        if not id in rpcs:
            rpcs[id] = {'offset': 0}
        if offset == 0:
            rpcs[id]['start'] = time
            rpcs[id]['offset'] = 0
        else:
            rpcs[id]['end'] = time
            if offset > rpcs[id]['offset']:
                rpcs[id]['offset'] = offset
        if core in last_gro:
            gap = time - last_gro[core]
            if gap < 1.0:
                gaps.append(gap)
        last_gro[core] = time
    else:
        if core in last_gro:
            del last_gro[core]

total_bytes = 0
total_time = 0
tputs = []
for id in rpcs:
    if (not 'start' in rpcs[id]) or (not 'end' in rpcs[id]):
        continue
    if rpcs[id]['offset'] < 300000:
        continue
    bytes = rpcs[id]['offset'] - 700
    time = rpcs[id]['end'] - rpcs[id]['start']
    tput = bytes*8.0/time/1000
    tputs.append(tput)
    total_bytes += bytes
    total_time += time

tputs.sort();
print("Messages >= 300KB %d" % (len(tputs)))
print("Minimum tput: %4.1f Gbps" % (tputs[0]))
print("Median tput:  %4.1f Gbps" % (tputs[len(tputs)//2]))
print("P90 tput:     %4.1f Gbps" % (tputs[len(tputs)*9//10]))
print("P99 tput:     %4.1f Gbps" % (tputs[len(tputs)*99//100]))
print("Maximum tput: %4.1f Gbps" % (tputs[-1]))
print("Average tput: %4.1f Gbps" % (total_bytes*8.0/total_time/1000))


gaps.sort();
print("\nAdjacent homa_gro_receive traces within 1 us: %d" % (len(gaps)))
print("Minimum gap: %5.3f usec" % (gaps[0]))
print("Median gap:  %5.3f usec" % (gaps[len(gaps)//2]))
print("P90 gap:     %5.3f usec" % (gaps[len(gaps)*9//10]))
print("P99 gap:     %5.3f usec" % (gaps[len(gaps)*99//100]))
print("Maximum gap: %5.3f usec" % (gaps[-1]))
print("Average gap: %5.3f usec" % (sum(gaps)/len(gaps)))