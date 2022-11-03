#!/usr/bin/python3

"""
Analyzes the rate at which data packets are transmitted in a given timetrace
(useful in situations where the uplink should be fully utilized, but isn't)

Usage: ttxmit.py [--verbose] [--gbps n] [trace]

If no timetrace file is given, this script reads timetrace info from stdin.
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

# First and last times in trace
first_time = -1
last_time = 0

# Time when next packet should be transmitted to maintain line rate
next_time = -1

# Each entry in this list corresponds to a "gap" (where a packet was
# sent later than expected); the value is the length of the gap (us).
gaps = []

# Number of cores with active calls to ip_queue_xmit
num_active = 0

# Dictionary indexed by core name; existing elements are the cores with
# active ip_queue_xmit calls. Value is time when ip_queue_xmit was
# invoked.
active_cores = {}

# Dictionary indexed by RPC id; value is number of bytes that have been
# transmitted for that RPC (i.e. ip_queue_xmit has returned).
rpc_xmitted = {}

# List of elapsed times in ip_queue_xmit
xmit_times = []

# For each integer value, the number times ip_queue_xmit was invoked
# with that many other concurrent calls in progress.
xmit_concurrency = []

# The most recent times when ip_queue_xmit was invoked and returned.
last_invoke = -1
last_return = -1

# Lists of elapsed times in ip_queue_xmit, when only one call was active
# at a time, and when other concurrent calls overlapped the one in
# question.
no_overlap_times = []
overlap_times = []

# Last time when num_active became 0.
last_idle = -1

# Records info about gaps of time when no ip_queue_xmit calls were
# active. Each key is the offset of the packet transmitted just after
# the gap; value is a list of gap lengths that occurred for that offset.
idle_gaps = {}

# Total idle time in gaps longer than long_idle_threshold
long_idle_threshold = 10
long_idle_time = 0

total_pkts = 0
total_bytes = 0
max_pkt_len = 0

for line in f:
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] ',
            line)
    if not match:
        continue

    time = float(match.group(1))
    core = match.group(3)

    match = re.match('.*calling ip_queue_xmit.* id ([0-9]+)', line)
    if match:
        id = int(match.group(1))
        last_invoke = time;
        while len(xmit_concurrency) <= num_active:
            xmit_concurrency.append(0)
        xmit_concurrency[num_active] += 1
        if not id in rpc_xmitted:
            rpc_xmitted[id] = 0
        offset = rpc_xmitted[id]
        if  num_active == 0 and last_idle != -1:
            idle = time - last_idle
            if not offset in idle_gaps:
                idle_gaps[offset] = []
            idle_gaps[offset].append(idle)
            if (idle >= long_idle_threshold):
                long_idle_time += idle
                if options.verbose:
                    print("%9.3f: Long idle time (%.1f us), id %d, "
                            "offset %d" % (time, idle, id, offset))
        num_active += 1
        active_cores[core] = time

    match = re.match('.*Finished queueing packet: rpc id ([0-9]+), '
            'offset ([0-9]+), len ([0-9]+)', line)
    if match:
        id = int(match.group(1))
        offset = int(match.group(2))
        pkt_len = int(match.group(3))
        rpc_xmitted[id] = offset + pkt_len

        if core in active_cores:
            my_start = active_cores[core]
            elapsed = time - my_start
            if options.verbose:
                print("%9.3f: ip_queue_xmit returned for id %d, elapsed %0.1f, "
                        "active %d" % (time, id, elapsed, num_active-1))
            if (last_invoke > my_start) or (last_return > my_start) \
                    or (num_active > 1):
                no_overlap_times.append(elapsed)
            else:
                overlap_times.append(elapsed)
            xmit_times.append(elapsed)
            del active_cores[core]
            num_active -= 1;
            if num_active == 0:
                last_idle = time;

        if first_time < 0:
            first_time = time
        last_time =  time
        total_pkts += 1
        total_bytes += pkt_len
        if pkt_len > max_pkt_len:
            max_pkt_len = pkt_len

        xmit_us = (pkt_len * 8.0)/(1000 * options.gbps)
        if next_time == -1:
            next_time = time + xmit_us
        else:
          if (time <= next_time):
              next_time += xmit_us
          else:
              gaps.append(time - next_time)
              next_time = time + xmit_us

gaps = sorted(gaps)
gap_time = sum(gaps)

xmit_times = sorted(xmit_times)
overlap_times = sorted(overlap_times)
no_overlap_times = sorted(no_overlap_times)
total_idle = 0
for offset in idle_gaps:
    idle_gaps[offset] = sorted(idle_gaps[offset])
    total_idle += sum(idle_gaps[offset])

total_time = last_time - first_time

print("Total packets: %d" % (total_pkts))
print("Total bytes: %.1f MB" % (total_bytes/1e06))
avg_tput =  total_bytes*8.0/(total_time)/1000
print("Average throughput: %.1f Gbps" % (avg_tput))
xmit_time = total_bytes*8.0/(options.gbps*1000)
print("Lost xmit time: %.1f us (%.1f%%)" % (total_time - xmit_time,
        100*(total_time - xmit_time)/total_time))
print("Serialization time for %d-byte packets: %.1f us" % (max_pkt_len,
        (max_pkt_len * 8.0)/(1000 * options.gbps)))
print("ip_queue_xmit time: min %.1f us, P50 %.1f us, P90 %.1f us, "
        "P99 %.1f us" % (xmit_times[0], xmit_times[len(xmit_times)//2],
        xmit_times[90*len(xmit_times)//100],
        xmit_times[99*len(xmit_times)//100]))
print("\nTotal idle time (no active ip_queue_xmit calls: %.1f us "
        "(%.1f%%)" % (total_idle, 100.0*total_idle/total_time))
print("Total time in idle gaps > %d us: %0.1f us (%.1f%%)" % (
        long_idle_threshold, long_idle_time, 100.0*long_idle_time/total_time))
print("Offset   Total Idle      Avg Gap    P50    P90    P99")
for offset in sorted(idle_gaps.keys()):
    gaps = idle_gaps[offset]
    total = sum(gaps)
    avg = total/len(gaps)
    print("%6d %7.1f (%4.1f%%)    %6.2f %6.2f %6.2f %6.2f" % (offset,
            total, 100.0*total/total_time, avg, gaps[len(gaps)//2],
            gaps[9*len(gaps)//10], gaps[99*len(gaps)//100]))
if 0:
    print("Idle intervals: min %.1f us, P50 %.1f us, P90 %.1f us, "
            "P99 %.1f us" % (idle_gaps[0], idle_gaps[len(idle_gaps)//2],
            idle_gaps[90*len(idle_gaps)//100], idle_gaps[99*len(idle_gaps)//100]))
    print("Idle time CDF:")
    sum = 0
    i = 0
    for target in range(10, 90, 10):
        while i < len(idle_gaps):
          sum += idle_gaps[i]
          i += 1
          pct = 100.0*sum/total_idle
          if pct >= target:
              print("    %2d%% of idle time in gaps >= %4.1f us" % (100 - target,
                      idle_gaps[i-1]))
              break
print("\nSlow xmits: %d (%.1f%%); P50 %.1f us, P90 %.1f us, P99 %.1f us" % (
        len(gaps), 100.0*len(gaps)/total_pkts, gaps[50*len(gaps)//100],
        gaps[90*len(gaps)//100], gaps[99*len(gaps)//100]))
print("Total xmit delay %.1f us (%.1f%%)" % (gap_time,
        100.0*gap_time/(total_time)))
print("Concurrent calls when ip_queue_xmit invoked:")
for i in range(0, len(xmit_concurrency)):
    print("  %d: %5d (%4.1f%%)" % (i, xmit_concurrency[i],
            100.0*xmit_concurrency[i]/total_pkts))