#!/usr/bin/env python

# Copyright (c) 2019 Stanford University
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
Compute service times for RPCs from a server-side trace.
Usage: service.py [tt_file]

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

min = 1000000
min_id = ""
max = 0
max_id = ""
times = []

# Keys are ids, values are corresponding service start times for RPCs
start_times = {}

# For each id, extra time before first call to homa_pkt_rcv
rcv_lag = {}

# For each id, extra time before server thread wakes up
wakeup_lag = {}

# For each id, the time when homa_ioc_recv finishes
finish = {}

# For each id, extra time to finish homa_ioc_recv
finish_lag = {}

# For each id, extra time to finish homa_ioc_recv
xmit_lag = {}

# For each id, time of last packet reception by mlx interrupt handler
interrupt = {}

# For each id, sum of gaps in interrupt handler
interrupt_lag = {}

# For each id, lag in time when mlx interrupt handler received the last packet
last_packet_lag = {}

# For each id, the last time Homa received a data packet
protocol = {}

# For each id, sum of gaps in Homa packet receipt
protocol_lag = {}

# For each id, total # of packets received by mlx under that id
packets = {}

for line in f:
    match = re.match(' *([0-9.]+) us .*mlx received packet, id ([0-9]+), .* type 20,',
            line)
    if match:
        id = match.group(2)
        time = float(match.group(1))
        if not id in start_times:
            start_times[id] = time
        if id in interrupt:
            if interrupt_lag[id] > 1000:
                print("High interrupt lag for id %s at time %.3f: %.1f" % (id, time, interrupt_lag[id]))
            lag = time - interrupt[id] - .45
            if lag > 0:
                interrupt_lag[id] += lag
        else:
            interrupt_lag[id] = -8.7
        interrupt[id] = time
        if id in packets:
            packets[id] += 1
        else:
            packets[id] = 1

    match = re.match(' *([0-9.]+) us .*mlx5e_xmit starting, id ([0-9]+), .* type 20.',
            line)
    if match:
        id = match.group(2)
        time = float(match.group(1))
        if id in start_times:
            elapsed = time - start_times[id]
            if (id in finish):
                lag = time - finish[id] - 14.8
                # print("xmit lag for id %s: %.1f (elapsed %.1f, finish %.1f)" % (
                    # id, lag, elapsed, finish[id]))
                if lag < 0:
                    lag = 0.0
                xmit_lag[id] = lag

            total_lag = time - start_times[id] - 76.2
            times.append(elapsed)
            if elapsed < min:
                min = elapsed
                min_id = id
                # print("New min %.1f: id %s, start %.1f, end line: %s" % (min,
                      # min_id, start_times[id], line))
            if elapsed > max:
                max = elapsed
                max_id = id
            print("%s %.2f" % (id, elapsed))

            lag = interrupt[id] - start_times[id] - 35.3
            if lag < 0:
                lag = 0
            last_packet_lag[id] = lag

            del start_times[id]
            if id in interrupt:
                del interrupt[id]
            if id in finish:
                del finish[id]
            if id in protocol:
                del protocol[id]

            if (id in interrupt_lag) and (interrupt_lag[id] > 200):
                print("High interrupt lag for id %s: %.1f, time %.3f" % (id, interrupt_lag[id], time))
     

    match = re.match(' *([0-9.]+) us .*Incoming packet .*, id ([0-9]+), type 20',
            line)
    if match:
        id = match.group(2)
        time = float(match.group(1))
        if (not id in rcv_lag) and (id in start_times):
            lag = time - start_times[id] - 8.7
            # print("receive lag for id %s: %.1f" % (id, lag))
            if lag < 0:
                # print("homa_ioc_rcv faster than 'min': id %s, %.1f us" % (
                #      id, lag))
                lag = 0.0
            rcv_lag[id] = lag

    match = re.match(' *([0-9.]+) us .*message woke up, id ([0-9]+)',
            line)
    if match:
        id = match.group(2)
        time = float(match.group(1))
        if (not id in wakeup_lag) and (id in start_times):
            lag = time - start_times[id] - 43.3
            # print("wakeup lag for id %s: %.1f" % (id, lag))
            if lag < 0:
                lag = 0.0
            wakeup_lag[id] = lag

    match = re.match(' *([0-9.]+) us .*homa_ioc_recv finished, id ([0-9]+)',
            line)
    if match:
        id = match.group(2)
        time = float(match.group(1))
        if (not id in finish_lag) and (id in wakeup_lag):
            finish[id] = time
            lag = time - start_times[id] - 61.3 - wakeup_lag[id]
            # print("finish lag for id %s: %.1f" % (id, lag))
            if lag < 0:
                lag = 0.0
            finish_lag[id] = lag

    match = re.match(' *([0-9.]+) us .*Incoming packet from.*, id ([0-9]+), type 20',
            line)
    if match:
        id = match.group(2)
        time = float(match.group(1))
        if id in protocol:
            protocol_lag[id] += time - protocol[id] - .42
        else:
            protocol_lag[id] = -2.9
        protocol[id] = time

# Discard data for any RPCs that haven't received the right number of packets.
counts = packets.values()
counts.sort()
correct_count = counts[len (counts)//2]
for id in packets:
    if packets[id] != correct_count:
        print("Discarding id %s: bad packet count %d (expected %d)" % (id,
                packets[id], correct_count))
        if id in rcv_lag:
            del rcv_lag[id]
        if id in wakeup_lag:
            del wakeup_lag[id]
        if id in finish_lag:
            del finish_lag[id]
        if id in xmit_lag:
            del xmit_lag[id]
        if id in interrupt_lag:
            del interrupt_lag[id]
        if id in last_packet_lag:
            del last_packet_lag[id]
        if id in protocol_lag:
            del protocol_lag[id]

average_lag = sum(times)/len(times) - min
if average_lag == 0:
   average_lag = 0.00001
average_rcv_lag = sum(rcv_lag.values())/len(rcv_lag)
average_wakeup_lag = sum(wakeup_lag.values())/len(wakeup_lag)
average_finish_lag = sum(finish_lag.values())/len(finish_lag)
average_xmit_lag = sum(xmit_lag.values())/len(xmit_lag)
average_interrupt_lag = sum(interrupt_lag.values())/len(interrupt_lag)
average_last_packet_lag = sum(last_packet_lag.values())/len(last_packet_lag)
average_protocol_lag = sum(protocol_lag.values())/len(protocol_lag)

times.sort()
print("%d completed RPCs, min %.1f us (%s), P50 %.1f us, max %.1f us (%s)" % (
        len(times), min, min_id, times[len(times)//2], max, max_id))

print("wakeup lag:              %5.1f (%4.1f%%)" % (average_wakeup_lag,
        100.0* average_wakeup_lag/average_lag))
print("    rcv_pkt lag:         %5.1f (%4.1f%%)" % (average_rcv_lag,
        100.0* average_rcv_lag/average_lag))
print("    interrupt gaps:      %5.1f (%4.1f%%)" % (average_interrupt_lag,
        100.0* average_interrupt_lag/average_lag))
print("    last interrupt lag:  %5.1f (%4.1f%%)" % (average_last_packet_lag,
        100.0* average_last_packet_lag/average_lag))
print("    protocol gaps:       %5.1f (%4.1f%%)" % (average_protocol_lag,
        100.0* average_protocol_lag/average_lag))
print("finish lag:              %5.1f (%4.1f%%)" % (average_finish_lag,
        100.0* average_finish_lag/average_lag))
print("xmit lag:                %5.1f (%4.1f%%)" % (average_xmit_lag,
        100.0* average_xmit_lag/average_lag))
print("Average total lag:       %5.1f" % (average_lag))