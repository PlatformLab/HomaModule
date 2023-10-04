#!/usr/bin/python3

# Copyright (c) 2022-2023 Stanford University
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
Scans a time trace file to analyze the lifetimes of receive buffers
(e.g. how many are active at a time, how long they live, etc.)
Usage: ttskbs.py [--threshold t] [--verbose] [file]
The --threshold option specifies a time in usecs: info will be printed
for every buffer whose lifetime is at least that long. If --verbose is
specified then start and end times are printed for each buffer.
"""

from __future__ import division, print_function
from glob import glob
from optparse import OptionParser
import math
import os
import re
import string
import sys

# Parse command line options
parser = OptionParser(description=
        'Read a timetrace and output information about lifetimes of incoming '
        'packet buffers.',
        usage='%prog [options] [trace]',
        conflict_handler='resolve')
parser.add_option('--id', type='string', dest='id', default=0,
        help='print lifetime information on a packet-by-packet basis '
        'for this RPC id')
parser.add_option('--threshold', type='float', dest='threshold', default=0,
        help='print packets with lifetimes longer than this')
parser.add_option('--verbose', '-v', action='store_true', default=False,
        dest='verbose',
        help='print lots of output')

(options, extra) = parser.parse_args()
f = sys.stdin
if len(extra) > 0:
    f = open(extra[0])
    if len(extra) > 1:
      print("Unrecognized argument %s" % (extra[1]))
      exit(1)

# Dictionary with one entry for each RPC, keyed by RPC id.
# Each entry is a dictionary keyed by offset, containing one entry for
# each packet buffer currently active for that RPC.
# Each of these entries is a dictionary with information about that packet:
# core:           core on which the packet was received.
# gro:            time when the buffer was seen by gro_receive
# softirq_start:  time when homa_softirq woke up (eventually processed buffer)
# softirq:        time when homa_softirq processed this buffer
# copy_start:     time when homa_copy_out started processing a batch of
#                 buffers containing this one
# free:           time when homa_copy_out freed this buffer
rpcs = {}

num_active = 0
max_active = 0

# List whose entries are the lifetimes of individual data packets.
lifetimes = []

# Dictionary with one entry for each core (keyed by core name); value
# is a list of lifetimes for packets received on that core.
core_lifetimes = {}

# Dictionary where keys are core ids and values are the most recent time
# homa_softirq started executing on that core.
softirq_start = {}

# Dictionary where keys are RPC ids and values are the most recent time
# homa_copy_out started copying out packets for that RPC.
copy_out_start = {}

# Dictionary where each key is an RPC ids and each value is the offset of the
# last packet for that RPC that has been copied to user space.
last_offsets = {}

earliest_time = 0
latest_time = 0

for line in f:
    match = re.match(' *([0-9.]+) us .* \[(C[0-9]+)\] (.*)', line)
    if not match:
        continue
    time = float(match.group(1))
    core = match.group(2)
    msg = match.group(3)

    match = re.match('.* id ([0-9.]+).*offset ([0-9.]+)', msg)
    if match:
        latest_time = time
        id =  match.group(1)
        offset = int(match.group(2))
        if not id in rpcs:
            rpcs[id] = {}
        rpc = rpcs[id]

        if "_gro_receive got packet" in msg:
            rpc[offset] = {"gro": time, "core": core}
            num_active += 1
            if num_active > max_active:
                max_active = num_active
            if options.verbose:
                print("%9.3f: allocate %s:%d (%d now active)" % (
                        time, id, offset, num_active))
            if earliest_time == 0:
                earliest_time = time

        if offset not in rpc:
            continue
        pkt = rpc[offset]

        if "incoming data packet" in msg:
            pkt["softirq_start"] = softirq_start[core]
            pkt["softirq"] = time

    if "homa_softirq: first packet" in msg:
        softirq_start[core] = time

    match = re.match('.*starting copy to user space for id ([0-9.]+)', msg)
    if match:
        copy_out_start[match.group(1)] = time

    match = re.match('.*finished copying .* last offset ([0-9.]+)', msg)
    if match:
        offset = int(match.group(1))
        last_offsets[id] = offset

    match = re.match('.*finished freeing .* for id ([0-9.]+)', msg)
    if match:
        id = match.group(1)
        if (not id in rpcs) or (not id in last_offsets):
            continue
        rpc = rpcs[id]
        for offset, pkt in rpc.items():
            if (offset <= last_offsets[id]) and ("free" not in pkt):
                pkt["copy_start"] = copy_out_start[id]
                pkt["free"] = time
                lifetime = time - pkt["gro"]
                lifetimes.append(lifetime)
                pkt_core = pkt["core"]
                if not pkt_core in core_lifetimes:
                    core_lifetimes[pkt_core] = []
                core_lifetimes[pkt_core].append(lifetime)
                num_active -= 1
                if options.verbose:
                    print("%9.3f: free %s:%d  after %.1f us (%d now active)" %
                            (time, id, offset, lifetime, num_active))
                elif (options.threshold > 0) and (lifetime >= options.threshold):
                    print("%9.3f: packet %s:%d lifetime %5.1f usec "
                            "(alloced on %s at %9.3f)" % (time,
                            id, offset, lifetime, pkt_core, pkt["gro"]))

if len(lifetimes) == 0:
    print("No packets found with complete life cycle")
    exit(1)

print("Maximum number of active skbs: %d" % (max_active))
print("Total lifetimes: %d" % (len(lifetimes)))

# Lists of elapsed times from one event to another:
gro_to_softirq_start     = []
softirq_start_to_softirq = []
softirq_to_copy_start    = []
copy_start_to_free       = []

for id, rpc in rpcs.items():
    for offset, pkt in rpc.items():
        if (not "softirq_start" in pkt) or (not "softirq" in pkt) \
                or (not "copy_start" in pkt) or (not "free" in pkt):
            continue
        gro_to_softirq_start.append(pkt["softirq_start"] - pkt["gro"])
        softirq_start_to_softirq.append(pkt["softirq"] - pkt["softirq_start"])
        softirq_to_copy_start.append(pkt["copy_start"] - pkt["softirq"])
        copy_start_to_free.append(pkt["free"] - pkt["copy_start"])
gro_to_softirq_start = sorted(gro_to_softirq_start)
softirq_start_to_softirq = sorted(softirq_start_to_softirq)
softirq_to_copy_start = sorted(softirq_to_copy_start)
copy_start_to_free = sorted(copy_start_to_free)
lifetimes = sorted(lifetimes)

print("                                                      Duration (usecs)")
print("Phase of packet lifetime                          P10    P50    P90     Max")
print("---------------------------------------------------------------------------")
l = len(gro_to_softirq_start)
print("GRO -> homa_softirq invocation:                %6.1f %6.1f %6.1f %7.1f" % (
        gro_to_softirq_start[10*l//100],
        gro_to_softirq_start[50*l//100],
        gro_to_softirq_start[90*l//100],
        gro_to_softirq_start[l-1]))
l = len(softirq_start_to_softirq)
print("homa_softirq_invocation -> SoftIRQ for packet  %6.1f %6.1f %6.1f %7.1f" % (
        softirq_start_to_softirq[10*l//100],
        softirq_start_to_softirq[50*l//100],
        softirq_start_to_softirq[90*l//100],
        softirq_start_to_softirq[l-1]))
l = len(softirq_to_copy_start)
print("SoftIRQ for packet -> copy_out invocation      %6.1f %6.1f %6.1f %7.1f" % (
        softirq_to_copy_start[10*l//100],
        softirq_to_copy_start[50*l//100],
        softirq_to_copy_start[90*l//100],
        softirq_to_copy_start[l-1]))
l = len(copy_start_to_free)
print("copy_out invocation -> packet free             %6.1f %6.1f %6.1f %7.1f" % (
        copy_start_to_free[10*l//100],
        copy_start_to_free[50*l//100],
        copy_start_to_free[90*l//100],
        copy_start_to_free[l-1]))
l = len(lifetimes)
print("End to end lifetime (GRO -> free)              %6.1f %6.1f %6.1f %7.1f" % (
        lifetimes[10*l//100],
        lifetimes[50*l//100],
        lifetimes[90*l//100],
        lifetimes[l-1]))

# Print lifetime information by core

cores = sorted(core_lifetimes.keys())
print("\nLifetimes by core (usec):")
print("Core   P10    P50    P90     Max  Samples  Kpkt/s")
print("-------------------------------------------------")
for core in cores:
    sorted_lifetimes = sorted(core_lifetimes[core])
    l = len(sorted_lifetimes)
    print("%s %6.1f %6.1f %6.1f %7.1f    %5d   %5.1f" % (core,
            sorted_lifetimes[10*l//100],
            sorted_lifetimes[50*l//100],
            sorted_lifetimes[90*l//100],
            sorted_lifetimes[-1],
            l, 1000*l/(latest_time - earliest_time)))

if options.id != 0:
    hdr = "Packets for id %s:" % (options.id)
    print("\n%s" % (hdr))
    print("-" * len(hdr))
    if options.id not in rpcs:
        print("No packets for RPC id %d" % (options.id))
    else:
        rpc = rpcs[options.id]
        print("Offset  Lifetime (usec)");
        for offset in sorted(rpc.keys()):
            pkt = rpc[offset]
            print("%6s     %7.1f" % (offset, pkt["free"] - pkt["gro"]))

