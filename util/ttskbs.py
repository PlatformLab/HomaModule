#!/usr/bin/python3

# Copyright (c) 2022 Stanford University
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

threshold = 0.0
verbose = False
f = sys.stdin

while (len(sys.argv) > 1) and sys.argv[1].startswith("--"):
    if sys.argv[1] == "--help":
        print("Usage: %s [--threshold usecs] [file]" % (sys.argv[0]))
        sys.exit(0)
    if sys.argv[1] == "--verbose":
        verbose = True
        sys.argv.pop(1)
        continue
    if len(sys.argv) < 3:
        print("Missing value for %s option" % (sys.argv[1]))
        sys.exit(1)
    if sys.argv[1] == "--threshold":
        threshold = float(sys.argv[2])
        sys.argv.pop(1)
        sys.argv.pop(1)
if len(sys.argv) >= 2:
    f = open(sys.argv[1])

# Dictionary where each entry corresponds to a packet buffer
# currently in use; the key has the form "id:offset", and the
# value is the time when the packet was passed to homa_gro_receive
active_skbs = {}

# Dictionary with one entry for each market buffer, indexed by
# buffer id of the form rpc_id:offset. Each value is a dictionary
# containing name-time entries for that buffer:
# gro:            time when the buffer was seen by gro_receive
# softirq_start:  homa_softirq woke up (eventually processed buffer)
# softirq:        homa_softirq processed this buffer
# copy_start:     homa_copy_out started processing a batch of
#                 buffers containing this one
# free:           homa_copy_out freed this buffer
rpcs = {}

num_active = 0
max_active = 0

# List whose entries are the lifetimes of individual data packets.
lifetimes = []

# Dictionary where keys are core ids and values are the most recent time
# homa_softirq started executing on that core.
softirq_start = {}

# Dictionary where keys are core ids and values are the most recent time
# homa_copy_out started executing on that core.
copy_out_start = {}

for line in f:
    match = re.match(' *([0-9.]+) us .* \[(C[0-9]+)\] (.*)', line)
    if not match:
        continue
    time = float(match.group(1))
    core = match.group(2)
    msg = match.group(3)

    match = re.match('.* id ([0-9.]+).*offset ([0-9.]+)', msg)
    if match:
        id =  match.group(1) + ':' + match.group(2)
        if not id in rpcs:
            rpcs[id] = {}
        rpc = rpcs[id]

        if "_gro_receive got packet" in msg:
            rpc["gro"] = time
            num_active += 1
            if num_active > max_active:
                max_active = num_active
            if verbose:
                print("%9.3f: allocate %s (%d now active)" % (
                        time, id, len(active_skbs)))

        if "gro" not in rpc:
            continue

        if "homa_copy_out freeing skb" in msg:
            rpc["copy_start"] = copy_out_start[core]
            rpc["free"] = time
            lifetime = time - rpc["gro"]
            lifetimes.append(lifetime)
            if (threshold > 0) and (lifetime >= threshold):
                print("%9.3f: packet %s freed after %5.1f usec" % (time,
                        id, lifetime))
            num_active -= 1
            if verbose:
                print("%9.3f: free     %s (%d now active)" % (time, id,
                        num_active))

        if "incoming data packet" in msg:
            rpc["softirq_start"] = softirq_start[core]
            rpc["softirq"] = time

    if "homa_softirq: first packet" in msg:
        softirq_start[core] = time

    if "starting copy to user space" in msg:
        copy_out_start[core] = time

if len(lifetimes) == 0:
    print("No packets found with complete life cycle")
    exit(1)

print("Maximum number of active skbs: %d" % (max_active))

# Lists of elapsed times from one event to another:
gro_to_softirq_start     = []
softirq_start_to_softirq = []
softirq_to_copy_start    = []
copy_start_to_free       = []

for key in rpcs.keys():
    rpc = rpcs[key]
    if not "free" in rpc:
        continue
    gro_to_softirq_start.append(rpc["softirq_start"] - rpc["gro"])
    softirq_start_to_softirq.append(rpc["softirq"] - rpc["softirq_start"])
    softirq_to_copy_start.append(rpc["copy_start"] - rpc["softirq"])
    copy_start_to_free.append(rpc["free"] - rpc["copy_start"])
gro_to_softirq_start = sorted(gro_to_softirq_start)
softirq_start_to_softirq = sorted(softirq_start_to_softirq)
softirq_to_copy_start = sorted(softirq_to_copy_start)
copy_start_to_free = sorted(copy_start_to_free)
lifetimes = sorted(lifetimes)

print("                                                    Duration (usecs)")
print("Phase of packet lifetime                         P10   P50   P90   Max")
print("----------------------------------------------------------------------")
l = len(gro_to_softirq_start)
print("GRO -> homa_softirq invocation:                %5.1f %5.1f %5.1f %5.1f" % (
        gro_to_softirq_start[10*l//100],
        gro_to_softirq_start[50*l//100],
        gro_to_softirq_start[90*l//100],
        gro_to_softirq_start[l-1]))
l = len(softirq_start_to_softirq)
print("homa_softirq_invocation -> SoftIRQ for packet  %5.1f %5.1f %5.1f %5.1f" % (
        softirq_start_to_softirq[10*l//100],
        softirq_start_to_softirq[50*l//100],
        softirq_start_to_softirq[90*l//100],
        softirq_start_to_softirq[l-1]))
l = len(softirq_to_copy_start)
print("SoftIRQ for packet -> copy_out invocation      %5.1f %5.1f %5.1f %5.1f" % (
        softirq_to_copy_start[10*l//100],
        softirq_to_copy_start[50*l//100],
        softirq_to_copy_start[90*l//100],
        softirq_to_copy_start[l-1]))
l = len(copy_start_to_free)
print("copy_out invocation -> packet free             %5.1f %5.1f %5.1f %5.1f" % (
        copy_start_to_free[10*l//100],
        copy_start_to_free[50*l//100],
        copy_start_to_free[90*l//100],
        copy_start_to_free[l-1]))
l = len(lifetimes)
print("End to end lifetime (GRO -> free)              %5.1f %5.1f %5.1f %5.1f" % (
        lifetimes[10*l//100],
        lifetimes[50*l//100],
        lifetimes[90*l//100],
        lifetimes[l-1]))
