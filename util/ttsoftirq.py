#!/usr/bin/python3

"""
Analyzes softirq wakeup times in a timetrace. Also analyzes how long
it takes from when the NAPI layer receives a packet until the packet
is released in homa_copy_to_user.
Usage: softirq.py [tt_file]

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

verbose = False
f = sys.stdin

while (len(sys.argv) > 1) and sys.argv[1].startswith("--"):
    if sys.argv[1] == "--help":
        print("Usage: %s [--verbose] [file]" % (sys.argv[0]))
        sys.exit(0)
    if sys.argv[1] == "--verbose":
        verbose = True
        sys.argv.pop(1)
        continue
if len(sys.argv) >= 2:
    f = open(sys.argv[1])

queued = {}
delays = []

# One entry for each packet seen by homa_gro_receive. Key is "rpcId:offset",
# value is arrival time in homa_gro_receive.
arrivals = {}

# One entry for each batch of packets freed by homa_copy_to_user. Value is
# elapsed time since packet was seen by homa_gro_receive.
lifetimes = []

for line in f:
    match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\]', line)
    if not match:
        continue
    time = float(match.group(1))
    core = int(match.group(2))

    match = re.match('.*enqueue_to_backlog.* cpu ([0-9]+)', line)
    if match:
        dest = int(match.group(1))
        queued[dest] = time

    match = re.match('.*homa_softirq: first packet', line)
    if match:
        if core in queued:
            delay = time - queued[core]
            delays.append(delay)
            if (delay > 10.0) and verbose:
                print("%9.3f Long SoftIRQ delay: %.1f usec (C%02d)" %
                        (time, delay, core))
            del queued[core]

    match = re.match('.*homa_gro_receive got packet .* id ([0-9]+), '
            'offset ([0-9]+),', line)
    if match:
        key = match.group(1) + ":" + match.group(2)
        arrivals[key] = time

    match = re.match('.*finished copying .* bytes for id ([0-9]+), '
            '.* last offset ([0-9]+)', line)
    if match:
        key = match.group(1) + ":" + match.group(2)
        if key in arrivals:
            lifetime = time - arrivals[key]
            lifetimes.append(lifetime)
            if False and verbose:
                print("%9.3f Packets freed with lifetime %5.1f us"
                        % (time, lifetime))

delays.sort()
print("Total SoftIRQ wakeup data points: %d" % (len(delays)))
print("Minimum delay: %4.1f usec" % (delays[0]))
print("Median delay:  %4.1f usec" % (delays[len(delays)//2]))
print("P90 delay:     %4.1f usec" % (delays[len(delays)*9//10]))
print("P99 delay:     %4.1f usec" % (delays[len(delays)*99//100]))
print("Maximum delay: %4.1f usec" % (delays[-1]))

print("")
if len(lifetimes) == 0:
    print("Couldn't extract information on receive packet lifetimes");
    exit(1)

lifetimes.sort()
print("Total packet lifetime data points: %d" % (len(lifetimes)))
print("Minimum lifetime: %4.1f usec" % (lifetimes[0]))
print("Median lifetime:  %4.1f usec" % (lifetimes[len(lifetimes)//2]))
print("P90 lifetime:     %4.1f usec" % (lifetimes[len(lifetimes)*9//10]))
print("P99 lifetime:     %4.1f usec" % (lifetimes[len(lifetimes)*99//100]))
print("Maximum lifetime: %4.1f usec" % (lifetimes[-1]))
