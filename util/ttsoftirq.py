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
show_idle = False
f = sys.stdin

while (len(sys.argv) > 1) and sys.argv[1].startswith("--"):
    if sys.argv[1] == "--help":
        print("Usage: %s [--verbose] [--show-idle] [file]" % (sys.argv[0]))
        sys.exit(0)
    if sys.argv[1] == "--verbose":
        verbose = True
        sys.argv.pop(1)
        continue
    if sys.argv[1] == "--show-idle":
        show_idle = True
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

# Keys are core numbers, values are time of last log entry seen for that core.
core_last = {}

# Keys are core numbers, values are the core's idle time (elapsed time with
# no log entries) as of the most recent "enqueue_to_backlog" entry
# targeting that core.
idle_before_wakeup = {}

# Contains one entry for each softirq wakeup, which is a dictionary
# with the following fields:
# core -       The core on which homa_softirq ran
# time -       Time when homa_softirq woke up
# delay -      Elapsed time since enqueue_to_backlog was most recently invoked
# idle -       How long the core was idle at the time of enqueue_to_backlog
wakeups = []

for line in f:
    match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\]', line)
    if not match:
        continue
    time = float(match.group(1))
    core = int(match.group(2))
    core_last[core] = time

    match = re.match('.*enqueue_to_backlog.* cpu ([0-9]+)', line)
    if match:
        dest = int(match.group(1))
        queued[dest] = time
        if not dest in core_last:
            core_last[dest] = 0.0
        idle_before_wakeup[dest] = time - core_last[dest]

    match = re.match('.*homa_softirq: first packet', line)
    if match:
        if core in queued:
            delay = time - queued[core]
            delays.append(delay)
            if (delay > 10.0) and verbose:
                print("%9.3f [C%02d] Long SoftIRQ delay: %.1f usec, "
                        "idle %.1f usec" %
                        (time, core, delay, idle_before_wakeup[core]))
            wakeups.append({"time": time, "core": core, "delay": delay,
                    "idle": idle_before_wakeup[core]});
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

if show_idle:
    wakeups.sort(key=lambda item: item["delay"], reverse=True)
    for wakeup in wakeups:
        print("%9.3f -> %9.3f [C%02d] delay %5.1f, idle %5.1f" % (
                wakeup["time"] - wakeup["delay"], wakeup["time"],
                wakeup["core"], wakeup["delay"], wakeup["idle"]))