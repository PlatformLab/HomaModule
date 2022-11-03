#!/usr/bin/python3

"""
Analyzes softirq wakeup times in a timetrace.
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

if len(sys.argv) == 2:
    f = open(sys.argv[1])
elif len(sys.argv) == 1:
    f = sys.stdin
else:
    print("Usage: %s [tt_file]" % (sys.argv[0]))
    sys.exit(1)

queued = {}
delays = []

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
            if delay > 10.0:
                print("%9.3f Long SoftIRQ delay: %.1f usec (C%02d)" %
                        (time, delay, core))

delays.sort();
print("Minimum delay: %4.1f usec" % (delays[0]))
print("Median delay:  %4.1f usec" % (delays[len(delays)//2]))
print("P90 delay:     %4.1f usec" % (delays[len(delays)*9//10]))
print("P99 delay:     %4.1f usec" % (delays[len(delays)*99//100]))
print("Maximum delay: %4.1f usec" % (delays[-1]))