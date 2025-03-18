#!/usr/bin/python3

# Copyright (c) 2019-2022 Homa Developers
# SPDX-License-Identifier: BSD-1-Clause

"""
This program reads timetrace information that was printk-ed to the
system log, removing extraneous syslog information and printing it
out with times in microseconds instead of clock cycles.

Usage:
ttsyslog.py [file]

If no file is given, the information is read from standard input.
"""

from __future__ import division, print_function
from glob import glob
from optparse import OptionParser
import math
import os
import re
import string
import sys

# Clock cycles per nanosecond.
cpu_ghz  = None

# Time in cycles of first event.
first_time = 0

# Time in cycles of previous event.
prev_time = 0

f = sys.stdin
if len(sys.argv) > 1:
    f = open(sys.argv[1])

lines = []

for line in f:
    # Ignore everything up until the initial line containing the clock speed.
    if cpu_ghz == None:
        match = re.match('.*cpu_khz: ([0-9.]+)', line)
        if match:
            cpu_ghz = float(match.group(1))*1e-06
        continue

    lines.append(line)

for line in reversed(lines):
    match = re.match('.* ([0-9.]+) (\[C..\] .+)', line)
    if not match:
        continue
    this_time = float(match.group(1))
    this_event = match.group(2)
    if first_time == 0.0:
        first_time = this_time
        prev_time = this_time
        print('%9.3f us (+%8.3f us) [C00] First event has timestamp %s '
                '(cpu_ghz %.15f)' % (0, 0, match.group(1), cpu_ghz))
    print('%9.3f us (+%8.3f us) %s' % (
            (this_time - first_time)/(1000.0 *cpu_ghz),
            (this_time - prev_time)/(1000.0 * cpu_ghz), this_event))
    prev_time = this_time

if cpu_ghz == None:
    print("Couldn't find initial line with clock speed", file=sys.stderr)