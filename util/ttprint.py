#!/usr/bin/python3

# Copyright (c) 2019-2022 Homa Developers
# SPDX-License-Identifier: BSD-1-Clause

"""
This program reads timetrace information from /proc/timetrace (or from
the first argument, if given) and prints it out in a different form,
with times in microseconds instead of clock cycles.
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
cpu_ghz  = 0.0

# Time in cycles of first event.
first_time = 0

# Time in cycles of previous event.
prev_time = 0

file_name = "/proc/timetrace"
if len(sys.argv) > 1:
    file_name = sys.argv[1]
f = open(file_name)

# Read initial line containing clock rate.
line = f.readline()
if not line:
    print('File empty!')
    exit(0)
match = re.match('cpu_khz: ([0-9.]+)', line)
if not match:
    print('Initial line doesn\'t contain clock rate:\n%s' % (line))
    exit(1)
cpu_ghz = float(match.group(1))*1e-06

for line in f:
    match = re.match('([0-9.]+) (.+)', line)
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