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
This program reads timetrace information from /proc/timetrace (or from
the first argument, if given) and prints it out in a different form,
with times in nanoseconds instead of clock cycles.
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
f = open(file_name);

# Read initial line containing clock rate.
line = f.readline()
if not line:
    print('File empty!')
    exit(0)
match = re.match('cpu_khz: ([0-9.]+)', line)
if not match:
    print('Initial line doesn\'t contain clock rate:\n%s' % (line))
    exit(1)
cpu_ghz = float(match.group(1))*1e-06;

for line in f:
    match = re.match('([0-9.]+) (.+)', line)
    if not match:
        continue
    this_time = float(match.group(1))
    this_event = match.group(2)
    if first_time == 0.0:
        first_time = this_time
        prev_time = this_time
    print('%10.1f ns (+%9.1f ns) %s' % ((this_time - first_time)/cpu_ghz,
            (this_time - prev_time)/cpu_ghz, this_event))
    prev_time = this_time