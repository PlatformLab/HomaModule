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
Reads Homa metrics from the kernel and prints out anything that is changed
since the last time this program was invoked.
Usage: metrics.py [file]

If file is specified, it gives the name of a file in which this program
saves current metrics each time it is run, so that the next run can determine
what has changed. File defaults to ~/.homa_metrics.
"""

from __future__ import division, print_function
from glob import glob
from optparse import OptionParser
import math
import os
import re
import string
import sys

if len(sys.argv) > 1:
    data_file = sys.argv[1]
else:
    data_file = os.path.expanduser("~") + "/.homa_metrics"

# Scan the old data file (if it exists and build a dictionary of
# values.
prev = {}
try:
    f = open(data_file)
except IOError:
    pass
if 'f' in locals():
    for line in f:
        match = re.match('^([^ ]*) *([0-9]+) *(.*)', line)
        if not match:
            print("Bogus line in data file: %s" % (line))
            continue
        symbol = match.group(1)
        count = int(match.group(2))
        prev[symbol] = count
    f.close()

# Scan the current metrics: compare with info from the data file, output
# differences, and also rewrite the data file with current data.

f = open("/proc/net/homa_metrics")
data = open(data_file, "w")
time_delta = 0
for line in f:
    data.write(line)
    match = re.match('^([^ ]*) *([0-9]+) *(.*)', line)
    if not match:
        print("Bogus line in Homa metrics: %s" % (line))
        continue
    symbol = match.group(1)
    count = int(match.group(2))
    doc = match.group(3)
    if (symbol in prev):
        old = prev[symbol]
    else:
        old = 0
    if (symbol == "rdtsc_cycles") and (old != 0):
        time_delta = count - old
    if old != count:
        if (symbol == "timer_cycles") and (time_delta != 0):
            print("%-22s %15d (%.2f%%) %s" % (symbol, count-old,
                100.0*float(count-old)/float(time_delta), doc))
        else:
            print("%-22s %15d %s" % (symbol, count-old, doc))
f.close()
data.close()