#!/usr/bin/python3

# Copyright (c) 2019-2022 Stanford University
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
Merge two or more timetraces into a single trace. All of the traces
must use the same time source.
Usage: ttmerge.py file file file ...
"""

from __future__ import division, print_function
from glob import glob
import math
from optparse import OptionParser
import os
import re
import string
import sys

# Each entry in the following list describes one file; it is a dictionary
# with the following fields:
# name:      Name of the file
# f:         Open file for reading
# ghz:       Clock rate assumed for this file
# first:     Timestamp of first entry
# offset:    How much to add to times in this file so they align
#            with times in the other files
# time:      Time of the current line, adjusted by offset
# suffix:    Everything on the current line after the times
files = []

# Earliest first timestamp from all the files.
first = 0

# Reference ghz (taken from input file with the earliest start time;
# used for output). Used to compensate for the fact that different
# traces may have assumed slightly different conversion rates from
# ticks to microseconds.
ghz = 0.0

def next_line(info):
    """
    Read information from a file. The info argument is one of the
    entries in files.
    """
    while True:
        line = info["f"].readline()
        if not line:
            info["f"].close()
            info["f"] = None
            return
        match = re.match(' *([0-9.]+) us \(\+ *([0-9.]+) us\) (.*)', line)
        if not match:
            continue
        info["time"] = (float(match.group(1)) * ghz / info["ghz"]) + info["offset"]
        info["suffix"] = match.group(3).rstrip()
        return

# Open each of the files and initialize information for them.
for file in sys.argv[1:]:
    f = open(file, newline='\n')
    line = f.readline()
    if not line:
        continue
    info = {"f": f}
    match = re.match(' *([0-9.]+) us \(\+ *([0-9.]+) us\) .* '
            'First event has timestamp ([0-9]+) '
            '\(cpu_ghz ([0-9.]+)\)', line)
    if not match:
        continue
    info = {"name": file,
            "f": f,
            "ghz": float(match.group(4)),
            "first": int(match.group(3)),
            "offset": 0.0}
    files.append(info)

# Find the earliest timestamp and set offsets.
for info in files:
    if (first == 0) or info["first"] < first:
        first = info["first"]
        ghz = info["ghz"]
for info in files:
    info["offset"] = ((info["first"] - first)/ghz)/1000.0
    # print("file %s has offset %.2f us (difference: %d)" % (info["name"],
    #         info["offset"], info["first"] - first))

    # Prime the info with the first real trace entry.
    next_line(info)

# Repeatedly output the earliest line until there are no lines left to output.
prevTime = 0.0
while True:
    best = None
    best_time = 0.0
    for info in files:
        if info["f"] and ((best_time == 0.0) or (info["time"] < best_time)):
            best_time = info["time"]
            best = info
    if not best:
        break
    time = best["time"]
    print("%9.3f us (+%8.3f us) %s" % (time, time - prevTime, best["suffix"]))
    prev_time = time
    next_line(best)