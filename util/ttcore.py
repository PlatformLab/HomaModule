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
Scan the timetrace data in a log file; for records containing certain
substrings, compute statistics for how often those records occur on each
core.
Usage: ttcore.py [substring substring ...] [file]
Each substring argument selects a collection of entries in the timetrace;
each collection will be analyzed separately for core usage. If no substrings
are specified, a default collection will be used. File gives the name of the
timetrace file to use (stdin is used if no file is specified).
"""

from __future__ import division, print_function
from glob import glob
from optparse import OptionParser
import math
import os
import re
import string
import sys

# The substrate arguments that we are matching against timetrace entries
substrings = []

# For each entry in substrings there is an entry in this array, which
# consists of an array of counts (how many times a timetrace entry matching
# the substring occurred on each core).
cores = []

# Highest core number seen
max_core = 0

def scan(f):
    """
    Scan the log file given by 'f' and accumulate core statistics.
    """

    global substrings, cores, max_core
    startTime = 0.0
    prevTime = 0.0
    writes = 0
    for line in f:
        match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\] (.*)',
                line)
        if not match:
            print("Line didn't match: %s" % (line))
            continue
        time = float(match.group(1))
        core = int(match.group(2))
        if core > max_core:
            max_core = core
        event = match.group(3)
        for i in range(0, len(substrings)):
            if substrings[i] in event:
                c = cores[i]
                while len(c) <= core:
                    c.append(0)
                c[core] += 1

f = sys.stdin
substrings = []
if len(sys.argv) > 1:
    try:
        f = open(sys.argv[-1])
        substrings = sys.argv[1:-1]
    except:
        substrings = sys.argv[1:]

if len(substrings) == 0:
    substrings = ["mlx processed",
        "homa_softirq: first",
        "homa_ioc_recv finished",
        "homa_ioc_send starting",
        "mlx_xmit starting, id",
        "pacer calling",
        "tcp_v4_rcv invoked",
        "tcp_recvmsg returning"
    ]

for i in range(0, len(substrings)):
    cores.append([])

scan(f)

max_length = 0
for i in range(0, len(substrings)):
    length = len(substrings[i])
    if length > max_length:
        max_length = length
    while len(cores[i]) <= max_core:
        cores[i].append(0)

line = "Event Substring         Core 0"
for i in range (1, len(cores[0])):
    line += " %5d" % (i)
print(line)
for i in range(0, len(substrings)):
    line = "%-*s " % (max_length+1, substrings[i] + ":")
    for count in cores[i]:
        line += " %5d" % (count)
    print(line)