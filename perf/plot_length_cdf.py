#!/usr/bin/python3

# Copyright (c) 2019-2020, Stanford University
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# This script generates a plot showing the CDF of message lengths,
# gathered from one or more experiment runs.
#
# Usage: plot_length_dist.py name pattern name pattern ...
#
# Each "name" argument gives the name a workload, which will appear in the
# graph keys. Each "pattern" argument gives a glob string (such as
# ("logs/w1/loaded*.txt") describine one or more data files that measure
# the distribution.

import glob
import matplotlib.pyplot as plt
import numpy as np
import os
import string
import sys

# Keys are message lengths, values are number of messages of that length.
counts = {}

def read_rtts(file, column):
    """
    Read file and add its data to the counts array. The "column" argument
    indicates which argument of each line contains the message length.
    """
    global counts

    print("Reading %s" % file)
    f = open(file, "r")
    for line in f:
        stripped = line.strip();
        if stripped[0] == '#':
            continue
        words = stripped.split()
        if (len(words) < (column+1)):
            print("Line too short (no column %d): '%s'" % (line, column))
            continue
        size = int(words[column])
        if size in counts:
            counts[size] += 1
        else:
            counts[size] = 1
    f.close()

if (len(sys.argv) < 3) or not (len(sys.argv) & 1):
    print("Usage: %s name pattern name pattern ..." % (sys.argv[0]))
    exit(1)

workloads = []
for i in range(1, len(sys.argv), 2):
    info = {}
    info["name"] = sys.argv[i]
    pattern = sys.argv[i+1]

    counts = {}
    got_data = False
    for f in glob.glob(pattern):
        read_rtts(f, 0)
        got_data = True
    if not got_data:
        print("Couldn't find any files corresponding to '%s'" % (pattern))
        continue;

    info["total_msgs"] = 0.0
    info["total_bytes"] = 0.0

    for length in counts:
        info["total_msgs"] += counts[length]
        info["total_bytes"] += length*counts[length]

    lengths = sorted(counts.keys())
    messages = 0
    bytes = 0
    info["x"] = []
    info["cum_msgs"] = []
    info["cum_bytes"] = []
    for l in lengths:
        info["x"].append(l)
        info["cum_msgs"].append(messages)
        info["cum_bytes"].append(bytes)
        messages += counts[l]/info["total_msgs"]
        bytes += (l * counts[l])/info["total_bytes"]
        info["x"].append(l)
        info["cum_msgs"].append(messages)
        info["cum_bytes"].append(bytes)
#       print("Length %d, CF messages %.2f, CF bytes %.2f" % (
#                 l, messages, bytes))
    workloads.append(info)

plt.subplot(211)
plt.axis([10, 1500000, 0, 1.0])
plt.xscale("log")
plt.xlabel("Message Length")
plt.ylabel("Cum. Frac. Messages")
plt.grid(which="major", axis="both")

for w in workloads:
    plt.plot(w["x"], w["cum_msgs"], label=w["name"])
plt.legend()

plt.subplot(212)
plt.axis([10, 1500000, 0, 1.0])
plt.xscale("log")
plt.xlabel("Message Length")
plt.ylabel("Cum. Frac. Bytes")
plt.grid(which="major", axis="both")

for w in workloads:
    print("Plotting workload %s" % (w["name"]));
    plt.plot(w["x"], w["cum_bytes"], label=w["name"])
plt.legend()

plt.savefig('length.pdf')