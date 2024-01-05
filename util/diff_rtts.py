#!/usr/bin/python3

# Copyright (c) 2023 Homa Developers
# SPDX-License-Identifier: BSD-1-Clause

"""
Compare two .rtts files to identify differences between them.

Usage: diff_rtts.py file1 file2
"""

from __future__ import division, print_function
from glob import glob
from operator import itemgetter
from optparse import OptionParser
import math
import os
import re
import string
import sys

def read_rtts(file):
    """
    Read a .rtts file and returns a list of (length, slowdown) pairs.

    file:  Name of file to read
    """

    slowdowns = []
    f = open(file)
    for line in f:
        if line.startswith('#') or not line:
            continue
        match = re.match(' *([0-9]+) +([0-9.]+)', line)
        if not match:
            raise Exception("Malformed line in .rtts file: %s" % (line.rstrip()))
        length = int(match.group(1))
        rtt = float(match.group(2))

        # Optimal time (usecs) assumes 13 usec minimum, 25 Gbps network
        optimal = 13.0 + length*8/25000.0
        slowdown = rtt/optimal
        slowdowns.append([length, slowdown])
    f.close()
    return slowdowns

def avg_slowdown(slowdowns):
    """
    Return average slowdown from a list of (length, slowdown) pairs.

    slowdowns:  Input list
    """
    sum = 0.0
    for item in slowdowns:
        sum += item[1]
    return sum/len(slowdowns)

def deciles(slowdowns):
    """
    Given a list of (length, slowdown) pairs, divide into 10 groups by
    length, then returns 6 lists (each with one entry per decile),
    containing:
        * largest length in the decile
        * P50 slowdown for the decile
        * P90 slowdown for the decile
        * P99 slowdown for the decile
        * P99.9 slowdown for the decile
        * max slowdown for the decile
    """
    p50 = []
    p90 = []
    p99 = []
    p999 = []
    max = []
    cutoffs = []
    s = sorted(slowdowns, key = itemgetter(0))
    for split in range(1, 11):
        split_start = len(s)*(split-1)//10
        split_end = len(s)*split//10
        decile = []
        for i in range(split_start, split_end):
            decile.append(s[i][1])
        cutoffs.append(s[split_end-1][0])
        decile = sorted(decile)
        p50.append(decile[len(decile)//2])
        p90.append(decile[len(decile)*9//10])
        p99.append(decile[len(decile)*99//100])
        p999.append(decile[len(decile)*999//1000])
        max.append(decile[-1])
    return cutoffs, p50, p90, p99, p999, max


if len(sys.argv) != 3:
    print("Usage: diff_rtts.py file1 file2")
    exit(1)
f1 = sys.argv[1]
f2 = sys.argv[2]

s1 = read_rtts(f1)
print("Average slowdown in %s: %.1f" % (f1, avg_slowdown(s1)))

s2 = read_rtts(sys.argv[2])
print("Average slowdown in %s: %.1f" % (f2, avg_slowdown(s2)))
print("")

c1, p50_1, p90_1, p99_1, p999_1, max_1 = deciles(s1)
c2, p50_2, p90_2, p99_2, p999_2, max_2 = deciles(s2)

out = ""
for cutoff in c1:
    out += " %d" % (cutoff)
print("Cutoffs for %s:%s" % (f1, out))
out = ""
for cutoff in c2:
    out += " %d" % (cutoff)
print("Cutoffs for %s:%s" % (f2, out))
print("")

out = ""
for val in p50_1:
    out += " %5.1f" % (val)
print("P50s for %s:%s" % (f1, out))
out = ""
for val in p50_2:
    out += " %5.1f" % (val)
print("P50s for %s:%s" % (f2, out))
print("")

out = ""
for val in p90_1:
    out += " %5.1f" % (val)
print("P90s for %s:%s" % (f1, out))
out = ""
for val in p90_2:
    out += " %5.1f" % (val)
print("P90s for %s:%s" % (f2, out))
print("")

out = ""
for val in p99_1:
    out += " %5.1f" % (val)
print("P99s for %s:%s" % (f1, out))
out = ""
for val in p99_2:
    out += " %5.1f" % (val)
print("P99s for %s:%s" % (f2, out))
print("")

out = ""
for val in p999_1:
    out += " %5.1f" % (val)
print("P99.9s for %s:%s" % (f1, out))
out = ""
for val in p999_2:
    out += " %5.1f" % (val)
print("P99.9s for %s:%s" % (f2, out))
print("")

out = ""
for val in max_1:
    out += " %5.1f" % (val)
print("Maxes for %s:%s" % (f1, out))
out = ""
for val in max_2:
    out += " %5.1f" % (val)
print("Maxes for %s:%s" % (f2, out))

exit(0)