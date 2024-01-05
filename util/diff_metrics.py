#!/usr/bin/python3

# Copyright (c) 2018-2022 Homa Developers
# SPDX-License-Identifier: BSD-1-Clause

"""
This program reads 2 Homa metrics files (/proc/net/homa_metrics)
and prints out all of the statistics that have changed, in the
same format as the original files.

Usage:
diff_metrics file1 file2
"""

from __future__ import division, print_function
from glob import glob
from optparse import OptionParser
import math
import os
import re
import string
import sys

# Contains values for all the metrics from the first file. Keys are
# metric names, values are metric values.
metrics = {}

def scan_first(name):
    """
    Scan the metrics file given by 'name' and record its metrics.
    """
    global metrics
    f = open(name)

    for line in f:
        match = re.match('^([^ ]+) *([0-9]+) *(.*)', line)
        if not match:
            print("Didn't match: %s\n" % (line))
            continue
        metrics[match.group(1)] = long(match.group(2))
    f.close()

def scan_second(name):
    """
    Scan the metrics file given by 'name', compare its metrics to
    those that have been recorded, and print an output line with
    the difference, if there is any.
    """
    global metrics
    f = open(name)

    for line in f:
        match = re.match('^([^ ]+) *([0-9]+) *(.*)', line)
        if not match:
            print("Didn't match: %s\n" % (line))
            continue
        name = match.group(1)
        value = long(match.group(2))
        comment = match.group(3)
        if not name in metrics:
            print("No metric for %s\n" % (name))
            continue
        # print("%s: %d %d\n" % (name, metrics[name], value))
        diff = value - metrics[name]
        if diff == 0:
            continue
        print("%-22s %15lu  %s" % (name, diff, comment))
    f.close()

if len(sys.argv) != 3:
    printf("Usage: %s file file2\n" % sys.argv[0])
    exit(1)

scan_first(sys.argv[1])
scan_second(sys.argv[2])