#!/usr/bin/python3

# Copyright (c) 2019-2022 Homa Developers
# SPDX-License-Identifier: BSD-1-Clause

"""
Scan the time trace data in a log file; find all records whose events
match a given Python regular expression, and output only those records.
If the --rebase argument is present, times are offset so the first event
is at time 0. If the file is omitted, standard input is used.
Usage: ttgrep.py [--rebase] regex [file]
"""

from __future__ import division, print_function
from glob import glob
from optparse import OptionParser
import math
import os
import re
import string
import sys

rebase = False

def scan(f, pattern):
    """
    Scan the log file given by 'f' (handle for an open file) and output
    all-time trace records that match pattern.
    """
    global rebase
    startTime = 0.0
    prevTime = 0.0
    writes = 0
    compiled = re.compile(pattern)
    for line in f:
        match = re.match(' *([-0-9.]+) us \(\+ *([0-9.]+) us\) (.*)',
                line)
        if not match:
            continue
        time = float(match.group(1))
        interval = float(match.group(2))
        event = match.group(3)
        if (not compiled.search(event)) and ("Freez" not in event):
            continue
        if startTime == 0.0:
            startTime = time
            prevTime = time
        if rebase:
            printTime = time - startTime
        else:
            printTime = time
        print("%9.3f us (+%8.3f us) %s" % (printTime,
                time - prevTime, event))
        prevTime = time

if (len(sys.argv) > 1) and (sys.argv[1] == "--rebase"):
    rebase = True
    del sys.argv[1]

f = sys.stdin
if len(sys.argv) == 3:
    f = open(sys.argv[2])
elif len(sys.argv) != 2:
    print("Usage: %s [--rebase] regex [logFile]" % (sys.argv[0]))
    sys.exit(1)

scan(f, sys.argv[1])