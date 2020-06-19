#!/usr/bin/env python

# Copyright (c) 2019-2020 Stanford University
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
Scan the time trace data in a log file; find all records containing
a given string, and output only those records. If the --rebase argument
is present, times are offset so the first event is at time 0. If the file
is omitted, standard input is used.
Usage: ttgrep.py [--rebase] string [file]
"""

from __future__ import division, print_function
from glob import glob
from optparse import OptionParser
import math
import os
import re
import string
import sys

rebase = False;

def scan(f, string):
    """
    Scan the log file given by 'f' (handle for an open file) and output
    all-time trace records containing string.
    """
    global rebase
    startTime = 0.0
    prevTime = 0.0
    writes = 0
    for line in f:
        match = re.match(' *([0-9.]+) us \(\+ *([0-9.]+) us\) (.*)',
                line)
        if not match:
            continue
        time = float(match.group(1))
        interval = float(match.group(2))
        event = match.group(3)
        if string not in event:
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
    print("Usage: %s [--rebase] string [logFile]" % (sys.argv[0]))
    sys.exit(1)

scan(f, sys.argv[1])