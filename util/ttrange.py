#!/usr/bin/python3

# Copyright (c) 2019-2022 Homa Developers
# SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

"""
Extract entries from a timetrace that For any particular time range.
Usage: ttrange.py start_time end_time [tt_file]

The existing timetrace is in tt_file (or stdin in tt_file is omitted); a new
timetrace will be written to standard output containing all entries whose
timestamps fall between start_time and end_time, inclusive.
"""

from __future__ import division, print_function
from glob import glob
from optparse import OptionParser
import math
import os
import re
import string
import sys

if len(sys.argv) == 4:
    f = open(sys.argv[3])
elif len(sys.argv) == 3:
    f = sys.stdin
else:
    print("Usage: %s start_time end_time [tt_file]" % (sys.argv[0]))
    sys.exit(1)

start_time = float(sys.argv[1])
end_time = float(sys.argv[2])

for line in f:
    match = re.match(' *([0-9.]+) us (.*)', line)
    if not match:
        continue
    time = float(match.group(1))
    if (time >= start_time) and (time <= end_time):
      print(line.rstrip('\n'))