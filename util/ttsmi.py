#!/usr/bin/python3

"""
Scans a timetrace looking for long gaps where no cores have any events
(probably because of System Management Interrupts)
Usage: ttsmi.py [tt_file]

The existing timetrace is in tt_file (or stdin in tt_file is omitted).
"""

from __future__ import division, print_function
from glob import glob
from optparse import OptionParser
import math
import os
import re
import string
import sys

if len(sys.argv) == 2:
    f = open(sys.argv[1])
elif len(sys.argv) == 1:
    f = sys.stdin
else:
    print("Usage: %s [tt_file]" % (sys.argv[0]))
    sys.exit(1)

prev_time = 0
printed = 0

for line in f:
    match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\]', line)
    if not match:
        continue
    time = float(match.group(1))
    core = int(match.group(2))

    if (time - prev_time) > 150:
        print(line.rstrip())
        printed += 1
        if printed >= 5:
            exit(0)
    
    prev_time = time
            