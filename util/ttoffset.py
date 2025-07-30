#!/usr/bin/python3

# Copyright (c) 2019-2022 Homa Developers
# SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

"""
Rewrite a time trace with all of the times offset by a fixed amount
(typically used to align the times in two timetraces)
Usage: ttoffset.py old_time new_time [tt_file]

The existing timetrace is in tt_file (or stdin in tt_file is omitted); a new
timetrace will be written to standard output, with (new_time - old_time)
added to each timestamp.
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
    print("Usage: %s old_time new_time [tt_file]" % (sys.argv[0]))
    sys.exit(1)

delta = float(sys.argv[2]) - float(sys.argv[1])

for line in f:
    match = re.match(' *([0-9.]+) us (.*)', line)
    if not match:
        print(line)
        continue
    time = float(match.group(1))
    print("%9.3f us %s" % (time + delta, match.group(2)))