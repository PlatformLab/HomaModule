#!/usr/bin/python3

"""
Analyzes packet arrivals in a timetrace, outputs info on arrival times
for each offset in a message.

Usage: ttrcv.py [--verbose] [trace]

If no timetrace file is given, this script reads timetrace info from stdin.
"""

from __future__ import division, print_function
from glob import glob
from optparse import OptionParser
import math
from operator import itemgetter
import os
import re
import string
import sys
from statistics import median

# Parse command line options
parser = OptionParser(description=
        'Read a timetrace and output information about arrival times for '
        'packets as a function of their offset in the message.',
        usage='%prog [options] [trace]',
        conflict_handler='resolve')
parser.add_option('--verbose', '-v', action='store_true', default=False,
        dest='verbose',
        help='print lots of output')

# Most recent RPC id seen in a data packet
cur_id = 0

# True means a resend has been issued for cur_id
resend = False

# Time when packet with offset 0 arrived for cur_id
offset0_time = 0

# Keys are offsets; values are lists of arrival times for that offset
arrivals = {}

(options, extra) = parser.parse_args()
f = sys.stdin
if len(extra) > 0:
    f = open(extra[0])
    if len(extra) > 1:
      print("Unrecognized argument %s" % (extra[1]))
      exit(1)

for line in f:
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
            'homa_gro_receive got packet .* id ([0-9]+), offset ([0-9]+)', line)
    if match:
        time = float(match.group(1))
        core = match.group(3)
        id = match.group(4)
        offset = int(match.group(5))

        if cur_id != id:
            if offset != 0:
                continue
            cur_id = id
            resend = False
            offset0_time = time
        if resend:
            resend_info = " (after resend)"
        else:
            resend_info = ""

        if resend:
            continue

        if not offset in arrivals:
            arrivals[offset] = [time - offset0_time]
        else:
            arrivals[offset].append(time - offset0_time)
        if options.verbose:
            print("id %6s, offset %6d, time %9.3f%s" % (id, offset,
                    time - offset0_time, resend_info))

    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
            'Sent RESEND for server RPC id ([0-9]+), .* offset ([0-9]+)*', line)
    if match:
        time = float(match.group(1))
        core = match.group(3)
        id = match.group(4)
        offset = int(match.group(5))

        if id == cur_id:
            resend = True

offsets = sorted(arrivals.keys())
for offset in offsets:
    print("%6d: %8.3f - %8.3f" % (offset, min(arrivals[offset]),
            max(arrivals[offset])))