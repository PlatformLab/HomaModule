#!/usr/bin/python3

"""
Scans a timetrace to compute grant lag: how long it takes after a
grant is issued for the granted packet to arrive.
Usage: ttgrant.py [tt_file]

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
from statistics import median

verbose = False
if (len(sys.argv) >= 2) and (sys.argv[1] == "--verbose"):
  verbose = True
  sys.argv.pop(1)
if len(sys.argv) == 2:
    f = open(sys.argv[1])
elif len(sys.argv) == 1:
    f = sys.stdin
else:
    print("Usage: %s [--verbose] [tt_file]" % (sys.argv[0]))
    sys.exit(1)

# Collects all the observed lag values, in microseconds
lags = []

# Keys are RPC ids. Each value is a list of lists, one per outstanding
# grant, where each sublist consists of an <offset, time> pair identifying
# one grant.
grants = {}

# The packet size is computed and saved here.
packet_size = 10000000

# Used to compute packet_size
last_id = 0
last_offset = 0

for line in f:
  match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
        'sending grant for id ([0-9.]+), offset ([0-9.]+)', line)
  if match:
    time = float(match.group(1))
    id = int(match.group(4))
    offset = int(match.group(5))
    if not id in grants:
      grants[id] = []
    grants[id].append([offset, time])
    # print("%9.3f: grant offset %d for id %d" % (time, offset, id))

  match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
        'homa_gro_receive got packet .* id ([0-9]+), offset ([0-9.]+)', line)
  if match:
    time = float(match.group(1))
    id = int(match.group(4))
    offset = int(match.group(5))

    # Compute packet size
    if (id == last_id):
      size = offset - last_offset
      if (size > 0) and (size < packet_size):
        packet_size = size
        # print("Setting packet size to %d" % (packet_size))
    last_id = id
    last_offset = offset

    # Update grant lags
    if not id in grants:
      continue
    g = grants[id]
    for i in range(len(g)):
      if g[i][0] < (offset + packet_size):
        if verbose:
          print("%9.3f: grant lag %.1f us, id %d, offset %d" % (time,
              time - g[i][1], id, offset))
        lags.append(time - g[i][1])
        g.pop(i)
        break

lags = sorted(lags)
print("Percentile    Lag")
for p in [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 99, 100]:
  i = int(p*len(lags)/100)
  if i >= len(lags):
    i = len(lags) - 1
  print("%3d       %6.1f us" %(p, lags[i]))

average = sum(lags)/len(lags)
print("Average:    %.1f us" % (average))