#!/usr/bin/python3

"""
Scans a client or server timetrace to compute the time it takes for each
phase of RPCs.
Usage: ttrpcs.py [--server] [tt_file]

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

# Lists of patterns (one for the client side and one for the server side).
# We'll record times for each RPC id when it hits each pattern. The list
# should be in order of occurrence within an RPC. Each entry also contains
# an indicator of whether we should record the *last* occurrence of the
# pattern, rather than first, and a human- readable string to use in output
# for this pattern.
client_patterns = [
  {"pattern": "homa_ioc_send starting.* id ([0-9]+)",
    "record_last": False, "name": "start"},
  {"pattern":"Finished queueing packet.* id ([0-9]+), offset 0",
    "record_last": False, "name": "first request packet sent"},
  {"pattern":"homa_gro_receive got packet .* id ([0-9]+), type 21",
    "record_last": False, "name": "first grant arrived"},
  {"pattern":"*Finished queueing packet.* id ([0-9]+), offset",
    "record_last": True, "name": "last request packet sent"},
  {"pattern":"homa_gro_receive got packet .* id ([0-9]+), offset 0",
    "record_last": False, "name": "first response packet arrived"},
  {"pattern":"sending grant for id ([0-9]+)",
    "record_last": False, "name": "sent grant"},
  {"pattern":"homa_gro_receive got packet .* id ([0-9]+), offset",
    "record_last": True, "name": "last response packet arrived"},
  {"pattern":"homa_ioc_recv finished,* id ([0-9]+)",
    "record_last": False, "name": "homa_ioc_recv finished"},
]

server_patterns = [
  {"pattern":"homa_gro_receive got packet .* id ([0-9]+), offset 0",
    "record_last": False, "name": "first request packet arrived"},
  {"pattern":"sending grant for id ([0-9]+)",
    "record_last": False, "name": "sent grant"},
  {"pattern":"homa_gro_receive got packet .* id ([0-9]+), offset",
    "record_last": True, "name": "last request packet arrived"},
  {"pattern":"homa_ioc_recv finished,* id ([0-9]+)",
    "record_last": False, "name": "homa_ioc_recv finished"},
  {"pattern":"homa_ioc_reply starting,* id ([0-9]+)",
    "record_last": False, "name": "homa_ioc_reply starting"},
  {"pattern":"Finished queueing packet.* id ([0-9]+), offset 0",
    "record_last": False, "name": "first response packet sent"},
  {"pattern":"homa_gro_receive got packet .* id ([0-9]+), type 21",
    "record_last": False, "name": "first grant arrived"},
  {"pattern":"*Finished queueing packet.* id ([0-9]+), offset",
    "record_last": True, "name": "last response packet sent"},
]

patterns = client_patterns
if (len(sys.argv) >= 2) and (sys.argv[1] == "--server"):
  patterns = server_patterns
  sys.argv.pop(1)
if len(sys.argv) == 2:
    f = open(sys.argv[1])
elif len(sys.argv) == 1:
    f = sys.stdin
else:
    print("Usage: %s [--server] [tt_file]" % (sys.argv[0]))
    sys.exit(1)

# Keys are RPC ids. Each value is a dictionary whose keys are indexes
# within patterns and whose values are the times when that event occurred.
rpcs = {}

for line in f:
  for i in range(len(patterns)):
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
        + patterns[i]["pattern"], line)
    if match:
      time = float(match.group(1))
      id = int(match.group(4))
      if not id in rpcs:
        rpcs[id] = {}
      if (i in rpcs[id]) and not (patterns[i]["record_last"]):
        continue
      rpcs[id][i] = time
      # print("%8.3f: %s for id %d" % (time, names[i], id))

for i in range(1, len(patterns)):
  elapsed = []
  deltas = []
  for id in rpcs:
    rpc = rpcs[id]
    if (0 not in rpc) or ((len(patterns)-1) not in rpc):
      continue
    if i not in rpc:
      continue
    elapsed.append(rpc[i] - rpc[0])
    prev = i - 1
    while not prev in rpc:
        prev -= 1
    deltas.append(rpc[i] - rpc[prev])
  if len(elapsed) == 0:
    print("%-30s (no events)" % (patterns[i]["name"]))
    continue
  elapsed = sorted(elapsed)
  deltas = sorted(deltas)
  print("%-30s Avg %6.1f us (+%6.1f us)  P90 %6.1fus (+%6.1f us)" % (
      patterns[i]["name"], sum(elapsed)/len(elapsed), sum(deltas)/len(deltas),
      elapsed[9*len(elapsed)//10], deltas[9*len(deltas)//10]))

print("\nTotal RPCs: %d" % (len(rpcs)))
avg_rpcs = 0
last = len(patterns)-1
for id in rpcs:
  rpc = rpcs[id]
  if 0 in rpc:
    start = rpc[0]
  else:
    start = 0
  if last in rpc:
    end = rpc[last]
  else:
    end = time
  avg_rpcs += (end - start) / time
  # print("RPC id %d: %.1f (%8.3f -> %8.3f)" % (id, end - start, start, end))
print("Average active RPCS: %.1f" % (avg_rpcs))