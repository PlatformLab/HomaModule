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
# should be in order of occurrence within an RPC. Fields that may exist
# in each pattern:
# pattern:      the regex pattern to match against each timetrace record
# name:         human-readable string to use in printout
# record_last:  if this field exists and if there are multiple records
#               matching the pattern, the time of the last will be recorded;
#               otherwise only the first will be recorded
# first_out:    this is the first data packet sent for the RPC
# out_packet:   data packet sent with offset != 0
# first_in:     this is the first data packet received for the RPC
# in_packet:    data packet received with offset != 0
# copy_in:      data was just copied from user spaceto kernel space
# copy_out:     data was just copied from kernel space to user space
client_patterns = [
  {"pattern": "homa_ioc_send starting.* id ([0-9]+)",
    "name": "start"},
  {"pattern": "data copied into request.* id ([0-9]+), length ([0-9]+)",
    "name": "data copied into request",
    "copy_out": True},
  {"pattern":"Finished queueing packet.* id ([0-9]+), offset 0",
    "name": "first request packet sent",
    "first_out": True},
  {"pattern":"homa_gro_receive got grant .* id ([0-9]+)",
    "name": "gro gets first grant"},
  {"pattern":"Finished queueing packet.* id ([0-9]+), offset ([0-9]+)",
    "name": "last request packet sent",
    "record_last": True,
    "out_packet": True},
  {"pattern":"homa_gro_receive got packet .* id ([0-9]+), offset 0",
    "name": "gro gets first response packet",
    "first_in": True},
  {"pattern":"sending grant for id ([0-9]+)",
    "name": "sent grant"},
  {"pattern":"homa_gro_receive got packet .* id ([0-9]+), offset ([0-9]+)",
    "name": "gro gets last response packet",
    "record_last": True,
    "in_packet": True},
  {"pattern":"homa_wait_for_message woke up,* id ([0-9]+)",
    "name": "client thread woke up"},
  {"pattern": "starting data copy to user.* id ([0-9]+), length ([0-9]+)",
    "name": "starting data copy to client"},
  {"pattern":"homa_ioc_recv finished,* id ([0-9]+), .* length ([0-9]+)",
    "name": "homa_ioc_recv finished",
    "copy_in": True},
]

server_patterns = [
  {"pattern":"homa_gro_receive got packet .* id ([0-9]+), offset 0",
    "name": "gro gets first request packet",
    "first_in": True},
  {"pattern":"sending grant for id ([0-9]+)",
    "name": "sent grant"},
  {"pattern":"homa_gro_receive got packet .* id ([0-9]+), offset ([0-9]+)",
    "name": "gro gets last request packet",
    "record_last": True,
    "in_packet": True},
  {"pattern":"homa_wait_for_message woke up,* id ([0-9]+)",
    "name": "server thread woke up"},
  {"pattern": "starting data copy to user.* id ([0-9]+), length ([0-9]+)",
    "name": "starting data copy to server"},
  {"pattern":"homa_ioc_recv finished,* id ([0-9]+), .* length ([0-9]+)",
    "name": "homa_ioc_recv finished",
    "copy_in": True},
  {"pattern":"homa_ioc_reply starting,* id ([0-9]+)",
    "name": "homa_ioc_reply starting"},
  {"pattern": "data copied into response.* id ([0-9]+), length ([0-9]+)",
    "name": "data copied into response",
    "copy_out": True},
  {"pattern":"Finished queueing packet.* id ([0-9]+), offset 0",
    "name": "first response packet sent",
    "first_out": True},
  {"pattern":"homa_gro_receive got grant .* id ([0-9]+)",
    "name": "gro gets first grant"},
  {"pattern":"*Finished queueing packet.* id ([0-9]+), offset ([0-9]+)",
    "name": "last response packet sent",
    "record_last": True,
    "out_packet": True},
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

# Keys are RPC ids. Value is the last starting offset seen in a packet
# transmitted or received for that RPC (used to calculate throughputs).
last_out_offset = {}
last_in_offset = {}

# Keys are RPC ids. Value represents time first or last data packet was
# sent or received
first_in_time = {}
first_out_time = {}
last_in_time = {}
last_out_time = {}

# These variables track data copies into and out of the kernel
copy_out_data = 0
copy_out_time = 0
copy_in_data = 0
copy_in_time = 0

for line in f:
  for i in range(len(patterns)):
    pattern = patterns[i]
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
        + pattern["pattern"], line)
    if match:
      time = float(match.group(1))
      id = int(match.group(4))
      if not id in rpcs:
        rpcs[id] = {}
      if (i in rpcs[id]) and (not "record_last" in pattern):
        continue
      rpcs[id][i] = time
      # print("%8.3f: %s for id %d" % (time, names[i], id))
      if "first_in" in pattern:
        first_in_time[id] = time
      if "first_out" in pattern:
        first_out_time[id] = time
      if "in_packet" in pattern:
        last_in_time[id] = time
        last_in_offset[id] = int(match.group(5))
      if "out_packet" in pattern:
        last_out_time[id] = time
        last_out_offset[id] = int(match.group(5))
      if i-1 in rpcs[id]:
        elapsed = time - rpcs[id][i-1]
        if "copy_out" in pattern:
          copy_out_data += int(match.group(5))
          copy_out_time += elapsed
        if "copy_in" in pattern:
          copy_in_data += int(match.group(5))
          copy_in_time += elapsed

for i in range(1, len(patterns)):
  pattern = patterns[i]
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
    print("%-30s (no events)" % (pattern["name"]))
    continue
  elapsed = sorted(elapsed)
  deltas = sorted(deltas)
  print("%-30s Avg %6.1f us (+%6.1f us)  P90 %6.1fus (+%6.1f us)" % (
      pattern["name"], sum(elapsed)/len(elapsed), sum(deltas)/len(deltas),
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

out_data = 0
out_time = 0
in_data = 0
in_time = 0
for id in first_in_time:
  if (id in last_in_time) and (id in last_in_offset):
    in_data += last_in_offset[id]
    in_time += last_in_time[id] - first_in_time[id]
for id in first_out_time:
  if (id in last_out_time) and (id in last_out_offset):
    out_data += last_out_offset[id]
    out_time += last_out_time[id] - first_out_time[id]
print("Throughput:")
if out_time != 0:
  print("  Transmit packets:     %5.1f Gbps (%4.1f%% of total time)" % (
      8e-03*out_data/out_time,
      100.0*out_time/end))
if in_time != 0:
  print("  Receive packets:      %5.1f Gbps (%4.1f%% of total time)" % (
      8e-03*in_data/in_time,
      100.0*in_time/end))
if copy_out_time != 0:
  print("  Copy from user space: %5.1f Gbps (%4.1f%% of total time)" % (
      8e-03*copy_out_data/copy_out_time,
      100.0*copy_out_time/end))
if copy_in_time != 0:
  print("  Copy to user space:   %5.1f Gbps (%4.1f%% of total time)" % (
      8e-03*copy_in_data/copy_in_time,
      100.0*copy_in_time/end))