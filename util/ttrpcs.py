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
client_patterns = [
  {"pattern": "homa_sendmsg request.* id ([0-9]+)",
    "name": "start"},
  {"pattern":"Finished queueing packet.* id ([0-9]+), offset 0",
    "name": "first request packet sent",
    "first_out": True},
  {"pattern":"processing grant .* id ([0-9]+)",
    "name": "softirq gets first grant"},
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
  {"pattern":"homa_recvmsg returning id ([0-9]+), length ([0-9]+)",
    "name": "homa_recvmsg returning"},
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
  {"pattern":"homa_recvmsg returning id ([0-9]+), length ([0-9]+)",
    "name": "homa_recvmsg returning"},
  {"pattern":"homa_sendmsg response,* id ([0-9]+)",
    "name": "homa_sendmsg response"},
  {"pattern":"Finished queueing packet.* id ([0-9]+), offset 0",
    "name": "first response packet sent",
    "first_out": True},
  {"pattern":"processing grant .* id ([0-9]+)",
    "name": "softirq gets first grant"},
  {"pattern":"*Finished queueing packet.* id ([0-9]+), offset ([0-9]+)",
    "name": "last response packet sent",
    "record_last": True,
    "out_packet": True},
]

# Additional patterns to track packet copying separately.
aux_client_patterns = [
  {"pattern": "homa_sendmsg request.* id ([0-9]+)",
    "name": "start"},
  {"pattern":"finished copy from user space for id ([0-9]+)",
    "name": "finished copying req into pkts"},
  {"pattern":"starting copy to user space for id ([0-9]+)",
    "name": "starting copying to user space"},
  {"pattern":"finished copying .* id ([0-9]+)",
    "name": "finished copying to user space",
    "record_last": True},
]

aux_server_patterns = [
  {"pattern":"homa_gro_receive got packet .* id ([0-9]+), offset 0",
    "name": "gro gets first request packet"},
  {"pattern":"starting copy to user space for id ([0-9]+)",
    "name": "starting copying to user space"},
  {"pattern":"finished copying .* id ([0-9]+)",
    "name": "finished copying to user space",
    "record_last": True},
  {"pattern":"finished copy from user space for id ([0-9]+)",
    "name": "finished copying resp into pkts"},
]

def print_stats(patterns, rpcs):
  """
  Print out a time line of when the events in patterns occur, using
  data collected in rpcs
  """
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
      print("%-32s (no events)" % (pattern["name"]))
      continue
    elapsed = sorted(elapsed)
    deltas = sorted(deltas)
    print("%-32s Avg %7.1f us (+%7.1f us)  P90 %7.1f us (+%7.1f us)" % (
        pattern["name"], sum(elapsed)/len(elapsed), sum(deltas)/len(deltas),
        elapsed[9*len(elapsed)//10], deltas[9*len(deltas)//10]))

patterns = client_patterns
aux_patterns = aux_client_patterns
if (len(sys.argv) >= 2) and (sys.argv[1] == "--server"):
  patterns = server_patterns
  aux_patterns = aux_server_patterns
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

# Similar to rpcs, except records info about aux_patterns.
aux_rpcs = {}

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

# Keys are core ids. Value is the most recent time when a copy to user
# space was initiated on that core.
last_copy_out_start = {}

# Keys are core ids. Value is the most recent time when a copy from user
# space was initiated on that core.
last_copy_in_start = {}

# These variables track data copies into and out of the kernel
copy_in_data = 0
copy_in_time = 0
copy_out_data = 0
copy_out_time = 0

# A list containing the elapsed time for each invocation of ip_queue_xmit
# or ip6_xmit for a data packet
xmit_times = []

# For each core, time of most recent call to either ip_queue_xmit or ip6_xmit.
start_xmit = {}

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
  for i in range(len(aux_patterns)):
    pattern = aux_patterns[i]
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
        + pattern["pattern"], line)
    if match:
      time = float(match.group(1))
      id = int(match.group(4))
      if not id in aux_rpcs:
        aux_rpcs[id] = {}
      if (i in aux_rpcs[id]) and (not "record_last" in pattern):
        continue
      aux_rpcs[id][i] = time

  match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
      'starting copy to user space', line)
  if match:
    time = float(match.group(1))
    core = int(match.group(3))
    last_copy_out_start[core] = time

  match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
      'starting copy from user space', line)
  if match:
    time = float(match.group(1))
    core = int(match.group(3))
    last_copy_in_start[core] = time

  match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
      'finished copy from user space for id ([-0-9.]+), length ([-0-9.]+)', line)
  if match:
    time = float(match.group(1))
    core = int(match.group(3))
    id = match.group(4)
    length = int(match.group(5))
    if core in last_copy_in_start:
        copy_in_time += time - last_copy_in_start[core]
        copy_in_data += length

  match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
      'finished copy from user space', line)
  if match:
    time = float(match.group(1))
    core = int(match.group(3))
    last_copy_in_start[core] = time

  match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
      'finished copying ([-0-9.]+) bytes for id ([-0-9.]+)', line)
  if match:
    time = float(match.group(1))
    count = int(match.group(4))
    core = int(match.group(3))
    if core in last_copy_out_start:
      elapsed = time - last_copy_out_start[core]
      copy_out_time += elapsed
      copy_out_data += count
      # print("%8.3f: %d bytes copied in %.1f usec: %.1f GB/sec" % (
          # qtime, count, elapsed, (count/1000)/elapsed))

  match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
      'calling .*_xmit: wire_bytes', line)
  if match:
    time = float(match.group(1))
    core = int(match.group(3))
    start_xmit[core] = time

  match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
      'Finished queueing packet:', line)
  if match:
    time = float(match.group(1))
    core = int(match.group(3))
    if core in start_xmit:
        xmit_times.append(time - start_xmit[core])

# Make sure aux_rpcs doesn't contain RPCs not in rpcs.
bad_ids = []
for id in aux_rpcs:
    if id in rpcs:
        rpc = rpcs[id]
        if (0 in rpc) and ((len(patterns)-1) in rpc):
            continue
    bad_ids.append(id)
for id in bad_ids:
    del aux_rpcs[id]

print_stats(patterns, rpcs)
print("")
print_stats(aux_patterns, aux_rpcs)

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
  print("  Transmit goodput (per RPC):    %5.1f Gbps (%4.1f%% of total time)" % (
      8e-03*out_data/out_time,
      100.0*out_time/end))
print("  Transmit goodput (aggregate):  %5.1f Gbps" % (
    8e-03*out_data/end))
if in_time != 0:
  print("  Receive goodput (per RPC):     %5.1f Gbps (%4.1f%% of total time)" % (
      8e-03*in_data/in_time,
      100.0*in_time/end))
print("  Receive goodput (aggregate):   %5.1f Gbps" % (
    8e-03*in_data/end))
if copy_in_time != 0:
  print("  Copy from user space:          %5.1f Gbps (%4.1f%% of total time)" % (
      8e-03*copy_in_data/copy_in_time,
      100.0*copy_in_time/end))
if copy_out_time != 0:
  print("  Copy to user space:           %6.1f Gbps (%4.1f%% of total time)" % (
      8e-03*copy_out_data/copy_out_time,
      100.0*copy_out_time/end))

if len(xmit_times):
    xmit_times = sorted(xmit_times)
    print("\nAverage time to xmit packet: %.1f us (P0: %.1f, P50: %.1f, "
            "P90: %.1f, P100: %.1f)" % (sum(xmit_times)/len(xmit_times),
            xmit_times[0], xmit_times[len(xmit_times)//2],
            xmit_times[9*len(xmit_times)//10], xmit_times[-1]))