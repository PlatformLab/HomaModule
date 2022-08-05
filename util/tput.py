#!/usr/bin/python3

"""
Analyzes throughput of message arrivals in a timetrace.
Usage: tput.py [--verbose] [tt_file]

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

verbose = False
if (len(sys.argv) >= 2) and (sys.argv[1] == "--verbose"):
  verbose = True
  sys.argv.pop(1)
if len(sys.argv) == 2:
    f = open(sys.argv[1])
elif len(sys.argv) == 1:
    f = sys.stdin
else:
    print("Usage: %s [tt_file]" % (sys.argv[0]))
    sys.exit(1)

# Keys are RPC ids, values are dictionaries containing the following fields:
# start: time offset 0 received
# grant: time the first grant was sent
# grant_offset: offset in last data packet after first grant
# end: time last packet received
# offset: highest offset in any packet received for the RPC
rpcs = {}

for line in f:
    match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\]', line)
    if not match:
        continue
    time = float(match.group(1))
    core = match.group(2)

    match = re.match('.*sending grant for id ([0-9]+)',
        line)
    if match:
      id = match.group(1)
      if id in rpcs and not 'grant' in rpcs[id]:
        rpcs[id]['grant'] = time
        rpcs[id]['grant_offset'] = rpcs[id]['offset']

    match = re.match('.*homa_gro_receive got packet .* id ([0-9]+), '
        'offset ([0-9]+)', line)
    if match:
        id = match.group(1)
        offset = int(match.group(2))
        if (not id in rpcs) and (offset == 0):
          rpcs[id] = {'offset': 0, 'start': time}
        if id in rpcs:
          rpcs[id]['end'] = time
          if offset > rpcs[id]['offset']:
              rpcs[id]['offset'] = offset

    match = re.match('.*incoming data packet, id ([0-9]+), .* offset '
        '([0-9]+)/([0-9]+)', line)
    if match:
      id = match.group(1)
      length = int(match.group(3))
      if id in rpcs:
        rpcs[id]['length'] = length

total_bytes = 0
total_bytes2 = 0
total_time = 0
total_time2 = 0
tputs = []
tputs2 = []
for id in sorted(rpcs.keys()):
    rpc = rpcs[id]
    if (not 'start' in rpc) or (not 'end' in rpc):
        continue
    if rpc['offset'] < 300000:
        continue
    bytes = rpc['offset']
    time = rpc['end'] - rpc['start']
    tput = bytes*8.0/time/1000
    tputs.append(tput)
    total_bytes += bytes
    total_time += time
 
    # Compute separate statistics for throughput after sending the first
    # grant (this eliminates time waiting for the message to become highest
    # priority)
    if 'grant' in rpc:
      bytes2 = rpc['offset'] - rpc['grant_offset']
      time2 = rpc['end'] - rpc['grant']
      tput2 = bytes2*8.0/time2/1000
      tputs2.append(tput2)
      total_bytes2 += bytes2
      total_time2 += time2

      if verbose:
        print("%9.3f: id %s, grant at %9.3f, offset grant_offset %d, "
            "last_offset %d at %9.3f, tput %.1f, tput2 %.1f" % (
            rpc['start'], id, rpc['grant'], rpc['grant_offset'], rpc['offset'],
            rpc['end'], tput, tput2))

tputs.sort()
if verbose:
  print("")
print("Messages >= 300KB: %d" % (len(tputs)))
print("Entire messages:")
print("Minimum tput: %4.1f Gbps" % (tputs[0]))
print("Median tput:  %4.1f Gbps" % (tputs[len(tputs)//2]))
print("P90 tput:     %4.1f Gbps" % (tputs[len(tputs)*9//10]))
print("P99 tput:     %4.1f Gbps" % (tputs[len(tputs)*99//100]))
print("Maximum tput: %4.1f Gbps" % (tputs[-1]))
print("Average tput: %4.1f Gbps" % (total_bytes*8.0/total_time/1000))

tputs2.sort()
print("\nMessage data after first grant:")
print("Minimum tput: %4.1f Gbps" % (tputs2[0]))
print("Median tput:  %4.1f Gbps" % (tputs2[len(tputs2)//2]))
print("P90 tput:     %4.1f Gbps" % (tputs2[len(tputs2)*9//10]))
print("P99 tput:     %4.1f Gbps" % (tputs2[len(tputs2)*99//100]))
print("Maximum tput: %4.1f Gbps" % (tputs2[-1]))
print("Average tput: %4.1f Gbps" % (total_bytes2*8.0/total_time2/1000))
