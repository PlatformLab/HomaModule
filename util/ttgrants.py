#!/usr/bin/python3

"""
Scans a timetrace to compute grant lag: how long it takes after a
grant is issued for the granted packet to arrive. Also computes
statistics on when grants arrive compared to when they are needed
to transmit at full bandwidth.
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

def percentile(list, pct, format, na):
    """
    Finds the element of list corresponding to a given percentile pct
    (0 is first, 100 or more is last), formats it according to format,
    and returns the result. Returns na if the list is empty.
    """
    if len(list) == 0:
        return na
    i = int(pct*len(list)/100)
    if i >= len(list):
        i = len(list) - 1
    return format % (list[i])

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

# Network link speed in Gbps.
gbps = 40

# Collects all the observed grant latencies (time from sending grant
# to receiving first data packet enabled by grant), in microseconds
latencies = []

# Keys are RPC ids. Each value is a list of lists, one per outstanding
# grant, where each sublist consists of a pair <time, start_offset, end_offset>
# griple identifying one grant
out_grants = {}

# Keys are RPC ids, values are the highest offset seen in any grant
# for the RPC (including the initial "grant" for unscheduled data).
last_grant = {}

# Largest observed incoming packet size (presumably a full GSO packet?).
packet_size = 0

# Keys are outgoing RPC ids; each value is the amount of unscheduled data
# transmitted for that RPC.
unscheduled = {}

# Keys are RPC ids; each value is a list of lists, one per grant received
# for that RPC, and each entry is an triple <time, start, end> pair indicating
# when the grant was received and the range of bytes it covers.
in_grants = {}

# Keys are RPC ids; each value is a list of lists, one per data packet
# sent for that RPC, and each entry is an <time, offset> pair describing
# that data packet.
out_data = {}

# Keys are RPC ids; each value is the first time at which we noticed that
# this RPC is transmitting data.
first_out = {}

for line in f:
    # Collect info about outgoing grants (including implicit grants
    # for unscheduled bytes)
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
          'Incoming message for id ([0-9.]+) has ([0-9.]+) unscheduled', line)
    if match:
        time = float(match.group(1))
        id = int(match.group(4))
        offset = int(match.group(5))
        last_grant[id] = offset
        out_grants[id] = []
        # print("%9.3f: unscheduled 'grant' for id %d, offset %d" % (
        #         time, id, offset))

    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
          'sending grant for id ([0-9.]+), offset ([0-9.]+)', line)
    if match:
        time = float(match.group(1))
        id = int(match.group(4))
        offset = int(match.group(5))
        if id in last_grant:
            # print("%9.3f: grant for id %d, %d:%d" % (time, id,
            #         last_grant[id], offset))
            out_grants[id].append([time, last_grant[id], offset])
            last_grant[id] = offset

    # Collect info about incoming data packets
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
          'incoming data packet, id ([0-9]+), .*, offset ([0-9.]+)', line)
    if match:
        time = float(match.group(1))
        id = int(match.group(4))
        offset = int(match.group(5))

        # Update grant latencies
        if not id in out_grants:
            continue
        grants = out_grants[id]
        if grants:
            grant = grants[0]
            if grant[1] < offset:
                if verbose:
                    print("%9.3f: grant lag %.1f us (%9.3f us), id %d, "
                            "range %d:%d" % (time, time - grant[0], grant[0],
                            id, grant[1], grant[2]))
                latencies.append(time - grant[0])
                grants.pop(0)

    # Collect information about unscheduled data for outgoing RPCs
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
            'starting copy from user space .* id ([0-9]+), .* unscheduled ([0-9]+)',
            line)
    if match:
        time = float(match.group(1))
        id = int(match.group(4))
        unsched = int(match.group(5))
        unscheduled[id] = unsched
        first_out[id] = time
        # print("%9.3f: %d unscheduled bytes for id %d" % (time, id, unsched))

    # Collect info about incoming grants
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
            'processing grant for id ([0-9]+), offset ([0-9]+)', line)
    if match:
        time = float(match.group(1))
        id = int(match.group(4))
        offset = int(match.group(5))
        if not id in in_grants:
            if not id in out_data:
                # The trace doesn't include any outgoing data packets
                continue
            in_grants[id] = []
        if in_grants[id]:
            start = in_grants[id][-1][2]
        else:
            if not id in unscheduled:
                continue
            start = unscheduled[id]
        if start >= offset:
            print("%9.3f: out of order grant for id %d: offset %d followed "
                    "by offset %d" % (time, id, start, offset))
            continue
        in_grants[id].append([time, start, offset])
        # print("%9.3f: incoming grant for id %d, range %d:%d" % (
        #         time, id, start, offset))

    # Collect info about outgoing data packets (and also the packet size)
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
            'Finished queueing packet: .* id ([0-9]+), offset ([0-9]+), '
            'len ([0-9]+)', line)
    if match:
        time = float(match.group(1))
        id = int(match.group(4))
        offset = int(match.group(5))
        size = int(match.group(6))
        if size > packet_size:
            packet_size = size
            # print("Setting packet size to %d" % (packet_size))
        if not id in out_data:
            if offset != 0:
                # The trace doesn't include all outgoing data packets
                continue
            out_data[id] = []
        out_data[id].append([time, offset])
        if not (id in first_out):
            first_out[id] = time
        # print("%9.3f: outgoing data for id %d, offset %d" % (
        #         time, id, offset))

# Get statistics about the time from first data packet to first
# incoming grant
first_grants = []
for id in out_data:
    if not ((id in in_grants) and in_grants[id]):
        continue
    delay = in_grants[id][0][0] - out_data[id][0][0]
    first_grants.append(delay)
    # print("Grant lag for id %d: %.3f us (ip_queue_xmit %.3f, "
            # "grant received %.1f" % (id, delay, out_data[id][0][0],
            # in_grants[id][0][0]))

# Time to transmit a full-size packet, in microseconds.
xmit_time = (packet_size * 8)/(gbps * 1000)
print("Largest observed incoming packet: %d bytes" % (packet_size))
print("Wire serialization time for %d-byte packet at %d Gbps: %.1f us" % (
        packet_size, gbps, xmit_time))

# Collect info for all incoming grants about how much additional data
# is authorized by each grant.
in_deltas = []
for key in in_grants:
    rpc_grants = in_grants[key]
    for grant in rpc_grants:
        in_deltas.append(grant[2] - grant[1])

# Compute lag in incoming grants (when the grant arrives relative to
# when we need it). For this, we only consider second and later grants
# for an RPC (assume the first one may be delayed by SRPT).
in_lags = []
total_lag = 0
for id in out_data:
    if not id in in_grants:
        continue
    data = out_data[id]
    grants = in_grants[id]
    # For each grant, find the last data packet that could be sent
    # without needing that grant
    d = 0
    prev_data_time = 0
    for g in range(1, len(in_grants[id])):
        grant = grants[g]
        grant_start = grant[1]
        time = grant[1]
        if d >= len(data):
            print("Ran out of data packets for id %d" % (id))
            break
        while (data[d][1] < grant_start) and (d < (len(data)-1)):
            prev_data_time = data[d][0]
            d += 1
        if data[d][1] < grant_start:
            break
        lag = grant[0] - prev_data_time - xmit_time
        in_lags.append(lag)
        if (lag > 0):
            total_lag += lag
        # print("%9.3f: grant offset %d arrived for id %d, data time %9.3f" % (
        #         grant[1], grant_start, id, prev_data_time))

# Compute total amount of time during which at least one RPC was actively
# transmitting.
xmit_active_time = 0
start_times = []
end_times = []
for id in out_data:
    start_times.append(first_out[id])
    end_times.append(out_data[id][-1][0])
start_times = sorted(start_times)
end_times = sorted(end_times)
num_active = 0
active_start = 0
while (len(start_times) > 0) or (len(end_times) > 0):
    if len(start_times) > 0:
        if (len(end_times) == 0) or (start_times[0] < end_times[0]):
            if num_active == 0:
                active_start = start_times[0]
            num_active += 1
            start_times.pop(0)
            continue
    num_active -= 1
    if num_active == 0:
        xmit_active_time += end_times[0] - active_start
    end_times.pop(0)

latencies = sorted(latencies)
first_grants = sorted(first_grants)
in_lags = sorted(in_lags)
print("\nLatency:         time from sending grant for an incoming message")
print("                 (in homa_send_grants) to receiving first granted")
print("                 data in Homa SoftIRQ")
print("First Lag:       time from calling ip_queue_xmit for first data packet")
print("                 until receiving first grant in Homa SoftIRQ")
print("In Lag:          time when a grant arrived, relative to time when")
print("                 it was needed to send message at full bandwidth")
print("                 (skips first grant for each message)")
print("Pctile       Latency     First Lag      In Lag")
for p in [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 99, 100]:
    print("%3d        %s     %s   %s" %(p,
            percentile(latencies, p, "%6.1f us", "   N/A   "),
            percentile(first_grants, p, "%6.1f us", "   N/A   "),
            percentile(in_lags, p, "%6.1f us", "   N/A   ")))

if len(latencies) == 0:
    out_avg = "   N/A   "
else:
    out_avg = "%6.1f us" % (sum(latencies)/len(latencies))
if len(first_grants) == 0:
    in_avg = "   N/A   "
else:
    in_avg = "%6.1f us" %  (sum(first_grants)/len(first_grants))
if len(in_lags) == 0:
    in_lags_avg = "   N/A   "
else:
    in_lags_avg = "%6.1f us" %  (sum(in_lags)/len(in_lags))
print("Average:   %9s     %9s   %9s" % (out_avg, in_avg, in_lags_avg))

if xmit_active_time != 0:
    print("\nTotal data packet xmit delays because grants were slow:\n"
            "%.1f us (%.1f%% of xmit active time)" % (
            total_lag, 100.0*total_lag/xmit_active_time))

in_deltas = sorted(in_deltas)
print("\nSizes of incoming grants (additional authorized data)")
print("Pctile       Size")
for p in [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 99, 100]:
    print("%3d      %8s" %(p, percentile(in_deltas, p, "%d", "N/A")))

if len(in_deltas) == 0:
    in_avg = "N/A"
else:
    in_avg = "%.0f" %  (sum(in_deltas)/len(in_deltas))
print("Average  %8s" % (in_avg))
