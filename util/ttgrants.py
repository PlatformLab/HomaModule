#!/usr/bin/python3

"""
Scans a timetrace to compute various statistics related to grants, such
as how long it takes after a grant is issued for the first newly granted
packet to arrive. It can be used on either a client-side or server-side trace.
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

# Parse command line options
parser = OptionParser(description=
        'Read a timetrace and output statistics related to grants (works'
        ' on both clients and servers)',
        usage='%prog [options] [trace]',
        conflict_handler='resolve')
parser.add_option('--verbose', '-v', action='store_true', default=False,
        dest='verbose',
        help='print lots of output')
parser.add_option('--gbps', type='int', dest='gbps', default=25,
        metavar = 'N', help='network speed in Gbps')
parser.add_option('--rtt_bytes', type='int', dest='rtt_bytes', default=60000,
        metavar = 'N', help='rtt_bytes sysctl parameter for Homa')

(options, extra) = parser.parse_args()
f = sys.stdin
if len(extra) > 0:
    f = open(extra[0])
    if len(extra) > 1:
      print("Unrecognized argument %s" % (extra[1]))
      exit(1)

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

# Collects all the observed grant latencies (time from sending grant
# to receiving first data packet enabled by grant), in microseconds
latencies = []

# Keys are RPC ids. Each value is a list of lists, one per outstanding
# grant, where each sublist consists of a <time, prev_offset, new_offset>
# triple identifying one grant
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
# for that RPC, and each entry is a triple <time, prev_offset, new_offset>
# indicating when the grant was received and the range of bytes it covers.
in_grants = {}

# Keys are RPC ids; each value is a list of lists, one per data packet
# received by homa_gro_receive for that RPC, and each entry is a <time, offset>
# pair describing that data packet.
gro_data = {}

# Keys are RPC ids; each value is a list of lists, one per data packet
# received by homa_softirq for that RPC, and each entry is a <time, offset>
# pair describing that data packet.
softirq_data = {}

# Keys are RPC ids; each value is a list of lists, one per data packet
# sent for that RPC, and each entry is an <time, offset, length> triple
# describing that data packet.
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

    # Collect info about incoming data packets processed by homa_softirq
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
          'incoming data packet, id ([0-9]+), .*, offset ([0-9.]+)', line)
    if match:
        time = float(match.group(1))
        id = int(match.group(4))
        offset = int(match.group(5))

        if not id in softirq_data:
            softirq_data[id] = []
        softirq_data[id].append([time, offset])

    # Collect info about incoming data packets processed by homa_gro_receive
    match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\] '
          'homa_gro_receive got packet .* id ([0-9]+), offset ([0-9.]+)',
          line)
    if match:
        time = float(match.group(1))
        id = int(match.group(4))
        offset = int(match.group(5))

        if not id in gro_data:
            gro_data[id] = []
        gro_data[id].append([time, offset])

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
        out_data[id].append([time, offset, size])
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
xmit_time = (packet_size * 8)/(options.gbps * 1000)
print("Largest observed outgoing packet: %d bytes" % (packet_size))
print("Wire serialization time for %d-byte packet at %d Gbps: %.1f us" % (
        packet_size, options.gbps, xmit_time))

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

# Compute "Latency": delay between issuing a grant and receipt in homa_softirq
# of the first data packet that depended on that grant.

for id in out_grants:
    if not id in softirq_data:
        continue;

    data = softirq_data[id].copy()
    for grant in out_grants[id]:
        while data and (data[0][1] <= grant[1]):
            data.pop(0)
        if not data:
            break
        latency = data[0][0] - grant[0]
        if options.verbose:
            print("%9.3f: grant lag %.1f us (%9.3f us), id %d, "
                    "range %d:%d" % (data[0][0], latency, grant[0],
                    id, grant[1], grant[2]))
        latencies.append(latency)

# Compute "Xmit Lag": time it takes after a data packet arrives in GRO to
# send a new grant enabled by that data packet.
xmit_lags = []
for id in out_grants:
    if not id in gro_data:
        continue
    data = sorted(gro_data[id], key=lambda tuple : tuple[1])
    prev_data = None
    for grant in out_grants[id]:
        while data and (data[0][1] + options.rtt_bytes) <= grant[1]:
            prev_data = data[0]
            data.pop(0)
        if not data:
            break

        # The current data packet is the one *just after* the one that
        # triggered the current grant, so the lag is measured from the
        # previous data packet.
        if not prev_data:
            print("%9.3f: no prev_data for grant" % (grant[0]))
            continue
        lag = grant[0] - prev_data[0]
        xmit_lags.append(lag)
        if options.verbose:
            print("%9.3f: data packet %d-%d triggered grant %d-%d, at %9.3f" %
                    (prev_data[0], prev_data[1], data[0][1],
                    grant[1], grant[2], grant[0]))

# Compute "Client Lag": time it takes after sending a data packet for
# homa_softirq to receive a new grant triggered by that packet.
client_lags = []
for id in in_grants:
    if not id in out_data:
        continue
    data = out_data[id].copy()
    for grant in in_grants[id]:
        while data and (data[0][1] + data[0][2] + options.rtt_bytes) <= grant[1]:
            data.pop(0)
        if not data:
            break

        lag = grant[0] - data[0][0]
        client_lags.append(lag)
        if options.verbose:
            print("%9.3f: client data packet %d-%d triggered grant %d-%d, at %9.3f" %
                    (data[0][0], data[0][1], data[0][1] + data[0][2],
                    grant[1], grant[2], grant[0]))

latencies = sorted(latencies)
first_grants = sorted(first_grants)
in_lags = sorted(in_lags)
xmit_lags = sorted(xmit_lags)
client_lags = sorted(client_lags)
print("\nLatency:         time from sending grant for an incoming message")
print("                 (in homa_send_grants) to receiving first granted")
print("                 data in Homa SoftIRQ")
print("First Lag:       time from calling ip_queue_xmit for first data packet")
print("                 until homa_softirq gets first grant")
print("Client Lag:      time from calling ip_queue_xmit for a data packet")
print("                 until homa_softirq gets grant triggered by that packet")
print("In Lag:          time when a grant arrived, relative to time when")
print("                 it was needed to send message at full bandwidth")
print("                 (skips first grant for each message)")
print("Xmit Lag:        time when a data packet arrives that allows a new")
print("                 grant until the new grant is transmitted")
print("Pctile      Latency   First Lag  Client Lag     In Lag   Xmit Lag")
for p in [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 99, 100]:
    print("%3d       %s   %s   %s  %s  %s" % (p,
            percentile(latencies, p, "%6.1f us", "      N/A"),
            percentile(first_grants, p, "%6.1f us", "      N/A"),
            percentile(client_lags, p, "%6.1f us", "      N/A"),
            percentile(in_lags, p, "%6.1f us", "      N/A"),
            percentile(xmit_lags, p, "%6.1f us", "      N/A")))

if latencies:
    out_avg = "%6.1f us" % (sum(latencies)/len(latencies))
else:
    out_avg = "      N/A"
if first_grants:
    first_avg = "%6.1f us" %  (sum(first_grants)/len(first_grants))
else:
    first_avg = "      N/A"
if client_lags:
    client_avg = "%6.1f us" %  (sum(client_lags)/len(client_lags))
else:
    client_avg = "      N/A"
if in_lags:
    in_lags_avg = "%6.1f us" %  (sum(in_lags)/len(in_lags))
else:
    in_lags_avg = "      N/A"
if xmit_lags:
    xmit_avg = "%6.1f us" % (sum(xmit_lags)/len(xmit_lags))
else:
    xmit_avg = "      N/A"
print("Avg:      %9s   %9s   %9s  %9s  %9s" % (out_avg, first_avg, client_avg,
        in_lags_avg, xmit_avg))

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
