#!/usr/bin/env python

# Copyright (c) 2019 Stanford University
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
Compute service times for RPCs from a server-side trace.
Usage: service.py [tt_file]

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

# RPC structures have the following elements:
# start -            Time of first record
# id -               RPC id
# rcv_lag -          Extra time before first call to homa_pkt_rcv
# wakeup_lag -       Extra time before the server thread wakes up
# recv_done -        The time when homa_ioc_recv finishes
# recv_done_lag -    Extra time to finish homa_ioc_recv
# first_xmit -       Time when first result packet is transmitted
# first_xmit_lag -   Extra time between receive_done and first_xmit
# freed -            Time when RPC is freed (last packet transmitted)
# grant_lag -        Time from start to xmit of first grant packet
# xmit_lag -         Extra time between first_xmit and freed
# interrupt -        Time of most recent packet reception by interrupt handler
# interrupt_gaps -   Total time in unexpectedly long gaps between pack
#                    receptions by the interrupt handler
# last_packet_lag -  Extra time before the interrupt handler received the
#                    last packet
# packets -          Total number of packets received for this RPC
# total -            Total elapsed time from receiving first data packet to
#                    transmitting last result packet

# RPCs for which at least one packet has arrived, but no result
# packets have been sent. Indexed by RPC id.
active = {}

# RPCs that appear to be complete (at least one packet has arrived, and
# at least one result has been sent)
complete = []

min = 1000000
min_id = ""
max = 0
max_id = ""

def average(dict, key):
    sum = 0.0
    if len(dict) == 0:
        return 0.0
    for record in dict:
        sum += record[key]
    return sum/len(dict)

def largest(dict, key):
    max = None
    if len(dict) == 0:
        return 0.0
    for record in dict:
        if (key in record) and ((not max) or (record[key] > max[key])):
            max = record
    return max

def smallest(dict, key):
    min = None
    if len(dict) == 0:
        return 0.0
    for record in dict:
        if (key in record) and ((not min) or (record[key] < min[key])):
            min = record
    return min

def collect(dict, key):
    result = []
    for record in dict:
        result.append(record[key])
    return result;

for line in f:
    match = re.match(' *([0-9.]+) us .* id ([0-9]+)', line)
    if not match:
        continue
    time = float(match.group(1))
    id = match.group(2)

    if re.match('.*mlx received homa.* offset ', line):
        if not id in active:
            rpc = {}
            rpc["start"] = time
            rpc["id"] = id
            rpc["packets"] = 1
            active[id] = rpc
        else:
            rpc = active[id]
            rpc["packets"] += 1

        if not "interrupt" in rpc:
            rpc["interrupt_gaps"] = -9.4
        else:
            lag = time - rpc["interrupt"] - .30
            if lag > 0:
                rpc["interrupt_gaps"] += lag
        rpc["interrupt"] = time

    if not id in active:
        continue
    rpc = active[id]

    if re.match('.*homa_pkt_recv: first.*, type 20', line):
        if not "rcv_lag" in rpc:
            lag = time - rpc["start"] - 4.5
            # print("receive lag for id %s: %.1f" % (id, lag))
            if lag < 0:
                lag = 0.0
            rpc["rcv_lag"] = lag

    if re.match('.*mlx_xmit starting, .* type 21', line):
        if not "grant_lag" in rpc:
            rpc["grant_lag"] = time - rpc["start"]

    if re.match('.*message woke up,', line):
        lag = time - rpc["start"] - 35.2
        # print("wakeup lag for id %s: %.1f" % (id, lag))
        if lag < 0:
            lag = 0.0
        rpc["wakeup_lag"] = lag

    if re.match('.*homa_ioc_recv finished', line):
        rpc["recv_done"] = time
        if not "wakeup_lag" in rpc:
            rpc["wakeup_lag"] = 0
        lag = time - rpc["start"] - 54.2 - rpc["wakeup_lag"]
        # print("finish lag for id %s: %.1f" % (id, lag))
        if lag < 0:
            lag = 0.0
        rpc["recv_done_lag"] = lag

    if re.match('.*mlx_xmit starting.* offset ', line) \
            and not "first_xmit" in rpc:
        if not "recv_done" in rpc:
            print("No recv_done for id %s" % (id))
            continue
        rpc["first_xmit"] = time
        lag = time - rpc["recv_done"] - 14.8
        if lag < 0:
            lag = 0.0
        rpc["first_xmit_lag"] = lag

        lag = rpc["interrupt"] - rpc["start"] - 34.4
        if lag < 0:
            lag = 0
        rpc["last_packet_lag"] = lag

    if re.match('.*Freeing rpc', line):
        total = time - rpc["start"]
        rpc["total"] = total
        if not "first_xmit" in rpc:
            print("No first_xmit for id %s" % (id))
            continue
        lag = time - rpc["first_xmit"] - 26.0
        if lag < 0:
            lag = 0.0
        rpc["xmit_lag"] = lag
        print("xmit_lag for id %s: %.1f" % (rpc["id"], lag))

        complete.append(rpc)
        del(active[id])

if len(complete) == 0:
    print("No complete RPCs were found; have trace records changed format?")
    exit(1)

# Discard data for any RPCs that haven't received the right number of packets.
counts = collect(complete, "packets")
expected_count = counts[len(counts)//2]
discards = ""
i = 0
while i < len(complete):
    rpc = complete[i]
    if rpc["packets"] != expected_count:
        if discards != "":
            discards += ", "
        discards += "id %s @ %.3f (%d packets)" % (rpc["id"], rpc["start"],
                rpc["packets"])
        del(complete[i])
    else:
        i += 1

# Print info about each completed RPC, plus compute min/max.
min = 1000000
min_id = ""
max = 0
max_id = ""
for rpc in complete:
    total = rpc["total"]
    print("%s %.2f" % (rpc["id"], total))
    if total < min:
        min = total
        min_id = rpc["id"]
        # print("New min %.1f: id %s, start %.1f, end line: %s" % (min,
              # min_id, rpc["start"], line))
    if total > max:
        max = total
        max_id = rpc["id"]

if discards != "":
    print("Discarded RPCs: %s" % (discards))

average_lag = average(complete, "total") - min
if average_lag == 0:
   average_lag = 0.00001
average_rcv_lag = average(complete, "rcv_lag")
average_wakeup_lag = average(complete, "wakeup_lag")
average_recv_done_lag = average(complete, "recv_done_lag")
average_first_xmit_lag = average(complete, "first_xmit_lag")
average_interrupt_gaps = average(complete, "interrupt_gaps")
average_last_packet_lag = average(complete, "last_packet_lag")
average_xmit_lag = average(complete, "xmit_lag")

times = collect(complete, "total")
times.sort()
print("%d completed RPCs, min %.1f us (%s), P50 %.1f us, max %.1f us (%s)" % (
        len(times), min, min_id, times[len(times)//2], max, max_id))

print("wakeup lag:              %5.1f us (%4.1f%%)" % (average_wakeup_lag,
        100.0* average_wakeup_lag/average_lag))
print("    homa_rcv_pkt lag:    %5.1f us (%4.1f%%)" % (average_rcv_lag,
        100.0* average_rcv_lag/average_lag))
print("    interrupt gaps:      %5.1f us (%4.1f%%)" % (average_interrupt_gaps,
        100.0* average_interrupt_gaps/average_lag))
print("    last interrupt lag:  %5.1f us (%4.1f%%)" % (average_last_packet_lag,
        100.0* average_last_packet_lag/average_lag))
print("recv_done lag:           %5.1f us (%4.1f%%)" % (average_recv_done_lag,
        100.0* average_recv_done_lag/average_lag))
print("first_xmit lag:          %5.1f us (%4.1f%%)" % (average_first_xmit_lag,
        100.0* average_first_xmit_lag/average_lag))
print("xmit lag:                %5.1f us (%4.1f%%)" % (average_xmit_lag,
        100.0* average_xmit_lag/average_lag))
print("Average total lag:       %5.1f us" % (average_lag))


times = collect(complete, "grant_lag")
times.sort()
min = smallest(complete, "grant_lag")
max = largest(complete, "grant_lag")
print("Grant delay: min %.1f us (%s), P50 %.1f us, P90 %.1fus, max %.1f us (%s)" % (
        min["grant_lag"], min["id"], times[len(times)//2], times[9*len(times)//10],
        max["grant_lag"], max["id"]))