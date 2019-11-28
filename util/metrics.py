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
Reads Homa metrics from the kernel and prints out anything that is changed
since the last time this program was invoked.
Usage: metrics.py [file]

If file is specified, it gives the name of a file in which this program
saves current metrics each time it is run, so that the next run can determine
what has changed. File defaults to ~/.homa_metrics.
"""

from __future__ import division, print_function
from glob import glob
from optparse import OptionParser
import math
import os
import re
import string
import sys

if len(sys.argv) > 1:
    data_file = sys.argv[1]
else:
    data_file = os.path.expanduser("~") + "/.homa_metrics"

# Scan the old data file (if it exists and build a dictionary of
# values.
prev = {}
deltas = {}
try:
    f = open(data_file)
except IOError:
    pass
if 'f' in locals():
    for line in f:
        match = re.match('^([^ ]*) *([0-9]+) *(.*)', line)
        if not match:
            print("Bogus line in data file: %s" % (line))
            continue
        symbol = match.group(1)
        count = int(match.group(2))
        prev[symbol] = count
    f.close()

# Scan the current metrics: compare with info from the data file, output
# differences, and also rewrite the data file with current data.

f = open("/proc/net/homa_metrics")
data = open(data_file, "w")
time_delta = 0
total_packets = 0
gro_packets = 0
elapsed_secs = 0
reaper_calls = 0
pad = ""

for line in f:
    data.write(line)
    match = re.match('^([^ ]*) *([0-9]+) *(.*)', line)
    if not match:
        print("Bogus line in Homa metrics: %s" % (line))
        continue
    symbol = match.group(1)
    count = int(match.group(2))
    doc = match.group(3)
    if (symbol in prev):
        old = prev[symbol]
    else:
        old = 0
    delta = float(count - old)
    deltas[symbol] = delta
    if (symbol == "rdtsc_cycles") and (old != 0) and "cpu_khz" in prev:
        time_delta = float(count - old)
        elapsed_secs = time_delta/(prev["cpu_khz"] * 1000.0)
        pad = pad.ljust(13)
    if old != count:
        rate_info = ""
        if (time_delta != 0):
            rate = float(count - old)/elapsed_secs
            if rate > 1000000:
                rate_info = "(%5.1f M/s) " % (rate/1000000.0)
            elif (rate > 1000):
                rate_info = "(%5.1f K/s) " % (rate/1000.0)
            else:
                rate_info = "(%5.1f  /s) " % (rate)
            rate_info = rate_info.ljust(13)
        if (symbol == "rdtsc_cycles") and (time_delta != 0):
            print("%-24s           %5.2f %sCPU clock rate (GHz)" % (
                  "clock_rate", float(prev["cpu_khz"])/1e06, pad))
            secs = "(%.1f s)" % (delta/(1000.0*prev["cpu_khz"]))
            secs = secs.ljust(12)
            print("%-24s %15d %s %s" % (symbol, count-old, secs, doc))
        elif symbol.endswith("_cycles") and (time_delta != 0):
            percent = "(%.1f%%)" % (100.0*delta/time_delta)
            percent = percent.ljust(12)
            print("%-24s %15d %s %s" % (symbol, count-old, percent, doc))
        else:
            print("%-24s %15d %s%s" % (symbol, count-old, rate_info, doc))
            if symbol.startswith("packets_rcvd_"):
                total_packets += count-old
            if symbol == "pkt_recv_calls":
                gro_packets = count-old
        if (symbol == "reaper_dead_skbs") and ("reaper_calls" in deltas):
            print("%-24s          %6.1f %sAvg. hsk->dead_skbs in reaper" % (
                  "avg_dead_skbs", delta/deltas["reaper_calls"], pad))
        if symbol.endswith("_miss_cycles") and (time_delta != 0):
            prefix = symbol[:-12]
            if (prefix + "_misses") in deltas:
                ns = (delta/deltas[prefix + "_misses"])/(prev["cpu_khz"]
                        * 1e-06)
                print("%-24s          %6.1f %sAvg. wait time per %s miss (ns)" % (
                    prefix + "_miss_delay", ns, pad, prefix))
if gro_packets != 0:
    print("%-24s          %6.2f %sHoma packets per GRO 'packet'" % (
          "gro_benefit", float(total_packets)/float(gro_packets), pad))

f.close()
data.close()