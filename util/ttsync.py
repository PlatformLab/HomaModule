#!/usr/bin/python3

"""
Scans two timetraces covering the same time interval, determines the clock
offset between the two machines, and outputs the second timetrace with its
times adjusted so that they are synchronized with the first timetrace.
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
        'Read two timetraces, compute the clock offset between them, and '
        'write to standard output a revised version of the second trace '
        'with its clock offset to match the first',
        usage='%prog [options] t1 t2',
        conflict_handler='resolve')
parser.add_option('--verbose', '-v', action='store_true', default=False,
        dest='verbose',
        help='print lots of output')

(options, extra) = parser.parse_args()
if len(extra) != 2:
    print("Usage: %s [options] t1 t2" % (sys.argv[0]), file=sys.stderr)
    exit(1)
t1 = extra[0]
t2 = extra[1]

def parse_tt(tt):
    """
    Reads the timetrace file given by tt and returns a dictionary whose
    keys are packet ids (rpc_id:offset). Each value is a dictionary containing
    some or all of the following elements:
    send:                time when ip_queue_xmit was called for that data packet
    gro_recv:            time when homa_gro_receive saw the packet
    Note: all RPC ids are stored as client-side ids (even); ids read from
    server traces are adjusted to the corresponding client-side id
    """

    global options
    packets = {}
    sent = 0
    recvd = 0

    for line in open(tt):
        match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\]'
                '.* id ([-0-9.]+),.* offset ([-0-9.]+)', line)
        if not match:
            continue

        time = float(match.group(1))
        core = int(match.group(3))
        id = match.group(4)
        id = str(int(id) & ~1)
        offset = match.group(5)
        pktid = id + ":" + offset

        if not pktid in packets:
            packets[pktid] = {}

        if re.match('.*calling .*_xmit: wire_bytes', line):
            packets[pktid]["send"] = time
            sent += 1

        if "homa_gro_receive got packet" in line:
            packets[pktid]["gro_recv"] = time
            recvd += 1

    if options.verbose:
        print("%s has %d packet sends, %d receives" % (tt, sent, recvd),
                file=sys.stderr)
    return packets

def get_delays(p1, p2, msg):
    """
    Given two results from parse_tt, return a list containing all the
    delays from a packet sent in p1 and received in p2. The list will
    be sorted in increasing order. Msg is a string of the form "a to b"
    indicating the direction of packet flow; used for verbose messages.
    """
    global options
    delays = []
    min_delay = 1e09
    min_id = ""
    send_time = None
    recv_time = None
    for key in p1:
        if not key in p2:
            continue
        info1 = p1[key]
        info2 = p2[key]
        if (not "send" in info1) or (not "gro_recv" in info2):
            continue
        delay = info2["gro_recv"] - info1["send"]
        delays.append(delay)
        if delay < min_delay:
            min_delay = delay
            min_id = key
            send_time = info1["send"]
            recv_time = info2["gro_recv"]
    if options.verbose:
        print("Min delay from %s: %.1f usec (id %s, send %9.3f, recv %9.3f)" %
                (msg, min_delay, min_id, send_time, recv_time),
                file=sys.stderr)
    return sorted(delays)

t1_pkts = parse_tt(t1)
t2_pkts = parse_tt(t2)

t1_to_t2 = get_delays(t1_pkts, t2_pkts, "%s to %s" % (t1, t2))
t2_to_t1 = get_delays(t2_pkts, t1_pkts, "%s to %s" % (t1, t2))

if options.verbose:
    print("Found %d packets from %s to %s, %d from %s to %s" % (
            len(t1_to_t2), t1, t2, len(t2_to_t1), t2, t1), file=sys.stderr)

# Percentile to use for computing offset
percentile = 0

min_rtt = (t1_to_t2[percentile*len(t1_to_t2)//100]
        + t2_to_t1[percentile*len(t2_to_t1)//100])
print("RTT: P0 %.1f us, P5 %.1f us, P10 %.1fus, P20 %.1f us, P50 %.1f us" % (
        t1_to_t2[0] + t2_to_t1[0],
        t1_to_t2[5*len(t1_to_t2)//100] + t2_to_t1[5*len(t2_to_t1)//100],
        t1_to_t2[10*len(t1_to_t2)//100] + t2_to_t1[10*len(t2_to_t1)//100],
        t1_to_t2[20*len(t1_to_t2)//100] + t2_to_t1[20*len(t2_to_t1)//100],
        t1_to_t2[50*len(t1_to_t2)//100] + t2_to_t1[50*len(t2_to_t1)//100]),
        file=sys.stderr)
offset = min_rtt/2 - t1_to_t2[percentile*len(t1_to_t2)//100]

if options.verbose:
    print("%s clock offset (assuming %.1f us RTT): %.1fus" % (
            t2, min_rtt, offset), file=sys.stderr)
    print("%s->%s packet delays: min %.1f us, P50 %.1f us, "
            "P90 %.1f us, P99 %.1f us" % (
            t1, t2, t1_to_t2[0] + offset,
            t1_to_t2[len(t1_to_t2)//2] + offset,
            t1_to_t2[len(t1_to_t2)*9//10] + offset,
            t1_to_t2[len(t1_to_t2)*99//100] + offset), file=sys.stderr)
    print("%s->%s packet delays: min %.1f us, P50 %.1f us, "
            "P90 %.1f us, P99 %.1f us" % (
            t2, t1, t2_to_t1[0] - offset,
            t2_to_t1[len(t2_to_t1)//2] - offset,
            t2_to_t1[len(t2_to_t1)*9//10] - offset,
            t2_to_t1[len(t2_to_t1)*99//100] - offset), file=sys.stderr)

# Now re-read the second trace and output a new trace whose
# clock is aligned with the first trace.

for line in open(t2):
    match = re.match(' *([-0-9.]+) us (\(\+ *[-0-9.]+ us\) \[C[0-9]+\].*)',
            line)
    if not match:
        print(line)
    else:
        time = float(match.group(1)) + offset
        print("%9.3f us %s" % (time, match.group(2)))