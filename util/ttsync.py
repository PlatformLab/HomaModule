#!/usr/bin/python3

"""
Scans two timetraces covering the same time interval, one from a client and one
from a server, determines the clock offset between the two machines, and
outputs the server timetrace with its times adjusted so that they are
synchronized with the client timetrace.

Usage: ttsync.py [--verbose] [client [server]]

The "client" and "server" arguments give the names of the two timetrace
files; they default to client.tt and server.tt.
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

client_trace = "client.tt"
server_trace = "server.tt"
verbose = False
if (len(sys.argv) >= 2) and (sys.argv[1] == "--help"):
    print("Usage: %s [--verbose] [client_trace [server_trace]]" % (sys.argv[0]))
    sys.exit(0)
if (len(sys.argv) >= 2) and (sys.argv[1] == "--verbose"):
  verbose = True
  sys.argv.pop(1)
if len(sys.argv) >= 2:
  client_trace = sys.argv[1]
  sys.argv.pop(1)
if len(sys.argv) >= 2:
  server_trace = sys.argv[1]

def parse_tt(tt, server):
    """
    Reads the timetrace file given by tt and returns a dictionary containing
    extracted statistics (see below). The server argument indicates whether
    this is a server trace; if so, 1 gets subtracted from all RPC ids to
    produce client ids.

    The return value from parse_tt is a dictionary whose keys are packet
    ids (rpc_id:offset). Each value is a dictionary containing some or all
    of the following elements:

    send:                time when ip_queue_xmit was called for that data packet
    gro_recv:            time when homa_gro_receive saw the packet
    """

    global verbose
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
        if (server):
            id = str(int(id) - 1)
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

    if verbose:
        print("%s trace has %d packet sends, %d receives" % (
                ("Server" if server else "Client"), sent, recvd),
                file=sys.stderr)
    return packets

def get_delays(p1, p2):
    """
    Given two results from parse_tt, return a list containing all the
    delays from a packet sent in p1 and received in p2. The list will
    be sorted in increasing order.
    """
    delays = []
    for key in p1:
        if not key in p2:
            continue
        info1 = p1[key]
        info2 = p2[key]
        if (not "send" in info1) or (not "gro_recv" in info2):
            continue
        delay = info2["gro_recv"] - info1["send"]
        delays.append(delay)
    return sorted(delays)

client = parse_tt(client_trace, False)
server = parse_tt(server_trace, True)

c_to_s = get_delays(client, server)
s_to_c = get_delays(server, client)

if verbose:
    print("Found %d packets from client to server, %d from server to client" % (
            len(c_to_s), len(s_to_c)), file=sys.stderr)

min_rtt = (c_to_s[5*len(c_to_s)//100] + s_to_c[5*len(s_to_c)//100])
print("RTT: P0 %.1f us, P5 %.1f us, P10 %.1fus, P20 %.1f us, P50 %.1f us" % (
        c_to_s[0] + s_to_c[0], min_rtt,
        c_to_s[10*len(c_to_s)//100] + s_to_c[10*len(s_to_c)//100],
        c_to_s[20*len(c_to_s)//100] + s_to_c[20*len(s_to_c)//100],
        c_to_s[50*len(c_to_s)//100] + s_to_c[50*len(s_to_c)//100]),
        file=sys.stderr)
offset = min_rtt/2 - c_to_s[5*len(c_to_s)//100]

if verbose:
    print("Server clock offset (assuming %.1f us RTT): %.1fus" % (
            min_rtt, offset), file=sys.stderr)
    print("Client->server packet delays: min %.1f us, P50 %.1f us, "
            "P90 %.1f us, P99 %.1f us" % (
            c_to_s[0] + offset,
            c_to_s[len(c_to_s)//2] + offset,
            c_to_s[len(c_to_s)*9//10] + offset,
            c_to_s[len(c_to_s)*99//100] + offset), file=sys.stderr)
    print("Server->client packet delays: min %.1f us, P50 %.1f us, "
            "P90 %.1f us, P99 %.1f us" % (
            s_to_c[0] - offset,
            s_to_c[len(s_to_c)//2] - offset,
            s_to_c[len(s_to_c)*9//10] - offset,
            s_to_c[len(s_to_c)*99//100] - offset), file=sys.stderr)

# Now re-read the server's trace and output a new trace whose
# clock is aligned with the client.

for line in open(server_trace):
    match = re.match(' *([-0-9.]+) us (\(\+ *[-0-9.]+ us\) \[C[0-9]+\].*)',
            line)
    if not match:
        print(line)
    else:
        time = float(match.group(1)) + offset
        print("%9.3f us %s" % (time, match.group(2)))