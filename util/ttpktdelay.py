#!/usr/bin/python3

"""
Scans two timetraces for the same time interval, one from a client and one
from a server, to analyze packet delays in both directions.

Usage: ttpktdelay.py [--verbose] [client [server]]

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

# For each of the following dictionaries, keys are packet ids (rpc_id:offset),
# values are times when that packet id was sent or received. rpc_id's are
# client-side ids, even for server info.
# data_send:     time when ip_queue_xmit was called for a data packet
# data_mlx:      time when mlx driver finished sending a data packet
# data_rcv:      time when Homa's GRO handler saw an incoming data packet
# data_softirq:  time when Homa's SoftIRQ handler processed an incoming
#                data packet.
# grant_send:    time when homa_send_grants decided to send a grant
# grant_mlx:     time when mlx driver finished sending a grant
# grant_mlx:     time when Homa's GRO handler saw an incoming grant
# grant_softirq: time when Homa's SoftIRQ handler processed a grant
client_data_send = {}
server_data_send = {}
client_data_mlx = {}
server_data_mlx = {}
client_data_rcv = {}
server_data_rcv = {}
client_data_softirq = {}
server_data_softirq = {}
client_grant_send = {}
server_grant_send = {}
client_grant_mlx = {}
server_grant_mlx = {}
client_grant_rcv = {}
server_grant_rcv = {}
client_grant_softirq = {}
server_grant_softirq = {}

def percentile(list, pct, format):
    """
    Finds the element of list corresponding to a given percentile pct
    (0 is first, 100 or more is last), formats it according to format,
    and returns the result. Returns "N/A" if the list is empty.
    """
    if len(list) == 0:
        return "N/A"
    i = int(pct*len(list)/100)
    if i >= len(list):
        i = len(list) - 1
    return format % (list[i])

def dict_diffs(dict1, dict2):
    """
    Return a list consisting of the differences between elements in
    dict2 and those in dict1 with matching keys (ignore elements that
    appear in only one dict).
    """
    diffs = []
    for key in dict1:
        if key in dict2:
            diffs.append(dict2[key] - dict1[key])
    return diffs

def parse_tt(tt, server, data_send, data_mlx, data_rcv, data_softirq,
        grant_send, grant_mlx, grant_rcv, grant_softirq):
    """
    Reads the timetrace file given by tt and extracts timing information
    into the remaining arguments (see documentation above) The server
    argument indicates whether this is a server trace; if so, 1 gets
    subtracted from all RPC ids to produce client ids.
    """

    # Keys are RPC ids and core; each value is the most recent pktid for which
    # ip_queue_xmit was invoked for this RPC on this core.
    grant_ids = {}

    for line in open(tt):
        match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\]'
                '.* id ([-0-9.]+),.* offset ([-0-9.]+)', line)
        if not match:
            # mlx finished sending grant
            match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\] mlx '
                    'sent homa packet to .* id ([-0-9.]+), type 21', line)
            if match:
                time = float(match.group(1))
                core = match.group(2)
                id = match.group(3)
                if (server):
                    id = str(int(id) - 1)
                key = id + ":" + core
                if key in grant_ids:
                    grant_mlx[grant_ids[key]] = time
            continue

        time = float(match.group(1))
        core = match.group(3)
        id = match.group(4)
        if (server):
            id = str(int(id) - 1)
        offset = match.group(5)
        pktid = id + ":" + offset

        # Outgoing data sent
        if "calling ip_queue_xmit: skb->len" in line:
            data_send[pktid] = time

        # Data packet passed to NIC
        if "mlx sent homa data packet" in line:
            data_mlx[pktid] = time

        # Incoming data (NAPI level)
        if "homa_gro_receive got packet" in line:
            data_rcv[pktid] = time

        # Incoming data (SoftIRQ level)
        if "incoming data packet, id" in line:
            data_softirq[pktid] = time

        # Outgoing grant
        if "sending grant for id" in line:
            grant_send[pktid] = time
            key = id + ":" + core
            grant_ids[key] = pktid

        # Incoming grant (NAPI level)
        if "homa_gro_receive got grant" in line:
            grant_rcv[pktid] = time

        # Incoming grant (SoftIRQ level)
        if "processing grant for id" in line:
            grant_softirq[pktid] = time

parse_tt(client_trace, False, client_data_send, client_data_mlx,
        client_data_rcv, client_data_softirq, client_grant_send,
        client_grant_mlx, client_grant_rcv, client_grant_softirq)
parse_tt(server_trace, True, server_data_send, server_data_mlx,
        server_data_rcv, server_data_softirq, server_grant_send,
        server_grant_mlx, server_grant_rcv, server_grant_softirq)

# Now combine the data from the two time traces to compute interesting delays

# Time differences for data packets and grants passing through the IP stack
# on a single machine.
client_data_xmit = sorted(dict_diffs(client_data_send, client_data_mlx))
client_grant_xmit = sorted(dict_diffs(client_grant_send, client_grant_mlx))
server_data_xmit = sorted(dict_diffs(server_data_send, server_data_mlx))
server_grant_xmit = sorted(dict_diffs(server_grant_send, server_grant_mlx))

# Time differences for data packets and grants passing from client to server.
# These differences include clock differences between the machines.
cs_data_delays = sorted(dict_diffs(client_data_mlx, server_data_rcv))
cs_grant_delays = sorted(dict_diffs(client_grant_mlx, server_grant_rcv))

# Time differences for data packets and grants passing from server to client.
# These differences include clock differences between the machines.
sc_data_delays = sorted(dict_diffs(server_data_send, client_data_rcv))
sc_grant_delays = sorted(dict_diffs(server_grant_send, client_grant_rcv))

# Lag between when a data packet is seen at GRO level and when it is
# processed at SoftIRQ level on the same machine.
client_data_softirq_delays = sorted(dict_diffs(client_data_rcv,
        client_data_softirq))
server_data_softirq_delays = sorted(dict_diffs(server_data_rcv,
        server_data_softirq))

# Lag between when a grant packet is seen at GRO level and when it is
# processed at SoftIRQ level on the same machine.
client_grant_softirq_delays = sorted(dict_diffs(client_grant_rcv,
        client_grant_softirq))
server_grant_softirq_delays = sorted(dict_diffs(server_grant_rcv,
        server_grant_softirq))

# Total delays (ip_queue_xmit to SoftIRQ)
cs_data_total = sorted(dict_diffs(client_data_send, server_data_softirq))
sc_data_total = sorted(dict_diffs(server_data_send, client_data_softirq))
cs_grant_total = sorted(dict_diffs(client_grant_send, server_grant_softirq))
sc_grant_total = sorted(dict_diffs(server_grant_send, client_grant_softirq))

if len(cs_data_delays) == 0:
    print("No data in cs_data_delays");
    exit(1)
if len(sc_data_delays) == 0:
    print("No data in sc_data_delays");
    exit(1)

rtt = sc_data_delays[0] + cs_data_delays[0]

# Server clock time - client clock time (best guess)
clock_offset = cs_data_delays[0] - rtt/2
print("Minimum Network RTT: %.1f us, clock offset %.1f us" % (rtt, clock_offset))

if verbose:
    min = 1000
    min_pktid = ""
    for pktid in client_grant_send:
        if not pktid in client_grant_mlx:
            print("pktid %s not in client_grant_mlx" % (pktid))
            continue
        if not pktid in server_grant_rcv:
            print("pktid not in server_grant_rcv")
            continue
        if not pktid in server_grant_softirq:
            print("pktid not in server_grant_softirq")
            continue
        net = server_grant_rcv[pktid] - client_grant_mlx[pktid] - clock_offset;
        if net < min:
            min = net
            min_pktid = pktid
    start = client_grant_send[min_pktid]
    print("Id %s, %6.1f us %6.1f us %6.1f us" % (pktid,
            client_grant_mlx[min_pktid] - start,
            server_grant_rcv[min_pktid] - clock_offset - start,
            server_grant_softirq[min_pktid] - clock_offset - start))
    print("%9.3f us -> %9.3f us (%9.3f us)" % (client_grant_mlx[min_pktid],
            server_grant_rcv[min_pktid],
            server_grant_rcv[min_pktid] - clock_offset));

# Adjust cross-machine times to reflect clock offset.
for list in [cs_data_delays, cs_grant_delays, cs_data_total, cs_grant_total]:
    for i in range(len(list)):
        list[i] -= clock_offset
for list in [sc_data_delays, sc_grant_delays, sc_data_total, sc_grant_total]:
    for i in range(len(list)):
        list[i] += clock_offset

percents = [0, 10, 50, 90, 99, 100]

print("\nData packet delays, client -> server:")
print("Pctile   IP stack        Net  GRO->SoftIRQ     Total")
for p in percents:
    print("%3d     %s  %s     %s %s" % (p,
            percentile(client_data_xmit, p, "%6.1f us"),
            percentile(cs_data_delays, p, "%6.1f us"),
            percentile(server_data_softirq_delays, p, "%6.1f us"),
            percentile(cs_data_total, p, "%6.1f us")))

print("\nData packet delays, server -> client:")
print("Pctile   IP stack        Net  GRO->SoftIRQ     Total")
for p in percents:
    print("%3d     %s  %s     %s %s" % (p,
            percentile(server_data_xmit, p, "%6.1f us"),
            percentile(sc_data_delays, p, "%6.1f us"),
            percentile(client_data_softirq_delays, p, "%6.1f us"),
            percentile(sc_data_total, p, "%6.1f us")))

print("\nGrant delays, client -> server:")
print("Pctile   IP stack        Net  GRO->SoftIRQ     Total")
for p in percents:
    print("%3d     %s  %s     %s %s" % (p,
            percentile(client_grant_xmit, p, "%6.1f us"),
            percentile(cs_grant_delays, p, "%6.1f us"),
            percentile(server_grant_softirq_delays, p, "%6.1f us"),
            percentile(cs_grant_total, p, "%6.1f us")))

print("\nGrant delays, server -> client:")
print("Pctile   IP stack        Net  GRO->SoftIRQ     Total")
for p in percents:
    print("%3d     %s  %s     %s %s" % (p,
            percentile(server_grant_xmit, p, "%6.1f us"),
            percentile(sc_grant_delays, p, "%6.1f us"),
            percentile(client_grant_softirq_delays, p, "%6.1f us"),
            percentile(sc_grant_total, p, "%6.1f us")))