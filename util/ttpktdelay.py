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

def print_sample(event1, event2, offset, delays, pct, msg):
    """
    Print identifying information about an event that falls at a given
    percentile (from smallest to largest) among a collection of delays
    event1: information about first event (dictionary mapping pktid -> time)
    event2: information about a later event
    offset: clock offset between times in event1 and those in event2
    delays: sorted list of delays computed from event1 to event2
    pct:    desired percentile
    msg:    human-readable text describing the interval
    """
    
    if len(delays) == 0:
        print("No delays available for %s" % (msg))
        return

    target = delays[pct*len(delays)//100]
    # print("target for P%d is %.1f us" % (pct, target))
    for pktid in event1:
        if not pktid in event2:
            continue
        elapsed = event2[pktid] - event1[pktid] - offset;
        if elapsed == target:
            print("%9.3f %-22s %3dth percentile event (%6.1f us) for %s" % (
                    event2[pktid], "(pktid %s):" % (pktid), pct, target, msg))
            return
    print("Couldn't find %dth percentile event (%.1f us) for %s" % (pct,
            target, msg))

def parse_tt(tt, server):
    """
    Reads the timetrace file given by tt and returns a dictionary containing
    extracted statistics (see below) The server argument indicates whether
    this is a server trace; if so, 1 gets subtracted from all RPC ids to
    produce client ids.

    The return value from parse_tt is a dictionary with the following elements:

    Each of the following elements is itself a dictionary, where keys are
    packet ids (rpc_id:offset) and values are times when that packet id
    reached the given point of processing. rpc_id's are client-side ids,
    even for server info.
    data_send:           time when ip_queue_xmit was called for a data packet
    data_mlx:            time when mlx driver finished sending a data packet
    data_gro_start:      time of first homa_gro_receive for batch that includes
                         this packet
    data_gro:            time when this packet was processed by homa_gro_receive
    data_gro_last:       time when last packet in batch containing this packet
                         was processed by homa_gro_receive
    data_wakeup:         time when SoftIRQ wakeup was issued for batch
                         containing this packet
    data_softirq_start:  time when homa_softirq was invoked with batch that
                         includes this packet
    data_softirq:        time when this homa_data_pkt processed this packet
                         at SoftIRQ level
    """

    data_send = {}
    data_mlx = {}
    data_gro_start = {}
    data_gro = {}
    data_gro_last = {}
    data_wakeup = {}
    data_softirq_start = {}
    data_softirq = {}

    grant_send = {}
    grant_mlx = {}
    grant_gro_start = {}
    grant_gro = {}
    grant_gro_last = {}
    grant_wakeup = {}
    grant_softirq_start = {}
    grant_softirq = {}

    # Keys are RPC ids and core; each value is the most recent pktid for which
    # ip_queue_xmit was invoked for this RPC on this core.
    grant_ids = {}

    # Keys are cores; each value is a list of packet ids that need
    # wakeup events for this core
    data_wakeup_ids = {}
    grant_wakeup_ids = {}

    # Keys are cores; each value is the most recent time when homa_softirq
    # was invoked on the core
    softirq_start = {}

    # Keys are cores; each value is the most recent time when Homa GRO
    # processed a packet on that core.
    last_gro = {}

    # Keys are cores; each value is the most recent time when mlx_5e_napi_poll
    # was invoked on that core.
    last_mlx_napi = {}

    for line in open(tt):
        match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\]'
                '.* id ([-0-9.]+),.* offset ([-0-9.]+)', line)
        if not match:
            # mlx finished sending grant
            match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\] mlx '
                    'sent homa packet to .* id ([-0-9.]+), type 21', line)
            if match:
                time = float(match.group(1))
                core = int(match.group(2))
                id = match.group(3)
                if (server):
                    id = str(int(id) - 1)
                key = id + ":" + str(core)
                if key in grant_ids:
                    grant_mlx[grant_ids[key]] = time

            # Interrupt handler on receiver
            match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\] '
                    'mlx5e_napi_poll invoked', line)
            if match:
                time = float(match.group(1))
                core = int(match.group(2))
                last_mlx_napi[core] = time

            # gro_complete invoked on core
            match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\] '
                    'homa_gro_complete chose core ([0-9]+) for', line)
            if match:
                time = float(match.group(1))
                core = int(match.group(2))
                target = int(match.group(3))
                if core in data_wakeup_ids:
                    for pktid in data_wakeup_ids[core]:
                        data_gro_last[pktid] = last_gro[core]
                        data_wakeup[pktid] = time
                if core in grant_wakeup_ids:
                    for pktid in grant_wakeup_ids[core]:
                        grant_gro_last[pktid] = last_gro[core]
                        grant_wakeup[pktid] = time
                data_wakeup_ids[core] = []
                grant_wakeup_ids[core] = []

            # GRO finishes without invoking homa_gro_complete (just one
            # packet?); must receord deferred events.
            match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\] '
                    'enqueue_to_backlog complete', line)
            if match:
                time = float(match.group(1))
                core = int(match.group(2))
                if core in data_wakeup_ids:
                    for pktid in data_wakeup_ids[core]:
                        data_gro_last[pktid] = last_gro[core]
                        data_wakeup[pktid] = time
                if core in grant_wakeup_ids:
                    for pktid in grant_wakeup_ids[core]:
                        grant_gro_last[pktid] = last_gro[core]
                        grant_wakeup[pktid] = time
                data_wakeup_ids[core] = []
                grant_wakeup_ids[core] = []
            
            # homa_softirq invocation time
            match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\] '
                    'homa_softirq: first packet', line)
            if match:
                time = float(match.group(1))
                core = int(match.group(2))
                softirq_start[core] = time

            continue

        time = float(match.group(1))
        core = int(match.group(3))
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

        # Incoming data packet processed by Homa GRO
        if "homa_gro_receive got packet" in line:
            data_gro[pktid] = time
            last_gro[core] = time
            if not core in data_wakeup_ids:
                data_wakeup_ids[core] = []
            data_wakeup_ids[core].append(pktid)
            if core in last_mlx_napi:
                data_gro_start[pktid] = last_mlx_napi[core]

        # Incoming data (SoftIRQ level)
        if "incoming data packet, id" in line:
            data_softirq[pktid] = time
            data_softirq_start[pktid] = softirq_start[core]

        # Outgoing grant
        if "sending grant for id" in line:
            grant_send[pktid] = time
            key = id + ":" + str(core)
            grant_ids[key] = pktid

        # Incoming grant processed by Homa GRO
        if "homa_gro_receive got grant" in line:
            grant_gro[pktid] = time
            last_gro[core] = time
            if not core in grant_wakeup_ids:
                grant_wakeup_ids[core] = []
            grant_wakeup_ids[core].append(pktid)
            if core in last_mlx_napi:
                grant_gro_start[pktid] = last_mlx_napi[core]

        # Incoming grant (SoftIRQ level)
        if "processing grant for id" in line:
            grant_softirq[pktid] = time
            grant_softirq_start[pktid] = softirq_start[core]
    
    return {
        'data_send': data_send,
        'data_mlx': data_mlx,
        'data_gro_start': data_gro_start,
        'data_gro': data_gro,
        'data_gro_last': data_gro_last,
        'data_wakeup': data_wakeup,
        'data_softirq_start': data_softirq_start,
        'data_softirq': data_softirq,

        'grant_send': grant_send,
        'grant_mlx': grant_mlx,
        'grant_gro_start': grant_gro_start,
        'grant_gro': grant_gro,
        'grant_gro_last': grant_gro_last,
        'grant_wakeup': grant_wakeup,
        'grant_softirq_start': grant_softirq_start,
        'grant_softirq': grant_softirq
    }
    

client = parse_tt(client_trace, False)
server = parse_tt(server_trace, True)

# Now combine the data from the two time traces to compute interesting delays

# Delays for data packets and grants passing through the IP stack
# on a single machine.
client_data_xmit = sorted(dict_diffs(client['data_send'], client['data_mlx']))
client_grant_xmit = sorted(dict_diffs(client['grant_send'], client['grant_mlx']))
server_data_xmit = sorted(dict_diffs(server['data_send'], server['data_mlx']))
server_grant_xmit = sorted(dict_diffs(server['grant_send'], server['grant_mlx']))

# Delays for data packets and grants from NIC on one machine to start of
# NAPI-level process on the other. These differences have not been compensated
# for clock differences between the machines.
cs_data_net = sorted(dict_diffs(client['data_mlx'], server['data_gro_start']))
cs_grant_net = sorted(dict_diffs(client['grant_mlx'], server['grant_gro_start']))
sc_data_net = sorted(dict_diffs(server['data_send'], client['data_gro_start']))
sc_grant_net = sorted(dict_diffs(server['grant_send'], client['grant_gro_start']))

# GRO processing for other packets before this one
client_data_gro = sorted(dict_diffs(client['data_gro_start'],
        client['data_gro']))
client_grant_gro = sorted(dict_diffs(client['grant_gro_start'],
        client['grant_gro']))
server_data_gro = sorted(dict_diffs(server['data_gro_start'],
        server['data_gro']))
server_grant_gro = sorted(dict_diffs(server['grant_gro_start'],
        server['grant_gro']))

# Additional GRO processing after this packet (other packets in batch)
client_data_gro_last = sorted(dict_diffs(client['data_gro'],
        client['data_gro_last']))
client_grant_gro_last = sorted(dict_diffs(client['grant_gro'],
        client['grant_gro_last']))
server_data_gro_last = sorted(dict_diffs(server['data_gro'],
        server['data_gro_last']))
server_grant_gro_last = sorted(dict_diffs(server['grant_gro'],
        server['grant_gro_last']))

# Delays from last GRO packet to SoftIRQ wakeup
client_data_wakeup = sorted(dict_diffs(client['data_gro_last'],
        client['data_wakeup']))
client_grant_wakeup = sorted(dict_diffs(client['grant_gro_last'],
        client['grant_wakeup']))
server_data_wakeup = sorted(dict_diffs(server['data_gro_last'],
        server['data_wakeup']))
server_grant_wakeup = sorted(dict_diffs(server['grant_gro_last'],
        server['grant_wakeup']))

# Delays from SoftIRQ wakeup until homa_softirq starts
client_data_softirq_start = sorted(dict_diffs(client['data_wakeup'],
        client['data_softirq_start']))
client_grant_softirq_start = sorted(dict_diffs(client['grant_wakeup'],
        client['grant_softirq_start']))
server_data_softirq_start = sorted(dict_diffs(server['data_wakeup'],
        server['data_softirq_start']))
server_grant_softirq_start = sorted(dict_diffs(server['grant_wakeup'],
        server['grant_softirq_start']))

# Delays from SoftIRQ start until the desired packet is processed
client_data_softirq = sorted(dict_diffs(client['data_softirq_start'],
        client['data_softirq']))
client_grant_softirq = sorted(dict_diffs(client['grant_softirq_start'],
        client['grant_softirq']))
server_data_softirq = sorted(dict_diffs(server['data_softirq_start'],
        server['data_softirq']))
server_grant_softirq = sorted(dict_diffs(server['grant_softirq_start'],
        server['grant_softirq']))

# Total delays (ip_queue_xmit to SoftIRQ)
cs_data_total = sorted(dict_diffs(client['data_send'], server['data_softirq']))
sc_data_total = sorted(dict_diffs(server['data_send'], client['data_softirq']))
cs_grant_total = sorted(dict_diffs(client['grant_send'], server['grant_softirq']))
sc_grant_total = sorted(dict_diffs(server['grant_send'], client['grant_softirq']))

if len(cs_data_net) == 0:
    print("No data in cs_data_net");
    exit(1)
if len(sc_data_net) == 0:
    print("No data in sc_data_net");
    exit(1)

# Compute minimum RTT and server clock offset
if len(cs_data_net) == 0:
    print("No data in cs_data_net");
    exit(1)
if len(sc_data_net) == 0:
    print("No data in sc_data_net");
    exit(1)

over = sorted(dict_diffs(client['data_mlx'], server['data_gro']))
back = sorted(dict_diffs(server['data_mlx'], client['data_gro']))
if len(over) == 0:
    print("Can't compute RTT: no client->server data")
    exit(1)
if len(back) == 0:
    print("Can't compute RTT: no server->client data")
    exit(1)
rtt = over[0] + back[0]
clock_offset = over[0] - rtt/2
print("Minimum Network RTT: %.1f us, clock offset %.1f us" % (rtt, clock_offset)) 

# Adjust cross-machine times to reflect clock offset.
for list in [cs_data_net, cs_grant_net, cs_data_total, cs_grant_total]:
    for i in range(len(list)):
        list[i] -= clock_offset
for list in [sc_data_net, sc_grant_net, sc_data_total, sc_grant_total]:
    for i in range(len(list)):
        list[i] += clock_offset

percents = [0, 10, 50, 90, 99, 100]

print("\nIP:        IP stack, from calling ip_queue_xmit to NIC wakeup")
print("Net:       Additional time until NAPI processing starts on receiver")
print("Pre GRO:   Time in NAPI before homa_gro_receive gets packet")
print("GRO Other: Time until end of GRO batch")
print("GRO Gap:   Delay after GRO packet processing until signalling SoftIRQ core")
print("Wakeup:    Delay until homa_softirq starts")
print("SoftIRQ:   Time in homa_softirq until packet is processed")
print("Total:     End-to-end time from calling ip_queue_xmit to homa_softirq")
print("           handler for packet")

print("\nData packet delays, client -> server:")
print("Pctile   IP     Net  Pre GRO  GRO Other GRO Gap  Wakeup  SoftIRQ   Total")
for p in percents:
    print("%3d  %6s  %6s   %6s     %6s  %6s  %6s   %6s  %6s" % (p,
            percentile(client_data_xmit, p, "%.1f"),
            percentile(cs_data_net, p, "%.1f"),
            percentile(server_data_gro, p, "%.1f"),
            percentile(server_data_gro_last, p, "%.1f"),
            percentile(server_data_wakeup, p, "%.1f"),
            percentile(server_data_softirq_start, p, "%.1f"),
            percentile(server_data_softirq, p, "%.1f"),
            percentile(cs_data_total, p, "%.1f")))

print("\nData packet delays, server -> client:")
print("Pctile   IP     Net  Pre GRO  GRO Other GRO Gap  Wakeup  SoftIRQ   Total")
for p in percents:
    print("%3d  %6s  %6s   %6s     %6s  %6s  %6s   %6s  %6s" % (p,
            percentile(server_data_xmit, p, "%.1f"),
            percentile(sc_data_net, p, "%.1f"),
            percentile(client_data_gro, p, "%.1f"),
            percentile(client_data_gro_last, p, "%.1f"),
            percentile(client_data_wakeup, p, "%.1f"),
            percentile(client_data_softirq_start, p, "%.1f"),
            percentile(client_data_softirq, p, "%.1f"),
            percentile(sc_data_total, p, "%.1f")))

print("\nGrant delays, client -> server:")
print("Pctile   IP     Net  Pre GRO  GRO Other GRO Gap  Wakeup  SoftIRQ   Total")
for p in percents:
    print("%3d  %6s  %6s   %6s     %6s  %6s  %6s   %6s  %6s" % (p,
            percentile(client_grant_xmit, p, "%.1f"),
            percentile(cs_grant_net, p, "%.1f"),
            percentile(server_grant_gro, p, "%.1f"),
            percentile(server_grant_gro_last, p, "%.1f"),
            percentile(server_grant_wakeup, p, "%.1f"),
            percentile(server_grant_softirq_start, p, "%.1f"),
            percentile(server_grant_softirq, p, "%.1f"),
            percentile(cs_grant_total, p, "%.1f")))

print("\nGrant delays, server -> client:")
print("Pctile   IP     Net  Pre GRO  GRO Other GRO Gap  Wakeup  SoftIRQ   Total")
for p in percents:
    print("%3d  %6s  %6s   %6s     %6s  %6s  %6s   %6s  %6s" % (p,
            percentile(server_grant_xmit, p, "%.1f"),
            percentile(sc_grant_net, p, "%.1f"),
            percentile(client_grant_gro, p, "%.1f"),
            percentile(client_grant_gro_last, p, "%.1f"),
            percentile(client_grant_wakeup, p, "%.1f"),
            percentile(client_grant_softirq_start, p, "%.1f"),
            percentile(client_grant_softirq, p, "%.1f"),
            percentile(sc_grant_total, p, "%.1f")))

if verbose:
    print("\nPotentially nteresting events:")
    print_sample(client['data_mlx'], server['data_gro_start'], clock_offset,
            cs_data_net, 0, "Net (client->server data)")
    print_sample(server['data_gro_start'], server['data_gro'], 0,
            server_data_gro, 90, "Pre GRO (client->server data)")
    print_sample(server['data_gro_start'], server['data_gro'], 0,
            server_data_gro, 99, "Pre GRO (client->server data)")
    print_sample(server['data_gro'], server['data_gro_last'], 0,
            server_data_gro_last, 90, "GRO Other (client->server data)")
    print_sample(server['data_gro'], server['data_gro_last'], 0,
            server_data_gro_last, 99, "GRO Other (client->server data)")
    print_sample(server['data_gro_last'], server['data_wakeup'], 0,
            server_data_wakeup, 90, "GRO Gap (client->server data)")
    print_sample(server['data_gro_last'], server['data_wakeup'], 0,
            server_data_wakeup, 99, "GRO Gap (client->server data)")
    print_sample(server['data_wakeup'], server['data_softirq_start'], 0,
            server_data_softirq_start, 90, "Wakeup (client->server data)")
    print_sample(server['data_wakeup'], server['data_softirq_start'], 0,
            server_data_softirq_start, 99, "Wakeup (client->server data)")
    print_sample(server['data_softirq_start'], server['data_softirq'], 0,
            server_data_softirq, 90, "SoftIRQ (client->server data)")
    print_sample(server['data_softirq_start'], server['data_softirq'], 0,
            server_data_softirq, 99, "SoftIRQ (client->server data)")