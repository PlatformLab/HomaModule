#!/usr/bin/python3

"""
Analyzes Homa timetraces on two different machines to extract a
latency profile for a single RPC.

Usage:
rpcid id client_node server_node

id:           The unique id for a given RPC
client_node:  The number (e.g. 1, corresponding to node-1) of the client
              node: its timetrace should be in ~/node.tt on that node.
server_node:  The number (e.g. 1, corresponding to node-1) of the server
              node: its timetrace should be in ~/node.tt on that node.

The existing timetrace is in tt_file (or stdin in tt_file is omitted).
"""

from __future__ import division, print_function
from glob import glob
from optparse import OptionParser
import math
import os
import re
import string
import subprocess
import sys

# Time in the future when the NIC queue will become empty.
nic_empty_time = 0.0

max_queue = 0.0

# Number of bytes per Ethernet packet for CRC, preamble, and inter-packet gap.
eth_overhead = 24

# Total header info for each additional TSO packet, including (in order)
# Homa data header, IP header, VLAN header, and eth_overhead
hdr_overhead = 40 + 20 + 20 + eth_overhead

# For printing interval info.
sfmt = "  %-22s %6.2f\n"
cfmt = "  %-22s %6.2f"

def track_nic_queue(line, time):
    """
    Update info about the NIC queue length to reflect the transmission
    of a new packet (or several packets if there is TSO)
    line:   Timetrace line describing the packet
    time:   Current time (already parsed from the line)
    """
    global nic_empty_time, eth_overhead, hdr_overhead, max_queue

    match = re.match('.* mlx packet info: len ([0-9]+), '
            'gso_size ([0-9]+), gso_segs ([0-9]+)', line)
    if not match:
        return
    bytes = int(match.group(1)) + eth_overhead
    segs = int(match.group(3))
    if segs > 1:
        bytes += (segs - 1) * hdr_overhead
    usecs = (bytes*8.0)/25000.0
    if nic_empty_time < time:
        nic_empty_time = time + usecs
    else:
        nic_empty_time += usecs
    delay = nic_empty_time - time
    if delay > max_queue:
        max_queue = delay
        # print("NIC queueing delay now %.3f us" % (max_queue))
    # print("NIC queue: bytes %d, usecs %.3f, time %.3f empty_time %.3f" %
    #         (bytes, usecs, time, nic_empty_time))

if len(sys.argv) != 4:
    print("Usage: %s id client_node server_node" % (sys.argv[0]))
    sys.exit(1)

id = sys.argv[1]
client = "node-" + sys.argv[2]
server = "node-" + sys.argv[3]

# Indexed by core id; holds the time of the last do_IRQ invocation
# for that core.
doirq = {}

tt = subprocess.Popen(["ssh", "-o", "StrictHostKeyChecking=no",
        server, "cat", "node.tt"], encoding="utf-8",
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

last = 0.0
done = False
gro_core = -1
total_nic_delay = 0.0

server_info = ""

for line in tt.stdout:
    match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\]', line)
    if not match:
        continue
    time = float(match.group(1))
    core = int(match.group(2))
    gap = time - last

    if "do_IRQ starting" in line:
        doirq[core] = time;

    if "Freezing" in line:
        server_info += sfmt % ("freeze delay", gap)
        break

    if "mlx packet info" in line:
        track_nic_queue(line, time)

    if ("enqueue_to_backlog complete" in line) and (core == gro_core):
        server_info += sfmt % ("NAPI", gap)
        gro_core = -1
        last = time
        continue

    match = re.match('.* id ([0-9]+)', line)
    if done or (not match) or (match.group(1) != id):
        continue

    event = ""
    if "homa_gro_receive got packet" in line:
        event = "(interrupt)"
        start = time
        gap = time - doirq[core]
        gro_core = core
    elif "homa_softirq: first packet" in line:
        event = "wakeup SoftIRQ"
    elif "homa_rpc_ready handed off" in line:
        event = "softIRQ"
    elif "received message while reaping" in line:
        event = "wakeup reaping thread"
    elif "homa_wait_for_message woke up" in line:
        event = "wakeup thread"
    elif "received message while polling" in line:
        event = "wakeup polling thread"
    elif "homa_ioc_recv finished" in line:
        event = "ioc_recv"
    elif "homa_ioc_reply starting," in line:
        event ="application"
    elif "mlx sent homa data packet" in line:
        event ="xmit reply"
        done = True

    if not event:
        continue
    server_info += sfmt % (event, gap)
    if (event == "xmit reply") and (nic_empty_time > time):
        server_info += sfmt % ("nic queue", nic_empty_time - time)
        total_nic_delay = nic_empty_time - time
    last = time
    if event == "xmit reply":
        done = True
        server_total = time - start
        server_info += sfmt % ("total", server_total)
tt.wait()

tt = subprocess.Popen(["ssh", "-o", "StrictHostKeyChecking=no",
        client, "cat", "node.tt"], encoding="utf-8",
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
last = 0.0
done = False
gro_core = -1
nic_empty_time = 0.0
max_queue = 0.0

print("Client:")
for line in tt.stdout:
    match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\]', line)
    if not match:
        continue
    time = float(match.group(1))
    core = int(match.group(2))

    if "do_IRQ starting" in line:
        doirq[core] = time;

    if "mlx packet info" in line:
        track_nic_queue(line, time)

    if ("enqueue_to_backlog complete" in line) and (core == gro_core):
        print(cfmt % ("NAPI", time - last))
        gro_core = -1
        last = time
        continue

    match = re.match('.* id ([0-9]+)', line)
    if done or (not match) or (match.group(1) != id):
        continue

    event = ""
    if "homa_ioc_send starting" in line:
        last = start = time
        continue
    elif "mlx sent homa data" in line:
        event = "xmit request"
    elif "homa_gro_receive got packet" in line:
        print(cfmt % ("server", server_total))
        print(cfmt % ("nic queueing", total_nic_delay))
        print(cfmt % ("network", time - last - server_total
                - total_nic_delay))
        last = doirq[core]
        event = "(interrupt)"
        gro_core = core
    elif "homa_softirq: first packet" in line:
        event = "wakeup SoftIRQ"
    elif "homa_rpc_ready handed off" in line:
        event = "softIRQ"
    elif "received message while reaping" in line:
        event = "wakeup reaping thread"
    elif "homa_wait_for_message woke up" in line:
        event = "wakeup thread"
    elif "received message while polling" in line:
        event = "wakeup polling thread"
    elif "homa_ioc_recv finished" in line:
        event = "ioc_recv"
    elif "Long RTT" in line:
        event ="ioc_recv"

    if not event:
        continue
    gap = time - last
    print(cfmt % (event, gap))
    if (event == "xmit request") and (nic_empty_time > time):
        print(cfmt % ("nic queue", nic_empty_time - time))
        total_nic_delay = nic_empty_time - time
    last = time
    if event == "ioc_recv":
        print(cfmt % ("total", time - start))
        break
tt.wait()

print("\nServer:")
print(server_info, end="")