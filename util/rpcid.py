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

If no arguments are supplied, then rpcid reads information from stdin,
which it expects to contain "Freezing because of request" lines from one
or more timetraces. For each such line found, it will output information
about the RPC described by that line.
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

# Each entry is a list of all the values (from different RPCs) for a single
# statistic.
stats = {}

rpcs_analyzed = 0

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

def add_stat(name, value):
    """
    Record a statistic with a given name and value (either appends to an
    existing list in stats or starts a new one).
    """
    global stats

    if name not in stats:
        stats[name] = [value]
    else:
        stats[name].append(value)

def avg_stat(name):
    global stats
    if not name in stats:
        return 0.0
    return sum(stats[name]) / len(stats[name])

def analyze_rpc(id, client_num, server_num):
    """
    Analyze the client and server timetraces for a given RPC and output
    a latency breakdown for the RPC.
    id:         id of the desired RPC
    client_num: number of the client machine (3, not node-3)
    server_num: number of the server machine
    """

    global nic_empty_time, max_queue, eth_overhead, cfmt, sfmt
    global rpcs_analyzed

    client_num = int(client_num)
    client = "node-" + str(client_num)
    server = "node-" + str(server_num)

    # Indexed by core id; holds the time of the last do_IRQ invocation
    # for that core.
    doirq = {}

    tt = subprocess.Popen(["ssh", "-o", "StrictHostKeyChecking=no",
            server, "cat", "node.tt"], encoding="utf-8",
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    last = 0.0
    done = False
    gro_core = -1
    nic_empty_time = 0.0
    max_queue = 0.0
    server_total = 0;
    total_nic_delay = 0.0
    start = -1.0
    server_interrupt = 0.0

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
            add_stat("server_freeze", gap)
            break

        if "mlx packet info" in line:
            track_nic_queue(line, time)

        if ("enqueue_to_backlog complete" in line) and (core == gro_core):
            server_info += sfmt % ("NAPI", gap)
            add_stat("server NAPI", gap)
            gro_core = -1
            last = time
            continue

        match = re.match('.* id ([0-9]+)', line)
        if done or (not match) or (match.group(1) != id):
            continue

        event = ""
        match = re.match('.*homa_gro_receive got packet from '
                '(0x[0-9a-f]+).* offset 0', line)
        if match:
            if (int(match.group(1), 16) & 0xff) == (client_num+1):
                event = "(interrupt)"
                start = time
                gap = time - doirq[core]
                server_interrupt = gap
                gro_core = core
        elif start < 0:
            continue

        if ("homa_softirq: first packet" in line):
            event = "wakeup SoftIRQ"
        elif "homa_rpc_ready handed off" in line:
            event = "softIRQ"
        elif "received message while reaping" in line:
            event = "wakeup reaping thread"
            add_stat("server wakeup", gap)
        elif "homa_wait_for_message woke up" in line:
            event = "wakeup thread"
            add_stat("server wakeup", gap)
        elif "received message while polling" in line:
            event = "wakeup polling thread"
            add_stat("server wakeup", gap)
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
        add_stat("server " + event, gap)
        if (event == "xmit reply") and (nic_empty_time > time):
            server_info += sfmt % ("(nic queue)", nic_empty_time - time)
            add_stat("server nic", gap)
            total_nic_delay = nic_empty_time - time
        last = time
        if event == "xmit reply":
            done = True
            server_total = time - start
            server_info += sfmt % ("total", server_total)
            add_stat("server total", server_total)
    tt.wait()

    tt = subprocess.Popen(["ssh", "-o", "StrictHostKeyChecking=no",
            client, "cat", "node.tt"], encoding="utf-8",
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    last = 0.0
    done = False
    gro_core = -1
    nic_empty_time = 0.0
    max_queue = 0.0
    gro_receive = False

    if server_total == 0:
        print("Incomplete trace data on %s for id %s; skipping" % (server, id))
        return

    if rpcs_analyzed != 0:
        print("")
    rpcs_analyzed += 1
    print("Client (%s, id %s):" % (client, id))
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
            add_stat("client NAPI", time - last)
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
        elif ("homa_gro_receive got packet" in line) and ("offset 0" in line):
            print(cfmt % ("server", server_total))
            print(cfmt % ("nic queueing", total_nic_delay))
            add_stat("nic queueing", total_nic_delay)
            net = time - last - server_total - total_nic_delay
            print(cfmt % ("network", net))
            add_stat("network", net)
            print(cfmt % ("(net - int)", net - (time - doirq[core])
                    - server_interrupt))
            last = doirq[core]
            event = "(interrupt)"
            gro_core = core
            gro_receive = True
        elif ("homa_softirq: first packet" in line) and gro_receive:
            event = "wakeup SoftIRQ"
        elif "homa_rpc_ready handed off" in line:
            event = "softIRQ"
        elif "received message while reaping" in line:
            event = "wakeup reaping thread"
            add_stat("client wakeup", time - last)
        elif "homa_wait_for_message woke up" in line:
            event = "wakeup thread"
            add_stat("client wakeup", time - last)
        elif "received message while polling" in line:
            event = "wakeup polling thread"
            add_stat("client wakeup", time - last)
        elif "homa_ioc_recv finished" in line:
            event = "ioc_recv"
        elif "Long RTT" in line:
            event ="ioc_recv"

        if not event:
            continue
        gap = time - last
        print(cfmt % (event, gap))
        add_stat("client " + event, gap)
        if (event == "xmit request") and (nic_empty_time > time):
            total_nic_delay += nic_empty_time - time
        last = time
        if event == "ioc_recv":
            print(cfmt % ("total", time - start))
            add_stat("total", time - start)
            break
    tt.wait()

    print("\nServer (%s):" % (server))
    print(server_info, end="")

# Main program:
if len(sys.argv) == 1:
    rpcs = []
    for line in sys.stdin:
        match = re.match('node-([0-9]+)', line)
        if match:
            node = match.group(1)
        match = re.match('.*Freezing because of request on port .* '
                'from (0x[0-9a-f]+):.* id ([0-9]+)', line)
        if match and node:
            client = (int(match.group(1), 16) & 0xff) - 1
            rpcs.append({"client": client, "server": node,
                    "id": match.group(2)})
    for rpc in rpcs:
        analyze_rpc(rpc["id"], rpc["client"], rpc["server"])

    if rpcs_analyzed < 2:
        exit(0)

    print("\nClient Averages (%d RPCs):" % (rpcs_analyzed))
    print(cfmt % ("xmit request", avg_stat("client xmit request")))
    print(cfmt % ("server", avg_stat("server total")))
    print(cfmt % ("nic queueing", avg_stat("nic queueing")))
    print(cfmt % ("network", avg_stat("network")))
    print(cfmt % ("(net - int)", avg_stat("network")
            - avg_stat("server (interrupt)") - avg_stat("client (interrupt)")))
    print(cfmt % ("(interrupt)", avg_stat("client (interrupt)")))
    print(cfmt % ("NAPI", avg_stat("client NAPI")))
    print(cfmt % ("wakeup SoftIRQ", avg_stat("client wakeup SoftIRQ")))
    print(cfmt % ("softIRQ", avg_stat("client softIRQ")))
    print(cfmt % ("wakeup thread", avg_stat("client wakeup")))
    print(cfmt % ("ioc_recv", avg_stat("client ioc_recv")))
    print(cfmt % ("total", avg_stat("total")))
    
    print("\nServer Averages:")
    print(cfmt % ("(interrupt)", avg_stat("server (interrupt)")))
    print(cfmt % ("NAPI", avg_stat("server NAPI")))
    print(cfmt % ("wakeup SoftIRQ", avg_stat("server wakeup SoftIRQ")))
    print(cfmt % ("softIRQ", avg_stat("server softIRQ")))
    print(cfmt % ("wakeup thread", avg_stat("server wakeup")))
    print(cfmt % ("ioc_recv", avg_stat("server ioc_recv")))
    print(cfmt % ("application", avg_stat("server application")))
    print(cfmt % ("xmit reply", avg_stat("server xmit reply")))
    print(cfmt % ("(nic queue)", avg_stat("server nic")))
    print(cfmt % ("total", avg_stat("server total")))
    exit(0)

if len(sys.argv) != 4:
    print("Usage: %s id client_node server_node" % (sys.argv[0]))
    sys.exit(1)

analyze_rpc(sys.argv[1], sys.argv[2], sys.argv[3])