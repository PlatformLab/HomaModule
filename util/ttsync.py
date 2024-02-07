#!/usr/bin/python3

# Copyright (c)2023 Homa Developers
# SPDX-License-Identifier: BSD-1-Clause

"""
Scans two or more timetraces covering the same time interval, determines the
clock offsets between each machine and the first, and adjusts the times in
all of the traces except the first so that the clocks are synchronized
across the traces
"""

from __future__ import division, print_function
from glob import glob
from optparse import OptionParser
import math
import os
from pathlib import Path
import re
import string
import sys
import tempfile

# Parse command line options
parser = OptionParser(description=
        'Read two or more timetraces, compute the clock offsets between them, '
        'and rewrite all of the traces except the first to synchronize '
        'their clocks. Also prints statistics about one-way packet delays.',
        usage='%prog [options] t1 t2 ...',
        conflict_handler='resolve')
parser.add_option('--no-rewrite', action='store_true', dest='no_rewrite',
        default=False, metavar='T/F', help='read-only: compute offsets but '
        "don't rewrite trace files")
parser.add_option('--verbose', '-v', action='store_true', default=False,
        dest='verbose',
        help='print lots of output')

(options, tt_files) = parser.parse_args()
if len(tt_files) < 2:
    print('Need at least 2 trace files; run "ttsync.py --help" for help')
    exit(1)

# (rpc_id:offset) -> <time, node> for each packet sent. rpc_id is the
# id on the sender, and node is the integer node identifier of the sender,
# as passed to parse_tt.
send_pkts = {}

# (rpc_id:offset) -> <time, node> for each packet received. rpc_id is the
# id on the sender, and node is the integer node identifier of the
# receiver, as passed to parse_tt.
recv_pkts = {}

# This is an NxN array, where N is the number of nodes. min_delays[A][B]
# gives the smallest delay seen from node A to node B, as measured with
# their unadjusted clocks (one of these delays could be negative).
min_delays = []

# This is an NxN array, where N is the number of nodes. Each entry corresponds
# to an entry in min_delays, and gives the time when the message producing
# the minimum delay was received.
recv_times = []

# For each node, the offset to add to its clock value in order to synchronize
# its clock with node 0.
offsets = []

# rpc_id -> maximum offset that has been sent so far for that RPC; used to
# skip retransmitted packets, which can mess up delay calculations.
max_send_offsets = {}

# rpc_id -> maximum offset that has been received so far for that RPC; used to
# skip receipts of retransmissions, which can mess up delay calculations.
max_recv_offsets = {}

def parse_tt(tt, node_num):
    """
    Reads a timetrace file and adds entries to send_pkts and recv_pkts.

    tt:        Name of the timetrace file
    node_num:  Integer identifier for this file/node (should reflect the
               order of the timetrace file in the arguments
    """

    global options, send_pkts, recv_pkts, max_send_offsets, max_recv_offsets
    sent = 0
    recvd = 0

    for line in open(tt):
        match = re.match(' *([-0-9.]+) us .* us\) \[C([0-9]+)\]'
                '.* id ([-0-9.]+),.* offset ([-0-9.]+)', line)
        if not match:
            continue

        time = float(match.group(1))
        core = int(match.group(2))
        id = int(match.group(3))
        offset = int(match.group(4))

        if re.match('.*calling .*_xmit: wire_bytes', line):
            if (id in max_send_offsets) and (max_send_offsets[id] >= offset):
                continue
            pktid = '%d:%d' % (id, offset)
            send_pkts[pktid] = [time, node_num]
            max_send_offsets[id] = offset
            sent += 1

        match2 = re.match('.*Finished queueing packet: rpc id .*, offset .*, '
                'len ([0-9.]+)', line)
        if match2:
            last_offset = offset + int(match2.group(1)) - 1
            if (id in max_send_offsets) and (max_send_offsets[id] < last_offset):
                max_send_offsets[id] = last_offset

        if "homa_gro_receive got packet" in line:
            if (id in max_recv_offsets) and (max_recv_offsets[id] >= offset):
                continue
            pktid = '%d:%d' % (id^1, offset)
            recv_pkts[pktid] = [time, node_num]
            max_recv_offsets[id] = offset
            recvd += 1

        if "sending grant for" in line:
            pktid = '%d:%dg' % (id, offset)
            if not pktid in send_pkts:
                send_pkts[pktid] = [time, node_num]
                sent += 1

        if "homa_gro_receive got grant from" in line:
            pktid = '%d:%dg' % (id^1, offset)
            recv_pkts[pktid] = [time, node_num]
            recvd += 1

    print("%s has %d packet sends, %d receives" % (tt, sent, recvd))

def find_min_delays(num_nodes):
    """
    Combines the information in send_pkts and recv_pkts to fill in
    min_delays

    num_nodes:  Total number of distinct nodes; node numbers in
                send_pkts and recv_pkts must be < num_nodes.
    """

    global min_delays, recv_times, send_pkts, recv_pkts

    min_delays = [[1e20 for i in range(num_nodes)] for j in range(num_nodes)]
    recv_times = [[0 for i in range(num_nodes)] for j in range(num_nodes)]

    # Iterate over all the client-side events and match them to server-side
    # events if possible.
    for id, send_pkt in send_pkts.items():
        if not id in recv_pkts:
            continue
        send_time, send_node = send_pkt
        recv_time, recv_node = recv_pkts[id]
        delay = recv_time - send_time
        if delay < min_delays[send_node][recv_node]:
            min_delays[send_node][recv_node] = delay
            recv_times[send_node][recv_node] = recv_time

def get_node_num(tt_file):
    """
    Given a timetrace file name with a node number in it somewhere,
    extract the number.
    """
    match = re.match('[^0-9]*([0-9]+)', tt_file)
    if match:
        return int(match.group(1))
    return tt_file

tt_files.sort(key = lambda name : get_node_num(name))
node_names = [Path(tt_file).stem for tt_file in tt_files]
num_nodes = len(tt_files)
for i in range(num_nodes):
    parse_tt(tt_files[i],i)
find_min_delays(num_nodes)


# List of offset info for all nodes; index = node id; elements are
# dictionaries with the following entries:
# ref:         Node that was used to synchronize this node. -1 means
#              this node isn't yet synchronized.
# ref_offset:  Amount to add to node's clock to sync with ref.
# offset:      Amount to add to node's clock to sync with index 0.
offsets = []
offsets.append({'ref': 0, 'ref_offset': 0.0, 'offset': 0.0})
for i in range(1, num_nodes):
    offsets.append({'ref': -1, 'ref_offset': 0.0, 'offset': 0.0})

# Compute clock offsets and min delays. In the simplest case the first
# node will be used as a reference for all the others, but this may not be
# possible if a node hasn't communicated with the first one. Also, the
# sync is likely to be inaccurate if the minimum RTT is very high.
# Each iteration through the following loop finds one node to sync, looking
# for a node that has a low RTT to one of the nodes that's already
# synced.
synced = 1
while synced < num_nodes:
    # Look for an unsynced node that we can sync.
    best_node = None
    best_ref = None
    best_rtt = 1e20
    for node in range(1, num_nodes):
        if offsets[node]['ref'] >= 0:
            continue
        # Look for a synced node that can be used as reference for node i.
        for ref in range(0, num_nodes):
            if offsets[ref]['ref'] < 0:
                # This candidate isn't synced.
                continue
            if (min_delays[node][ref] > 1e10) or (min_delays[ref][node] > 1e10):
                # No traffic between these nodes.
                continue
            # ref can potentially serve as reference for i.
            rtt = min_delays[ref][node] + min_delays[node][ref]
            if rtt < 0:
                print('Negative RTT %.1f between %s (recv %.3f) and '
                        '%s (recv %.3f),' % (rtt, node_names[ref],
                        recv_times[node][ref], node_names[node],
                        recv_times[ref][node]))
            if (rtt < best_rtt) and (rtt > 0):
                best_node = node
                best_ref = ref
                best_rtt = rtt
                if best_rtt < 15.0:
                    break
        if best_rtt < 15.0:
            break
    if best_node == None:
        # The remaining unsynced nodes can't be synced; print a message.
        unsynced = []
        for i in range(1, num_nodes):
            if offsets[i]['ref'] < 0:
                unsynced.append(node_names[i])
        print('The following nodes couldn\'t be synced: %s (no traffic between\n'
                'these nodes and other nodes)' %
                (', '.join(unsynced)), file=sys.stderr)
        exit(1)

    ref_offset = best_rtt/2 - min_delays[best_ref][best_node]
    offsets[best_node] = {'ref': best_ref, 'ref_offset': ref_offset,
            'offset': offsets[best_ref]['offset'] + ref_offset};
    synced += 1

print('\nTime offsets computed for each node:')
print('Ref:       Reference node used to sync this node')
print('MinOut:    Smallest time difference (unsynced clocks) for a packet')
print('           to get from Ref to this node')
print('MinBack:   Smallest time difference (unsynced clocks) for a packet')
print('           to get from this node to Ref')
print('MinRTT:    Minimum RTT (computed from MinOut and MinBack)')
print('RefOffset: Add this to node\'s clock to align with Ref')
print('Offset:    Add this to node\'s clock to align with %s' % (node_names[0]))
print('\nNode       Ref          MinOut  MinBack  Min RTT RefOffset   Offset')
print('%-10s %-10s %8.1f %8.1f  %7.1f  %8.1f %8.1f' % (node_names[0], "N/A",
        0.0, 0.0, 0.0, 0.0, 0.0))
for node in range(1, num_nodes):
    min_rtt = min_delays[0][node] + min_delays[node][0]
    info = offsets[node]
    ref = info['ref']
    min_rtt = min_delays[ref][node] + min_delays[node][ref]
    print('%-10s %-10s %8.1f %8.1f  %7.1f  %8.1f %8.1f' % (node_names[node],
            node_names[ref], min_delays[ref][node], min_delays[node][ref],
            min_rtt, info['ref_offset'], info['offset']))

# Check for consistency (with these offsets, will all one-way delays be
# positive?)
for src in range(num_nodes):
    for dst in range(num_nodes):
        if src == dst:
            continue
        src_offset = offsets[src]['offset']
        dst_offset = offsets[dst]['offset']
        new_min = min_delays[src][dst] + dst_offset - src_offset
        if new_min < 0:
            print('Problematic offsets for %s (%.1f) and %s (%.1f)'
                    %(node_names[src], src_offset, node_names[dst], dst_offset))
            print('   mimimum delay %.1f becomes %.1f, received at %9.3f' %
                    (min_delays[src][dst], new_min,
                    recv_times[src][dst] + dst_offset))

# Rewrite traces with synchronized times
if not options.no_rewrite:
    print("")
    for i in range(1, num_nodes):
        offset = offsets[i]['offset']
        src = open(tt_files[i])
        dst = tempfile.NamedTemporaryFile(dir=os.path.dirname(tt_files[i]),
                mode='w', encoding='utf-8', delete=False)
        print("Rewriting %s with offset %.1f usec" % (tt_files[i], offset))
        for line in src:
            match = re.match(' *([-0-9.]+) us (\(\+ *[-0-9.]+ us\) \[C[0-9]+\].*)',
                    line)
            if not match:
                print(line, file=dst)
            else:
                time = float(match.group(1)) + offset
                dst.write('%9.3f us %s\n' % (time, match.group(2)))
        dst.close()
        os.rename(dst.name, tt_files[i])
