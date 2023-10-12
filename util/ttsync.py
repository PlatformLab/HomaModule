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

# Dictionary describing all data and grant packets sent/received
# by clients. Keys are packet ids (rpc_id:offset, with a "g" suffix
# for grant packets). Each value is a list <time, type, node> where
# time is when the packet was sent or received, type is "send" or "recv",
# indicating whether the packet was sent or received by this node, and
# "node" is the integer node identifier passed to parse_tt.
client_pkts = {}

# Same as client_pkts, exception describes it and grant packets sent/received
# by servers. Note: RPC ids are stored as client-side(even) ids
server_pkts = {}

# This is an NxN array, where N is the number of nodes. min_delays[A][B]
# gives the smallest delay seen from node A to node B, as measured with
# their unadjusted clocks (one of these delays could be negative).
min_delays = []

# For each node, the offset to add to its clock value in order to synchronize
# its clock with node 0.
offsets = []

def parse_tt(tt, node_num):
    """
    Reads a timetrace file and adds entries to client_pkts and server_pkts.

    tt:        Name of the timetrace file
    node_num:  Integer identifier for this file/node (should reflect the
               order of the timetrace file in the arguments
    """

    global options, client_pkts, server_pkts
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
        pkts = client_pkts
        if id & 1:
            pkts = server_pkts
            id = id - 1
        offset = match.group(4)
        pktid = str(id) + ":" + offset

        if re.match('.*calling .*_xmit: wire_bytes', line):
            pkts[pktid] = [time, "send", node_num]
            sent += 1

        if "homa_gro_receive got packet" in line:
            pkts[pktid] = [time, "recv", node_num]
            recvd += 1

        if "sending grant for" in line:
            pkts[pktid+"g"] = [time, "send", node_num]
            sent += 1

        if "homa_gro_receive got grant from" in line:
            pkts[pktid+"g"] = [time, "recv", node_num]
            recvd += 1

    print("%s has %d packet sends, %d receives" % (tt, sent, recvd))

def find_min_delays(num_nodes):
    """
    Combines the information in client_pkts and server_pkts to fill in
    min_delays

    num_nodes:  Total number of distinct nodes; node numbers in
                client_pkts and server_pkts must be < num_nodes.
    """

    global min_delays, client_pkts, server_pkts

    min_delays = [[1e20 for i in range(num_nodes)] for j in range(num_nodes)]

    # Iterate over all the client-side events and match them to server-side
    # events if possible.
    for id, client_pkt in client_pkts.items():
        if not id in server_pkts:
            continue
        client_time, client_type, client_node = client_pkt
        server_time, server_type, server_node = server_pkts[id]
        if ("send"  == client_type) and ("recv" == server_type):
            delay = server_time - client_time
            if delay < min_delays[client_node][server_node]:
                min_delays[client_node][server_node] = delay
        if ("send"  == server_type) and ("recv" == client_type):
            delay = client_time - server_time
            if delay < min_delays[server_node][client_node]:
                min_delays[server_node][client_node] = delay

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
node_ids = [get_node_num(tt_file) for tt_file in tt_files]
num_nodes = len(tt_files)
for i in range(num_nodes):
    parse_tt(tt_files[i],i)
find_min_delays(num_nodes)

# Compute clock offsets from min_delays
offsets = [0.0 for i in range(num_nodes)]
print('\nTime offsets computed for each node by synchronizing with node %d' %
        (node_ids[0]))
print('MinOut:   Smallest time difference (unsynced clocks) for a packet')
print('          to get from the node %d to this node' % (node_ids[0]))
print('MinBack:  Smallest time difference (unsynced clocks) for a packet')
print('          to get from this node to the node %d' % (node_ids[0]))
print('MinRTT:   Minimum RTT (computed from MinOut and MinBack)')
print('Offset:   Add this to node\'s clock to align with the first node')
print('\nNode    MinOut  MinBack Min RTT   Offset')
print('%-5d %8.1f %8.1f %7.1f %8.1f' % (node_ids[0],
        0.0, 0.0, 0.0, 0.0))
for node in range(1, num_nodes):
    min_rtt = min_delays[0][node] + min_delays[node][0]
    offsets[node] = min_rtt/2 - min_delays[0][node]
    print('%-5d %8.1f %8.1f %7.1f %8.1f' % (node_ids[node],
            min_delays[0][node], min_delays[node][0], min_rtt, offsets[node]))

# Check for consistency (with these offsets, will all one-way delays be
# positive?)
for src in range(num_nodes):
    for dst in range(num_nodes):
        if src == dst:
            continue
        new_min = min_delays[src][dst] + offsets[dst] - offsets[src]
        if new_min < 0:
            print('Problematic offsets for node %d (%.1f) and %d (%.1f)'
                    %(src, offsets[src], dst, offsets[dst]))
            print('   mimimum delay %.1f becomes %.1f' %
                    (min_delays[src][dst], new_min))

# Rewrite traces with synchronized times
if not options.no_rewrite:
    print("")
    for i in range(1, num_nodes):
        offset = offsets[i]
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
