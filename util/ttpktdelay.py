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

def percentile2(list, pct, format):
    """
    Finds the element of list corresponding to a given percentile pct
    (0 is first, 100 or more is last), treats the element a list,
    formats the first element of that list according to format,
    and returns the result. Returns "N/A" if the list is empty.
    """
    if len(list) == 0:
        return "N/A"
    i = int(pct*len(list)/100)
    if i >= len(list):
        i = len(list) - 1
    return format % (list[i][0])

def dict_diffs(dict1, dict2, msg=None):
    """
    Return a list consisting of the differences between elements in
    dict2 and those in dict1 with matching keys (ignore elements that
    appear in only one dict). If msg is specified, then negative
    differences should be ignored and an error message should be printed;
    msg provides info about the dictionaries being diffed.
    """
    diffs = []
    for key in dict1:
        if key in dict2:
            if msg and dict2[key] < dict1[key]:
                print("Skipping out of order diff for %s, id %s: %9.3f "
                        "< %9.3f" % (msg, key, dict2[key], dict1[key]))
            else:
                diffs.append(dict2[key] - dict1[key])
    return diffs

def print_samples(event1, event2, offset, delays, pct, msg, num_samples):
    """
    Print identifying information about events that fall at or near a given
    percentile  (from smallest to largest) among a collection of delays
    event1:      information about first event (dictionary mapping pktid -> time)
    event2:      information about a later event
    offset:      clock offset between times in event1 and those in event2
    delays:      sorted list of delays computed from event1 to event2
    pct:         desired percentile
    msg:         human-readable text describing the interval
    num_samples: number of events to print
    """

    if len(delays) == 0:
        print("No delays available for %s" % (msg))
        return
    target =  delays[pct*len(delays)//100]
    samples = []
    for pktid in event1:
        if not pktid in event2:
            continue
        elapsed = event2[pktid] - event1[pktid] - offset;
        samples.append({'time': event2[pktid], 'pktid': pktid,
                        'delay': elapsed})

    # Sort samples by how close their delay is to the desired one.
    samples = sorted(samples, key=lambda sample : abs(target - sample['delay']))

    # Now select the best samples without duplicating times
    chosen = []
    for sample in samples:
        for choice in chosen:
            if abs(choice['time'] - sample['time']) < 100:
                sample = None
                break
        if sample != None:
            chosen.append(sample)
            if len(chosen) == num_samples:
                break

    if len(chosen) == 0:
        print("Couldn't find %dth percentile events for %s" % (pct, msg))
        return
    print("%3dth percentile events for %s:" % (pct, msg))
    for sample in chosen:
        print("  %9.3f %-22s %.1f us" % (sample['time'],
                "(pktid %s):" % (sample['pktid']), sample['delay']))

def print_samples2(events, pct, msg, fmt, num_samples):
    """
    Similar to print_sample, except that the data is passed in a single
    list. Prints info about the event that in events that falls at a given
    percentile (from smallest to largest)
    events:      list of <value, time> tuples, where value is the data on
                 which we're computing percentile, and time is the time
                 in the trace when the tuple was logged. The list is sorted
                 in order of the values
    pct:         desired percentile
    msg:         human-readable text describing the values
    fmt:         printf-style format string for printing a value
    num_samples: number of events to print
    """

    if len(events) == 0:
        print("No events available for %s" % (msg))
        return
    target = events[pct*len(events)//100][0]

    # Sort sample by how close their value is to the target value
    resorted = sorted(events, key = lambda event: abs(target - event[0]))

    # Now select the best samples without duplicating times
    chosen = []
    for sample in resorted:
        for choice in chosen:
            if abs(choice[1] - sample[1]) < 100:
                sample = None
                break
        if sample != None:
            chosen.append(sample)
            if len(chosen) == num_samples:
                break

    # Print out the chosen samples
    if len(chosen) == 0:
        print("Couldn't find %dth percentile events for %s" % (pct, msg))
        return
    print("%3dth percentile events for %s:" % (pct, msg))
    for sample in chosen:
        print("  %9.3f %s" % (sample[1], fmt % (sample[0])))

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
    data_gro:            time when this packet was processed by homa_gro_receive
    data_gro_last:       time when last packet in batch containing this packet
                         was processed by homa_gro_receive
    data_handoff:        time when SoftIRQ handoff was issued for batch
                         containing this packet
    data_softirq_start:  time when homa_softirq was invoked with batch that
                         includes this packet
    data_softirq:        time when this homa_data_pkt processed this packet
                         at SoftIRQ level

    Each of the following elements is a list of 2-element lists, of which
    the second element is the time at which the last relevant event occurred
    delays_before_napi:  elements are <usecs, time> lists, where usecs is the
                         delay between common_interrupt and mlx5e_napi_poll
    gro_times:           elements are <usecs, time> lists, where usecs is the
                         the delay between the invocation of mlx5e_napi_poll
                         and the last call to homa_gro_receive for a batch of
                         packets
    gro_counts:          elements are <count, time> lists, where count is the
                         number of packets processed by homa_gro_receive in a
                         batch
    gro_gaps:            elements are <usecs, time> lists, where usecs is the
                         time between the last call to homa_gro_receive and
                         when the handoff to SoftIRQ was made
    """

    global verbose

    data_send = {}
    data_mlx = {}
    data_gro = {}
    data_gro_last = {}
    data_handoff = {}
    data_softirq_start = {}
    data_softirq = {}

    grant_send = {}
    grant_mlx = {}
    grant_gro = {}
    grant_gro_last = {}
    grant_handoff = {}
    grant_softirq_start = {}
    grant_softirq = {}

    delays_before_napi = []
    gro_times = []
    gro_counts = []
    gro_gaps = []

    # Keys are RPC ids and core; each value is the most recent pktid for which
    # ip_queue_xmit was invoked for this RPC on this core.
    grant_ids = {}

    # Keys are cores; each value is a list of packet ids that need
    # handoff events for this core
    data_handoff_ids = {}
    grant_handoff_ids = {}

    # Keys are cores; each value is the most recent time when homa_softirq
    # was invoked on the core
    softirq_start = {}

    # Keys are cores; each value is the most recent time when Homa GRO
    # processed a packet on that core.
    last_gro = {}

    # Keys are cores; each value is the number of packets processed by
    # homa_gro_receive in the current batch.
    num_gro_packets = {}

    # Keys are cores; each value is the most recent time when mlx_5e_napi_poll
    # was invoked on that core.
    last_mlx_napi = {}

    # Keys are cores; each value is the most recent time when the lowest
    # level interrupt handler (common_interrupt) was invoked.
    last_irq = {}

    # Counts of number of records of each type; used to detect when
    # changes in the timetrace code break these statistics.
    counts = {
        "sent packet": 0,
        "napi_poll invoked": 0,
        "backlog enqueue": 0,
        "softirq start": 0,
        "interrupt start": 0,
        "ip_queue_xmit": 0,
        "gro_receive": 0,
        "softirq data pkt": 0,
        "sent grant": 0,
        "gro_receive got grant": 0,
        "grant processed": 0,
    }

    for line in open(tt):
        match = re.match(' *([-0-9.]+) us \(\+ *([-0-9.]+) us\) \[C([0-9]+)\]'
                '.* id ([-0-9.]+),.* offset ([-0-9.]+)', line)
        if not match:
            # mlx finished sending grant
            match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\] mlx '
                    'sent homa packet to .* id ([-0-9.]+), type 21', line)
            if match:
                counts["sent packet"] += 1
                time = float(match.group(1))
                core = int(match.group(2))
                id = match.group(3)
                if (server):
                    id = str(int(id) - 1)
                key = id + ":" + str(core)
                if key in grant_ids:
                    grant_mlx[grant_ids[key]] = time

            # NAPI handler on receiver
            match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\] '
                    'mlx5e_napi_poll invoked', line)
            if match:
                counts["napi_poll invoked"] += 1
                time = float(match.group(1))
                core = int(match.group(2))
                last_mlx_napi[core] = time
                if core in last_irq:
                    delays_before_napi.append([time - last_irq[core], time])

            # Batch of packets has been handed off to SoftIRQ
            match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\] '
                    'enqueue_to_backlog', line)
            if match:
                counts["backlog enqueue"] += 1
                time = float(match.group(1))
                core = int(match.group(2))
                if core in last_gro:
                    gro_gaps.append([time - last_gro[core], time])
                    if core in last_mlx_napi:
                        gro_times.append([last_gro[core] - last_mlx_napi[core],
                                last_mlx_napi[core]])
                if core in num_gro_packets:
                    gro_counts.append([num_gro_packets[core], time])
                num_gro_packets[core] = 0
                if core in data_handoff_ids:
                    for pktid in data_handoff_ids[core]:
                        data_gro_last[pktid] = last_gro[core]
                        data_handoff[pktid] = time
                if core in grant_handoff_ids:
                    for pktid in grant_handoff_ids[core]:
                        grant_gro_last[pktid] = last_gro[core]
                        grant_handoff[pktid] = time
                data_handoff_ids[core] = []
                grant_handoff_ids[core] = []

            # homa_softirq invocation time
            match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\] '
                    'homa_softirq: first packet', line)
            if match:
                counts["softirq start"] += 1
                time = float(match.group(1))
                core = int(match.group(2))
                softirq_start[core] = time

            # common_interrupt invocation time
            match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\] '
                    'irq common_interrupt starting', line)
            if match:
                counts["interrupt start"] += 1
                time = float(match.group(1))
                core = int(match.group(2))
                last_irq[core] = time

            continue

        time = float(match.group(1))
        core = int(match.group(3))
        id = match.group(4)
        if (server):
            id = str(int(id) - 1)
        offset = match.group(5)
        pktid = id + ":" + offset

        # Outgoing data sent
        if re.match('.*calling .*_xmit: skb->len', line):
            counts["ip_queue_xmit"] += 1
            data_send[pktid] = time

        # Data packet passed to NIC
        if "Finished queueing packet" in line:
            counts["ip_queue_xmit"] += 1
            data_mlx[pktid] = time

        # Incoming data packet processed by Homa GRO
        if "homa_gro_receive got packet" in line:
            counts["gro_receive"] += 1
            data_gro[pktid] = time
            last_gro[core] = time
            if not core in num_gro_packets:
                num_gro_packets[core] = 0;
            num_gro_packets[core] += 1;
            if not core in data_handoff_ids:
                data_handoff_ids[core] = []
            data_handoff_ids[core].append(pktid)

        # Incoming data (SoftIRQ level)
        if "incoming data packet, id" in line:
            counts["softirq data pkt"] += 1
            if core in softirq_start:
                data_softirq[pktid] = time
                data_softirq_start[pktid] = softirq_start[core]

        # Outgoing grant
        if "sending grant for id" in line:
            counts["sent grant"] += 1
            grant_send[pktid] = time
            key = id + ":" + str(core)
            grant_ids[key] = pktid

        # Incoming grant processed by Homa GRO
        if "homa_gro_receive got grant" in line:
            counts["gro_receive got grant"] += 1
            grant_gro[pktid] = time
            last_gro[core] = time
            if not core in grant_handoff_ids:
                grant_handoff_ids[core] = []
            grant_handoff_ids[core].append(pktid)

        # Incoming grant (SoftIRQ level)
        if "processing grant for id" in line:
            counts["grant processed"] += 1
            if core in softirq_start:
                grant_softirq[pktid] = time
                grant_softirq_start[pktid] = softirq_start[core]

    if verbose:
        if server:
            print("Record counts in server log:")
        else:
            print("Record counts in client log:")
        for id in counts:
            print("  %-24s %6d" % (id, counts[id]))

    return {
        'data_send': data_send,
        'data_mlx': data_mlx,
        'data_gro': data_gro,
        'data_gro_last': data_gro_last,
        'data_handoff': data_handoff,
        'data_softirq_start': data_softirq_start,
        'data_softirq': data_softirq,

        'grant_send': grant_send,
        'grant_mlx': grant_mlx,
        'grant_gro': grant_gro,
        'grant_gro_last': grant_gro_last,
        'grant_handoff': grant_handoff,
        'grant_softirq_start': grant_softirq_start,
        'grant_softirq': grant_softirq,

        'delays_before_napi': delays_before_napi,
        'gro_times': gro_times,
        'gro_counts': gro_counts,
        'gro_gaps': gro_gaps,
    }

client = parse_tt(client_trace, False)
server = parse_tt(server_trace, True)

# Now combine the data from the two time traces to compute interesting delays

# Delays for data packets and grants passing through the IP stack
# on a single machine.
client_data_xmit = sorted(dict_diffs(client['data_send'], client['data_mlx'],
        "client data_send -> data_mlx"))
client_grant_xmit = sorted(dict_diffs(client['grant_send'], client['grant_mlx'],
        "client grant_send -> grant_mlx"))
server_data_xmit = sorted(dict_diffs(server['data_send'], server['data_mlx'],
        "server data_send -> data_mlx"))
server_grant_xmit = sorted(dict_diffs(server['grant_send'], server['grant_mlx'],
        "server grant_send -> grant_mlx"))

# Delays for data packets and grants from NIC on one machine to start of
# NAPI-level process on the other. These differences have not been compensated
# for clock differences between the machines.
cs_data_net = sorted(dict_diffs(client['data_mlx'], server['data_gro']))
cs_grant_net = sorted(dict_diffs(client['grant_mlx'], server['grant_gro']))
sc_data_net = sorted(dict_diffs(server['data_send'], client['data_gro']))
sc_grant_net = sorted(dict_diffs(server['grant_send'], client['grant_gro']))

# Additional GRO processing after this packet (other packets in batch)
client_data_gro_last = sorted(dict_diffs(client['data_gro'],
        client['data_gro_last'], "client data_gro -> data_gro_last"))
client_grant_gro_last = sorted(dict_diffs(client['grant_gro'],
        client['grant_gro_last'], "client grant_gro -> grant_gro_last"))
server_data_gro_last = sorted(dict_diffs(server['data_gro'],
        server['data_gro_last'], "server data_gro -> data_gro_last"))
server_grant_gro_last = sorted(dict_diffs(server['grant_gro'],
        server['grant_gro_last'], "server grant_gro -> grant_gro_last"))

# Delays from last GRO packet to SoftIRQ handoff
client_data_handoff = sorted(dict_diffs(client['data_gro_last'],
        client['data_handoff'], "client data_gro_last -> data_handoff"))
client_grant_handoff = sorted(dict_diffs(client['grant_gro_last'],
        client['grant_handoff'], "client grant_gro_last -> grant_handoff"))
server_data_handoff = sorted(dict_diffs(server['data_gro_last'],
        server['data_handoff'], "server data_gro_last -> data_handoff"))
server_grant_handoff = sorted(dict_diffs(server['grant_gro_last'],
        server['grant_handoff'], "server grant_gro_last -> grant_handoff"))

# Delays from SoftIRQ handoff until homa_softirq starts
client_data_softirq_start = sorted(dict_diffs(client['data_handoff'],
        client['data_softirq_start'], "client data_handoff -> softirq_start"))
client_grant_softirq_start = sorted(dict_diffs(client['grant_handoff'],
        client['grant_softirq_start'], "client grant_handoff -> softirq_start"))
server_data_softirq_start = sorted(dict_diffs(server['data_handoff'],
        server['data_softirq_start'], "server data_handoff -> softirq_start"))
server_grant_softirq_start = sorted(dict_diffs(server['grant_handoff'],
        server['grant_softirq_start'], "server grant_handoff -> softirq_start"))

# Delays from SoftIRQ start until the desired packet is processed
client_data_softirq = sorted(dict_diffs(client['data_softirq_start'],
        client['data_softirq'], "client data_softirq_start -> data_softirq"))
client_grant_softirq = sorted(dict_diffs(client['grant_softirq_start'],
        client['grant_softirq'], "client grant_softirq_start -> grant_softirq"))
server_data_softirq = sorted(dict_diffs(server['data_softirq_start'],
        server['data_softirq'], "server data_softirq_start -> data_softirq"))
server_grant_softirq = sorted(dict_diffs(server['grant_softirq_start'],
        server['grant_softirq'], "server grant_softirq_start -> grant_softirq"))

# Total delays (ip_queue_xmit to SoftIRQ)
cs_data_total = sorted(dict_diffs(client['data_send'], server['data_softirq']))
sc_data_total = sorted(dict_diffs(server['data_send'], client['data_softirq']))
cs_grant_total = sorted(dict_diffs(client['grant_send'], server['grant_softirq']))
sc_grant_total = sorted(dict_diffs(server['grant_send'], client['grant_softirq']))

# Compute minimum RTT and server clock offset
if len(cs_data_net) == 0:
    print("No data in cs_data_net");
    exit(1)
if len(sc_data_net) == 0:
    print("No data in sc_data_net");
    exit(1)
rtt = cs_data_net[0] + sc_data_net[0]
clock_offset = cs_data_net[0] - rtt/2
print("Minimum Network RTT: %.1f us, clock offset %.1f us" % (rtt, clock_offset))

# Adjust cross-machine times to reflect clock offset.
for list in [cs_data_net, cs_grant_net, cs_data_total, cs_grant_total]:
    for i in range(len(list)):
        list[i] -= clock_offset
for list in [sc_data_net, sc_grant_net, sc_data_total, sc_grant_total]:
    for i in range(len(list)):
        list[i] += clock_offset

percents = [0, 10, 30, 50, 70, 90, 99, 100]

print("\nIP:        IP stack, from calling ip_queue_xmit to NIC wakeup")
print("Net:       Additional time until homa_gro_receive gets packet")
print("GRO Other: Time until end of GRO batch")
print("GRO Gap:   Delay after GRO packet processing until SoftIRQ handoff")
print("Wakeup:    Delay until homa_softirq starts")
print("SoftIRQ:   Time in homa_softirq until packet is processed")
print("Total:     End-to-end time from calling ip_queue_xmit to homa_softirq")
print("           handler for packet")

print("\nData packet lifetime (us), client -> server:")
print("Pctile   IP     Net  GRO Other GRO Gap  Wakeup  SoftIRQ   Total")
for p in percents:
    print("%3d  %6s  %6s     %6s  %6s  %6s   %6s  %6s" % (p,
            percentile(client_data_xmit, p, "%.1f"),
            percentile(cs_data_net, p, "%.1f"),
            percentile(server_data_gro_last, p, "%.1f"),
            percentile(server_data_handoff, p, "%.1f"),
            percentile(server_data_softirq_start, p, "%.1f"),
            percentile(server_data_softirq, p, "%.1f"),
            percentile(cs_data_total, p, "%.1f")))

print("\nData packet lifetime (us), server -> client:")
print("Pctile   IP     Net  GRO Other GRO Gap  Wakeup  SoftIRQ   Total")
for p in percents:
    print("%3d  %6s  %6s     %6s  %6s  %6s   %6s  %6s" % (p,
            percentile(server_data_xmit, p, "%.1f"),
            percentile(sc_data_net, p, "%.1f"),
            percentile(client_data_gro_last, p, "%.1f"),
            percentile(client_data_handoff, p, "%.1f"),
            percentile(client_data_softirq_start, p, "%.1f"),
            percentile(client_data_softirq, p, "%.1f"),
            percentile(sc_data_total, p, "%.1f")))

print("\nGrant lifetime (us), client -> server:")
print("Pctile   IP     Net  GRO Other GRO Gap  Wakeup  SoftIRQ   Total")
for p in percents:
    print("%3d  %6s  %6s     %6s  %6s  %6s   %6s  %6s" % (p,
            percentile(client_grant_xmit, p, "%.1f"),
            percentile(cs_grant_net, p, "%.1f"),
            percentile(server_grant_gro_last, p, "%.1f"),
            percentile(server_grant_handoff, p, "%.1f"),
            percentile(server_grant_softirq_start, p, "%.1f"),
            percentile(server_grant_softirq, p, "%.1f"),
            percentile(cs_grant_total, p, "%.1f")))

print("\nGrant lifetime (us), server -> client:")
print("Pctile   IP     Net  GRO Other GRO Gap  Wakeup  SoftIRQ   Total")
for p in percents:
    print("%3d  %6s  %6s     %6s  %6s  %6s   %6s  %6s" % (p,
            percentile(server_grant_xmit, p, "%.1f"),
            percentile(sc_grant_net, p, "%.1f"),
            percentile(client_grant_gro_last, p, "%.1f"),
            percentile(client_grant_handoff, p, "%.1f"),
            percentile(client_grant_softirq_start, p, "%.1f"),
            percentile(client_grant_softirq, p, "%.1f"),
            percentile(sc_grant_total, p, "%.1f")))

print("\nAdditional client-side statistics:")
print("Pre NAPI:   usecs from interrupt entry to NAPI handler")
print("GRO Total:  usecs from NAPI handler entry to last homa_gro_receive")
print("Batch:      number of packets processed in one interrupt")
print("Gap:        usecs from last homa_gro_receive call to SoftIRQ handoff")
delays_before_napi = sorted(client['delays_before_napi'],
        key=lambda tuple : tuple[0])
gro_times = sorted(client['gro_times'], key=lambda tuple : tuple[0])
gro_counts = sorted(client['gro_counts'], key=lambda tuple : tuple[0])
gro_gaps = sorted(client['gro_gaps'], key=lambda tuple : tuple[0])
print("\nPctile   Pre NAPI    GRO  Batch     Gap")
for p in percents:
    print("%3d        %6s %6s  %5s  %6s" % (p,
            percentile2(delays_before_napi, p, "%.1f"),
            percentile2(gro_times, p, "%.1f"),
            percentile2(gro_counts, p, "%d"),
            percentile2(gro_gaps, p, "%.1f")))

print("\nSame stats for server:")
delays_before_napi = sorted(server['delays_before_napi'],
        key=lambda tuple : tuple[0])
gro_times = sorted(server['gro_times'], key=lambda tuple : tuple[0])
gro_counts = sorted(server['gro_counts'], key=lambda tuple : tuple[0])
gro_gaps = sorted(server['gro_gaps'], key=lambda tuple : tuple[0])
print("Pctile   Pre NAPI    GRO  Batch     Gap")
for p in percents:
    print("%3d        %6s %6s  %5s  %6s" % (p,
            percentile2(delays_before_napi, p, "%.1f"),
            percentile2(gro_times, p, "%.1f"),
            percentile2(gro_counts, p, "%d"),
            percentile2(gro_gaps, p, "%.1f")))

num_samples = 5
if verbose:
    print("\nPotentially interesting events:")
    print_samples(client['data_mlx'], server['data_gro'], clock_offset,
            cs_data_net, 0, "Net (client->server data)", num_samples)
    print_samples(client['data_mlx'], server['data_gro'], clock_offset,
            cs_data_net, 90, "Net (client->server data)", num_samples)
    print_samples(client['data_mlx'], server['data_gro'], clock_offset,
            cs_data_net, 99, "Net (client->server data)", num_samples)
    print_samples(server['data_gro'], server['data_gro_last'], 0,
            server_data_gro_last, 90, "GRO Other (client->server data)",
            num_samples)
    print_samples(server['data_gro'], server['data_gro_last'], 0,
            server_data_gro_last, 99, "GRO Other (client->server data)",
            num_samples)
    print_samples(server['data_gro_last'], server['data_handoff'], 0,
            server_data_handoff, 90, "GRO Gap (client->server data)",
            num_samples)
    print_samples(server['data_gro_last'], server['data_handoff'], 0,
            server_data_handoff, 99, "GRO Gap (client->server data)",
            num_samples)
    print_samples(server['data_handoff'], server['data_softirq_start'], 0,
            server_data_softirq_start, 90, "Wakeup (client->server data)",
            num_samples)
    print_samples(server['data_handoff'], server['data_softirq_start'], 0,
            server_data_softirq_start, 99, "Wakeup (client->server data)",
            num_samples)
    print_samples(server['data_softirq_start'], server['data_softirq'], 0,
            server_data_softirq, 90, "SoftIRQ (client->server data)",
            num_samples)
    print_samples(server['data_softirq_start'], server['data_softirq'], 0,
            server_data_softirq, 99, "SoftIRQ (client->server data)",
            num_samples)

    print()
    print_samples2(delays_before_napi, 90, "delay before NAPI starts (server)",
            "%.1f us", num_samples);
    print_samples2(delays_before_napi, 99, "delay before NAPI starts (server)",
            "%.1f us", num_samples);
    print_samples2(gro_times, 90, "total time for GRO batch (server)",
            "%.1f us", num_samples);
    print_samples2(gro_times, 99, "total time for GRO batch (server)",
            "%.1f us", num_samples);
    print_samples2(gro_counts, 90, "packets in a GRO batch (server)",
            "%d", num_samples);
    print_samples2(gro_counts, 99, "packets in a GRO batch (server)",
            "%d", num_samples);
    print_samples2(gro_gaps, 90, "gap before SoftIRQ wakeup (server)",
            "%.1f us", num_samples);
    print_samples2(gro_gaps, 99, "gap before SoftIRQ wakeup (server)",
            "%.1f us", num_samples);