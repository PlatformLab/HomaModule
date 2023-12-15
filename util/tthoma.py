#!/usr/bin/python3

"""
This script analyzes time traces gathered from Homa in a variety of ways.
Invoke with the --help option for documentation.
"""

from collections import defaultdict
from glob import glob
from optparse import OptionParser
import math
from operator import itemgetter
import os
from pathlib import Path
import re
import string
import sys
import textwrap
import time

# This global variable holds information about every RPC from every trace
# file; it is created by AnalyzeRpcs. Keys are RPC ids, values are dictionaries
# of info about that RPC, with the following elements (some elements may be
# missing if the RPC straddled the beginning or end of the timetrace):
# peer:              Address of the peer host
# node:              'node' field from the trace file where this RPC appeared
#                    (name of trace file without extension)
# gro_data:          List of <time, offset, priority> tuples for all incoming
#                    data packets processed by GRO
# gro_grant:         List of <time, offset> tuples for all incoming
#                    grant packets processed by GRO
# gro_core:          Core that handled GRO processing for this RPC
# softirq_data:      List of <time, offset> tuples for all incoming
#                    data packets processed by SoftIRQ
# softirq_grant:     List of <time, offset> tuples for all incoming
#                    grant packets processed by SoftIRQ
# handoff:           Time when RPC was handed off to waiting thread
# queued:            Time when RPC was added to ready queue (no
#                    waiting threads). At most one of 'handoff' and 'queued'
#                    will be present.
# found:             Time when homa_wait_for_message found the RPC
# recvmsg_done:      Time when homa_recvmsg returned
# sendmsg:           Time when homa_sendmsg was invoked
# in_length:         Size of the incoming message, in bytes
# out_length:        Size of the outgoing message, in bytes
# send_data:         List of <time, offset, length> tuples for outgoing
#                    data packets (length is message data)
# send_grant:        List of <time, offset, priority> tuples for
#                    outgoing grant packets
# ip_xmits:          Dictionary mapping from offset to ip_*xmit time for
#                    that offset. Only contains entries for offsets where
#                    the ip_xmit record has been seen but not send_data
# resends:           Maps from offset to (most recent) time when a RESEND
#                    request was made for that offset
# retansmits:        One entry for each packet retransmitted; maps from offset
#                    to <time, length> tuple
#
rpcs = {}

# This global variable holds information about all of the traces that
# have been read. Maps from the 'node' fields of a traces to a dictionary
# containing the following values:
# file:         Name of file from which the trace was read
# line:         The most recent line read from the file
# node:         The last element of file, with extension removed; used
#               as a host name in various output
# first_time:   Time of the first event read for this trace
# last_time:    Time of the last event read for this trace
# elapsed_time: Total time interval covered by the trace
traces = {}

# Maps from peer addresses to the associated node names. Computed by
# AnalyzeRpcs.
peer_nodes = {}

# This variable holds information about every data packet in the traces.
# it is created by AnalyzePackets. Keys have the form id:offset where id is
# the RPC id on the sending side and offset is the offset in message of
# the first byte of the packet. Each value is a dictionary containing
# the following fields:
# xmit:        Time when ip*xmit was invoked
# nic:         Time when the NIC transmitted the packet (if available)
# gro:         Time when GRO received the packet
# softirq:     Time when homa_softirq processed the packet
# free:        Time when skb was freed (after copying to application)
# id:          RPC id on the sender
# offset:      Offset of the data in the packet within its message
# length:      # bytes of message data in this packet
# msg_length:  Total number of bytes in the message
# priority:    Priority at which packet was transmitted
packets = defaultdict(dict)

# This variable holds information about every grant packet in the traces.
# it is created by AnalyzePackets. Keys have the form id:offset where id is
# the RPC id on the sending side and offset is the offset in message of
# the first byte of the packet. Each value is a dictionary containing
# the following fields:
# xmit:     Time when ip*xmit was invoked
# nic:      Time when the NIC transmitted the packet
# gro:      Time when GRO received (the first bytes of) the packet
# softirq:  Time when homa_softirq processed the packet
# id:       Id of the RPC on the sender
grants = defaultdict(dict)

def dict_avg(data, key):
    """
    Given a list of dictionaries, return the average of the elements
    with the given key.
    """
    count = 0
    total = 0.0
    for item in data:
        if (key in item) and (item[key] != None):
            total += item[key]
            count += 1
    if not count:
        return 0
    return total / count

def list_avg(data, index):
    """
    Given a list of lists, return the average of the index'th elements
    of the lists.
    """
    if len(data) == 0:
        return 0
    total = 0
    for item in data:
        total += item[0]
    return total / len(data)

def extract_num(s):
    """
    If the argument contains an integer number as a substring,
    return the number. Otherwise, return None.
    """
    match = re.match('[^0-9]*([0-9]+)', s)
    if match:
        return int(match.group(1))
    return None

def get_first_time():
    """
    Return the earliest event time across all trace files.
    """
    earliest = 1e20
    for trace in traces.values():
        first = trace['first_time']
        if first < earliest:
            earliest = first
    return earliest

def get_last_time():
    """
    Return the latest event time across all trace files.
    """
    latest = -1e20
    for trace in traces.values():
        last = trace['last_time']
        if last > latest:
            latest = last
    return latest

def get_packet_size():
    """
    Returns the amount of message data in a full-size network packet (as
    received by the receiver; GSO packets sent by senders may be larger).
    """

    global rpcs

    # We cache the result to avoid recomputing
    if get_packet_size.result != None:
        return get_packet_size.result

    if len(rpcs) == 0:
        raise Exception('get_packet_size failed: no RPCs (did you forget '
                'to include the rpc analyzer?)')

    # Scan incoming data packets for all of the RPCs, looking for one
    # with at least 4 packets. Of the 3 gaps in offset, at least 2 must
    # be the same (the only special case is for unscheduled data). If
    # we can't find any RPCs with 4 packets, then look for one with 2
    # packets and find the offset of the second packet. If there are
    # no multi-packet RPCs, then just pick a large value (the size won't
    # matter).
    for id, rpc in rpcs.items():
        if not 'softirq_data' in rpc:
            continue
        offsets = sorted(map(lambda pkt : pkt[1], rpc['softirq_data']))
        if (len(offsets) < 2) or (offsets[0] != 0) or not 'recvmsg_done' in rpc:
            continue
        size1 = offsets[1] - offsets[0]
        if len(offsets) >= 4:
            size2 = None
            for i in range(2, len(offsets)):
                size = offsets[i] - offsets[i-1]
                if (size == size1) or (size == size2):
                    get_packet_size.result = size
                    return size
                choice2 = size
        get_packet_size.result = size1
    if get_packet_size.result == None:
        print('Can\'t compute maximum packet size; assuming 100000')
        get_packet_size.result = 100000
    return get_packet_size.result;
get_packet_size.result = None

def get_sorted_nodes():
    """
    Returns a list of node names ('node' value from traces), sorted
    by node number if there are numbers in the names, otherwise
    sorted alphabetically.
    """
    global traces

    # We cache the result to avoid recomputing
    if get_sorted_nodes.result != None:
        return get_sorted_nodes.result

    # First see if all of the names contain numbers.
    nodes = traces.keys()
    got_nums = True
    for node in nodes:
        if extract_num(node) == None:
            got_nums = False
            break
    if not got_nums:
        get_sorted_nodes.result = sorted(nodes)
    else:
        get_sorted_nodes.result = sorted(nodes, key=lambda name : extract_num(name))
    return get_sorted_nodes.result
get_sorted_nodes.result = None

def get_time_stats(samples):
    """
    Given a list of elapsed times, returns a string containing statistics
    such as min time, P99, and average.
    """
    if not samples:
        return 'no data'
    sorted_data = sorted(samples)
    average = sum(sorted_data)/len(samples)
    return 'Min %.1f, P50 %.1f, P90 %.1f, P99 %.1f, Avg %.1f' % (
            sorted_data[0],
            sorted_data[50*len(sorted_data)//100],
            sorted_data[90*len(sorted_data)//100],
            sorted_data[99*len(sorted_data)//100],
            average)

def percentile(data, pct, format, na):
    """
    Finds the element of data corresponding to a given percentile pct
    (0 is first, 100 or more is last), formats it according to format,
    and returns the result. Returns na if the list is empty. Data must
    be sorted in percentile order
    """
    if len(data) == 0:
        return na
    i = int(pct*len(data)/100)
    if i >= len(data):
        i = len(data) - 1
    return format % (data[i])

def pkt_id(id, offset):
    return '%d:%d' % (id, offset)

def print_analyzer_help():
    """
    Prints out documentation for all of the analyzers.
    """

    module = sys.modules[__name__]
    for attr in sorted(dir(module)):
        if not attr.startswith('Analyze'):
            continue
        object = getattr(module, attr)
        analyzer = attr[7].lower() + attr[8:]
        if object.__doc__ == None:
            continue
        print('%s: %s' % (analyzer, object.__doc__))

class Dispatcher:
    """
    This class manages a set of patterns to match against the records
    of a timetrace. It then reads  time trace files and passes information
    about matching records to other classes that are interested in them.
    """

    def __init__(self):
        # List of all objects with registered interests, in order of
        # registration.
        self.objs = []

        # Keys are names of all classes passed to the interest method.
        # Values are the corresponding objects.
        self.analyzers = {}

        # Keys are pattern names, values are lists of objects interested in
        # that pattern.
        self.interests = {}

        # List of objects with tt_all methods, which will be invoked for
        # every record.
        self.all_interests= []

        # List (in same order as patterns) of all patterns that appear in
        # interests. Created lazily by parse, can be set to None to force
        # regeneration.
        self.active = []

    def get_analyzers(self):
        """
        Return a list of all analyzer objects registered with this
        dispatcher
        """

        return self.objs

    def interest(self, analyzer):
        """
        If analyzer hasn't already been registered with this dispatcher,
        create an instance of that class and arrange for its methods to
        be invoked for matching lines in timetrace files. For each method
        named 'tt_xxx' in the class there must be a pattern named 'xxx';
        the method will be invoked whenever the pattern matches a timetrace
        line, with parameters containing parsed fields from the line.

        analyzer: name of a class containing trace analysis code
        """

        if analyzer in self.analyzers:
            return
        obj = getattr(sys.modules[__name__], analyzer)(self)
        self.analyzers[analyzer] = obj
        self.objs.append(obj)

        for name in dir(obj):
            if not name.startswith('tt_'):
                continue
            method = getattr(obj, name)
            if not callable(method):
                continue
            name = name[3:]
            if name == 'all':
                self.all_interests.append(obj)
                continue
            for pattern in self.patterns:
                if name != pattern['name']:
                    continue
                found_pattern = True
                if not name in self.interests:
                    self.interests[name] = []
                    self.active = None
                self.interests[name].append(obj)
                break
            if not name in self.interests:
                raise Exception('Couldn\'t find pattern %s for analyzer %s'
                        % (name, analyzer))

    def parse(self, file):
        """
        Parse a timetrace file and invoke interests.
        file:     Name of the file to parse.
        """

        global traces
        self.__build_active()

        trace = {}
        trace['file'] = file
        node = Path(file).stem
        trace['node'] = node
        traces[node] = trace

        print('Reading trace file %s' % (file), file=sys.stderr)
        for analyzer in self.objs:
            if hasattr(analyzer, 'init_trace'):
                analyzer.init_trace(trace)

        f = open(file)
        first = True
        for trace['line'] in f:
            # Parse each line in 2 phases: first the time and core information
            # that is common to all patterns, then the message, which will
            # select at most one pattern.
            match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\] (.*)', trace['line'])
            if not match:
                continue
            time = float(match.group(1))
            core = int(match.group(2))
            msg = match.group(3)

            if first:
                trace['first_time'] = time
                first = False
            trace['last_time'] = time
            for pattern in self.active:
                match = re.match(pattern['regexp'], msg)
                if match:
                    pattern['parser'](trace, time, core, match,
                            self.interests[pattern['name']])
                    break
            for interest in self.all_interests:
                interest.tt_all(trace, time, core, msg)
        f.close()
        trace['elapsed_time'] = trace['last_time'] - trace['first_time']

    def __build_active(self):
        """
        Build the list of patterns that must be matched against the trace file.
        Also, fill in the 'parser' element for each pattern.
        """

        if self.active:
            return
        self.active = []
        for pattern in self.patterns:
            pattern['parser'] = getattr(self, '_Dispatcher__' + pattern['name'])
            if pattern['name'] in self.interests:
                self.active.append(pattern)

    # Each entry in this list represents one pattern that can be matched
    # against the lines of timetrace files. For efficiency, the patterns
    # most likely to match should be at the front of the list. Each pattern
    # is a dictionary containing the following elements:
    # name:       Name for this pattern. Used for auto-configuration (e.g.
    #             methods named tt_<name> are invoked to handle matching
    #             lines).
    # regexp:     Regular expression to match against the message portion
    #             of timetrace records (everything after the core number).
    # matches:    Number of timetrace lines that matched this pattern.
    # parser:     Method in this class that will be invoked to do additional
    #             parsing of matched lines and invoke interests.
    # This object is initialized as the parser methods are defined below.
    patterns = []

    # The declarations below define parser methods and their associated
    # patterns. The name of a parser is derived from the name of its
    # pattern. Parser methods are invoked when lines match the corresponding
    # pattern. The job of each method is to parse the matches from the pattern,
    # if any, and invoke all of the relevant interests. All of the methods
    # have the same parameters:
    # self:         The Dispatcher object
    # trace:        Holds information being collected from the current trace file
    # time:         Time of the current record (microseconds)
    # core:         Number of the core on which the event occurred
    # match:        The match object returned by re.match
    # interests:    The list of objects to notify for this event

    def __gro_data(self, trace, time, core, match, interests):
        peer = match.group(1)
        id = int(match.group(2))
        offset = int(match.group(3))
        prio = int(match.group(4))
        for interest in interests:
            interest.tt_gro_data(trace, time, core, peer, id, offset, prio)

    patterns.append({
        'name': 'gro_data',
        'regexp': 'homa_gro_receive got packet from ([^ ]+) id ([0-9]+), '
                  'offset ([0-9.]+), priority ([0-9.]+)'
    })

    def __gro_grant(self, trace, time, core, match, interests):
        peer = match.group(1)
        id = int(match.group(2))
        offset = int(match.group(3))
        priority = int(match.group(4))
        for interest in interests:
            interest.tt_gro_grant(trace, time, core, peer, id, offset, priority)

    patterns.append({
        'name': 'gro_grant',
        'regexp': 'homa_gro_receive got grant from ([^ ]+) id ([0-9]+), '
                  'offset ([0-9]+), priority ([0-9]+)'
    })

    def __softirq_data(self, trace, time, core, match, interests):
        id = int(match.group(1))
        offset = int(match.group(2))
        msg_length = int(match.group(3))
        for interest in interests:
            interest.tt_softirq_data(trace, time, core, id, offset, msg_length)

    patterns.append({
        'name': 'softirq_data',
        'regexp': 'incoming data packet, id ([0-9]+), .*, offset ([0-9.]+)'
                  '/([0-9.]+)'
    })

    def __softirq_grant(self, trace, time, core, match, interests):
        id = int(match.group(1))
        offset = int(match.group(2))
        for interest in interests:
            interest.tt_softirq_grant(trace, time, core, id, offset)

    patterns.append({
        'name': 'softirq_grant',
        'regexp': 'processing grant for id ([0-9]+), offset ([0-9]+)'
    })

    def __ip_xmit(self, trace, time, core, match, interests):
        id = int(match.group(1))
        offset = int(match.group(2))
        for interest in interests:
            interest.tt_ip_xmit(trace, time, core, id, offset)

    patterns.append({
        'name': 'ip_xmit',
        'regexp': 'calling ip.*_xmit: .* id ([0-9]+), offset ([0-9]+)'
    })

    def __send_data(self, trace, time, core, match, interests):
        id = int(match.group(1))
        offset = int(match.group(2))
        length = int(match.group(3))
        if length == 0:
            # Temporary fix to compensate for Homa bug; delete this code soon.
            return
        for interest in interests:
            interest.tt_send_data(trace, time, core, id, offset, length)

    patterns.append({
        'name': 'send_data',
        'regexp': 'Finished queueing packet: rpc id ([0-9]+), offset '
                  '([0-9]+), len ([0-9]+)'
    })

    def __send_grant(self, trace, time, core, match, interests):
        id = int(match.group(1))
        offset = int(match.group(2))
        priority = int(match.group(3))
        for interest in interests:
            interest.tt_send_grant(trace, time, core, id, offset, priority)

    patterns.append({
        'name': 'send_grant',
        'regexp': 'sending grant for id ([0-9]+), offset ([0-9]+), '
                  'priority ([0-9]+)'
    })

    def __mlx_data(self, trace, time, core, match, interests):
        peer = match.group(1)
        id = int(match.group(2))
        offset = int(match.group(3))
        for interest in interests:
            interest.tt_mlx_data(trace, time, core, peer, id, offset)

    patterns.append({
        'name': 'mlx_data',
        'regexp': 'mlx sent homa data packet to ([^,]+), id ([0-9]+), '
                  'offset ([0-9]+)'
    })

    def __mlx_grant(self, trace, time, core, match, interests):
        peer = match.group(1)
        id = int(match.group(2))
        offset = int(match.group(3))
        for interest in interests:
            interest.tt_mlx_grant(trace, time, core, peer, id, offset)

    patterns.append({
        'name': 'mlx_grant',
        'regexp': 'mlx sent homa grant to ([^,]+), id ([0-9]+), offset ([0-9]+)'
    })

    def __sendmsg_request(self, trace, time, core, match, interests):
        peer = match.group(1)
        id = int(match.group(2))
        length = int(match.group(3))
        for interest in interests:
            interest.tt_sendmsg_request(trace, time, core, peer, id, length)

    patterns.append({
        'name': 'sendmsg_request',
        'regexp': 'homa_sendmsg request, target ([^: ]+):.* id '
                  '([0-9]+), length ([0-9]+)'
    })

    def __sendmsg_response(self, trace, time, core, match, interests):
        id = int(match.group(1))
        length = int(match.group(2))
        for interest in interests:
            interest.tt_sendmsg_response(trace, time, core, id, length)

    patterns.append({
        'name': 'sendmsg_response',
        'regexp': 'homa_sendmsg response, id ([0-9]+), .*length ([0-9]+)'
    })

    def __recvmsg_done(self, trace, time, core, match, interests):
        id = int(match.group(1))
        length = int(match.group(2))
        for interest in interests:
            interest.tt_recvmsg_done(trace, time, core, id, length)

    patterns.append({
        'name': 'recvmsg_done',
        'regexp': 'homa_recvmsg returning id ([0-9]+), length ([0-9]+)'
    })

    def __copy_in_start(self, trace, time, core, match, interests):
        for interest in interests:
            interest.tt_copy_in_start(trace, time, core)

    patterns.append({
        'name': 'copy_in_start',
        'regexp': 'starting copy from user space'
    })

    def __copy_in_done(self, trace, time, core, match, interests):
        id = int(match.group(1))
        num_bytes = int(match.group(2))
        for interest in interests:
            interest.tt_copy_in_done(trace, time, core, id, num_bytes)

    patterns.append({
        'name': 'copy_in_done',
        'regexp': 'finished copy from user space for id ([-0-9.]+), '
                'length ([-0-9.]+)'
    })

    def __copy_out_start(self, trace, time, core, match, interests):
        id = int(match.group(1))
        for interest in interests:
            interest.tt_copy_out_start(trace, time, core, id)

    patterns.append({
        'name': 'copy_out_start',
        'regexp': 'starting copy to user space for id ([0-9]+)'
    })

    def __copy_out_done(self, trace, time, core, match, interests):
        start = int(match.group(1))
        end = int(match.group(2))
        id = int(match.group(3))
        for interest in interests:
            interest.tt_copy_out_done(trace, time, core, id, start, end)

    patterns.append({
        'name': 'copy_out_done',
        'regexp': 'copied out bytes ([0-9.]+)-([0-9.]+) for id ([0-9.]+)'
    })

    def __free_skbs(self, trace, time, core, match, interests):
        num_skbs = int(match.group(1))
        for interest in interests:
            interest.tt_free_skbs(trace, time, core, num_skbs)

    patterns.append({
        'name': 'free_skbs',
        'regexp': 'finished freeing ([0-9]+) skbs'
    })

    def __gro_handoff(self, trace, time, core, match, interests):
        softirq_core = int(match.group(1))
        for interest in interests:
            interest.tt_gro_handoff(trace, time, core, softirq_core)

    patterns.append({
        'name': 'gro_handoff',
        'regexp': 'homa_gro_.* chose core ([0-9]+)'
    })

    def __softirq_start(self, trace, time, core, match, interests):
        for interest in interests:
            interest.tt_softirq_start(trace, time, core)

    patterns.append({
        'name': 'softirq_start',
        'regexp': 'homa_softirq: first packet'
    })

    def __rpc_handoff(self, trace, time, core, match, interests):
        id = int(match.group(1))
        for interest in interests:
            interest.tt_rpc_handoff(trace, time, core, id)

    patterns.append({
        'name': 'rpc_handoff',
        'regexp': 'homa_rpc_handoff handing off id ([0-9]+)'
    })

    def __rpc_queued(self, trace, time, core, match, interests):
        id = int(match.group(1))
        for interest in interests:
            interest.tt_rpc_queued(trace, time, core, id)

    patterns.append({
        'name': 'rpc_queued',
        'regexp': 'homa_rpc_handoff finished queuing id ([0-9]+)'
    })

    def __wait_found_rpc(self, trace, time, core, match, interests):
        id = int(match.group(1))
        for interest in interests:
            interest.tt_wait_found_rpc(trace, time, core, id)

    patterns.append({
        'name': 'wait_found_rpc',
        'regexp': 'homa_wait_for_message found rpc id ([0-9]+)'
    })

    def __poll_success(self, trace, time, core, match, interests):
        id = int(match.group(1))
        for interest in interests:
            interest.tt_poll_success(trace, time, core, id)

    patterns.append({
        'name': 'poll_success',
        'regexp': 'received RPC handoff while polling, id ([0-9]+)'
    })

    def __resend(self, trace, time, core, match, interests):
        id = int(match.group(1))
        offset = int(match.group(2))
        for interest in interests:
            interest.tt_resend(trace, time, core, id, offset)

    patterns.append({
        'name': 'resend',
        'regexp': 'Sent RESEND for client RPC id ([0-9]+), .* offset ([0-9]+)'
    })

    def __retransmit(self, trace, time, core, match, interests):
        offset = int(match.group(1))
        length = int(match.group(2))
        id = int(match.group(3))
        for interest in interests:
            interest.tt_retransmit(trace, time, core, id, offset, length)

    patterns.append({
        'name': 'retransmit',
        'regexp': 'retransmitting offset ([0-9]+), length ([0-9]+), id ([0-9]+)'
    })

#------------------------------------------------
# Analyzer: activity
#------------------------------------------------
class AnalyzeActivity:
    """
    Prints statistics about how many RPCs are active and data throughput.
    """

    def __init__(self, dispatcher):
        dispatcher.interest('AnalyzeRpcs')
        return

    def sum_list(self, events):
        """
        Given a list of <time, event> entries where event is 'start' or 'end',
        return a list <num_starts, active_frac, avg_active>:
        num_starts:    Total number of 'start' events
        active_frac:   Fraction of all time when #starts > #ends
        avg_active:    Average value of #starts - #ends
        The input list should be sorted in order of time by the caller.
        """
        num_starts = 0
        cur_active = 0
        active_time = 0
        active_integral = 0
        last_time = events[0][0]

        for time, event in events:
            # print("%9.3f: %s, cur_active %d, active_time %.1f, active_integral %.1f" %
            #         (time, event, cur_active, active_time, active_integral))
            delta = time - last_time
            if cur_active:
                active_time += delta
            active_integral += delta * cur_active
            if event == 'start':
                num_starts += 1
                cur_active += 1
            else:
                cur_active -= 1
            last_time = time
        total_time = events[-1][0] - events[0][0]
        return num_starts, active_time/total_time, active_integral/total_time

    def output(self):
        global rpcs, traces

        # Each of the following lists contains <time, event> entries,
        # where event is 'start' or end'. The entry indicates that an
        # input or output message started arriving or completed at the given time.

        # Maps from node name to a list of events for input messages
        # on that server.
        node_in_events = {}

        # Maps from a node name to a list of events for output messages
        # on that server.
        node_out_events = {}

        # Maps from node name to a dictionary that maps from core
        # number to total GRO data received by that core
        node_core_in_bytes = {}

        # Maps from node name to a count of total bytes output by that node
        node_out_bytes = {}

        for node in get_sorted_nodes():
            node_in_events[node] = []
            node_out_events[node] = []
            node_core_in_bytes[node] = {}
            node_out_bytes[node] = 0
        for id, rpc in rpcs.items():
            node = rpc['node']

            gros = rpc['gro_data']
            if gros:
                # The start time for an input message is normally the time when
                # GRO received the first data packet. However, if offset 0
                # doesn't appear in the GRO list, assume the message was
                # already in progress when the trace began.
                if gros[0][1] == 0:
                    in_start = gros[0][0]
                else:
                    in_start = traces[node]['first_time']
                    for gro in gros:
                        if gro[1] == 0:
                            in_start = gros[0][0]
                            break

                if 'recvmsg_done' in rpc:
                    in_end = rpc['recvmsg_done']
                else:
                    in_end = traces[node]['last_time']
                node_in_events[node].append([in_start, 'start'])
                node_in_events[node].append([in_end, 'end'])

                # Compute total data received for the message.
                min_offset = 10000000
                max_offset = -1
                for pkt in gros:
                    offset = pkt[1]
                    if offset < min_offset:
                        min_offset = offset
                    if offset > max_offset:
                        max_offset = offset
                if 'recvmsg_done' in rpc:
                    if 'in_length' in rpc:
                        bytes = rpc['in_length'] - min_offset
                    else:
                        bytes = 0
                else:
                    bytes = max_offset + get_packet_size() - min_offset
                core = rpc['gro_core']
                cores = node_core_in_bytes[rpc['node']]
                if not core in cores:
                    cores[core] = bytes
                else:
                    cores[core] += bytes

            # Collect information about outgoing messages.
            if rpc['send_data']:
                if 'sendmsg' in rpc:
                    out_start = rpc['sendmsg']
                else:
                    out_start = traces[node]['first_time']
                time, offset, length = rpc['send_data'][-1]
                out_end = time
                if 'out_length' in rpc:
                    if (offset + length) != rpc['out_length']:
                        out_end = traces[node]['last_time']
                node_out_events[node].append([out_start, 'start'])
                node_out_events[node].append([out_end, 'end'])

                # Collect total data sent for the message.
                bytes = 0
                for pkt in rpc['send_data']:
                    bytes += pkt[2]
                node_out_bytes[rpc['node']] += bytes

        def print_list(node, events, num_bytes, extra):
            global traces
            events.sort(key=lambda tuple : tuple[0])
            msgs, activeFrac, avgActive = self.sum_list(events)
            rate = msgs/(events[-1][0] - events[0][0])
            gbps = num_bytes*8e-3/(traces[node]['elapsed_time'])
            print('%-10s %6d %7.3f %9.3f %8.2f %7.2f  %7.2f%s' % (
                    node, msgs, rate, activeFrac, avgActive, gbps,
                    gbps/activeFrac, extra))

        print('\n-------------------')
        print('Analyzer: activity')
        print('-------------------\n')
        print('Msgs:          Total number of incoming/outgoing messages')
        print('MsgRate:       Rate at which new messages arrived (M/sec)')
        print('ActvFrac:      Fraction of time when at least one message was active')
        print('AvgActv:       Average number of active messages')
        print('Gbps:          Total message throughput (Gbps)')
        print('ActvGbps:      Total throughput when at least one message was active (Gbps)')
        print('MaxCore:       Highest incoming throughput via a single GRO core (Gbps)')
        print('\nIncoming messages:')
        print('Node         Msgs MsgRate  ActvFrac  AvgActv    Gbps ActvGbps       MaxCore')
        print('---------------------------------------------------------------------------')
        for node in get_sorted_nodes():
            if not node in node_in_events:
                continue
            events = node_in_events[node]
            max_core = 0
            max_bytes = 0
            total_bytes = 0
            for core, bytes in node_core_in_bytes[node].items():
                total_bytes += bytes
                if bytes > max_bytes:
                    max_bytes = bytes
                    max_core = core
            max_gbps = max_bytes*8e-3/(traces[node]['elapsed_time'])
            print_list(node, events, total_bytes,
                    ' %7.2f (C%02d)' % (max_core, max_gbps))
        print('\nOutgoing messages:')
        print('Node         Msgs MsgRate  ActvFrac  AvgActv    Gbps ActvGbps')
        print('-------------------------------------------------------------')
        for node in get_sorted_nodes():
            if not node in node_out_events:
                continue
            bytes = node_out_bytes[node]
            print_list(node, node_out_events[node], bytes, "")

#------------------------------------------------
# Analyzer: copy
#------------------------------------------------
class AnalyzeCopy:
    """
    Measures the throughput of copies between user space and kernel space.
    """

    def __init__(self, dispatcher):
        return

    def init_trace(self, trace):
        trace['copy'] = {
            # Keys are cores; values are times when most recent copy from
            # user space started on that core
            'in_start': {},

            # Total bytes of data copied from user space for large messages
            'large_in_data': 0,

            # Total microseconds spent copying data for large messages
            'large_in_time': 0.0,

            # Total number of large messages copied into kernel
            'large_in_count': 0,

            # List of copy times for messages no larger than 1200 B
            'small_in_times': [],

            # Total time spent copying in data for all messages
            'total_in_time': 0.0,

            # Keys are cores; values are times when most recent copy to
            # user space started on that core
            'out_start': {},

            # Keys are cores; values are times when most recent copy to
            # user space ended on that core
            'out_end': {},

            # Keys are cores; values are sizes of last copy to user space
            'out_size': {},

            # Total bytes of data copied to user space for large messages
            'large_out_data': 0,

            # Total microseconds spent copying data for large messages
            'large_out_time': 0.0,

            # Total microseconds spent copying data for large messages,
            # including time spent freeing skbs.
            'large_out_time_with_skbs': 0.0,

            # Total number of large messages copied out of kernel
            'large_out_count': 0,

            # List of copy times for messages no larger than 1200 B
            'small_out_times': [],

            # Total time spent copying out data for all messages
            'total_out_time': 0.0,

            # Total number of skbs freed after copying data to user space
            'skbs_freed': 0,

            # Total time spent freeing skbs after copying data
            'skb_free_time': 0.0
        }

    def tt_copy_in_start(self, trace, time, core):
        stats = trace['copy']
        stats['in_start'][core] = time

    def tt_copy_in_done(self, trace, time, core, id, num_bytes):
        global options
        stats = trace['copy']
        if core in stats['in_start']:
            delta = time - stats['in_start'][core]
            stats['total_in_time'] += delta
            if num_bytes <= 1000:
                stats['small_in_times'].append(delta)
            elif num_bytes >= 5000:
                stats['large_in_data'] += num_bytes
                stats['large_in_time'] += delta
                stats['large_in_count'] += 1
            if options.verbose:
                print('%9.3f Copy in finished [C%02d]: %d bytes, %.1f us, %5.1f Gbps' %
                        (time, core, num_bytes, delta, 8e-03*num_bytes/delta))

    def tt_copy_out_start(self, trace, time, core, id):
        stats = trace['copy']
        stats['out_start'][core] = time

    def tt_copy_out_done(self, trace, time, core, id, start, end):
        global options
        stats = trace['copy']
        num_bytes = end - start
        if core in stats['out_start']:
            stats['out_end'][core] = time
            stats['out_size'][core] = num_bytes
            delta = time - stats['out_start'][core]
            stats['out_start'][core] = time
            stats['total_out_time'] += delta
            if num_bytes <= 1000:
                stats['small_out_times'].append(delta)
            elif num_bytes >= 5000:
                stats['large_out_data'] += num_bytes
                stats['large_out_time'] += delta
                stats['large_out_time_with_skbs'] += delta
                stats['large_out_count'] += 1
            if options.verbose:
                print('%9.3f Copy out finished [C%02d]: %d bytes, %.1f us, %5.1f Gbps' %
                        (time, core, num_bytes, delta, 8e-03*num_bytes/delta))

    def tt_free_skbs(self, trace, time, core, num_skbs):
        stats = trace['copy']
        if core in stats['out_end']:
            delta = time - stats['out_end'][core]
            stats['skbs_freed'] += num_skbs
            stats['skb_free_time'] += delta
            if stats['out_size'][core] >= 5000:
                stats['large_out_time_with_skbs'] += delta

    def output(self):
        global traces
        print('\n---------------')
        print('Analyzer: copy')
        print('---------------')
        print('Performance of data copying between user space and kernel:')
        print('Node:     Name of node')
        print('#Short:   Number of short blocks copied (<= 1000 B)')
        print('Min:      Minimum copy time for a short block (usec)')
        print('P50:      Median copy time for short blocks (usec)')
        print('P90:      90th percentile copy time for short blocks (usec)')
        print('P99:      99th percentile copy time for short blocks (usec)')
        print('Max:      Maximum copy time for a short block (usec)')
        print('Avg:      Average copy time for short blocks (usec)')
        print('#Long:    Number of long blocks copied (>= 5000 B)')
        print('TputC:    Average per-core throughput for copying long blocks')
        print('          when actively copying (Gbps)')
        print('TputN:    Average long block copy throughput for the node (Gbps)')
        print('Cores:    Average number of cores copying long blocks')
        print('')
        print('Copying from user space to kernel:')
        print('Node       #Short   Min   P50   P90   P99   Max   Avg  #Long  '
                'TputC TputN Cores')
        print('--------------------------------------------------------------'
                '-----------------')
        for node in get_sorted_nodes():
            trace = traces[node]
            stats = trace['copy']

            num_short = len(stats['small_in_times'])
            if num_short == 0:
                min = p50 = p90 = p99 = max = avg = 0.0
            else:
                sorted_data = sorted(stats['small_in_times'])
                min = sorted_data[0]
                p50 = sorted_data[50*num_short//100]
                p90 = sorted_data[90*num_short//100]
                p99 = sorted_data[99*num_short//100]
                max = sorted_data[-1]
                avg = sum(sorted_data)/num_short

            num_long = stats['large_in_count']
            if stats['large_in_time'] == 0:
                core_tput = '   N/A'
                node_tput = '   N/A'
                cores = 0
            else:
                core_tput = '%6.1f' % (8e-03*stats['large_in_data']
                            /stats['large_in_time'])
                node_tput = '%6.1f' % (8e-03*stats['large_in_data']
                            /trace['elapsed_time'])
                cores = stats['total_in_time']/trace['elapsed_time']
            print('%-10s %6d%6.1f%6.1f%6.1f%6.1f%6.1f%6.1f  %5d %s%s %5.2f' %
                    (node, num_short, min, p50, p90, p99, max, avg, num_long,
                    core_tput, node_tput, cores))

        print('\nCopying from kernel space to user:')
        print('Node       #Short   Min   P50   P90   P99   Max   Avg  #Long  '
                'TputC TputN Cores')
        print('--------------------------------------------------------------'
                '-----------------')
        for node in get_sorted_nodes():
            trace = traces[node]
            stats = trace['copy']

            num_short = len(stats['small_out_times'])
            if num_short == 0:
                min = p50 = p90 = p99 = max = avg = 0.0
            else:
                sorted_data = sorted(stats['small_out_times'])
                min = sorted_data[0]
                p50 = sorted_data[50*num_short//100]
                p90 = sorted_data[90*num_short//100]
                p99 = sorted_data[99*num_short//100]
                max = sorted_data[-1]
                avg = sum(sorted_data)/num_short

            num_long = stats['large_out_count']
            if stats['large_out_time'] == 0:
                core_tput = '   N/A'
                node_tput = '   N/A'
                cores = 0
            else:
                core_tput = '%6.1f' % (8e-03*stats['large_out_data']
                            /stats['large_out_time'])
                node_tput = '%6.1f' % (8e-03*stats['large_out_data']
                            /trace['elapsed_time'])
                cores = stats['total_out_time']/trace['elapsed_time']
            print('%-10s %6d%6.1f%6.1f%6.1f%6.1f%6.1f%6.1f  %5d %s%s %5.2f' %
                    (node, num_short, min, p50, p90, p99, max, avg, num_long,
                    core_tput, node_tput, cores))

        print('\nImpact of freeing socket buffers while copying to user:')
        print('Node:     Name of node')
        print('#Freed:   Number of skbs freed')
        print('Time:     Average time to free an skb (usec)')
        print('Tput:     Effective kernel->user throughput per core (TputC) including')
        print('          skb freeing (Gbps)')
        print('')
        print('Node       #Freed   Time   Tput')
        print('-------------------------------')
        for node in get_sorted_nodes():
            trace = traces[node]
            stats = trace['copy']
            stats['skbs_freed']
            if stats['skbs_freed'] == 0:
                free_time = 0
                tput = 0
            else:
                free_time = stats['skb_free_time']/stats['skbs_freed']
                if stats['large_out_time_with_skbs']:
                    tput = '%6.1f' % (8e-03*stats['large_out_data']
                        /stats['large_out_time_with_skbs'])
                else:
                    tput = '   N/A'
            print('%-10s %6d %6.2f %s' % (node, stats['skbs_freed'],
                    free_time, tput))

#------------------------------------------------
# Analyzer: delay
#------------------------------------------------
class AnalyzeDelay:
    """
    Prints information about various delays, including delays associated
    with packets at various stages and delays in waking up threads. With
    --verbose, prints information about specific instances of long delays.
    """

    def __init__(self, dispatcher):
        dispatcher.interest('AnalyzePackets')
        dispatcher.interest('AnalyzeRpcs')

        # <delay, end time> for gro->softirq handoffs
        self.softirq_wakeups = []

        # RPC id -> time when homa_rpc_handoff handed off that RPC to a thread.
        self.rpc_handoffs = {}

        # RPC id -> time when homa_rpc_handoff queued the RPC.
        self.rpc_queued = {}

        # <delay, end time, node> for softirq->app handoffs (thread was polling)
        self.app_poll_wakeups = []

        # <delay, end time, node> for softirq->app handoffs (thread was sleeping)
        self.app_sleep_wakeups = []

        # <delay, end time, node> for softirq->app handoffs when RPC was queued
        self.app_queue_wakeups = []

        # An entry exists for RPC id if a handoff occurred while a
        # thread was polling
        self.poll_success = {}

    def init_trace(self, trace):
        # Target core id -> time when gro chose that core
        self.gro_handoffs = {}

    def tt_gro_handoff(self, trace, time, core, softirq_core):
        self.gro_handoffs[softirq_core] = time

    def tt_softirq_start(self, trace, time, core):
        if not core in self.gro_handoffs:
            return
        self.softirq_wakeups.append([time - self.gro_handoffs[core], time,
                trace['node']])
        del self.gro_handoffs[core]

    def tt_rpc_handoff(self, trace, time, core, id):
        if id in self.rpc_handoffs:
            print('Multiple RPC handoffs for id %s on %s: %9.3f and %9.3f' %
                    (id, trace['node'], self.rpc_handoffs[id], time),
                    file=sys.stderr)
        self.rpc_handoffs[id] = time

    def tt_poll_success(self, trace, time, core, id):
        self.poll_success[id] = time

    def tt_rpc_queued(self, trace, time, core, id):
        self.rpc_queued[id] = time

    def tt_wait_found_rpc(self, trace, time, core, id):
        if id in self.rpc_handoffs:
            delay = time - self.rpc_handoffs[id]
            if id in self.poll_success:
                self.app_poll_wakeups.append([delay, time, trace['node']])
                del self.poll_success[id]
            else:
                self.app_sleep_wakeups.append([delay, time, trace['node']])
            del self.rpc_handoffs[id]
        elif id in self.rpc_queued:
            self.app_queue_wakeups.append([time - self.rpc_queued[id], time,
                    trace['node']])
            del self.rpc_queued[id]

    def print_pkt_delays(self):
        """
        Prints basic packet delay info, returns verbose output for optional
        printing by caller.
        """
        global packets, grants, options

        # Each of the following lists holds <delay, pkt_id, time> tuples for
        # a particular stage of a packet's lifetime, where delay is the
        # delay through that stage, pkt_id identifies the packet (rpc_id:offset)
        # and time is when the delay ended.
        short_to_nic = []
        short_to_gro = []
        short_to_softirq = []
        short_total = []

        long_to_nic = []
        long_to_gro = []
        long_to_softirq = []
        long_total = []

        grant_to_nic = []
        grant_to_gro = []
        grant_to_softirq = []
        grant_total = []

        # Collect statistics about delays within individual packets.
        mtu = get_packet_size()
        for p, pkt in packets.items():
            if ('msg_length') in pkt and (pkt['msg_length'] <= mtu):
                if ('xmit' in pkt) and ('nic' in pkt):
                    short_to_nic.append(
                            [pkt['nic'] - pkt['xmit'], p, pkt['nic']])
                if ('nic' in pkt) and ('gro' in pkt):
                    short_to_gro.append(
                            [pkt['gro'] - pkt['nic'], p, pkt['gro']])
                if ('gro' in pkt) and ('softirq' in pkt):
                    short_to_softirq.append(
                            [pkt['softirq'] - pkt['gro'], p, pkt['softirq']])
                if ('softirq' in pkt) and ('xmit' in pkt):
                    short_total.append(
                            [pkt['softirq'] - pkt['xmit'], p, pkt['softirq']])
            else:
                if ('xmit' in pkt) and ('nic' in pkt):
                    long_to_nic.append(
                            [pkt['nic'] - pkt['xmit'], p, pkt['nic']])
                if ('nic' in pkt) and ('gro' in pkt):
                    long_to_gro.append(
                            [pkt['gro'] - pkt['nic'], p, pkt['gro']])
                if ('gro' in pkt) and ('softirq' in pkt):
                    long_to_softirq.append(
                            [pkt['softirq'] - pkt['gro'], p, pkt['softirq']])
                if ('softirq' in pkt) and ('xmit' in pkt):
                    long_total.append(
                            [pkt['softirq'] - pkt['xmit'], p, pkt['softirq']])

        for p, pkt in grants.items():
            if ('xmit' in pkt) and ('nic' in pkt):
                grant_to_nic.append(
                        [pkt['nic'] - pkt['xmit'], p, pkt['nic']])
            if ('nic' in pkt) and ('gro' in pkt):
                grant_to_gro.append(
                        [pkt['gro'] - pkt['nic'], p, pkt['gro']])
            if ('gro' in pkt) and ('softirq' in pkt):
                grant_to_softirq.append(
                        [pkt['softirq'] - pkt['gro'], p, pkt['softirq']])
            if ('softirq' in pkt) and ('xmit' in pkt):
                grant_total.append(
                        [pkt['softirq'] - pkt['xmit'], p, pkt['softirq']])

        print('\n----------------')
        print('Analyzer: delay')
        print('----------------')
        print('Delays in the transmission and processing of data and grant packets')
        print('(all times in usecs):')
        print('Xmit:     Time from ip*xmit call until driver queued packet for NIC')
        print('          (for grants, includes time in homa_send_grants and ')
        print('          homa_xmit_control)')
        print('Net:      Time from when NIC received packet until GRO started processing')
        print('SoftIRQ:  Time from GRO until SoftIRQ started processing')
        print('Total:    Total time from ip*xmit call until SoftIRQ processing')

        def print_pcts(data, label):
            data.sort(key=lambda t : t[0])
            if not data:
                print('%-10s      0' % (label))
            else:
                print('%-10s %6d %6.1f %6.1f %6.1f %6.1f %6.1f %6.1f %6.1f' % (label,
                    len(data), data[0][0], data[10*len(data)//100][0],
                    data[50*len(data)//100][0], data[90*len(data)//100][0],
                    data[99*len(data)//100][0], data[len(data)-1][0],
                    list_avg(data, 0)))
        print('\nPhase        Count   Min    P10    P50    P90    P99    Max    Avg')
        print('-------------------------------------------------------------------------')
        print('Data packets from single-packet messages:')
        print_pcts(short_to_nic, 'Xmit')
        print_pcts(short_to_gro, 'Net')
        print_pcts(short_to_softirq, 'SoftIRQ')
        print_pcts(short_total, 'Total')

        print('\nData packets from multi-packet messages:')
        print_pcts(long_to_nic, 'Xmit')
        print_pcts(long_to_gro, 'Net')
        print_pcts(long_to_softirq, 'SoftIRQ')
        print_pcts(long_total, 'Total')

        print('\nGrants:')
        print_pcts(grant_to_nic, 'Xmit')
        print_pcts(grant_to_gro, 'Net')
        print_pcts(grant_to_softirq, 'SoftIRQ')
        print_pcts(grant_total, 'Total')

        # Handle --verbose for packet-related delays.
        def print_worst(data, label):
            global rpcs

            # The goal is to print about 20 packets covering the 98th-100th
            # percentiles; we'll print one out of every "interval" packets.
            result = ''
            num_pkts = len(data)
            interval = num_pkts//(50*20)
            if interval == 0:
                interval = 1
            for i in range(num_pkts-1, num_pkts - 20*interval, -interval):
                if i < 0:
                    break
                pkt = data[i]
                recv_id = int(pkt[1].split(':')[0]) ^ 1
                dest = '      ????   ??'
                if recv_id in rpcs:
                    rpc = rpcs[recv_id]
                    if 'gro_core' in rpc:
                        dest = '%10s %4d' % (rpc['node'], rpc['gro_core'])
                    else:
                        dest = '%10s   ??' % (rpc['node'])
                result += '%-8s %6.1f  %20s %s %9.3f %5.1f\n' % (label, pkt[0],
                        pkt[1], dest, pkt[2], i*100/num_pkts)
            return result

        verbose = 'Sampled packets with outlier delays:\n'
        verbose += 'Phase:    Phase of delay: Xmit, Net, or SoftIRQ\n'
        verbose += 'Delay:    Delay for this phase\n'
        verbose += 'Packet:   Sender\'s identifier for packet: rpc_id:offset\n'
        verbose += 'Node:     Node where packet was received\n'
        verbose += 'Core:     Core where homa_gro_receive processed packet\n'
        verbose += 'EndTime:  Time when phase completed\n'
        verbose += 'Pctl:     Percentile of this packet\'s delay\n\n'
        verbose += ('Phase   Delay (us)             Packet   RecvNode Core   '
                'EndTime  Pctl\n')
        verbose += ('--------------------------------------------------------'
                '-------------\n')

        verbose += 'Data packets from single-packet messages:\n'
        verbose += print_worst(short_to_nic, 'Xmit')
        verbose += print_worst(short_to_gro, 'Net')
        verbose += print_worst(short_to_softirq, 'SoftIRQ')
        verbose += print_worst(short_total, 'Total')

        verbose += '\nData packets from multi-packet messages:\n'
        verbose += print_worst(long_to_nic, 'Xmit')
        verbose += print_worst(long_to_gro, 'Net')
        verbose += print_worst(long_to_softirq, 'SoftIRQ')
        verbose += print_worst(long_total, 'Total')

        verbose += '\nGrants:\n'
        verbose += print_worst(grant_to_nic, 'Xmit')
        verbose += print_worst(grant_to_gro, 'Net')
        verbose += print_worst(grant_to_softirq, 'SoftIRQ')
        verbose += print_worst(grant_total, 'Total')

        # Redo the statistics gathering, but only include the worst packets
        # from each category.
        min_short = short_total[98*len(short_total)//100][0]
        max_short = short_total[99*len(short_total)//100][0]
        min_long = long_total[98*len(long_total)//100][0]
        max_long = long_total[99*len(long_total)//100][0]
        min_grant = grant_total[98*len(grant_total)//100][0]
        max_grant = grant_total[99*len(grant_total)//100][0]

        short_to_nic = []
        short_to_gro = []
        short_to_softirq = []

        long_to_nic = []
        long_to_gro = []
        long_to_softirq = []

        grant_to_nic = []
        grant_to_gro = []
        grant_to_softirq = []

        for p, pkt in packets.items():
            if (not 'softirq' in pkt) or (not 'xmit' in pkt):
                continue
            total = pkt['softirq'] - pkt['xmit']
            if ('msg_length' in pkt) and (pkt['msg_length'] <= mtu):
                if (total < min_short) or (total > max_short):
                    continue;
                if ('xmit' in pkt) and ('nic' in pkt):
                    short_to_nic.append(
                            [pkt['nic'] - pkt['xmit'], p, pkt['nic']])
                if ('nic' in pkt) and ('gro' in pkt):
                    short_to_gro.append(
                            [pkt['gro'] - pkt['nic'], p, pkt['gro']])
                if ('gro' in pkt) and ('softirq' in pkt):
                    short_to_softirq.append(
                            [pkt['softirq'] - pkt['gro'], p, pkt['softirq']])
            else:
                if (total < min_long) or (total > max_long):
                    continue;
                if ('xmit' in pkt) and ('nic' in pkt):
                    long_to_nic.append(
                            [pkt['nic'] - pkt['xmit'], p, pkt['nic']])
                if ('nic' in pkt) and ('gro' in pkt):
                    long_to_gro.append(
                            [pkt['gro'] - pkt['nic'], p, pkt['gro']])
                if ('gro' in pkt) and ('softirq' in pkt):
                    long_to_softirq.append(
                            [pkt['softirq'] - pkt['gro'], p, pkt['softirq']])

        for pkt in grants.values():
            if (not 'softirq' in pkt) or (not 'xmit' in pkt):
                continue
            total = pkt['softirq'] - pkt['xmit']
            if (total < min_grant) or (total > max_grant):
                continue;
            if ('xmit' in pkt) and ('nic' in pkt):
                grant_to_nic.append(
                        [pkt['nic'] - pkt['xmit'], p, pkt['nic']])
            if ('nic' in pkt) and ('gro' in pkt):
                grant_to_gro.append(
                        [pkt['gro'] - pkt['nic'], p, pkt['gro']])
            if ('gro' in pkt) and ('softirq' in pkt):
                grant_to_softirq.append(
                        [pkt['softirq'] - pkt['gro'], p, pkt['softirq']])

        def get_slow_summary(data):
            data.sort(key=lambda t : t[0])
            return '%6.1f %6.1f' % (data[50*len(data)//100][0],
                    list_avg(data, 0))

        print('\nPhase breakdown for P98-P99 packets:')
        print('                          Xmit          Net         SoftIRQ')
        print('               Pkts    P50    Avg    P50    Avg    P50    Avg')
        print('-------------------------------------------------------------')
        print('Single-packet %5d %s %s %s' % (len(short_to_nic),
                get_slow_summary(short_to_nic),
                get_slow_summary(short_to_gro),
                get_slow_summary(short_to_softirq)))
        print('Multi-packet  %5d %s %s %s' % (len(long_to_nic),
                get_slow_summary(long_to_nic),
                get_slow_summary(long_to_gro),
                get_slow_summary(long_to_softirq)))
        print('Grants        %5d %s %s %s' % (len(grant_to_nic),
                get_slow_summary(grant_to_nic),
                get_slow_summary(grant_to_gro),
                get_slow_summary(grant_to_softirq)))
        return verbose

    def print_wakeup_delays(self):
        """
        Prints basic info about thread wakeup delays, returns verbose output
        for optional printing by caller.
        """
        global options

        soft = self.softirq_wakeups
        soft.sort()
        app_poll = self.app_poll_wakeups
        app_poll.sort()
        app_sleep = self.app_sleep_wakeups
        app_sleep.sort()
        app_queue = self.app_queue_wakeups
        app_queue.sort()
        print('\nDelays in handing off from one core to another:')
        print('                            Count   Min    P10    P50    P90    P99    '
                'Max    Avg')
        print('------------------------------------------------------------'
                '---------------------')

        def print_percentiles(label, data):
            num = len(data)
            if num == 0:
                print('%-26s %6d' % (label, 0))
            else:
                print('%-26s %6d %5.1f %6.1f %6.1f %6.1f %6.1f %6.1f %6.1f'
                    % (label, num, data[0][0], data[10*num//100][0],
                    data[50*num//100][0], data[90*num//100][0],
                    data[99*num//100][0], data[num-1][0], list_avg(data, 0)))
        print_percentiles('GRO to SoftIRQ:', soft)
        print_percentiles('SoftIRQ to polling app:', app_poll)
        print_percentiles('SoftIRQ to sleeping app:', app_sleep)
        print_percentiles('SoftIRQ to app via queue:', app_queue)

        verbose = 'Worst-case handoff delays:\n'
        verbose += 'Type                   Delay (us)    End Time       Node  Pctl\n'
        verbose += '--------------------------------------------------------------\n'

        def print_worst(label, data):
            # The goal is to print about 10 records covering the 98th-100th
            # percentiles; we'll print one out of every "interval" packets.
            num = len(data)
            interval = num//(50*10)
            if interval == 0:
                interval = 1
            result = ''
            for i in range(num-1, num - 10*interval, -interval):
                if i < 0:
                    break
                time, delay, node = data[i]
                result += '%-26s %6.1f   %9.3f %10s %5.1f\n' % (
                        label, time, delay, node, 100*i/(num-1))
            return result

        verbose += print_worst('GRO to SoftIRQ', soft)
        verbose += print_worst('SoftIRQ to polling app', app_poll)
        verbose += print_worst('SoftIRQ to sleeping app', app_sleep)
        verbose += print_worst('SoftIRQ to app via queue', app_queue)
        return verbose

    def output(self):
        global options

        delay_verbose = self.print_pkt_delays()
        wakeup_verbose = self.print_wakeup_delays()
        if options.verbose:
            print('')
            print(delay_verbose, end='')
            print('')
            print(wakeup_verbose, end='')

#------------------------------------------------
# Analyzer: incoming
#------------------------------------------------
class AnalyzeIncoming:
    """
    Generates detailed timelines of rates of incoming data and packets for
    each core of each node. Use the --data option to specify a directory for
    data files.
    """
    def __init__(self, dispatcher):
        dispatcher.interest('AnalyzeRpcs')
        dispatcher.interest('AnalyzePackets')
        return

    def write_node_data(self, node, pkts):
        """
        Write a data file describing incoming traffic to a given node.

        node:   Name of the node
        pkts:   List of <time, length, core, priority> tuples describing
                packets on that node.
        """
        global options

        interval = 20

        # Figure out which cores received packets on this node.
        cores = {}
        for pkt in pkts:
            cores[pkt[2]] = 1
        core_ids = sorted(cores.keys())

        pkts.sort(key=lambda t : t[0])
        start = pkts[0][0]
        interval_end = (start//interval) * interval
        if interval_end > start:
            interval_end -= interval

        core_bytes = {}
        core_pkts = {}
        min_prio = 100

        f = open('%s/incoming_%s.dat' % (options.data_dir, node), 'w')
        f.write('# Node: %s\n' % (node))
        f.write('# Generated at %s.\n' %
                (time.strftime('%I:%M %p on %m/%d/%Y')))
        f.write('# Rate of arrival of incoming data and packets, broken down\n')
        f.write('# by core and time interval:\n')
        f.write('# Time:    End of the time interval\n')
        f.write('# GbpsN:   Data arrival rate on core N for the '
                'interval (Gbps)\n')
        f.write('# PktsN:   Total packets (grants and data) that arrived on '
                'core N in the interval\n')
        f.write('# Gbps:    Total arrival rate of data across all '
                'cores (Gbps)\n')
        f.write('# Pkts:    Total packet arrivals (grants and data) across all '
                'cores\n')
        f.write('# MinP:    Lowest priority level for any incoming packet\n')
        f.write('\nInterval')
        for c in core_ids:
            f.write(' Gbps%d Pkts%d' % (c, c))
        f.write('   Gbps   Pkts  MinP\n')

        for t, length, core, priority in pkts:
            if t >= interval_end:
                if interval_end > start:
                    f.write('%8.1f' % (interval_end))
                    total_gbps = 0
                    total_pkts = 0
                    for c in core_ids:
                        gbps = 8*core_bytes[c]/(interval*1e03)
                        f.write(' %5.1f %5d' % (gbps, core_pkts[c]))
                        total_gbps += gbps
                        total_pkts += core_pkts[c]
                    f.write('  %5.1f  %5d   %3d\n' % (total_gbps,
                            total_pkts, min_prio))
                for c in core_ids:
                    core_bytes[c] = 0
                    core_pkts[c] = 0
                    min_prio = 7
                interval_end += 20
            core_pkts[core] += 1
            core_bytes[core] += length
            if priority < min_prio:
                min_prio = priority
        f.close()

    def output(self):
        global packets, grants, options, rpcs

        # Maps from node names to a list of packets for that core. Each packet
        # is described by a tuple <time, size, core> giving the arrival time
        # and size of the packet (size 0 means the packet was a grant) and the
        # core where it was received.
        nodes = defaultdict(list)

        skipped = 0
        total_pkts = 0
        mtu = get_packet_size()
        for pkt in packets.values():
            if not 'gro' in pkt:
                continue
            if not 'length' in pkt:
                if 'msg_length' in pkt:
                    length = pkt['msg_length'] - pkt['offset']
                    if length > mtu:
                        length = mtu
                else:
                    skipped += 1
                    continue
            else:
                length = pkt['length']
            if not 'id' in pkt:
                print('Packet: %s' % (pkt))
            rpc = rpcs[pkt['id']^1]
            nodes[rpc['node']].append([pkt['gro'], length, rpc['gro_core'],
                    pkt['priority']])
            total_pkts += 1
        if skipped > 0:
            print('Incoming analyzer skipped %d packets out of %d (%.2f%%): '
                    'couldn\'t compute length' % (skipped, total_pkts,
                    100.0*(skipped//total_pkts)), file=sys.stderr)

        for grant in grants.values():
            if not 'gro' in grant:
                continue
            rpc = rpcs[grant['id']^1]
            nodes[rpc['node']].append([grant['gro'], 0, rpc['gro_core'], 7])

        print('\n-------------------')
        print('Analyzer: incoming')
        print('-------------------')
        if options.data_dir == None:
            print('No --data option specified, data can\'t be written.')

        for node, cores in nodes.items():
              self.write_node_data(node, cores)

#------------------------------------------------
# Analyzer: net
#------------------------------------------------
class AnalyzeNet:
    """
    Prints information about delays in the network including NICs, network
    delay and congestion, and receiver GRO overload. With --data, generates
    data files describing backlog and delay over time on a core-by-core
    basis.
    """

    def __init__(self, dispatcher):
        dispatcher.interest('AnalyzeRpcs')
        return

    def collect_events(self):
        """
        Matches up packet sends and receives for all RPCs to return a
        dictionary that maps from the name for a receiving node to a
        list of events for that receiver. Each event is a
        <time, event, length, core, delay> list:
        time:      Time when the event occurred
        event:     What happened: "xmit" for packet transmission or "recv"
                   for packet reception (by GRO)
        length:    Number of message bytes in packet
        core:      Core where packet was processed by GRO
        delay:     End-to-end delay for packet; zero for xmit events
        """

        global rpcs, traces, options
        receivers = defaultdict(list)

        # Process RPCs in sender-receiver pairs to collect data
        max_data = get_packet_size()
        for xmit_id, xmit_rpc in rpcs.items():
            recv_id = xmit_id ^ 1
            if not recv_id in rpcs:
                continue
            recv_rpc = rpcs[recv_id]
            receiver = receivers[recv_rpc['node']]
            if not 'gro_core' in recv_rpc:
                continue
            core = recv_rpc['gro_core']

            xmit_pkts = sorted(xmit_rpc['send_data'], key=lambda t : t[1])
            if xmit_pkts:
                xmit_end = xmit_pkts[-1][1] + xmit_pkts[-1][2]
            elif 'out_length' in xmit_rpc:
                xmit_end = xmit_rpc['out_length']
            elif 'in_length' in recv_rpc:
                xmit_end = recv_rpc['in_length']
            else:
                # Not enough info to process this RPC
                continue

            recv_pkts = sorted(recv_rpc['gro_data'],
                    key=lambda tuple : tuple[1])
            xmit_ix = 0
            if xmit_pkts:
                xmit_time, xmit_offset, xmit_length = xmit_pkts[0]
            else:
                xmit_offset = 100000000
                xmit_length = 0
            xmit_bytes = 0
            for i in range(0, len(recv_pkts)):
                recv_time, recv_offset, prio = recv_pkts[i]
                if i == (len(recv_pkts) - 1):
                    length = xmit_end - recv_offset
                else:
                    length = recv_pkts[i+1][1] - recv_offset
                if length > max_data:
                    length = max_data

                while recv_offset >= (xmit_offset + xmit_length):
                    if xmit_bytes:
                        receiver.append([xmit_time, "xmit", xmit_bytes,
                                core, 0.0])
                    xmit_ix += 1
                    if xmit_ix >= len(xmit_pkts):
                        break
                    xmit_time, xmit_offset, xmit_length = xmit_pkts[xmit_ix]
                    xmit_bytes = 0
                if recv_offset < xmit_offset:
                    # No xmit record; skip
                    continue
                if xmit_ix >= len(xmit_pkts):
                    # Receiver trace extends beyond sender trace; ignore extras
                    break
                if (recv_offset in recv_rpc['resends']) or (recv_offset
                        in xmit_rpc['retransmits']):
                    # Skip retransmitted packets (too hard to account for).
                    # BTW, need both of the above checks to handle corner cases.
                    continue
                receiver.append([recv_time, "recv", length, core,
                        recv_time - xmit_time])
                if recv_time < xmit_time and not options.negative_ok:
                    print('%9.3f Negative delay, xmit_time %9.3f, '
                            'xmit_node %s recv_node %s recv_offset %d '
                            'xmit_offset %d xmit_length %d'
                            % (recv_time, xmit_time, xmit_rpc['node'],
                            recv_rpc['node'], recv_offset, xmit_offset,
                            xmit_length), file=sys.stderr)
                xmit_bytes += length
            if xmit_bytes:
                receiver.append([xmit_time, "xmit", xmit_bytes, core, 0.0])

        for name, receiver in receivers.items():
            receiver.sort(key=lambda tuple : tuple[0])
        return receivers

    def summarize_events(self, events):
        """
        Given a dictionary returned by collect_events, return information
        about each GRO core as a dictionary indexed by node names. Each
        element is a dictionary indexed by cores, which in turn is a
        dictionary with the following values:
        num_packets:      Total number of packets received by the core
        avg_delay:        Average end-to-end delay for packets
        max_delay:        Worst-case end-to-end delay
        max_delay_time:   Time when max_delay occurred
        avg_backlog:      Average number of bytes of data in transit
        max_backlog:      Worst-case number of bytes of data in transit
        max_backlog_time: Time when max_backlog occurred
        """
        global options

        stats = defaultdict(lambda: defaultdict(lambda: {
            'num_packets': 0,
            'avg_delay': 0,
            'max_delay': 0,
            'avg_backlog': 0,
            'max_backlog': 0,
            'cur_backlog': 0,
            'prev_time': 0}))

        for name, node_events in events.items():
            node = stats[name]
            for event in node_events:
                time, type, length, core, delay = event
                core_data = node[core]
                core_data['avg_backlog'] += (core_data['cur_backlog'] *
                        (time - core_data['prev_time']))
                if type == "recv":
                    core_data['num_packets'] += 1
                    core_data['avg_delay'] += delay
                    if delay > core_data['max_delay']:
                        core_data['max_delay'] = delay
                        core_data['max_delay_time'] = time
                    if core_data['cur_backlog'] == core_data['max_backlog']:
                        core_data['max_backlog_time'] = time
                    core_data['cur_backlog'] -= length
                    if (delay < 0) and not options.negative_ok:
                        print('Negative delay: %s' % (event))
                else:
                    core_data['cur_backlog'] += length
                    if core_data['cur_backlog'] > core_data['max_backlog']:
                            core_data['max_backlog'] = core_data['cur_backlog']
                core_data['prev_time'] = time
            for core_data in node.values():
                core_data['avg_delay'] /= core_data['num_packets']
                core_data['avg_backlog'] /= traces[name]['elapsed_time']
        return stats

    def generate_delay_data(self, events, dir):
        """
        Creates data files for the delay information in events.

        events:    Dictionary of events returned by collect_events.
        dir:       Directory in which to write data files (one file per node)
        """

        for node, node_events in events.items():
            # Maps from core number to a list of <time, delay> tuples
            # for that core. Each tuple indicates when a packet was processed
            # by GRO on that core, and the packet's end-to-end delay. The
            # list for each core is sorted in increasing time order.
            core_data = defaultdict(list)
            for event in node_events:
                event_time, type, length, core, delay = event
                if type != "recv":
                    continue
                core_data[core].append([event_time, delay])

            cores = sorted(core_data.keys())
            max_len = 0
            for core in cores:
                length = len(core_data[core])
                if length > max_len:
                    max_len = length

            f = open('%s/net_delay_%s.dat' % (dir, node), 'w')
            f.write('# Node: %s\n' % (node))
            f.write('# Generated at %s.\n' %
                    (time.strftime('%I:%M %p on %m/%d/%Y')))
            doc = ('# Packet delay information for a single node, broken '
                'out by the core '
                'where the packet is processed by GRO. For each active core '
                'there are two columns, TimeN and '
                'DelayN. Each line corresponds to a packet that was processed '
                'by homa_gro_receive on core N at the given time with '
                'the given delay '
                '(measured end to end from ip_*xmit call to homa_gro_receive '
                'call)')
            f.write('\n# '.join(textwrap.wrap(doc)))
            f.write('\n')
            for core in cores:
                t = 'Time%d' % core
                d = 'Delay%d' % core
                f.write('%8s%8s' % (t, d))
            f.write('\n')
            for i in range(0, max_len):
                for core in cores:
                    pkts = core_data[core]
                    if i >= len(pkts):
                        f.write('' * 15)
                    else:
                        f.write('%8.1f %7.1f' % (pkts[i][0], pkts[i][1]))
                f.write('\n')
            f.close()

    def generate_backlog_data(self, events, dir):
        """
        Creates data files for per-core backlog information

        events:    Dictionary of events returned by collect_events.
        dir:       Directory in which to write data files (one file per node)
        """
        global options

        for node, node_events in events.items():
            # Maps from core number to a list; entry i in the list is
            # the backlog on that core at the end of interval i.
            backlogs = defaultdict(list)

            interval_length = 20.0
            start = (node_events[0][0]//interval_length) * interval_length
            interval_end = start + interval_length
            cur_interval = 0

            for event in node_events:
                event_time, type, length, core, delay = event
                while event_time >= interval_end:
                    interval_end += interval_length
                    cur_interval += 1
                    for core_intervals in backlogs.values():
                        core_intervals.append(core_intervals[-1])

                if not core in backlogs:
                    backlogs[core] = [0] * (cur_interval+1)
                if type == "recv":
                    backlogs[core][-1] -= length
                else:
                    backlogs[core][-1] += length

            cores = sorted(backlogs.keys())

            f = open('%s/net_backlog_%s.dat' % (dir, node), "w")
            f.write('# Node: %s\n' % (node))
            f.write('# Generated at %s.\n' %
                    (time.strftime('%I:%M %p on %m/%d/%Y')))
            doc = ('# Time-series history of backlog for each active '
                'GRO core on this node.  Column "BackC" shows the backlog '
                'on core C at the given time (in usec). Backlog '
                'is the KB of data destined '
                'for core C that have been passed to ip*_xmit at the sender '
                'but not yet seen by homa_gro_receive on the receiver.')
            f.write('\n# '.join(textwrap.wrap(doc)))
            f.write('\n    Time')
            for core in cores:
                f.write(' %7s' % ('Back%d' % core))
            f.write('\n')
            for i in range(0, cur_interval):
                f.write('%8.1f' % (start + (i+1)*interval_length))
                for core in cores:
                    f.write(' %7.1f' % (backlogs[core][i] / 1000))
                f.write('\n')
            f.close()

    def output(self):
        global rpcs, traces, options

        events = self.collect_events()

        if options.data_dir != None:
            self.generate_delay_data(events, options.data_dir)
            self.generate_backlog_data(events, options.data_dir)

        stats = self.summarize_events(events)

        print('\n--------------')
        print('Analyzer: net')
        print('--------------')
        print('Network delay (including sending NIC, network, receiving NIC, and GRO')
        print('backup, for packets with GRO processing on a particular core.')
        print('Pkts:      Total data packets processed by Core on Node')
        print('AvgDelay:  Average end-to-end delay from ip_*xmit invocation to '
                'GRO (usec)')
        print('MaxDelay:  Maximum end-to-end delay, and the time when the max packet was')
        print('           processed by GRO (usec)')
        print('AvgBack:   Average backup for Core on Node (total data bytes that were')
        print('           passed to ip_*xmit but not yet seen by GRO) (KB)')
        print('MaxBack:   Maximum backup for Core (KB) and the time when GRO processed')
        print('           a packet from that backup')
        print('')
        print('Node       Core   Pkts  AvgDelay     MaxDelay (Time)    '
                'AvgBack     MaxBack (Time)')
        print('--------------------------------------------------------'
                '----------------------------', end='')
        for name in get_sorted_nodes():
            if not name in stats:
                continue
            node = stats[name]
            print('')
            for core in sorted(node.keys()):
                core_data = node[core]
                print('%-10s %4d %6d %9.1f %9.1f (%9.3f) %8.1f %8.1f (%9.3f)' % (
                        name, core, core_data['num_packets'],
                        core_data['avg_delay'], core_data['max_delay'],
                        core_data['max_delay_time'],
                        core_data['avg_backlog'] * 1e-3,
                        core_data['max_backlog'] * 1e-3,
                        core_data['max_backlog_time']))

#------------------------------------------------
# Analyzer: nicbufs
#------------------------------------------------
class AnalyzeNicbufs:
    """
    Analyzes lifetimes of skbs for incoming packets to compute total buffer
    usage for each channel and underflows of NIC buffer caches (based on
    caching mechanism of Mellanox mlx5 driver).
    """

    def __init__(self, dispatcher):
        dispatcher.interest('AnalyzePackets')
        dispatcher.interest('AnalyzeRpcs')

    def output(self):
        global packets, rpcs

        # List of <time, type, id, core, length> records, where type is
        # "alloc" or "free", id is a packet id, core is the core where
        # homa_gro_receive processed the packet (in the form "node.core"),
        # and length is the number of bytes consumed by the packet.
        events = []

        # Maps from core id (node.core) to the total number of bytes
        # received so far by homa_gro_receive on that core.
        core_bytes = defaultdict(lambda : 0)

        # Maps from packet id to a <gro_time, core_bytes> tuple, where
        # gro_time is the time when the packet was processed by homa_gro_receive
        # and core_bytes is the value of core_bytes just before the packet
        # was allocated.
        pkt_allocs = {}

        # Maps from core id to <time, active_bytes, pkid, gro_time>, where
        # active_bytes is the largest number of active skb bytes seen for that
        # core, time is the time when some of those bytes were finally freed,
        # pid is the id of the packet freed at time, and gro_time is the time
        # when that packet was processed by homa_gro_receive.
        core_max = defaultdict(lambda : [0, 0, '', 0])

        # Scan all packets to build the events list. Note: change packet
        # ids to refer to those on the receiver, not sender.
        for pkt in packets.values():
            if (not 'gro' in pkt) or (not 'length' in pkt):
                continue
            rpc_id = pkt['id'] ^ 1
            pkid = '%d:%d' % (rpc_id, pkt['offset'])
            rpc = rpcs[rpc_id]
            core = '%s.%d' % (rpc['node'], rpc['gro_core'])
            events.append([pkt['gro'], 'alloc', pkid, core, pkt['length']])
            if 'free' in pkt:
                events.append([pkt['free'], 'free', pkid, core, pkt['length']])

        # Process the events in time order
        events.sort(key=lambda t : t[0])
        for time, type, pkid, core, length in events:
            if type == 'alloc':
                pkt_allocs[pkid] = [time, core_bytes[core]]
                core_bytes[core] += length
            elif type == 'free':
                active_bytes = core_bytes[core] - pkt_allocs[pkid][1]
                if active_bytes > core_max[core][1]:
                    core_max[core] = [time, active_bytes, pkid,
                            pkt_allocs[pkid][0]]
            else:
                print('Bogus event type %s in nicbufs analzyer' % (type),
                        file=sys.stderr)


        print('\n-----------------')
        print('Analyzer: nicbufs')
        print('-----------------')
        print('Maximum active NIC buffer space used for each GRO core over the')
        print('life of the traces (assuming Mellanox mlx5 buffer cache):')
        print('Active:    Maximum bytes of NIC buffers used by the core (bytes')
        print('           allocated on Core between when PktId was received and')
        print('           when PktId was freed)')
        print('PktId:     Identifier (as seen by receiver) for the packet ')
        print('           corresponding to Active')
        print('Node:      Node where Pktid was received')
        print('Core:      Core on which Pktid was received')
        print('GRO:       Time when homa_gro_receive processed Pktid on Core')
        print('Free:      Time when packet was freed after copying to user space')
        print('Life:      Packet lifetime (Free - GRO, usecs)\n')

        maxes = []
        for core, max in core_max.items():
            time, active, pkid, gro_time = max
            maxes.append([core, time, active, pkid, gro_time])
        maxes.sort(key=lambda t : t[2], reverse = True)
        print('  Active                PktId       Node Core       GRO      '
                'Free    Life')
        print('-------------------------------------------------------------'
                '------------')
        for core, time, active, pkid, gro_time in maxes:
            node, core_id = core.split('.')
            print('%8d %20s %10s %4s %9.3f %9.3f %7.1f' % (active, pkid,
                    node, core_id, gro_time, time, time - gro_time))

#------------------------------------------------
# Analyzer: ooo
#------------------------------------------------
class AnalyzeOoo:
    """
    Prints statistics about out-of-order packet arrivals. Also prints
    details about out-of-order packets in the RPCs that experienced the
    highest out-of-order delays (--verbose will print info for all OOO RPCs)
    """

    def __init__(self, dispatcher):
        dispatcher.interest('AnalyzeRpcs')

    def output(self):
        global rpcs, options

        total_rpcs = 0
        total_packets = 0
        ooo_packets = 0

        # Each element of this list contains a <delay, info> tuple describing
        # all of the out-of-order packets in a single RPC: delay is the
        # maximum delay experienced by any of the out-of-order packets, and
        # info contains one or more lines of text, each line describing one
        # ooo packet.
        ooo_rpcs = []

        # Each element of this list represents one RPC whose completion
        # was delayed by ooo packets (i.e. the last packet received didn't
        # contain the last bytes of the message). Each element is a tuple
        # <delay, id, count>:
        # delay:   time between the arrival of the packet containing the
        #          last bytes of the message and the arrival of the last
        #          packet
        # id:      RPC identifier
        # count:   the number of packets that arrived after the one containing
        #          the last bytes of the message
        delayed_msgs = []

        # Scan the incoming packets in each RPC.
        for id, rpc in rpcs.items():
            if not 'gro_data' in rpc:
                continue
            total_rpcs += 1
            pkts = rpc['gro_data']
            total_packets += len(pkts)
            highest_index = -1
            highest_offset = -1
            highest_offset_time = 0
            last_time = 0
            packets_after_highest = 0
            highest_prio = 0
            max_delay = -1
            info = ''
            for i in range(len(pkts)):
                time, offset, prio = pkts[i]
                last_time = time
                if offset > highest_offset:
                    highest_index = i;
                    highest_offset = offset
                    highest_offset_time = time
                    highest_prio = prio
                    packets_after_highest = 0
                    continue
                else:
                    packets_after_highest += 1

                # This packet is out of order. Find the first packet received
                # with higher offset than this one so we can compute how long
                # this packet was delayed.
                ooo_packets += 1
                gap = highest_index
                while gap > 0:
                    if pkts[gap-1][1] < offset:
                        break
                    gap -= 1
                gap_time, gap_offset, gap_prio = pkts[gap]
                delay = time - gap_time
                if max_delay == -1:
                    rpc_id = '%12d' % (id)
                else:
                    rpc_id = ' ' * 12
                info += '%s %7d %10s %9.3f %6.1f %8d  %3d  %3d\n' % (rpc_id, offset,
                        rpc['node'], time, delay, highest_offset - offset,
                        prio, highest_prio)
                if delay > max_delay:
                    max_delay = delay
            if info:
                ooo_rpcs.append([max_delay, info])
            if packets_after_highest > 0:
                delayed_msgs.append([last_time - highest_offset_time, id,
                        packets_after_highest])

        print('\n-----------------')
        print('Analyzer: ooo')
        print('-----------------')
        print('Messages with out-of-order packets: %d/%d (%.1f%%)' %
                (len(ooo_rpcs), total_rpcs, 100.0*len(ooo_rpcs)/total_rpcs))
        print('Out-of-order packets: %d/%d (%.1f%%)' %
                (ooo_packets, total_packets, 100.0*ooo_packets/total_packets))
        if delayed_msgs:
            delayed_msgs.sort()
            print('')
            print('Messages whose completion was delayed by out-of-order-packets: '
                    '%d (%.1f%%)' % (len(delayed_msgs),
                    100.0*len(delayed_msgs)/len(rpcs)))
            print('P50 completion delay: %.1f us' % (
                    delayed_msgs[len(delayed_msgs)//2][0]))
            print('P90 completion delay: %.1f us' % (
                    delayed_msgs[(9*len(delayed_msgs))//10][0]))
            print('Worst delays:')
            print('Delay (us)         RPC   Receiver  Late Pkts')
            for i in range(len(delayed_msgs)-1, len(delayed_msgs)-6, -1):
                if i < 0:
                    break;
                delay, id, packets = delayed_msgs[i]
                print('  %8.1f  %10d %10s      %5d' %
                        (delay, id, rpcs[id]['node'], packets))

            delayed_msgs.sort(key=lambda t : t[2])
            packets_sum = sum(i[2] for i in delayed_msgs)
            print('Late packets per delayed message: P50 %.1f, P90 %.1f, Avg %.1f' %
                    (delayed_msgs[len(delayed_msgs)//2][2],
                    delayed_msgs[(9*len(delayed_msgs))//10][2],
                    packets_sum / len(delayed_msgs)))
        else:
            print('No RPCs had their completion delayed by out-of-order packtets')

        if not ooo_rpcs:
            return
        print('')
        print('Information about out-of-order packets, grouped by RPC and sorted')
        print('so that RPCs with largest OOO delays appear first (use --verbose')
        print('to display all RPCs with OOO packets):')
        print('RPC:     Identifier for the RPC')
        print('Offset:  Offset of the out-of-order packet within the RPC')
        print('Node:    Node on which the packet was received')
        print('Time:    Time when the packet was received by homa_gro_receive')
        print('Delay:   Time - receive time for earliest packet with higher offset')
        print('Gap:     Offset of highest packet received before this one, minus')
        print('         offset of this packet')
        print('Prio:    Priority of this packet')
        print('Prev:    Priority of the highest-offset packet received before ')
        print('         this one')
        print('')
        print('         RPC  Offset       Node      Time  Delay      Gap Prio Prev')
        print('-------------------------------------------------------------------')
        ooo_rpcs.sort(key=lambda t : t[0], reverse=True)
        count = 0
        for delay, info in ooo_rpcs:
            if (count >= 20) and not options.verbose:
                break
            print(info, end='')
            count += 1

#------------------------------------------------
# Analyzer: packet
#------------------------------------------------
class AnalyzePacket:
    """
    Analyzes the delay between when a particular packet was sent and when
    it was received by GRO: prints information about other packets competing
    for the same GRO core. Must specify the packet of interest with the
    --pkt option: this is the packet id on the sender.
    """

    def __init__(self, dispatcher):
        dispatcher.interest('AnalyzeRpcs')
        return

    def output(self):
        global rpcs, traces, options, peer_nodes

        pkt_max = get_packet_size()

        print('\n-----------------')
        print('Analyzer: packet')
        print('-----------------')
        if not options.pkt:
            print('Skipping packet analyzer: --pkt not specified',
                    file=sys.stderr)
            return

        # Find the packet as received by GRO.
        recv_id = options.pkt_id ^ 1
        if not recv_id in rpcs:
            print('Can\'t find RPC %d for packet %s'
                    % (recv_id, options.pkt), file=sys.stderr)
            print("RPC ids: %s" % (sorted(rpcs.keys())))
            return
        recv_rpc = rpcs[recv_id]
        success = False
        for recv_time, offset, pkt_prio in recv_rpc['gro_data']:
            if offset == options.pkt_offset:
                success = True
                break
        if not success:
            print('Can\'t find packet with offset for %s' % (options.pkt),
                    file=sys.stderr)
            return

        # Find the corresponding packet transmission.
        xmit_id = options.pkt_id
        if not xmit_id in rpcs:
            print('Can\'t find RPC that transmitted %s' % (options.pkt),
                    file=sys.stderr)
        xmit_rpc = rpcs[xmit_id]
        for xmit_time, offset, length in xmit_rpc['send_data']:
            if (options.pkt_offset >= offset) and (
                    options.pkt_offset < (offset + length)):
                success = True
                break
        if not success:
            print('Can\'t find transmitted packet corresponding to %s'
                    % (options.pkt), file=sys.stderr)
            return
        print('Packet: RPC id %d, offset %d, delay %6.1f us' % (xmit_id,
                options.pkt_offset, recv_time - xmit_time))
        print('%.3f: Packet transmitted by %s' % (xmit_time, xmit_rpc['node']))
        print('%.3f: Packet received by %s on core %d with priority %d'
                % (recv_time, recv_rpc['node'], recv_rpc['gro_core'], pkt_prio))

        # Collect information for all packets received by the GRO core after
        # xmit_time. Each list entry is a tuple:
        # <recv_time, xmit_time, rpc_id, offset, sender, length, prio, gro_core>
        pkts = []

        # Amount of data already in transit to target at the time reference
        # packet was transmitted.
        prior_bytes = 0

        for id, rpc in rpcs.items():
            if id == 0:
                print('\nId: %d, RPC: %s' % (id, rpc))
            if (rpc['node'] != recv_rpc['node']) or (not 'gro_core' in rpc):
                continue
            rcvd = sorted(rpc['gro_data'], key=lambda t: t[1])
            xmit_id = id ^ 1
            if not xmit_id in rpcs:
                sent = []
                peer = rpc['peer']
                if peer in peer_nodes:
                    sender = peer_nodes[peer]
                else:
                    sender = "unknown"
                xmit_rpc = None
            else:
                xmit_rpc = rpcs[xmit_id]
                sent = sorted(xmit_rpc['send_data'], key=lambda t : t[1])
                sender = xmit_rpc['node']
            for rtime, roffset, rprio in rcvd:
                if rtime < xmit_time:
                    continue
                if rtime == recv_time:
                    # Skip the reference packet
                    continue

                # Initial guess at length (in case no xmit info available)
                length = pkt_max
                if ('in_length' in rpc):
                    length = min(length, rpc['in_length'] - roffset)

                missing_xmit = True
                while sent:
                    stime, soffset, slength = sent[0]
                    if stime >= recv_time:
                        missing_xmit = False
                        break
                    if roffset >= (soffset + slength):
                        sent.pop(0)
                        continue
                    if roffset >= soffset:
                        length = min(pkt_max, soffset + slength - roffset)
                        pkts.append([rtime, stime, xmit_id, roffset, sender,
                                length, rprio, rpc['gro_core']])
                        if stime < xmit_time:
                            prior_bytes += length
                        missing_xmit = False
                    break
                if missing_xmit:
                    # Couldn't find the transmission record for this packet;
                    # if it looks like the packet's transmission overlapped
                    # the reference packet, print as much info as possible.
                    if rtime >= recv_time:
                        continue
                    if sender != 'unknown':
                        if traces[sender]['last_time'] < rtime:
                            # Special send time means "send time unknown"
                            pkts.append([rtime, -1e10, id, roffset, sender,
                                    length, rprio, rpc['gro_core']])
                            continue
                    if xmit_rpc:
                        if ('sendmsg' in xmit_rpc) and (xmit_rpc['sendmsg']
                                >= recv_time):
                            continue
                    pkts.append([rtime, -1e10, id, roffset, sender, length,
                            rprio, rpc['gro_core']])
                    prior_bytes += length
        print('%.1f KB already in transit to target core when packet '
                'transmitted' % (prior_bytes * 1e-3))
        print('\nOther packets whose transmission to %s overlapped this '
                'packet:' % (recv_rpc['node']))
        print('Xmit:     Time packet was transmitted')
        print('Recv:     Time packet was received on core %d'
                % (recv_rpc['gro_core']))
        print('Delay:    End-to-end latency for packet')
        print('Rpc:      Id of packet\'s RPC (on sender)')
        print('Offset:   Offset of packet within message')
        print('Sender:   Node that sent packet')
        print('Length:   Number of message bytes in packet')
        print('Prio:     Priority at which packet was transmitted')
        print('Core:     Core on which homa_gro_receive handled packet')
        print('\n     Xmit       Recv    Delay         Rpc   Offset     Sender '
                'Length  Prio  Core')
        print('--------------------------------------------------------------'
                '------------------')
        pkts.sort()
        message_printed = False
        before_before = ''
        before_after = ''
        after_before_core = ''
        after_before_other = ''
        after_after = ''
        unknown_before = ''
        for rtime, stime, rpc_id, offset, sender, length, prio, core in pkts:
            if stime == -1e10:
                unknown_before += ('\n      ???  %9.3f      ??? %11d  %7d %10s '
                    '%6d    %2d  %4d' % (rtime, rpc_id, offset, sender, length,
                    prio, core))
                continue
            msg = '\n%9.3f  %9.3f %8.1f %11d  %7d %10s %6d    %2d  %4d' % (stime,
                    rtime, rtime - stime, rpc_id, offset, sender, length, prio,
                    core)
            if stime < xmit_time:
                if rtime < recv_time:
                    before_before += msg
                else:
                    before_after += msg
            else:
                if rtime < recv_time:
                    if core == recv_rpc['gro_core']:
                        after_before_core += msg
                    else:
                        after_before_other += msg
                else:
                    after_after += msg
        if before_before:
            print('Sent before %s, received before:%s' %
                    (options.pkt, before_before))
        if before_after:
            print('\nSent before %s, received after:%s' %
                    (options.pkt, before_after))
        if after_before_core:
            print('\nSent after %s, received on core %d before:%s' %
                    (options.pkt, recv_rpc['gro_core'], after_before_core))
        if after_before_other:
            print('\nSent after %s, received on other cores before:%s' %
                    (options.pkt, after_before_other))
        if after_after:
            print('\nSent after %s, received after:%s' %
                    (options.pkt, after_after))
        if unknown_before:
            print('\nSend time unknown, received before:%s' % (unknown_before))


#------------------------------------------------
# Analyzer: packets
#------------------------------------------------
class AnalyzePackets:
    # Collects information about each data packet and grant but doesn't
    # generate any output. The data it collects is used by other analyzers.

    def __init__(self, dispatcher):
        return

    def init_trace(self, trace):
        # Maps from RPC id to a list of active data packets for that RPC
        # (packets that have been received by homa_gro_receive but not
        # yet copied to user space).
        self.active = defaultdict(list)

        # Maps from core to a list of packets that have been copied out
        # to user space by that core (but not yet freed).
        self.copied = defaultdict(list)

    def tt_ip_xmit(self, trace, time, core, id, offset):
        global packets
        packets[pkt_id(id, offset)]['xmit'] = time

    def tt_mlx_data(self, trace, time, core, peer, id, offset):
        global packets
        packets[pkt_id(id, offset)]['nic'] = time

    def tt_gro_data(self, trace, time, core, peer, id, offset, prio):
        global packets
        p = packets[pkt_id(id^1, offset)]
        p['gro'] = time
        p['priority'] = prio
        p['id'] = id^1
        p['offset'] = offset
        self.active[id].append(p)

    def tt_softirq_data(self, trace, time, core, id, offset, msg_length):
        global packets
        p = packets[pkt_id(id^1, offset)]
        p['softirq'] = time
        p['msg_length'] = msg_length

    def tt_copy_out_done(self, trace, time, core, id, start, end):
        pkts = self.active[id]
        for i in range(len(pkts) -1, -1, -1):
            p = pkts[i]
            if (p['offset'] >= start) and (p['offset'] < end):
                self.copied[core].append(p)
                pkts.pop(i)

    def tt_free_skbs(self, trace, time, core, num_skbs):
        for p in self.copied[core]:
            p['free'] = time
        self.copied[core] = []

    def tt_send_data(self, trace, time, core, id, offset, length):
        global packets
        p = packets[pkt_id(id, offset)]
        p['id'] = id
        p['length'] = length

    def tt_send_grant(self, trace, time, core, id, offset, priority):
        global grants
        grants[pkt_id(id, offset)]['xmit'] = time

    def tt_mlx_grant(self, trace, time, core, peer, id, offset):
        global grants
        grants[pkt_id(id, offset)]['nic'] = time

    def tt_gro_grant(self, trace, time, core, peer, id, offset, priority):
        global grants
        g = grants[pkt_id(id^1, offset)]
        g['gro'] = time
        g['id'] = id^1

    def tt_softirq_grant(self, trace, time, core, id, offset):
        global grants
        grants[pkt_id(id^1, offset)]['softirq'] = time

#------------------------------------------------
# Analyzer: rpcs
#------------------------------------------------
class AnalyzeRpcs:
    # Collects information about each RPC but doesn't actually print
    # anything. Intended for use by other analyzers.

    def __init__(self, dispatcher):
        return

    def new_rpc(self, id, node):
        """
        Initialize a new RPC.
        """

        global rpcs
        rpcs[id] = {'node': node,
            'gro_data': [],
            'gro_grant': [],
            'softirq_data': [],
            'softirq_grant': [],
            'send_data': [],
            'send_grant': [],
            'ip_xmits': {},
            'resends': {},
            'retransmits': {}}

    def append(self, trace, id, name, value):
        """
        Add a value to an element of an RPC's dictionary, creating the RPC
        and the list if they don't exist already

        trace:      Overall information about the trace file being parsed.
        id:         Identifier for a specific RPC; stats for this RPC are
                    initialized if they don't already exist
        name:       Name of a value in the RPC's record; will be created
                    if it doesn't exist
        value:      Value to append to the list indicated by id and name
        """

        global rpcs
        if not id in rpcs:
            self.new_rpc(id, trace['node'])
        rpc = rpcs[id]
        if not name in rpc:
            rpc[name] = []
        rpc[name].append(value)

    def tt_gro_data(self, trace, time, core, peer, id, offset, prio):
        global rpcs
        self.append(trace, id, 'gro_data', [time, offset, prio])
        rpcs[id]['peer'] = peer
        rpcs[id]['gro_core'] = core

    def tt_gro_grant(self, trace, time, core, peer, id, offset, priority):
        self.append(trace, id, 'gro_grant', [time, offset])
        rpcs[id]['peer'] = peer
        rpcs[id]['gro_core'] = core

    def tt_rpc_handoff(self, trace, time, core, id):
        if not id in rpcs:
            self.new_rpc(id, trace['node'])
        rpcs[id]['handoff'] = time
        rpcs.pop('queued', None)

    def tt_ip_xmit(self, trace, time, core, id, offset):
        global rpcs
        if not id in rpcs:
            self.new_rpc(id, trace['node'])
        rpcs[id]['ip_xmits'][offset] = time

    def tt_rpc_queued(self, trace, time, core, id):
        if not id in rpcs:
            self.new_rpc(id, trace['node'])
        rpcs[id]['queued'] = time
        rpcs.pop('handoff', None)

    def tt_resend(self, trace, time, core, id, offset):
        global rpcs
        if not id in rpcs:
            self.new_rpc(id, trace['node'])
        rpcs[id]['resends'][offset] = time

    def tt_retransmit(self, trace, time, core, id, offset, length):
        global rpcs
        if not id in rpcs:
            self.new_rpc(id, trace['node'])
        rpcs[id]['retransmits'][offset] = [time, length]

    def tt_softirq_data(self, trace, time, core, id, offset, length):
        global rpcs
        self.append(trace, id, 'softirq_data', [time, offset])
        rpcs[id]['in_length'] = length

    def tt_softirq_grant(self, trace, time, core, id, offset):
        self.append(trace, id, 'softirq_grant', [time, offset])

    def tt_send_data(self, trace, time, core, id, offset, length):
        # Combine the length and other info from this record with the time
        # from the ip_xmit call. No ip_xmit call? Skip this record too.
        global rpcs
        if (not id in rpcs) or (not offset in rpcs[id]['ip_xmits']):
            return
        ip_xmits = rpcs[id]['ip_xmits']
        self.append(trace, id, 'send_data', [ip_xmits[offset], offset, length])
        del ip_xmits[offset]

    def tt_send_grant(self, trace, time, core, id, offset, priority):
        self.append(trace, id, 'send_grant', [time, offset, priority])

    def tt_sendmsg_request(self, trace, time, core, peer, id, length):
        global rpcs
        if not id in rpcs:
            self.new_rpc(id, trace['node'])
        rpcs[id]['out_length'] = length
        rpcs[id]['peer'] = peer
        rpcs[id]['sendmsg'] = time

    def tt_sendmsg_response(self, trace, time, core, id, length):
        global rpcs
        if not id in rpcs:
            self.new_rpc(id, trace['node'])
        rpcs[id]['sendmsg'] = time
        rpcs[id]['out_length'] = length

    def tt_recvmsg_done(self, trace, time, core, id, length):
        global rpcs
        if not id in rpcs:
            self.new_rpc(id, trace['node'])
        rpcs[id]['recvmsg_done'] = time

    def tt_wait_found_rpc(self, trace, time, core, id):
        if not id in rpcs:
            self.new_rpc(id, trace['node'])
        rpcs[id]['found'] = time

    def tt_copy_out_start(self, trace, time, core, id):
        global rpcs
        if not id in rpcs:
            self.new_rpc(id, trace['node'])
        if not 'copy_out_start' in rpcs[id]:
            rpcs[id]['copy_out_start'] = time

    def tt_copy_out_done(self, trace, time, core, id, start, end):
        global rpcs
        if not id in rpcs:
            self.new_rpc(id, trace['node'])
        rpcs[id]['copy_out_done'] = time

    def tt_copy_in_done(self, trace, time, core, id, num_bytes):
        global rpcs
        if not id in rpcs:
            self.new_rpc(id, trace['node'])
        rpcs[id]['copy_in_done'] = time

    def analyze(self):
        """
        Fill in peer_traces.
        """
        global rpcs, traces, peer_nodes

        for id, rpc in rpcs.items():
            if not 'peer' in rpc:
                continue
            peer = rpc['peer']
            if peer in peer_nodes:
                continue
            peer_id = id ^ 1
            if peer_id in rpcs:
                peer_nodes[peer] = rpcs[peer_id]['node']

#------------------------------------------------
# Analyzer: rtt
#------------------------------------------------
class AnalyzeRtt:
    """
    Prints statistics about round-trip times for short RPCs and identifies
    RPCs with the longest RTTs. The --max-rtt option can be used to restrict
    the time range for the "long" RPCs to print out.
    """
    def __init__(self, dispatcher):
        dispatcher.interest('AnalyzeRpcs')
        return

    def output(self):
        global rpcs, peer_nodes, options

        # List with one entry for each short RPC, containing a tuple
        # <rtt, id, start, end, client, server> where rtt is the round-trip
        # time, id is the client's RPC id, start and end are the beginning
        # and ending times, and client and server are the names of the two
        # nodes involved.
        rtts = []

        for id, rpc in rpcs.items():
            if id & 1:
                continue
            if (not 'sendmsg' in rpc) or (not 'recvmsg_done' in rpc):
                continue
            if (not 'out_length' in rpc) or (rpc['out_length'] > 1500):
                continue
            if (not 'in_length' in rpc) or (rpc['in_length'] > 1500):
                continue
            rtts.append([rpc['recvmsg_done'] - rpc['sendmsg'], id,
                    rpc['sendmsg'], rpc['recvmsg_done'], rpc['node'],
                    peer_nodes[rpc['peer']]])

        rtts.sort(key=lambda t : t[0])

        print('\n-------------')
        print('Analyzer: rtt')
        print('-------------')
        if not rtts:
            print('Traces contained no short RPCs (<= 1500 bytes)')
            return
        print('Round-trip times for %d short RPCs (<= 1500 bytes):'
                % (len(rtts)))
        print('Min:  %6.1f' % rtts[0][0])
        print('P10:  %6.1f' % rtts[10*len(rtts)//100][0])
        print('P50:  %6.1f' % rtts[50*len(rtts)//100][0])
        print('P90:  %6.1f' % rtts[90*len(rtts)//100][0])
        print('P99:  %6.1f' % rtts[99*len(rtts)//100][0])
        print('Max:  %6.1f' % rtts[len(rtts) - 1][0])

        def get_phase(rpc1, phase1, rpc2, phase2):
            """
            Returns the elapsed time from phase1 in rpc1 to phase2 in
            rpc2, or None if the required data is missing.
            """
            if phase1 not in rpc1:
                return None
            start = rpc1[phase1]
            if type(start) == list:
                if not start:
                    return None
                start = start[0][0]
            if phase2 not in rpc2:
                return None
            end = rpc2[phase2]
            if type(end) == list:
                if not end:
                    return None
                end = end[0][0]
            return end - start

        def get_phases(crpc, srpc):
            """
            Returns a dictionary containing the delays for each phase in
            the RPC recorded on the client side in crpc and the server side
            in srpc. Each phase measures from the end of the previous phase;
            if data wasn't available for a phase then the value will be None.
            prep:       From sendmsg until call to ip*xmit on client
            net:        To GRO on the server
            gro:        To SoftIRQ on the server
            softirq:    To homa_rpc_handoff
            handoff:    Handoff to waiting thread
            queue:      Wait on queue for receiving thread (alternative to
                        handoff: one of these will be None)
            sendmsg:    To sendmsg call on server
            prep2:      To call to ip*xmit on server
            net2:       To GRO on the client
            gro2:       To SoftIRQ on the client
            softirq2:   To homa_rpc_handoff on client
            handoff2:   Handoff to waiting thread
            queue2:     Wait on queue for receiving thread (only one of
                        this and handoff2 will be set)
            done:       To return from sendmsg on client
            """
            global rpcs

            result = {}

            result['prep'] = get_phase(crpc, 'sendmsg', crpc, 'send_data')
            result['net'] =  get_phase(crpc, 'send_data', srpc, 'gro_data')
            result['gro'] = get_phase(srpc, 'gro_data', srpc, 'softirq_data')
            if 'queued' in srpc:
                result['softirq'] = get_phase(srpc, 'softirq_data', srpc, 'queued')
                if result['softirq'] < 0:
                    result['softirq'] = 0
                result['queue'] = get_phase(srpc, 'queued', srpc, 'found')
                result['handoff'] = None
            else:
                result['softirq'] = get_phase(srpc, 'softirq_data', srpc, 'handoff')
                if result['softirq'] < 0:
                    result['softirq'] = 0
                result['handoff'] = get_phase(srpc, 'handoff', srpc, 'found')
                result['queue'] = None
            result['sendmsg'] = get_phase(srpc, 'found', srpc, 'sendmsg')
            result['prep2'] = get_phase(srpc, 'sendmsg', srpc, 'send_data')
            result['net2'] =  get_phase(srpc, 'send_data', crpc, 'gro_data')
            result['gro2'] = get_phase(crpc, 'gro_data', crpc, 'softirq_data')
            if 'queued' in crpc:
                result['softirq2'] = get_phase(crpc, 'softirq_data', crpc, 'queued')
                if result['softirq2'] < 0:
                    result['softirq2'] = 0
                result['queue2'] = get_phase(crpc, 'queued', crpc, 'found')
                result['handoff2'] = None
            else:
                result['softirq2'] = get_phase(crpc, 'softirq_data', crpc, 'handoff')
                if result['softirq2'] < 0:
                    result['softirq2'] = 0
                result['handoff2'] = get_phase(crpc, 'handoff', crpc, 'found')
                result['queue2'] = None
            result['done'] = get_phase(crpc, 'found', crpc, 'recvmsg_done')
            return result

        print('\nShort RPCs with the longest RTTs:')
        print('RTT:       Round-trip time (usecs)')
        print('Client Id: RPC id as seen by client')
        print('Server:    Node that served the RPC')
        print('Start:     Time of sendmsg invocation on client')
        print('Prep:      Time until request passed to ip*xmit')
        print('Net:       Time for request to reach server GRO')
        print('GRO:       Time to finish GRO and wakeup homa_softirq on server')
        print('SIRQ:      Time until server homa_softirq invokes homa_rpc_handoff')
        print('Handoff:   Time to pass RPC to waiting thread (if thread waiting)')
        print('Queue:     Time RPC is enqueued until receiving thread arrives')
        print('App:       Time until application wakes up and invokes sendmsg '
                'for response')
        print('Prep2:     Time until response passed to ip*xmit')
        print('Net2:      Time for response to reach client GRO')
        print('GRO2:      Time to finish GRO and wakeup homa_softirq on client')
        print('SIRQ2:     Time until client homa_softirq invokes homa_rpc_handoff')
        print('Hand2:     Time to pass RPC to waiting thread (if thread waiting)')
        print('Queue2:    Time RPC is enqueued until receiving thread arrives')
        print('Done:      Time until recvmsg returns on client')
        print('')
        print('   RTT    Client Id     Server     Start Prep    Net   GRO SIRQ '
                'Handoff  Queue  App Prep2   Net2   GRO2 SIRQ2  Hand2 Queue2 Done')
        print('----------------------------------------------------------------'
                '----------------------------------------------------------------')
        slow_phases = []
        slow_rtt_sum = 0
        to_print = 20
        max_rtt = 1e20
        if options.max_rtt != None:
            max_rtt = options.max_rtt
        for i in range(len(rtts)-1, -1, -1):
            rtt, id, start, end, client, server = rtts[i]
            if rtt > max_rtt:
                continue
            crpc = rpcs[id]
            server_id = id ^ 1
            if not server_id in rpcs:
                continue
            srpc = rpcs[server_id]
            phases = get_phases(crpc, srpc)
            slow_phases.append(phases)
            slow_rtt_sum += rtt

            def fmt_phase(phase, size=6):
                if (phase == None):
                    return ' '*size
                else:
                    return ('%' + str(size) + '.1f') % (phase)

            print('%6.1f %12d %10s %9.3f %s' % (rtt, id, server, start,
                    fmt_phase(phases['prep'], 4)), end='')
            print(' %s %s %s  %s' % (fmt_phase(phases['net']),
                    fmt_phase(phases['gro'], 5),
                    fmt_phase(phases['softirq'], 4),
                    fmt_phase(phases['handoff'])), end='')
            print(' %s %s %s %s' % (
                    fmt_phase(phases['queue']), fmt_phase(phases['sendmsg'], 4),
                    fmt_phase(phases['prep2'], 5), fmt_phase(phases['net2'])),
                    end='')
            print('  %s %s %s %s %s' % (fmt_phase(phases['gro2'], 5),
                    fmt_phase(phases['softirq2'], 5), fmt_phase(phases['handoff2']),
                    fmt_phase(phases['queue2'], 6), fmt_phase(phases['done'], 4)))
            to_print -= 1
            if to_print == 0:
                break

        # Print out phase averages for fast RPCs.
        fast_phases = []
        fast_rtt_sum = 0
        for i in range(len(rtts)):
            rtt, id, start, end, client, server = rtts[i]
            crpc = rpcs[id]
            server_id = id ^ 1
            if not server_id in rpcs:
                continue
            srpc = rpcs[server_id]
            fast_phases.append(get_phases(crpc, srpc))
            fast_rtt_sum += rtt
            if len(fast_phases) >= 10:
                break
        print('\nAverage times for the fastest short RPCs:')
        print('   RTT                                   Prep    Net   GRO SIRQ '
                'Handoff  Queue  App Prep2   Net2   GRO2 SIRQ2  Hand2 Queue2 Done')
        print('----------------------------------------------------------------'
                '----------------------------------------------------------------')
        print('%6.1f %33s %4.1f %6.1f %5.1f' % (
                fast_rtt_sum/len(fast_phases), '',
                dict_avg(fast_phases, 'prep'), dict_avg(fast_phases, 'net'),
                dict_avg(fast_phases, 'gro')), end='')
        print(' %4.1f %7.1f %6.1f %4.1f %5.1f' % (
                dict_avg(fast_phases, 'softirq'), dict_avg(fast_phases, 'handoff'),
                dict_avg(fast_phases, 'queue'), dict_avg(fast_phases, 'sendmsg'),
                dict_avg(fast_phases, 'prep2')), end='')
        print(' %6.1f %6.1f %5.1f %6.1f %6.1f %4.1f' % (
                dict_avg(fast_phases, 'net2'), dict_avg(fast_phases, 'gro2'),
                dict_avg(fast_phases, 'softirq2'), dict_avg(fast_phases, 'handoff2'),
                dict_avg(fast_phases, 'queue2'), dict_avg(fast_phases, 'done')))

        # Print out how much slower each phase is for slow RPCs than
        # for fast ones.
        print('\nAverage extra time spent by slow RPCs relative to fast ones:')
        print('   RTT                                   Prep    Net   GRO SIRQ '
                'Handoff  Queue  App Prep2   Net2   GRO2 SIRQ2  Hand2 Queue2 Done')
        print('----------------------------------------------------------------'
                '----------------------------------------------------------------')
        print('%6.1f %33s %4.1f %6.1f %5.1f' % (
                slow_rtt_sum/len(slow_phases) - fast_rtt_sum/len(fast_phases),
                '',
                dict_avg(slow_phases, 'prep') - dict_avg(fast_phases, 'prep'),
                dict_avg(slow_phases, 'net') - dict_avg(fast_phases, 'net'),
                dict_avg(slow_phases, 'gro') - dict_avg(fast_phases, 'gro')),
                        end='')
        print(' %4.1f %7.1f %6.1f %4.1f %5.1f' % (
                dict_avg(slow_phases, 'softirq') - dict_avg(fast_phases, 'softirq'),
                dict_avg(slow_phases, 'handoff') - dict_avg(fast_phases, 'handoff'),
                dict_avg(slow_phases, 'queue') - dict_avg(fast_phases, 'queue'),
                dict_avg(slow_phases, 'sendmsg') - dict_avg(fast_phases, 'sendmsg'),
                dict_avg(slow_phases, 'prep2') - dict_avg(fast_phases, 'prep2')),
                        end='')
        print(' %6.1f %6.1f %5.1f %6.1f %6.1f %4.1f' % (
                dict_avg(slow_phases, 'net2') - dict_avg(fast_phases, 'net2'),
                dict_avg(slow_phases, 'gro2') - dict_avg(fast_phases, 'gro2'),
                dict_avg(slow_phases, 'softirq2') - dict_avg(fast_phases, 'softirq2'),
                dict_avg(slow_phases, 'handoff2') - dict_avg(fast_phases, 'handoff2'),
                dict_avg(slow_phases, 'queue2') - dict_avg(fast_phases, 'queue2'),
                dict_avg(slow_phases, 'done') - dict_avg(fast_phases, 'done')))

#------------------------------------------------
# Analyzer: smis
#------------------------------------------------
class AnalyzeSmis:
    """
    Prints out information about SMIs (System Management Interrupts) that
    occurred during the traces. An SMI causes all of the cores on a node
    to freeze for a significant amount of time.
    """
    def __init__(self, dispatcher):
        # A list of <start, end, node> tuples, each of which describes one
        # gap that looks like an SMI.
        self.smis = []

        # Time of the last trace record seen.
        self.last_time = None
        return

    def tt_all(self, trace, time, core, msg):
        if self.last_time == None:
            self.last_time = time
            return
        if (time - self.last_time) > 50:
            self.smis.append([self.last_time, time, trace['node']])
        self.last_time = time

    def output(self):
        print('\n-------------------')
        print('Analyzer: smis')
        print('-------------------')
        print('Gaps that appear to be caused by System Management '
                'Interrupts (SMIs),')
        print('which freeze all cores on a node simultaneously:')
        print('')
        print('    Start        End     Gap   Node')
        print('-----------------------------------')
        for smi in sorted(self.smis, key=lambda t : t[0]):
            start, end, node = smi
            print('%9.3f  %9.3f  %6.1f  %s' % (start, end, end - start, node))

#------------------------------------------------
# Analyzer: timeline
#------------------------------------------------
class AnalyzeTimeline:
    """
    Prints a timeline showing how long it takes for RPCs to reach various
    interesting stages on both clients and servers. Most useful for
    benchmarks where all RPCs are the same size.
    """
    def __init__(self, dispatcher):
        dispatcher.interest('AnalyzeRpcs')
        return

    def output(self):
        global rpcs
        num_client_rpcs = 0
        num_server_rpcs = 0
        print('\n-------------------')
        print('Analyzer: timeline')
        print('-------------------')

        # These tables describe the phases of interest. Each sublist is
        # a <label, name, lambda> triple, where the label is human-readable
        # string for the phase, the name selects an element of an RPC, and
        # the lambda extracts a time from the RPC element.
        client_phases = [
            ['start',                         'sendmsg',      lambda x : x],
            ['first request packet sent',     'send_data',    lambda x : x[0][0]],
            ['softirq gets first grant',      'softirq_grant',lambda x : x[0][0]],
            ['last request packet sent',      'send_data',    lambda x : x[-1][0]],
            ['gro gets first response packet','gro_data',     lambda x : x[0][0]],
            ['sent grant',                    'send_grant',   lambda x : x[0][0]],
            ['gro gets last response packet', 'gro_data',     lambda x : x[-1][0]],
            ['homa_recvmsg returning',        'recvmsg_done', lambda x : x]
            ]
        client_extra = [
            ['start',                         'sendmsg',       lambda x : x],
            ['finished copying req into pkts','copy_in_done',  lambda x : x],
            ['started copying to user space', 'copy_out_start',lambda x : x],
            ['finished copying to user space','copy_out_done', lambda x : x]
        ]

        server_phases = [
            ['start',                          'gro_data',      lambda x : x[0][0]],
            ['sent grant',                     'send_grant',    lambda x : x[0][0]],
            ['gro gets last request packet',  'gro_data',       lambda x : x[-1][0]],
            ['homa_recvmsg returning',         'recvmsg_done',  lambda x : x],
            ['homa_sendmsg response',          'sendmsg',       lambda x : x],
            ['first response packet sent',     'send_data',     lambda x : x[0][0]],
            ['softirq gets first grant',       'softirq_grant', lambda x : x[0][0]],
            ['last response packet sent',      'send_data',     lambda x : x[-1][0]]
        ]
        server_extra = [
            ['start',                         'gro_data',       lambda x : x[0][0]],
            ['started copying to user space', 'copy_out_start', lambda x : x],
            ['finished copying to user space','copy_out_done',  lambda x : x],
            ['finished copying req into pkts','copy_in_done',   lambda x : x]
        ]

        # One entry in each of these lists for each phase of the RPC,
        # values are lists of times from RPC start (or previous phase)
        client_totals = []
        client_deltas = []
        client_extra_totals = []
        client_extra_deltas = []
        server_totals = []
        server_deltas = []
        server_extra_totals = []
        server_extra_deltas = []

        # Collect statistics from all of the RPCs.
        for id, rpc in rpcs.items():
            if not (id & 1):
                # This is a client RPC
                if (not 'sendmsg' in rpc) or (not 'recvmsg_done' in rpc):
                    continue
                num_client_rpcs += 1
                self.__collect_stats(client_phases, rpc, client_totals,
                        client_deltas)
                self.__collect_stats(client_extra, rpc, client_extra_totals,
                        client_extra_deltas)
            else:
                # This is a server RPC
                if (not rpc['gro_data']) or (rpc['gro_data'][0][1] != 0) \
                        or (not rpc['send_data']):
                    continue
                num_server_rpcs += 1
                self.__collect_stats(server_phases, rpc, server_totals,
                        server_deltas)
                self.__collect_stats(server_extra, rpc, server_extra_totals,
                        server_extra_deltas)

        if client_totals:
            print('\nTimeline for clients (%d RPCs):\n' % (num_client_rpcs))
            self.__print_phases(client_phases, client_totals, client_deltas)
            print('')
            self.__print_phases(client_extra, client_extra_totals,
                    client_extra_deltas)
        if server_totals:
            print('\nTimeline for servers (%d RPCs):\n' % (num_server_rpcs))
            self.__print_phases(server_phases, server_totals, server_deltas)
            print('')
            self.__print_phases(server_extra, server_extra_totals,
                    server_extra_deltas)

    def __collect_stats(self, phases, rpc, totals, deltas):
        """
        Utility method used by print to aggregate delays within an RPC
        into buckets corresponding to different phases of the RPC.
        phases:     Describes the phases to aggregate
        rpc:        Dictionary containing information about one RPC
        totals:     Total delays from start of the RPC are collected here
        deltas:     Delays from one phase to the next are collected here
        """

        while len(phases) > len(totals):
            totals.append([])
            deltas.append([])
        for i in range(len(phases)):
            phase = phases[i]
            if phase[1] in rpc:
                rpc_phase = rpc[phase[1]]
                if rpc_phase:
                    t = phase[2](rpc_phase)
                    if i == 0:
                        start = prev = t
                    totals[i].append(t - start)
                    deltas[i].append(t - prev)
                    prev = t

    def __print_phases(self, phases, totals, deltas):
        """
        Utility method used by print to print out summary statistics
        aggregated by __phase_stats
        """
        for i in range(1, len(phases)):
            label = phases[i][0]
            if not totals[i]:
                print('%-32s (no events)' % (label))
                continue
            elapsed = sorted(totals[i])
            gaps = sorted(deltas[i])
            print('%-32s Avg %7.1f us (+%7.1f us)  P90 %7.1f us (+%7.1f us)' %
                (label, sum(elapsed)/len(elapsed), sum(gaps)/len(gaps),
                elapsed[9*len(elapsed)//10], gaps[9*len(gaps)//10]))

#------------------------------------------------
# Analyzer: txqueues
#------------------------------------------------
class AnalyzeTxqueues:
    """
    Prints statistics about the amount of outbound packet data queued
    in the NIC of each node. The --gbps option specifies the rate at
    which packets are transmitted. With --data option, generates detailed
    timelines of NIC queue lengths.
    """

    def __init__(self, dispatcher):
        # Maps from node names to a list of <time, length, queue_length> tuples
        # for all transmitted packets. Length is the packet length including
        # includes Homa header but not IP or Ethernet overheads. Queue_length
        # is the # bytes in the NIC queue as of time (includes this packet).
        # Queue_length starts off zero and is updated later.
        self.nodes = defaultdict(list)

    def tt_send_data(self, trace, time, core, id, offset, length):
        self.nodes[trace['node']].append([time, length + 60, 0])

    def tt_send_grant(self, trace, time, core, id, offset, priority):
        self.nodes[trace['node']].append([time, 34, 0])

    def output(self):
        global options, traces

        print('\n-------------------')
        print('Analyzer: txqueues')
        print('-------------------')

        # Compute queue lengths, find maximum for each node.
        print('Worst-case length of NIX tx queue for each node, assuming a link')
        print('speed of %.1f Gbps (change with --gbps):' % (options.gbps))
        print('Node:        Name of node')
        print('MaxLength:   Highest observed output queue length for NIC (bytes)')
        print('Time:        Time when worst-case queue length occurred')
        print('Delay:       Delay (usec until fully transmitted) experienced by packet ')
        print('             transmitted at Time')
        print('')
        print('Node     MaxLength       Time   Delay')

        for node in get_sorted_nodes():
            pkts = self.nodes[node]
            if not pkts:
                continue
            pkts.sort()
            max_queue = 0
            max_time = 0
            cur_queue = 0
            prev_time = traces[node]['first_time']
            for i in range(len(pkts)):
                time, length, ignore = pkts[i]

                # 20 bytes for IPv4 header, 42 bytes for Ethernet overhead (CRC,
                # preamble, interpacket gap)
                total_length = length + 62

                xmit_bytes = ((time - prev_time) * (1000.0*options.gbps/8))
                if xmit_bytes < cur_queue:
                    cur_queue -= xmit_bytes
                else:
                    cur_queue = 0
                if 0 and (node == 'node6'):
                    if cur_queue == 0:
                        print('%9.3f (+%4.1f): length %6d, queue empty' %
                                (time, time - prev_time, total_length))
                    else:
                        print('%9.3f (+%4.1f): length %6d, xmit %5d, queue %6d -> %6d' %
                                (time, time - prev_time, total_length,
                                xmit_bytes, cur_queue, cur_queue + total_length))
                cur_queue += total_length
                if cur_queue > max_queue:
                    max_queue = cur_queue
                    max_time = time
                prev_time = time
                pkts[i][2] = cur_queue
            print('%-10s  %6d  %9.3f %7.1f ' % (node, max_queue, max_time,
                    (max_queue*8)/(options.gbps*1000)))

        if options.data_dir:
            # Print stats for each node at regular intervals
            file = open('%s/txqueues.dat' % (options.data_dir), 'w')
            line = 'Interval'
            for node in get_sorted_nodes():
                line += ' %10s' % (node)
            print(line, file=file)

            interval = 20
            start = get_first_time()
            end = get_last_time()
            interval_end = start//interval * interval
            if interval_end < start:
                interval_end += interval

            # Maps from node name to current index in that node's packets
            cur = {}
            for node in get_sorted_nodes():
                cur[node] = 0

            while True:
                line = '%8.1f' % (interval_end)
                for node in get_sorted_nodes():
                    max = -1
                    i = cur[node]
                    xmits = self.nodes[node]
                    while i < len(xmits):
                        time, ignore, queue_length = xmits[i]
                        if time > interval_end:
                            break
                        if queue_length > max:
                            max = queue_length
                        i += 1
                    cur[node] = i
                    if max == -1:
                        line += ' ' * 11
                    else:
                        line += '   %8d' % (max)
                print(line, file=file)
                if interval_end > end:
                    break
                interval_end += interval
            file.close()

# Parse command-line options.
parser = OptionParser(description=
        'Analyze one or more Homa timetrace files and print information '
        'extracted from the file(s). Command-line arguments determine '
        'which analyses to perform.',
        usage='%prog [options] [trace trace ...]',
        conflict_handler='resolve')
parser.add_option('--analyzers', '-a', dest='analyzers', default='all',
        metavar='A', help='Space-separated list of analyzers to apply to '
        'the trace files (default: all)')
parser.add_option('--data', '-d', dest='data_dir', default=None,
        metavar='DIR', help='If this option is specified, analyzers will '
        'output data files (suitable for graphing) in the directory given '
        'by DIR. If this option is not specified, no data files will '
        'be generated.')
parser.add_option('--gbps', dest='gbps', type=float, default=25.0,
        metavar='G', help='Link speed in Gbps (default: 25); used by some '
        'analyzers.')
parser.add_option('-h', '--help', dest='help', action='store_true',
                  help='Show this help message and exit')
parser.add_option('--negative-ok', action='store_true', default=False,
        dest='negative_ok',
        help='Don\'t print warnings when negative delays are encountered')
parser.add_option('--node', dest='node', default=None,
        metavar='N', help='Specifies a particular node (the name of its '
        'trace file without the extension); this option is required by '
        'some analyzers')
parser.add_option('--max-rtt', dest='max_rtt', type=float, default=None,
        metavar='T', help='Only consider RPCs with RTTs <= T usecs.  Used by '
        'rpc analyzer to select which specific RTTs to print out.')
parser.add_option('--pkt', dest='pkt', default=None,
        metavar='ID:OFF', help='Identifies a specific packet with ID:OFF, '
        'where ID is the RPC id on the sender (even means request message, '
        'odd means response) and OFF is an offset in the message; if this '
        'option is specified, some analyzers will output information specific '
        'to that packet.')
parser.add_option('--verbose', '-v', action='store_true', default=False,
        dest='verbose',
        help='Print additional output with more details')

(options, tt_files) = parser.parse_args()
if options.help:
    parser.print_help()
    print("\nAvailable analyzers:")
    print_analyzer_help()
    exit(0)
if not tt_files:
    print('No trace files specified')
    exit(1)
if options.data_dir:
    os.makedirs(options.data_dir, exist_ok=True)
if options.pkt:
    match = re.match('([0-9]+):([0-9]+)$', options.pkt)
    if not match:
        print('Bad value "%s" for --pkt option; must be id:offset'
                % (options.pkt), file=sys.stderr)
        exit(1)
    options.pkt_id = int(match.group(1))
    options.pkt_offset = int(match.group(2))
d = Dispatcher()
for name in options.analyzers.split():
    class_name = 'Analyze' + name[0].capitalize() + name[1:]
    if not hasattr(sys.modules[__name__], class_name):
        print('No analyzer named "%s"' % (name), file=sys.stderr)
        exit(1)
    d.interest(class_name)

# Parse the timetrace files; this will invoke handler in the analyzers.
for file in tt_files:
    d.parse(file)

# Invoke 'analyze' methods in each analyzer, if present, to perform
# postprocessing now that all the trace data has been read.
for analyzer in d.get_analyzers():
    if hasattr(analyzer, 'analyze'):
        analyzer.analyze()

# Give each analyzer a chance to output its findings (includes
# printing output and generating data files).
for analyzer in d.get_analyzers():
    if hasattr(analyzer, 'output'):
        analyzer.output()