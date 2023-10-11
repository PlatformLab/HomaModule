#!/usr/bin/python3

"""
This script analyzes time traces gathered from Homa in a variety of ways.
Invoke with the --help option for documentation.
"""

from glob import glob
from optparse import OptionParser
import math
from operator import itemgetter
import os
import re
import string
import sys

def get_time_stats(samples):
    """
    Given a list of elapsed times, returns a string containing statistics
    such as min time, P99, and average.
    """
    if not samples:
        return "no data"
    sorted_data = sorted(samples)
    average = sum(sorted_data)/len(samples)
    return "Min %.1f, P50 %.1f, P90 %.1f, P99 %.1f, Avg %.1f" % (
            sorted_data[0],
            sorted_data[50*len(sorted_data)//100],
            sorted_data[90*len(sorted_data)//100],
            sorted_data[99*len(sorted_data)//100],
            average)

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
        named "tt_xxx" in the class there must be a pattern named "xxx";
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
                raise Exception("Couldn't find pattern %s for analyzer %s"
                        % (name, analyzer))

    def parse(self, file, trace):
        """
        Parse a timetrace file and invoke interests.
        file:     Name of the file to parse.
        trace:    Dictionary in which data from the timetrace file will be
                  collected. Usage is up to the various interests that have
                  been created; typically each interested class will store
                  its information under one key of the dictionary.
        """

        self.__build_active()

        trace['file'] = file
        for analyzer in self.objs:
            if hasattr(analyzer, "init_trace"):
                analyzer.init_trace(trace)

        f = open(file)
        for line in f:
            # Parse each line in 2 phases: first the time and core information
            # that is common to all patterns, then the message, which will
            # select at most one pattern.
            match = re.match(' *([-0-9.]+) us .* \[C([0-9]+)\] (.*)', line)
            if not match:
                continue
            time = float(match.group(1))
            core = int(match.group(2))
            msg = match.group(3)

            trace['last_time'] = time
            for pattern in self.active:
                match = re.match(pattern['regexp'], msg)
                if match:
                    pattern['parser'](trace, time, core, match,
                            self.interests[pattern['name']])
                    break
        f.close()

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
            if pattern["name"] in self.interests:
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
        for interest in interests:
            interest.tt_gro_data(trace, time, core, peer, id, offset)

    patterns.append({
        'name': 'gro_data',
        'regexp': 'homa_gro_receive got packet from ([^ ]+) id ([0-9]+), '
                  'offset ([0-9.]+)'
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
        length = int(match.group(3))
        for interest in interests:
            interest.tt_softirq_data(trace, time, core, id, offset, length)

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

    def __send_data(self, trace, time, core, match, interests):
        id = int(match.group(1))
        offset = int(match.group(2))
        length = int(match.group(3))
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
        num_bytes = int(match.group(1))
        id = int(match.group(2))
        for interest in interests:
            interest.tt_copy_out_done(trace, time, core, id, num_bytes)

    patterns.append({
        'name': 'copy_out_done',
        'regexp': 'finished copying ([-0-9.]+) bytes for id ([-0-9.]+)'
    })

    def __free_skbs(self, trace, time, core, match, interests):
        num_skbs = int(match.group(1))
        for interest in interests:
            interest.tt_free_skbs(trace, time, core, num_skbs)

    patterns.append({
        'name': 'free_skbs',
        'regexp': 'finished freeing ([0-9]+) skbs'
    })

#------------------------------------------------
# Analyzer: copy
#------------------------------------------------
class AnalyzeCopy:
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
            if num_bytes <= 1200:
                stats['small_in_times'].append(delta)
            elif num_bytes >= 100000:
                stats['large_in_data'] += num_bytes
                stats['large_in_time'] += delta
                stats['large_in_count'] += 1
            if options.verbose:
                print('%9.3f Copy in finished [C%02d]: %d bytes, %.1f us, %5.1f Gbps' %
                        (time, core, num_bytes, delta, 8e-03*num_bytes/delta))

    def tt_copy_out_start(self, trace, time, core, id):
        stats = trace['copy']
        stats['out_start'][core] = time

    def tt_copy_out_done(self, trace, time, core, id, num_bytes):
        global options
        stats = trace['copy']
        if core in stats['out_start']:
            stats['out_end'][core] = time
            stats['out_size'][core] = num_bytes
            delta = time - stats['out_start'][core]
            stats['total_out_time'] += delta
            if num_bytes <= 1200:
                stats['small_out_times'].append(delta)
            elif num_bytes >= 100000:
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
            if stats['out_size'][core] >= 100000:
                stats['large_out_time_with_skbs'] += delta

    def print(self, traces):
        stats = traces[0]['copy']
        total_time = traces[0]['last_time']
        print("\nAnalyzer: copy")
        print("--------------")
        print("Copying data from user space to kernel:")
        print("  %d short messages (<= 1200B): latency %s usec" %
                (len(stats['small_in_times']),
                get_time_stats(stats['small_in_times'])))
        print("  %d long messages (>= 100KB): per-thread throughput %5.1f Gbps" %
                (stats['large_in_count'],
                8e-03*stats['large_in_data']/stats['large_in_time']))
        print("  Average core utilization: %.2f cores" %
                (stats['total_in_time']/total_time))
        print("Copying data from kernel to user space:")
        print("  %d short messages (<= 1200B): latency (usec) %s" %
                (len(stats['small_out_times']),
                get_time_stats(stats['small_out_times'])))
        print("  %d long messages (>= 100KB): per-thread throughput %5.1f Gbps" %
                (stats['large_out_count'],
                8e-03*stats['large_out_data']/stats['large_out_time']))
        print("  Average core utilization: %.2f cores" %
                (stats['total_out_time']/total_time))
        if stats['skbs_freed'] > 0:
            print("Freeing skbs after copying data to user space:")
            print("  %d skbs, average free time %.2f us" % (stats['skbs_freed'],
                    stats['skb_free_time']/stats['skbs_freed']))
            print("  Copy throughput per thread, with skb freeing: %.1f Gbps"
                    % (8e-03*stats['large_out_data']
                    /stats['large_out_time_with_skbs']))

#------------------------------------------------
# Analyzer: rpcLifecycle
#------------------------------------------------
class AnalyzeRpcLifecycle:
    def __init__(self, dispatcher):
        return

    def init_trace(self, trace):
        # Keys are RPC ids, values are dictionaries of info about that RPC,
        # with the following elements (elements not necessarily present):
        # peer:              Address of the peer host
        # in_length:         Size of the incoming message, in bytes
        # gro_data:          List of <time, offset> tuples for all incoming
        #                    data packets processed by GRO
        # gro_grant:         List of <time, offset> tuples for all incoming
        #                    grant packets processed by GRO
        # softirq_data:      List of <time, offset> tuples for all incoming
        #                    data packets processed by SoftIRQ
        # softirq_grant:     List of <time, offset> tuples for all incoming
        #                    grant packets processed by SoftIRQ
        # recvmsg_return:    Time when homa_recvmsg returned
        # sendmsg:           Time when homa_sendmsg was invoked
        # out_length:        Size of the outgoing message, in bytes
        # send_data:         List of <time, offset, length> tuples for outgoing
        #                    data packets (length is message data)
        # send_grant:        List of <time, offset, priority> tuples for
        #                    outgoing grant packets
        #
        trace['rpc_lifecycle'] = {}

    def append(self, trace, id, name, value):
        """
        Add a value to an element of an RPC's dictionary, creating the RPC
        and the list if they don't exist already

        trace:      Where information about this RPC is stored
        id:         Identifier for a specific RPC; stats for this RPC are
                    initialized if they don't already exist
        name:       Name of a value in the RPC's record; will be created
                    if it doesn't exist
        value:      Value to append to the list indicated by id and name
        """

        stats = trace['rpc_lifecycle']
        if not id in stats:
            stats[id] = {}
        rpc = stats[id]
        if not name in rpc:
            rpc[name] = []
        rpc[name].append(value)

    def tt_gro_data(self, trace, time, core, peer, id, offset):
        self.append(trace, id, "gro_data", [time, offset])

    def tt_gro_grant(self, trace, time, core, peer, id, offset, priority):
        self.append(trace, id, "gro_grant", [time, offset])

    def tt_softirq_data(self, trace, time, core, id, offset, length):
        self.append(trace, id, "softirq_data", [time, offset])
        trace['rpc_lifecycle'][id]['in_length'] = length

    def tt_softirq_grant(self, trace, time, core, id, offset):
        self.append(trace, id, "softirq_grant", [time, offset])

    def tt_send_data(self, trace, time, core, id, offset, length):
        self.append(trace, id, "send_data", [time, offset, length])

    def tt_send_grant(self, trace, time, core, id, offset, priority):
        self.append(trace, id, "send_grant", [time, offset, priority])

    def tt_sendmsg_request(self, trace, time, core, peer, id, length):
        stats = trace['rpc_lifecycle']
        if not id in stats:
            stats[id] = {}
        stats[id]['sendmsg'] = time
        stats[id]['out_length'] = length

    def tt_sendmsg_response(self, trace, time, core, id, length):
        stats = trace['rpc_lifecycle']
        if not id in stats:
            stats[id] = {}
        stats[id]['sendmsg'] = time
        stats[id]['out_length'] = length

    def tt_recvmsg_done(self, trace, time, core, id, length):
        stats = trace['rpc_lifecycle']
        if not id in stats:
            stats[id] = {}
        stats[id]['recvmsg_done'] = time

    def tt_copy_out_start(self, trace, time, core, id):
        stats = trace['rpc_lifecycle']
        if not id in stats:
            stats[id] = {}
        if not 'copy_out_start' in stats[id]:
            stats[id]['copy_out_start'] = time

    def tt_copy_out_done(self, trace, time, core, id, num_bytes):
        stats = trace['rpc_lifecycle']
        if not id in stats:
            stats[id] = {}
        stats[id]['copy_out_done'] = time

    def tt_copy_in_done(self, trace, time, core, id, num_bytes):
        stats = trace['rpc_lifecycle']
        if not id in stats:
            stats[id] = {}
        stats[id]['copy_in_done'] = time

    def print(self, traces):
        trace = traces[0]
        stats = trace['rpc_lifecycle']
        separator = ''

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
        for id, rpc in stats.items():
            if not (id & 1):
                # This is a client RPC
                if (not 'sendmsg' in rpc) or (not 'recvmsg_done' in rpc):
                    continue
                self.__collect_stats(client_phases, rpc, client_totals,
                        client_deltas)
                self.__collect_stats(client_extra, rpc, client_extra_totals,
                        client_extra_deltas)
            else:
                # This is a server RPC
                if (not 'gro_data' in rpc) or (rpc['gro_data'][0][1] != 0) \
                        or (not 'send_data' in rpc):
                    continue
                self.__collect_stats(server_phases, rpc, server_totals,
                        server_deltas)
                self.__collect_stats(server_extra, rpc, server_extra_totals,
                        server_extra_deltas)

        if client_totals:
            print(separator, end='')
            separator = '\n'
            print("Client RPCs:")
            self.__print_phases(client_phases, client_totals, client_deltas)
            print("")
            self.__print_phases(client_extra, client_extra_totals,
                    client_extra_deltas)
        if server_totals:
            print(separator, end='')
            separator = '\n'
            print("Server RPCs:")
            self.__print_phases(server_phases, server_totals, server_deltas)
            print("")
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
                t = phase[2](rpc[phase[1]])
                if i == 0:
                    start = prev = t
                totals[i].append(t - start)
                deltas[i].append(t - prev)

    def __print_phases(self, phases, totals, deltas):
        """
        Utility method used by print to print out summary statistics
        aggregated by __phase_stats
        """
        for i in range(1, len(phases)):
            label = phases[i][0]
            elapsed = sorted(totals[i])
            gaps = sorted(deltas[i])
            print("%-32s Avg %7.1f us (+%7.1f us)  P90 %7.1f us (+%7.1f us)" %
                (label, sum(elapsed)/len(elapsed), sum(gaps)/len(gaps),
                elapsed[9*len(elapsed)//10], gaps[9*len(gaps)//10]))

# Parse command line options
parser = OptionParser(description=
        'Analyze one or more Homa timetrace files and print information '
        'extracted from the file(s). Command-line arguments determine '
        'which analyses to perform.',
        usage='%prog [options] [trace trace ...]',
        conflict_handler='resolve')
parser.add_option('--analyzers', '-a', dest='analyzers', default='all',
        help="space-separated list of analyzers to apply to the trace files "
        "(default: all)")
parser.add_option('--verbose', '-v', action='store_true', default=False,
        dest='verbose',
        help='print additional output with more details')

(options, tt_files) = parser.parse_args()
if not tt_files:
    print("No trace files specified")
    exit(1)
d = Dispatcher()
for name in options.analyzers.split():
    d.interest('Analyze' + name[0].capitalize() + name[1:])
traces = []
for file in tt_files:
    traces.append({})
    d.parse(file, traces[-1])
for analyzer in d.get_analyzers():
    if hasattr(analyzer, "print"):
        analyzer.print(traces)