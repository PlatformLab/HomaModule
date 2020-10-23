#!/usr/bin/python3

# Copyright (c) 2020 Stanford University
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# This file contains library functions used to run cluster performance
# tests for the Linux kernel implementation of Homa.

import argparse
import copy
import datetime
import glob
import math
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import traceback

if platform.system() != "Windows":
    import fcntl

# If a server's id appears as a key in this dictionary, it means we
# have started cp_node running on that node. The value of each entry is
# a Popen object that can be used to communicate with the node.
active_nodes = {}

# If a server's id appears as a key in this dictionary, it means we
# have started homa_prio running on that node. The value of each entry is
# a Popen object for the homa_prio instance; if this is terminated, then
# the homa_prio process will end
homa_prios = {}

# The range of nodes currently running cp_node servers.
server_nodes = range(0,0)

# Directory containing log files.
log_dir = ''

# Open file (in the log directory) where log messages should be written.
log_file = 0

# Indicates whether we should generate additional log messages for debugging
verbose = False

# Defaults for command-line options, if the application doesn't specify its
# own values.
default_defaults = {
    'gbps':                0.0,
    # Note: very large numbers for client_max hurt Homa throughput with
    # unlimited load (throttle queue inserts take a long time).
    'client_max':          200,
    'client_ports':        5,
    'log_dir':             'logs/' + time.strftime('%Y%m%d%H%M%S'),
    'mtu':                 0,
    'no_trunc':            '',
    'protocol':            'homa',
    'port_receivers':      3,
    'port_threads':        2,
    'seconds':             5,
    'server_ports':        9,
    'tcp_client_ports':    9,
    'tcp_port_receivers':  1,
    'tcp_server_ports':    15,
    'tcp_port_threads':    1,
    'unloaded':            0,
    'unsched':             0,
    'unsched_boost':       0.0,
    'workload':            'w5'
}

# Keys are experiment names, and each value is the digested data for that
# experiment.  The digest is itself a dictionary containing some or all of
# the following keys:
# rtts:            A dictionary with message lengths as keys; each value is
#                  a list of the RTTs (in usec) for all messages of that length.
# total_messages:  Total number of samples in rtts.
# lengths:         Sorted list of message lengths, corresponding to buckets
#                  chosen for plotting
# cum_frac:        Cumulative fraction of all messages corresponding to each length
# counts:          Number of RTTs represented by each bucket
# p50:             List of 50th percentile rtts corresponding to each length
# p99:             List of 99th percentile rtts corresponding to each length
# p999:            List of 999th percentile rtts corresponding to each length
# slow_50:         List of 50th percentile slowdowns corresponding to each length
# slow_99:         List of 99th percentile slowdowns corresponding to each length
# slow_999:        List of 999th percentile slowdowns corresponding to each length
digests = {}

# A dictionary where keys are message lengths, and each value is the median
# unloaded RTT (usecs) for messages of that length.
unloaded_p50 = {}

# Keys are filenames, and each value is a dictionary containing data read
# from that file. Within that dictionary, each key is the name of a column
# within the file, and the value is a list of numbers read from the given
# column of the given file.
data_from_files = {}

# Time when this benchmark was run.
date_time = str(datetime.datetime.now())

# Standard colors for plotting
tcp_color =      '#00B000'
tcp_color2 =     '#5BD15B'
tcp_color3 =     '#96E296'
homa_color =     '#1759BB'
homa_color2 =    '#6099EE'
homa_color3 =    '#A6C6F6'
dctcp_color =    '#7A4412'
dctcp_color2 =   '#CB701D'
dctcp_color3 =   '#EAA668'
unloaded_color = '#d62728'

# Default bandwidths to use when running all of the workloads.
load_info = [["w1", 1.4], ["w2", 3.2], ["w3", 14], ["w4", 20], ["w5", 20]]

# PyPlot color circle colors:
pyplot_colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd',
        '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf']

def boolean(s):
    """
    Used as a "type" in argparse specs; accepts Boolean-looking things.
    """
    map = {'true': True, 'yes': True, 'ok': True, "1": True, 'y': True,
        't': True, 'false': False, 'no': False, '0': False, 'f': False,
        'n': False}
    lc = s.lower()
    if lc not in map:
        raise ValueError("Expected boolean value, got %s" % (s))
    return map[lc]

def log(message):
    """
    Write the a log message both to stdout and to the cperf log file.

    message:  The log message to write; a newline will be appended.
    """
    global log_file
    print(message)
    log_file.write(message)
    log_file.write("\n")

def vlog(message):
    """
    Log a message, like log, but if verbose logging isn't enabled, then
    log only to the cperf log file, not to stdout.

    message:  The log message to write; a newline will be appended.
    """
    global log_file, verbose
    if verbose:
        print(message)
    log_file.write(message)
    log_file.write("\n")

def get_parser(description, usage, defaults = {}):
    """
    Returns an ArgumentParser for options that are commonly used in
    performance tests.

    description:    A string describing the overall functionality of this
                    particular performance test
    usage:          A command synopsis (passed as usage to ArgumentParser)
    defaults:       A dictionary whose keys are option names and whose values
                    are defaults; used to modify the defaults for some of the
                    options (there is a default default for each option).
    """
    for key in default_defaults:
        if not key in defaults:
            defaults[key] = default_defaults[key]
    parser = argparse.ArgumentParser(description=description + ' The options '
            'below may include some that are not used by this particular '
            'benchmark', usage=usage, add_help=False,
            conflict_handler='resolve')
    parser.add_argument('-b', '--gbps', type=float, dest='gbps',
            metavar='B', default=defaults['gbps'],
            help='Generate a total of B Gbits/sec of bandwidth on the most '
            'heavily loaded machines; 0 means run as fast as possible '
            '(default: %.2f)' % (defaults['gbps']))
    parser.add_argument('--client-max', type=int, dest='client_max',
            metavar='count', default=defaults['client_max'],
            help='Maximum number of requests each client machine can have '
            'outstanding at a time (divided evenly among its ports) '
            '(default: %d)' % (defaults['client_max']))
    parser.add_argument('--client-ports', type=int, dest='client_ports',
            metavar='count', default=defaults['client_ports'],
            help='Number of ports on which each client should issue requests '
            '(default: %d)' % (defaults['client_ports']))
    parser.add_argument('--cperf-log', dest='cperf_log',
            metavar='F', default='cperf.log',
            help='Name to use for the cperf log file (default: cperf.log)')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true',
            help='Pause after starting servers to enable debugging setup')
    parser.add_argument('-h', '--help', action='help',
            help='Show this help message and exit')
    parser.add_argument('-l', '--log-dir', dest='log_dir',
            metavar='D', default=defaults['log_dir'],
            help='Directory to use for logs and metrics')
    parser.add_argument('--mtu', type=int, dest='mtu',
            required=False, metavar='M', default=defaults['mtu'],
            help='Maximum allowable packet size (0 means use existing, '
            'default: %d)' % (defaults['mtu']))
    parser.add_argument('-n', '--nodes', type=int, dest='num_nodes',
            required=True, metavar='N',
            help='Total number of nodes to use in the cluster')
    parser.add_argument('--no-homa-prio', dest='no_homa_prio',
            action='store_true', default=False,
            help='Don\'t run homa_prio on nodes to adjust unscheduled cutoffs')
    parser.add_argument('--plot-only', dest='plot_only', action='store_true',
            help='Don\'t run experiments; generate plot(s) with existing data')
    parser.add_argument('--port-receivers', type=int, dest='port_receivers',
            metavar='count', default=defaults['port_receivers'],
            help='Number of threads listening for responses on each Homa '
            'client port (default: %d)'% (defaults['port_receivers']))
    parser.add_argument('--port-threads', type=int, dest='port_threads',
            metavar='count', default=defaults['port_threads'],
            help='Number of threads listening on each Homa server port '
            '(default: %d)'% (defaults['port_threads']))
    parser.add_argument('-p', '--protocol', dest='protocol',
            choices=['homa', 'tcp', 'dctcp'], default=defaults['protocol'],
            help='Transport protocol to use (default: %s)'
            % (defaults['protocol']))
    parser.add_argument('-s', '--seconds', type=int, dest='seconds',
            metavar='S', default=defaults['seconds'],
            help='Run each experiment for S seconds (default: %.1f)'
            % (defaults['seconds']))
    parser.add_argument('--server-ports', type=int, dest='server_ports',
            metavar='count', default=defaults['server_ports'],
            help='Number of ports on which each server should listen '
            '(default: %d)'% (defaults['server_ports']))
    parser.add_argument('--tcp-client-ports', type=int, dest='tcp_client_ports',
            metavar='count', default=defaults['tcp_client_ports'],
            help='Number of ports on which each TCP client should issue requests '
            '(default: %d)'% (defaults['tcp_client_ports']))
    parser.add_argument('--tcp-port-receivers', type=int,
            dest='tcp_port_receivers', metavar='count',
            default=defaults['tcp_port_receivers'],
            help='Number of threads listening for responses on each TCP client '
            'port (default: %d)'% (defaults['tcp_port_receivers']))
    parser.add_argument('--tcp-port-threads', type=int, dest='tcp_port_threads',
            metavar='count', default=defaults['tcp_port_threads'],
            help='Number of threads listening on each TCP server port '
            '(default: %d)'% (defaults['port_threads']))
    parser.add_argument('--tcp-server-ports', type=int, dest='tcp_server_ports',
            metavar='count', default=defaults['tcp_server_ports'],
            help='Number of ports on which TCP servers should listen '
            '(default: %d)'% (defaults['tcp_server_ports']))
    parser.add_argument('--unsched', type=int, dest='unsched',
            metavar='count', default=defaults['unsched'],
            help='If nonzero, homa_prio will always use this number of '
            'unscheduled priorities, rather than computing from workload'
            '(default: %d)'% (defaults['unsched']))
    parser.add_argument('--unsched-boost', type=float, dest='unsched_boost',
            metavar='float', default=defaults['unsched'],
            help='Increase the number of unscheduled priorities that homa_prio '
            'assigns by this (possibly fractional) amount (default: %.2f)'
            % (defaults['unsched_boost']))
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
            help='Enable verbose output in node logs')
    parser.add_argument('-w', '--workload', dest='workload',
            metavar='W', default=defaults['workload'],
            help='Workload to use for benchmark: w1-w5 or number, empty '
            'means try each of w1-w5 (default: %s)'
            % (defaults['workload']))
    return parser

def init(options):
    """
    Initialize various global state, such as the log file.
    """
    global log_dir, log_file, verbose
    log_dir = options.log_dir
    if not options.plot_only:
        if os.path.exists(log_dir):
            shutil.rmtree(log_dir)
        os.makedirs(log_dir)
        os.makedirs(log_dir + "/reports")
    log_file = open("%s/reports/%s" % (log_dir, options.cperf_log), "a")
    verbose = options.verbose
    vlog("cperf starting at %s" % (date_time))
    s = ""
    opts = vars(options)
    for name in sorted(opts.keys()):
        if len(s) != 0:
            s += ", "
        s += ("--%s: %s" % (name, str(opts[name])))
    vlog("Options: %s" % (s))
    if options.mtu != 0:
        log("Setting MTU to %d" % (options.mtu))
        do_ssh(["set_mtu", str(options.mtu)], range(0, options.num_nodes))

def wait_output(string, nodes, cmd, time_limit=10.0):
    """
    This method waits until a particular string has appeared on the stdout of
    each of the nodes in the list given by nodes. If a long time goes by without
    the string appearing, an exception is thrown.
    string:      The value to wait for
    cmd:         Used in error messages to indicate the command that failed
    time_limit:  An error will be generated if this much time goes by without
                 the desired string appearing
    """
    global active_nodes
    outputs = []
    printed = False

    for id in nodes:
        while len(outputs) <= id:
            outputs.append("")
    start_time = time.time()
    while time.time() < (start_time + time_limit):
        for id in nodes:
            data = active_nodes[id].stdout.read(1000)
            if data != None:
                print_data = data
                if print_data.endswith(string):
                    print_data = print_data[:(len(data) - len(string))]
                if print_data != "":
                    log("output from node-%d: '%s'" % (id, print_data))
                outputs[id] += data
        bad_node = -1
        for id in nodes:
            if not string in outputs[id]:
                bad_node = id
                break
        if bad_node < 0:
            return
        if (time.time() > (start_time + time_limit)) and not printed:
            log("expected output from node-%d not yet received "
            "after command '%s': expecting '%s', got '%s'"
            % (bad_node, cmd, string, outputs[bad_node]))
            printed = True;
        time.sleep(0.1)
    raise Exception("bad output from node-%d after command '%s': "
            "expected '%s', got '%s'"
            % (bad_node, cmd, string, outputs[bad_node]))

def start_nodes(r, options):
    """
    Start up cp_node on a group of nodes.

    r:        The range of nodes on which to start cp_node, if it isn't already
              running
    options:  Command-line options that may affect experiment
    """
    global active_nodes
    started = []
    for id in r:
        if id in active_nodes:
            continue
        vlog("Starting cp_node on node-%d" % (id))
        node = subprocess.Popen(["ssh", "-o", "StrictHostKeyChecking=no",
                "node-%d" % (id), "cp_node"], encoding="utf-8",
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
        fl = fcntl.fcntl(node.stdin, fcntl.F_GETFL)
        fcntl.fcntl(node.stdin, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        fl = fcntl.fcntl(node.stdout, fcntl.F_GETFL)
        fcntl.fcntl(node.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        active_nodes[id] = node
        if not options.no_homa_prio:
            f = open("%s/homa_prio-%d.log" % (log_dir,id), "w")
            homa_prios[id] = subprocess.Popen(["ssh", "-o",
                    "StrictHostKeyChecking=no", "node-%d" % (id), "sudo",
                    "bin/homa_prio", "--interval", "500", "--unsched",
                    str(options.unsched), "--unsched-boost",
                    str(options.unsched_boost)], encoding="utf-8",
                    stdout=f, stderr=subprocess.STDOUT)
            f.close
        started.append(id)
    wait_output("% ", started, "ssh")
    log_level = "normal"
    if verbose:
        log_level = "verbose"
    command = "log --file node.log --level %s" % (log_level)
    for id in started:
        active_nodes[id].stdin.write(command + "\n")
        active_nodes[id].stdin.flush()
    wait_output("% ", started, command)

def stop_nodes():
    """
    Exit all of the nodes that are currently active.
    """
    global active_nodes, server_nodes
    for id, popen in homa_prios.items():
        subprocess.run(["ssh", "-o", "StrictHostKeyChecking=no",
                "node-%d" % id, "sudo", "pkill", "homa_prio"])
        try:
            popen.wait(5.0)
        except subprocess.TimeoutExpired:
            log("Timeout killing homa_prio on node-%d" % (id))
    for node in active_nodes.values():
        node.stdin.write("exit\n")
        try:
            node.stdin.flush()
        except BrokenPipeError:
            log("Broken pipe to node-%d" % (id))
    for node in active_nodes.values():
        node.wait(5.0)
    for id in active_nodes:
        subprocess.run(["rsync", "-rtvq", "node-%d:node.log" % (id),
                "%s/node-%d.log" % (log_dir, id)])
    active_nodes.clear()
    server_nodes = range(0,0)

def do_cmd(command, r, r2 = range(0,0)):
    """
    Execute a cp_node command on a given group of nodes.

    command:    A command to execute on each node
    r:          A group of node ids on which to run the command (range, list, etc.)
    r2:         An optional additional group of node ids on which to run the
                command; if a note is present in both r and r2, the
                command will only be performed once
    """
    global active_nodes
    nodes = []
    for id in r:
        nodes.append(id)
    for id in r2:
        if id not in r:
            nodes.append(id)
    for id in nodes:
        vlog("Command for node-%d: %s" % (id, command))
        active_nodes[id].stdin.write(command + "\n")
        try:
            active_nodes[id].stdin.flush()
        except BrokenPipeError:
            log("Broken pipe to node-%d" % (id))
    wait_output("% ", nodes, command)

def do_ssh(command, nodes):
    """
    Use ssh to execute a particular shell command on a group of nodes.

    command:  command to execute on each node (a list of argument words)
    nodes:    specifies ids of the nodes on which to execute the command:
              should be a range, list, or other object that supports "in"
    """
    vlog("ssh command on nodes %s: %s" % (str(nodes), " ".join(command)))
    for id in nodes:
        subprocess.run(["ssh", "node-%d" % id] + command,
                stdout=subprocess.DEVNULL)

def get_sysctl_parameter(name):
    """
    Retrieve the value of a particular system parameter using sysctl on
    the current host, and return the value as a string.

    name:      name of the desired configuration parameter
    """
    output = subprocess.run(["sysctl", name], stdout=subprocess.PIPE,
            encoding="utf-8").stdout.rstrip()
    match = re.match('.*= (.*)', output)
    if not match:
         raise Error("Couldn't parse sysctl output: %s" % output)
    return match.group(1)

def set_sysctl_parameter(name, value, nodes):
    """
    Modify the value of a system parameter on a group of nodes.

    name:     name of the sysctl configuration parameter to modify
    value:    desired value for the parameter
    nodes:    specifies ids of the nodes on which to execute the command:
              should be a range, list, or other object that supports "in"
    """
    vlog("Setting Homa parameter %s to %s on nodes %s" % (name, value,
            str(nodes)))
    for id in nodes:
        subprocess.run(["ssh", "node-%d" % id, "sudo", "sysctl",
                "%s=%s" % (name, value)], stdout=subprocess.DEVNULL)

def start_servers(r, options):
    """
    Starts cp_node servers running on a group of nodes

    r:       A group of node ids on which to start cp_node servers
    options: A namespace that must contain at least the following
             keys, which will be used to configure the servers:
                 server_ports
                 port_threads
                 protocol
    """
    global server_nodes
    log("Starting %s servers %d:%d" % (options.protocol, r.start, r.stop-1))
    if len(server_nodes) > 0:
        do_cmd("stop servers", server_nodes)
        server_nodes = range(0,0)
    start_nodes(r, options)
    if options.protocol == "homa":
        do_cmd("server --ports %d --port-threads %d --protocol %s" % (
                options.server_ports, options.port_threads,
                options.protocol), r)
    else:
        do_cmd("server --ports %d --port-threads %d --protocol %s" % (
                options.tcp_server_ports, options.tcp_port_threads,
                options.protocol), r)
    server_nodes = r

def run_experiment(name, clients, options):
    """
    Starts cp_node clients running on a group of nodes, lets the clients run
    for an amount of time given by options.seconds, and gathers statistics.

    name:     Identifier for this experiment, which is used in the names
              of files created in the log directory.
    clients:  List of node numbers on which to run clients
    options:  A namespace that must contain at least the following attributes,
              which control the experiment:
                  client_max
                  client_ports
                  first_server
                  gbps
                  port_receivers
                  protocol
                  seconds
                  server_nodes
                  server_ports
                  tcp_client_ports
                  tcp_server_ports
                  workload
    """

    global active_nodes
    start_nodes(clients, options)
    nodes = []
    log("Starting %s experiment with clients %d:%d" % (
            name, clients.start, clients.stop-1))
    num_servers = len(server_nodes)
    if "server_nodes" in options:
        num_servers = options.server_nodes
    first_server = server_nodes.start
    if "first_server" in options:
        first_server = options.first_server
    for id in clients:
        if options.protocol == "homa":
            command = "client --ports %d --port-receivers %d --server-ports %d " \
                    "--workload %s --server-nodes %d --first-server %d " \
                    "--gbps %.3f --client-max %d --protocol %s --id %d" % (
                    options.client_ports,
                    options.port_receivers,
                    options.server_ports,
                    options.workload,
                    num_servers,
                    first_server,
                    options.gbps,
                    options.client_max,
                    options.protocol,
                    id);
            if "unloaded" in options:
                command += " --unloaded %d" % (options.unloaded)
        else:
            if "no_trunc" in options:
                trunc = '--no-trunc'
            else:
                trunc = ''
            command = "client --ports %d --port-receivers %d --server-ports %d " \
                    "--workload %s --server-nodes %d --first-server %d " \
                    "--gbps %.3f %s --client-max %d --protocol %s --id %d" % (
                    options.tcp_client_ports,
                    options.tcp_port_receivers,
                    options.tcp_server_ports,
                    options.workload,
                    num_servers,
                    first_server,
                    options.gbps,
                    trunc,
                    options.client_max,
                    options.protocol,
                    id);
        active_nodes[id].stdin.write(command + "\n")
        try:
            active_nodes[id].stdin.flush()
        except BrokenPipeError:
            log("Broken pipe to node-%d" % (id))
        nodes.append(id)
        vlog("Command for node-%d: %s" % (id, command))
    wait_output("% ", nodes, command, 40.0)
    if not "unloaded" in options:
        if options.protocol == "homa":
            # Wait a bit so that homa_prio can set priorities appropriately
            time.sleep(2)
            vlog("Recording initial metrics")
            for id in active_nodes:
                subprocess.run(["ssh", "node-%d" % (id), "metrics.py"],
                        stdout=subprocess.DEVNULL)
        if not "no_rtt_files" in options:
            do_cmd("dump_times /dev/null", clients)
        do_cmd("log Starting %s experiment" % (name), server_nodes, clients)
        debug_delay = 0
        # time.sleep(debug_delay)
        # do_cmd("debug 240000000 480000000", clients);
        time.sleep(options.seconds - debug_delay)
        do_cmd("log Ending %s experiment" % (name), server_nodes, clients)
    log("Retrieving data for %s experiment" % (name))
    if not "no_rtt_files" in options:
        do_cmd("dump_times rtts", clients)
    if options.protocol == "homa":
        vlog("Recording final metrics")
        for id in active_nodes:
            f = open("%s/%s-%d.metrics" % (options.log_dir, name, id), 'w')
            subprocess.run(["ssh", "node-%d" % (id), "metrics.py"], stdout=f);
            f.close()
        shutil.copyfile("%s/%s-%d.metrics" % (options.log_dir, name, first_server),
                "%s/reports/%s.metrics" % (options.log_dir, name))
    do_cmd("stop senders", clients)
    # if "homa" in name:
        # do_cmd("tt print cp.tt", clients)
    # do_ssh(["sudo", "sysctl", ".net.homa.log_topic=3"], clients)
    # do_ssh(["sudo", "sysctl", ".net.homa.log_topic=2"], clients)
    # do_ssh(["sudo", "sysctl", ".net.homa.log_topic=1"], clients)
    do_cmd("stop clients", clients)
    if not "no_rtt_files" in options:
        for id in clients:
            subprocess.run(["rsync", "-rtvq", "node-%d:rtts" % (id),
                    "%s/%s-%d.rtts" % (options.log_dir, name, id)])

def scan_log(file, node, experiments):
    """
    Read a log file and extract various useful information, such as fatal
    error messages or interesting statistics.

    file:         Name of the log file to read
    node:         Name of the node that generated the log, such as "node-1".
    experiments:  Info from the given log file is added to this structure
                  * At the top level it is dictionary indexed by experiment
                    name, where
                  * Each value is dictionary indexed by node name, where
                  * Each value is a dictionary with keys such as client_kops,
                    client_gbps, client_latency, server_kops, or server_Mbps,
                    each of which is
                  * A list of values measured at regular intervals for that node
    """
    exited = False
    experiment = ""
    node_data = None

    for line in open(file):
        match = re.match('.*Starting (.*) experiment', line)
        if match:
            experiment = match.group(1)
            if not experiment in experiments:
                experiments[experiment] = {}
            if not node in experiments[experiment]:
                experiments[experiment][node] = {}
            node_data = experiments[experiment][node]
            continue
        if re.match('.*Ending .* experiment', line):
            experiment = ""
        if experiment != "":
            gbps = -1.0
            match = re.match('.*Clients: ([0-9.]+) Kops/sec, '
                        '([0-9.]+) Gbps.*P50 ([0-9.]+)', line)
            if match:
                gbps = float(match.group(2))
            else:
                match = re.match('.*Clients: ([0-9.]+) Kops/sec, '
                            '([0-9.]+) MB/sec.*P50 ([0-9.]+)', line)
                if match:
                    gbps = 8.0*float(match.group(2))
            if gbps >= 0.0:
                if not "client_kops" in node_data:
                    node_data["client_kops"] = []
                node_data["client_kops"].append(float(match.group(1)))
                if not "client_gbps" in node_data:
                    node_data["client_gbps"] = []
                node_data["client_gbps"].append(gbps)
                if not "client_latency" in node_data:
                    node_data["client_latency"] = []
                node_data["client_latency"].append(float(match.group(3)))
                continue

            gbps = -1.0
            match = re.match('.*Servers: ([0-9.]+) Kops/sec, '
                    '([0-9.]+) Gbps', line)
            if match:
                gbps = float(match.group(2))
            else:
                match = re.match('.*Servers: ([0-9.]+) Kops/sec, '
                            '([0-9.]+) MB/sec', line)
                if match:
                    gbps = 8.0*float(match.group(2))
            if gbps >= 0.0:
                if not "server_kops" in node_data:
                    node_data["server_kops"] = []
                node_data["server_kops"].append(float(match.group(1)))
                if not "server_gbps" in node_data:
                    node_data["server_gbps"] = []
                node_data["server_gbps"].append(gbps)
                continue

            match = re.match('.*Outstanding client RPCs: ([0-9.]+)', line)
            if match:
                if not "outstanding_rpcs" in node_data:
                    node_data["outstanding_rpcs"] = []
                node_data["outstanding_rpcs"].append(int(match.group(1)))
                continue

            match = re.match('.*Backed-up sends: ([0-9.]+)/([0-9.]+)', line)
            if match:
                if not "backups" in node_data:
                    node_data["backups"] = []
                node_data["backups"].append(float(match.group(1))
                        /float(match.group(2)))
                continue
        if "FATAL:" in line:
            log("%s: %s" % (file, line[:-1]))
            exited = True
        if "ERROR:" in line:
            log("%s: %s" % (file, line[:-1]))
        if "cp_node exiting" in line:
            exited = True
    if not exited:
        log("%s appears to have crashed (didn't exit)" % (node))

def scan_logs():
    """
    Read all of the node-specific log files produced by a run, and
    extract useful information.
    """
    global log_dir, verbose

    # This value is described in the header doc for scan_log.
    experiments = {}

    for file in sorted(glob.glob(log_dir + "/node-*.log")):
        node = re.match('.*/(node-[0-9]+)\.log', file).group(1)
        scan_log(file, node, experiments)

    for name, exp in experiments.items():
        totals = {}
        nodes = {}
        nodes["client"] = {}
        nodes["server"] = {}
        nodes["all"] = {}

        for type in ['client', 'server']:
            gbps_key = type + "_gbps"
            kops_key = type + "_kops"
            averages = []
            vlog("\n%ss for %s experiment:" % (type.capitalize(), name))
            for node in sorted(exp.keys()):
                if not gbps_key in exp[node]:
                    if name.startswith("unloaded"):
                        exp[node][gbps_key] = [0.0]
                        exp[node][kops_key] = [0.0]
                    else:
                        continue
                gbps = exp[node][gbps_key]
                avg = sum(gbps)/len(gbps)
                vlog("%s: %.2f Gbps (%s)" % (node, avg,
                    ", ".join(map(lambda x: "%.1f" % (x), gbps))))
                averages.append(avg)
                nodes["all"][node] = 1
                nodes[type][node] = 1
            if len(averages) > 0:
                totals[gbps_key] = sum(averages)
                vlog("%s average: %.2f Gbps\n"
                        % (type.capitalize(), totals[gbps_key]/len(averages)))

            averages = []
            for node in sorted(exp.keys()):
                key = type + "_kops"
                if not kops_key in exp[node]:
                    continue
                kops = exp[node][kops_key]
                avg = sum(kops)/len(kops)
                vlog("%s: %.1f Kops/sec (%s)" % (node, avg,
                    ", ".join(map(lambda x: "%.1f" % (x), kops))))
                averages.append(avg)
                nodes["all"][node] = 1
                nodes[type][node] = 1
            if len(averages) > 0:
                totals[kops_key] = sum(averages)
                vlog("%s average: %.1f Kops/sec"
                        % (type.capitalize(), totals[kops_key]/len(averages)))

        log("\nClients for %s experiment: %d nodes, %.2f Gbps, %.1f Kops/sec "
                "(avg per node)" % (name, len(nodes["client"]),
                totals["client_gbps"]/len(nodes["client"]),
                totals["client_kops"]/len(nodes["client"])))
        log("Servers for %s experiment: %d nodes, %.2f Gbps, %.1f Kops/sec "
                "(avg per node)" % (name, len(nodes["server"]),
                totals["server_gbps"]/len(nodes["server"]),
                totals["server_kops"]/len(nodes["server"])))
        log("Overall for %s experiment: %d nodes, %.2f Gbps, %.1f Kops/sec "
                "(avg per node)" % (name, len(nodes["all"]),
                (totals["client_gbps"] + totals["server_gbps"])/len(nodes["all"]),
                (totals["client_kops"] + totals["server_kops"])/len(nodes["all"])))

        for node in sorted(exp.keys()):
            if "outstanding_rpcs" in exp[node]:
                counts = exp[node]["outstanding_rpcs"]
                log("Outstanding RPCs for %s: %s" % (node,
                        ", ".join(map(lambda x: "%d" % (x), counts))))
                break

        backups = []
        for node in sorted(exp.keys()):
            if "backups" in exp[node]:
                fracs = exp[node]["backups"]
                vlog("Backed-up RPCs for %s: %s" % (node,
                        ", ".join(map(lambda x: "%.1f%%" % (100.0*x), fracs))))
                backups.extend(fracs)
        if len(backups) > 0:
            log("Average rate of backed-up RPCs: %.1f%%"
                    % (100.0*sum(backups)/len(backups)))
    log("")

def read_rtts(file, rtts):
    """
    Read a file generated by cp_node's "dump_times" command and add its
    data to the information present in rtts.

    file:    Name of the log file.
    rtts:    Dictionary whose keys are message lengths; each value is a
             list of all of the rtts recorded for that message length (in usecs)
    Returns: The total number of rtts read from the file.
    """

    total = 0
    f = open(file, "r")
    for line in f:
        stripped = line.strip();
        if stripped[0] == '#':
            continue
        words = stripped.split()
        if (len(words) < 2):
            print("Line in %s too short (need at least 2 columns): '%s'" %
                    (file, line))
            continue
        length = int(words[0])
        usec = float(words[1])
        if length in rtts:
            rtts[length].append(usec)
        else:
            rtts[length] = [usec]
        total += 1
    f.close()
    return total

def get_buckets(rtts, total):
    """
    Generates buckets for histogramming the information in rtts.

    rtts:     A collection of message rtts, as returned by read_rtts
    total:    Total number of samples in rtts
    Returns:  A list of <length, cum_frac> pairs, in sorted order. The length
              is the largest message size for a bucket, and cum_frac is the
              fraction of all messages with that length or smaller.
    """
    buckets = []
    cumulative = 0
    for length in sorted(rtts.keys()):
        cumulative += len(rtts[length])
        buckets.append([length, cumulative/total])
    return buckets

def set_unloaded(experiment):
    """
    Compute the optimal RTTs for each message size.
    
    experiment:   Name of experiment that measured RTTs under low load
    """
    
    # Find (or generate) unloaded data for comparison.
    files = sorted(glob.glob("%s/%s-*.rtts" % (log_dir, experiment)))
    if len(files) == 0:
        raise Exception("Couldn't find %s RTT data" % (experiment))
    rtts = {}
    for file in files:
        read_rtts(file, rtts)
    unloaded_p50.clear()
    for length in rtts.keys():
        unloaded_p50[length] = sorted(rtts[length])[len(rtts[length])//2]
    vlog("Computed unloaded_p50: %d entries" % len(unloaded_p50))

def get_digest(experiment):
    """
    Returns an element of digest that contains data for a particular
    experiment; if this is the first request for a given experiment, the
    method reads the data for experiment and generates the digest. For
    each new digest generated, a .data file is generated in the "reports"
    subdirectory of the log directory.

    experiment:  Name of the desired experiment
    """
    global digests, log_dir, unloaded_p50

    if experiment in digests:
        return digests[experiment]
    digest = {}
    digest["rtts"] = {}
    digest["total_messages"] = 0
    digest["lengths"] = []
    digest["cum_frac"] = []
    digest["counts"] = []
    digest["p50"] = []
    digest["p99"] = []
    digest["p999"] = []
    digest["slow_50"] = []
    digest["slow_99"] = []
    digest["slow_999"] = []

    # Read in the RTT files for this experiment.
    files = sorted(glob.glob(log_dir + ("/%s-*.rtts" % (experiment))))
    if len(files) == 0:
        raise Exception("Couldn't find RTT data for %s experiment"
                % (experiment))
    sys.stdout.write("Reading RTT data for %s experiment: " % (experiment))
    sys.stdout.flush()
    for file in files:
        digest["total_messages"] += read_rtts(file, digest["rtts"])
        sys.stdout.write("#")
        sys.stdout.flush()
    print("")
    
    if len(unloaded_p50) == 0:
        raise Exception("No unloaded data: must invoked set_unloaded")

    rtts = digest["rtts"]
    buckets = get_buckets(rtts, digest["total_messages"])
    bucket_length, bucket_cum_frac = buckets[0]
    next_bucket = 1
    bucket_rtts = []
    bucket_slowdowns = []
    bucket_count = 0
    cur_unloaded = unloaded_p50[min(unloaded_p50.keys())]
    lengths = sorted(rtts.keys())
    lengths.append(999999999)            # Force one extra loop iteration
    for length in lengths:
        if length > bucket_length:
            digest["lengths"].append(bucket_length)
            digest["cum_frac"].append(bucket_cum_frac)
            digest["counts"].append(bucket_count)
            if len(bucket_rtts) == 0:
                bucket_rtts.append(0)
                bucket_slowdowns.append(0)
            bucket_rtts = sorted(bucket_rtts)
            digest["p50"].append(bucket_rtts[bucket_count//2])
            digest["p99"].append(bucket_rtts[bucket_count*99//100])
            digest["p999"].append(bucket_rtts[bucket_count*999//1000])
            bucket_slowdowns = sorted(bucket_slowdowns)
            digest["slow_50"].append(bucket_slowdowns[bucket_count//2])
            digest["slow_99"].append(bucket_slowdowns[bucket_count*99//100])
            digest["slow_999"].append(bucket_slowdowns[bucket_count*999//1000])
            if next_bucket >= len(buckets):
                break
            bucket_rtts = []
            bucket_slowdowns = []
            bucket_count = 0
            bucket_length, bucket_cum_frac = buckets[next_bucket]
            next_bucket += 1
        if length in unloaded_p50:
            cur_unloaded = unloaded_p50[length]
        bucket_count += len(rtts[length])
        for rtt in rtts[length]:
            bucket_rtts.append(rtt)
            bucket_slowdowns.append(rtt/cur_unloaded)
    log("Digest finished for %s" % (experiment))

    dir = "%s/reports" % (log_dir)
    f = open("%s/reports/%s.data" % (log_dir, experiment), "w")
    f.write("# Digested data for %s experiment, run at %s\n"
            % (experiment, date_time))
    f.write("# length  cum_frac  samples     p50      p99     p999   "
            "s50    s99    s999\n")
    for i in range(len(digest["lengths"])):
        f.write(" %7d %9.6f %8d %7.1f %8.1f %8.1f %5.1f %6.1f %7.1f\n"
                % (digest["lengths"][i], digest["cum_frac"][i],
                digest["counts"][i], digest["p50"][i], digest["p99"][i],
                digest["p999"][i], digest["slow_50"][i],
                digest["slow_99"][i], digest["slow_999"][i]))
    f.close()

    digests[experiment] = digest
    return digest

def start_slowdown_plot(title, max_y, x_experiment, size=10,
        show_top_label=True, show_bot_label=True, figsize=[6,4],
        y_label="Slowdown"):
    """
    Create a pyplot graph that will be used for slowdown data. Returns the
    Axes object for the plot.

    title:           Title for the plot; may be empty
    max_y:           Maximum y-coordinate
    x_experiment:    Name of experiment whose rtt distribution will be used to
                     label the x-axis of the plot. None means don't label the
                     x-axis (caller will presumably invoke cdf_xaxis to do it).
    size:            Size to use for fonts
    show_top_label:  True means display title text for upper x-axis
    show_bot_label:  True means display title text for lower x-axis
    figsize:         Dimensions of plot
    y_label:         Label for the y-axis
    """

    fig = plt.figure(figsize=figsize)
    ax = fig.add_subplot(111)
    if title != "":
        ax.set_title(title, size=size)
    ax.set_xlim(0, 1.0)
    ax.set_yscale("log")
    ax.set_ylim(1, max_y)
    ax.tick_params(right=True, which="both", direction="in", length=5)
    ticks = []
    labels = []
    y = 1
    while y <= max_y:
        ticks.append(y);
        labels.append("%d" % (y))
        y = y*10
    ax.set_yticks(ticks)
    ax.set_yticklabels(labels, size=size)
    if show_bot_label:
        ax.set_xlabel("Message Length", size=size)
    ax.set_ylabel(y_label, size=size)
    ax.grid(which="major", axis="y")

    top_axis = ax.twiny()
    top_axis.tick_params(axis="x", direction="in", length=5)
    top_axis.set_xlim(0, 1.0)
    top_ticks = []
    top_labels = []
    for x in range(0, 11, 2):
        top_ticks.append(x/10.0)
        top_labels.append("%d%%" % (x*10))
    top_axis.set_xticks(top_ticks)
    top_axis.set_xticklabels(top_labels, size=size)
    if show_top_label:
        top_axis.set_xlabel("Cumulative % of Messages", size=size)
    top_axis.xaxis.set_label_position('top')

    if x_experiment != None: 
        # Generate x-axis labels
        ticks = []
        labels = []
        cumulative_count = 0
        target_count = 0
        tick = 0
        digest = get_digest(x_experiment)
        rtts = digest["rtts"]
        total = digest["total_messages"]
        for length in sorted(rtts.keys()):
            cumulative_count += len(rtts[length])
            while cumulative_count >= target_count:
                ticks.append(target_count/total)
                if length < 1000:
                    labels.append("%.0f" % (length))
                elif length < 100000:
                    labels.append("%.1fK" % (length/1000))
                elif length < 1000000:
                    labels.append("%.0fK" % (length/1000))
                else:
                    labels.append("%.1fM" % (length/1000000))
                tick += 1
                target_count = (total*tick)/10
        ax.set_xticks(ticks)
        ax.set_xticklabels(labels, size=size)
    return ax

def cdf_xaxis(ax, x_values, counts, num_ticks, size=10):
    """
    Generate labels for an x-axis that is scaled nonlinearly to reflect
    a particular distribution of samples.
    
    ax:       matplotlib Axes object for the plot
    x:        List of x-values
    counts:   List giving the number of samples for each point in x
    ticks:    Total number of ticks go generate (including axis ends)
    size:     Font size to use for axis labels
    """

    ticks = []
    labels = []
    total = sum(counts)
    cumulative_count = 0
    target_count = 0
    tick = 0
    for (x, count) in zip(x_values, counts):
        cumulative_count += count
        while cumulative_count >= target_count:
            ticks.append(target_count/total)
            if x < 1000:
                labels.append("%.0f" % (x))
            elif x < 100000:
                labels.append("%.1fK" % (x/1000))
            elif x < 1000000:
                labels.append("%.0fK" % (x/1000))
            else:
                labels.append("%.1fM" % (x/1000000))
            tick += 1
            target_count = (total*tick)/(num_ticks-1)
    ax.set_xticks(ticks)
    ax.set_xticklabels(labels, size=size)
        

def make_histogram(x, y, init=None, after=True):
    """
    Given x and y coordinates, return new lists of coordinates that describe
    a histogram (transform (x1,y1) and (x2,y2) into (x1,y1), (x2,y1), (x2,y2)
    to make steps.

    x:        List of x-coordinates
    y:        List of y-coordinates corresponding to x
    init:     An optional initial point (x and y coords) which will be
              plotted before x and y
    after:    True means the horizontal line corresponding to each
              point occurs to the right of that point; False means to the
              left
    Returns:  A list containing two lists, one with new x values and one
              with new y values.
    """
    x_new = []
    y_new = []
    if init:
        x_new.append(init[0]);
        y_new.append(init[1]);
    for i in range(len(x)):
        if i != 0:
            if after:
                x_new.append(x[i])
                y_new.append(y[i-1])
            else:
                x_new.append(x[i-1])
                y_new.append(y[i])
        x_new.append(x[i])
        y_new.append(y[i])
    return [x_new, y_new]

def plot_slowdown(ax, experiment, percentile, label, **kwargs):
    """
    Add a slowdown histogram to a plot.

    ax:            matplotlib Axes object: info will be plotted here.
    experiment:    Name of the experiment whose data should be graphed.
    percentile:    While percentile of slowdown to graph: must be "p50", "p99",
                   or "p999"
    label:         Text to display in the graph legend for this curve
    kwargs:        Additional keyword arguments to pass through to plt.plot
    """

    digest = get_digest(experiment)
    if percentile == "p50":
        x, y = make_histogram(digest["cum_frac"], digest["slow_50"],
                init=[0, digest["slow_50"][0]], after=False)
    elif percentile == "p99":
        x, y = make_histogram(digest["cum_frac"], digest["slow_99"],
                init=[0, digest["slow_99"][0]], after=False)
    elif percentile == "p999":
        x, y = make_histogram(digest["cum_frac"], digest["slow_999"],
                init=[0, digest["slow_999"][0]], after=False)
    else:
        raise Exception("Bad percentile selector %s; must be p50, p99, or p999"
                % (percentile))
    ax.plot(x, y, label=label, **kwargs)

def start_cdf_plot(title, min_x, max_x, min_y, x_label, y_label,
        figsize=[5, 4], size=10):
    """
    Create a pyplot graph that will be display a complementary CDF with
    log axes.

    title:      Overall title for the graph (empty means no title)
    min_x:       Smallest x-coordinate that must be visible
    max_x:       Largest x-coordinate that must be visible
    min_y:       Smallest y-coordinate that must be visible (1.0 is always
                 the largest value for y)
    x_label:     Label for the x axis (empty means no label)
    y_label:     Label for the y axis (empty means no label)
    figsize:     Dimensions of plot
    size:        Size to use for fonts
    """
    plt.figure(figsize=figsize)
    if title != "":
        plt.title(title, size=size)
    plt.axis()
    plt.xscale("log")
    ax = plt.gca()

    # Round out the x-axis limits to even powers of 10.
    exp = math.floor(math.log(min_x , 10))
    min_x = 10**exp
    exp = math.ceil(math.log(max_x, 10))
    max_x = 10**exp
    plt.xlim(min_x, max_x)
    ticks = []
    tick = min_x
    while tick <= max_x:
        ticks.append(tick)
        tick = tick*10
    plt.xticks(ticks)
    plt.tick_params(top=True, which="both", direction="in", labelsize=size,
            length=5)

    plt.yscale("log")
    plt.ylim(min_y, 1.0)
    # plt.yticks([1, 10, 100, 1000], ["1", "10", "100", "1000"])
    if x_label:
        plt.xlabel(x_label, size=size)
    if y_label:
        plt.ylabel(y_label, size=size)
    plt.grid(which="major", axis="y")
    plt.grid(which="major", axis="x")
    plt.plot([min_x, max_x*1.2], [0.5, 0.5], linestyle= (0, (5, 3)),
            color="red", clip_on=False)
    plt.text(max_x*1.3, 0.5, "P50", fontsize=16, horizontalalignment="left",
            verticalalignment="center", color="red", size=size)
    plt.plot([min_x, max_x*1.2], [0.01, 0.01], linestyle= (0, (5, 3)),
            color="red", clip_on=False)
    plt.text(max_x*1.3, 0.01, "P99", fontsize=16, horizontalalignment="left",
            verticalalignment="center", color="red", size=size)

def get_short_cdf(experiment):
    """
    Return a complementary CDF histogram for the RTTs of short messages in
    an experiment. Short messages means all messages shorter than 1500 bytes
    that are also among the 10% of shortest messages (if there are no messages
    shorter than 1500 bytes, then extract data for the shortest message
    length available). This function also saves the data in a file in the
    reports directory.

    experiment:  Name of the experiment containing the data to plot
    Returns:     A list with two elements (a list of x-coords and a list
                 of y-coords) that histogram the complementary cdf.
    """
    global log_dir, date_time
    short = []
    digest = get_digest(experiment)
    rtts = digest["rtts"]
    messages_left = digest["total_messages"]//10
    longest = 0
    for length in sorted(rtts.keys()):
        if (length >= 1500) and (len(short) > 0):
            break
        short.extend(rtts[length])
        messages_left -= len(rtts[length])
        longest = length
        if messages_left < 0:
            break
    vlog("Largest message used for short CDF for %s: %d"
            % (experiment, longest))
    x = []
    y = []
    total = len(short)
    remaining = total
    f = open("%s/reports/%s_cdf.data" % (log_dir, experiment), "w")
    f.write("# Fraction of RTTS longer than a given time for %s experiment\n"
            % (experiment));
    f.write("# Includes messages <= %d bytes; measured at %s\n"
            % (longest, date_time))
    f.write("# Data collected at %s \n" % (date_time))
    f.write("#       usec        frac\n")

    # Reduce the volume of data by waiting to add new points until there
    # has been a significant change in either coordinate. "prev" variables hold
    # the last point actually graphed.
    prevx = 0
    prevy = 1.0
    for rtt in sorted(short):
        remaining -= 1
        frac = remaining/total
        if (prevy != 0) and (prevx != 0) and (abs((frac - prevy)/prevy) < .01) \
                and (abs((rtt - prevx)/prevx) < .01):
            continue;
        if len(x) > 0:
            x.append(rtt)
            y.append(prevy)
        x.append(rtt)
        y.append(frac)
        f.write("%12.3f  %.8f\n" % (rtt, frac))
        prevx = rtt
        prevy = frac
    f.close()
    return [x, y]

def column_from_file(file, column):
    """
    Return a list containing a column of data from a given file.

    file:    Path to the file containing the desired data.
    column:  Name of the column within the file.
    """

    global data_from_files
    if file in data_from_files:
        return data_from_files[file][column]

    data = {}
    last_comment = ""
    columns = []
    for line in open(file):
        fields = line.strip().split()
        if len(fields) == 0:
            continue
        if fields[0] == '#':
            last_comment = line
            continue
        if len(columns) == 0:
            # Parse column names
            if len(last_comment) == 0:
                raise Exception("no columns headers in data file '%s'" % (file))
            columns = last_comment.split()
            columns.pop(0)
            for c in columns:
                data[c] = []
        for i in range(0, len(columns)):
                data[columns[i]].append(float(fields[i]))
    data_from_files[file] = data
    return data[column]