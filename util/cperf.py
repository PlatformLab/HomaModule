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
import fcntl
import glob
import math
import matplotlib.pyplot as plt
import numpy as np
import os
import re
import shutil
import subprocess
import sys
import time
import traceback

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
    'net_bw':              0.0,
    'client_max':          2000,
    'client_ports':        5,
    'log_dir':             'logs/' + time.strftime('%Y%m%d%H%M%S'),
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

# Standard colors for plotting
tcp_color =      '#00B000'
tcp_color2 =     '#5BD15B'
tcp_color3 =     '#96E296'
homa_color =     '#1759BB'
homa_color2 =    '#4287EC'
dctcp_color =    '#985416'
dctcp_color2 =   '#E59247'
unloaded_color = '#d62728'

# Default bandwidths to use when running all of the workloads.
load_info = [["w1", 0.18], ["w2", 0.4], ["w3", 1.8], ["w4", 2.4], ["w5", 2.4]]

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
    parser.add_argument('-b', '--net-bw', type=float, dest='net_bw',
            metavar='B', default=defaults['net_bw'],
            help='Generate a total of B Gbits/sec of bandwidth from each '
            'client machine; 0 means run as fast as possible (default: %.2f)'
            % (defaults['net_bw']))
    parser.add_argument('--client-max', type=int, dest='client_max',
            metavar='count', default=defaults['client_max'],
            help='Maximum number of requests each client machine can have '
            'outstanding at a time (divided evenly among its ports) '
            '(default: %d)' % (defaults['client_max']))
    parser.add_argument('--client-ports', type=int, dest='client_ports',
            metavar='count', default=defaults['client_ports'],
            help='Number of ports on which each client should issue requests '
            '(default: %d)' % (defaults['client_ports']))
    parser.add_argument('-d', '--debug', dest='debug', action='store_true',
            help='Pause after starting servers to enable debugging setup')
    parser.add_argument('-h', '--help', action='help',
            help='Show this help message and exit')
    parser.add_argument('-l', '--log-dir', dest='log_dir',
            metavar='D', default=defaults['log_dir'],
            help='Directory to use for logs and metrics')
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
    log_file = open("%s/cperf.log" % log_dir, "a")
    verbose = options.verbose

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
        popen.wait(5.0)
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
                  net_bw
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
                    "--net-bw %.3f --client-max %d --protocol %s --id %d" % (
                    options.client_ports,
                    options.port_receivers,
                    options.server_ports,
                    options.workload,
                    num_servers,
                    first_server,
                    options.net_bw,
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
                    "--net-bw %.3f %s --client-max %d --protocol %s --id %d" % (
                    options.tcp_client_ports,
                    options.tcp_port_receivers,
                    options.tcp_server_ports,
                    options.workload,
                    num_servers,
                    first_server,
                    options.net_bw,
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
    wait_output("% ", nodes, command, 30.0)
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
        time.sleep(options.seconds)
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
    do_cmd("stop senders", clients)
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
                  * Each value is a dictionary with keys client_kops,
                    client_mbps, client_latency, server_kops, or server_Mbps,
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
            match = re.match('.*Clients: ([0-9.]+) Kops/sec, '
                        '([0-9.]+) MB/sec.*P50 ([0-9.]+)', line)
            if match:
                if not "client_kops" in node_data:
                    node_data["client_kops"] = []
                node_data["client_kops"].append(float(match.group(1)))
                if not "client_mbps" in node_data:
                    node_data["client_mbps"] = []
                node_data["client_mbps"].append(float(match.group(2)))
                if not "client_latency" in node_data:
                    node_data["client_latency"] = []
                node_data["client_latency"].append(float(match.group(3)))
                continue

            match = re.match('.*Servers: ([0-9.]+) Kops/sec, '
                    '([0-9.]+) MB/sec', line)
            if match:
                if not "server_kops" in node_data:
                    node_data["server_kops"] = []
                node_data["server_kops"].append(float(match.group(1)))
                if not "server_mbps" in node_data:
                    node_data["server_mbps"] = []
                node_data["server_mbps"].append(float(match.group(2)))
                continue

            match = re.match('.*Outstanding client RPCs: ([0-9.]+)', line)
            if match:
                if not "outstanding_rpcs" in node_data:
                    node_data["outstanding_rpcs"] = []
                node_data["outstanding_rpcs"].append(int(match.group(1)))
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
            mbps_key = type + "_mbps"
            kops_key = type + "_kops"
            averages = []
            vlog("\n%ss for %s experiment:" % (type.capitalize(), name))
            for node in sorted(exp.keys()):
                if not mbps_key in exp[node]:
                    if name.startswith("unloaded"):
                        exp[node][mbps_key] = [0.0]
                        exp[node][kops_key] = [0.0]
                    else:
                        continue
                mbps = exp[node][mbps_key]
                avg = sum(mbps)/len(mbps)
                vlog("%s: %.1f MB/sec (%s)" % (node, avg,
                    ", ".join(map(lambda x: "%.1f" % (x), mbps))))
                averages.append(avg)
                nodes["all"][node] = 1
                nodes[type][node] = 1
            if len(averages) > 0:
                totals[mbps_key] = sum(averages)
                vlog("%s average: %.1f MB/sec\n"
                        % (type.capitalize(), totals[mbps_key]/len(averages)))

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

        log("\nClients for %s experiment: %d nodes, %.1f MB/sec, %.1f Kops/sec "
                "(avg per node)" % (name, len(nodes["client"]),
                totals["client_mbps"]/len(nodes["client"]),
                totals["client_kops"]/len(nodes["client"])))
        log("Servers for %s experiment: %d nodes, %.1f MB/sec, %.1f Kops/sec "
                "(avg per node)" % (name, len(nodes["server"]),
                totals["server_mbps"]/len(nodes["server"]),
                totals["server_kops"]/len(nodes["server"])))
        log("Overall for %s experiment: %d nodes, %.1f MB/sec, %.1f Kops/sec "
                "(avg per node)" % (name, len(nodes["all"]),
                (totals["client_mbps"] + totals["server_mbps"])/len(nodes["all"]),
                (totals["client_kops"] + totals["server_kops"])/len(nodes["all"])))

        for node in sorted(exp.keys()):
            if "outstanding_rpcs" in exp[node]:
                counts = exp[node]["outstanding_rpcs"]
                log("Outstanding RPCs for %s: %s" % (node,
                        ", ".join(map(lambda x: "%d" % (x), counts))))
                break

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
    Computes a reasonable set of the buckets for histogramming the information
    in rtts. We don't want super-small buckets because the statistics will be
    bad, so this method merges several message sizes if needed to ensure
    that each bucket has a reasonable number of messages.

    rtts:     A collection of message rtts, as returned by read_rtts
    total:    Total number of samples in rtts
    Returns:  A list of <length, cum_frac> pairs, in sorted order. The length
              is the largest message size for a bucket, and cum_frac is the
              fraction of all messages with that length or smaller.
    """
    buckets = []
    min_size = total//400
    cur_bucket_count = 0
    cumulative = 0
    for length in sorted(rtts.keys()):
        samples = len(rtts[length])
        cur_bucket_count += samples
        cumulative += samples
        if cur_bucket_count >= min_size:
            buckets.append([length, cumulative/total])
            cur_bucket_count = 0
        last_length = length
    if cur_bucket_count != 0:
        buckets[-1] = [last_length, 1.0]
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
    if not os.path.exists(dir):
        os.makedirs(dir)
    f = open("%s/reports/%s.data" % (log_dir, experiment), "w")
    f.write("# Digested data for %s experiment\n" % (experiment))
    f.write("# length cum_frac  samples     p50      p99     p999   "
            "s50    s99    s999\n")
    for i in range(len(digest["lengths"])):
        f.write(" %7d %8.3f %8d %7.1f %8.1f %8.1f %5.1f %6.1f %7.1f\n"
                % (digest["lengths"][i], digest["cum_frac"][i],
                digest["counts"][i], digest["p50"][i], digest["p99"][i],
                digest["p999"][i], digest["slow_50"][i],
                digest["slow_99"][i], digest["slow_999"][i]))
    f.close()

    digests[experiment] = digest
    return digest

def start_slowdown_plot(title, max_y, x_experiment):
    """
    Create a pyplot graph that will be used for slowdown data.

    title:         Title for the plot; may be empty
    max_y:         Maximum y-coordinate
    x_experiment:  Name of experiment whose rtt distribution will be used to
                   label the x-axis of the plot
    """

    plt.figure(figsize=[6, 4])
    if title != "":
        plt.title(title)
    plt.rcParams.update({'font.size': 10})
    plt.axis()
    plt.xlim(0, 1.0)
    plt.yscale("log")
    plt.ylim(1, max_y)
    ticks = []
    labels = []
    y = 1
    while y <= max_y:
        ticks.append(y);
        labels.append("%d" % (y))
        y = y*10
    plt.yticks(ticks, labels)
    plt.xlabel("Message Length")
    plt.ylabel("Slowdown")
    plt.grid(which="major", axis="y")

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
    plt.xticks(ticks, labels)

def make_histogram(x, y):
    """
    Given x and y coordinates, return new lists of coordinates that describe
    a histogram (transform (x1,y1) and (x2,y2) into (x1,y1), (x2,y1), (x2,y2)
    to make steps.

    x:        List of x-coordinates
    y:        List of y-coordinates corresponding to x
    Returns:  A list containing two lists, one with new x values and one
              with new y values.
    """
    x_new = []
    y_new = []
    for i in range(len(x)):
        if len(x_new) != 0:
            x_new.append(x[i])
            y_new.append(y[i-1])
        else:
            x_new.append(0)
            y_new.append(y[i])
        x_new.append(x[i])
        y_new.append(y[i])
    return [x_new, y_new]

def plot_slowdown(experiment, percentile, label, **kwargs):
    """
    Add a slowdown histogram to the current graph.

    experiment:    Name of the experiment whose data should be graphed.
    percentile:    While percentile of slowdown to graph: must be "p50", "p99",
                   or "p999"
    label:         Text to display in the graph legend for this curve
    kwargs:        Additional keyword arguments to pass through to plt.plot
    """

    digest = get_digest(experiment)
    if percentile == "p50":
        x, y = make_histogram(digest["cum_frac"], digest["slow_50"])
    elif percentile == "p99":
        x, y = make_histogram(digest["cum_frac"], digest["slow_99"])
    elif percentile == "p999":
        x, y = make_histogram(digest["cum_frac"], digest["slow_999"])
    else:
        raise Exception("Bad percentile selector %s; must be p50, p99, or p999"
                % (percentile))
    plt.plot(x, y, label=label, **kwargs)

def start_cdf_plot(title, min_x, max_x, min_y, x_label, y_label):
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
    """
    plt.figure(figsize=[5, 4])
    if title != "":
        plt.title(title)
    plt.rcParams.update({'font.size': 10})
    plt.axis()
    plt.xscale("log")

    # Round out the x-axis limits to even powers of 10.
    exp = math.floor(math.log(min_x , 10))
    min_x = 10**exp
    exp = math.ceil(math.log(max_x, 10))
    max_x = 10**exp
    plt.xlim(min_x, max_x)

    plt.yscale("log")
    plt.ylim(min_y, 1.0)
    # plt.yticks([1, 10, 100, 1000], ["1", "10", "100", "1000"])
    if x_label:
        plt.xlabel(x_label)
    if y_label:
        plt.ylabel(y_label)
    plt.grid(which="major", axis="y")
    plt.grid(which="major", axis="x")

def get_short_cdf(experiment):
    """
    Return a complementary CDF histogram for the RTTs of short messages in
    an experiment. Short messages means all messages shorter than 1500 bytes
    that are also among the 10% of shortest messages (if there are no messages
    shorter than 1500 bytes, then extract data for the shortest message
    length available).

    experiment:  Name of the experiment containing the data to plot
    Returns:     A list with two elements (a list of x-coords and a list
                 of y-coords) that histogram the complementary cdf.
    """
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
    for rtt in sorted(short):
        if len(x) > 0:
            x.append(rtt)
            y.append(remaining/total)
        remaining -= 1
        x.append(rtt)
        y.append(remaining/total)
    return [x, y]