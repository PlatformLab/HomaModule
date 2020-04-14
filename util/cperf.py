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

# The range of nodes currently running cp_node servers.
server_nodes = range(0,0)

# Directory containing log files.
log_dir = ''

# Open file (in the log directory) where log messages should be written.
log_file = 0

# Indicates whether we should generate additional log messages for debugging
verbose = False

# Defaults for command-line options, if the application doesn's specify its
# own values..
default_defaults = {
    'net_bw':         0.0,
    'client_ports':   4,
    'log_dir':        'logs/' + time.strftime('%Y%m%d%H%M%S'),
    'protocol':       'homa',
    'port_max':       500,
    'port_receivers': 3,
    'port_threads':   2,
    'seconds':        5,
    'server_max':     500,
    'server_ports':   8,
    'workload':       'w3'
}

def log(message):
    """
    Write the message argument, followed by a newline, both to stdout and to
    the cperf log file.
    """
    global log_file
    print(message)
    log_file.write(message)
    log_file.write("\n")

def vlog(message):
    """
    Log a message, like log, but if verbose blogging isn't enabled, then
    log only to the cperf log file, not to stdou
    """
    global log_file, verbose
    if verbose:
        print(message)
    log_file.write(message)
    log_file.write("\n")

def get_parser(description, usage, defaults = {}):
    """
    Returns an ArgumentParser for options that are commonly used in
    performance tests. The description argument is a string describing the
    overall functionality of this particular performance test. Usage is
    a command synopsis (passed as usage to ArgumentParser. Defaults is
    a dictionary that can be used to modify the defaults for some of the
    options (there is a default default for each option).
    """
    for key in default_defaults:
        if not key in defaults:
            defaults[key] = default_defaults[key]
    parser = argparse.ArgumentParser(description=description + ' The options '
            'below may include some that are not used by this particular '
            'benchmark', usage=usage,add_help=False)
    parser.add_argument('-b', '--net-bw', type=float, dest='net_bw',
            metavar='B', default=defaults['net_bw'],
            help='Generate a total of B Gbits/sec of bandwidth from each '
            'client machine; 0 means run as fast as possible (default: %.2f)'
            % (defaults['net_bw']))
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
    parser.add_argument('-p', '--protocol', dest='protocol',
            choices=['homa', 'tcp'], default=defaults['protocol'],
            help='Transport protocol to use (default: %s)'
            % (defaults['protocol']))
    parser.add_argument('--port-max', type=int, dest='port_max',
            metavar='count', default=defaults['port_max'],
            help='Maximum number of requests each client thread can have '
            'outstanding at a time (default: %d)'
            % (defaults['port_max']))
    parser.add_argument('--port-receivers', type=int, dest='port_receivers',
            metavar='count', default=defaults['port_receivers'],
            help='Number of threads listening for responses on each client '
            'port (default: %d)'% (defaults['port_receivers']))
    parser.add_argument('--port-threads', type=int, dest='port_threads',
            metavar='count', default=defaults['port_threads'],
            help='Number of threads listening on each Homa server port '
            '(default: %d)'% (defaults['port_threads']))
    parser.add_argument('-s', '--seconds', type=int, dest='seconds',
            metavar='S', default=defaults['seconds'],
            help='Run each experiment for S seconds (default: %.1f)'
            % (defaults['seconds']))
    parser.add_argument('--server-max', type=int, dest='server_max',
            metavar='count', default=defaults['server_max'],
            help='Maximum number of requests a single client thread can have '
            'outstanding to a single server port at a time (default: %d)'
            % (defaults['server_max']))
    parser.add_argument('--server-ports', type=int, dest='server_ports',
            metavar='count', default=defaults['server_ports'],
            help='Number of ports on which each server should listen '
            '(default: %d)'% (defaults['server_ports']))
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
            help='Enable verbose output in node logs')
    parser.add_argument('-w', '--workload', dest='workload',
            metavar='W', default=defaults['workload'],
            help='Workload to use for benchmark (w1-w5 or number, default: %s)'
            % (defaults['workload']))
    return parser

def init(options):
    """
    Initialize various global state, such as the log file.
    """
    global log_dir, log_file, verbose
    if os.path.exists(options.log_dir):
        shutil.rmtree(options.log_dir)
    log_dir = options.log_dir
    os.makedirs(log_dir)
    log_file = open("%s/cperf.log" % log_dir, "w")
    verbose = options.verbose

def wait_output(string, nodes, cmd):
    """
    This method waits until the given string has appeared on the stdout of
    each of the nodes in the list given by nodes. If a long time goes by without
    the string appearing, an exception is thrown; the cmd argument is used
    in the error message to indicate the command that failed.
    """
    global active_nodes
    outputs = []
    printed = False

    for id in nodes:
        while len(outputs) <= id:
            outputs.append("")
    start_time = time.time()
    while time.time() < (start_time + 5.0):
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
        if (time.time() > (start_time + 5.0)) and not printed:
            log("expected output from node-%d not yet received "
            "after command '%s': expecting '%s', got '%s'"
            % (bad_node, cmd, string, outputs[bad_node]))
            printed = True;
        time.sleep(0.1)
    raise Exception("bad output from node-%d after command '%s': "
            "expected '%s', got '%s'"
            % (bad_node, cmd, string, outputs[bad_node]))

def start_nodes(r):
    """
    Start up cp_node on nodes with ids in the range given by r,
    if it isn't already running.
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
        started.append(id)
    wait_output("% ", started, "ssh")
    log_level = "normal"
    if verbose:
        log_level = "verbose"
    do_cmd("log --file node.log --level %s\n" % (log_level), r)

def stop_nodes():
    """
    Exit all of the nodes that are currently running.
    """
    global active_nodes
    for node in active_nodes.values():
        node.stdin.write("exit\n")
        node.stdin.flush()
    for node in active_nodes.values():
        node.wait(5.0)
    for id in active_nodes:
        subprocess.run(["rsync", "-rtvq", "node-%d:node.log" % (id),
                "%s/node-%d.log" % (log_dir, id)])
    active_nodes.clear();

def do_cmd(command, r, r2 = range(0,0)):
    """
    Execute a cp_node command on the range of nodes given by r and r2, and
    wait for the command to complete on each node. The command need
    be terminated by a newline. If there is overlap between r and r2, the
    overlapping nodes will perform the command only once.
    """
    global active_nodes
    nodes = []
    for id in r:
        nodes.append(id)
    for id in r2:
        if id not in r:
            nodes.append(id)
    for id in nodes:
        vlog("Command for node-%d: %s" % (id, command[:-1]))
        active_nodes[id].stdin.write(command)
        active_nodes[id].stdin.flush()
    wait_output("% ", nodes, command)

def start_servers(r, options):
    """
    Starts cp_node servers running on nodes whose ids fall in the range given
    by r. Options is a dictionary that must contain at least the following
    keys, which will be used to configure the servers:
    server_ports
    port_threads
    protocol
    """
    global server_nodes
    if len(server_nodes) > 0:
        do_cmd("stop servers", server_nodes)
        server_nodes = range(0,0)
    start_nodes(r)
    do_cmd("server --ports %d --port-threads %d --protocol %s\n" % (
            options.server_ports, options.port_threads,
            options.protocol), r)
    server_nodes = r

def run_experiment(name, clients, options):
    """
    Starts cp_node clients running on nodes in the range given by clients,
    lets the clients run for an amount of time given by options.seconds,
    and gathers statistics. Name is an identifier for this experiment, which
    is used in the name of files created in the log directory. Options is a
    namespace that must contain at least the following attributes, which control
    the experiment:
    client_ports
    first_server
    net_bw
    port_max
    port_receivers
    protocol
    seconds
    server_max
    server_nodes
    server_ports
    workload
    """

    global active_nodes
    start_nodes(clients)
    nodes = []
    log("Starting %s experiment with clients %d-%d" % (
            name, clients.start, clients.stop-1))
    num_servers = len(server_nodes)
    if "server_nodes" in options:
        num_servers = options.server_nodes
    first_server = server_nodes.start
    if "first_server" in options:
        first_server = options.first_server
    for id in clients:
        command = "client --ports %d --port-receivers %d --server-ports %d " \
                "--workload %s --server-nodes %d --first-server %d " \
                "--net-bw %.3f --port-max %d --server-max %d --protocol %s " \
                "--id %d\n" % (
                options.client_ports,
                options.port_receivers,
                options.server_ports,
                options.workload,
                num_servers,
                first_server,
                options.net_bw,
                options.port_max,
                options.server_max,
                options.protocol,
                id);
        active_nodes[id].stdin.write(command)
        active_nodes[id].stdin.flush()
        nodes.append(id)
        vlog("Command for node-%d: %s" % (id, command[:-1]))
    wait_output("% ", nodes, command)
    vlog("Recording initial metrics")
    for id in clients:
        subprocess.run(["ssh", "node-%d" % (id), "metrics.py"],
                stdout=subprocess.DEVNULL)
    do_cmd("dump_times /dev/null\n", clients)
    do_cmd("log Starting %s experiment\n" % (name), server_nodes, clients)
    time.sleep(options.seconds)
    do_cmd("log Ending %s experiment\n" % (name), server_nodes, clients)
    log("Retrieving data for %s experiment" % (name))
    do_cmd("dump_times rtts\n", clients)
    for id in clients:
        f = open("%s/%s-%d.metrics" % (options.log_dir, name, id), 'w')
        subprocess.run(["ssh", "node-%d" % (id), "metrics.py"], stdout=f);
        f.close()
    do_cmd("stop clients\n", clients)
    for id in clients:
        subprocess.run(["rsync", "-rtvq", "node-%d:rtts" % (id),
                "%s/%s-%d.rtts" % (options.log_dir, name, id)])

def scan_log(file_name, node, experiments):
    """
    Read a single log file and extract various useful information,
    such as fatal error messages or interesting statistics. The node
    parameter gives the name of the node that generated the log, such
    as "node-1". The experiments argument is:
       * A dictionary indexed by experiment name, where each value is:
       * A dictionary indexed by node name, where each value is:
       * A dictionary with keys client_kops, client_mbps, server_kops,
         or server_Mbps, each of which is:
       * A list of values measured at regular intervals for that node.
    This method adds adds information from the given log file to the
    experiments structure.
    """
    exited = False
    experiment = ""
    node_data = None

    for line in open(file_name):
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
            match = re.match('.*(Clients|Servers): ([0-9.]+) Kops/sec, '
                        '([0-9.]+) MB/sec', line)
            if match:
                if match.group(1) == "Clients":
                    type = "client"
                else:
                    type = "server"
                key = type + "_kops"
                if not key in node_data:
                    node_data[key] = []
                node_data[key].append(float(match.group(2)))
                key = type + "_mbps"
                if not key in node_data:
                    node_data[key] = []
                node_data[key].append(float(match.group(3)))
        if "FATAL:" in line:
            log("%s: %s" % (file, line))
            exited = True
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