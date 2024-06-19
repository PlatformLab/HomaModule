#!/usr/bin/python3

# Copyright (c) 2019-2023 Homa Developers
# SPDX-License-Identifier: BSD-1-Clause

"""
Reads Homa metrics from the kernel and prints out anything that is changed
since the last time this program was invoked.
Usage: metrics.py [file]

If file is specified, it gives the name of a file in which this program
saves current metrics each time it is run, so that the next run can determine
what has changed. File defaults to ~/.homa_metrics.
"""

from __future__ import division, print_function
from glob import glob
from optparse import OptionParser
import math
import os
import re
import string
import sys

# Both prev and cur below are arrays of dictionaries: each element of
# the array stores information for one core in the form of a dictionary,
# where keys are metric names and values are metric values.
prev = []
cur = []

# List of metric names, in the order in which they appeared in the
# input file.
symbols = []

# Maps from metric name to the difference in total counts between new
# and old data.
deltas = {}

# Maps from metric name to the documentation for that metric.
docs = {}

# Read in metrics, parse the results for internal use, and, optionally
# copy the raw metrics to an output file. Also reinitialize symbols

def read_metrics(metrics_file, out):
    """
    Read metrics from the file whose name is "metrics_file" and generate
    a data structure in the format described above for "prev". In
    addition, if out is not None, write the raw metrics to that file.
    Returns the parsed metrics.
    """

    global symbols, docs
    symbols.clear()
    metrics = []
    metrics.append({})
    core = 0
    f = open(metrics_file)
    for line in f:
        if out:
            out.write(line)

        match = re.match('^([^ ]*) *([0-9]+) *(.*)', line)
        if not match:
            print("Ignoring bogus line in metrics file %s: %s" %
                    (metrics_file, line))
            continue
        symbol = match.group(1)
        count = int(match.group(2))
        doc = match.group(3)
        if symbol == "core":
            core = count
            while len(metrics) <= core:
                metrics.append({})
            continue
        if core == 0:
            symbols.append(symbol)
            docs[symbol] = doc
        metrics[core][symbol] = count
    f.close()
    return metrics

def scale_number(number):
    """
    Return a string describing a number, but with a "K", "M", or "G"
    suffix to keep the number small and readable
    """

    if number > 1e9:
        return "%5.1f G" % (number/1e9)
    elif number > 1000000:
        return "%5.1f M" % (number/1000000.0)
    elif (number > 1000):
        return "%5.1f K" % (number/1000.0)
    else:
        return "%5.1f  " % (number)

# Read the metrics saved the last time we ran, as well as the new
# metrics.

if len(sys.argv) > 1:
    data_file = sys.argv[1]
else:
    data_file = os.path.expanduser("~") + "/.homa_metrics"
try:
    prev = read_metrics(data_file, None)
except IOError:
    prev = []
    pass
data = open(data_file, "w")
cur = read_metrics("/proc/net/homa_metrics", data)
data.close()
num_cores = len(cur)

# Sum all of the individual core counts for both the new and old data and
# compute the difference in "deltas"
for symbol in symbols:
    if (symbol == "rdtsc_cycles") or (symbol == "cpu_khz") or (symbol == "core"):
        # This symbol shouldn't be summed.
        continue
    total_cur = 0
    for core in cur:
        total_cur += core[symbol]
    total_prev = 0
    for core in prev:
        total_prev += core[symbol]
    delta = total_cur - total_prev
    deltas[symbol] = delta

time_delta = 0
total_packets = 0
total_received_bytes = 0
gro_packets = 0
elapsed_secs = 0
reaper_calls = 0
pad = ""
cpu_khz = float(cur[0]["cpu_khz"])

if len(prev) > 0:
    time_delta = cur[0]["rdtsc_cycles"] - prev[0]["rdtsc_cycles"]
    elapsed_secs = float(time_delta)/(cpu_khz * 1000.0)
    pad = pad.ljust(13)
    secs = "(%.1f s)" % (elapsed_secs)
    secs = secs.ljust(12)
    print("%-28s %15d %s %s" % ("rdtsc_cycles", time_delta, secs,
            docs["rdtsc_cycles"]))
else:
    print("%-15s %28d %s%s" % ("rdtsc_cycles", cur[0]["rdtsc_cycles"],
            "", docs["rdtsc_cycles"]))

print("%-28s           %5.2f %sCPU clock rate (GHz)" % ("clock_rate",
        cpu_khz/1e06, pad))

for symbol in symbols:
    if (symbol == "rdtsc_cycles") or (symbol == "cpu_khz"):
        # This symbol is handled specially above
        continue
    delta = deltas[symbol]
    doc = docs[symbol]
    if delta != 0:
        rate_info = ""
        if (time_delta != 0):
            rate = float(delta)/elapsed_secs
            rate_info = ("(%s/s) " % (scale_number(rate))).ljust(13)
        if ("msg_bytes" in symbol) and (symbol != "sent_msg_bytes"):
            total_received_bytes += delta
        if symbol.endswith("_cycles") and (time_delta != 0):
            percent = "(%.1f%%)" % (100.0*delta/time_delta)
            percent = percent.ljust(12)
            print("%-28s %15d %s %s" % (symbol, delta, percent, doc))
        elif symbol.endswith("_queued") and (time_delta != 0):
            received = deltas[symbol[:-7] + "_received"]
            if received != 0:
                percent = "(%.1f%%)" % (100.0*float(delta)/float(received))
            else:
                percent = " "
            percent = percent.ljust(12)
            print("%-28s %15d %s %s" % (symbol, delta, percent, doc))
        else:
            print("%-28s %15d %s%s" % (symbol, delta, rate_info, doc))
            if symbol.startswith("packets_rcvd_"):
                total_packets += delta
            if symbol == "softirq_calls":
                gro_packets = delta
        if (symbol == "reaper_dead_skbs") and ("reaper_calls" in deltas):
            print("%-28s          %6.1f %sAvg. hsk->dead_skbs in reaper" % (
                  "avg_dead_skbs", delta/deltas["reaper_calls"], pad))
        if symbol.endswith("_miss_cycles") and (time_delta != 0):
            prefix = symbol[:-12]
            if ((prefix + "_misses") in deltas) and (deltas[prefix + "_misses"] != 0):
                ns = (delta/deltas[prefix + "_misses"])/(cpu_khz * 1e-06)
                print("%-28s          %6.1f %sAvg. wait time per %s miss (ns)" % (
                    prefix + "_miss_delay", ns, pad, prefix))
    if (symbol == "large_msg_bytes") and (total_received_bytes != 0) \
            and (time_delta != 0):
        rate = float(total_received_bytes)/elapsed_secs
        rate_info = ("(%s/s) " % (scale_number(rate))).ljust(13)
        print("%-28s %15d %s%s" % ("received_msg_bytes", total_received_bytes,
                rate_info, "Total bytes in all incoming messages"))
if gro_packets != 0:
    print("%-28s          %6.2f %sHoma packets per homa_softirq call" % (
          "gro_benefit", float(total_packets)/float(gro_packets), pad))
avg_grantable_rpcs = 0.0
if ("grantable_rpcs_integral" in deltas) and (time_delta != 0):
    avg_grantable_rpcs = float(deltas["grantable_rpcs_integral"])/time_delta
    print("%-28s          %6.2f %sAverage number of grantable incoming RPCs" % (
          "avg_grantable_rpcs", avg_grantable_rpcs, pad))

if elapsed_secs != 0:
    print("\nPer-Core CPU Usage:")
    print("-------------------")
    totals = []
    busiest_core = 0
    while len(totals) < num_cores:
        totals.append(0.0)
    cores_per_line = 8
    for first_core in range(0, num_cores, cores_per_line):
        if first_core != 0:
            print("")
        end_core = first_core + cores_per_line
        if end_core > num_cores:
            end_core = num_cores
        line = "             "
        for core in range(first_core, end_core):
            line += "  Core%-2d" % (core)
        print(line)
        for where in ["napi", "softirq", "send", "recv", "reply",
                "timer", "pacer"]:
            if where == "softirq":
                symbol = "linux_softirq_cycles"
            else:
                symbol = where + "_cycles"
            line = "%-10s  " % (where)
            for core in range(first_core, end_core):
                frac = float(cur[core][symbol] - prev[core][symbol]) / float(
                        time_delta)
                line += "   %5.2f" % (frac)
                totals[core] += frac
            print(line)
        line = "Total       "
        for core in range(first_core, end_core):
            line += "   %5.2f" % (totals[core])
            if totals[core] > totals[busiest_core]:
                busiest_core = core
        print(line)
    print("\nBusiest core: %d (%.2f)" % (busiest_core, totals[busiest_core]))
    other_busy = ""
    for core in range(0, num_cores):
        if (totals[core] >= 0.8) and (core != busiest_core):
            if other_busy:
                other_busy += ", "
            other_busy += " %d (%.2f)" % (core, totals[core]);
    if other_busy:
        print("Other busy cores: %s" % (other_busy))

    packets_received = 0.0
    packets_sent = 0.0
    for symbol in symbols:
        if symbol.startswith("packets_rcvd_"):
            packets_received += deltas[symbol]
        if symbol.startswith("packets_sent_"):
            packets_sent += deltas[symbol]

    print("\nOverall Core Utilization:")
    print("-------------------------")
    total_cores_used = 0.0
    total_syscalls = 0

    time = float(deltas["send_cycles"])
    cores = time/time_delta
    total_cores_used += cores
    calls = float(deltas["send_calls"])
    total_syscalls += calls
    if calls == 0:
        us_per = 0
    else:
        us_per = (time/calls)/(cpu_khz/1e03)
    print("send syscall                %6.2f   %7.2f us/syscall" % (cores, us_per))

    time = float(deltas["recv_cycles"]) - float(deltas["poll_cycles"])
    cores = time/time_delta
    total_cores_used += cores
    calls = float(deltas["recv_calls"])
    total_syscalls += calls
    if calls == 0:
        us_per = 0
    else:
        us_per = (time/calls)/(cpu_khz/1e03)
    print("recv syscall (-poll)        %6.2f   %7.2f us/syscall" % (cores, us_per))

    time = float(deltas["reply_cycles"])
    cores = time/time_delta
    total_cores_used += cores
    calls = float(deltas["reply_calls"])
    total_syscalls += calls
    if calls == 0:
        us_per = 0
    else:
        us_per = (time/calls)/(cpu_khz/1e03)
    print("reply syscall               %6.2f   %7.2f us/syscall" % (cores, us_per))

    for print_name, symbol in [["NAPI", "napi_cycles"],
            ["  Bypass homa_softirq", "bypass_softirq_cycles"],
            ["Linux SoftIRQ", "linux_softirq_cycles"],
            ["  Normal homa_softirq", "softirq_cycles"]]:
        cpu_time = float(deltas[symbol])
        cores = cpu_time/time_delta
        if packets_received > 0:
            print("%s      %6.2f   %7.2f us/packet" % (print_name.ljust(22),
                    cores, (cpu_time/packets_received) / (cpu_khz/1e03)))
        else:
            print("%s      %6.2f" % (print_name.ljust(22), cores))
    cpu_time = float(deltas["napi_cycles"])
    if cpu_time == 0:
        cpu_time = float(deltas["bypass_softirq_cycles"])
    total_cores_used += cpu_time/time_delta
    cpu_time = float(deltas["linux_softirq_cycles"])
    if cpu_time == 0:
        cpu_time = float(deltas["softirq_cycles"])
    total_cores_used += cpu_time/time_delta

    for print_name, symbol in [["Pacer", "pacer_cycles"],
            ["Timer handler", "timer_cycles"]]:
        cpu_time = float(deltas[symbol])
        cores = cpu_time/time_delta
        total_cores_used += cores
        print("%s      %6.2f" % (print_name.ljust(22), cores))

    print("----------------------------------")
    print("Total Core Utilization      %6.2f" % (total_cores_used))

    time = float(deltas["poll_cycles"])
    cores = time/time_delta
    calls = float(deltas["recv_calls"])
    if calls == 0:
        us_per = 0
    else:
        us_per = (time/calls)/(cpu_khz/1e03)
    print("")
    print("Polling in recv             %6.2f   %7.2f us/syscall" % (cores, us_per))

    calls = deltas["skb_allocs"]
    if calls == 0:
        us_per = 0
    else:
        us_per = (deltas["skb_alloc_cycles"]/calls)/(cpu_khz/1e03)
    print("Skb allocation              %6.2f   %7.2f us/skb" % (
            deltas["skb_alloc_cycles"]/time_delta, us_per))

    calls = deltas["skb_frees"]
    if calls == 0:
        us_per = 0
    else:
        us_per = (deltas["skb_free_cycles"]/calls)/(cpu_khz/1e03)
    print("Skb freeing                 %6.2f   %7.2f us/skb" % (
            deltas["skb_free_cycles"]/time_delta, us_per))

    print("\nLock Misses:")
    print("------------")
    print("            Misses/sec.  ns/Miss   %CPU")
    for lock in ["client", "server", "socket", "grantable", "throttle", "peer_ack"]:
        misses = float(deltas[lock + "_lock_misses"])
        cycles = float(deltas[lock + "_lock_miss_cycles"])
        if misses == 0:
            cycles_per_miss = 0.0
        else:
            cycles_per_miss = cycles/misses
        print("%-10s    %s    %6.1f   %5.1f" % (lock,
                scale_number(misses/elapsed_secs),
                cycles_per_miss/(cpu_khz/1e06), 100.0*cycles/time_delta))

    total_messages = float(deltas["requests_received"]
            + deltas["responses_received"])
    if total_messages > 0.0:
        print("\nReceiving Messages:")
        print("-------------------")
        poll_percent = 100.0*float(deltas["fast_wakeups"])/total_messages
        sleep_percent = 100.0*float(deltas["slow_wakeups"])/total_messages
        if deltas["gen3_alt_handoffs"]:
            gen3_alt_percent = (100.0*deltas["gen3_alt_handoffs"]
                    /deltas["gen3_handoffs"])
        else:
            gen3_alt_percent = 0.0
        if deltas["handoffs_alt_thread"]:
            alt_thread_percent = (100.0*deltas["handoffs_alt_thread"]
                    /deltas["handoffs_thread_waiting"])
        else:
            alt_thread_percent = 0.0
        if deltas["packets_rcvd_DATA"]:
            data_bypass_percent = (100.0*deltas["gro_data_bypasses"]
                        /deltas["packets_rcvd_DATA"])
        else:
            data_bypass_percent = 0.0
        if deltas["packets_rcvd_GRANT"]:
            grant_bypass_percent = (100.0*deltas["gro_grant_bypasses"]
                        /deltas["packets_rcvd_GRANT"])
        else:
            grant_bypass_percent = 0.0
        print("Available immediately:        %5.1f%%" % (100.0 - poll_percent
                - sleep_percent))
        print("Arrived while polling:        %5.1f%%" % (poll_percent))
        print("Blocked at least once:        %5.1f%%" % (sleep_percent))
        print("Alternate GRO handoffs:       %5.1f%%" % (gen3_alt_percent))
        print("Alternate thread handoffs:    %5.1f%%" % (alt_thread_percent))
        print("GRO bypass for data packets:  %5.1f%%" % (data_bypass_percent))
        print("GRO bypass for grant packets: %5.1f%%" % (grant_bypass_percent))

    print("\nMiscellaneous:")
    print("--------------")
    if packets_received > 0:
        print("Bytes/packet rcvd:    %6.0f" % (
                total_received_bytes/packets_received))
        print("Packets received:      %5.3f M/sec" % (
                1e-6*packets_received/elapsed_secs))
        print("Packets sent:          %5.3f M/sec" % (
                1e-6*packets_sent/elapsed_secs))
        print("Core efficiency:       %5.3f M packets/sec/core "
                "(sent & received combined)" % (
                1e-6*(packets_sent + packets_received)/elapsed_secs
                /total_cores_used))
        print("                      %5.2f  Gbps/core (goodput)" % (
                8e-9*(total_received_bytes + float(deltas["sent_msg_bytes"]))
                /(total_cores_used * elapsed_secs)))
    if deltas["pacer_cycles"] != 0:
        pacer_secs = float(deltas["pacer_cycles"])/(cpu_khz * 1000.0)
        print("Pacer throughput:     %5.2f  Gbps (pacer output when pacer running)" % (
                deltas["pacer_bytes"]*8e-09/pacer_secs))
    if deltas["throttled_cycles"] != 0:
        throttled_secs = float(deltas["throttled_cycles"])/(cpu_khz * 1000.0)
        print("Throttled throughput: %5.2f  Gbps (pacer output when throttled)" % (
                deltas["pacer_bytes"]*8e-09/throttled_secs))
    if deltas["skb_allocs"] != 0:
        print("Skb alloc time:        %4.2f  usec/skb" % (
                float(deltas["skb_alloc_cycles"]) / (cpu_khz / 1000.0) /
                deltas["skb_allocs"]))

    print("\nCanaries (possible problem indicators):")
    print("---------------------------------------")
    for symbol in ["requests_queued", "responses_queued"]:
        delta = deltas[symbol]
        if delta != 0:
            received = deltas[symbol[:-7] + "_received"]
            if (received != 0):
                percent = "(%.1f%%)" % (100.0*float(delta)/float(received))
                percent = percent.ljust(12)
                print("%-28s %15d %s %s" % (symbol, delta, percent, docs[symbol]))
    for symbol in ["resent_packets", "resent_packets_used",
            "packet_discards", "resent_discards", "unknown_rpcs",
            "peer_kmalloc_errors", "peer_route_errors", "control_xmit_errors",
            "data_xmit_errors",
            "server_cant_create_rpcs", "server_cant_create_rpcs",
            "short_packets", "rpc_timeouts", "server_rpc_discards",
            "server_rpcs_unknown", "forced_reaps", "buffer_alloc_failures",
            "dropped_data_no_bufs", "linux_pkt_alloc_bytes"]:
        if deltas[symbol] == 0:
            continue
        rate = float(deltas[symbol])/elapsed_secs
        rate_info = ("(%s/s) " % (scale_number(rate))).ljust(13)
        print("%-28s %15d %s%s" % (symbol, deltas[symbol],
                rate_info, docs[symbol]))
    for symbol in ["pacer_lost_cycles", "timer_reap_cycles",
            "data_pkt_reap_cycles", "grantable_lock_cycles"]:
        delta = deltas[symbol]
        if delta == 0 or time_delta == 0:
            continue
        percent = "(%.1f%%)" % (100.0*delta/time_delta)
        percent = percent.ljust(12)
        print("%-28s %15d %s %s" % (symbol, delta, percent, docs[symbol]))

    if deltas["throttle_list_adds"] > 0:
        print("%-28s %15.1f              List traversals per throttle "
                "list insert" % ("checks_per_throttle_insert",
                deltas["throttle_list_checks"]/deltas["throttle_list_adds"]))

    if deltas["responses_received"] > 0:
        print("%-28s %15.1f              ACK packets sent per 1000 client RPCs"
                % ("acks_per_rpc", 1000.0 * deltas["packets_sent_ACK"]
                / deltas["responses_received"]))

    if avg_grantable_rpcs > 1.0:
        print("%-28s          %6.2f %sAverage number of grantable incoming RPCs" % (
              "avg_grantable_rpcs", avg_grantable_rpcs, pad))
