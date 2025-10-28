#!/usr/bin/python3

# Copyright (c) 2023 Homa Developers
# SPDX-License-Identifier: BSD-1-Clause

# This file defines the Switch class.

import fcntl
import os
import re
import subprocess
import sys
import time

# A Switch object represents a Mellanox top-of-rack switch for a CloudLab
# experiment, and it provides various operations on the switch such
# as configuring ports and querying statistics such as maximum buffer
# usage.
class Switch:
    def __init__(self, verbose=False):
        self.verbose = verbose

        # Open an ssh connection to the switch.
        self.ssh = subprocess.Popen(["ssh", "-T", "-p", "51295",
                "-o", "HostKeyAlgorithms=+ssh-rsa",
                "-o", "PubkeyAcceptedKeyTypes=+ssh-rsa", "admin@localhost"],
                encoding="utf-8", stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
        fl = fcntl.fcntl(self.ssh.stdout, fcntl.F_GETFL)
        fcntl.fcntl(self.ssh.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        # Enter config mode
        self.do_cmd("enable")
        self.do_cmd("configure terminal")

    def close(self):
        """
        Shut down the ssh connection to the switch; this object will become
        unusable.
        """
        self.ssh.terminate()

    def do_cmd(self, command, time_limit=5.0):
        """
        Invoke a command on the switch and wait for it to complete. If a
        long time goes by without a command prompt, an exception is thrown.
        All of the output is returned.
        command:     Command to invoke; if empty, then no command is invoked
                     (but we wait for a prompt to appear).
        time_limit:  An error will be generated if this many seconds go by
                     without the appearance of a command prompt.
        """
        if self.verbose:
            print(command)
        if len(command) > 0:
            print(command, file=self.ssh.stdin)
        # Because we're running ssh without a pseudo-tty (which is necessary,
        # because otherwise ssh doesn't exit if this process exits), the
        # switch doesn't generate any prompts. So, output a bogus command
        # and use the error message from that command as an indication that
        # the earlier command has completed.
        print('xyzzy', file=self.ssh.stdin, flush=True)

        output = ""
        start_time = time.time()
        while True:
            if time.time() > (start_time + time_limit):
                raise Exception("switch command '%s' didn't complete; output:\n%s"
                        % (command.rstrip(), output))
            data = self.ssh.stdout.read(1000)
            if data != "":
                output += data
                if re.search('Unrecognized command.*xyzzy.*help', output,
                        flags=re.DOTALL):
                    return output
            time.sleep(0.1)

    def get_max_buffer_usage(self):
        """
        Return the maximum total buffer usage (across all egress ports).
        """
        output = self.do_cmd("show buffers pools ePool0")
        match = re.search(r'.*ePool0\s+egress.*[0-9.]+M?\s+[0-9.]+M?\s+([0-9.]+)([MK]?)',
                output)
        if match:
            if match.group(2) == 'M':
                return float(match.group(1))
            elif match.group(2) == 'K':
                return float(match.group(1))/1000.0
            else:
                return float(match.group(1))/1e06
        raise Exception("Switch.get_max_buffer_usage couldn't find "
                "information for ePool0; here is the output:\n%s" % (output))

    def clear_max_buffer_usage(self):
        """
        Reset the maximum total buffer usage so that it will recompute
        starting now.
        """
        self.do_cmd("clear buffers pool max-usage")

    def config_port(self, port):
        """
        Configure the settings on a particular egress port to meet Homa's
        needs.
        port: Index of the port to configure.
        """

        # Enable priority queues for Homa.
        self.do_cmd("interface ethernet 1/%d qos trust both" % (port))
        for tc in range(8):
            self.do_cmd("interface ethernet 1/%d traffic-class %d dcb ets strict" %
                    (port, tc))

        # Enable large packets.
        self.do_cmd("interface ethernet 1/%d mtu 9216 force" % (port))

        # Set DCTCP marking thresholds.
        self.do_cmd("interface ethernet 1/%d traffic-class 0 congestion-control ecn "
                "minimum-absolute 70 maximum-absolute 70" % (port))
        self.do_cmd("interface ethernet 1/%d traffic-class 1 congestion-control ecn "
                "minimum-absolute 70 maximum-absolute 70" % (port))

    def config_all_ports(self):
        """
        Invoke config_port on all of the egress ports for the switch.
        """

        for port in range(1, 41):
            self.config_port(port)

    def reset_port(self, port):
        """
        Restore default settings for a port (undo the effects of a previous
        call to config_port).
        """

        # Restore QOS priorities.
        self.do_cmd("interface ethernet 1/%d no qos trust" % (port))
        for tc in range(8):
            print("interface ethernet 1/%d traffic-class %d no dcb ets" %
                    (port, tc))

        # Disable large packets
        self.do_cmd("interface ethernet 1/%d mtu 1500 force" % (port))

        # Reset DCTCP marking thresholds:
        self.do_cmd("interface ethernet 1/%d no traffic-class 0 congestion-control"
                % (port))
        self.do_cmd("interface ethernet 1/%d no traffic-class 1 congestion-control"
                % (port))

    def reset_all_ports(self):
        """
        Invoke resetport on all of the egress ports for the switch.
        """

        for port in range(1, 41):
            self.reset_port(port)

    def set_buffer_limit(self, mbytes):
        """
        Configure the switch to limit the total amount of buffer space
        in egress ports to a given amount.
        mbytes:   Desired limit, in Mbytes
        """
        self.do_cmd("advance buffer management force")
        self.do_cmd("pool ePool0 size %.3fM type dynamic" % (mbytes))

    def set_ecn_threshold(self, port, kb):
        """
        Set the ECN marking threshold for a given port.

        port:       The port to configure
        kb:         Value to set for the marking threshold, in KB
        """

        self.do_cmd("interface ethernet 1/%d traffic-class 0 congestion-control ecn "
                "minimum-absolute %d maximum-absolute %d" % (port, kb, kb))
        self.do_cmd("interface ethernet 1/%d traffic-class 1 congestion-control ecn "
                "minimum-absolute %d maximum-absolute %d" % (port, kb, kb))

    def set_all_ecn_thresholds(self, kb):
        """
        Set ECN marking threshold for all of the ports in the switch.

        kb:         Value to set for the marking threshold, in KB
        """

        for port in range(1, 41):
            self.set_ecn_threshold(port, kb)
