# Installing Homa

Here are the steps you will need to go through to compile and
install the Homa kernel module for Linux. If you run into any problems,
feel free to contact me (John Ousterhout, ouster@cs.stanford.edu).

1. Download Homa from GitHub:
   ```
   git clone https://github.com/PlatformLab/HomaModule.git
   ```

2. Compile Homa: type `make all` in the top-level directory.
   * The `main` branch is known to work under Linux 6.17.8; I recommend
     using this branch if you can.
   * The branches `rhel8` and `rhel9.5` are known to work with the
     corresponding versions of Red Hat Enterprise Linux. I try to
     keep them up to date with the `main` branch.
   * There are also branches for several older versions of Linux, with
     names like `linux_4.15.18` that indicate the Linux version number.
     These branches are generally out of date feature-wise: recent commits
     have not been back-ported to them.
   * If you need to run on a version of Linux that is not currently supported
     or up to date, contact me and I'll help you get Homa running on that
     version. You might also try compiling the `main` branch to see what
     works and/or fails. You may find it's easy to modify Homa to compile
     on a different version of Linux.

1. Load the executable `homa.ko` into your Linux kernel
   with the following command:
   ```
   sudo insmod homa.ko
   ```
   Once installed, you can uninstall it with:
   ```
   sudo rmmod homa
   ```
   (Note: you cannot remove Homa if there are any Homa sockets open)

1. At this point you should be able to write programs that send and receive
   Homa messages (type `make` in the `man` directory to generate the manual
   pages, then review them for details). However, Homa's performance won't
   be very good (especially for large messages) unless you make a few other
   configuration changes to your system, which are described below. In my test
   environment
   (the CloudLab research cluster) I use the script in `cloudlib/bin/config`
   to perform these configuration changes; I invoke it with a single
   parameter `default`. The key configuration changes are broken out
   below.

1. Enable jumbo frames on your NICs if they are not already enabled:
   ```
   sudo ip link set <interface> mtu 9000
   ```
   Note: if you increase the MTU on your hosts, you'll need to make sure
   that your switches are also configured to support the larger MTU.

1. Configure your NIC. The default configuration for most NICs interferes
   with low latency by deferring interrupts in the hope of coalescing
   multiple interrupts. I recommend invoking the following commands
   to set NIC parameters for lowest latency:
   ```
   sudo ethtool -C <interface> adaptive-rx off
   sudo ethtool -C <interface> rx-usecs 0
   sudo ethtool -C <interface> rx-frames 1
   sudo ethtool -C <interface> adaptive-tx off
   sudo ethtool -C <interface> tx-usecs 5
   ```
   If you are using Intel NICs, I recommend this additional command
   to increase the tx ring size:
   ```
   sudo ethtool -G <interface> tx 1024
   ```

1. Make sure that RPS (Receive Packet Steering) and RFS (Receive Flow
   Steering) are enabled. See the function `config_rps` in the
   script `cloudlab/bin/config` for details on how to do this.

1. Activate Homa's queuing discipline. Homa has its own queuing discipline,
   which serves two purposes. First, it paces output packets
   from Homa in order to eliminate queue buildup in the NIC. This is
   essential to Homa's SRPT (Shortest Remaining Processing Time) scheduling
   policy, which favors shorter messages. Without the queuing discipline,
   small messages can get stuck in long NIC queues, which will impact
   their tail latency. Second, the queuing discipline manages outgoing packets
   from other protcols such as TCP, ensuring that the protocols don't
   interfere with each other. Without the queuing discipline, if TCP and
   Homa are used concurrently on a node, TCP will interfere with Homa's
   performance. The queuing discipline manages interactions between
   protocols to avoid interference: with it, all protocols (including TCP)
   get better performance. Activating Homa's queuing discipline requires
   each individual output queue to be individually configured; see the
   function `config_qdisc` in `cloudlab/bin/config` for details.

1. Configure the top-of-rack switches in your network to enable priority
   queues for host downlinks. The exact commands for this will vary
   depending on the switch, but the goal is to configure the switch
   so that the 3 high-order bits of the DSCP field in IPv4 headers or
   the 4 high-order bits of the Traffic Class field in IPv6 headers
   determine which priority queue a packet is placed in, and priority
   queues are serviced in strict priority order with priority 0 receiving
   lowest priority. As one example, the script `cloudlab/bin/switch.py`
   will generate configuration commands for Mellanox switches running MLNX-OS.
   By default Homa will use all 8 priority levels, but it can be configured
   to use fewer levels than that (my experience is that there is not
   much difference in performance between 4 levels and 8).

1. Enable segmentation offload (TSO or GSO). This is essential for good
   performance on large messages.  If segmentation offload is disabled
   (the default), Homa generates MTU-sized output packets and each of these
   packets must pass through the Linux IP stack, which is quite expensive.
   This limits output throughput. With segmentation offload, Homa generates
   output packets that are much larger than the network MTU. Once a packet
   has passed through the IP stack and been handed off to the NIC, the
   NIC chops the packet up into multiple smaller packets (segments). This
   reduces IP stack overhead. Virtually all NICs support segmentation offload
   for TCP (TSO).  Unfortunately, many NICs will not perform segmentation
   if the packet transport protocol is unknown, which is the case for
   Homa. You have four options:
   * If your NICs were made by Mellanox or NVIDIA, they will segment Homa
     packets by default. All you need to do is set Homa's `max_gso_size`
     configuration parameter to a large number on each node:
     ```
     sudo sysctl .net.homa.max_gso_size=100000
     ```
   * If your NICs were made by Intel, they will not segment Homa packets
     by default. However, I have been told that DDP (Dynamic Device
     Personalization) can be used to configure Intel NICs so that
     they will segment Homa packets. I don't have any experience with DDP
     so I can't tell you exactly how to do this. NICs by other manufacturers
     may also have customization capabilities.
   * Enable TCP hijacking. Homa has a mode called "TCP hijacking" in which
     it generates output packets that look like TCP packets and are transmitted
     using the TCP IP protocol. Since the packets look just like TCP
     packets, NICs will perform TSO on them. The packets have a few bits
     set in a way that would never occur with real TCP packets; when
     the packets reach the destination, Homa recognizes them and "steals"
     them back so they are processed by Homa and not TCP. You can enable
     TCP hijacking with the following command:
     ```
     sudo sysctl .net.homa.hijack_tcp=1
     ```
     Once you have done this, set `max_gso_size` as described above.
     Unfortunately some datacenters employ security mechanisms in their
     switches that detect TCP packets that "don't seem right" (e.g.,
     they don't belong to legitimate connections) and drop them. These filters
     will discard TCP-encapsulated Homa packets, so hijacking will not work.
   * As a last resort, use software segmentation (GSO). Linux has a mechanism
     in which packets can be segmented in software after they have passed
     through the IP stack. This is not as efficient as TSO in the NIC, but it
     is still more efficient than passing every MTU-sized packet individually
     through the network stack. Homa has support for GSO, but unfortunately
     this support is temporarily broken due. If you need GSO before I get
     around to fixing it, contact me and I will prioritize the fix.

1. You may also find the script `cloudlab/bin/install_homa` useful.
   It will copy relevant Homa files across a cluster of machines and configure
   Homa on each node. It assumes that nodes have names `nodeN` where N is a
   small integer, and it also assumes that you have already run `make` both
   in the top-level directory and in `util`.