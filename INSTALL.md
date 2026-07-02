# Installing Homa

Here are the steps you will need to go through to compile and
install the Homa kernel module for Linux." If you run into any problems,
feel free to contact me (John Ousterhout, ouster@cs.stanford.edu).

1. Download Homa from GitHub:
   ```
   git clone https://github.com/PlatformLab/HomaModule.git
   ```

2. Compile Homa: type `make all` in the top-level directory. I recommend
   using the head of the `main` branch so you are as up-to-date as possible
   on features. The head is targeted for a specific version of Linux
   (see `README.md` for details) so it's possible it may not compile
   on the version you are using. If this happens, contact me and I'll
   work with you to get Homa compiling on your version.

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

1. Enable jumbo frames on your NICs if they are not already enabled:
   ```
   sudo ip link set <interface> mtu 9000
   ```
   Note: if you increase the MTU on your hosts, you'll need to make sure
   that your switches are also configured to support the larger MTU.

1. At this point you should be able to write programs that send and receive
   Homa messages (type `make` in the `man` directory to generate the manual
   pages, then review them for details). However, Homa is unlikely to
   achieve optimal performance unless you make a few other configuration
   changes to your system, which are described below. In my test environment
   (the CloudLab research cluster) I use the script in `cloudlib/bin/config`
   to perform these configuration changes; I invoke it with a single
   parameter `default`. I've broken out the key configuration changes
   below.

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
   so that the high-order 3 bits of the DSCP field in IPv4 headers
   (high-order 3 bits of the Traffic Class field for IPv6 headers)
   determine which priority queue a packet is placed in, and priority
   queues are serviced in strict priority order with priority 0 receiving
   lowest priority. As one example, the script `cloudlab/bin/switch.py`
   will generate configuration commands for Mellanox switches running MLNX-OS.
   By default Homa will use all 8 priority levels, but it can be configured
   to use fewer levels than that (my experience is that there is not
   much difference in performance between 4 levels and 8).