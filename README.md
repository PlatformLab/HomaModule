This repo contains an implementation of the Homa transport protocol as a Linux kernel module.

- For more information on Homa in general, see the [Homa
  Wiki](https://homa-transport.atlassian.net/wiki/spaces/HOMA).

- More information about this implementation and its performance are available in
  the paper [A Linux Kernel Implementation of the Homa Transport
  Protocol](https://www.usenix.org/system/files/atc21-ousterhout.pdf),
  which appeared in the USENIX Annual Technical Conference in July, 2021.

- A synopsis of the protocol implemented by this module is available in
  [protocol.md](https://github.com/PlatformLab/HomaModule/blob/master/protocol.md).

- As of August 2020, Homa has complete functionality for running real applications,
  and its tail latency is more than 10x better than TCP for all workloads I have
  measured (Homa's 99-th percentile latency is usually better than TCP's mean
  latency). Here is a list of the most significant functionality that is still
  missing:
  - The incast optimization from Section 3.6 of the SIGCOMM paper has not
    been implemented yet. If you would like to test Homa under large incasts,
    let me know and I will implement this feature.
  - Socket buffer memory management needs more work. Large numbers of large
    messages (hundreds of MB?) may cause buffer exhaustion and deadlock.

 - Please contact me if you have any problems using this repo; I'm happy to
   provide advice and support.

- The head is known to work under Linux 6.10.6. In the past, Homa has
  run under several earlier versions of Linux. There is a separate branch
  for each of these
  older versions, with names such as linux_4.15.18. Older branches are
  out of date feature-wise: recent commits have not been back-ported to them.
  Other versions of Linux have not been tested and
  may require code changes (these upgrades rarely take more than a couple
  of hours). If you get Homa working on some other version, please submit a
  pull request with the required code changes.

- Related work that you may find useful:
  - [Preliminary support for using Homa with gRPC](https://github.com/PlatformLab/grpc_homa)
  - [A Go client that works with this module](https://github.com/dpeckett/go-homa)

- To build the module, type `make all`; then type `sudo insmod homa.ko` to install
  it, and `sudo rmmod homa` to remove an installed module. In practice, though,
  you'll probably want to do several other things as part of installing Homa.
  I have created a Python script that I use for installing Homa on clusters
  managed by the CloudLab project; it's in `cloudlab/bin/config`. I normally
  invoke it with no parameters to install and configure Homa on the current
  machine.

- The script `cloudlab/bin/install_homa` will copy relevant Homa files
  across a cluster of machines and configure Homa on each node. It assumes
  that nodes have names `nodeN` where N is a small integer, and it also
  assumes that you have already run `make` both in the top-level directory and
  in `util`.

- For best Homa performance, you should also make the following configuration
  changes:
  - Enable priority queues in your switches, selected by the 3
    high-order bits of the DSCP field in IPv4 packet headers or the 4
    high-order bits of the Traffic Class field in IPv6 headers.
    You can use `sysctl` to configure Homa's use of
    priorities (e.g., if you want it to use fewer than 8 levels). See the man
    page `homa.7` for more info.
  - Enable jumbo frames on your switches and on the Linux nodes.

- NIC support for TSO: Homa can use TCP Segmentation Offload (TSO) in order
  to send large messages more efficiently. To do this, it uses a header format
  that matches TCP's headers closely enough to take advantage of TSO support in NICs.
  It is not clear that this approach will work with all NICs, but the following
  NICs are known to work:
  - Mellanox ConnectX-4, ConnectX-5, and ConnectX-6

  There have been reports of problems with the following NICs (these have not
  yet been explored thoroughly enough to know whether the problems are
  insurmountable):
  - Intel E810 (ice), XXV710 (i40e), XL710

  Please let me know if you find other NICs that work (or NICs that don't work).
  If the NIC doesn't support TSO for Homa, then you can request that Homa
  perform segmentation in software by setting the `gso_force_software` parameter
  to a nonzero value using `sysctl`. Unfortunately, software segmentation
  is inefficient because it has to copy the packet data. Alternatively,
  you can ensure that the `max_gso_size` parameter is the same as the maximum
  packet size, which eliminates GSO in any form. This is also inefficient
  because it requires more packets to traverse the Linux networking stack.

- A collection of man pages is available in the "man" subdirectory. The API for
  Homa is different from TCP sockets.

- The subdirectory "test" contains unit tests, which you can run by typing
  "make" in that subdirectory.

- The subdirectory "util" contains an assortment of utility programs that
  you may find useful in exercising and benchmarking Homa. Compile them by typing
  `make` in that subdirectory. Here are some examples of benchmarks you might
  find useful:
  - The `cp_node` program can be run stand-alone on clients and servers to run
    simple benchmarks. For a simple latency test, run `cp_node server` on node1 of
    the cluster, then run `cp_node client` on node 0. The client will send
    continuous back-to-back short requests to the server and output timing
    information. Or, run `cp_node client --workload 500000` on the client:
    this will send continuous 500 KB messages for a simple througput test.
    Type `cp_node --help` to learn about other ways you can use this program.
  - The `cp_vs_tcp` script uses `cp_node` to run cluster-wide tests comparing
    Homa with TCP (and/or DCTCP); it was used to generate the data for
    Figures 3 and 4 in the Homa ATC paper. Here is an example command:
    ```
    cp_vs_tcp -n 10 -w w4 -b 20
    ```
    When invoked on node0, this will run a benchmark using the W4 workload
    from the ATC paper,
    running on 10 nodes and generating 20 Gbps of offered load (80%
    network load on a 25 Gbps network). Type `cp_vs_tcp --help` for
    information on all available options.
  - Other `cp_` scripts can be used for different benchmarks.
    See `util/README.md` for more information.

 - Some additional tools you might find useful:
   - Homa collects various metrics about its behavior, such as the size
     distribution of incoming messages. You can access these through the
     file `/proc/net/homa_metrics`. The script `util/metrics.py` will
     collect metrics and print out all the numbers that have changed
     since its last run.
   - Homa exports a collection of configuration parameters through the
     sysctl mechanism. For details, see the man page `homa.7`.

## Significant recent improvements
- July 2024: introduced "TCP hijacking", where Homa packets are sent as
  legitimate TCP segments (using TCP as the IP protocol) and then reclaimed
  from TCP on the destination. This allows Homa to make better use of
  TSO and RSS.
- June 2024: refactored sk_buff management to use frags; improves
  efficiency significantly.
- April 2024: replaced `master` branch with `main`
- December 2022: Version 2.0. This includes a new mechanism for managing
  buffer space for incoming messages, which improves throughput by
  50-100% in many situations. In addition, Homa now uses the sendmsg
  and recvmsg system calls, rather than ioctls, for sending and receiving
  messages. The API for receiving messages is incompatible with 1.01.
- November 2022: implemented software GSO for Homa.
- September 2022: added support for IPv6, as well as completion cookies.
  This required small but incompatible changes to the API.
  Many thanks to Dan Manjarres for contributing these
  improvements.
- September 2022: Homa now works on Linux 5.18 as well as 5.17.7
- June 2022: upgraded to Linux 5.17.7.
- November 2021: changed semantics to at-most-once (servers can no
  longer see multiple instances of the same RPC).
- August 2021: added new versions of the Homa system calls that
  support iovecs; in addition, incoming messages can be read
  incrementally across several homa_recv calls.
- November 2020: upgraded to Linux 5.4.3.
- June 2020: implemented busy-waiting during homa_recv: shaves 2
  microseconds off latency.
- June 2020: several fixes to prevent RPCs from getting "stuck",
  where they never make progress.
- May 2020: got priorities working correctly using the DSCP field
  of IP headers.
- December 2019: first versions of cperf ("cluster performance")
  benchmark.
- December 2019 - June 2020: many improvements to the GRO mechanism,
  including better hashing and batching across RPCs; improves both
  throughput and latency.
- Fall 2019: many improvements to pacer, spread over a couple of months.
- November 6, 2019: reworked locking to use RPC-level locks instead of
  socket locks for most things (significantly reduces socket lock.
  contention). Many more refinements to this in subsequent commits.
- September 25, 2019: reworked timeout mechanism to eliminate over-hasty
  timeouts. Also, limit the rate at which RESENDs will be sent to an
  overloaded machine.
- August 1, 2019: GSO and GRO are now working.
- March 13, 2019: added support for shutdown kernel call, plus poll, select,
  and epoll. Homa now connects will all of the essential Linux plumbing.
- March 11, 2019: extended homa_recv API with new arguments: flags, id.
- February 16, 2019: added manual entries in the subdirectory "man".
- February 14, 2019: output queue throttling now seems to work (i.e., senders
  implement SRPT properly).
- November 6, 2019: timers and packet retransmission now work.
