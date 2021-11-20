This repo contains an implementation of the Homa transport protocol as a Linux kernel module.

- For details on the protocol, see the paper [Homa: A Receiver-Driven Low-Latency
  Transport Protocol Using Network Priorities](https://dl.acm.org/citation.cfm?id=3230564)
  which appeared in SIGCOMM in August, 2018.

- More information about this implementation and its performance are available in
  the paper [A Linux Kernel Implementation of the Homa Transport
  Protocol](https://www.usenix.org/system/files/atc21-ousterhout.pdf),
  which appeared in the USENIX Annual Technical Conference in July, 2021.

- As of August 2020, Homa has complete functionality for running real applications,
  and its tail latency is more than 10x better than TCP for all workloads I have
  measured (Homa's 99-th percentile latency is usually better than TCP's mean
  latency). Here is a list of the most significant functionality that is still
  missing:
  - Socket buffer memory management needs more work. Large numbers of large
    messages (hundreds of MB?) may cause buffer exhaustion and deadlock.

- Linux v5.4.3 is the primary development platform for this code. In the past
  it has run under 4.15.18;  other versions of Linux have not been tested and
  may require code changes (the upgrade from 4.15.18 to 5.4.3 took only about
  a day). If you get Homa working on other versions, please let me know and/or submit
  pull requests for required code changes.
  
- There now exists support for using Homa with gRPC: see the
  [GitHub repo](https://github.com/PlatformLab/grpc_homa).

- To build the module, type "make all"; then type "sudo insmod homa.ko" to install
  it, and "sudo rmmod homa" to remove an installed module.
  
- A collection of man pages is available in the "man" subdirectory. The API for
  Homa is different from TCP sockets.

- The subdirectory "test" contains unit tests, which you can run by typing
  "make" in that subdirectory.
  
- The subdirectory "util" contains an assortment of utility programs that
  you may find useful in exercising Homa. Compile them by typing "make" in that
  subdirectory. Most notable is the "cperf" family of programs, which will
  run a variety of benchmarks on a cluster of nodes. The file cperf.py contains
  library functions for benchmarking, which are used by a variety of benchmarks
  with names starting with "cp_".
  
 - Some additional tools you might find useful:
   - Homa collects various metrics about its behavior, such as the size
     distribution of incoming messages. You can access these through the
     file /proc/net/homa_metrics. The script "util/metrics.py" will
     collect metrics and print out all the numbers that have changed
     since its last run.
   - Homa exports a collection of configuration parameters through the
     sysctl mechanism. For details, see the man page "homa.7".
     
## Significant recent improvements
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
