This repo contains an implementation of the Homa transport protocol for Linux.

- For details on the protocol, see the paper [Homa: A Receiver-Driven Low-Latency
  Transport Protocol Using Network Priorities](https://dl.acm.org/citation.cfm?id=3230564).

- The code here is is still a work in progress. As of September 2019, Homa's
  functionality is nearly complete, and it  should be capable of running real
  applications. See the "invoke" test in tests/homa_test.c for an
  example), and see below in this document for information on recent improvements.
  Here is a partial list of functionality that is still missing:
  - Socket buffer memory management needs more work. Large numbers of large
    messages (hundreds of KB?) may cause buffer exhaustion and deadlock.
  - Performance analysis and tuning are currently underway. Some performance
    improvements have already been made, such as opening TSO and GRO, and
    I expect additional improvements in the future. As of 9/2019, Homa's
    unloaded latency is about 2us less than TCP, but TCP's throughput under
    load is about 2x that of Homa. I haven't yet tested Homa's expected
    advantage in terms of congestion control and small request latency under
    load.

- Linux v4.16.10 is the primary development platform for this code. It is also
  known to work with v4.15.0-38-generic;  other versions of Linux have not been
  tested and may require code changes. If you get Homa working on other versions,
  please let me know and/or submit pull requests for required code changes.

- To build the module, type "make all"; then type "sudo insmod homa.ko" to install
  it, and "sudo rmmod homa" to remove an installed module.
  
- A collection of man pages is available in the "man" subdirectory.

- The subdirectory "unit" contains unit tests, which you can run by typing
  "make" in that subdirectory.
  
- The subdirectory "tests" contains an assortment of programs that may be
  useful in exercising Homa. Compile them by typing "make" in that
  subdirectory.
  
 - Some additional tools you might find useful:
   - Homa collects various metrics about its behavior, such as the size
     distribution of incoming messages. You can access these through the
     file /proc/net/homa_metrics. The script "util/metrics.py" will
     collect metrics and print out all the numbers that have changed
     since its last run.
   - Homa exports a collection of configuration parameters through the
     sysctl mechanism. For details, see the man page "homa.7".
     
## Significant recent improvements
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
