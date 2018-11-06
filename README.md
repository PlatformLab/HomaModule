This repo contains an implementation of the Homa transport protocol for Linux.

- For details on the protocol, see the paper [Homa: A Receiver-Driven Low-Latency
  Transport Protocol Using Network Priorities](https://dl.acm.org/citation.cfm?id=3230564).

- The code here is is still a work in progress. As of November 2018, Homa
  has barely enough functionality to transmit RPC requests and responses
  (see the "invoke" test in tests/homa_test.c for an example), and it can
  now handle timeouts and retransmissions, but it is not yet complete.
  Here is a partial list of functionality that is still missing:
  - The throttling mechanism to limit queueing in source NICs hasn't been
    implemented, which means SRPT isn't properly implemented on senders
    and there can be head-of-line blocking.
  - Big chunks of Linux plumbing are still missing (e.g., Homa doesn't yet
    connect with the select or poll mechanisms).
  - Socket buffer memory management needs more work. Large
    messages (hundreds of KB?) may cause buffer exhaustion and deadlock.
  - There has been no performance analysis or tuning, so performance
    measurements made now are unlikely to be meaningful.

- Linux v4.16.10 is the primary development platform for this code. It is also
  known to work with v4.15.0-38-generic;  other versions of Linux have not been
  tested and may require code changes. If you get Homa working on other versions,
  please let me know and/or submit pull requests for required code changes.

- To build the module, type "make all"; then type "sudo insmod homa.ko" to install
  it, and "sudo rmmod homa" to remove an installed module.

- The subdirectory "unit" contains unit tests, which you can run by typing
  "make" in that subdirectory.
  
- The subdirectory "tests" contains an assortment of programs that may be
  useful in exercising Homa. Compile them by typing "make" in that
  subdirectory.
  
 - Some additional tools you might find useful:
   - Homa collects various metrics about its behavior, such as the size
     distribution of incoming messages. You can access these through the
     file /proc/net/homa_metrics. The script "tests/diff_metrics.py"
     will compare two metrics files collected at different times and
     show only the counters that have changed.
   - Homa exports a collection of configuration parameters through the
     sysctl mechanism. To see what is available, type "sysctl net.homa".
