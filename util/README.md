This directory contains a collection of utilities for testing and
analyzing Homa. Here is a summary of some of the programs in this
directory; for more information, run any program with the "--help"
option, or look at its source code.

### Cluster Performance Tests

**cp_node**: a program that runs on an individual node as part of cluster
benchmarks. You can run this program by hand (e.g. on one client machine
and one server machine): type `cp_node --help` for basic documentation.
This program is also run automatically by the other cp_* benchmarks.

**cp_vs_tcp**: the primary cluster performance test. Measures slowdown
as a function of message size for Homa and TCP under various workloads.

**cp_basic**: measures basic latency and throughput for Homa and TCP.

**cp_client_threads**: measures the throughput of a single client as a
function of the number of sending threads.

**cp_config**: measures Homa slowdown while varying one or more
configuration parameters.

**cp_load**: generates CDFs of short message latency for Homa and
TCP under different network loads.

**cp_mtu**: generates CDFs of short message latency for Homa and TCP
while varying the maximum packet length.

**cp_server_ports**: measures single-server throughput as a function
of the number of receiving ports.

**cp_tcp**: measures the performance of TCP by itself, with no message
truncation.

### Timetracing Tools
A number of programs are available for collecting, transforming, and analyzing
timetraces. Most have --help options that provide documentation. The following
scripts are relatively general-purpose (i.e. they don't have Homa dependencies):

**ttgrep.py**: extracts records from a timetrace that match a pattern and
recomputes the time differences using only those records.

**ttmerge.py**: combines two or more timetraces into a single timetrace.

**ttoffset.py**: offsets all of the times in a timetrace by a given amount (usually
done to line up times in one trace with times in another).

**ttrange.py**: extracts timetrace entries from a given time range.

**ttsum.py**: outputs statistics from a timetrace on the delay preceding each
event. Can also produce a timeline for repeated operations such as processing
a request on a server.

The following scripts are Homa-specific:

**ttprint.py**: extracts the most recent timetrace from the kernel and
prints it to standard output.

**ttsync.py**: analyzes Homa-specific information in a collection of
timetraces simultaneously on different nodes and rewrites the traces to
synchronize their clocks.

**tthoma.py**: this is the primary script for analyzing Homa data. It
contains multiple analyzers that extract different kinds of data from a
collection of timetraces. Invoke with --help for full documentation.

### Other Useful Tools

**diff_rtts.py**: compares two .rtts files collected by the cperf benchmarks,
tries to identify how/why they are different.