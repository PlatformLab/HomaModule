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
timetraces. Most of these programs depend on the existence of certain
records in the timetrace. As Homa evolves, the actual timetrace records
also evolve, which can break the scripts; if you discover a broken script,
either update the script to use Homa's current timetrace records, or
change Homa to output better records (try not to break other scripts when
doing this). In addition, some of these scripts depend on timetrace records
from the main Linux kernel, outside Homa; these scripts won't work unless
you have installed my kernel modifications.

**ttprint.py**: extracts the most recent timetrace from the kernel and
prints it to standard output.

**ttcore.py**: extracts records containing certain substrings and computes how
often those records occur on each core.

**ttgrants.py**: computes *grant lag* for a timetrace: how long it takes after a
grant is issued for the granted packet to arrive. Also computes statistics on
when grants arrive, compared to when they need to arrive to transmit at full
link speed.

**ttgrep.py**: extracts records from a timetrace that match a pattern, and recomputes
the time differences using only those records.

**ttmerge.py**: combines two or more timetraces into a single timetrace.

**ttnicdelay.py**:: analyzes synchronized client and server traces to
detect situations where the NIC is delaying interrupts.

**ttoffset.py**: offsets all of the times in a timetrace by a given amount (usually
done to line up times in one trace with times in another).

**ttpktdelay.py**: reads client and server timetraces gathered at about the same time,
and analyzes packet delays in both directions.

**ttrpcs.py**: scans a client or server timetrace to compute the time taken for each
phase of the RPC.

**ttrange.py**: extracts timetrace entries from a given time range.

**ttrcv.py**: analyzes packet arrivals in a timetrace, outputs information
on arrival times for each offset within a message.

**ttsoftirq.py**: analyzes SoftIRQ wakeup times in a timetrace. Also measures
total lifetime of receive buffers from GRO -> kfree_skb.

**ttsum.py**: outputs statistics from a timetrace on the delay preceding each event.
Can also produce a timeline for repeated operations such as processing a request
on a server.

**ttsync.py**: reads client and server timetraces gathered at about the same time,
computes the clock offset between client and server, and outputs a new server
trace with its clock values offset to match the client clock.

**ttxmit.py**: analyzes packet transmissions from a timetrace to identify
uplink bubbles (gaps during which the uplink was idle even though there
were active outbound messages).

### Other Useful Tools

**diff_rtts.py**: compares two .rtts files collected by the cperf benchmarks,
tries to identify how/why they are different.