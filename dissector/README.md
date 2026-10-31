# HOMA Dissector

A dissector for viewing [Homa](https://homa-transport.atlassian.net/wiki/spaces/HOMA/overview)
inside UDP port 5001. UDP supplies a buffer starting at the inner Homa
header, not at the UDP header. Native IP-protocol-146 decoding is not
registered by this variant.

The earlier native dissector was tested with Wireshark 3.6.2 on Ubuntu.
Those results do not validate the current UDP layout. The host used for
validation lacks Wireshark development headers, CMake and tshark, so the
plugin build and offline decoding have not been tested for the UDP layout.

## Prerequisites

The dissector is a cmake based wireshark plugin. For building please make sure that the required wireshark dependencies,
including wireshark headers, are installed. For Debian based systems the following command line may be
used: `apt install wireshark-dev wireshark-common`

## Installation

The Plugin can be installed with the following steps.

CMake reads `HOMA_UDP_PORT` from [the public header](../homa.h) and supplies
the definition to the decoder; there is no separate private port value.
Changes to that header trigger reconfiguration. This keeps the decoder
portable without importing Linux socket API headers. Configuration fails
explicitly if the expected single numeric definition is missing or ambiguous.
This build wiring has not been executed: the validation host lacks the CMake
and Wireshark prerequisites.

```shell
cmake -S . -B build
cmake --build build
```

Installing a plugin changes the selected Wireshark plugin directory. Do this
only on a host with a compatible Wireshark version:

```shell
cmake --install build
```

Per default, the plugin will be installed inside the local plugin folder of wireshark. For installing the plugin global
on your system, run the following command:

```shell
cmake -S . -B build -DINSTALL_PLUGIN_LOCAL=OFF
cmake --build build
sudo cmake --install build
```

## Decoding contract and offline checks

The common header is 13 bytes; DATA is 41 bytes with its segment offset at
byte 37. ACK is always 65 bytes, with at most five valid entries selected by
its count. CUTOFFS exposes eight separate 32-bit values. START_MSG carries a
32-bit length after the common header. Unknown types, excessive ACK counts,
and truncated headers must not be reported as valid complete packets.

Once the plugin is built/loaded on a Wireshark host, inspect a
capture with, for example:

```shell
tshark -r capture.pcap -Y homa -T fields \
    -e ip.version -e ipv6.version -e udp.srcport -e udp.dstport \
    -e homa.type -e homa.sport -e homa.dport -e homa.id \
    -e homa.length -e homa.offset -e homa.num_acks \
    -e homa.unsched_cutoffs -e _ws.expert.message
```

Compare fields with the fixture/capture manifest, including every packet
class, DATA tails and retransmissions, ACK counts 0 and 5, excessive counts,
unknown types and truncated headers. Plain TCP and unrelated UDP must not
decode as Homa. Synthetic fixtures or an independent packet checker do not
substitute for running this plugin. Live captures from a loaded Homa module
remain a separate integration TODO.
