# HOMA Dissector

A dissector for viewing [homa](https://homa-transport.atlassian.net/wiki/spaces/HOMA/overview) packets. The dissector
was tested with Ubuntu 18.04 and Ubuntu 22.04 with the Wireshark version 3.6.2

## Prerequisites

The dissector is a cmake based wireshark plugin. For building please make sure that the required wireshark dependencies,
including wireshark headers, are installed. For Debian based systems the following command line may be
used: `apt install wireshark-dev wireshark-common`

## Installation

The Plugin can be installed with the following steps.

```shell
cmake .
make
make install
```

Per default, the plugin will be installed inside the local plugin folder of wireshark. For installing the plugin global
on your system, run the following command:

```shell
cmake -DINSTALL_PLUGIN_LOCAL=OFF .
make
sudo make install
```
