# UDP Hijacking for Homa

## Overview

UDP hijacking is an optional mechanism that encapsulates Homa packets as UDP
datagrams, using `IPPROTO_UDP` instead of `IPPROTO_HOMA` as the IP protocol.
It works alongside the existing TCP hijacking feature — only one can be active
at a time on a given socket.

### Why UDP hijacking?

TCP hijacking uses `SYN+RST` flag combinations that never occur in real TCP
traffic. However, some firewalls (particularly on virtualized environments)
inspect TCP flags and drop packets with these "impossible" flag combinations.
UDP hijacking avoids this issue entirely since UDP has no flags for firewalls
to inspect.

### Trade-offs vs TCP hijacking

| Feature             | TCP hijacking          | UDP hijacking          |
|---------------------|------------------------|------------------------|
| NIC TSO support     | Yes (multi-segment)    | No (single-segment)    |
| Firewall friendly   | No (SYN+RST blocked)  | Yes                    |
| GSO segments/packet | Multiple               | 1 (`segs_per_gso = 1`) |
| IP protocol         | `IPPROTO_TCP`          | `IPPROTO_UDP`          |
| sysctl              | `hijack_tcp`           | `hijack_udp`           |

Because NICs do not perform TSO on UDP packets the same way they do for TCP,
UDP hijacking forces `segs_per_gso = 1` (one segment per GSO packet). This
means each Homa data packet is sent individually rather than being batched
into large TSO super-packets.

## Configuration

Enable UDP hijacking at runtime via sysctl:

```bash
# Enable UDP hijacking (disable TCP hijacking first if it was on)
sudo sysctl net.homa.hijack_tcp=0
sudo sysctl net.homa.hijack_udp=1
```

To switch back to TCP hijacking:

```bash
sudo sysctl net.homa.hijack_udp=0
sudo sysctl net.homa.hijack_tcp=1
```

**Note:** If both `hijack_tcp` and `hijack_udp` are set, TCP hijacking takes
priority (sockets opened while both are set will use TCP).

## How It Works

### Sending (outgoing packets)

1. **Socket initialization** (`homa_hijack_sock_init`): When a new Homa socket
   is created, if `hijack_udp` is set the socket's `sk_protocol` is set to
   `IPPROTO_UDP`. The kernel then transmits packets with a UDP IP protocol.

2. **Header setup** (`homa_udp_hijack_set_hdr`): Before transmission, Homa
   writes UDP-compatible header fields:
   - `flags` is set to `HOMA_HIJACK_FLAGS` (6) — a marker value.
   - `urgent` is set to `HOMA_HIJACK_URGENT` (0xb97d) — a second marker.
   - Bytes 4-5 of the transport header are overwritten with the UDP length.
   - Bytes 6-7 are set up for proper UDP checksum offload.
   - Because the sequence field (bytes 4-7) is overwritten, the packet offset
     is stored in `seg.offset` instead.

3. **GSO geometry**: With UDP hijacking, `segs_per_gso` is forced to 1 (no
   multi-segment GSO batching).

### Receiving (incoming packets)

1. **GRO interception** (`homa_udp_hijack_gro_receive`): Homa hooks into the
   UDP GRO pipeline. When a UDP packet arrives, Homa checks:
   - At least 20 bytes of transport header are available.
   - `flags == HOMA_HIJACK_FLAGS` and `urgent == HOMA_HIJACK_URGENT`.

2. If the packet is identified as a Homa-over-UDP packet, the IP protocol
   is rewritten to `IPPROTO_HOMA` and the packet is handed to Homa's normal
   GRO handler. Real UDP packets are passed through to the normal UDP stack.

### Qdisc support

The `is_homa_pkt()` function in `homa_qdisc.c` recognizes both TCP-hijacked
and UDP-hijacked packets, ensuring they receive proper Homa qdisc treatment.

## Files Modified

| File              | Changes                                                    |
|-------------------|------------------------------------------------------------|
| `homa_wire.h`     | No new defines needed (reuses `HOMA_HIJACK_FLAGS` and `HOMA_HIJACK_URGENT`) |
| `homa_impl.h`     | Added `hijack_udp` field to `struct homa`                  |
| `homa_hijack.h`   | Added `homa_udp_hijack_set_hdr()`, `homa_sock_udp_hijacked()`, `homa_skb_udp_hijacked()`; updated `homa_hijack_sock_init()` |
| `homa_hijack.c`   | Added `homa_udp_hijack_init()`, `homa_udp_hijack_end()`, `homa_udp_hijack_gro_receive()` |
| `homa_outgoing.c` | Added `segs_per_gso=1` for UDP; added UDP header calls in xmit paths |
| `homa_plumbing.c` | Added `hijack_udp` sysctl; added UDP init/end calls        |
| `homa_qdisc.c`    | Added `IPPROTO_UDP` check in `is_homa_pkt()`               |
| `util/homa_test.cc` | Added `udp_ping()`, `test_udp()`, "udp" test command     |
| `util/server.cc`  | Added `udp_server()` function                              |
| `util/cp_node.cc` | Added `udp_server` and `udp_client` classes, "udp" protocol option |

## Key Constants

| Constant             | Value    | Purpose                                              |
|----------------------|----------|------------------------------------------------------|
| `HOMA_HIJACK_FLAGS`  | 6        | Marker in the `flags` field (shared with TCP hijack) |
| `HOMA_HIJACK_URGENT` | 0xb97d   | Marker in the `urgent` field (shared with TCP hijack)|
