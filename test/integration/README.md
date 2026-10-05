# UDP Tunnel Integration Tests

The integration scripts exercise a loaded Homa module in temporary network
namespaces and leave captures and logs under `artifacts/`.

Request/response callers use `homa_test --count 1 udp`, which sends 10
warmups and 1 measured request over the namespace-selected Homa transport.
Each shell and Python script has a top-of-file description of its purpose.
Local helper tests, including mocked client count and error checks, run without
root privileges or live traffic:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s test/integration -p 'test_*.py' -v
```

Run as root from the module tree:

```bash
test/integration/run_udp_tunnel.sh
```

The harness verifies:

- port-collision rollback and independent per-network-namespace controls;
- IPv4 and IPv6 request/response, including messages larger than the MTU;
- UDP source/destination port, length, checksum, and inner Homa header from
  an ingress packet capture;
- operation with veth TX checksum offload disabled when supported;
- concurrent socket/RPC creation during disable, followed by re-enable;
- namespace deletion during active RPCs, immediate recreation, and reuse;
- native Homa fallback regression.

Additional scripts:

- `run_udp_pmtu.sh`: routed IPv4/IPv6 PMTU and tiny-MTU rejection.
- `run_udp_checksum.sh`: valid, invalid, and computed-zero checksums.
- `run_udp_isolation.sh`: live native/UDP mismatch rejection both ways.
- `run_udp_retransmit.sh`: one-shot drop, retransmission, and control classes.
- `run_udp_pacing.sh`: native baseline and 100 Mbit/s UDP pacing proof.

`run_udp_pacing.sh` reports SRPT as incomplete on veth. Veth advertises a
fixed 10 Gbit/s rate, while Homa's qdisc has a 5% minimum; a rate-configurable
device is required for a valid constrained-link SRPT test.

Requirements are root privileges, a loaded `homa.ko`, `ip`, `tcpdump`,
`ethtool`, `tc`, `iptables`, Python 3, `timeout`, and the normal utility build
dependencies.
The harness warns when the running kernel is not Linux 6.17; results from an
older kernel are useful regression evidence but do not satisfy final V1 target
validation. The checksum validator accepts classic Ethernet pcap files and
uses only the Python standard library.

The race stress exercises real concurrent transitions but is not a formal
LKMM proof. Run the harness on a KASAN-enabled Linux 6.17 kernel to turn RCU
lifetime defects during namespace and socket teardown into detectable errors.

## Current Pending Evidence

- Linux 6.17 KASAN/lockdep/RCU execution and matching 6.17 headers.
- Physical-wire IPv6 offload validation; the physical hosts have no IPv6
  address.
- SRPT on a rate-configurable device running Homa's qdisc.
- Wireshark/TShark runtime dissector validation.

All feasible Linux 6.12 UDP scenarios are complete. TCP-related testing is not
required.