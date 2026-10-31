# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

Linux kernel module implementing the Homa transport. This variant sends **all**
Homa packets as UDP datagrams with outer source and destination port **5001**
(IPv4 and IPv6). `IPPROTO_HOMA` (146) is kept only as the application socket
protocol selector and option level; it is not a wire protocol. The Homa socket
API is unchanged. There is no TCP hijack, no native IP delivery, and no new
sysctl. The strip/upstream mechanism (`__STRIP__`, `__UPSTREAM__`,
`IF_NO_STRIP`, `util/strip.py`, `Makefile.upstream`) is unchanged and the UDP
tunnel is part of the stripped build; the GRO callbacks in `homa_offload.c` are
not. Plain TCP in the utilities is application
functionality and stays.

## Build and test

- Module: `make all` (uses `KDIR`, default `/lib/modules/$(uname -r)/build`).
- Unit tests: `make -C test test_both` (IPv4 and IPv6, `-Wall -Werror`, ASan).
  The current suite has 863 tests per family; keep it passing.
- Static checks: `make checkpatch`, `make kdoc` (not yet run on this change).
- Utilities: `make -C util all`. A stale tree can make this a no-op; use
  `make -B -C util all` for a full rebuild.
- Validated on Linux 6.17.8 only. The code uses the v6.17 signatures of
  `udp_tunnel_xmit_skb` / `udp_tunnel6_xmit_skb` and has no kernel-version guard.
- Do not run `make clean` on shared test hosts; remove generated files by an
  explicit list.

## Layout

- `homa_udp_tunnel.c/.h`: per-namespace pair of kernel UDP sockets, encap
  receive (`homa_udp_encap_rcv`), ICMP (`homa_udp_encap_err_rcv`).
- `homa_peer.c`: `homa_route_xmit`, the single transmit entry.
- `homa_outgoing.c`: packet geometry, `homa_tx_skb_alloc` (GSO skbs),
  `homa_tx_skb_send`, control packets.
- `homa_offload.c`: Homa-aware UDP GRO callbacks.
- `homa_plumbing.c`: module init/exit, `homa_softirq`, ICMP error handlers.
- `homa_qdisc.c`: Homa packet classification and pacing.
- `test/`: unit tests (`unit_*.c`), kernel mocks in `mock.c`, fixtures in
  `utils.c`. `util/`: `cp_node`, `server`, `homa_test`, raw UDP tools
  (`send_raw`, `receive_raw`), timetrace scripts.

## Invariants (do not break)

- The kernel tunnel transmit helpers return `void` and always consume the skb
  and the dst reference. Do not claim they return an error.
- `sk_user_data` of a tunnel socket is published only after both sockets exist
  and is NULL during teardown. Every callback must treat NULL as "discard".
- Do not hold an RPC lock across `homa_route_xmit`. Follow the lock-order notes
  in `homa_impl.h` and the BH/RCU notes in `homa_peer.c`.
- Each GSO segment carries its own full Homa DATA header; `max_seg_data` is fixed
  when a message is built. Receive requires a nonzero UDP checksum and
  UDP length equal to the buffer length.
- A route whose MTU is too small fails with `-EHOSTUNREACH` and `error_msg`,
  at message creation and, if the MTU shrinks later, at send time (RPC abort).
  Do not add PMTU learning or message rebuilding.
- Bound every wire-controlled value (priority, lengths, offsets) before using it
  as an index. The GRANT priority is not bounded yet (see Open items).

## Conventions

- Files start with `// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+`.
  Kernel style, 80 columns, kernel-doc on non-trivial functions (state locking,
  ownership and return values).
- Keep private functions `static`, headers narrow, and comments about reasons
  and invariants, not obvious steps. Use `__must_hold` for caller-locked
  helpers (the repo does not use `lockdep_assert_held`).
- Unit tests: `TEST_F(suite, function__case)`; add or update tests with every
  behavior change. Reuse existing helpers and kernel code before writing new
  plumbing; justify custom code.
- Do not make unrelated changes (formatting sweeps, mode changes, tooling).
  Record unrelated problems instead of fixing them.

## How to work

- Edit files with the editor tools, not with shell redirection or scripted
  rewrites. Do not change files outside the working directory.
- Do not assume. When scope, design or a host action is unclear, ask first.
- If a command fails because of the environment (for example SSH), stop and ask
  before retrying.
- Check every change for: agreement on design and scope, prior art (Homa and
  in-tree kernel code, including helper contracts for ownership, headroom,
  checksum, GSO/GRO), explicit lock ownership, resource lifetimes and teardown,
  deliberate error paths, behavior and performance preservation, and a focused
  diff with reproducible evidence.

## Validation and test hosts

- Builds and tests run on the designated test hosts, not locally. Ask for the
  host names, paths and permissions; do not guess them.
- Without approval: read-only inspection, and builds and unit tests in the
  recorded remote tree. With approval only: loading or unloading the module,
  changing sysctls, NIC or firewall settings, injecting packets into UDP 5001
  (`send_raw`), and anything memory- or CPU-heavy on shared hosts.
- Keep evidence in the working directory, tie it to a commit or file hashes,
  and state which checks passed, failed or were not run.

## Records

For each change, state the decision, the files changed, and what was and was
not tested (in the commit message and the PR description).

## Open items and pitfalls

- GRANT priority is stored unclamped (`homa_incoming.c`) and can index 8-entry
  arrays out of bounds; pre-existing.
- `softirq_backlog` is incremented only for merged batches but decremented for
  every `homa_softirq` call, so it drifts.
- `is_homa_pkt` pulls only the 13-byte common header.
- ICMP errors match on peer address and Homa destination port, not RPC id.
- The qdisc counts the 24-byte frame overhead once per skb, not per segment.
- Default `max_gso_size` (1000) gives one segment per skb.
- Not tested: IPv6 traffic, retransmission and loss, the send-time `-EMSGSIZE`
  abort on the wire, other kernels, performance.
- Some utilities are stale: `get_time_trace` (old syscall), `send_many`,
  `smi` core arguments, and sysctl names in `util/cp_bench` and `util/cperf.py`.

## Before a PR

Commit with a clear message, run `checkpatch` and `kdoc`, rebuild and re-run
the unit tests and the runtime test on the final revision, and disclose the
limitations above.
