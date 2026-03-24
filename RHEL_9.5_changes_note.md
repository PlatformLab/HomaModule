# Homa Kernel Module — RHEL 9.5 Porting Changes

**Base branch:** `rhel8` (commit `bba532e`)
**Target kernel:** 5.14.0-503.15.1.el9_5.x86_64 (RHEL 9.5)

The `rhel8` branch was written for kernel 4.18 (RHEL 8). The following
changes were needed to compile and run on kernel 5.14 (RHEL 9.5).

---

## homa_impl.h

**What changed:** `homa_setsockopt` declaration — `char __user *optval`
→ `sockptr_t optval`.

**Why:** Kernel 5.14 changed the `proto_ops.setsockopt` callback
signature to use `sockptr_t` instead of a raw user-space pointer.
`sockptr_t` is a tagged union that can represent both user and kernel
pointers, allowing the same interface for both `setsockopt` and
`bpf_setsockopt`.

---

## homa_metrics.c

**What changed:** `struct file_operations` → `struct proc_ops`;
field names prefixed with `proc_` (e.g. `.open` → `.proc_open`).

**Why:** Kernel 5.6 introduced `proc_ops` as a dedicated operations
structure for `/proc` files, replacing the generic `file_operations`.
This avoids pulling in unused VFS callbacks and reduces the structure
size.

---

## homa_offload.c

**What changed (1):** Added `#include <net/rps.h>` and
`#include <net/gro.h>`.

**Why:** In kernel 5.14 the declarations for `rps_sock_flow_table`,
`rps_cpu_mask`, `GRO_HASH_BUCKETS`, and the `gro_list`/`napi_struct`
GRO fields were moved out of the main networking headers into
`<net/rps.h>` and `<net/gro.h>`.

**What changed (2):** Uncommented and enabled `tt_record` calls inside
`homa_tcp_gro_receive`, plus added a `tt_record2` for source address
logging.

**Why:** Debugging instrumentation to trace TCP-hijacking packet flow.
The original code had these trace points commented out; they were
enabled to diagnose Homa-over-TCP receive issues on kernel 5.14.

---

## homa_outgoing.c

**What changed:** Added a 7th argument (`0`) to all four `ip6_xmit`
call sites.

**Why:** Kernel 5.14 added a `priority` parameter (7th argument) to
`ip6_xmit()`. Passing `0` preserves the default priority behavior.

---

## homa_peer.c

**What changed:** `security_sk_classify_flow(&hsk->sock, &peer->flow)`
→ `security_sk_classify_flow(&hsk->sock, &peer->flow.u.__fl_common)`
at both IPv4 and IPv6 call sites.

**Why:** Kernel 5.14 changed `security_sk_classify_flow` to take a
`struct flowi_common *` instead of a `struct flowi *`. Passing
`&peer->flow.u.__fl_common` provides the correct inner type.

---

## homa_plumbing.c

**What changed (1):** Removed `.netns_ok = 1` from the
`homa_protocol` struct.

**Why:** The `.netns_ok` field was removed from `struct net_protocol`
in kernel 5.14. Network-namespace awareness is now handled differently.

**What changed (2):** `char __user *optval` → `sockptr_t optval` in
`homa_setsockopt` definition; `copy_from_user` → `copy_from_sockptr`
(two call sites).

**Why:** Same `setsockopt` signature change as noted in `homa_impl.h`.
`copy_from_sockptr` is the correct accessor for `sockptr_t`, handling
both user and kernel pointers transparently.

**What changed (3):** `complete_and_exit` → `kthread_complete_and_exit`.

**Why:** `complete_and_exit` was renamed to `kthread_complete_and_exit`
in kernel 5.17 (backported to RHEL 9's 5.14). The old name no longer
exists.

---

## homa_skb.c

**What changed:** `frag->page_offset` → `frag->bv_offset` at four
access sites.

**Why:** The `bio_vec` / `skb_frag_t` structure renamed the
`page_offset` field to `bv_offset` in kernel 5.14, aligning the
naming with the block I/O layer's `struct bio_vec`.

---

## timetrace.c

**What changed:** `struct file_operations` → `struct proc_ops`;
field names prefixed with `proc_` (e.g. `.open` → `.proc_open`).

**Why:** Same `proc_ops` migration as `homa_metrics.c`. Required
since kernel 5.6.
