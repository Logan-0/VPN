# Optimization Execution Spec — RustVPN

This document is the **execution instance** of the root [`OptimizationSpec.md`](../../OptimizationSpec.md) for RustVPN.

**First full audit: 2026-07-09.**

> **Guiding rule:** none of these may weaken kill-switch/privilege fail-closed behavior. See `ErrorHandlingExecutionSpec.md` for the safety-critical fixes made alongside these.

---

## 1. Release profile favored binary size over packet-loop throughput — FIXED

**Where:** `Cargo.toml` `[profile.release]`.

`opt-level = "z"` (optimize for size) was applied crate-wide, including `Tunnel::encapsulate`/`decapsulate` (`src/core/tunnel.rs`), which run in `run_packet_loop`'s hot loop (`src/core/packet_loop.rs`) on every network packet. Size-optimization is the wrong tradeoff for a throughput/latency-sensitive per-packet crypto loop.

**Fix applied:** changed to `opt-level = 3`. Kept `lto = true`, `codegen-units = 1`, `strip = true`. (Also removed `panic = "abort"` in the same block — see `ErrorHandlingExecutionSpec.md` P1; unrelated optimization but same file/section.)

**Verified:** `cargo build --all-features` clean.

---

## 2. `tokio` pulled in `"full"` feature set — FIXED

**Where:** `Cargo.toml`.

Actual usage across the crate: `tokio::runtime::{Builder, Runtime}` (rt + rt-multi-thread), `tokio::select!`/`#[tokio::test]` (macros), `tokio::sync::{mpsc, watch}`, `tokio::time::{interval, sleep}`, `tokio::net::UdpSocket`, `tokio::task::spawn_blocking`. No filesystem, process, or signal tokio APIs.

**Fix applied:** `features = ["rt", "rt-multi-thread", "macros", "sync", "time", "net"]`. `cargo build --all-features` compiled clean with no missing-feature errors.

---

## 3. `reqwest::Client::new()` rebuilt without a timeout — FIXED (folds into an Error Handling fix)

**Where:** `src/update.rs::check_for_updates`.

Covered in `ErrorHandlingExecutionSpec.md` P2 — the same fix (build a client once with `.timeout(...)`) addresses both the missing-timeout error-handling gap and the "rebuild an expensive client per call" optimization pattern. Low runtime impact today (called once per app launch), but the fix was free to combine.

---

## 4. Unused `mockall` dev-dependency — kept, not removed (see Testing spec)

**Where:** `Cargo.toml` `[dev-dependencies]`.

Zero references anywhere in `src/`/`tests/` today — normally a "trim unused dependency" candidate. **Not removed**, because `TestingStrategyExecutionSpec.md`'s top-priority recommendation is to use it for a `KillSwitch` command-runner mock seam (the biggest testing gap in the project). Removing it now would just be churn if that refactor happens soon. Revisit if that testing work is explicitly deprioritized — then remove it.

---

## 5. Per-packet heap allocation in the hot loop — NOT attempted this pass

**Where:** `src/core/packet_loop.rs`, TX/RX arms.

Every packet in both directions costs at least two fresh heap allocations (`vec![0u8; ...]` for the encrypt/decrypt buffer, plus a `.to_vec()` copy for batching) inside the single hottest loop in the application.

**Recommendation:** reuse pooled buffers (a small free-list of `Vec<u8>`, or `bytes::BytesMut` with `split_to`) instead of allocating fresh per packet. **Medium effort, not attempted:** needs care around buffer lifetime/reuse correctness in a loop that's also the kill-switch's primary traffic path — exactly the kind of change that deserves a throughput micro-benchmark before/after (per `TestingStrategySpec.md`'s "add a perf regression guard before optimizing" guidance) rather than a same-pass rewrite. Flagged for a dedicated follow-up.

---

## Quick-reference summary

| # | Optimization | Effort | Status |
|---|---|---|---|
| 1 | `opt-level` size→speed for packet hot path | Low/Medium | **Fixed 2026-07-09** |
| 2 | Trim `tokio` features | Low | **Fixed 2026-07-09** |
| 3 | Reuse `reqwest::Client` with timeout | Trivial | **Fixed 2026-07-09** (via error-handling fix) |
| 4 | Unused `mockall` dependency | Trivial | Kept intentionally — reserved for testing work |
| 5 | Per-packet heap allocation | Medium | Open — needs a benchmark-guarded follow-up |

Items 1–3 are done and verified. Item 5 is the one genuine remaining performance opportunity, deliberately deferred rather than rushed on the packet-processing hot path.
