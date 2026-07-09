# Code Commenting Execution Spec — RustVPN

This document is the **execution instance** of the root [`CodeCommentingSpec.md`](../../CodeCommentingSpec.md) for RustVPN.

This is **not** a general educational overview. It records the measured state of in-code documentation coverage and accuracy across every `src/**/*.rs` file.

---

## Coverage tracker (last verified 2026-07-09)

| Area | File-level `//!` docs | `pub fn` docs | Status |
|------|------------------------|----------------|--------|
| All 21 files under `src/` | 100% — every file has a `//!` header with Role/Contracts/Platform Notes/Non-goals | Strong overall | see gap below |
| `src/privilege.rs`, `src/dns/{filter,intercept,resolver}.rs` | 100% | 100%, including failure-mode/safety-rationale sections | done |
| `src/core/killswitch.rs` public surface (`new`, `enable`, `disable`, `is_enabled`, `get_state`) | 100% | 100% | done |
| `src/core/killswitch.rs::enable_linux`/`disable_linux` | n/a (private fns) | **was undocumented — fixed 2026-07-09** | done |

**Method:** full read of all 21 `src/**/*.rs` files for `//!` headers, plus targeted review of the safety-critical modules (`killswitch.rs`, `privilege.rs`, `dns/*.rs`) for `pub fn` and safety-critical-private-fn doc coverage.

## Gap found and fixed: `enable_linux`/`disable_linux` had no `///` docs

Per `CodeCommentingSpec.md`, safety-critical functions require docs "where meaningful" regardless of `pub`-ness. `enable_linux`/`disable_linux` — the two functions that actually construct and remove the firewall rules, the most safety-critical code in the project — had only a bare `// Platform-specific implementations` comment above the pair. Added `///` docs to both documenting:
- The ordering invariant in `enable_linux`: only the final `iptables -I OUTPUT 1 -j RUSTVPN_OUT` call actually links the DROP-based chain into the traffic path, so a failure on any earlier call leaves traffic completely unblocked, not "partially protected." This directly explains *why* the P0 fail-closed fix in `ErrorHandlingExecutionSpec.md` was necessary — the doc now makes that risk discoverable from the code itself, not just from an external audit.
- Why `disable_linux` deliberately ignores individual command failures (`let _ =` throughout): a partial cleanup failure leaves the network *more* restricted, never less — the safe direction to fail in for a kill switch, unlike `enable_linux`.

## Accuracy gaps found and fixed (Gate 1 violations)

CodeCommentingSpec's Gate 1 requires comments/docs to match current implementation exactly. Four found, all stemming from commit `bf1a8a7` ("Remove macOS and Windows platform support - Linux only") not being fully propagated through the docs:

1. **`src/lib.rs`** and **`src/gui/mod.rs`** module docs claimed macOS/Windows platform support that doesn't exist (no `platform::macos`/`platform::windows` modules). Corrected to state Linux-only scope and explain what's actually missing.
2. **`src/dns/mod.rs`** claimed "encrypted DNS resolution via DNS-over-HTTPS (DoH)" as if it were part of the live path. `resolver::DnsResolver` is fully implemented but never instantiated or called from `core::` — verified via `grep -rn "DnsResolver" src/`, only its own definition matches. Corrected to state DoH is implemented-but-dormant.
3. **`src/core/killswitch.rs::enable`**'s doc comment claimed "macOS: Uses pf... Windows: Uses Windows Filtering Platform API" as active behavior. Corrected to state these platforms are not implemented and fail closed.
4. **`docs/RoadMap.md`** and **`docs/ProjectSummary.md`** — `RoadMap.md` claimed "The Windows path now compiles cleanly via `cargo check --target x86_64-pc-windows-gnu`" and `ProjectSummary.md`'s file tree listed `src/platform/macos.rs`, `src/platform/windows.rs`, and `src/tunnel/noise.rs` as existing files. None exist; confirmed via `git log` that they were deliberately removed in `bf1a8a7`, and that later commits ("docs: Align docs to v0.4.0 Linux-only release candidate") updated `Education.md` but missed `RoadMap.md`/`ProjectSummary.md`. Both corrected with explicit historical notes rather than silently rewritten, so the removal is traceable.

## Skipped / out of scope

- Full re-verification of all ~161 test docstrings — not exhaustively re-read this pass, no spot-check issues found in the files touched.
- `docs/Education.md` was not re-audited (it was already updated for the Linux-only release per its own commit history).
