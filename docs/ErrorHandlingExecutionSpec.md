# Error Handling Execution Spec — RustVPN

This document is the **execution instance** of the root [`ErrorHandlingSpec.md`](../../ErrorHandlingSpec.md) for RustVPN. It cites specific files/functions and says *what happens today*, *why it's a problem*, and *the concrete fix*. Ordered by severity.

**Audience:** maintainers hardening a safety-critical VPN client. For a VPN, fail-closed means "on any doubt, block network traffic" — the opposite default from most services.

**First full audit: 2026-07-09.** No prior execution spec existed for this project.

---

## Severity legend

| Level | Meaning |
|-------|---------|
| P0 | Silent failure or wrong exit code — for a VPN, specifically: traffic leaks despite requested protection |
| P1 | Confusing/misdiagnosed errors, or one failure blinds a whole subsystem |
| P2 | Missing validation that lets bad input reach a tool |
| P3 | Hygiene: logging, taxonomy, panic audit |

---

## P0 — Kill switch enable failure did not abort the connect flow (fail-open) — FIXED 2026-07-09

**Where:** `src/core/controller.rs`, `VpnCommand::Connect` handler.

**Problem (as found):** when kill-switch protection was on and `ks.enable()` failed (missing `iptables`, permission issue, etc.), the code logged the error and emitted a GUI event, but did **not** abort — execution fell through into TUN device creation and full tunnel bring-up, so traffic could flow with no firewall backstop. This is the textbook fail-open kill-switch bug: the one path whose entire purpose is "block traffic if protection can't be guaranteed" treated its own failure as non-fatal.

The same pattern existed in `VpnCommand::SetKillSwitch(enabled)`: `kill_switch_enabled` was set to the user's requested value regardless of whether `ks.enable()` actually succeeded, so internal state (and the GUI checkbox) could say "protected" while no firewall rule existed.

**Fix applied:** in `Connect`, a failed `ks.enable()` now emits an error, transitions to `VpnState::Error`, and `continue`s (aborts the connect) instead of proceeding to bring up the tunnel. In `SetKillSwitch`, `kill_switch_enabled` is reset to `false` if `ks.enable()` fails, so the flag never lies about protection state.

**Verified:** `cargo build && cargo test` green. No existing test covered this path (see `TestingStrategyExecutionSpec.md` — this is the top testing gap).

---

## P0 — macOS/Windows kill switch referenced but not implemented (compile hazard) — FIXED 2026-07-09

**Where:** `src/core/killswitch.rs::enable`/`disable`.

**Problem (as found):** `#[cfg(target_os = "macos")] self.enable_macos(...)` and the Windows equivalent were called but never defined anywhere in the crate — a macOS/Windows build would fail to compile with a confusing "no method found" error, not a clear message. This matched a broader compile hazard: `bf1a8a7` ("Remove macOS and Windows platform support - Linux only") deleted `src/platform/windows.rs` and `src/platform/macos.rs` but left several `#[cfg(target_os = "windows"/"macos")]` call sites dangling across `controller.rs` and `killswitch.rs`.

**Fix applied:** added `enable_macos`/`disable_macos`/`enable_windows`/`disable_windows` stub methods that return a clear `Err` on enable (fail-closed — combined with the P0 fix above, this means a macOS/Windows build, if one is attempted again, cannot connect while claiming protection it doesn't have) and `Ok(())` on disable (disabling something never enabled is a correct no-op). Documentation across `lib.rs`, `gui/mod.rs`, `dns/mod.rs`, `docs/RoadMap.md`, and `docs/README.md` corrected to stop claiming macOS/Windows support exists (Gate 1 accuracy — see `CodeCommentingSpec.md`).

**Not fixed (deliberately out of scope):** actually implementing macOS `pf`/Windows Filtering Platform rules. That's a from-scratch platform reimplementation requiring a test machine on each OS — not attempted in this audit pass. `docs/RoadMap.md` now documents what would be needed to resume that work.

---

## P1 — `panic = "abort"` defeated Drop-based cleanup — FIXED 2026-07-09

**Where:** `Cargo.toml` `[profile.release]`.

**Problem (as found):** `KillSwitch::drop`, `LinuxPlatform::drop`, and `Tunnel::drop` all rely on `Drop` as a last-resort safety net to clean up firewall rules/TUN devices. `panic = "abort"` means any panic terminates the process without unwinding, so none of these `Drop` impls run — the intended recovery mechanism was architecturally present but release-profile-disabled.

**Fix applied:** removed `panic = "abort"` from `[profile.release]` (kept the default `panic = "unwind"`), with a comment explaining why. Small binary-size cost, but the Drop-based cleanup guarantee now actually fires on a release-build panic.

---

## P1 — Windows privilege check was fail-open by design — FIXED 2026-07-09

**Where:** `src/main.rs::check_privileges`.

**Problem (as found):** on Windows and any unrecognized platform, this startup gate unconditionally returned `true` ("Temporary: allow running for now"), i.e., it always claimed privileges were sufficient — exactly backwards for a privilege gate whose purpose is to fail fast when it can't verify what it's checking.

**Fix applied:** both branches now return `false` (fail-closed) with a clear error log. Confirmed the caller (`main()`) already calls `std::process::exit(1)` on `false`, so this correctly blocks startup rather than limping into a later, more confusing failure.

---

## P2 — `update.rs`: unbounded HTTP call + status ignored before parsing — FIXED 2026-07-09

**Where:** `src/update.rs::check_for_updates`.

**Problem (as found):** `reqwest::Client::new()` has no default timeout and none was set — a hung GitHub API connection blocked this background task indefinitely. Separately, the response body was parsed as JSON before checking `response.status()`, so a rate-limit (403) or outage (5xx) produced a misleading "failed to parse JSON" error instead of a clear status-based one.

**Fix applied:** client now built with a 10s timeout; `response.error_for_status()` checked before `.json()`, with `.context(...)` on both for a clear error chain.

---

## P3 — Latent panics guarded only by "this can't fail today" — not attempted this pass

**Where (still open):**
- `src/gui/app.rs` — `ServerManager::new().unwrap()` at GUI startup.
- `src/core/reconnect.rs` — `Self::new().expect(...)` in `impl Default`.
- `src/core/controller.rs` — three `.expect(...)` calls around Tokio runtime/thread creation inside the spawned VPN worker thread.
- `src/platform/linux.rs` — `self.tun_device.as_mut().unwrap()` safe only because of an ambient invariant two lines above.

**Status:** flagged, not fixed. None are currently reachable (the functions they call don't actually fail today), and with `panic = "abort"` now removed (see P1 above), a panic here at least unwinds and lets `Drop`-based cleanup run rather than hard-aborting the process — which meaningfully lowers the severity of these compared to when this audit started. Left as documented technical debt rather than rushed changes to safety-adjacent code paths without dedicated review.

---

## Summary

| Finding | Severity | Status |
|---|---|---|
| Kill switch fail-open on enable failure | P0 | **Fixed 2026-07-09** |
| macOS/Windows killswitch compile hazard | P0 | **Fixed 2026-07-09** (stubs fail closed; real implementation still absent) |
| `panic = "abort"` defeats Drop cleanup | P1 | **Fixed 2026-07-09** |
| Windows privilege check fail-open default | P1 | **Fixed 2026-07-09** |
| `update.rs` unbounded call + status ignored | P2 | **Fixed 2026-07-09** |
| Latent `.unwrap()`/`.expect()` sites | P3 | Open, documented, low urgency |

The two P0s were real, live traffic-leak risks in the kill-switch path — both closed. Everything else applied this pass is either a direct enabler of those fixes (Drop cleanup, privilege gate) or a low-risk bounded-call fix.
