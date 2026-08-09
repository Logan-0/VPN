# Changelog

All notable changes to the RustVPN project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Project Status**: Stable (v1.0.0)

---

## [Unreleased] - 2026-08-09

### Changed

- **Documentation pass** — `docs/RoadMap.md` was reduced from a 151-line
  completed-work archive to the small amount of genuinely open work. The
  five "Completed Items" it described (real server list, DNS filtering at the
  TUN layer, privilege minimization, update-checker GUI banner, configurable
  client TUN IP) were already recorded in this file's April 2026 snapshot
  below and were removed rather than duplicated. The design *rationale* the
  roadmap carried — why the DoH resolver was deliberately left unwired, and
  why the original `setuid()` plan was rejected in favour of
  `minimize_capabilities()` — moved to `docs/Education.md`, which is the
  right home for it.
- Corrected the recorded test totals: the suite is **158 passing, 0 failures,
  10 ignored** (7 of the ignored are doc-tests), not the 156/12 the docs had
  been repeating.
- Corrected `docs/README.md`, which still claimed `config::get_config_path`
  carried inert `#[cfg(target_os = "macos"/"windows")]` branches. Those were
  removed in the optimization pass recorded below; the function is now
  unconditional.
- Reframed the April 2026 snapshot's note on `capture_invoking_user`: it was
  described as groundwork "for future setuid hardening", but the setuid
  design was abandoned and the function is a leftover hook.

---

## [Unreleased] - 2026-07-14

Post-1.0.0 optimization pass. Internal refactors, hot-path allocation
cleanup, and dead-code/dependency pruning only — no user-facing feature
change, and the safety-critical behaviors (kill-switch fail-closed ordering,
WireGuard crypto correctness, DNS-leak prevention) are preserved. Every claim
below maps to a change in commit `8633749`.

### Changed

- **Packet loop hot path** (`src/core/packet_loop.rs`) — Removed the
  env-configurable UDP batching (`BATCH_SIZE` / `BATCH_TIMEOUT_MS`,
  `flush_packet_buffer`), which issued one `send()` per packet anyway (it
  coalesced no syscalls) while adding up to a few ms of latency and a
  per-packet `.to_vec()` copy; outbound encrypted packets are now sent
  immediately. Added a TUN buffer recycling free-list and hoisted the
  encrypt/decrypt scratch buffers out of the loop, so no per-packet `Vec` is
  allocated and zeroed. **Crypto correctness preserved**: only the
  boringtun-written `[..n]` prefix is ever transmitted, so stale trailing
  bytes from a reused buffer are never sent.
- **Kill switch** (`src/core/killswitch.rs`) — Collapsed the repeated
  `iptables` invocations into `iptables_checked` / `iptables_best_effort`
  helpers plus an RFC 1918 loop. **Fail-closed ordering preserved**: the
  OUTPUT chain link-in remains the last, `?`-checked step so a partial
  failure never leaves a "looks blocked but isn't" state, and rule removal on
  disable stays best-effort (failing to remove a rule leaves the network
  *more* restricted — the safe direction).
- **Controller** (`src/core/controller.rs`) — Centralized the
  "emit `Error` event + `StateChanged(Error)`" invariant in `emit_error()`
  and the backoff-then-re-`Connect` logic in `resend_connect_after()`, shared
  by both auto-reconnect retry paths. The exponential backoff ladder is
  unchanged.
- **DNS filtering** (`src/dns/filter.rs`, `src/dns/intercept.rs`) — Blocklist
  matching now normalizes qnames through a `Cow`, so only the rare
  mixed-case / trailing-dot / non-ASCII query allocates; qname parsing
  reserves worst-case capacity up front. Filtering and DNS-leak-prevention
  behavior is unchanged.
- **GUI** (`src/gui/app.rs`) — Dropped the dedicated `CoreEvent`
  subscription; `VpnEvent`s are now drained from the receiver on the periodic
  `Tick`, whose interval was relaxed from 100 ms to 1 s, and the startup
  update check now runs on a current-thread Tokio runtime.
- **Linux-only conditional cleanup** — Removed dead `macOS`/`Windows`
  `#[cfg]` branches now that the tree is Linux-only, collapsing
  `config::get_config_path`, `main`'s privilege check, and the
  controller/killswitch/`core::mod` platform dispatch to the single supported
  path. Linux behavior is unchanged, and the privilege check still fails
  closed.

### Removed

- Dead code: `src/core/packet_loop_windows.rs` (235 lines, unreachable with
  no `platform::windows` to pair with) and the unused reconnect helpers in
  `src/core/reconnect.rs` (`health_check_loop`, `ReconnectReason`,
  `wait_before_reconnect`, `HEALTH_CHECK_INTERVAL`).
- Unused dependencies from `Cargo.toml`: `rustls`, `rustls-native-certs`,
  `thiserror`, the Windows-target `windows` / `wintun` crates, and the
  `tokio-test` dev-dependency.
- Retired the audit execution-spec documents (`CodeCommentingExecutionSpec.md`,
  `ErrorHandlingExecutionSpec.md`, `OptimizationExecutionSpec.md`,
  `TestingStrategyExecutionSpec.md`) from `docs/`.

---

## [1.0.0] - 2026-07-09

### Changed
- **Version bump**: 0.4.0 → **1.0.0** — Stable release; documented scope is frozen.
- **Project Status**: Release Candidate → **Stable**.
- Fixed broken sequential numbering in `docs/RoadMap.md` (previously skipped
  items 4-5 after Windows/macOS entries were removed without renumbering).
- Removed stale cross-platform (macOS/Windows) claims from `docs/Education.md`
  and `docs/README.md`'s Technology Stack, Quick Start, and
  Configuration File Location sections — RustVPN is Linux-only with no
  intention of adding other platforms.
- Corrected `Cargo.toml`'s and `debian/control`'s package descriptions, which
  still advertised "cross-platform across Linux, macOS, and Windows."

### Scope for 1.0.0
No further optional features are planned. The only remaining, non-blocking
work is expanding `resources/servers.toml` with additional real server
endpoints as they become available — operational upkeep, not development.

---

## [0.4.0] - 2026-05-21

### Changed
- **Version bump**: 0.1.0 → **0.4.0** — release candidate; core features complete.
- **Project Status**: Alpha → **Release Candidate**.
- **Platform Support**: Linux-only with full CAP_NET_ADMIN support.

---

## [Unreleased] - Alpha

### Added

#### Documentation
- **Project documentation suite**
  - RoadMap.md with consolidated status and remaining work
  - Education.md with architecture overview
  - README.md with feature summary
  - ChangeLog.md with version history

### Changed

- Set `GITHUB_RELEASES_API_URL` to the real endpoint: `https://api.github.com/repos/Logan-0/VPN/releases/latest`.
- Updated update-checker documentation examples in `docs/RoadMap.md` and `docs/Education.md` to match the real repository URL.

---

## Completed Items (April 2026)

**Historical snapshot** — this section and the three tables immediately
below it (Project Statistics, Platform Status, Known Limitations, Version
History Summary) describe the state of the project in April 2026, before
Windows/macOS support was removed in commit `bf1a8a7`. Items 4 and 7 below
(Windows TUN Device, macOS TUN Device) no longer exist in the tree. See the
`[1.0.0]` entry above and `docs/RoadMap.md` for current, accurate status.

### 1. Real Server List
- Placeholder server list with cryptographically valid base64 X25519 public keys
- RFC 5737 documentation IPs (203.0.113.0/24)
- Every key parses correctly through `tunnel::base64_to_key`
- Handshake fails as expected (no real server holds matching private key)

### 2. DNS Filtering at the TUN Layer
- Outbound packets inspected before encryption
- IPv4 / UDP / dst-port 53 DNS query interception
- Blocklist matching (QNAME or parent label)
- Synthesised DNS reply pointing blocked domains to 0.0.0.0
- Test coverage: 9 unit tests in `dns::intercept`

### 3. Privilege Minimization (Linux)
- `privilege::minimize_capabilities()` drops all capabilities except CAP_NET_ADMIN
- Runs before loading user-controlled input
- Captures invoking user's UID/GID (`capture_invoking_user`) — a leftover hook
  from a setuid design that was evaluated and abandoned; see `docs/Education.md`
- Prevents escalation to CAP_DAC_OVERRIDE, CAP_SYS_ADMIN, CAP_KILL, etc.

### 4. Windows TUN Device (Structural Only)
- Compiles cleanly via `cargo check --target x86_64-pc-windows-gnu`
- Uses WinTun driver through official `wintun` crate
- Configures adapter address and MTU via netsh
- Platform-specific packet loop drives WinTun session API
- **Not operationally validated**: Needs testing on real Windows 10/11

### 5. Update Checker GUI Banner
- `VpnEvent::UpdateAvailable(String)` added to controller event enum
- Update check runs from `VpnApp::new` on its own Tokio runtime
- Fires exactly one `UpdateAvailable` event when newer release found
- GUI renders dismissable banner when `pending_update` is Some

### 6. Configurable Client TUN IP
- New `client_tun_ip_cidr: Option<String>` field in `VpnConfig`
- Controller calls `VpnConfig::client_tun_address()` at worker startup
- Parses CIDR string into octet tuples
- Falls back to hardcoded `10.8.0.2/24` when unset
- Invalid values surface as user-visible error

### 7. macOS TUN Device
- **Explicitly skipped** per user direction
- `src/platform/macos.rs` remains unmodified stub

---

## Project Statistics

| Item | Value |
|------|-------|
| Total tests | 156 (0 failures) |
| Core modules complete | 13 / 13 |
| Platform layers | 1 fully (Linux), 1 structurally (Windows), 1 stub (macOS) |
| `cargo build` (Linux) | Clean |
| `cargo check --target x86_64-pc-windows-gnu` | Clean (warnings only) |

---

## Platform Status

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | Fully operational | All features working |
| Windows | Structurally complete | Code-complete, needs testing on real hardware |
| macOS | Stub | Explicitly skipped, not a priority |

---

## Known Limitations

### Windows
- Not operationally validated on real Windows 10/11
- WinTun.dll not bundled with release artifact
- netsh argument quoting not verified for spaces/Unicode
- WinTun adapter cleanup after crash not confirmed
- End-to-end smoke test not performed

### macOS
- Explicitly skipped
- Would require `PF_SYSTEM` / `SYSPROTO_CONTROL` socket
- Would require `ioctl`-based IP configuration
- Would require `route add` for routing
- Needs macOS test machine

---

## Version History Summary

| Status | Description |
|--------|-------------|
| Stable (current) | v1.0.0 — Linux-only, feature-complete; no further platform or feature work planned |
| Alpha (historical, April 2026) | Linux operationally complete, Windows structurally complete, macOS stub — Windows/macOS later removed in `bf1a8a7` |

---

## Next Steps

Tracked in `docs/RoadMap.md`, not here. In short: nothing is required for
v1.0.0, and the only ongoing task is adding real server endpoints to
`resources/servers.toml`.
