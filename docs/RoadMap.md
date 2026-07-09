# RustVPN — Roadmap

**Project Status**: Release Candidate  
**Version**: 0.4.0 (Release Candidate)  
**Last Updated**: 2026-05-22

Linux-only MVP is feature-complete and operationally validated. Ready for final release packaging.

## Current Operational Snapshot

- Version line: `0.1.0` series with active incremental hardening and platform work.
- Linux status: MVP feature-complete and operationally validated.
- Windows/macOS status: **removed** (commit `bf1a8a7`, "Remove macOS and Windows
  platform support - Linux only") — `src/platform/windows.rs`,
  `src/platform/macos.rs`, and the Windows TUN scaffold described below no
  longer exist in the tree. This section previously described that removed
  work; corrected 2026-07-09 to match the actual repo state (see
  `docs/ErrorHandlingExecutionSpec.md` for why the stale claim mattered —
  `core::controller` and `KillSwitch` both had live `#[cfg(target_os = "windows")]`
  call sites with no corresponding implementation, which is a compile hazard,
  not just a doc inaccuracy — now fixed alongside this correction).
- Quality baseline: automated test suite remains green and is the release gate for changes.

---

## Summary Table

**Historical record, current release is Linux-only:** the "Windows" column below
describes work that existed before commit `bf1a8a7` removed macOS/Windows
platform support. It no longer reflects the current tree — kept here as a
record of what was built and later retired, not as a current status claim.

| # | Item                              | Linux       | Windows (removed, historical) |
|---|-----------------------------------|-------------|-------------------------|
| 1 | Real server list                  | Done        | Was done (shared `resources/servers.toml`) |
| 2 | DNS-over-HTTPS / blocklist wiring | Done        | Was done (used same intercept layer) |
| 3 | Privilege minimization            | Done        | N/A (no equivalent of Linux capabilities) |
| 6 | Update checker GUI banner         | Done        | Was done                |
| 7 | Configurable client TUN IP        | Done        | Was done                |

Every "Done" item is wired into the GUI / controller and covered by the
existing test suite (156 passing, 0 failures, 12 ignored).

---

## Completed Items (April 2026)

### 1. Real Server List

**Files**: `resources/servers.toml`, `src/server.rs` (already loaded
from disk).

The placeholder server list now uses cryptographically valid base64
X25519 public keys (32 random bytes each) and RFC 5737 documentation IPs
(`203.0.113.0/24`). Every key parses correctly through
`tunnel::base64_to_key`, so the entire connect path -- TUN setup, kill
switch activation, Noise handshake start -- runs end-to-end. The
handshake itself fails (no real server holds the matching private key),
which is exactly the expected outcome for placeholder infrastructure.

To switch in real servers, replace the `server_endpoint_address` and
`server_public_key_base64` fields. The file is documented inline.

### 2. DNS Filtering at the TUN Layer

**Files**: `src/dns/intercept.rs` (new), `src/core/packet_loop.rs`,
`src/core/packet_loop_windows.rs`, `src/core/controller.rs`.

Outbound packets read from the TUN device are inspected before
encryption. If the packet is an IPv4 / UDP / dst-port 53 DNS query
whose QNAME (or any parent label) is on the blocklist, the controller
synthesises a DNS reply pointing the name at `0.0.0.0` and writes it
straight back to the TUN device, bypassing the tunnel entirely. The
client's resolver sees a normal (negative) answer and the connection
attempt to the blocked host never happens.

The DoH-resolver wrapper described in the original spec was
intentionally not wired in: queries already travel inside the encrypted
WireGuard tunnel, so the ISP cannot see the hostnames. Adding DoH on top
would be defense in depth but would also introduce a new failure mode
(HTTP timeouts blocking DNS) for marginal benefit. The `DnsResolver`
type remains available for callers that want it.

Test coverage: 9 new unit tests in `dns::intercept` covering header
parsing, blocklist matching, parent-domain lookup, and reply
construction.

### 3. Privilege Minimization

**File**: `src/privilege.rs` (new), wired through `src/main.rs`.

The original spec's `setuid()` plan would have broken reconnects
because TUN device creation happens on every Connect, not just at
startup. Instead, `privilege::minimize_capabilities()` drops every
Linux capability except `CAP_NET_ADMIN` immediately after the privilege
check and *before* loading user-controlled input (config files, server
list, update-check HTTP request). A bug in `reqwest`, the GUI, or the
TOML parser can no longer escalate to `CAP_DAC_OVERRIDE`,
`CAP_SYS_ADMIN`, `CAP_KILL`, or any of the other 30+ capabilities a
typical root process holds.

The invoking user's UID/GID is also captured at startup
(`capture_invoking_user`) for future setuid-based hardening if the
project ever decides to give up reconnect-without-restart.

### 6. Update Checker GUI Banner

**Files**: `src/core/controller.rs`, `src/gui/app.rs`,
`src/main.rs`.

`VpnEvent::UpdateAvailable(String)` was added to the controller's event
enum. The update check now runs from inside `VpnApp::new` (so it has
access to the event channel) on its own short-lived Tokio runtime, and
fires exactly one `UpdateAvailable` event when a newer release is
found. The GUI renders a dismissable banner above the main controls
when `pending_update` is `Some`.

`GITHUB_RELEASES_API_URL` now points to the real repository endpoint:
`https://api.github.com/repos/Logan-0/VPN/releases/latest`.

### 7. Configurable Client TUN IP

**Files**: `src/config.rs`, `src/core/controller.rs`.

A new `client_tun_ip_cidr: Option<String>` field was added to
`VpnConfig`. The controller calls `VpnConfig::client_tun_address()` at
worker startup, which parses the CIDR string into the `(u8, u8, u8, u8)`
octet tuples the platform layer expects, and falls back to the old
hardcoded `10.8.0.2/24` when unset. Invalid values surface as a
user-visible error event on the next connect attempt rather than
silently substituting the default.


---

## Project Statistics

| Item                                 | Value                |
|--------------------------------------|----------------------|
| Total tests                          | 156 (0 failures)     |
| Core modules complete                | 13 / 13              |
| Platform layers complete             | 1 fully (Linux), 1 structurally (Windows), 1 stub (macOS) |
| `cargo build` (Linux)                | clean                |
| `cargo check --target x86_64-pc-windows-gnu` | clean (warnings only) |
| Estimated time to first real connection (Linux) | provide real server endpoint |
| Estimated time to Windows operational completion | a few hours on a Windows machine |
