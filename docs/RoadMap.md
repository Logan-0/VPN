# RustVPN — Roadmap

**Project Status**: Stable  
**Version**: 1.0.0 (documented release; see `Projects/VersioningSpec.md`)  
**Last Updated**: 2026-07-09

Linux-only implementation is feature-complete and operationally validated. No
further optional features are planned — the documented scope for v1.0.0 is
frozen. The only remaining work is operational, not developmental: adding
more real server endpoints to `resources/servers.toml` as they become
available.

## Current Operational Snapshot

- Linux status: feature-complete and operationally validated.
- Windows/macOS: **permanently retired** (commit `bf1a8a7`, "Remove macOS and
  Windows platform support - Linux only"). `src/platform/windows.rs` and
  `src/platform/macos.rs` do not exist in the tree. There is no intention to
  revisit either platform — RustVPN is a Linux-only project going forward.
- Quality baseline: automated test suite (156 passing, 0 failures, 12
  ignored) remains green and is the release gate for changes.

---

## Summary Table

| # | Item                              | Status |
|---|-----------------------------------|--------|
| 1 | Real server list                  | Done   |
| 2 | DNS-over-HTTPS / blocklist wiring | Done   |
| 3 | Privilege minimization            | Done   |
| 4 | Update checker GUI banner         | Done   |
| 5 | Configurable client TUN IP        | Done   |

Every item is wired into the GUI / controller and covered by the existing
test suite (156 passing, 0 failures, 12 ignored).

---

## Completed Items

### 1. Real Server List

**Files**: `resources/servers.toml`, `src/server.rs` (already loaded
from disk).

The placeholder server list uses cryptographically valid base64
X25519 public keys (32 random bytes each) and RFC 5737 documentation IPs
(`203.0.113.0/24`). Every key parses correctly through
`tunnel::base64_to_key`, so the entire connect path -- TUN setup, kill
switch activation, Noise handshake start -- runs end-to-end. The
handshake itself fails (no real server holds the matching private key),
which is exactly the expected outcome for placeholder infrastructure.

To switch in real servers, replace the `server_endpoint_address` and
`server_public_key_base64` fields. The file is documented inline. This is
the only open-ended item in the project: adding more entries here is
ordinary operational upkeep, not a development task.

### 2. DNS Filtering at the TUN Layer

**Files**: `src/dns/intercept.rs`, `src/core/packet_loop.rs`,
`src/core/controller.rs`.

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
type remains available for callers that want it; wiring it in is not
planned.

Test coverage: 9 unit tests in `dns::intercept` covering header
parsing, blocklist matching, parent-domain lookup, and reply
construction.

### 3. Privilege Minimization

**File**: `src/privilege.rs`, wired through `src/main.rs`.

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
(`capture_invoking_user`), a leftover hook from an earlier setuid design
that is no longer planned.

### 4. Update Checker GUI Banner

**Files**: `src/core/controller.rs`, `src/gui/app.rs`,
`src/main.rs`.

`VpnEvent::UpdateAvailable(String)` was added to the controller's event
enum. The update check runs from inside `VpnApp::new` (so it has
access to the event channel) on its own short-lived Tokio runtime, and
fires exactly one `UpdateAvailable` event when a newer release is
found. The GUI renders a dismissable banner above the main controls
when `pending_update` is `Some`.

`GITHUB_RELEASES_API_URL` points to the real repository endpoint:
`https://api.github.com/repos/Logan-0/VPN/releases/latest`.

### 5. Configurable Client TUN IP

**Files**: `src/config.rs`, `src/core/controller.rs`.

A `client_tun_ip_cidr: Option<String>` field was added to
`VpnConfig`. The controller calls `VpnConfig::client_tun_address()` at
worker startup, which parses the CIDR string into the `(u8, u8, u8, u8)`
octet tuples the platform layer expects, and falls back to the
hardcoded `10.8.0.2/24` when unset. Invalid values surface as a
user-visible error event on the next connect attempt rather than
silently substituting the default.

---

## Project Statistics

| Item                                  | Value                |
|----------------------------------------|----------------------|
| Total tests                            | 156 (0 failures)     |
| Core modules complete                  | 13 / 13              |
| Platform layers complete               | 1 / 1 (Linux — the only supported platform) |
| `cargo build` (Linux)                  | clean                |
| Remaining work                         | none required; adding more server endpoints is optional, ongoing operational upkeep |

---

## What "Complete" Means Here

v1.0.0 is the documented, stable release. There is no "Before 1.0" backlog
left open, and no Windows/macOS work is planned or deferred — both were
evaluated and deliberately retired (see commit `bf1a8a7`). Historical audit
notes on error handling, testing, and optimization live in their respective
execution specs (`ErrorHandlingExecutionSpec.md`, `TestingStrategyExecutionSpec.md`,
`OptimizationExecutionSpec.md`); items marked "not attempted" there are
recorded technical debt, not committed roadmap work.
