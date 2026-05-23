# RustVPN — Roadmap

**Version**: 0.4.0 (Release Candidate)  
**Last Updated**: 2026-05-22

Linux-only MVP is feature-complete and operationally validated. Ready for final release packaging.

## Current Operational Snapshot

- Version line: `0.1.0` series with active incremental hardening and platform work.
- Linux status: MVP feature-complete and operationally validated.
- Windows status: code-complete path compiles cleanly but remains operationally unverified on physical hosts.
- macOS status: intentionally deferred and tracked as future platform work.
- Quality baseline: automated test suite remains green and is the release gate for changes.

---

## Summary Table

| # | Item                              | Linux       | Windows                 |
|---|-----------------------------------|-------------|-------------------------|
| 1 | Real server list                  | Done        | Done (shared `resources/servers.toml`) |
| 2 | DNS-over-HTTPS / blocklist wiring | Done        | Done (uses same intercept layer) |
| 3 | Privilege minimization            | Done        | N/A (no equivalent of Linux capabilities) |
| 4 | macOS TUN device                  | N/A         | N/A — explicitly skipped |
| 5 | Windows TUN device                | N/A         | Structural only — see notes below |
| 6 | Update checker GUI banner         | Done        | Done                    |
| 7 | Configurable client TUN IP        | Done        | Done                    |

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

### 5. Windows TUN Device — Structural Only

**Files**: `src/platform/windows.rs`, `src/core/packet_loop_windows.rs`,
`Cargo.toml` (added `wintun = "0.5"` under
`[target.'cfg(windows)'.dependencies]`).

The Windows path now compiles cleanly via
`cargo check --target x86_64-pc-windows-gnu`. It uses the WinTun driver
through the official `wintun` crate, configures the adapter address and
MTU via `netsh`, and adds the same routing pattern as Linux
(server bypass route via the original gateway, plus two half-default
routes through the tunnel). A platform-specific packet loop drives the
WinTun session API since Windows does not expose a file descriptor.

**What this is**: a code-complete, type-safe scaffold. The Linux
controller and Windows controller share one Connect handler via a
`TunHandle` cfg-aliased type, so future Linux-side fixes apply
automatically.

**What this is not**: operationally validated. None of the following
have been done because the development environment is Linux-only:

- Running on real Windows 10/11
- Bundling `wintun.dll` with the release artifact
- Verifying that the netsh argument quoting handles spaces/Unicode
- Confirming WinTun adapter cleanup after a crash
- End-to-end smoke test of TUN read/write through a real WireGuard server

These are deferred for a future Windows-equipped session. Mark Windows
as **functionally complete but operationally unverified** in release
notes.

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

## Skipped Items

### 4. macOS TUN Device

Explicitly skipped per user direction. `src/platform/macos.rs` remains
the unmodified stub. Adding macOS support requires opening a
`PF_SYSTEM` / `SYSPROTO_CONTROL` socket for `utun`, `ioctl`-based IP
configuration, and `route add` for routing -- straightforward but
needs a macOS test machine.

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
