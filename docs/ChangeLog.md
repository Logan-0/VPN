# Changelog

All notable changes to the RustVPN project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Project Status**: Alpha

---

## [Unreleased] - Alpha

### Added

#### Documentation
- **Project documentation suite**
  - RoadMap.md with consolidated status and remaining work
  - Education.md with architecture overview
  - ProjectSummary.md with feature summary
  - ChangeLog.md with version history

---

## Completed Items (April 2026)

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
- Captures invoking user's UID/GID for future setuid hardening
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
| Alpha | Linux operationally complete, Windows structurally complete, macOS stub |

---

## Next Steps

### Windows Operational Completion
- Run on real Windows 10/11
- Bundle wintun.dll with release artifact
- Verify netsh argument quoting
- Confirm WinTun adapter cleanup
- End-to-end smoke test with real WireGuard server

### Linux Enhancements
- Provide real server endpoint
- Production deployment testing
- Performance optimization

### General
- Consider macOS implementation if test machine becomes available
- Add more server locations
- Implement additional security features
