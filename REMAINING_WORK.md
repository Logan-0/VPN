# RustVPN — Remaining Work

**Last Updated**: April 20, 2026

This document covers only work that is **not yet complete**. For the full list
of what is already implemented, see `STATUS.md`.

---

## Priority 1 — Blocking for Real-World Use

### 1. Real Server List

**File**: `src/server.rs`, `resources/servers.toml` (to create)  
**Complexity**: Low

**Why this matters**: The current server list is hardcoded with placeholder IP
addresses and dummy WireGuard public keys. Clicking Connect will reach
`create_tun()` and the Noise handshake attempt, but the handshake will
immediately fail because the keys are fake. Nothing in the core needs to change
— you just need real endpoints.

**What WireGuard needs from a server**:
- A UDP `host:port` endpoint reachable from the internet
- The server's X25519 public key (32 bytes, base64-encoded)
- The server must be configured to route the client's assigned TUN IP (`10.8.0.2`)

**What to do**:
1. Create `resources/servers.toml` using the format below
2. Update `ServerManager::new()` in `src/server.rs` to load from that file with `include_str!()` or `fs::read_to_string()`

```toml
# resources/servers.toml

[[servers]]
id = "us-nyc-1"
name = "US — New York"
country = "US"
city = "New York"
ip = "203.0.113.1"
port = 51820
public_key = "REAL_BASE64_PUBLIC_KEY_HERE="

[[servers]]
id = "se-stockholm-1"
name = "Sweden — Stockholm"
country = "SE"
city = "Stockholm"
ip = "203.0.113.10"
port = 51820
public_key = "REAL_BASE64_PUBLIC_KEY_HERE="
```

---

## Priority 2 — Security Features

### 2. DNS-over-HTTPS Wiring

**Files**: `src/dns/filter.rs`, `src/dns/resolver.rs`, `src/core/controller.rs`  
**Complexity**: Medium

**Why this matters**: Without this, DNS queries bypass the VPN tunnel entirely.
Your browser sends a DNS query to `8.8.8.8:53` over UDP — that packet exits
through the TUN device and gets routed through the tunnel, but the *reply* comes
back from Google's IP directly. More critically, many DNS queries are made
before any packets flow through the tunnel, so your ISP can see every hostname
you visit. DNS-over-HTTPS wraps DNS inside an encrypted HTTPS connection,
preventing this.

**What already exists**:
- `DnsResolver` in `src/dns/resolver.rs` — fully implemented Cloudflare DoH
  (`1.1.1.1/dns-query`) and Google DoH (`8.8.8.8/dns-query`) clients using
  `hickory-resolver`
- `DnsFilter` in `src/dns/filter.rs` — blocklist matching with `HashSet<String>`,
  hosts-file parsing, `DnsFilterMode::ExternalDns` passthrough mode

**What is missing — wiring the two together**:
- The `run_packet_loop` currently forwards all UDP packets as-is. DNS queries
  (destination port 53) need to be intercepted and passed through `DnsFilter`
  before being resolved via `DnsResolver::resolve_doh()`
- If the domain is blocked, return a synthetic `0.0.0.0` response to the TUN
  device instead of forwarding the query
- If allowed, forward through DoH and write the response back to TUN

```text
DNS packet from TUN (dst port 53)
        │
        ▼
DnsFilter::should_block(hostname)?
        │ Yes                │ No
        ▼                    ▼
Return 0.0.0.0          DnsResolver::resolve_doh(hostname)
synthetic reply               │
        │                    ▼
        └──► Write DNS response to TUN device
```

**Suggested implementation location**: inside the outgoing arm of the
`tokio::select!` in `run_packet_loop`, after reading a packet from the TUN fd,
before calling `tunnel.encapsulate()`.

---

### 3. Privilege Dropping

**File**: `src/main.rs`  
**Complexity**: Low

**Why this matters**: The process starts as root (or with `CAP_NET_ADMIN`) to
create the TUN device and configure iptables. Once setup is done, there is no
need for elevated privileges. Running as root for the lifetime of the process is
a security risk — a bug in the HTTP client, the GUI, or the config parser could
be exploited with full root access.

**What to do**: After `VpnController::new()` returns (TUN and iptables are
configured inside the background thread at connect time), the main thread can
drop privileges. On Linux this looks like:

```rust
// After tunnel setup, drop to a non-root user
unsafe {
    // Replace 1000 with the actual UID of the invoking user
    // (read from $SUDO_UID or $PKEXEC_UID at startup)
    libc::setuid(1000);
    libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
}
```

The tricky part is knowing *which* UID to drop to. The standard approach is to
read `$SUDO_UID` from the environment before dropping privileges, so you return
to the user who invoked `sudo`.

---

## Priority 3 — Platform Completeness

### 4. macOS TUN Device

**File**: `src/platform/macos.rs`  
**Complexity**: Medium

**Why this matters**: macOS does not have the Linux `tun` character device at
`/dev/net/tun`. Instead it uses `utun` (user-space TUN) devices that are
created through a `PF_SYSTEM` socket with `SYSPROTO_CONTROL`. The routing setup
also differs: macOS uses `route add -net` instead of `ip route`.

**What exists**: `macos.rs` is a stub that returns `Err("not implemented")` for
`create_tun()`.

**What to implement**:
1. Open a `PF_SYSTEM` / `SYSPROTO_CONTROL` socket
2. Connect with `utun` control name to get a `utunN` device
3. Use `ioctl` to assign the IP address and bring the interface up
4. Add routes with `route add` via `std::process::Command`
5. Implement `cleanup()` to remove routes and close the socket

The `tun` crate (already a dependency) supports macOS `utun` devices, so the
implementation can closely mirror `linux.rs` — the main difference is the
routing commands.

---

### 5. Windows TUN Device

**File**: `src/platform/windows.rs`  
**Complexity**: High

**Why this matters**: Windows has no native TUN support in the kernel. WireGuard
on Windows uses the **WinTun** driver, a kernel-mode driver that must be
installed separately or bundled with the application. The driver exposes a
Ring Buffer API to user space.

**What exists**: `windows.rs` is a stub.

**What to implement**:
1. Bundle or download the WinTun DLL (`wintun.dll`)
2. Call `WintunCreateAdapter()` to create a virtual adapter
3. Open a session with `WintunStartSession()`
4. Use `WintunAllocateSendPacket()` / `WintunSendPacket()` for outbound traffic
5. Use `WintunReceivePacket()` for inbound traffic
6. Configure IP address via Windows IP Helper API (`SetUnicastIpAddressEntry`)
7. Add routes via `CreateIpForwardEntry2`

The `wintun` crate (not currently a dependency) wraps the WinTun C API.

---

## Priority 4 — Polish

### 6. Update Checker Notifications

**File**: `src/update.rs`, `src/gui/app.rs`  
**Complexity**: Low

**What exists**: `UpdateChecker::check_for_updates()` is fully implemented —
it hits the GitHub releases API, parses `tag_name`, and returns
`Some(version_string)` if an update is available. The constant
`GITHUB_RELEASES_API_URL` needs to be set to the real repository path.

**What is missing**:
1. Replace the placeholder in `GITHUB_RELEASES_API_URL` with the actual repo path:
   ```rust
   // src/update.rs
   const GITHUB_RELEASES_API_URL: &str =
       "https://api.github.com/repos/YOUR_USER/YOUR_REPO/releases/latest";
   ```
2. Wire the result from `check_for_updates()` back to the GUI. The background
   update check is already spawned in `main()`. Add a `VpnEvent::UpdateAvailable(String)`
   variant and send it through the event channel when a new version is found.
3. Display a dismissable banner in the Iced view when `app_state.pending_update`
   is `Some(version)`.

---

### 7. Configurable Client TUN IP

**File**: `src/core/controller.rs`, `src/config.rs`  
**Complexity**: Low

**What exists**: The client-side TUN IP is hardcoded to `10.8.0.2/24` in the
`Connect` handler in `controller.rs`. This works when there is only one client
and the server is configured for that subnet, but breaks when deploying multiple
clients or using a server with a different address range.

**What to do**: Add `tun_ip: Option<String>` to `VpnConfig` and read it in
the `Connect` handler, falling back to `"10.8.0.2"` if not set. Expose it as
an optional field in the GUI settings or parse it from the server's provisioning
response.

---

## Project Statistics

| Item | Value |
|---|---|
| Total tests | 155 (0 failures) |
| Core modules complete | 13 / 13 |
| Platform layers complete | 1 / 3 (Linux only) |
| Estimated time to first real connection | 1–2 h (item 1 only) |
| Estimated time to production-ready | 20–40 h (all items) |
