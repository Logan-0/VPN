# RustVPN — Project Status

**Version**: 0.1.0 | **Last Updated**: April 20, 2026 | **Status**: MVP feature-complete on Linux

---

## What This Project Is

RustVPN is a WireGuard-based VPN client written entirely in Rust. It encrypts
all outbound traffic through a TUN virtual network device using the
ChaCha20-Poly1305 cipher and X25519 key exchange (the same cryptography used by
WireGuard itself). The GUI is built with the Iced framework (Elm architecture),
the async VPN core runs on a dedicated Tokio runtime, and the two halves
communicate through a typed message-passing channel.

---

## How the Pieces Fit Together

```
┌─────────────────────────────────────────────────┐
│  Iced GUI (src/gui/app.rs)                      │
│  • Elm update() loop on main thread             │
│  • 100 ms Tick subscription polls VpnEvent rx  │
│  • Sends VpnCommand via VpnController           │
└───────────────┬─────────────────────────────────┘
                │  tokio::sync::mpsc  (commands ↓, events ↑)
┌───────────────▼─────────────────────────────────┐
│  VpnController worker (src/core/controller.rs)  │
│  Background thread + single-threaded Tokio rt   │
│                                                 │
│  On Connect:                                    │
│   1. Load/generate X25519 private key           │
│   2. Decode server public key from base64       │
│   3. Enable kill switch (iptables)              │
│   4. LinuxPlatform::create_tun() → RawFd        │
│   5. Tunnel::new() + connect() (Noise handshake)│
│   6. tokio::spawn(run_packet_loop)              │
│                                                 │
│  On Disconnect / Shutdown:                      │
│   • Signal packet loop via watch::channel       │
│   • platform.cleanup() removes routes + TUN     │
│   • kill_switch.disable()                       │
└───────────────┬─────────────────────────────────┘
                │
┌───────────────▼─────────────────────────────────┐
│  Packet Loop (src/core/packet_loop.rs)          │
│  tokio::select! over three arms:                │
│   TUN read  → encapsulate → UDP send            │
│   UDP recv  → decapsulate → TUN write           │
│   25 s timer → WireGuard keepalive              │
└─────────────────────────────────────────────────┘
```

---

## What Is Complete

### VPN Core
- **WireGuard tunnel** (`src/core/tunnel.rs`) — X25519 key exchange, ChaCha20-Poly1305 encrypt/decrypt via `boringtun`; `generate_keypair()`, `base64_to_key()`, `key_to_base64()` utilities
- **Kill switch** (`src/core/killswitch.rs`) — iptables (Linux), pf (macOS stub), netsh (Windows stub); enable before handshake, disable on clean disconnect/shutdown
- **Auto-reconnect** (`src/core/reconnect.rs`) — exponential backoff 1 s → 2 s → … → 30 s cap; `record_failure()` doubles delay, `record_success()` resets, `reset()` clears history
- **Packet loop** (`src/core/packet_loop.rs`) — async TUN↔UDP bridge with keepalive; exits cleanly on `watch::channel` stop signal
- **Controller** (`src/core/controller.rs`) — full tunnel bring-up wired; auto-reconnect re-queues `VpnCommand::Connect` after unexpected packet loop exit

### Platform
- **Linux TUN** (`src/platform/linux.rs`) — `create_tun()` creates device, saves original gateway, installs split-default routes (`0.0.0.0/1`, `128.0.0.0/1`) to avoid conflicting with the system default route; `cleanup()` undoes all of it on drop

### Configuration
- **VpnConfig** (`src/config.rs`) — TOML load/save with atomic write + `0600` permissions; `get_or_create_private_key()` generates an X25519 key on first run, persists it, and returns a `Zeroizing<[u8;32]>` on all subsequent runs
- **Server manager** (`src/server.rs`) — `find_by_id()`, `find_by_country()`, `get_server_display_list()`
- **DNS filter** (`src/dns/filter.rs`) — HashSet blocklist, hosts-file parser, Pi-hole `ExternalDns` pass-through mode

### GUI
- **Iced app** (`src/gui/app.rs`) — Connect/Disconnect, server dropdown, Kill Switch / Auto-reconnect / DNS Filtering toggles; 100 ms event poll subscription; live HH:MM:SS uptime counter

### Tests
- **155 tests, 0 failures** — `cargo test` requires no system libraries (pure-Rust TLS via `rustls-tls`)
- Inline `#[cfg(test)]` modules in `config.rs`, `update.rs`, `reconnect.rs`, `tunnel.rs`, `controller.rs`
- Integration test files: `dns_filter_tests.rs`, `reconnect_tests.rs`, `server_tests.rs`, `tunnel_tests.rs`, `e2e_test_plan.rs`

---

## Quick Start

```bash
# Run all tests (no root, no system deps)
cargo test

# Run e2e tests that need root
sudo cargo test --test e2e_test_plan -- --ignored

# Build and run the GUI (requires GTK4 dev libs)
sudo apt-get install -y pkg-config libgtk-4-dev
cargo run
```

To actually connect, you need a real WireGuard server. Pass its
`host:port` endpoint and base64 public key through the GUI connect dialog.
The client IP is currently hardcoded to `10.8.0.2/24`; the server must be
configured to accept that address.

---

## Project Structure

```
src/
├── core/
│   ├── controller.rs   # GUI↔core bridge; full tunnel bring-up
│   ├── tunnel.rs       # WireGuard encrypt/decrypt; key utilities
│   ├── killswitch.rs   # Firewall rules (Linux complete, macOS/Windows stubs)
│   ├── reconnect.rs    # Exponential backoff manager
│   └── packet_loop.rs  # Async TUN↔UDP bridge
├── dns/
│   ├── filter.rs       # Blocklist (complete); DoH wiring (pending)
│   └── resolver.rs     # Cloudflare/Google DoH, custom DNS (complete)
├── gui/
│   └── app.rs          # Iced Elm-architecture GUI
├── platform/
│   ├── linux.rs        # TUN device + routing (complete)
│   ├── macos.rs        # Stub
│   └── windows.rs      # Stub
├── config.rs           # VpnConfig load/save + private key management
├── server.rs           # Server list + selection
└── update.rs           # GitHub release check (HTTP complete; GUI notification pending)
```

---

## Security Model

| Property | Status | Notes |
|---|---|---|
| Traffic encryption | Complete | ChaCha20-Poly1305 via boringtun |
| Identity key persistence | Complete | `Zeroizing<[u8;32]>`, saved `0600` |
| Kill switch (no-leak) | Complete (Linux) | iptables; stubs on macOS/Windows |
| Auto-reconnect | Complete | Exponential backoff, full chain |
| DNS leak prevention | Pending | See REMAINING_WORK.md |
| IPv6 leak prevention | Partial | Kill switch blocks IPv6; not tested |
| Privilege dropping | Pending | Needs `CAP_NET_ADMIN` only for setup |

---

## What's Next

See **REMAINING_WORK.md** for full details on each item.

1. **Real server list** — replace hardcoded example servers with real endpoints and valid public keys
2. **DNS-over-HTTPS wiring** — connect the existing `resolver.rs` DoH client to the packet loop so DNS queries are filtered and encrypted
3. **Update checker notifications** — fill in the `GITHUB_RELEASES_API_URL` constant and wire update results to the GUI
4. **macOS / Windows TUN** — implement `utun` (macOS) and WinTun (Windows) platform layers
5. **Privilege dropping** — call `prctl(PR_SET_DUMPABLE, 0)` and drop to a non-root UID after TUN creation
