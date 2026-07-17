# Project Summary - RustVPN

**Project Status**: Stable (v1.0.0)

**Version**: 1.0.0 (documented release; see `Projects/Guidelines/VersioningSpec.md`)

## Documentation

Detailed documentation is available in the `docs/` folder:
- `docs/Education.md` — Layered architecture, core components, and implementation details
- `docs/RoadMap.md` — Project status and remaining (optional) work
- `docs/README.md` — This file (feature summary and technology stack)
- `docs/ChangeLog.md` — Version history

## Overview

A secure, lightweight VPN client written in Rust using the WireGuard protocol with a graphical interface, kill switch, DNS filtering, and automatic reconnection — **Linux-only** implementation (v1.0.0, feature-complete).

For detailed explanations of VPN concepts, WireGuard protocol, TUN devices, kill switches, and DNS filtering, see `docs/Education.md`.

## Architecture

The application is organized as a stack of layers. For detailed architecture and module breakdown, see `docs/Education.md`.

For detailed explanations of TUN devices, kill switches, DNS filtering, exponential backoff, and TOML configuration, see `docs/Education.md`.

---

## What This Project Does

This project provides:
- **VPN client** using WireGuard protocol for encrypted tunnels
- **Linux support** with CAP_NET_ADMIN for non-root operation
- **Kill switch** with firewall-enforced leak prevention
- **DNS filtering** with blocklist-based ad and malware blocking
- **Auto-reconnect** with exponential backoff
- **Graphical interface** (Iced framework, pure Rust)
- **Zero logs policy** — no connection data ever written to disk
- **Debian packaging** for easy installation on Linux
- **Update checker** for new release notifications

---

## Key Features

### Core VPN Features
- **WireGuard protocol** — Modern, audited, and fast
- **TUN device management** — Virtual network interface creation
- **Cryptographic handshake** — ChaCha20, Poly1305, Curve25519
- **Encrypted tunnel** — All traffic routed through VPN server

### Security Features
- **Kill switch** — Firewall-enforced leak prevention when tunnel drops
- **DNS filtering** — Blocklist-based ad and malware blocking at the TUN layer (DNS already travels encrypted inside the WireGuard tunnel; the DoH resolver type exists but is intentionally not wired in — see Technology Stack)
- **Zero logs** — No connection data, timestamps, or IP addresses written to disk
- **Path validation** — Prevents configuration file escape attacks

### User Experience
- **Auto-reconnect** — Exponential backoff reconnection logic
- **Graphical interface** — Iced framework with Elm architecture
- **Server selection** — Dropdown picker with server metadata
- **Feature toggles** — Kill switch and DNS filtering controls
- **Update notifications** — Banner for new releases
- **Configurable client TUN IP** — Custom tunnel IP address

### Platform Support
- **Linux** — Full support with CAP_NET_ADMIN for non-root operation

### Deployment
- **Debian .deb packages** — Easy installation on Debian-based systems
- **Automatic capability setup** — Post-install script sets CAP_NET_ADMIN
- **Desktop integration** — Application launcher entries and icons

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Language | Rust | Fast, memory-safe systems language |
| VPN Protocol | WireGuard | Modern, fast VPN protocol |
| GUI Framework | Iced | Pure Rust GUI framework (Elm architecture) |
| Configuration | TOML + Serde | Configuration file serialization |
| TUN (Linux) | `ip tuntap` | Linux TUN device creation |
| Firewall (Linux) | iptables | Linux firewall rules |
| DNS | Custom + DoH (dormant) | DNS filtering; DoH resolver implemented but not wired into the live path |
| Packaging | cargo-deb | Debian package building |

---

## Project Structure

Reflects the actual tree as of 2026-07-09 (previously listed files that were
removed in commit `bf1a8a7`, "Remove macOS and Windows platform support -
Linux only" — see `docs/RoadMap.md` for what that removal covered):

```
VPN/
├── src/
│   ├── main.rs                    Entry point
│   ├── lib.rs                     Library root
│   ├── config.rs                  Configuration management
│   ├── server.rs                  Server registry
│   ├── update.rs                  Update checker
│   ├── privilege.rs               Privilege management (Linux)
│   ├── core/
│   │   ├── mod.rs
│   │   ├── controller.rs          Core VPN control logic
│   │   ├── killswitch.rs          Kill switch implementation (Linux only —
│   │   │                          macOS/Windows fail closed, not implemented)
│   │   ├── reconnect.rs           Auto-reconnect logic
│   │   ├── tunnel.rs              WireGuard tunnel (encapsulate/decapsulate)
│   │   └── packet_loop.rs         Packet processing (Linux/unix)
│   ├── dns/
│   │   ├── mod.rs
│   │   ├── filter.rs              Blocklist filtering
│   │   ├── intercept.rs           Packet-level DNS interception
│   │   └── resolver.rs            DoH resolver — defined but not wired in
│   ├── gui/
│   │   ├── mod.rs
│   │   └── app.rs                 Iced GUI application
│   └── platform/
│       ├── mod.rs
│       └── linux.rs               Linux-specific code — the only implemented platform
├── resources/
│   ├── servers.toml               VPN server list
│   └── servers.toml.example       Template for the server list
├── debian/                        Debian packaging
├── tests/                         Comprehensive test suite
├── .github/                       CI/CD (ci, release, security, dependency-review,
│   │                              actionlint workflows + dependabot)
├── .pre-commit-config.yaml        Pre-commit hooks
└── setup.sh                       Linux setup script
```

Note: `src/platform/macos.rs`, `src/platform/windows.rs`,
`src/core/packet_loop_windows.rs` (the dead Windows packet loop, removed in
the post-1.0.0 optimization pass — see `docs/ChangeLog.md`), and
`src/tunnel/noise.rs` (WireGuard Noise protocol, superseded by `boringtun`
via `src/core/tunnel.rs`) do not exist in the current tree — this file
previously listed them as present.

---

## Server Coverage

Defined in `resources/servers.toml` (9 servers):

- **United States**: California, New York, Texas, Florida
- **Sweden**: Stockholm, Gothenburg, Malmö
- **Germany**: Berlin, Frankfurt

---

## Quick Start

### Building

```bash
cargo build --release
```

### Linux (Recommended)

#### Prerequisites

Building needs only a Rust toolchain — the GUI uses Iced with the `wgpu`
backend (pure Rust, `winit`-based), so there are **no GTK or OpenSSL system
dev packages to install** (TLS goes through `rustls`). CI builds the project
with no extra `apt` packages.

At **runtime** the GUI needs a working display server (X11 or Wayland) and
GPU drivers (Vulkan/GL). `pkg-config` and a C toolchain (`build-essential`)
are usually already present; install them if a transitive crate's build
complains.

#### Quick Start (Recommended)

1. Build the release binary:
```bash
cargo build --release
```

2. Run the setup script to grant required capabilities:
```bash
./setup.sh
```

3. Run the application:
```bash
./target/release/rust-vpn
```

#### Manual Setup

If the setup script doesn't work, you can manually grant the capability:

```bash
# Grant CAP_NET_ADMIN capability
sudo setcap cap_net_admin+ep ./target/release/rust-vpn

# Run as normal user
./target/release/rust-vpn
```

#### Why CAP_NET_ADMIN is Needed

The GUI requires display server access (X11/Wayland), which doesn't work well when running as root. Granting the `CAP_NET_ADMIN` capability allows the app to:
- Run as a normal user (proper GUI display access)
- Create TUN virtual network devices
- Configure routing tables
- Install firewall rules (kill switch)

This provides the minimum necessary privileges without the security risks of running the entire GUI as root.

#### Troubleshooting

If you see "Not running as root or with CAP_NET_ADMIN capability":
- Run `./setup.sh` to automatically grant the capability
- Or manually run: `sudo setcap cap_net_admin+ep ./target/release/rust-vpn`

If the GUI doesn't display:
- Ensure you're running as a normal user (not root)
- Check that DISPLAY is set: `echo $DISPLAY`
- Try running without Wayland: `WAYLAND_DISPLAY= ./target/release/rust-vpn`

### Debian Package Installation (.deb)

#### Building a .deb Package

To create a Debian package for easy installation on any Debian-based system:

```bash
# Install cargo-deb
cargo install cargo-deb

# Build the .deb package
cargo deb
```

This creates a `.deb` file in `target/debian/` that includes:
- The compiled binary
- Automatic capability setup via post-install script
- Desktop entry for application launcher
- Icon files

#### Installing from .deb

```bash
# Install the package
sudo dpkg -i target/debian/rust-vpn_*.deb

# If there are dependency issues, fix them:
sudo apt-get install -f
```

The .deb package automatically:
- Installs the binary to `/usr/bin/rust-vpn`
- Sets CAP_NET_ADMIN capability on the binary
- Creates a desktop entry in `/usr/share/applications/`
- Installs icons to `/usr/share/icons/`

#### Running After .deb Installation

```bash
# Run from command line
rust-vpn

# Or launch from application menu
```

---

## Configuration File Location

| OS | Path |
|----|------|
| Linux | `~/.config/rustvpn/config.toml` |

Linux is the only supported platform; the config-loading code still has
inert `#[cfg(target_os = "macos"/"windows")]` branches left over from before
`bf1a8a7` retired those platforms, but they are unreachable in any build this
project ships.

---

## Configuration Options

```toml
auto_connect_on_application_startup = false
kill_switch_protection_enabled = true
auto_reconnect_enabled = true
dns_filtering_protection_enabled = true
selected_vpn_server_identifier = "us-california-1"
custom_dns_server_address = "1.1.1.1"  # Optional
client_tun_ip_cidr = "10.8.0.2/24"     # Optional, defaults to 10.8.0.2/24
```

---

## Educational Value

For architecture, traffic/data flow, security model, and networking concept walkthroughs, see `docs/Education.md`.

---

## Project Status and Limitations

Current implementation status, platform readiness, known limitations, and remaining work are tracked in `docs/RoadMap.md`.

---

## Further Reading

- [WireGuard Official Site](https://www.wireguard.com/) — How the protocol works
- [The Rust Book](https://doc.rust-lang.org/book/) — Learning Rust from the beginning
- [TOML Specification](https://toml.io/en/) — The configuration file format
- [DNS-over-HTTPS (RFC 8484)](https://datatracker.ietf.org/doc/html/rfc8484) — Encrypted DNS standard
- [Linux TUN/TAP devices](https://www.kernel.org/doc/html/latest/networking/tuntap.html) — How virtual network interfaces work in the kernel

---

## License

MIT

---

## Conclusion

The RustVPN project is a comprehensive, Linux-only VPN client implementation that demonstrates secure systems programming in Rust. The architecture prioritizes security through zero logs, kill switch, and DNS filtering. The project serves as an excellent educational resource for understanding VPN technology and network programming in Rust.
