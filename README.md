# RustVPN

A secure, lightweight VPN client written in Rust using the WireGuard protocol.
It includes a graphical interface, a kill switch, DNS filtering, and automatic
reconnection — all cross-platform across Linux, macOS, and Windows.

---

## Documentation

Detailed documentation is available in the `docs/` folder:
- `docs/HowItWorks.md` — Layered architecture, core components, and implementation details
- `docs/RoadMap.md` — Project status and future work
- `docs/ProjectSummary.md` — Feature summary and technology stack
- `docs/ChangeLog.md` — Version history
- `docs/ARCHITECTURE.md` — Detailed architecture documentation
- `docs/COMPONENT_DOCUMENTATION.md` — Component-level documentation
- `docs/DATA_FLOW_DOCUMENTATION.md` — Data flow documentation
- `docs/NETWORKING_CONCEPTS.md` — Networking concepts explained
- `docs/STATUS.md` — Implementation status tracking

## Overview

A secure, lightweight VPN client written in Rust using the WireGuard protocol with a graphical interface, kill switch, DNS filtering, and automatic reconnection — cross-platform across Linux, macOS, and Windows.

For detailed explanations of VPN concepts, WireGuard protocol, TUN devices, kill switches, and DNS filtering, see `docs/NETWORKING_CONCEPTS.md`.

## Architecture

The application is organized as a stack of layers. For detailed architecture and module breakdown, see `docs/ARCHITECTURE.md`.

For detailed explanations of TUN devices, kill switches, DNS filtering, exponential backoff, TOML configuration, and cross-platform Rust, see `docs/NETWORKING_CONCEPTS.md`.
}
```

Only the block matching the target operating system is compiled into the binary.
The other blocks are completely ignored by the compiler.

---

## Features

- **Zero Logs**: No connection data, timestamps, or IP addresses are ever written to disk
- **WireGuard Protocol**: Modern, audited, and fast
- **Kill Switch**: Firewall-enforced leak prevention when the tunnel drops
- **DNS Filtering**: Blocklist-based ad and malware blocking over DoH/DoT
- **Auto-Reconnect**: Exponential backoff reconnection with no user intervention
- **Cross-Platform**: Linux, macOS, and Windows from a single codebase
- **GUI**: Iced graphical interface (pure Rust, Elm architecture) with connect button, server picker, and feature toggles

## Server Coverage

- **United States**: One server per state (50 locations)
- **Sweden**: Multiple locations (Stockholm, Gothenburg, Malmo)

---

## Building

```bash
cargo build --release
```

## Running on Any Linux Machine

### Prerequisites

Install required system dependencies:

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y pkg-config libgtk-4-dev libssl-dev

# Fedora/RHEL
sudo dnf install -y pkg-config gtk4-devel openssl-devel

# Arch Linux
sudo pacman -S pkg-config gtk4 openssl
```

### Quick Start (Recommended)

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

### Manual Setup

If the setup script doesn't work, you can manually grant the capability:

```bash
# Grant CAP_NET_ADMIN capability
sudo setcap cap_net_admin+ep ./target/release/rust-vpn

# Run as normal user
./target/release/rust-vpn
```

### Why CAP_NET_ADMIN is Needed

The GUI requires display server access (X11/Wayland), which doesn't work well when running as root. Granting the `CAP_NET_ADMIN` capability allows the app to:
- Run as a normal user (proper GUI display access)
- Create TUN virtual network devices
- Configure routing tables
- Install firewall rules (kill switch)

This provides the minimum necessary privileges without the security risks of running the entire GUI as root.

### Troubleshooting

If you see "Not running as root or with CAP_NET_ADMIN capability":
- Run `./setup.sh` to automatically grant the capability
- Or manually run: `sudo setcap cap_net_admin+ep ./target/release/rust-vpn`

If the GUI doesn't display:
- Ensure you're running as a normal user (not root)
- Check that DISPLAY is set: `echo $DISPLAY`
- Try running without Wayland: `WAYLAND_DISPLAY= ./target/release/rust-vpn`

## Running on macOS / Windows

### macOS

Root privileges are required:

```bash
sudo ./target/release/rust-vpn
```

### Windows

Run the executable as Administrator.

## Debian Package Installation (.deb)

### Building a .deb Package

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

### Installing from .deb

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

### Running After .deb Installation

```bash
# Run from command line
rust-vpn

# Or launch from application menu
```

### Configuration File Location

| OS | Path |
|----|------|
| Linux | `~/.config/rustvpn/config.toml` |
| macOS | `~/Library/Application Support/RustVPN/config.toml` |
| Windows | `%APPDATA%\RustVPN\config.toml` |

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
