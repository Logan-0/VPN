# RustVPN

A secure, lightweight VPN client written in Rust using the WireGuard protocol.
It includes a graphical interface, a kill switch, DNS filtering, and automatic
reconnection — all cross-platform across Linux, macOS, and Windows.

---

## What You Will Learn

- What a VPN is and why one is useful
- How the WireGuard protocol encrypts traffic through a tunnel
- What a TUN (virtual network) device is and how the OS uses it
- What a kill switch does and how firewall rules enforce it
- How DNS filtering intercepts and blocks unwanted queries
- How Rust's module system organizes a complex application into layers
- How cross-platform Rust code handles OS differences with `#[cfg(target_os = ...)]`
- How configuration is serialized and saved with TOML and Serde

---

## What is a VPN?

When you connect to the internet normally, your Internet Service Provider (ISP) can
see every website you visit. Websites can see your real IP address. A
**VPN** (Virtual Private Network) hides this by creating an encrypted **tunnel**
between your computer and a server run by the VPN provider.

```
Without VPN:
  Your Computer --> [ISP can see all traffic] --> Website

With VPN:
  Your Computer --> [encrypted tunnel] --> VPN Server --> Website
                                           (ISP sees only
                                           encrypted noise)
```

Websites see the VPN server's IP address, not yours. The ISP sees only encrypted
data going to the VPN server — it cannot tell which websites you visit.

---

## What is WireGuard?

WireGuard is a modern VPN protocol designed to be:
- **Simple**: The entire specification fits in a research paper
- **Fast**: Less overhead than older protocols like OpenVPN or IPSec
- **Secure**: Uses state-of-the-art cryptography (ChaCha20, Poly1305, Curve25519)

WireGuard works at the **network layer** by creating a virtual network interface
(a TUN device) that looks like a real network card to the operating system.

---

## Architecture

The application is organized as a stack of layers, each depending only on the layer
below it:

```
GUI Layer          (src/gui/)
  User clicks Connect / Disconnect, toggles settings
      |
Configuration Layer   (src/config.rs, src/server.rs)
  Loads user preferences, picks the target VPN server
      |
Core VPN Layer     (src/core/)
  Manages the WireGuard tunnel, activates kill switch, handles reconnection
      |
Platform Layer     (src/platform/)
  OS-specific: creates TUN device, configures routing, manages firewall rules
      |
Network Interface
  Actual packets leave/enter the machine here
```

### Module Breakdown

| Module | File(s) | Responsibility |
|--------|---------|----------------|
| Entry point | `src/main.rs` | Privilege checks, config load, update check, starts GUI |
| Configuration | `src/config.rs` | Load/save user settings as TOML |
| Server registry | `src/server.rs` | List of available VPN servers with metadata |
| Core tunnel | `src/core/` | WireGuard session management, encryption loop |
| Kill switch | `src/core/killswitch.rs` | Firewall rules that block non-VPN traffic |
| Auto-reconnect | `src/core/reconnect.rs` | Exponential backoff reconnection logic |
| DNS filtering | `src/dns/` | Intercepts DNS queries, checks blocklists, uses DoH |
| GUI | `src/gui/app.rs` | Iced graphical interface -- Elm architecture (connect button, server picker, toggles) |
| Linux platform | `src/platform/linux.rs` | `ip tuntap`, `iptables`, routing tables |
| macOS platform | `src/platform/macos.rs` | `utun` device, `pf` firewall, routing |
| Windows platform | `src/platform/windows.rs` | WinTun driver, Windows Firewall |
| Updater | `src/update.rs` | Checks GitHub releases for a newer version |

---

## Key Concepts Explained

### What is a TUN Device?

A **TUN** (network TUNnel) device is a virtual network interface created in software.
To the operating system it looks identical to a physical network card, but instead of
sending packets to hardware, it hands them to a user-space program (our Rust code).

The VPN client:
1. Creates a TUN device (e.g., `tun0` on Linux)
2. Tells the OS to route all internet traffic through `tun0`
3. Reads packets from `tun0`, **encrypts** them with WireGuard, and sends them to
   the real VPN server over UDP
4. Receives encrypted packets from the server, **decrypts** them, and writes the
   plaintext back to `tun0` so the OS delivers them normally

### What is a Kill Switch?

A kill switch prevents your real IP address from being exposed if the VPN connection
drops unexpectedly. Without one, the OS would route traffic through your normal
network interface while the VPN reconnects — briefly leaking your identity.

The kill switch works by installing **firewall rules** that block all traffic
**except**:
- Traffic through the VPN tunnel interface
- UDP to the VPN server's IP (needed to re-establish the tunnel)
- Local network traffic (192.168.x.x, 10.x.x.x, 172.16.x.x)
- Loopback (127.0.0.1)

On Linux this uses `iptables`. On macOS it uses `pf`. On Windows it uses the Windows
Firewall API.

### What is DNS Filtering?

Every time you type a web address your computer makes a **DNS query** to translate
the name (e.g., `example.com`) into an IP address. Normally these queries travel
unencrypted, meaning your ISP can log every site you try to visit.

This project intercepts DNS queries and:
1. Checks the domain against a blocklist of known ads and malware
2. Returns a fake "not found" response for blocked domains — the browser never
   connects
3. Forwards allowed queries over **DNS-over-HTTPS** (DoH) or **DNS-over-TLS** (DoT),
   which encrypts the query so nobody on the network can read it

### What is Exponential Backoff?

If the VPN connection drops, retrying immediately every second would flood the server
with connection attempts and drain the battery. **Exponential backoff** solves this by
waiting longer between each retry:

```
Attempt 1: wait 1 second
Attempt 2: wait 2 seconds
Attempt 3: wait 4 seconds
Attempt 4: wait 8 seconds
...
Maximum:   wait 60 seconds (then keep retrying at that interval)
```

The wait time doubles each time, so failed retries settle into a gentle polling
rhythm without hammering the network.

### What is TOML Configuration?

User settings are saved to disk in **TOML** format (Tom's Obvious Minimal Language).
It is designed to be easy for humans to read and edit:

```toml
auto_connect_on_application_startup = false
kill_switch_protection_enabled = true
dns_filtering_protection_enabled = true
selected_vpn_server_identifier = "us-california-1"
```

Serde deserializes this file into the `VpnConfig` struct automatically. If the file
does not exist, `VpnConfig::default()` returns secure defaults (kill switch on, DNS
filtering on).

### How Does Cross-Platform Rust Work?

Rust uses **conditional compilation** attributes to include different code for
different operating systems:

```rust
#[cfg(target_os = "linux")]
fn setup_firewall() {
    // use iptables here
}

#[cfg(target_os = "macos")]
fn setup_firewall() {
    // use pf here
}

#[cfg(target_os = "windows")]
fn setup_firewall() {
    // use Windows Firewall API here
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
