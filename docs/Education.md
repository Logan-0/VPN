# Education - RustVPN

This document explains the overarching architecture and educational philosophy behind the RustVPN project.

---

## Educational Philosophy

This project demonstrates how to build a secure, lightweight VPN client using the WireGuard protocol. It showcases:
- **VPN technology** and how encrypted tunnels work
- **TUN (virtual network) devices** and how the OS uses them
- **Kill switch implementation** with firewall rules (iptables on Linux)
- **DNS filtering** at the network layer
- **Linux-specific system programming** with CAP_NET_ADMIN capabilities
- **Rust's module system** for organizing complex applications
- **Configuration management** with TOML and Serde
- **Platform abstraction** for OS-specific operations

---

## System Architecture

### Layer-Based Architecture

The application is organized as a stack of layers, each depending only on the layer below it:

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
  Linux-only: creates TUN device, configures routing with iptables, manages firewall rules
  Requires CAP_NET_ADMIN capability for non-root operation
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
| GUI | `src/gui/app.rs` | Iced graphical interface (Elm architecture) |
| Linux platform | `src/platform/linux.rs` | `ip tuntap`, `iptables`, routing tables |
| macOS platform | `src/platform/macos.rs` | `utun` device, `pf` firewall, routing |
| Windows platform | `src/platform/windows.rs` | WinTun driver, Windows Firewall |
| Updater | `src/update.rs` | Checks GitHub releases for newer version |

---

## Core Components

### 1. TUN Device

**Purpose**: Create a virtual network interface for the VPN tunnel

**How it works**:
1. Creates a TUN device (e.g., `tun0` on Linux)
2. Tells the OS to route all internet traffic through `tun0`
3. Reads packets from `tun0`, **encrypts** them with WireGuard
4. Sends encrypted packets to the real VPN server over UDP
5. Receives encrypted packets from the server, **decrypts** them
6. Writes plaintext back to `tun0` so the OS delivers them normally

**Platform-specific implementations**:
- **Linux**: `ip tuntap add dev tun0 mode tun`
- **macOS**: `utun` device with `ioctl`-based IP configuration
- **Windows**: WinTun driver via `wintun` crate

### 2. WireGuard Protocol

**Purpose**: Encrypt traffic through a tunnel

**How it works**:
1. Performs cryptographic handshake with server
2. Uses ChaCha20 for encryption, Poly1305 for authentication
3. Uses Curve25519 for key exchange
4. Establishes secure tunnel for all traffic

**Key features**:
- Simple specification (fits in a research paper)
- Fast (less overhead than OpenVPN/IPSec)
- Secure (state-of-the-art cryptography)

### 3. Kill Switch

**Purpose**: Prevent IP address leakage if VPN connection drops

**How it works**:
1. Installs firewall rules when VPN connects
2. Blocks all traffic **except**:
   - Traffic through VPN tunnel interface
   - UDP to VPN server's IP (needed for reconnection)
   - Local network traffic (192.168.x.x, 10.x.x.x, 172.16.x.x)
   - Loopback (127.0.0.1)
3. Removes firewall rules when VPN disconnects

**Platform-specific implementations**:
- **Linux**: `iptables` rules
- **macOS**: `pf` firewall
- **Windows**: Windows Firewall API

### 4. DNS Filtering

**Purpose**: Block ads and malware at the DNS level

**How it works**:
1. Intercepts DNS queries from the TUN device
2. Checks the domain against a blocklist
3. For blocked domains: Returns fake "not found" response (0.0.0.0)
4. For allowed domains: Forwards query over DNS-over-HTTPS (DoH)

**Benefits**:
- Blocks ads before they load
- Prevents malware domains
- Encrypts DNS queries (via DoH)
- ISP cannot see which sites you visit

### 5. Auto-Reconnect

**Purpose**: Automatically reconnect if VPN connection drops

**How it works**:
1. Detects connection failure
2. Waits using exponential backoff:
   - Attempt 1: wait 1 second
   - Attempt 2: wait 2 seconds
   - Attempt 3: wait 4 seconds
   - Attempt 4: wait 8 seconds
   - Maximum: wait 60 seconds
3. Retries connection until successful

**Benefits**:
- No manual intervention needed
- Prevents flooding server with connection attempts
- Gentle polling rhythm

### 6. Configuration Management

**Purpose**: Load and save user preferences

**How it works**:
1. Reads from `~/.config/rustvpn/config.toml` (Linux)
2. Deserializes TOML into `VpnConfig` struct using Serde
3. If file doesn't exist, uses `VpnConfig::default()` with secure defaults
4. Saves changes back to TOML file

**Configuration options**:
- Auto-connect on startup
- Kill switch enabled
- DNS filtering enabled
- Selected VPN server
- Client TUN IP address

### 7. Cross-Platform Support

**Purpose**: Run on Linux, macOS, and Windows from a single codebase

**How it works**:
1. Uses Rust's conditional compilation: `#[cfg(target_os = "...")]`
2. Only the block matching the target OS is compiled
3. Platform-specific code lives in `src/platform/`
4. Shared code uses cfg-aliased types

**Example**:
```rust
#[cfg(target_os = "linux")]
fn setup_firewall() {
    // use iptables here
}

#[cfg(target_os = "macos")]
fn setup_firewall() {
    // use pf here
}
```

---

## GUI Architecture

### Iced Framework

**Purpose**: Provide a graphical user interface

**Architecture**: Elm architecture (Model-View-Update)

**Components**:
- Connect button
- Server picker dropdown
- Feature toggles (kill switch, DNS filtering)
- Status display
- Update banner

**Features**:
- Pure Rust (no external GUI toolkit dependencies)
- Cross-platform (Linux, macOS, Windows)
- Modern, clean interface

---

## Data Flow Architecture

### Outgoing Traffic

```
Application (browser, etc.)
    |
    v
OS routing table (routes to TUN device)
    |
    v
TUN device (tun0)
    |
    v
WireGuard encryption
    |
    v
UDP packet to VPN server
    |
    v
VPN server decrypts and forwards to internet
```

### Incoming Traffic

```
Internet response
    |
    v
VPN server encrypts
    |
    v
UDP packet from VPN server
    |
    v
WireGuard decryption
    |
    v
TUN device (tun0)
    |
    v
OS delivers to application
```

---

## Security Architecture

### Zero Logs Policy

**Principle**: No connection data, timestamps, or IP addresses are ever written to disk

**Implementation**:
- No logging of connection timestamps
- No logging of visited websites
- No logging of transferred data
- Only runtime logging for debugging (can be disabled)

### Cryptographic Security

**WireGuard cryptography**:
- ChaCha20 for stream cipher
- Poly1305 for message authentication
- Curve25519 for key exchange
- BLAKE2s for hashing

### Kill Switch Security

**Purpose**: Prevent IP leaks during connection drops

**Implementation**:
- Firewall rules block all non-VPN traffic
- Only allows VPN server UDP traffic
- Allows local network traffic
- Allows loopback traffic

### DNS Security

**Purpose**: Prevent DNS leaks and block malicious domains

**Implementation**:
- DNS-over-HTTPS encrypts DNS queries
- Blocklist prevents access to known bad domains
- Interception at TUN layer ensures all DNS is filtered

---

## Networking Fundamentals in Context

This section consolidates the core networking concepts used throughout this project.

### Where RustVPN Operates in the Network Stack

- Layer 3 (Network): TUN interface captures and injects IP packets.
- Layer 4 (Transport): WireGuard traffic is sent over UDP.
- Encryption/Auth: WireGuard uses X25519 key exchange and ChaCha20-Poly1305 with integrity checks.

### Routing and Tunnel Behavior

- On connect, default routes are redirected through the VPN interface.
- VPN server endpoint traffic is explicitly excluded from tunnel recursion.
- Local network access can be preserved through targeted firewall/routing allowances.

### DNS and Leak Prevention

- DNS queries are filtered against blocklists before external resolution.
- DNS-over-HTTPS support is available for encrypted resolver communication.
- Kill switch and routing policy work together to prevent DNS and IP leaks on disconnects.

---

## Connection Lifecycle

### Connect Flow

1. Load configuration and selected server.
2. Enable kill switch protections.
3. Create/configure TUN device for the platform.
4. Initialize WireGuard tunnel and perform handshake.
5. Start packet loop (TUN -> encrypt -> UDP, UDP -> decrypt -> TUN).
6. Start health monitoring and reconnect supervision.

### Disconnect/Recovery Flow

- Unexpected drop: auto-reconnect applies exponential backoff and retries tunnel establishment.
- User disconnect: stop packet loop, restore routes/interface state, and disable kill switch.
- Shutdown path prioritizes cleanup so no restrictive firewall state remains unintentionally.

---

## Privilege Management

### Linux: CAP_NET_ADMIN

**Purpose**: Allow creating TUN devices and configuring routing without running as root

**Implementation**:
```bash
sudo setcap cap_net_admin+ep ./target/release/rust-vpn
```

**Benefits**:
- Run as normal user (proper GUI display access)
- Create TUN virtual network devices
- Configure routing tables
- Install firewall rules
- Minimum necessary privileges

### macOS / Windows: Root/Admin

**Requirement**: Root privileges required

**macOS**: `sudo ./target/release/rust-vpn`

**Windows**: Run as Administrator

---

## Update Checker

**Purpose**: Notify users of new releases

**How it works**:
1. Checks GitHub Releases API for newer version
2. Compares version numbers
3. Shows dismissable banner in GUI if update available
4. User can manually download new version

**Configuration**:
- `GITHUB_RELEASES_API_URL` constant (`https://api.github.com/repos/Logan-0/VPN/releases/latest`)
- Runs on application startup

---

## Debian Packaging

### Building .deb Package

```bash
cargo install cargo-deb
cargo deb
```

### Installation

```bash
sudo dpkg -i target/debian/rust-vpn_*.deb
```

### What Gets Installed

- Binary: `/usr/bin/rust-vpn`
- CAP_NET_ADMIN capability (automatic via post-install script)
- Desktop entry: `/usr/share/applications/`
- Icons: `/usr/share/icons/`

---

## Conclusion

This architecture demonstrates how to build a secure, cross-platform VPN client using Rust. The layered design, platform-specific abstractions, and comprehensive security features (kill switch, DNS filtering, zero logs) showcase modern systems programming practices. The project serves as an excellent educational resource for understanding VPN technology, network programming, and cross-platform development in Rust.
