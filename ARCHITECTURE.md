# RustVPN Architecture Documentation

## Table of Contents
1. [Overview](#overview)
2. [How VPNs Work](#how-vpns-work)
3. [WireGuard Protocol](#wireguard-protocol)
4. [Component Architecture](#component-architecture)
5. [Data Flow](#data-flow)
6. [Security Model](#security-model)

## Overview

RustVPN is a secure, lightweight VPN client built in Rust using the WireGuard protocol. It provides:
- **Zero logging** - No connection data, timestamps, or IP addresses stored
- **Kill switch** - Prevents traffic leaks if VPN disconnects
- **DNS filtering** - Built-in ad/malware blocking via DNS-over-HTTPS
- **Auto-reconnect** - Automatic recovery from connection failures
- **Cross-platform** - Linux, macOS, and Windows support

## How VPNs Work

### The Problem VPNs Solve

Without a VPN, your internet traffic is visible to:
- Your ISP (Internet Service Provider)
- Your network administrator (at work/school)
- Websites you visit (they see your real IP address)
- Anyone monitoring the network (on public WiFi)

### The VPN Solution

A VPN creates an encrypted "tunnel" between your device and a VPN server:

```
┌─────────────────────────────────────────────────────────────────┐
│                         YOUR DEVICE                             │
│                                                                 │
│  ┌──────────┐      ┌──────────┐      ┌──────────────────┐     │
│  │  Browser │ ───► │   TUN    │ ───► │  WireGuard       │     │
│  │   App    │      │  Device  │      │  Encryption      │     │
│  └──────────┘      └──────────┘      └──────────────────┘     │
│                          │                     │                │
│                          │                     │                │
│                    Plain Packet          Encrypted Packet       │
└─────────────────────────────────────────────┼──────────────────┘
                                                │
                                                │ UDP (Port 51820)
                                                │ Over Internet
                                                │
                                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                       VPN SERVER                                │
│                                                                 │
│  ┌──────────────────┐      ┌──────────────────────────┐        │
│  │  WireGuard       │ ───► │  Decrypted Packet        │        │
│  │  Decryption      │      │  Forwarded to Internet   │        │
│  └──────────────────┘      └──────────────────────────┘        │
│                                     │                           │
└─────────────────────────────────────┼───────────────────────────┘
                                      │
                                      ▼
                              ┌───────────────┐
                              │   Website     │
                              │   Server      │
                              └───────────────┘
```

### Key Benefits

1. **Privacy**: Your ISP only sees encrypted traffic to the VPN server
2. **Security**: All traffic is encrypted (important on public WiFi)
3. **Anonymity**: Websites see the VPN server's IP, not yours
4. **Access**: Bypass geographic restrictions and censorship

## WireGuard Protocol

### Why WireGuard?

WireGuard is a modern VPN protocol that's:
- **Fast**: Minimal overhead, runs in kernel space
- **Secure**: Uses state-of-the-art cryptography
- **Simple**: ~4,000 lines of code (vs 100,000+ for OpenVPN)
- **Audited**: Extensively reviewed by security researchers

### Cryptography Stack

```
┌─────────────────────────────────────────────────────────┐
│ Layer 1: Key Exchange                                   │
│ ─────────────────────                                   │
│ • Curve25519 (X25519)                                   │
│ • Establishes shared secret between client and server   │
│ • Provides perfect forward secrecy                      │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 2: Symmetric Encryption                           │
│ ──────────────────────────                              │
│ • ChaCha20 stream cipher                                │
│ • Encrypts/decrypts packet payload                      │
│ • Very fast, constant-time (prevents timing attacks)    │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 3: Authentication                                 │
│ ────────────────────────                                │
│ • Poly1305 MAC (Message Authentication Code)            │
│ • Ensures packets haven't been tampered with            │
│ • Prevents man-in-the-middle attacks                    │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│ Layer 4: Hashing                                        │
│ ─────────────────                                       │
│ • BLAKE2s                                               │
│ • Fast, secure hashing for various protocol needs       │
└─────────────────────────────────────────────────────────┘
```

### Noise Protocol Handshake

WireGuard uses the Noise Protocol Framework for key exchange:

```
Client                                    Server
  │                                          │
  │  1. Initiation Message                  │
  │  ──────────────────────────────────────►│
  │     • Client public key                 │
  │     • Timestamp (encrypted)             │
  │     • MAC                                │
  │                                          │
  │  2. Response Message                    │
  │  ◄──────────────────────────────────────│
  │     • Server public key                 │
  │     • Timestamp (encrypted)             │
  │     • MAC                                │
  │                                          │
  │  3. Shared Secret Established           │
  │  ═══════════════════════════════════════│
  │                                          │
  │  4. Data Packets (encrypted)            │
  │  ◄─────────────────────────────────────►│
  │                                          │
```

After the handshake:
- Both sides have a shared secret
- All data packets are encrypted with ChaCha20-Poly1305
- Keys are rotated every 2 minutes for forward secrecy

## Component Architecture

### Module Structure

```
rust-vpn/
├── core/               # Core VPN functionality
│   ├── tunnel.rs       # WireGuard tunnel management
│   ├── killswitch.rs   # Traffic blocking when disconnected
│   └── reconnect.rs    # Auto-reconnect with backoff
│
├── dns/                # DNS filtering
│   ├── filter.rs       # Blocklist management
│   └── resolver.rs     # DNS-over-HTTPS/TLS client
│
├── gui/                # User interface
│   └── app.rs          # Iced-based GUI
│
├── platform/           # OS-specific code
│   ├── linux.rs        # Linux TUN/iptables
│   ├── macos.rs        # macOS utun/pfctl
│   └── windows.rs      # Windows WinTun
│
├── config.rs           # Configuration management
├── server.rs           # Server selection logic
└── update.rs           # Update checking
```

### Component Responsibilities

#### Tunnel Module (`core/tunnel.rs`)
- Creates and manages WireGuard tunnel instances
- Encrypts outgoing packets (encapsulation)
- Decrypts incoming packets (decapsulation)
- Manages connection state
- Handles keepalive messages

#### Reconnect Manager (`core/reconnect.rs`)
- Detects connection failures
- Implements exponential backoff (1s → 2s → 4s → 8s → 16s → 30s max)
- Tracks consecutive failures
- Runs periodic health checks (every 30 seconds)
- Triggers reconnection attempts

#### Kill Switch (`core/killswitch.rs`)
- Blocks all non-VPN traffic when disconnected
- Uses platform-specific firewalls:
  - Linux: iptables/nftables
  - macOS: pf (packet filter)
  - Windows: Windows Firewall API
- Prevents DNS/IPv6 leaks

#### DNS Module (`dns/`)
- Intercepts DNS queries
- Filters ads/malware/trackers
- Uses DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT)
- Caches results for performance
- Prevents DNS leaks

## Data Flow

### Outgoing Traffic (Your App → Internet)

```
┌─────────────────────────────────────────────────────────────────┐
│ Step 1: Application sends data                                  │
│ ─────────────────────────────────                               │
│ Your browser wants to visit example.com                         │
│ Creates HTTP request packet                                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 2: TUN device intercepts packet                            │
│ ───────────────────────────────────────                         │
│ Virtual network interface captures all outgoing traffic         │
│ Packet is read by our VPN application                           │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 3: WireGuard encapsulation (tunnel.encapsulate())          │
│ ─────────────────────────────────────────────────────           │
│ 1. Encrypt packet with ChaCha20-Poly1305                        │
│ 2. Add WireGuard header (16 bytes)                              │
│ 3. Add authentication tag (16 bytes)                            │
│ 4. Result: Encrypted packet ready for transmission              │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 4: Send over UDP socket                                    │
│ ──────────────────────────────                                  │
│ Encrypted packet sent to VPN server (port 51820)                │
│ Travels over regular internet (ISP only sees encrypted data)    │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 5: VPN server receives and decrypts                        │
│ ───────────────────────────────────────────                     │
│ Server decrypts packet using its private key                    │
│ Extracts original HTTP request                                  │
│ Forwards to example.com                                         │
└─────────────────────────────────────────────────────────────────┘
```

### Incoming Traffic (Internet → Your App)

```
┌─────────────────────────────────────────────────────────────────┐
│ Step 1: VPN server receives response from website               │
│ ────────────────────────────────────────────────                │
│ example.com sends HTTP response to VPN server                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 2: Server encrypts and sends to client                     │
│ ──────────────────────────────────────────                      │
│ Encrypts response packet with WireGuard                         │
│ Sends encrypted packet over UDP to your device                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 3: Your device receives encrypted packet                   │
│ ────────────────────────────────────────────                    │
│ UDP socket receives packet from VPN server                      │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 4: WireGuard decapsulation (tunnel.decapsulate())          │
│ ─────────────────────────────────────────────────────           │
│ 1. Verify authentication tag (detect tampering)                 │
│ 2. Decrypt with ChaCha20-Poly1305                               │
│ 3. Remove WireGuard header                                      │
│ 4. Result: Original HTTP response packet                        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 5: Write to TUN device                                     │
│ ─────────────────────────────                                   │
│ Decrypted packet written to virtual network interface           │
│ Operating system routes packet to your browser                  │
│ Browser displays the webpage!                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Connection Lifecycle

```
[User clicks "Connect"]
         │
         ▼
┌────────────────────┐
│ Load Configuration │  • Read private key
│                    │  • Get server details
└────────┬───────────┘  • Load DNS settings
         │
         ▼
┌────────────────────┐
│ Create TUN Device  │  • Platform-specific
│                    │  • Assign IP address
└────────┬───────────┘  • Set up routing
         │
         ▼
┌────────────────────┐
│ Enable Kill Switch │  • Block non-VPN traffic
│                    │  • Prevent leaks
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ Connect Tunnel     │  • WireGuard handshake
│                    │  • Establish encryption
└────────┬───────────┘  • Start keepalive
         │
         ▼
┌────────────────────┐
│ Start Packet Loop  │  • Read from TUN → Encrypt → Send UDP
│                    │  • Receive UDP → Decrypt → Write TUN
└────────┬───────────┘  • Handle keepalive
         │
         ▼
┌────────────────────┐
│ Start Health Check │  • Verify connection every 30s
│                    │  • Trigger reconnect if needed
└────────┬───────────┘
         │
         ▼
    [Connected]
         │
         │ (Connection lost)
         ▼
┌────────────────────┐
│ Auto-Reconnect     │  • Exponential backoff
│                    │  • Retry until success
└────────┬───────────┘  • Or user disconnects
         │
         ▼
    [Connected]
```

## Security Model

### Zero-Knowledge Architecture

RustVPN is designed to know as little as possible about your activity:

```
┌─────────────────────────────────────────────────────────────────┐
│ What We NEVER Store:                                            │
│ ──────────────────────                                          │
│ Connection timestamps                                         │
│ Bandwidth usage                                               │
│ IP addresses                                                  │
│ DNS queries                                                   │
│ Browsing history                                              │
│ Traffic content                                               │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ What We Store Locally (encrypted):                              │
│ ─────────────────────────────────────                           │
│ Your private key (in secure storage)                          │
│ Server configurations                                         │
│ User preferences                                              │
└─────────────────────────────────────────────────────────────────┘
```

### Threat Model

#### What We Protect Against

1. **ISP Surveillance**: Your ISP cannot see what websites you visit
2. **Network Monitoring**: Public WiFi operators cannot intercept your traffic
3. **DNS Leaks**: All DNS queries go through encrypted tunnel
4. **IPv6 Leaks**: IPv6 traffic is routed through VPN or blocked
5. **Connection Drops**: Kill switch prevents unencrypted traffic

#### What We Don't Protect Against

1. **Malware on Your Device**: VPN doesn't scan for viruses
2. **Compromised VPN Server**: Trust the server operator
3. **Browser Fingerprinting**: Websites can still track you via cookies, etc.
4. **Traffic Analysis**: Advanced adversaries might correlate timing/size

### Memory Safety

Rust's memory safety guarantees prevent entire classes of vulnerabilities:
- **No buffer overflows**: Bounds checking at compile time
- **No use-after-free**: Ownership system prevents dangling pointers
- **No data races**: Borrow checker ensures thread safety
- **Secure memory wiping**: `Zeroizing` wrapper clears sensitive data

### Key Management

```
┌─────────────────────────────────────────────────────────────────┐
│ Private Key Lifecycle                                           │
│ ───────────────────────                                         │
│                                                                 │
│ 1. Generation                                                   │
│    • Created using cryptographically secure RNG                 │
│    • Never transmitted over network                             │
│    • Stored encrypted on disk                                   │
│                                                                 │
│ 2. In Memory                                                    │
│    • Wrapped in Zeroizing<[u8; 32]>                             │
│    • Automatically wiped when dropped                           │
│    • Never logged or printed                                    │
│                                                                 │
│ 3. Usage                                                        │
│    • Only used for WireGuard handshake                          │
│    • Converted to StaticSecret type                             │
│    • Session keys derived for actual encryption                 │
│                                                                 │
│ 4. Rotation                                                     │
│    • User can generate new keypair anytime                      │
│    • Old key securely wiped from memory                         │
│    • New key registered with VPN server                         │
└─────────────────────────────────────────────────────────────────┘
```

## Future Enhancements

### Planned Features

1. **Multi-hop**: Route through multiple VPN servers
2. **Split tunneling**: Route only specific apps through VPN
3. **Port forwarding**: For torrenting and gaming
4. **Custom DNS filters**: User-defined blocklists
5. **Traffic statistics**: Real-time bandwidth monitoring (local only)
6. **Server load balancing**: Automatic selection of fastest server

### Performance Optimizations

1. **Zero-copy networking**: Minimize memory allocations
2. **Kernel-space WireGuard**: Use native kernel module when available
3. **Connection pooling**: Reuse UDP sockets
4. **Batch packet processing**: Process multiple packets at once

---

**Last Updated**: March 18, 2026
**Version**: 0.1.0
