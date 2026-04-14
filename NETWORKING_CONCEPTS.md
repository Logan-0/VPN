# Networking Concepts for RustVPN

## Table of Contents
1. [Introduction to Networking Fundamentals](#introduction-to-networking-fundamentals)
2. [How VPNs Work: A Deep Dive](#how-vpns-work-a-deep-dive)
3. [Network Protocols and Layers](#network-protocols-and-layers)
4. [IP Addresses and Routing](#ip-addresses-and-routing)
5. [UDP vs TCP](#udp-vs-tcp)
6. [Encryption and Cryptography](#encryption-and-cryptography)
7. [TUN/TAP Devices](#tuntap-devices)
8. [DNS (Domain Name System)](#dns-domain-name-system)
9. [Firewalls and Packet Filtering](#firewalls-and-packet-filtering)
10. [Network Interfaces](#network-interfaces)

---

## Introduction to Networking Fundamentals

### What is a Network?

A computer network is a collection of interconnected devices that can exchange data. When you browse the internet, your device communicates with servers around the world through a complex network infrastructure.

### Key Networking Concepts

#### 1. IP Addresses (Internet Protocol Addresses)

Every device on a network needs a unique identifier called an IP address. Think of it like a phone number for your computer.

- **IPv4**: 32-bit address (e.g., 192.168.1.1)
- **IPv6**: 128-bit address (e.g., 2001:db8::1)

**In Rust:**
```rust
use std::net::IpAddr;

// IPv4 address
let ipv4_address: IpAddr = "192.168.1.1".parse().unwrap();

// IPv6 address
let ipv6_address: IpAddr = "2001:db8::1".parse().unwrap();
```

#### 2. Ports

A port is a communication endpoint. Think of it like an apartment number in a building (IP address is the building, port is the apartment).

- Port 80: HTTP (unencrypted web)
- Port 443: HTTPS (encrypted web)
- Port 51820: WireGuard VPN (default)

**In Rust:**
```rust
use std::net::SocketAddr;

// IP address + port = Socket address
let server_address: SocketAddr = "203.0.113.1:51820".parse().unwrap();
```

#### 3. Packets

Data sent over networks is broken into small chunks called packets. Each packet contains:
- **Payload**: The actual data being sent
- **Header**: Metadata (source IP, destination IP, port numbers, etc.)

**In Rust:**
```rust
// A packet is just a byte array
let packet: Vec<u8> = vec![0x45, 0x00, 0x00, 0x3c, ...]; // IP packet example
```

---

## How VPNs Work: A Deep Dive

### The Problem: Why We Need VPNs

Without a VPN, your internet traffic is exposed:

```
Your Device ──► ISP ──► Website
     │            │          │
  Real IP      Can see     Can see
  exposed     all traffic  real IP
```

**Risks:**
- Your ISP can see which websites you visit
- Public WiFi operators can intercept your traffic
- Websites can track your real IP address
- Network administrators can monitor your activity

### The VPN Solution: Encrypted Tunnel

A VPN creates an encrypted tunnel between your device and a VPN server:

```
Your Device ──► Encrypted Tunnel ──► VPN Server ──► Website
     │                  │                   │          │
  Real IP hidden    ISP sees only       Server sees  Website sees
  by encryption    encrypted blobs    decrypted   VPN server IP
                                         traffic
```

### How the Tunnel Works

#### Step 1: Application Sends Data
```
Browser: "GET https://example.com HTTP/1.1"
         ↓
Creates IP packet: [Source: Your IP, Dest: example.com IP]
```

#### Step 2: TUN Device Intercepts
```
The TUN (network tunnel) device is a virtual network interface.
It captures all outgoing traffic from your applications.
```

**In Rust (conceptual):**
```rust
// TUN device reads packets from the operating system
let packet = tun_device.read().await?;
// packet contains the IP packet your browser created
```

#### Step 3: Encryption (Encapsulation)
```
Original IP packet → Encrypt with ChaCha20-Poly1305 → Add WireGuard header
```

**In Rust:**
```rust
// Encrypt the packet
let mut encrypted_buffer = vec![0u8; packet.len() + 32];
let encrypted_length = tunnel.encapsulate(&packet, &mut encrypted_buffer)?;
```

#### Step 4: Transmission Over Internet
```
Encrypted packet sent over UDP to VPN server (port 51820)
ISP only sees encrypted data, cannot read contents
```

**In Rust:**
```rust
// Send encrypted packet over UDP
udp_socket.send_to(&encrypted_buffer[..encrypted_length], server_address).await?;
```

#### Step 5: Server Decryption and Forwarding
```
VPN Server receives encrypted packet
↓
Decrypts with server's private key
↓
Extracts original IP packet
↓
Forwards to example.com
```

#### Step 6: Response (Reverse Process)
```
example.com sends response to VPN server
↓
VPN server encrypts response
↓
Sends encrypted packet to your device
↓
Your device decrypts
↓
Writes decrypted packet to TUN device
↓
Operating system delivers to browser
```

---

## Network Protocols and Layers

### The OSI Model

The Open Systems Interconnection (OSI) model has 7 layers:

```
┌─────────────────────────────────────────┐
│ Layer 7: Application                    │ ← Your browser, email client
│         (HTTP, DNS, SMTP)               │
├─────────────────────────────────────────┤
│ Layer 6: Presentation                    │ ← Encryption, formatting
│         (TLS/SSL, ASCII, UTF-8)          │
├─────────────────────────────────────────┤
│ Layer 5: Session                        │ ← Connection management
│         (Session establishment)          │
├─────────────────────────────────────────┤
│ Layer 4: Transport                      │ ← End-to-end communication
│         (TCP, UDP)                       │
├─────────────────────────────────────────┤
│ Layer 3: Network                        │ ← Routing between networks
│         (IP, ICMP)                       │
├─────────────────────────────────────────┤
│ Layer 2: Data Link                      │ ← Direct device communication
│         (Ethernet, MAC)                  │
├─────────────────────────────────────────┤
│ Layer 1: Physical                       │ ← Actual hardware
│         (Cables, WiFi signals)           │
└─────────────────────────────────────────┘
```

### Where VPN Operates

A VPN operates at **Layer 3 (Network)** and **Layer 4 (Transport)**:

- **Layer 3**: VPN creates a virtual network interface (TUN device)
- **Layer 4**: VPN uses UDP (User Datagram Protocol) for transport
- **Layer 5-6**: VPN handles encryption (presentation layer)

### TCP vs UDP

#### TCP (Transmission Control Protocol)
- **Reliable**: Guaranteed delivery, ordered packets
- **Connection-oriented**: Requires handshake before data transfer
- **Slower**: Overhead from error checking and retransmission
- **Use case**: Web browsing, email, file transfer

**TCP Three-Way Handshake:**
```
Client                    Server
  │                          │
  │ ── SYN ──────────────────►│  "I want to connect"
  │                          │
  │ ◄── SYN-ACK ─────────────│  "I hear you, let's connect"
  │                          │
  │ ── ACK ──────────────────►│  "Connection established"
  │                          │
  │ [Data can now flow]      │
```

#### UDP (User Datagram Protocol)
- **Unreliable**: No guarantee of delivery or order
- **Connectionless**: Send and forget
- **Faster**: No overhead from handshakes or error checking
- **Use case**: Video streaming, gaming, VPNs

**Why WireGuard Uses UDP:**
1. **Speed**: VPN needs to be fast, TCP overhead adds latency
2. **Simplicity**: UDP is simpler, easier to implement
3. **Flexibility**: VPN can handle reliability at higher layer
4. **NAT Traversal**: UDP works better through NAT devices

**In Rust:**
```rust
use tokio::net::UdpSocket;

// Create UDP socket
let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;

// Send data (no connection needed)
udp_socket.send_to(&data, server_address).await?;

// Receive data
let (received_data, sender_address) = udp_socket.recv_from().await?;
```

---

## IP Addresses and Routing

### IP Address Classes

#### Private IP Addresses (Not routable on internet)
- **192.168.0.0/16**: Home networks
- **10.0.0.0/8**: Corporate networks
- **172.16.0.0/12**: Corporate networks

#### Public IP Addresses (Routable on internet)
- Assigned by ISPs
- Unique across the internet
- Can be geolocated

### CIDR Notation (Classless Inter-Domain Routing)

CIDR notation specifies IP address ranges:

- **192.168.1.0/24**: 192.168.1.0 to 192.168.1.255 (256 addresses)
- **10.0.0.0/8**: 10.0.0.0 to 10.255.255.255 (16,777,216 addresses)
- **0.0.0.0/0**: All IP addresses (entire internet)

**In Rust:**
```rust
use std::net::Ipv4Addr;

// Parse CIDR notation
let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
let prefix: u8 = 24; // /24 prefix

// Calculate network address
let network_address = ip_to_network(ip, prefix);
```

### Routing Tables

Your operating system uses a routing table to decide where to send packets:

```
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         192.168.1.1     0.0.0.0         UG    0      0        0 eth0
192.168.1.0     0.0.0.0         255.255.255.0   U     0      0        0 eth0
10.8.0.0        0.0.0.0         255.255.255.0   U     0      0        0 wg0
```

**How VPN Changes Routing:**
1. Default route (0.0.0.0/0) points to VPN interface (wg0)
2. All traffic goes through VPN
3. VPN server IP is explicitly routed through normal interface

**In Rust (Linux):**
```rust
use std::process::Command;

// Add route through VPN interface
Command::new("ip")
    .args(["route", "add", "0.0.0.0/0", "dev", "wg0"])
    .output()
    .expect("Failed to add route");
```

---

## Encryption and Cryptography

### Symmetric Encryption

Same key encrypts and decrypts.

**How it works:**
```
Plaintext + Key ──► Encrypt ──► Ciphertext
Ciphertext + Key ──► Decrypt ──► Plaintext
```

**ChaCha20 (used by WireGuard):**
- Stream cipher
- Very fast
- Constant-time (prevents timing attacks)
- Designed for high-performance systems

**In Rust:**
```rust
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

// Create cipher
let key = Key::from_slice(&your_32_byte_key);
let cipher = ChaCha20Poly1305::new(key);

// Encrypt
let nonce = Nonce::from_slice(&your_12_byte_nonce);
let ciphertext = cipher.encrypt(nonce, plaintext)?;
```

### Asymmetric Encryption

Different keys for encryption and decryption.

**How it works:**
```
Public Key (shared)  ──► Encrypt ──► Ciphertext
Private Key (secret) ──► Decrypt ──► Plaintext
```

**X25519 (used by WireGuard for key exchange):**
- Elliptic curve cryptography
- Establishes shared secret between two parties
- Each party has a keypair (private + public)
- Private keys never shared
- Public keys can be shared openly

**Key Exchange Process:**
```
Client                          Server
  │                                │
  │ Private key: secret            │ Private key: secret
  │ Public key: shared             │ Public key: shared
  │                                │
  │ ── Public key ─────────────────►│
  │                                │
  │ ◄── Public key ────────────────│
  │                                │
  │ Both compute:                  │
  │ shared_secret =                │
  │   X25519(my_private,           │
  │           their_public)        │
  │                                │
  │ Now both have same secret!     │
  │                                │
  │ Use shared secret for          │
  │ symmetric encryption           │
```

**In Rust:**
```rust
use boringtun::x25519::{StaticSecret, PublicKey};

// Generate keypair
let private_key = StaticSecret::random_from_rng(rand::thread_rng());
let public_key = PublicKey::from(&private_key);

// Derive shared secret
let shared_secret = private_key.diffie_hellman(&their_public_key);
```

### Authentication (MAC)

Message Authentication Code ensures data hasn't been tampered with.

**Poly1305 (used by WireGuard):**
- Produces 16-byte authentication tag
- Tag is sent with encrypted data
- Receiver verifies tag before decrypting
- If tag invalid → packet rejected

**How it works:**
```
Data + Key ──► Poly1305 ──► Authentication Tag
Data + Tag ──► Verify ──► Valid/Invalid
```

**In Rust:**
```rust
use poly1305::Poly1305;

// Create MAC
let mac = Poly1305::new(key);
let tag = mac.compute_unauthenticated(data);

// Verify
let verification_result = mac.verify(data, tag);
```

### WireGuard's Cryptography Stack

WireGuard uses a layered approach:

```
┌─────────────────────────────────────────┐
│ Layer 1: Key Exchange                    │
│ X25519 (establishes shared secret)       │
├─────────────────────────────────────────┤
│ Layer 2: Symmetric Encryption            │
│ ChaCha20 (encrypts/decrypts data)        │
├─────────────────────────────────────────┤
│ Layer 3: Authentication                  │
│ Poly1305 (verifies data integrity)       │
├─────────────────────────────────────────┤
│ Layer 4: Hashing                         │
│ BLAKE2s (fast, secure hashing)           │
└─────────────────────────────────────────┘
```

**Why this combination?**
- **X25519**: Fast key exchange, forward secrecy
- **ChaCha20**: Very fast encryption, constant-time
- **Poly1305**: Fast authentication, minimal overhead
- **BLAKE2s**: Fast hashing, resistant to attacks

---

## TUN/TAP Devices

### What are TUN/TAP Devices?

TUN and TAP are virtual network interfaces that allow user-space programs to intercept network traffic.

#### TUN Device (Layer 3 - Network)
- Handles IP packets
- Used by VPNs
- Works at the network layer

#### TAP Device (Layer 2 - Data Link)
- Handles Ethernet frames
- Used by virtual machines
- Works at the data link layer

### How TUN Devices Work

```
┌─────────────────────────────────────────────────────────┐
│                  Operating System                        │
│                                                         │
│  Application                                            │
│       │                                                 │
│       │ Socket write                                    │
│       ▼                                                 │
│  TCP/IP Stack                                          │
│       │                                                 │
│       │ IP packet created                               │
│       ▼                                                 │
│  Routing Table                                         │
│       │                                                 │
│       │ Route to TUN device                             │
│       ▼                                                 │
│  ┌─────────────────┐                                    │
│  │   TUN Device    │ ◄─── VPN application reads from   │
│  │   (virtual)    │      here                        │
│  └─────────────────┘                                    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### TUN Device in RustVPN

**Flow:**
1. Application sends HTTP request
2. OS creates IP packet
3. Routing table sends packet to TUN device (wg0)
4. RustVPN reads packet from TUN device
5. RustVPN encrypts packet
6. RustVPN sends encrypted packet over UDP to VPN server

**In Rust (using tun crate):**
```rust
use tun::{Configuration, create};

// Configure TUN device
let configuration = Configuration::default()
    .name("wg0")
    .address((10, 8, 0, 2))
    .netmask((255, 255, 255, 0))
    .up();

// Create TUN device
let mut tun_device = create(&configuration)?;

// Read packet from TUN device
let mut packet_buffer = [0u8; 1500];
let packet_length = tun_device.read(&mut packet_buffer)?;

// Process packet (encrypt, send over UDP, etc.)
```

### TUN Device Permissions

Creating TUN devices requires elevated privileges:

- **Linux**: root or CAP_NET_ADMIN capability
- **macOS**: root privileges
- **Windows**: Administrator privileges

**Why?**
- TUN devices modify routing tables
- TUN devices intercept all traffic
- Security risk if misused

---

## DNS (Domain Name System)

### What is DNS?

DNS translates human-readable domain names to IP addresses:

```
example.com ──► DNS Query ──► 93.184.216.34
```

### How DNS Works

```
Your Device                    DNS Server                   Website
    │                              │                          │
    │ ── "example.com?" ──────────►│                          │
    │                              │                          │
    │                              │ ── "example.com?" ──────►│
    │                              │                          │
    │                              │ ◄── "93.184.216.34" ─────│
    │                              │                          │
    │ ◄── "93.184.216.34" ─────────│                          │
    │                              │                          │
    │ Now connect to 93.184.216.34 │                          │
```

### DNS Leak Problem

Without DNS protection, your DNS queries might bypass the VPN:

```
Your Device
    │
    ├─► DNS Query ──► ISP DNS Server (LEAK!)
    │                   Can see which websites you visit
    │
    └─► VPN Tunnel ──► VPN DNS Server (Protected)
```

### DNS Filtering

DNS filtering blocks requests to known malicious/advertising domains:

```
Query: ads.example.com
↓
DNS Filter checks blocklist
↓
Found in blocklist!
↓
Return: 0.0.0.0 (blocked)
```

### DNS-over-HTTPS (DoH)

Encrypts DNS queries using HTTPS:

```
Normal DNS:
Your Device ──► Clear text DNS query ──► DNS Server
(Anyone can see what you're querying)

DNS-over-HTTPS:
Your Device ──► Encrypted HTTPS ──► DNS Server
(ISP cannot see DNS queries)
```

**In RustVPN (planned):**
```rust
use hickory_resolver::Resolver;

// Create DoH resolver
let resolver = Resolver::tokio_from_config(
    ResolverConfig::cloudflare_https(),
    ResolverOpts::default()
)?;

// Resolve domain (encrypted)
let response = resolver.lookup_ip("example.com").await?;
```

---

## Firewalls and Packet Filtering

### What is a Firewall?

A firewall controls network traffic by allowing or blocking packets based on rules.

### How Firewalls Work

```
Incoming Packet
        │
        ▼
┌─────────────────┐
│ Firewall Rules  │
│                 │
│ Rule 1: Allow   │ ◄── Check against rules
│ Rule 2: Block   │
│ Rule 3: Allow   │
│ ...             │
└────────┬────────┘
         │
         ▼
    Decision
    │      │
    Allow  Block
```

### Kill Switch as Firewall

The VPN kill switch uses firewall rules to block non-VPN traffic:

```
┌─────────────────────────────────────────┐
│          Kill Switch Rules               │
│                                         │
│ 1. Block all outgoing traffic           │
│ 2. Allow VPN interface (wg0)            │
│ 3. Allow VPN server connection          │
│ 4. Allow local network (192.168.x.x)    │
│ 5. Allow loopback                       │
│ 6. Block everything else                │
└─────────────────────────────────────────┘
```

### Linux iptables

**Example kill switch rules:**
```bash
# Create custom chain
iptables -N RUSTVPN_OUT

# Allow loopback
iptables -A RUSTVPN_OUT -o lo -j ACCEPT

# Allow VPN interface
iptables -A RUSTVPN_OUT -o wg0 -j ACCEPT

# Allow VPN server
iptables -A RUSTVPN_OUT -d 203.0.113.1 -p udp --dport 51820 -j ACCEPT

# Allow local network
iptables -A RUSTVPN_OUT -d 192.168.0.0/16 -j ACCEPT

# Drop everything else
iptables -A RUSTVPN_OUT -j DROP

# Insert chain at beginning of OUTPUT
iptables -I OUTPUT 1 -j RUSTVPN_OUT
```

**In Rust:**
```rust
use std::process::Command;

// Execute iptables command
Command::new("iptables")
    .args(["-A", "RUSTVPN_OUT", "-o", "wg0", "-j", "ACCEPT"])
    .output()
    .expect("Failed to add iptables rule");
```

### macOS pf (Packet Filter)

**Example kill switch rules:**
```pf
# Block all traffic
block drop all

# Allow VPN interface
pass on utun0

# Allow VPN server
pass out proto udp to 203.0.113.1 port 51820

# Allow local network
pass to 192.168.0.0/16
```

### Windows Firewall

**Example kill switch rules:**
```cmd
# Block all outbound
netsh advfirewall firewall add rule name=RustVPN-BlockAll dir=out action=block

# Allow VPN server
netsh advfirewall firewall add rule name=RustVPN-AllowServer dir=out action=allow protocol=UDP remoteport=51820 remoteip=203.0.113.1
```

---

## Network Interfaces

### What is a Network Interface?

A network interface is the point of interconnection between a computer and a network.

### Types of Network Interfaces

#### Physical Interfaces
- **eth0**: Ethernet (wired)
- **wlan0**: Wireless (WiFi)
- **en0**: macOS Ethernet
- **Wi-Fi**: macOS Wireless

#### Virtual Interfaces
- **lo**: Loopback (127.0.0.1)
- **wg0**: WireGuard VPN
- **utun0**: macOS TUN device
- **docker0**: Docker bridge

### Interface Properties

Each interface has:
- **IP Address**: Unique identifier on network
- **Netmask**: Defines network size
- **MAC Address**: Hardware identifier (layer 2)
- **MTU**: Maximum Transmission Unit (max packet size)

**In Rust:**
```rust
use std::net::Ipv4Addr;

let interface_ip: Ipv4Addr = "10.8.0.2".parse().unwrap();
let netmask: Ipv4Addr = "255.255.255.0".parse().unwrap();
let mtu: u16 = 1420; // WireGuard default
```

### VPN Interface Configuration

When VPN connects:
1. Create virtual interface (wg0)
2. Assign IP address (e.g., 10.8.0.2)
3. Set netmask (e.g., 255.255.255.0)
4. Set MTU (typically 1420 for WireGuard)
5. Add routes through interface

**In Rust (Linux):**
```rust
// Configure interface
Command::new("ip")
    .args(["addr", "add", "10.8.0.2/24", "dev", "wg0"])
    .output()?;

// Bring interface up
Command::new("ip")
    .args(["link", "set", "wg0", "up"])
    .output()?;

// Add route
Command::new("ip")
    .args(["route", "add", "0.0.0.0/0", "dev", "wg0"])
    .output()?;
```

---

## Summary: How All These Concepts Work Together in RustVPN

### Complete Data Flow

```
1. User opens browser
   ↓
2. Browser resolves domain (DNS)
   ↓
3. Browser creates HTTP request
   ↓
4. OS creates IP packet
   ↓
5. Routing table sends to wg0 (TUN device)
   ↓
6. RustVPN reads packet from TUN device
   ↓
7. RustVPN encrypts with ChaCha20-Poly1305
   ↓
8. RustVPN sends over UDP to VPN server
   ↓
9. VPN server decrypts
   ↓
10. VPN server forwards to destination
   ↓
11. Response comes back (reverse process)
```

### Key Networking Concepts in RustVPN

1. **TUN Device**: Captures traffic at network layer
2. **UDP Protocol**: Fast, connectionless transport
3. **WireGuard Protocol**: Modern VPN protocol
4. **X25519**: Asymmetric key exchange
5. **ChaCha20-Poly1305**: Symmetric encryption + authentication
6. **Routing Tables**: Direct traffic through VPN
7. **Firewall Rules**: Kill switch blocks leaks
8. **DNS Filtering**: Blocks malicious domains

### Why Rust is Great for Networking

1. **Memory Safety**: No buffer overflows, use-after-free
2. **Performance**: Zero-cost abstractions, fast execution
3. **Concurrency**: tokio async runtime for efficient I/O
4. **Type Safety**: Compile-time error prevention
5. **Modern Ecosystem**: Excellent networking crates

---

**Last Updated**: April 14, 2026
**Version**: 0.1.0
