# RustVPN Data Flow Documentation

## Table of Contents
1. [VPN Data Flow: General Concepts](#vpn-data-flow-general-concepts)
2. [RustVPN Specific Data Flow](#rustvpn-specific-data-flow)
3. [Outgoing Traffic Flow](#outgoing-traffic-flow)
4. [Incoming Traffic Flow](#incoming-traffic-flow)
5. [Connection Lifecycle](#connection-lifecycle)
6. [Error Handling and Recovery](#error-handling-and-recovery)
7. [Packet Format Analysis](#packet-format-analysis)

---

## VPN Data Flow: General Concepts

### What is Data Flow in a VPN?

Data flow refers to the path that network packets take from your device to the internet (and back) when a VPN is active. Understanding this flow is crucial for understanding how VPNs provide privacy and security.

### The Traditional (Non-VPN) Data Flow

Without a VPN, your traffic flows directly:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Traditional Data Flow                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌────────────┐      ┌────────────┐      ┌──────────────┐     │
│  │  Your App  │ ───► │   Your ISP │ ───► │  Website     │     │
│  │ (Browser)  │      │            │      │  Server      │     │
│  └────────────┘      └────────────┘      └──────────────┘     │
│         │                  │                    │                │
│         │                  │                    │                │
│    Unencrypted       Can see all        Can see your         │
│    traffic           traffic             real IP               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Problems with Traditional Flow:**
- Your ISP sees which websites you visit
- Your ISP can see the content of unencrypted traffic
- Websites see your real IP address
- Network administrators can monitor your activity
- Public WiFi operators can intercept your traffic

### The VPN Data Flow

With a VPN, traffic is encrypted and routed through a VPN server:

```
┌─────────────────────────────────────────────────────────────────┐
│                        VPN Data Flow                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌────────────┐      ┌────────────┐      ┌──────────────┐     │
│  │  Your App  │ ───► │  VPN Tunnel│ ───► │  VPN Server  │     │
│  │ (Browser)  │      │ (Encrypted)│      │              │     │
│  └────────────┘      └────────────┘      └──────┬───────┘     │
│         │                  │                    │                │
│         │                  │                    │                │
│    Plain packet      Encrypted          Decrypts and          │
│    to TUN device     over UDP            forwards             │
│                                             │                  │
│                                             ▼                  │
│                                    ┌──────────────┐             │
│                                    │  Website     │             │
│                                    │  Server      │             │
│                                    └──────────────┘             │
│                                                                 │
│  ISP sees only encrypted blobs, cannot read contents            │
│  Website sees VPN server IP, not your real IP                   │
└─────────────────────────────────────────────────────────────────┘
```

**Benefits of VPN Flow:**
- Your ISP sees only encrypted traffic to VPN server
- Your ISP cannot see which websites you visit
- Websites see VPN server IP, not your real IP
- Traffic is encrypted end-to-end (your device to VPN server)
- Public WiFi operators cannot intercept your traffic

---

## RustVPN Specific Data Flow

### Architecture Overview

RustVPN uses a modular architecture where each component handles a specific part of the data flow:

```
┌─────────────────────────────────────────────────────────────────┐
│                     RustVPN Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌────────────┐                                                 │
│  │  Your App  │ ◄─── User applications (browser, email, etc.)  │
│  └─────┬──────┘                                                 │
│        │                                                         │
│        │ Plain IP packet                                        │
│        ▼                                                         │
│  ┌─────────────────┐                                            │
│  │ Operating System│                                            │
│  │   TCP/IP Stack  │                                            │
│  └────────┬────────┘                                            │
│           │                                                     │
│           │ Routing decision → TUN device (wg0)                │
│           ▼                                                     │
│  ┌─────────────────┐                                            │
│  │   TUN Device    │ ◄─── Virtual network interface             │
│  │    (wg0)        │      (platform/linux.rs)                   │
│  └────────┬────────┘                                            │
│           │                                                     │
│           │ RustVPN reads packet                                │
│           ▼                                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              RustVPN Application                         │   │
│  │                                                         │   │
│  │  ┌─────────────┐      ┌─────────────┐                  │   │
│  │  │   Tunnel    │ ───► │ Encapsulate │                  │   │
│  │  │  Module     │      │ (Encrypt)   │                  │   │
│  │  └─────────────┘      └──────┬──────┘                  │   │
│  │                               │                           │   │
│  │                               │ Encrypted packet          │   │
│  │                               ▼                           │   │
│  │                    ┌─────────────┐                       │   │
│  │                    │ UDP Socket  │                       │   │
│  │                    │ (Port 51820)│                       │   │
│  │                    └──────┬──────┘                       │   │
│  │                           │                                │   │
│  │                           │ Over internet                 │   │
│  │                           ▼                                │   │
│  │                    ┌─────────────┐                       │   │
│  │                    │ VPN Server   │                       │   │
│  │                    └─────────────┘                       │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Supporting Modules:                                            │
│  - Kill Switch (core/killswitch.rs) - Blocks non-VPN traffic    │
│  - Reconnect (core/reconnect.rs) - Auto-reconnect on failure    │
│  - DNS (dns/) - Filter and encrypt DNS queries                  │
│  - GUI (gui/app.rs) - User interface                            │
└─────────────────────────────────────────────────────────────────┘
```

### Module Interaction During Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                  Module Interaction Flow                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  User clicks "Connect"                                          │
│         │                                                        │
│         ▼                                                        │
│  GUI (gui/app.rs)                                               │
│         │                                                        │
│         │ Enable kill switch                                    │
│         ▼                                                        │
│  Kill Switch (core/killswitch.rs)                               │
│         │                                                        │
│         │ Apply firewall rules                                  │
│         ▼                                                        │
│  Platform (platform/linux.rs)                                   │
│         │                                                        │
│         │ Create TUN device                                    │
│         ▼                                                        │
│  Tunnel (core/tunnel.rs)                                        │
│         │                                                        │
│         │ Perform WireGuard handshake                           │
│         ▼                                                        │
│  [Connected - Ready for data flow]                              │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                  Packet Loop                              │  │
│  │                                                          │  │
│  │  TUN Device ──► Tunnel::encapsulate() ──► UDP Socket    │  │
│  │       │              │                    │              │  │
│  │       │              ▼                    ▼              │  │
│  │       │         ChaCha20           Send to VPN          │  │
│  │       │         Encryption          Server               │  │
│  │       │                                                  │  │
│  │  UDP Socket ──► Tunnel::decapsulate() ◄── VPN Server     │  │
│  │       │              │                    │              │  │
│  │       │              ▼                    ▼              │  │
│  │       │         ChaCha20           Receive from          │  │
│  │       │         Decryption         VPN Server            │  │
│  │       │                                                  │  │
│  │       └──► TUN Device (write decrypted packet)           │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Health Check (core/reconnect.rs)                               │
│         │                                                        │
│         │ Check connection every 30s                            │
│         ▼                                                        │
│  If failed → Trigger reconnection                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Outgoing Traffic Flow

### Step-by-Step Outgoing Flow

This is the detailed flow of data from your application to the internet when using RustVPN.

#### Step 1: Application Sends Data

```
User Action: Browser opens "https://example.com"
    │
    ▼
Browser creates HTTP request:
    GET / HTTP/1.1
    Host: example.com
    User-Agent: Mozilla/5.0...
    │
    ▼
Browser passes request to operating system TCP/IP stack
```

**Networking Concept:**
- Application doesn't know about VPN
- Application uses standard socket API
- Application thinks it's communicating directly with example.com

**Rust Context:**
- No Rust code involved yet
- This is standard application behavior

#### Step 2: Operating System Creates IP Packet

```
TCP/IP Stack receives HTTP request
    │
    ▼
Creates TCP segment:
    - Source Port: 54321 (ephemeral port)
    - Dest Port: 443 (HTTPS)
    - Sequence numbers
    - Flags (SYN, ACK, etc.)
    │
    ▼
Creates IP packet:
    - Source IP: 192.168.1.100 (your real IP)
    - Dest IP: 93.184.216.34 (example.com's IP)
    - Protocol: TCP (6)
    - TTL: 64
    │
    ▼
IP packet ready for transmission
```

**Networking Concept:**
- IP packet contains your real IP address
- This is what would normally be sent to ISP
- VPN intercepts this before it leaves your device

**Rust Context:**
- No Rust code involved yet
- This is standard OS behavior

#### Step 3: Routing Table Decision

```
OS consults routing table:
    
    Destination     Gateway         Interface
    ──────────────────────────────────────────
    0.0.0.0/0       -               wg0        ← Default route
    192.168.1.0/24  -               eth0
    10.8.0.0/24     -               wg0
    
    │
    ▼
Destination 93.184.216.34 matches 0.0.0.0/0
    │
    ▼
Route through interface: wg0 (VPN interface)
```

**Networking Concept:**
- Routing table determines which interface to use
- VPN changes default route to point to wg0
- All traffic goes through VPN interface

**Rust Context:**
- RustVPN configured routing table during connection
- This was done by platform/linux.rs

#### Step 4: TUN Device Intercepts Packet

```
IP packet sent to wg0 interface
    │
    ▼
┌─────────────────────────────────────┐
│         TUN Device (wg0)            │
│  Virtual network interface           │
│  Captures all outgoing traffic      │
└──────────────┬──────────────────────┘
               │
               │ Packet available for read
               ▼
RustVPN reads packet from TUN device
```

**Networking Concept:**
- TUN device is a virtual network interface
- It operates at Layer 3 (Network layer)
- It captures IP packets before they leave the device

**Rust Implementation:**
```rust
// In platform/linux.rs (future implementation)
let mut packet_buffer = [0u8; 1500];
let packet_length = tun_device.read(&mut packet_buffer)?;
// packet_buffer now contains the IP packet
```

#### Step 5: RustVPN Receives Packet

```
RustVPN packet loop receives packet from TUN device
    │
    ▼
Packet contents:
    [IP Header][TCP Header][HTTP Request]
    │
    ▼
Pass to Tunnel::encapsulate()
```

**Networking Concept:**
- RustVPN now has the plain IP packet
- This packet contains your real IP as source
- This packet needs to be encrypted

**Rust Implementation:**
```rust
// In future packet_loop.rs
let packet = tun_device.read().await?;
let mut encrypted_buffer = vec![0u8; packet.len() + 32];
```

#### Step 6: WireGuard Encapsulation

```
Tunnel::encapsulate() called with plain packet
    │
    ▼
┌─────────────────────────────────────────┐
│         Encapsulation Process            │
├─────────────────────────────────────────┤
│                                         │
│  1. Add WireGuard header (16 bytes)     │
│     - Message type                      │
│     - Receiver index                    │
│     - Counter                           │
│                                         │
│  2. Encrypt payload with ChaCha20       │
│     - Uses session key from handshake   │
│     - Encrypts IP packet                │
│                                         │
│  3. Add Poly1305 authentication tag     │
│     - 16 bytes                          │
│     - Verifies integrity                │
│                                         │
└─────────────────────────────────────────┘
    │
    ▼
Encrypted WireGuard packet ready
```

**Networking Concept:**
- Encapsulation wraps original packet in encryption
- WireGuard header provides protocol information
- ChaCha20 encrypts the payload
- Poly1305 ensures data hasn't been tampered with

**Rust Implementation:**
```rust
// In core/tunnel.rs
pub fn encapsulate(&mut self, packet: &[u8], dst: &mut [u8]) -> Result<usize> {
    let tunn = self.wireguard_tunnel.as_mut()
        .context("Tunnel not initialized")?;

    match tunn.encapsulate(packet, dst) {
        TunnResult::WriteToNetwork(data) => Ok(data.len()),
        // ... handle other cases
    }
}
```

#### Step 7: UDP Socket Transmission

```
Encrypted packet sent over UDP socket
    │
    ▼
UDP packet structure:
    [UDP Header][Encrypted WireGuard Packet]
    - Source Port: Random ephemeral port
    - Dest Port: 51820 (WireGuard default)
    │
    ▼
Send to VPN server endpoint (e.g., 203.0.113.1:51820)
```

**Networking Concept:**
- WireGuard uses UDP (not TCP)
- UDP is faster, no connection overhead
- Port 51820 is WireGuard's standard port
- Packet travels over internet to VPN server

**Rust Implementation:**
```rust
// In future packet_loop.rs
udp_socket.send_to(&encrypted_buffer[..encrypted_length], server_endpoint).await?;
```

#### Step 8: Transmission Over Internet

```
Encrypted packet travels over internet
    │
    ▼
┌─────────────────────────────────────────┐
│         ISP Perspective                 │
├─────────────────────────────────────────┤
│                                         │
│  ISP sees:                              │
│  - Source: Your real IP                 │
│  - Dest: VPN server IP                  │
│  - Protocol: UDP                        │
│  - Port: 51820                          │
│  - Data: Encrypted blob                 │
│                                         │
│  ISP CANNOT see:                        │
│  - Actual destination (example.com)      │
│  - Protocol type (HTTP/HTTPS)           │
│  - Content (HTTP request)               │
│                                         │
└─────────────────────────────────────────┘
```

**Networking Concept:**
- ISP sees only encrypted traffic to VPN server
- ISP cannot determine which website you're visiting
- ISP cannot see the content of your traffic
- This provides privacy from ISP surveillance

#### Step 9: VPN Server Receives Packet

```
VPN server receives encrypted UDP packet
    │
    ▼
┌─────────────────────────────────────────┐
│         VPN Server Processing            │
├─────────────────────────────────────────┤
│                                         │
│  1. Receive UDP packet                  │
│  2. Verify Poly1305 authentication tag  │
│  3. Decrypt with ChaCha20                │
│  4. Remove WireGuard header             │
│  5. Extract original IP packet          │
│                                         │
└─────────────────────────────────────────┘
    │
    ▼
Original IP packet recovered:
    [IP Header][TCP Header][HTTP Request]
    - Source: Your VPN-assigned IP (e.g., 10.8.0.2)
    - Dest: example.com IP (93.184.216.34)
```

**Networking Concept:**
- VPN server has private key to decrypt
- Server extracts original packet
- Server now knows the real destination
- Server forwards packet to destination

#### Step 10: Forward to Destination

```
VPN server forwards packet to example.com
    │
    ▼
Packet from VPN server to example.com:
    - Source: VPN server public IP
    - Dest: example.com IP
    - Content: Original HTTP request
    │
    ▼
example.com receives request
    │
    ▼
example.com sees VPN server IP, not your real IP
```

**Networking Concept:**
- Website sees VPN server IP, not your real IP
- This provides anonymity
- Website cannot determine your actual location

---

## Incoming Traffic Flow

### Step-by-Step Incoming Flow

This is the detailed flow of data from the internet back to your application.

#### Step 1: Website Sends Response

```
example.com processes HTTP request
    │
    ▼
example.com creates HTTP response:
    HTTP/1.1 200 OK
    Content-Type: text/html
    Content-Length: 1270
    
    <html>...</html>
    │
    ▼
example.com sends response to VPN server IP
```

**Networking Concept:**
- Website responds to VPN server IP
- Website doesn't know your real IP
- Response is unencrypted (website to VPN server)

#### Step 2: VPN Server Receives Response

```
VPN server receives HTTP response
    │
    ▼
VPN server knows this belongs to your session
    │
    ▼
VPN server creates IP packet:
    - Source: example.com IP
    - Dest: Your VPN-assigned IP (10.8.0.2)
    - Payload: HTTP response
```

**Networking Concept:**
- VPN server tracks which packets belong to which client
- Server creates IP packet for your VPN IP
- This packet needs to be encrypted

#### Step 3: WireGuard Encapsulation (Server Side)

```
VPN server encapsulates packet:
    │
    ▼
┌─────────────────────────────────────────┐
│      Server-Side Encapsulation           │
├─────────────────────────────────────────┤
│                                         │
│  1. Add WireGuard header                 │
│  2. Encrypt with session key            │
│  3. Add Poly1305 tag                     │
│                                         │
└─────────────────────────────────────────┘
    │
    ▼
Encrypted WireGuard packet
```

**Networking Concept:**
- Server uses same encryption process
- Session key was established during handshake
- Both sides use same key for encryption/decryption

#### Step 4: UDP Transmission to Client

```
VPN server sends encrypted packet over UDP
    │
    ▼
Destination: Your public IP (from NAT)
Port: Your UDP port (from connection tracking)
```

**Networking Concept:**
- Server sends to your public IP
- NAT (if present) translates to your private IP
- UDP is stateless but server tracks session

#### Step 5: Your Device Receives Packet

```
Your device receives UDP packet
    │
    ▼
UDP socket receives packet
    │
    ▼
Pass to Tunnel::decapsulate()
```

**Networking Concept:**
- Packet arrives at your device
- RustVPN's UDP socket receives it
- Ready for decryption

**Rust Implementation:**
```rust
// In future packet_loop.rs
let (encrypted_packet, _sender_addr) = udp_socket.recv_from().await?;
let mut decrypted_buffer = vec![0u8; encrypted_packet.len()];
```

#### Step 6: WireGuard Decapsulation

```
Tunnel::decapsulate() called with encrypted packet
    │
    ▼
┌─────────────────────────────────────────┐
│         Decapsulation Process            │
├─────────────────────────────────────────┤
│                                         │
│  1. Verify Poly1305 authentication tag  │
│     - If invalid: Reject packet         │
│     - If valid: Continue                │
│                                         │
│  2. Decrypt with ChaCha20               │
│     - Uses session key                  │
│     - Decrypts payload                  │
│                                         │
│  3. Remove WireGuard header             │
│     - Extract original IP packet        │
│                                         │
└─────────────────────────────────────────┘
    │
    ▼
Original IP packet recovered:
    [IP Header][TCP Header][HTTP Response]
```

**Networking Concept:**
- Authentication tag prevents tampering
- Decryption recovers original packet
- WireGuard header removed

**Rust Implementation:**
```rust
// In core/tunnel.rs
pub fn decapsulate(&mut self, packet: &[u8], dst: &mut [u8]) -> Result<usize> {
    let tunn = self.wireguard_tunnel.as_mut()
        .context("Tunnel not initialized")?;

    match tunn.decapsulate(None, packet, dst) {
        TunnResult::WriteToTunnelV4(data, _) => Ok(data.len()),
        // ... handle other cases
    }
}
```

#### Step 7: Write to TUN Device

```
Decrypted packet written to TUN device
    │
    ▼
┌─────────────────────────────────────┐
│         TUN Device (wg0)            │
│  Receives decrypted IP packet       │
│  Injects into network stack         │
└──────────────┬──────────────────────┘
               │
               │ Packet injected
               ▼
Operating system receives packet
```

**Networking Concept:**
- TUN device injects packet into OS network stack
- OS thinks packet arrived from network
- OS routes packet to appropriate application

**Rust Implementation:**
```rust
// In future packet_loop.rs
tun_device.write(&decrypted_buffer[..decrypted_length]).await?;
```

#### Step 8: Operating System Processing

```
OS receives IP packet
    │
    ▼
IP header processing:
    - Dest IP: 192.168.1.100 (your real IP)
    - Protocol: TCP
    │
    ▼
TCP segment processing:
    - Dest Port: 54321 (ephemeral port)
    │
    ▼
Route to application that owns port 54321
```

**Networking Concept:**
- OS processes IP and TCP headers
- OS identifies destination application by port
- OS delivers data to application

#### Step 9: Application Receives Data

```
Browser receives HTTP response
    │
    ▼
Browser processes response:
    - Parse HTTP headers
    - Render HTML
    - Display webpage
    │
    ▼
User sees webpage
```

**Networking Concept:**
- Application receives data as if no VPN existed
- Application is unaware of encryption/decryption
- Transparency is key to VPN usability

---

## Connection Lifecycle

### Complete Connection Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│              RustVPN Connection Lifecycle                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [START]                                                        │
│    │                                                            │
│    ▼                                                            │
│  ┌────────────────────┐                                        │
│  │ Load Configuration │  • Read user preferences                │
│  │                    │  • Load server list                     │
│  │                    │  • Get private key                      │
│  └────────┬───────────┘                                        │
│           │                                                     │
│           ▼                                                     │
│  ┌────────────────────┐                                        │
│  │   User clicks     │                                        │
│  │   "Connect"       │                                        │
│  └────────┬───────────┘                                        │
│           │                                                     │
│           ▼                                                     │
│  ┌────────────────────┐                                        │
│  │ Enable Kill Switch │  • Apply firewall rules                │
│  │                    │  • Block non-VPN traffic               │
│  │                    │  • Allow VPN server connection          │
│  └────────┬───────────┘                                        │
│           │                                                     │
│           ▼                                                     │
│  ┌────────────────────┐                                        │
│  │ Create TUN Device  │  • Platform-specific creation          │
│  │                    │  • Assign IP (10.8.0.2)                │
│  │                    │  • Set MTU (1420)                       │
│  │                    │  • Configure routing                   │
│  └────────┬───────────┘                                        │
│           │                                                     │
│           ▼                                                     │
│  ┌────────────────────┐                                        │
│  │ Connect Tunnel      │  • Create WireGuard instance           │
│  │                    │  • Perform Noise handshake              │
│  │                    │  • Establish shared secret              │
│  │                    │  • Update state: Connected             │
│  └────────┬───────────┘                                        │
│           │                                                     │
│           ▼                                                     │
│  ┌────────────────────┐                                        │
│  │ Start Packet Loop  │  • Read from TUN → Encrypt → UDP       │
│  │                    │  • Receive UDP → Decrypt → TUN         │
│  │                    │  • Handle keepalive                    │
│  └────────┬───────────┘                                        │
│           │                                                     │
│           ▼                                                     │
│  ┌────────────────────┐                                        │
│  │ Start Health Check │  • Check connection every 30s         │
│  │                    │  • Trigger reconnect if failed          │
│  └────────┬───────────┘                                        │
│           │                                                     │
│           ▼                                                     │
│  ┌────────────────────┐                                        │
│  │   [CONNECTED]      │  • Traffic flowing                     │
│  │                    │  • Encryption active                   │
│  │                    │  • Kill switch active                  │
│  └────────┬───────────┘                                        │
│           │                                                     │
│           │ (Connection lost or user disconnects)               │
│           ▼                                                     │
│  ┌────────────────────┐                                        │
│  │ Handle Disconnect  │                                        │
│  │                    │                                        │
│  │ If lost:          │  • Auto-reconnect attempts              │
│  │   ├─ Reconnect    │  • Exponential backoff                  │
│  │   └─ Retry        │                                        │
│  │                    │                                        │
│  │ If user disconnect:│  • Disable kill switch                  │
│  │   └─ Cleanup      │  • Destroy TUN device                   │
│  │                    │  • Clear routing                        │
│  └────────┬───────────┘                                        │
│           │                                                     │
│           ▼                                                     │
│  [DISCONNECTED]                                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Detailed Connection Establishment

#### Noise Protocol Handshake

```
Client                                    Server
  │                                          │
  │ State: Disconnected                      │ State: Listening
  │                                          │
  │ ── Step 1: Initiation Message ──────────►│
  │                                          │
  │ Contents:                                │
  │ • Client ephemeral public key (32 bytes) │
  │ • Encrypted timestamp                    │
  │ • MAC (authentication)                   │
  │                                          │
  │ Server processes:                        │
  │ • Derive shared secret:                  │
  │   shared = X25519(server_private,        │
  │                   client_ephemeral_pub)  │
  │ • Verify MAC                             │
  │ • Decrypt timestamp                      │
  │                                          │
  │ ◄─ Step 2: Response Message ─────────────│
  │                                          │
  │ Contents:                                │
  │ • Server ephemeral public key (32 bytes) │
  │ • Encrypted timestamp                    │
  │ • MAC                                   │
  │                                          │
  │ Client processes:                        │
  │ • Derive shared secret:                  │
  │   shared = X25519(client_private,        │
  │                   server_ephemeral_pub)  │
  │ • Verify MAC                             │
  │ • Decrypt timestamp                      │
  │                                          │
  │ ── Step 3: Both have shared secret ──────│
  │                                          │
  │ Shared secret now used for:              │
  │ • Deriving session keys                  │
  │ • Encrypting/decrypting data packets      │
  │                                          │
  │ State: Connected                         │ State: Connected
  │                                          │
  │ ── Step 4: Data exchange (encrypted) ───►│
  │ ◄─ Step 4: Data exchange (encrypted) ─────│
```

**Key Exchange Details:**

```
X25519 Key Exchange:
    
    Client                              Server
      │                                    │
      │ Private: a (secret)               │ Private: b (secret)
      │ Public: A = a·G (shared)          │ Public: B = b·G (shared)
      │                                    │
      │ ── A ───────────────────────────► │
      │                                    │
      │ ◄── B ─────────────────────────── │
      │                                    │
      │ Compute shared secret:             │ Compute shared secret:
      │ shared = a·B                       │ shared = b·A
      │         = a·(b·G)                  │         = b·(a·G)
      │         = (a·b)·G                  │         = (a·b)·G
      │                                    │
      │ Both have same shared secret!       │
```

**Session Key Derivation:**

```
Shared secret → KDF → Session keys
                     │
                     ├─ Encryption key (send)
                     ├─ Encryption key (receive)
                     └─ Other keys

Keys rotated every 2 minutes for forward secrecy
```

---

## Error Handling and Recovery

### Connection Failure Scenarios

#### Scenario 1: Network Change

```
User switches from WiFi to cellular
    │
    ▼
VPN connection drops
    │
    ▼
Health check detects failure
    │
    ▼
ReconnectManager triggered
    │
    ▼
Wait backoff duration (1s)
    │
    ▼
Attempt reconnection
    │
    ├─ Success: Record success, reset backoff
    │
    └─ Failure: Record failure, increase backoff (2s)
        │
        ▼
    Wait 2s
        │
        ▼
    Attempt reconnection
        │
        └─ (repeat until success)
```

#### Scenario 2: Server Unreachable

```
VPN server goes down for maintenance
    │
    ▼
All connection attempts fail
    │
    ▼
Backoff increases: 1s → 2s → 4s → 8s → 16s → 30s
    │
    ▼
ReconnectManager caps at 30s
    │
    ▼
Continues retrying every 30s
    │
    ▼
Server comes back online
    │
    ▼
Connection succeeds
    │
    ▼
Record success, reset backoff to 1s
```

#### Scenario 3: Kill Switch Activation

```
VPN connection drops unexpectedly
    │
    ▼
Kill switch already enabled (was enabled before connect)
    │
    ▼
All non-VPN traffic blocked
    │
    ▼
Only VPN reconnection attempts allowed
    │
    ▼
Reconnection succeeds
    │
    ▼
Traffic resumes through VPN
```

### Error Recovery Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                  Error Recovery Flow                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Error Detected                                                 │
│    │                                                            │
│    ├─ Network error (timeout, unreachable)                      │
│    ├─ Authentication error (invalid key)                         │
│    ├─ Decryption error (corrupted packet)                       │
│    └─ Health check failure                                      │
│    │                                                            │
│    ▼                                                            │
│  Log error details                                               │
│    │                                                            │
│    ▼                                                            │
│  Update tunnel state to Error or Reconnecting                   │
│    │                                                            │
│    ▼                                                            │
│  If auto-reconnect enabled:                                     │
│    │                                                            │
│    ├─ Trigger ReconnectManager                                  │
│    ├─ Wait backoff duration                                     │
│    ├─ Attempt reconnection                                      │
│    │                                                            │
│    └─ If success:                                                │
│          • Record success                                        │
│          • Reset backoff                                         │
│          • Update state to Connected                             │
│          • Resume packet loop                                    │
│                                                                 │
│    └─ If failure (after max retries):                            │
│          • Notify user via GUI                                   │
│          • Keep kill switch active                               │
│          • Allow manual reconnection                             │
│                                                                 │
│  If auto-reconnect disabled:                                     │
│    │                                                            │
│    ├─ Notify user via GUI                                       │
│    ├─ Update state to Disconnected                               │
│    └─ Wait for manual reconnect                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Packet Format Analysis

### Plain IP Packet Format (Before Encryption)

```
┌─────────────────────────────────────────────────────────────────┐
│                  Plain IP Packet Structure                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ IP Header (20-60 bytes)                                 │   │
│  │                                                          │   │
│  │  Version (4)   IHL (4)   TOS (8)    Total Length (16)   │   │
│  │  Identification (16)   Flags (3)   Fragment Offset (13)  │   │
│  │  TTL (8)   Protocol (8)   Header Checksum (16)           │   │
│  │  Source IP Address (32)                                │   │
│  │  Destination IP Address (32)                            │   │
│  │  Options (0-40 bytes, if present)                      │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ TCP Header (20-60 bytes)                                │   │
│  │                                                          │   │
│  │  Source Port (16)   Destination Port (16)               │   │
│  │  Sequence Number (32)                                   │   │
│  │  Acknowledgment Number (32)                             │   │
│  │  Data Offset (4)  Reserved (3)  Flags (9)   Window (16)│   │
│  │  Checksum (16)    Urgent Pointer (16)                  │   │
│  │  Options (0-40 bytes, if present)                      │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Payload (HTTP request/response, etc.)                   │   │
│  │                                                          │   │
│  │  GET / HTTP/1.1                                         │   │
│  │  Host: example.com                                      │   │
│  │  ...                                                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Encrypted WireGuard Packet Format

```
┌─────────────────────────────────────────────────────────────────┐
│            Encrypted WireGuard Packet Structure                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ UDP Header (8 bytes)                                    │   │
│  │                                                          │   │
│  │  Source Port (16)   Destination Port (16)               │   │
│  │  Length (16)       Checksum (16)                        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ WireGuard Header (16 bytes)                             │   │
│  │                                                          │   │
│  │  Message Type (4)   Receiver Index (4)                 │   │
│  │  Counter (64)                                          │   │
│  │                                                          │   │
│  │  Message Type:                                          │   │
│  │  • 1: Handshake Initiation                              │   │
│  │  • 2: Handshake Response                               │   │
│  │  • 3: Cookie Reply                                      │   │
│  │  • 4: Transport Data                                    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Encrypted Payload (Variable length)                     │   │
│  │                                                          │   │
│  │  [Encrypted IP Packet + TCP Header + Payload]           │   │
│  │  [Encrypted with ChaCha20 stream cipher]                │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Poly1305 Authentication Tag (16 bytes)                  │   │
│  │                                                          │   │
│  │  128-bit MAC (Message Authentication Code)              │   │
│  │  Verifies packet integrity and authenticity              │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Packet Size Analysis

**Typical Packet Sizes:**

```
Plain IP Packet:
- IP Header: 20 bytes
- TCP Header: 20 bytes
- Payload: Variable (e.g., 500 bytes HTTP request)
- Total: ~540 bytes

WireGuard Encrypted Packet:
- UDP Header: 8 bytes
- WireGuard Header: 16 bytes
- Encrypted Payload: 540 bytes
- Poly1305 Tag: 16 bytes
- Total: ~580 bytes

Overhead: 40 bytes (7.4% overhead)
```

**MTU Considerations:**

```
Standard Ethernet MTU: 1500 bytes
WireGuard MTU: 1420 bytes (recommended)
- Allows for WireGuard overhead
- Prevents fragmentation

If packet exceeds MTU:
- Packet must be fragmented
- Reduces performance
- Increases latency
```

---

## Summary

### Key Takeaways

1. **Data Flow Transparency**: Applications are unaware of VPN; they operate normally
2. **Encryption Point**: Encryption happens at TUN device level (Layer 3)
3. **Transport Protocol**: WireGuard uses UDP for speed and simplicity
4. **Key Exchange**: X25519 provides secure key exchange with forward secrecy
5. **Packet Overhead**: WireGuard adds ~40 bytes per packet for encryption
6. **Routing**: VPN changes routing table to direct traffic through TUN device
7. **Kill Switch**: Firewall rules ensure no traffic leaks when VPN disconnects
8. **Auto-Reconnect**: Exponential backoff prevents server hammering during outages

### Security Guarantees

- **ISP Privacy**: ISP sees only encrypted traffic to VPN server
- **Website Anonymity**: Websites see VPN server IP, not real IP
- **Data Integrity**: Poly1305 prevents packet tampering
- **Forward Secrecy**: Key rotation every 2 minutes
- **Leak Prevention**: Kill switch blocks non-VPN traffic

### Performance Considerations

- **Encryption Overhead**: ChaCha20 is very fast (constant-time)
- **Protocol Choice**: UDP is faster than TCP (no handshake overhead)
- **MTU Optimization**: 1420 byte MTU prevents fragmentation
- **Keepalive**: 25-second keepalive prevents NAT timeout
- **Health Checks**: 30-second interval balances monitoring and overhead

---

**Last Updated**: April 14, 2026
**Version**: 0.1.0
