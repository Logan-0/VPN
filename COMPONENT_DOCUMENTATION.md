# RustVPN Component Documentation

## Table of Contents
1. [Tunnel Module (core/tunnel.rs)](#tunnel-module-coretunnelrs)
2. [Kill Switch Module (core/killswitch.rs)](#kill-switch-module-corekillswitchrs)
3. [Reconnect Manager (core/reconnect.rs)](#reconnect-manager-corereconnectrs)
4. [DNS Module (dns/)](#dns-module-dns)
5. [GUI Module (gui/app.rs)](#gui-module-guiapprs)
6. [Platform Module (platform/)](#platform-module-platform)
7. [Configuration Module (config.rs)](#configuration-module-configrs)
8. [Server Module (server.rs)](#server-module-serverrs)
9. [Update Module (update.rs)](#update-module-updaters)
10. [Main Entry Point (main.rs)](#main-entry-point-mainrs)

---

## Tunnel Module (core/tunnel.rs)

### Overview

The Tunnel module is the heart of RustVPN. It implements the WireGuard VPN protocol, handling encryption, decryption, and connection state management. This module is responsible for creating the secure encrypted tunnel between your device and the VPN server.

### Networking Concepts

#### WireGuard Protocol
WireGuard is a modern VPN protocol that uses:
- **Layer 3 (Network)**: Operates at the IP layer
- **UDP Transport**: Uses User Datagram Protocol for fast, connectionless communication
- **Noise Protocol Framework**: For secure key exchange
- **Cryptographic Stack**: X25519 + ChaCha20-Poly1305 + BLAKE2s

#### Encapsulation (Outgoing Traffic)
Encapsulation is the process of wrapping original data packets in additional protocol headers. In VPNs, this means:
1. Original IP packet (your browser's HTTP request)
2. Encrypt with ChaCha20-Poly1305
3. Add WireGuard header (16 bytes)
4. Add authentication tag (16 bytes)
5. Result: Encrypted WireGuard packet

#### Decapsulation (Incoming Traffic)
Decapsulation reverses encapsulation:
1. Receive encrypted WireGuard packet
2. Verify authentication tag (Poly1305)
3. Decrypt with ChaCha20-Poly1305
4. Remove WireGuard header
5. Result: Original IP packet

### Rust Implementation Details

#### Key Structures

**TunnelConfig**
```rust
pub struct TunnelConfig {
    pub private_key: Zeroizing<[u8; 32]>,      // Client's X25519 private key
    pub server_public_key: [u8; 32],           // Server's X25519 public key
    pub server_endpoint: SocketAddr,           // VPN server IP:port (UDP)
    pub allowed_ips: Vec<(IpAddr, u8)>,       // IP ranges to route through VPN
    pub dns_servers: Vec<IpAddr>,              // DNS servers to use when connected
}
```

**Networking Explanation:**
- `private_key`: Your secret cryptographic key (never shared, 32 bytes)
- `server_public_key`: Server's public key (used to authenticate server)
- `server_endpoint`: Where to send encrypted UDP packets (e.g., 203.0.113.1:51820)
- `allowed_ips`: CIDR notation for routing (e.g., 0.0.0.0/0 routes all traffic)
- `dns_servers`: DNS resolvers (e.g., 1.1.1.1, 1.0.0.1)

**Tunnel**
```rust
pub struct Tunnel {
    config: TunnelConfig,                      // Connection configuration
    state: Arc<RwLock<TunnelState>>,           // Thread-safe connection state
    wireguard_tunnel: Option<Box<Tunn>>,      // Actual WireGuard instance
}
```

**Networking Explanation:**
- `config`: Stores all connection parameters
- `state`: Tracks if connected/disconnected (thread-safe for async operations)
- `wireguard_tunnel`: The boringtun library's WireGuard implementation

#### Key Methods

**new() - Creates a new tunnel instance**
```rust
pub fn new(config: TunnelConfig) -> Result<Self>
```

**Networking Concept:**
This is the constructor that initializes a tunnel object but does NOT establish a connection yet. Think of it as preparing to make a phone call - you have the number, but haven't dialed yet.

**Rust Implementation:**
- Stores configuration
- Initializes state as Disconnected
- No network I/O occurs

**connect() - Establishes the VPN connection**
```rust
pub async fn connect(&mut self) -> Result<()>
```

**Networking Concept:**
This performs the Noise Protocol handshake with the VPN server:
1. Convert raw key bytes to cryptographic types (StaticSecret, PublicKey)
2. Create WireGuard tunnel instance (initiates handshake)
3. Establish shared secret using X25519 key exchange
4. Update state to Connected

**Handshake Process:**
```
Client                                    Server
  │                                          │
  │  1. Initiation Message                  │
  │  ──────────────────────────────────────►│
  │     • Client ephemeral public key       │
  │     • Encrypted timestamp               │
  │     • MAC (authentication)              │
  │                                          │
  │  2. Response Message                    │
  │  ◄──────────────────────────────────────│
  │     • Server ephemeral public key       │
  │     • Encrypted timestamp               │
  │     • MAC                               │
  │                                          │
  │  3. Shared Secret Established           │
  │  ═══════════════════════════════════════│
  │     • Both parties compute:             │
  │       shared_secret = X25519(          │
  │         my_private,                     │
  │         their_public                    │
  │       )                                 │
  │                                          │
  │  4. Ready to encrypt/decrypt packets     │
```

**Rust Implementation:**
- Uses `boringtun::x25519::StaticSecret` for private key
- Uses `boringtun::x25519::PublicKey` for public key
- Creates `boringtun::noise::Tunn` instance
- Sets keepalive interval (25 seconds to prevent NAT timeout)
- Updates state atomically using RwLock

**disconnect() - Tears down the VPN connection**
```rust
pub async fn disconnect(&mut self) -> Result<()>
```

**Networking Concept:**
Gracefully closes the VPN tunnel:
1. Update state to Disconnected
2. Drop WireGuard tunnel (clears cryptographic state)
3. Securely wipes session keys from memory

**Rust Implementation:**
- Sets state to Disconnected
- Sets `wireguard_tunnel` to None (Rust's Drop trait cleans up)
- No explicit shutdown message needed (WireGuard is stateless)

**encapsulate() - Encrypts outgoing packets**
```rust
pub fn encapsulate(&mut self, packet: &[u8], dst: &mut [u8]) -> Result<usize>
```

**Networking Concept:**
This is the core encryption function. It takes a plain IP packet (from your browser) and produces an encrypted WireGuard packet ready for transmission over UDP.

**Data Flow:**
```
Plain IP Packet (from TUN device)
    ↓
ChaCha20 Encryption (using session key)
    ↓
Add WireGuard Header (16 bytes)
    ↓
Poly1305 Authentication Tag (16 bytes)
    ↓
Encrypted WireGuard Packet
```

**Rust Implementation:**
- Takes plain packet as input
- Writes encrypted packet to destination buffer
- Returns number of bytes written
- Handles boringtun's TunnResult enum:
  - `Done`: No data to send (keepalive only)
  - `Err`: Encryption error
  - `WriteToNetwork`: Encrypted packet ready to send
  - `WriteToTunnelV4/V6`: Decrypted packet (unexpected in encapsulate)

**decapsulate() - Decrypts incoming packets**
```rust
pub fn decapsulate(&mut self, packet: &[u8], dst: &mut [u8]) -> Result<usize>
```

**Networking Concept:**
This is the reverse of encapsulate. It takes an encrypted WireGuard packet (received over UDP from the VPN server) and produces the original plain IP packet.

**Data Flow:**
```
Encrypted WireGuard Packet (from UDP socket)
    ↓
Verify Poly1305 Authentication Tag
    ↓
ChaCha20 Decryption (using session key)
    ↓
Remove WireGuard Header
    ↓
Plain IP Packet (ready for TUN device)
```

**Rust Implementation:**
- Takes encrypted packet as input
- Writes decrypted packet to destination buffer
- Returns number of bytes written
- Handles boringtun's TunnResult enum:
  - `Done`: No data to write (keepalive response)
  - `Err`: Decryption error or authentication failure
  - `WriteToNetwork`: Handshake packet (unexpected in decapsulate)
  - `WriteToTunnelV4/V6`: Decrypted packet ready for TUN device

**generate_keypair() - Generates X25519 keypair**
```rust
pub fn generate_keypair() -> ([u8; 32], [u8; 32])
```

**Networking Concept:**
X25519 is an elliptic curve key exchange algorithm. Each party needs:
- **Private key**: 32 random bytes, never shared
- **Public key**: Derived from private key using elliptic curve multiplication, can be shared

**Key Generation Process:**
```
Random 32 bytes (cryptographically secure)
    ↓
X25519 Private Key (keep secret!)
    ↓
Elliptic Curve Multiplication
    ↓
X25519 Public Key (can share)
```

**Rust Implementation:**
- Uses `StaticSecret::random_from_rng()` with thread_rng
- Derives public key using `PublicKey::from(&private)`
- Returns both as 32-byte arrays
- Private key is NOT wrapped in Zeroizing here (caller's responsibility)

**base64_to_key() - Decodes base64 key**
```rust
pub fn base64_to_key(base64_str: &str) -> Result<[u8; 32]>
```

**Networking Concept:**
WireGuard keys are typically shared in base64 format for human readability. This function converts base64 string to raw 32-byte array.

**Example:**
```
Base64: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
         ↓
Decoded: 32-byte raw key
```

**Rust Implementation:**
- Uses base64 crate's STANDARD engine
- Validates length is exactly 32 bytes
- Returns error if invalid base64 or wrong length

**key_to_base64() - Encodes key to base64**
```rust
pub fn key_to_base64(key: &[u8; 32]) -> String
```

**Networking Concept:**
Converts raw 32-byte key to base64 string for display or storage in config files.

**Rust Implementation:**
- Uses base64 crate's STANDARD engine
- Returns base64-encoded string

### Integration with Other Modules

The Tunnel module integrates with:
- **Platform module**: For TUN device creation (reads packets to encapsulate)
- **Reconnect module**: For automatic reconnection on failure
- **Kill switch**: To block traffic when tunnel is disconnected
- **DNS module**: To configure DNS servers when connected

---

## Kill Switch Module (core/killswitch.rs)

### Overview

The Kill Switch module prevents IP/DNS leaks when the VPN connection drops. It uses platform-specific firewall rules to block all non-VPN traffic, ensuring your real IP address is never exposed.

### Networking Concepts

#### Why Kill Switch is Critical

Without a kill switch, if your VPN disconnects:
1. Your real IP address is exposed to websites
2. Your ISP can see your unencrypted traffic
3. DNS queries leak to your ISP's DNS servers
4. You might not notice the connection dropped

#### Firewall Rules

A firewall controls network traffic by allowing or blocking packets based on rules. The kill switch creates rules that:
- Block all outgoing traffic by default
- Allow traffic through VPN interface only
- Allow local network access (printers, local servers)
- Allow VPN server connection (for reconnection)
- Block IPv6 to prevent leaks

#### Leak Prevention

The kill switch prevents:
- **IP Leak**: Real IP address never exposed
- **DNS Leak**: DNS queries can't bypass VPN
- **IPv6 Leak**: IPv6 traffic blocked or routed through VPN
- **WebRTC Leak**: Local IP discovery blocked

### Rust Implementation Details

#### Key Structures

**KillSwitch**
```rust
pub struct KillSwitch {
    state: KillSwitchState,           // Current state (enabled/disabled)
    vpn_server_ip: Option<IpAddr>,    // VPN server IP (allowed through firewall)
    vpn_interface: Option<String>,    // VPN interface name (e.g., "wg0")
}
```

**Networking Explanation:**
- `state`: Tracks if kill switch is active
- `vpn_server_ip`: Server's IP must be allowed (for reconnection)
- `vpn_interface`: VPN interface must be allowed (for tunnel traffic)

#### Key Methods

**enable() - Activates kill switch**
```rust
pub fn enable(&mut self, vpn_server_ip: IpAddr, vpn_interface: &str) -> Result<()>
```

**Networking Concept:**
This applies firewall rules to block all non-VPN traffic. Should be called BEFORE connecting to VPN to ensure no leaks during connection.

**Linux iptables Rules:**
```bash
# Create custom chain
iptables -N RUSTVPN_OUT

# Allow loopback (local communication)
iptables -A RUSTVPN_OUT -o lo -j ACCEPT

# Allow VPN interface (encrypted tunnel traffic)
iptables -A RUSTVPN_OUT -o wg0 -j ACCEPT

# Allow VPN server (for initial connection/reconnection)
iptables -A RUSTVPN_OUT -d 203.0.113.1 -p udp --dport 51820 -j ACCEPT

# Allow local networks (192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12)
iptables -A RUSTVPN_OUT -d 192.168.0.0/16 -j ACCEPT
iptables -A RUSTVPN_OUT -d 10.0.0.0/8 -j ACCEPT
iptables -A RUSTVPN_OUT -d 172.16.0.0/12 -j ACCEPT

# Drop everything else
iptables -A RUSTVPN_OUT -j DROP

# Insert chain at beginning of OUTPUT chain
iptables -I OUTPUT 1 -j RUSTVPN_OUT
```

**macOS pf Rules:**
```pf
# Block all traffic
block drop all

# Allow VPN interface
pass on utun0

# Allow VPN server
pass out proto udp to 203.0.113.1 port 51820

# Allow local networks
pass to 192.168.0.0/16
pass to 10.0.0.0/8
pass to 172.16.0.0/12
```

**Windows Firewall Rules:**
```cmd
# Block all outbound
netsh advfirewall firewall add rule name=RustVPN-BlockAll dir=out action=block

# Allow VPN server
netsh advfirewall firewall add rule name=RustVPN-AllowServer dir=out action=allow protocol=UDP remoteport=51820 remoteip=203.0.113.1

# Allow local networks
netsh advfirewall firewall add rule name=RustVPN-AllowLocal dir=out action=allow remoteip=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12
```

**Rust Implementation:**
- Stores VPN server IP and interface name
- Calls platform-specific enable function
- Uses conditional compilation (`#[cfg(target_os = "...")]`)
- Updates state to Enabled

**disable() - Deactivates kill switch**
```rust
pub fn disable(&mut self) -> Result<()>
```

**Networking Concept:**
Removes all firewall rules and restores normal network access. Should be called when user manually disconnects from VPN.

**Rust Implementation:**
- Calls platform-specific disable function
- Clears stored VPN server IP and interface
- Updates state to Disabled

**Platform-Specific Implementations:**

**Linux (enable_linux):**
- Uses `std::process::Command` to execute iptables commands
- Creates custom chain "RUSTVPN_OUT"
- Adds rules in order (loopback, VPN interface, VPN server, local networks, drop)
- Inserts chain at beginning of OUTPUT chain
- Blocks IPv6 with ip6tables

**Linux (disable_linux):**
- Removes chain from OUTPUT chain
- Flushes and deletes custom chain
- Restores IPv6 to ACCEPT

**macOS (enable_macos):**
- Creates pf rules file in /tmp
- Writes rules using format! macro
- Loads rules with pfctl -f
- Enables pf with pfctl -e

**macOS (disable_macos):**
- Flushes all pf rules with pfctl -F
- Removes temporary rules file

**Windows (enable_windows):**
- Uses netsh commands (simpler than WFP API)
- Creates block rule for all outbound traffic
- Creates allow rule for VPN server
- Creates allow rule for local networks

**Windows (disable_windows):**
- Deletes all RustVPN firewall rules using netsh

### Integration with Other Modules

The Kill Switch module integrates with:
- **Tunnel module**: Enabled before connecting, disabled after disconnecting
- **GUI module**: User can toggle kill switch on/off
- **Platform module**: Uses platform-specific firewall commands

---

## Reconnect Manager (core/reconnect.rs)

### Overview

The Reconnect Manager handles automatic reconnection when the VPN connection is lost. It implements exponential backoff to avoid hammering the server with constant retry attempts.

### Networking Concepts

#### Why Auto-Reconnect is Important

VPN connections can drop for many reasons:
- **Network changes**: WiFi to cellular, different WiFi network
- **Server maintenance**: VPN server restarts
- **Temporary outages**: Internet goes down briefly
- **NAT timeout**: Router drops idle connection
- **Firewall interference**: Corporate firewall blocks connection

Without auto-reconnect, users would have to manually reconnect every time, leaving gaps where traffic isn't protected.

#### Exponential Backoff Strategy

Exponential backoff increases wait time between retries to:
- Quickly recover from brief outages (1-2 second retry)
- Reduce server load during extended outages
- Prevent battery drain from constant attempts
- Give network time to stabilize

**Backoff Sequence:**
```
Attempt 1: Wait 1 second   (INITIAL_BACKOFF)
Attempt 2: Wait 2 seconds  (1s × 2)
Attempt 3: Wait 4 seconds  (2s × 2)
Attempt 4: Wait 8 seconds  (4s × 2)
Attempt 5: Wait 16 seconds (8s × 2)
Attempt 6+: Wait 30 seconds (capped at MAX_BACKOFF)
```

#### Health Check Loop

Even when connected, we periodically verify the connection is working:
- Runs every 30 seconds
- Can trigger reconnection if health check fails
- Helps detect "zombie" connections (connected but not working)

### Rust Implementation Details

#### Key Structures

**ReconnectManager**
```rust
pub struct ReconnectManager {
    current_backoff: Duration,              // Current wait duration
    consecutive_failures: u32,               // Number of failed attempts
    last_connection_attempt: Option<Instant>, // When last attempt was made
    last_successful_connection: Option<Instant>, // When last success occurred
}
```

**Networking Explanation:**
- `current_backoff`: How long to wait before next retry
- `consecutive_failures`: Count of failed attempts (affects backoff)
- `last_connection_attempt`: Timestamp of last attempt (for timing)
- `last_successful_connection`: Timestamp of last success (for uptime tracking)

#### Key Methods

**wait_before_reconnect() - Waits appropriate backoff duration**
```rust
pub async fn wait_before_reconnect(&mut self, reason: ReconnectReason)
```

**Networking Concept:**
This function implements the exponential backoff logic. On first attempt, it returns immediately. On subsequent attempts, it waits for the current backoff duration.

**Rust Implementation:**
- If no failures yet, returns immediately (no wait)
- If failures occurred, uses tokio::time::sleep to wait
- Logs the backoff duration and attempt number
- Updates last_connection_attempt timestamp

**record_failure() - Records failed connection attempt**
```rust
pub fn record_failure(&mut self)
```

**Networking Concept:**
This updates the backoff state after a failed connection attempt. It doubles the backoff duration (up to MAX_BACKOFF) to implement exponential backoff.

**Rust Implementation:**
- Increments consecutive_failures counter
- Doubles current_backoff (capped at 30 seconds)
- Logs failure count and next backoff duration

**record_success() - Records successful connection**
```rust
pub fn record_success(&mut self)
```

**Networking Concept:**
This resets the backoff state after a successful connection. The next failure will start from 1 second backoff again.

**Rust Implementation:**
- Logs success if there were previous failures
- Resets consecutive_failures to 0
- Resets current_backoff to INITIAL_BACKOFF (1 second)
- Updates last_successful_connection timestamp

**should_attempt_reconnect() - Checks if ready to retry**
```rust
pub fn should_attempt_reconnect(&self) -> bool
```

**Networking Concept:**
This checks if enough time has passed since the last attempt to try reconnecting again.

**Rust Implementation:**
- If no previous attempt, returns true (ready now)
- If previous attempt, checks if elapsed time >= current_backoff
- Returns true if ready, false if still in backoff period

**health_check_loop() - Runs periodic health checks**
```rust
pub async fn health_check_loop<F, Fut>(
    mut check_fn: F,
    mut should_stop: tokio::sync::watch::Receiver<bool>,
)
```

**Networking Concept:**
This runs a background loop that periodically checks if the VPN connection is healthy. If the check fails, it logs a warning (caller should trigger reconnection).

**Health Check Process:**
```
Start loop
    ↓
Wait 30 seconds
    ↓
Run health check function
    ↓
Is healthy?
    ├─ Yes: Continue loop
    └─ No: Log warning, continue loop
    ↓
Check stop signal
    ├─ Stop requested: Exit loop
    └─ Continue: Repeat
```

**Rust Implementation:**
- Uses tokio::select! for concurrent operations
- Sleeps for HEALTH_CHECK_INTERVAL (30 seconds)
- Calls check_fn() to perform health check
- Watches should_stop channel for shutdown signal
- Logs warning if health check fails

### Integration with Other Modules

The Reconnect Manager integrates with:
- **Tunnel module**: Monitors tunnel state, triggers reconnection on failure
- **GUI module**: Displays reconnection status to user
- **Kill switch**: Ensures kill switch remains active during reconnection

---

## DNS Module (dns/)

### Overview

The DNS module handles DNS resolution and filtering. It intercepts DNS queries, filters them against blocklists, and uses DNS-over-HTTPS/TLS for encrypted DNS queries.

### Networking Concepts

#### DNS (Domain Name System)

DNS translates human-readable domain names to IP addresses:
```
example.com ──► DNS Query ──► 93.184.216.34
```

#### DNS Leak Problem

Without DNS protection, DNS queries might bypass the VPN:
```
Your Device
    │
    ├─► DNS Query ──► ISP DNS Server (LEAK!)
    │                   Can see which websites you visit
    │
    └─► VPN Tunnel ──► VPN DNS Server (Protected)
```

#### DNS Filtering

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

#### DNS-over-HTTPS (DoH)

Encrypts DNS queries using HTTPS:
```
Normal DNS:
Your Device ──► Clear text DNS query ──► DNS Server
(Anyone can see what you're querying)

DNS-over-HTTPS:
Your Device ──► Encrypted HTTPS ──► DNS Server
(ISP cannot see DNS queries)
```

### Rust Implementation Details

#### Current Status

The DNS module is currently a stub implementation. The structures exist but are not yet implemented.

**Planned Implementation:**
- `DnsFilter`: Load and manage blocklists (ads, malware, trackers)
- `DnsResolver`: Implement DNS-over-HTTPS/TLS client

#### Future Implementation

**DnsFilter will:**
- Load blocklists from files or URLs
- Parse domain lists
- Check domain queries against blocklist
- Return blocked/allowed status

**DnsResolver will:**
- Use hickory-resolver crate
- Configure DoH/DoT servers (Cloudflare, Google, etc.)
- Encrypt DNS queries
- Cache responses for performance

### Integration with Other Modules

The DNS module will integrate with:
- **Tunnel module**: Configure DNS servers when VPN connects
- **Platform module**: Set system DNS resolver to use VPN's DNS
- **GUI module**: Allow user to toggle DNS filtering

---

## GUI Module (gui/app.rs)

### Overview

The GUI module provides a user interface using GTK4. It displays connection status, allows server selection, and provides settings toggles for kill switch, auto-reconnect, and DNS filtering.

### Networking Concepts

The GUI itself doesn't directly handle networking, but it:
- Displays VPN connection state (Connected/Disconnected/Connecting)
- Shows server information (IP, location)
- Allows user to control networking features (kill switch, etc.)
- Displays uptime and connection statistics

### Rust Implementation Details

#### Key Structures

**VpnApp**
```rust
pub struct VpnApp {
    pub connection_state: Rc<RefCell<ConnectionState>>,
    pub kill_switch_enabled: Rc<RefCell<bool>>,
    pub auto_reconnect_enabled: Rc<RefCell<bool>>,
    pub dns_filtering_enabled: Rc<RefCell<bool>>,
}
```

**Networking Explanation:**
- `connection_state`: Tracks VPN connection status
- `kill_switch_enabled`: User preference for kill switch
- `auto_reconnect_enabled`: User preference for auto-reconnect
- `dns_filtering_enabled`: User preference for DNS filtering

#### Key Methods

**build_ui() - Constructs the GTK4 interface**
```rust
pub fn build_ui(app: &Application)
```

**GUI Components:**
- Title label ("RustVPN")
- Status label (Current connection state)
- Server info label (Selected server)
- IP label (Current VPN IP)
- Uptime label (Connection duration)
- Connect/Disconnect button
- Server selection dropdown
- Settings checkboxes (Kill switch, Auto-reconnect, DNS filtering)

**run() - Starts the GTK4 application**
```rust
pub fn run()
```

**Rust Implementation:**
- Creates GTK4 Application
- Sets application ID (com.rustvpn.app)
- Connects activate signal to build_ui
- Runs the GTK main loop

### Integration with Other Modules

The GUI module will integrate with:
- **Tunnel module**: Call connect()/disconnect() on button click
- **Kill switch**: Enable/disable based on checkbox
- **Reconnect manager**: Display reconnection status
- **Server module**: Populate server dropdown

---

## Platform Module (platform/)

### Overview

The Platform module contains OS-specific code for creating TUN devices and configuring network interfaces. Different operating systems have different APIs for network management.

### Networking Concepts

#### TUN Device Creation

A TUN device is a virtual network interface that operates at Layer 3 (Network layer). It allows user-space programs to intercept IP packets.

**Linux TUN Device:**
- Device name: tun0, tun1, tun2, etc.
- Requires: root or CAP_NET_ADMIN capability
- Configuration: ip command (iproute2)

**macOS TUN Device:**
- Device name: utun0, utun1, utun2, etc.
- Requires: root privileges
- Configuration: ifconfig and route commands

**Windows TUN Device:**
- Device name: WireGuard tunnel interface
- Requires: Administrator privileges
- Configuration: WinTun driver or netsh

### Rust Implementation Details

#### Current Status

The Platform module is currently a stub implementation. The structures exist but are not yet implemented.

**Planned Implementation:**
- `LinuxPlatform`: Create and configure Linux TUN devices
- `MacOSPlatform`: Create and configure macOS utun devices
- `WindowsPlatform`: Create and configure Windows TUN devices

#### Future Implementation

**LinuxPlatform will:**
- Use tun crate to create TUN device
- Assign IP address using ip command
- Configure routing tables
- Set MTU (typically 1420 for WireGuard)

**MacOSPlatform will:**
- Use tun crate for utun devices
- Assign IP address using ifconfig
- Configure routing using route command
- Handle macOS-specific networking

**WindowsPlatform will:**
- Use WinTun driver for TUN device
- Configure using Windows API (netsh or Win32 API)
- Handle Windows-specific networking

### Integration with Other Modules

The Platform module will integrate with:
- **Tunnel module**: Provide TUN device for packet I/O
- **Kill switch**: Execute platform-specific firewall commands
- **DNS module**: Configure system DNS resolver

---

## Configuration Module (config.rs)

### Overview

The Configuration module manages user preferences and application settings. It handles loading and saving configuration to disk.

### Networking Concepts

Configuration doesn't directly handle networking, but it stores:
- User preferences (kill switch enabled/disabled)
- Last selected server
- Auto-connect on startup
- DNS filtering preference

### Rust Implementation Details

#### Key Structures

**VpnConfig**
```rust
pub struct VpnConfig {
    pub auto_connect: bool,                 // Auto-connect on startup
    pub kill_switch_enabled: bool,           // Kill switch preference
    pub dns_filtering_enabled: bool,         // DNS filtering preference
    pub selected_server: Option<String>,    // Last selected server ID
}
```

#### Key Methods

**load() - Loads configuration from disk**
```rust
pub fn load() -> Result<Self>
```

**Current Implementation:**
Returns default configuration (not yet loading from file)

**Planned Implementation:**
- Read from platform-specific config location:
  - Linux: ~/.config/rustvpn/config.toml
  - macOS: ~/Library/Application Support/RustVPN/config.toml
  - Windows: %APPDATA%\RustVPN\config.toml
- Parse TOML file using serde
- Return VpnConfig struct

**save() - Saves configuration to disk**
```rust
pub fn save(&self) -> Result<()>
```

**Current Implementation:**
Does nothing (stub)

**Planned Implementation:**
- Serialize VpnConfig to TOML using serde
- Write to platform-specific config location
- Set appropriate file permissions (read/write for owner only)

### Integration with Other Modules

The Configuration module integrates with:
- **GUI module**: Load settings on startup, save on change
- **Tunnel module**: Use configured server and preferences
- **All modules**: Read user preferences

---

## Server Module (server.rs)

### Overview

The Server module manages VPN server selection and configuration. It stores server information (IP, public key, location) and provides logic for selecting the best server.

### Networking Concepts

#### Server Selection

VPN servers are located around the world. Users select servers based on:
- Geographic location (closer = lower latency)
- Server load (less load = better performance)
- Privacy jurisdiction (some countries have better privacy laws)

#### Server Information

Each server needs:
- **IP address**: Where to connect (UDP endpoint)
- **Public key**: Server's X25519 public key for authentication
- **Location**: City, country, state for display
- **Load**: Current server load percentage (for selection)

### Rust Implementation Details

#### Key Structures

**Server**
```rust
pub struct Server {
    pub id: String,           // Unique server identifier
    pub name: String,         // Display name (e.g., "US-California-1")
    pub country: String,      // Country code (e.g., "US")
    pub state: Option<String>, // State (e.g., "California")
    pub endpoint: String,     // IP:port (e.g., "203.0.113.1:51820")
    pub public_key: String,    // Base64-encoded public key
}
```

**ServerManager**
```rust
pub struct ServerManager {
    servers: Vec<Server>,      // List of available servers
}
```

#### Key Methods

**new() - Creates server manager**
```rust
pub fn new() -> Result<Self>
```

**Current Implementation:**
Creates empty server list (not yet loading from file)

**Planned Implementation:**
- Load servers from configuration file (TOML/JSON)
- Parse server list
- Return ServerManager with populated list

**get_servers() - Returns list of servers**
```rust
pub fn get_servers(&self) -> &[Server]
```

**Networking Explanation:**
Returns reference to server list for GUI to display.

**select_best_server() - Selects optimal server**
```rust
pub fn select_best_server(&self) -> Option<&Server>
```

**Current Implementation:**
Returns first server (not yet implementing selection logic)

**Planned Implementation:**
- Ping all servers to measure latency
- Check server load
- Select server with lowest latency and acceptable load
- Fallback to random server if all unavailable

### Integration with Other Modules

The Server module integrates with:
- **Tunnel module**: Provide server endpoint and public key
- **GUI module**: Populate server dropdown
- **Configuration module**: Save/restore selected server

---

## Update Module (update.rs)

### Overview

The Update module checks for application updates from GitHub releases. It notifies users when a new version is available.

### Networking Concepts

The Update module uses HTTP to:
- Fetch GitHub releases API
- Compare current version with latest release
- Download update if available

### Rust Implementation Details

#### Key Structures

**UpdateChecker**
```rust
pub struct UpdateChecker {
    current_version: String,   // Current application version
}
```

#### Key Methods

**new() - Creates update checker**
```rust
pub fn new(version: String) -> Self
```

**current_version() - Returns current version**
```rust
pub fn current_version(&self) -> &str
```

**check_for_updates() - Checks for new version**
```rust
pub async fn check_for_updates(&self) -> Result<Option<String>>
```

**Current Implementation:**
Returns None (no update available)

**Planned Implementation:**
- Fetch GitHub releases API
- Parse JSON response
- Compare version numbers
- Return latest version if newer

### Integration with Other Modules

The Update module integrates with:
- **GUI module**: Display update notification to user
- **Main module**: Run update check on startup

---

## Main Entry Point (main.rs)

### Overview

The main.rs file is the application entry point. It initializes logging and starts the GTK4 GUI application.

### Networking Concepts

main.rs doesn't directly handle networking, but it:
- Initializes logging for network operations
- Starts the GUI which controls networking components

### Rust Implementation Details

#### Code Structure

```rust
use rust_vpn::gui::app::VpnApp;

fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Run the GTK4 GUI application
    VpnApp::run();
}
```

**Logging:**
- Uses tracing-subscriber for structured logging
- Logs network operations (connections, errors, etc.)
- Helps debug networking issues

**GUI Startup:**
- Creates GTK4 application
- Runs main event loop
- Handles user interaction

### Integration with Other Modules

The main module integrates with:
- **GUI module**: Starts the user interface
- **All modules**: Logging initialized for all components

---

## Summary: Complete Data Flow

### Application Startup
```
main.rs
    ↓
Initialize logging
    ↓
Start GUI (gui/app.rs)
    ↓
Load configuration (config.rs)
    ↓
Load server list (server.rs)
```

### User Clicks Connect
```
GUI button click
    ↓
Enable kill switch (core/killswitch.rs)
    ↓
Create TUN device (platform/linux.rs)
    ↓
Configure routing (platform/linux.rs)
    ↓
Connect tunnel (core/tunnel.rs::connect)
    ↓
Perform Noise Protocol handshake
    ↓
Establish shared secret
    ↓
Update GUI state to Connected
```

### Outgoing Packet Flow
```
Application (browser)
    ↓
Create IP packet
    ↓
OS routing table → TUN device
    ↓
RustVPN reads from TUN device
    ↓
Encapsulate (core/tunnel.rs::encapsulate)
    ↓
ChaCha20-Poly1305 encryption
    ↓
Send over UDP socket
    ↓
VPN server receives
    ↓
Decrypt and forward to destination
```

### Incoming Packet Flow
```
Website sends response to VPN server
    ↓
VPN server encrypts
    ↓
Send over UDP to client
    ↓
RustVPN receives on UDP socket
    ↓
Decapsulate (core/tunnel.rs::decapsulate)
    ↓
Verify Poly1305 tag
    ↓
ChaCha20 decryption
    ↓
Write to TUN device
    ↓
OS delivers to application
```

### Connection Lost
```
Health check fails (core/reconnect.rs)
    ↓
Update state to Reconnecting
    ↓
Wait backoff duration (exponential)
    ↓
Attempt reconnection
    ↓
If success: Record success, reset backoff
    ↓
If failure: Record failure, increase backoff
    ↓
Repeat until success or user disconnects
```

### User Clicks Disconnect
```
GUI button click
    ↓
Disconnect tunnel (core/tunnel.rs::disconnect)
    ↓
Clear cryptographic state
    ↓
Disable kill switch (core/killswitch.rs)
    ↓
Remove firewall rules
    ↓
Destroy TUN device (platform/linux.rs)
    ↓
Restore routing
    ↓
Update GUI state to Disconnected
```

---

**Last Updated**: April 14, 2026
**Version**: 0.1.0
