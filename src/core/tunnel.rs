//! # WireGuard Tunnel Module
//!
//! This module implements the core VPN tunnel functionality using the WireGuard protocol.
//!
//! ## How VPNs Work - Data Flow Overview
//!
//! ```text
//! ┌─────────────┐                                      ┌─────────────┐
//! │   Your App  │                                      │   Website   │
//! │ (Browser)   │                                      │   Server    │
//! └──────┬──────┘                                      └──────▲──────┘
//!        │                                                    │
//!        │ 1. Plain HTTP/HTTPS request                       │
//!        ▼                                                    │
//! ┌─────────────────────────────────────────────────────┐    │
//! │           TUN Virtual Network Interface             │    │
//! │  (Intercepts all outgoing traffic from your apps)   │    │
//! └──────┬──────────────────────────────────────────────┘    │
//!        │                                                    │
//!        │ 2. Packet captured by TUN device                  │
//!        ▼                                                    │
//! ┌─────────────────────────────────────────────────────┐    │
//! │              WireGuard Encapsulation                │    │
//! │  - Encrypts packet with ChaCha20-Poly1305          │    │
//! │  - Adds WireGuard header                            │    │
//! │  - Uses your private key + server's public key      │    │
//! └──────┬──────────────────────────────────────────────┘    │
//!        │                                                    │
//!        │ 3. Encrypted WireGuard packet                     │
//!        ▼                                                    │
//! ┌─────────────────────────────────────────────────────┐    │
//! │              UDP Socket (Port 51820)                │    │
//! │  Sends encrypted packet over internet               │    │
//! └──────┬──────────────────────────────────────────────┘    │
//!        │                                                    │
//!        │ 4. Encrypted packet travels over internet         │
//!        ▼                                                    │
//! ┌─────────────────────────────────────────────────────┐    │
//! │              VPN Server (WireGuard)                 │    │
//! │  - Receives encrypted packet                        │    │
//! │  - Decrypts using server private key                │    │
//! │  - Extracts original packet                         │    │
//! └──────┬──────────────────────────────────────────────┘    │
//!        │                                                    │
//!        │ 5. Decrypted packet forwarded to destination      │
//!        └────────────────────────────────────────────────────┘
//!                                                             │
//!        ┌────────────────────────────────────────────────────┘
//!        │ 6. Response comes back (reverse flow)
//!        ▼
//! ```
//!
//! ## WireGuard Protocol Specifics
//!
//! WireGuard uses:
//! - **Curve25519** for key exchange (X25519)
//! - **ChaCha20** for symmetric encryption
//! - **Poly1305** for authentication
//! - **BLAKE2s** for hashing
//! - **UDP** as transport protocol
//!
//! ### Key Exchange (Noise Protocol Framework)
//! 1. Client has: Private key (secret), Public key (derived from private)
//! 2. Server has: Private key (secret), Public key (shared with clients)
//! 3. Handshake establishes shared secret for session encryption
//! 4. Keys are rotated periodically for forward secrecy
//!
//! ### Packet Structure
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │  WireGuard Header (16 bytes)                     │
//! │  - Message type (4 bytes)                        │
//! │  - Receiver index (4 bytes)                      │
//! │  - Counter (8 bytes)                             │
//! ├──────────────────────────────────────────────────┤
//! │  Encrypted Payload                               │
//! │  - Original IP packet (encrypted)                │
//! │  - Authentication tag (16 bytes)                 │
//! └──────────────────────────────────────────────────┘
//! ```
//!
//! ## This Module's Role
//!
//! The `Tunnel` struct manages:
//! - Creating WireGuard tunnel instances
//! - Encrypting outgoing packets (encapsulation)
//! - Decrypting incoming packets (decapsulation)
//! - Managing connection state
//! - Handling keepalive messages
//!
//! ## Example Usage (Future Integration)
//!
//! ```rust,ignore
//! // 1. Create tunnel configuration
//! let config = TunnelConfig {
//!     private_key: Zeroizing::new(client_private_key),
//!     server_public_key: server_public_key,
//!     server_endpoint: "vpn.example.com:51820".parse()?,
//!     allowed_ips: vec![("0.0.0.0".parse()?, 0)], // Route all traffic
//!     dns_servers: vec!["1.1.1.1".parse()?],
//! };
//!
//! // 2. Create and connect tunnel
//! let mut tunnel = Tunnel::new(config)?;
//! tunnel.connect().await?;
//!
//! // 3. In packet processing loop:
//! loop {
//!     // Read packet from TUN device
//!     let packet = tun_device.read().await?;
//!     
//!     // Encrypt and send
//!     let mut encrypted = vec![0u8; packet.len() + 32];
//!     let len = tunnel.encapsulate(&packet, &mut encrypted)?;
//!     udp_socket.send(&encrypted[..len]).await?;
//!     
//!     // Receive and decrypt
//!     let encrypted = udp_socket.recv().await?;
//!     let mut decrypted = vec![0u8; encrypted.len()];
//!     let len = tunnel.decapsulate(&encrypted, &mut decrypted)?;
//!     tun_device.write(&decrypted[..len]).await?;
//! }
//! ```

use anyhow::{Context, Result};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

/// WireGuard keepalive interval in seconds (prevents NAT timeout)
const KEEPALIVE_INTERVAL: u16 = 25;


/// Configuration for establishing a WireGuard tunnel.
///
/// This contains all the necessary information to create a secure
/// connection to a VPN server.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// Client's private key (32 bytes, X25519)
    /// Wrapped in Zeroizing to securely wipe from memory when dropped
    pub private_key: Zeroizing<[u8; 32]>,
    
    /// Server's public key (32 bytes, X25519)
    /// Used to authenticate the server and establish shared secret
    pub server_public_key: [u8; 32],
    
    /// Server's endpoint (IP:Port)
    /// Where to send encrypted UDP packets
    pub server_endpoint: SocketAddr,
    
    /// IP ranges to route through the VPN (CIDR notation)
    /// Example: ("0.0.0.0", 0) routes all IPv4 traffic
    /// Example: ("10.0.0.0", 8) routes only 10.0.0.0/8
    pub allowed_ips: Vec<(IpAddr, u8)>,
    
    /// DNS servers to use when connected
    /// These will handle DNS resolution for VPN traffic
    pub dns_servers: Vec<IpAddr>,
}

/// Current state of the VPN tunnel connection.
///
/// State transitions:
/// ```text
/// Disconnected -> Connecting -> Connected
///      ▲              │              │
///      │              ▼              ▼
///      └──────────── Error ◄─── Reconnecting
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// No active connection
    Disconnected,
    
    /// Attempting to establish connection
    Connecting,
    
    /// Active VPN tunnel, traffic is encrypted
    Connected,
    
    /// Connection lost, attempting to reconnect
    Reconnecting,
    
    /// Fatal error occurred
    Error,
}

/// Main WireGuard tunnel manager.
///
/// Handles encryption/decryption of packets and connection state management.
/// This is the core component that makes the VPN work.
pub struct Tunnel {
    /// Tunnel configuration (keys, server, etc.)
    config: TunnelConfig,
    
    /// Current connection state (thread-safe)
    state: Arc<RwLock<TunnelState>>,
    
    /// The actual WireGuard tunnel instance from boringtun
    /// None when disconnected, Some when connected
    wireguard_tunnel: Option<Box<Tunn>>,
}

impl Tunnel {
    /// Creates a new tunnel instance with the given configuration.
    ///
    /// This does NOT establish a connection yet. Call `connect()` to actually
    /// initiate the VPN tunnel.
    ///
    /// # Arguments
    /// * `config` - Tunnel configuration with keys and server details
    ///
    /// # Returns
    /// A new `Tunnel` instance in `Disconnected` state
    pub fn new(config: TunnelConfig) -> Result<Self> {
        info!("Creating new WireGuard tunnel");
        
        Ok(Self {
            config,
            state: Arc::new(RwLock::new(TunnelState::Disconnected)),
            wireguard_tunnel: None,
        })
    }

    /// Establishes the WireGuard tunnel connection.
    ///
    /// This performs the Noise protocol handshake with the server:
    /// 1. Converts keys to proper cryptographic types
    /// 2. Creates WireGuard tunnel instance (initiates handshake)
    /// 3. Updates state to Connected
    ///
    /// After this succeeds, you can call `encapsulate()` and `decapsulate()`
    /// to encrypt/decrypt packets.
    ///
    /// # Returns
    /// * `Ok(())` - Connection established successfully
    /// * `Err(_)` - Failed to establish connection
    ///
    /// # Example Flow
    /// ```text
    /// 1. State: Disconnected -> Connecting
    /// 2. Create WireGuard tunnel (performs handshake)
    /// 3. State: Connecting -> Connected
    /// 4. Ready to encrypt/decrypt packets
    /// ```
    pub async fn connect(&mut self) -> Result<()> {
        info!("Initiating tunnel connection to {:?}", self.config.server_endpoint);
        
        let mut state = self.state.write().await;
        *state = TunnelState::Connecting;
        drop(state);

        // Convert raw bytes to cryptographic key types
        let private_key = StaticSecret::from(*self.config.private_key);
        let public_key = PublicKey::from(self.config.server_public_key);
        
        // Create WireGuard tunnel with Noise protocol
        // This initiates the cryptographic handshake
        let tunn = Tunn::new(
            private_key,
            public_key,
            None,                      // No preshared key
            Some(KEEPALIVE_INTERVAL),  // Send keepalive every 25s
            0,                         // Index (managed by boringtun)
            None,                      // No rate limiter
        )
        .map_err(|e| anyhow::anyhow!("Failed to create WireGuard tunnel: {}", e))?;
        
        self.wireguard_tunnel = Some(Box::new(tunn));

        let mut state = self.state.write().await;
        *state = TunnelState::Connected;
        drop(state);

        info!("Tunnel connected successfully");
        Ok(())
    }

    /// Tears down the VPN tunnel connection.
    ///
    /// This:
    /// 1. Updates state to Disconnected
    /// 2. Drops the WireGuard tunnel (cleans up crypto state)
    ///
    /// After this, no more packets can be encrypted/decrypted until
    /// `connect()` is called again.
    pub async fn disconnect(&mut self) -> Result<()> {
        info!("Disconnecting tunnel");
        
        let mut state = self.state.write().await;
        *state = TunnelState::Disconnected;
        drop(state);

        // Dropping the tunnel cleans up all cryptographic state
        self.wireguard_tunnel = None;
        
        info!("Tunnel disconnected");
        Ok(())
    }

    /// Gets the current tunnel state.
    pub async fn get_state(&self) -> TunnelState {
        *self.state.read().await
    }

    /// Updates the tunnel state.
    pub async fn set_state(&self, new_state: TunnelState) {
        let mut state = self.state.write().await;
        if *state != new_state {
            debug!("Tunnel state changed: {:?} -> {:?}", *state, new_state);
            *state = new_state;
        }
    }

    /// Checks if the tunnel is currently connected.
    pub fn is_connected(&self) -> bool {
        self.wireguard_tunnel.is_some()
    }

    /// Encrypts an outgoing packet for transmission over the VPN.
    ///
    /// This is called when a packet is read from the TUN device (your app's traffic).
    /// The packet is encrypted and wrapped in a WireGuard header, ready to be sent
    /// over UDP to the VPN server.
    ///
    /// # Data Flow
    /// ```text
    /// Plain packet -> [Encrypt with ChaCha20-Poly1305] -> Encrypted packet
    ///                 [Add WireGuard header]
    ///                 [Add authentication tag]
    /// ```
    ///
    /// # Arguments
    /// * `packet` - The plain IP packet to encrypt
    /// * `dst` - Buffer to write encrypted packet to (must be large enough)
    ///
    /// # Returns
    /// Number of bytes written to `dst` (the encrypted packet size)
    ///
    /// # Example
    /// ```rust,ignore
    /// let plain_packet = tun.read().await?;  // Read from TUN device
    /// let mut encrypted = vec![0u8; plain_packet.len() + 32];
    /// let len = tunnel.encapsulate(&plain_packet, &mut encrypted)?;
    /// udp_socket.send(&encrypted[..len]).await?;  // Send over internet
    /// ```
    pub fn encapsulate(&mut self, packet: &[u8], dst: &mut [u8]) -> Result<usize> {
        let tunn = self.wireguard_tunnel.as_mut()
            .context("Tunnel not initialized")?;

        match tunn.encapsulate(packet, dst) {
            TunnResult::Done => Ok(0),
            TunnResult::Err(e) => {
                error!("Encapsulation error: {:?}", e);
                anyhow::bail!("Encapsulation failed: {:?}", e)
            }
            TunnResult::WriteToNetwork(data) => {
                debug!("Encapsulated {} bytes", data.len());
                Ok(data.len())
            }
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                warn!("Unexpected tunnel write during encapsulation");
                Ok(0)
            }
        }
    }

    /// Decrypts an incoming packet received from the VPN server.
    ///
    /// This is called when an encrypted packet is received over UDP from the server.
    /// The packet is decrypted and the original IP packet is extracted, ready to be
    /// written to the TUN device (delivered to your apps).
    ///
    /// # Data Flow
    /// ```text
    /// Encrypted packet -> [Verify authentication tag]
    ///                     [Decrypt with ChaCha20-Poly1305]
    ///                     [Remove WireGuard header]
    ///                  -> Plain packet
    /// ```
    ///
    /// # Arguments
    /// * `packet` - The encrypted WireGuard packet
    /// * `dst` - Buffer to write decrypted packet to
    ///
    /// # Returns
    /// Number of bytes written to `dst` (the decrypted packet size)
    ///
    /// # Example
    /// ```rust,ignore
    /// let encrypted = udp_socket.recv().await?;  // Receive from internet
    /// let mut plain = vec![0u8; encrypted.len()];
    /// let len = tunnel.decapsulate(&encrypted, &mut plain)?;
    /// tun.write(&plain[..len]).await?;  // Write to TUN device
    /// ```
    pub fn decapsulate(&mut self, packet: &[u8], dst: &mut [u8]) -> Result<usize> {
        let tunn = self.wireguard_tunnel.as_mut()
            .context("Tunnel not initialized")?;

        match tunn.decapsulate(None, packet, dst) {
            TunnResult::Done => Ok(0),
            TunnResult::Err(e) => {
                error!("Decapsulation error: {:?}", e);
                anyhow::bail!("Decapsulation failed: {:?}", e)
            }
            TunnResult::WriteToNetwork(_) => {
                warn!("Unexpected network write during decapsulation");
                Ok(0)
            }
            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                debug!("Decapsulated {} bytes", data.len());
                Ok(data.len())
            }
        }
    }

    /// Returns a reference to the tunnel configuration.
    pub fn get_config(&self) -> &TunnelConfig {
        &self.config
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        if self.wireguard_tunnel.is_some() {
            warn!("Tunnel dropped while still connected");
        }
    }
}

/// Generates a new X25519 keypair for WireGuard.
///
/// This creates a cryptographically secure random private key and derives
/// the corresponding public key.
///
/// # Returns
/// A tuple of `(private_key, public_key)` as 32-byte arrays
///
/// # Security
/// - The private key is generated using a cryptographically secure RNG
/// - The public key is mathematically derived from the private key
/// - Store the private key securely and never share it
/// - The public key can be shared with VPN servers
///
/// # Example
/// ```rust,ignore
/// let (private_key, public_key) = generate_keypair();
/// println!("Your public key: {}", key_to_base64(&public_key));
/// // Share public_key with VPN server, keep private_key secret
/// ```
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    use boringtun::x25519::{PublicKey, StaticSecret};
    
    let private = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&private);
    
    (private.to_bytes(), public.to_bytes())
}

/// Converts a base64-encoded key to its raw 32-byte representation.
/// Returns an error if the base64 is invalid or the decoded length is not 32 bytes.
///
/// # Arguments
///
/// * `b64` - Base64-encoded key string
///
/// # Returns
///
/// * `Ok([u8; 32])` - The decoded 32-byte key
/// * `Err(_)` - If the string is not valid base64 or not 32 bytes
///
/// # Example
/// ```rust,ignore
/// let key = base64_to_key("YourBase64KeyHere==")?;
/// ```
pub fn base64_to_key(b64: &str) -> Result<[u8; 32]> {
    use base64::{Engine as _, engine::general_purpose};
    
    let decoded = general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| anyhow::anyhow!("Invalid base64 encoding: {}", e))?;
    
    if decoded.len() != 32 {
        anyhow::bail!("Key must be exactly 32 bytes");
    }
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// Converts a 32-byte key to a base64-encoded string.
///
/// This is useful for displaying keys to users or storing them in
/// configuration files.
///
/// # Arguments
/// * `key` - The 32-byte key to encode
///
/// # Returns
/// Base64-encoded string representation of the key
///
/// # Example
/// ```rust,ignore
/// let (private_key, public_key) = generate_keypair();
/// println!("Public key: {}", key_to_base64(&public_key));
/// ```
pub fn key_to_base64(key: &[u8; 32]) -> String {
    use base64::{Engine as _, engine::general_purpose};
    general_purpose::STANDARD.encode(key)
}
