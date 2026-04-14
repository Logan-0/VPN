//! # VPN Server Management Module
//!
//! This module manages VPN server information, selection, and configuration.
//! It stores server details such as location, endpoint, and cryptographic keys.
//!
//! ## Networking Concepts
//!
/// VPN Server Selection
///
/// VPN servers are located around the world in different geographic regions.
/// Server selection affects:
///
/// - **Latency**: Closer servers have lower latency (faster response times)
/// - **Jurisdiction**: Different countries have different privacy laws
/// - **Performance**: Server load affects connection quality
/// - **Content Access**: Some content is geo-restricted to certain regions
///
/// Server Information Required
///
/// Each VPN server needs:
///
/// 1. **Endpoint**: IP address and UDP port where WireGuard listens
///    - Example: "203.0.113.1:51820"
///    - This is where encrypted packets are sent
///
/// 2. **Public Key**: Server's X25519 public key for authentication
///    - Used in Noise Protocol handshake
///    - Verifies server identity
///    - Establishes shared secret
///
/// 3. **Location**: Geographic information for display
///    - Country: e.g., "US", "SE"
///    - State: e.g., "California"
///    - City: e.g., "Los Angeles"
///
/// 4. **Load**: Current server load percentage (future implementation)
///    - Helps select least busy server
///    - Affects connection quality

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Server configuration file format for TOML parsing
#[derive(Debug, Deserialize)]
struct ServerConfig {
    servers: Vec<Server>,
}

/// VPN Server Configuration
///
/// Contains all information needed to connect to a specific VPN server.
/// This includes the server's network endpoint, cryptographic public key,
/// and geographic location information.
///
/// ## Networking Relevance
///
/// - `server_identifier`: Unique ID for referencing the server in configuration
/// - `server_display_name`: Human-readable name shown in GUI
/// - `server_country_code`: ISO country code (affects jurisdiction and latency)
/// - `server_state_name`: State/region for more precise location
/// - `server_endpoint_address`: IP:port where WireGuard UDP traffic is sent
/// - `server_public_key_base64`: X25519 public key for cryptographic authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    /// Unique identifier for this server
    /// 
    /// Used internally to reference this server in configuration files
    /// and user preferences. Format: "country-city-number" (e.g., "us-california-1")
    pub server_identifier: String,
    
    /// Human-readable display name for the server
    /// 
    /// This is shown to the user in the GUI server selection dropdown.
    /// Example: "US-California-1" or "Sweden-Stockholm-1"
    pub server_display_name: String,
    
    /// ISO 3166-1 alpha-2 country code
    /// 
    /// Two-letter country code indicating where the server is located.
    /// Examples: "US" (United States), "SE" (Sweden), "DE" (Germany)
    /// 
    /// This affects:
    /// - Jurisdiction (privacy laws)
    /// - Latency (distance from user)
    /// - Content access (geo-restrictions)
    pub server_country_code: String,
    
    /// State or region name (optional)
    /// 
    /// Provides more precise location information within the country.
    /// Examples: "California", "Stockholm" (for cities)
    /// 
    /// None for countries where state/region is not applicable or unknown.
    pub server_state_name: Option<String>,
    
    /// Network endpoint for WireGuard connection
    /// 
    /// The IP address and UDP port where this VPN server accepts WireGuard connections.
    /// Format: "IP_ADDRESS:PORT" (e.g., "203.0.113.1:51820")
    /// 
    /// WireGuard uses UDP port 51820 by default. All encrypted VPN traffic
    /// is sent to this endpoint.
    /// 
    /// ## Networking Details
    /// 
    /// - Protocol: UDP (User Datagram Protocol)
    /// - Port: 51820 (WireGuard standard)
    /// - Transport: Encrypted WireGuard packets
    pub server_endpoint_address: String,
    
    /// Server's X25519 public key in base64 encoding
    /// 
    /// The public key used in the Noise Protocol handshake to authenticate
    /// the server and establish a shared secret for encryption.
    /// 
    /// ## Cryptography Details
    /// 
    /// - Algorithm: X25519 (elliptic curve Diffie-Hellman)
    /// - Key size: 32 bytes (256 bits)
    /// - Encoding: Base64 for human readability
    /// - Usage: Server authentication and key exchange
    /// 
    /// ## Handshake Process
    /// 
    /// During connection:
    /// 1. Client has its own private/public keypair
    /// 2. Client sends its public key to server
    /// 3. Server responds with its public key
    /// 4. Both parties compute shared secret: X25519(my_private, their_public)
    /// 5. Shared secret used for symmetric encryption (ChaCha20)
    /// 
    /// ## Security
    /// 
    /// The public key can be shared openly. It is used to:
    /// - Verify server identity (prevent MITM attacks)
    /// - Derive shared secret (forward secrecy)
    pub server_public_key_base64: String,
}

/// VPN Server Manager
///
/// Manages the list of available VPN servers and provides methods for
/// server selection and querying. This is the central repository for
/// server information used by the VPN client.
///
/// ## Networking Relevance
///
/// The server manager is responsible for:
/// 1. Loading server list from configuration
/// 2. Providing server list to GUI for display
/// 3. Selecting optimal server based on criteria
/// 4. Returning server details for tunnel connection
pub struct ServerManager {
    /// List of available VPN servers
    /// 
    /// Contains all servers that the user can connect to. This list is
    /// typically loaded from a configuration file (servers.toml) on startup.
    available_vpn_servers_list: Vec<Server>,
}

impl ServerManager {
    /// Creates a new server manager and loads servers from configuration
    /// 
    /// Loads the server list from the configuration file (servers.toml)
    /// and initializes the server manager with the available servers.
    /// 
    /// ## Networking Context
    /// 
    /// Server manager creation occurs during application initialization.
    /// The server list is loaded from the configuration file and used
    /// to populate the GUI dropdown and for server selection.
    /// 
    /// ## Configuration File Location
    /// 
    /// The server configuration file is located at:
    /// - Linux/macOS: `/etc/rustvpn/servers.toml` or `resources/servers.toml`
    /// - Windows: `C:\\ProgramData\\RustVPN\\servers.toml` or `resources\\servers.toml`
    /// 
    /// Fallback to `resources/servers.toml` in the application directory
    /// if system-wide configuration is not found.
    /// 
    /// # Returns
    /// 
    /// * `Ok(ServerManager)` - New server manager with loaded servers
    /// * `Err(_)` - If server configuration cannot be loaded or parsed
    pub fn new() -> Result<Self> {
        // Try to load from system-wide configuration first
        let config_paths = vec![
            // System-wide locations
            Path::new("/etc/rustvpn/servers.toml"),
            Path::new("C:\\ProgramData\\RustVPN\\servers.toml"),
            // Fallback to resources directory
            Path::new("resources/servers.toml"),
        ];
        
        let mut servers = Vec::new();
        
        for config_path in config_paths {
            if let Ok(config_content) = fs::read_to_string(config_path) {
                match toml::from_str::<ServerConfig>(&config_content) {
                    Ok(config) => {
                        servers = config.servers;
                        tracing::info!("Loaded {} servers from {}", servers.len(), config_path.display());
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse server config from {}: {}", config_path.display(), e);
                    }
                }
            }
        }
        
        if servers.is_empty() {
            tracing::warn!("No servers loaded from configuration, using empty list");
        }
        
        Ok(Self {
            available_vpn_servers_list: servers,
        })
    }

    /// Returns a reference to the list of available servers
    /// 
    /// This is used by the GUI to populate the server selection dropdown
    /// and by other components to query server information.
    /// 
    /// ## Networking Context
    /// 
    /// The server list is used to:
    /// 1. Display available servers in the GUI
    /// 2. Allow user to select a server
    /// 3. Perform server selection algorithms
    /// 4. Provide server details for tunnel connection
    /// 
    /// # Returns
    /// 
    /// Slice reference to the internal server list
    pub fn get_servers(&self) -> &[Server] {
        &self.available_vpn_servers_list
    }

    /// Selects the best available server
    /// 
    /// Implements server selection logic to choose the optimal server
    /// based on various criteria such as latency, load, and location.
    /// 
    /// ## Networking Context
    /// 
    /// Server selection affects VPN performance:
    /// 
    /// - **Latency**: Closer servers have lower round-trip time
    /// - **Load**: Less loaded servers provide better throughput
    /// - **Jurisdiction**: Different countries have different privacy laws
    /// - **Reliability**: Some servers may be more stable than others
    /// 
    /// ## Selection Algorithm (Future)
    /// 
    /// Future implementation will:
    /// 1. Ping all servers to measure latency
    /// 2. Query server load metrics
    /// 3. Apply user preferences (location, jurisdiction)
    /// 4. Select server with lowest latency and acceptable load
    /// 5. Fallback to random server if all unavailable
    /// 
    /// ## Current Implementation
    /// 
    /// Currently returns the first server in the list as a simple placeholder.
    /// 
    /// # Returns
    /// 
    /// * `Some(&Server)` - Reference to selected server
    /// * `None` - No servers available
    pub fn select_best_server(&self) -> Option<&Server> {
        self.available_vpn_servers_list.first()
    }
}
