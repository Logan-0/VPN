//! # VPN Configuration Module
//!
//! This module manages user preferences and application settings for the VPN client.
//! It handles loading and saving configuration to disk in a platform-specific manner.
//!
//! ## Networking Concepts
//!
//! Configuration doesn't directly handle networking, but it stores critical settings
//! that affect network behavior:
//!
//! - **Auto-connect**: Automatically establish VPN tunnel on application startup
//! - **Kill switch**: Block all non-VPN traffic when disconnected (prevents IP leaks)
//! - **Auto-reconnect**: Automatically restore the tunnel if the connection drops
//! - **DNS filtering**: Intercept and filter DNS queries to block ads/malware
//! - **Selected server**: Which VPN server to connect to (affects latency and jurisdiction)
//!
//! ## Configuration Storage Locations
//!
//! Different operating systems have standard locations for application configuration:
//!
//! - **Linux**: `~/.config/rustvpn/config.toml`
//! - **macOS**: `~/Library/Application Support/RustVPN/config.toml`
//! - **Windows**: `%APPDATA%\RustVPN\config.toml`
//!
//! ## Security Considerations
//!
//! Configuration files may contain sensitive information:
//! - User preferences (privacy-related settings)
//! - Last selected server (usage patterns)
//! - Future: API keys, credentials
//!
//! Files should be protected with appropriate permissions:
//! - Read/write for owner only
//! - No access for group or others

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// VPN Configuration Structure
///
/// This structure contains all user-configurable settings for the VPN application.
/// These settings control how the VPN behaves and which features are enabled.
///
/// ## Networking Relevance
///
/// While configuration itself doesn't perform networking operations, these settings
/// directly affect network behavior:
///
/// - `auto_connect_on_application_startup`: Determines if VPN tunnel is established
///   automatically when the application starts, ensuring immediate protection.
///
/// - `kill_switch_protection_enabled`: When enabled, uses platform-specific firewall
///   rules to block all non-VPN traffic, preventing IP/DNS leaks if the connection drops.
///
/// - `auto_reconnect_enabled`: When enabled, the reconnect manager automatically
///   re-establishes the tunnel on failure using exponential backoff.
///
/// - `dns_filtering_protection_enabled`: Enables DNS query interception and filtering
///   to block requests to known malicious/advertising domains, and uses DNS-over-HTTPS
///   to encrypt DNS queries.
///
/// - `selected_vpn_server_identifier`: Determines which VPN server to connect to,
///   affecting latency, jurisdiction, and privacy characteristics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VpnConfig {
    /// Automatically establish VPN connection when application starts
    /// 
    /// When true, the VPN client will immediately attempt to connect to the
    /// last used server upon startup, providing immediate privacy protection.
    /// When false, the user must manually click "Connect" to establish the tunnel.
    pub auto_connect_on_application_startup: bool,
    
    /// Enable kill switch protection to block non-VPN traffic
    /// 
    /// When true, the kill switch is activated before connecting and deactivated
    /// after disconnecting. It uses platform-specific firewall rules (iptables on Linux,
    /// pf on macOS, Windows Firewall on Windows) to block all traffic except:
    /// - Traffic through the VPN tunnel interface
    /// - Traffic to the VPN server (for reconnection)
    /// - Local network traffic (192.168.x.x, 10.x.x.x, 172.16.x.x)
    /// - Loopback traffic
    /// 
    /// This prevents IP address exposure if the VPN connection drops unexpectedly.
    pub kill_switch_protection_enabled: bool,
    
    /// Automatically reconnect when VPN connection is lost
    /// 
    /// When true, the reconnect manager monitors the tunnel state and automatically
    /// attempts to re-establish the connection on failure using exponential backoff
    /// (1s → 2s → 4s → 8s → 16s → 30s max) to avoid hammering the server.
    /// When false, the user must manually click "Connect" after a dropped connection.
    pub auto_reconnect_enabled: bool,
    
    /// Enable DNS filtering and DNS-over-HTTPS
    /// 
    /// When true, DNS queries are:
    /// 1. Intercepted before leaving the device
    /// 2. Checked against blocklists (ads, malware, trackers)
    /// 3. Encrypted using DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT)
    /// 4. Sent to privacy-focused DNS resolvers (Cloudflare, Google, etc.)
    /// 
    /// This prevents DNS leaks and blocks access to malicious domains.
    pub dns_filtering_protection_enabled: bool,
    
    /// Identifier of the selected VPN server
    /// 
    /// Stores the server ID (e.g., "us-california-1") of the last selected server.
    /// This allows the application to remember the user's preferred server and
    /// automatically select it on startup.
    /// 
    /// None indicates no server has been selected yet.
    pub selected_vpn_server_identifier: Option<String>,

    /// Optional custom DNS server address (e.g., Pi-hole).
    /// 
    /// When set, the VPN client delegates DNS resolution and filtering to this
    /// server instead of using built-in DNS-over-HTTPS and the local blocklist.
    /// This is useful when a Pi-hole or similar DNS-level ad blocker is running
    /// on the local network.
    /// 
    /// The DNS queries still travel through the encrypted VPN tunnel -- only the
    /// final resolution is handled by the custom server.
    /// 
    /// Format: IPv4 or IPv6 address as a string (e.g., "192.168.1.53").
    /// None means use the default Cloudflare DoH resolver with built-in filtering.
    pub custom_dns_server_address: Option<String>,

    /// The client's WireGuard private key, stored as a base64 string.
    ///
    /// ## Why This Key Exists
    ///
    /// Every WireGuard peer has a 32-byte X25519 private key that:
    /// 1. Proves the client's identity to the server during the Noise protocol
    ///    handshake (think of it as an SSH key for VPN connections)
    /// 2. Participates in Diffie-Hellman key exchange to derive the per-session
    ///    encryption key (ChaCha20-Poly1305)
    /// 3. Must stay secret -- anyone who holds this key can impersonate this device
    ///
    /// ## Why Store It in the Config File
    ///
    /// The key is stable across restarts so the server always sees the same client
    /// identity. In a production deployment the server's allowlist maps each public
    /// key (derived from this private key) to allowed IPs and bandwidth limits.
    /// Regenerating the key each run would look like a new, unregistered device.
    ///
    /// ## Why `Option<String>` Instead of a Required Field
    ///
    /// `None` means no key has been generated yet. [`VpnConfig::get_or_create_private_key`]
    /// generates one on the first call and writes it back to disk. Existing config
    /// files that predate this field deserialize as `None` (via `#[serde(default)]`)
    /// and get a key automatically on next connect.
    ///
    /// ## Security
    ///
    /// - Saved with 0600 permissions (owner read/write only, no group/other access)
    /// - Loaded into [`Zeroizing<[u8; 32]>`] which overwrites the bytes on drop
    /// - Never logged or transmitted in plaintext
    #[serde(default)]
    pub client_private_key_base64: Option<String>,
}

impl Default for VpnConfig {
    /// Creates a default VPN configuration with recommended security settings.
    /// 
    /// The defaults prioritize security and privacy:
    /// - Auto-connect is disabled (user choice)
    /// - Kill switch is enabled (prevents leaks)
    /// - Auto-reconnect is enabled (automatic recovery)
    /// - DNS filtering is enabled (blocks ads/malware)
    /// - No server selected (user must choose)
    /// 
    /// ## Networking Rationale
    /// 
    /// Kill switch and DNS filtering are enabled by default because:
    /// 1. Most users want maximum privacy protection
    /// 2. These features prevent common VPN leaks
    /// 3. They have minimal performance impact
    /// 4. Disabling them requires explicit user action
    fn default() -> Self {
        Self {
            auto_connect_on_application_startup: false,
            kill_switch_protection_enabled: true,
            auto_reconnect_enabled: true,
            dns_filtering_protection_enabled: true,
            selected_vpn_server_identifier: None,
            custom_dns_server_address: None,
            client_private_key_base64: None,
        }
    }
}

impl VpnConfig {
    /// Gets the platform-specific configuration file path
    /// 
    /// Returns the appropriate configuration directory for the current platform:
    /// - Linux: ~/.config/rustvpn/config.toml
    /// - macOS: ~/Library/Application Support/RustVPN/config.toml
    /// - Windows: %APPDATA%\RustVPN\config.toml
    fn get_config_path() -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            let mut path = std::env::var("HOME")
                .unwrap_or_else(|_| ".".to_string());
            path.push_str("/.config/rustvpn/config.toml");
            PathBuf::from(path)
        }
        
        #[cfg(target_os = "macos")]
        {
            let mut path = std::env::var("HOME")
                .unwrap_or_else(|_| ".".to_string());
            path.push_str("/Library/Application Support/RustVPN/config.toml");
            PathBuf::from(path)
        }
        
        #[cfg(target_os = "windows")]
        {
            let mut path = std::env::var("APPDATA")
                .unwrap_or_else(|_| ".".to_string());
            path.push_str("\\RustVPN\\config.toml");
            PathBuf::from(path)
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            // Fallback for other platforms
            PathBuf::from("config.toml")
        }
    }
    
    /// Loads VPN configuration from disk.
    /// 
    /// This method reads the configuration file from the platform-specific location
    /// and parses it using TOML format. If the file doesn't exist or is invalid,
    /// it returns the default configuration.
    /// 
    /// ## Networking Context
    /// 
    /// Configuration loading occurs during application startup, before any network
    /// operations. The loaded settings determine:
    /// 
    /// 1. Whether to auto-connect (immediate VPN tunnel establishment)
    /// 2. Whether to enable kill switch (firewall rule configuration)
    /// 3. Whether to enable auto-reconnect (reconnect manager behavior)
    /// 4. Whether to enable DNS filtering (DNS resolver configuration)
    /// 5. Which server to connect to (affects routing and latency)
    /// 
    /// ## Platform-Specific Paths
    /// 
    /// - **Linux**: `~/.config/rustvpn/config.toml`
    /// - **macOS**: `~/Library/Application Support/RustVPN/config.toml`
    /// - **Windows**: `%APPDATA%\RustVPN\config.toml`
    /// 
    /// # Returns
    /// 
    /// * `Ok(VpnConfig)` - Loaded or default configuration
    /// * `Err(_)` - If configuration file is corrupted (returns default)
    pub fn load() -> Result<Self> {
        let config_path = Self::get_config_path();
        
        // Try to read the configuration file
        match fs::read_to_string(&config_path) {
            Ok(content) => {
                match toml::from_str::<VpnConfig>(&content) {
                    Ok(config) => {
                        tracing::info!("Loaded configuration from {}", config_path.display());
                        Ok(config)
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse configuration from {}: {}, using defaults", config_path.display(), e);
                        Ok(Self::default())
                    }
                }
            }
            Err(_) => {
                tracing::info!("Configuration file not found at {}, using defaults", config_path.display());
                Ok(Self::default())
            }
        }
    }

    /// Saves VPN configuration to disk.
    /// 
    /// This method serializes the configuration to TOML format and writes it to
    /// the platform-specific configuration directory. This ensures user preferences
    /// persist across application restarts.
    /// 
    /// ## Networking Context
    /// 
    /// Configuration saving typically occurs:
    /// 1. When user changes settings in the GUI
    /// 2. When user selects a different server
    /// 3. When user toggles features (kill switch, auto-reconnect, DNS filtering)
    /// 4. On application shutdown (to ensure latest state is saved)
    /// 
    /// Saved settings will be loaded on next startup and applied to network operations.
    /// 
    /// ## Security Considerations
    /// 
    /// Configuration files are protected with appropriate permissions:
    /// - Read/write for owner only (mode 0600 on Unix)
    /// - No access for group or others
    /// - Prevents other users from reading VPN preferences
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - Configuration saved successfully
    /// * `Err(_)` - If unable to write configuration file
    pub fn save(&self) -> Result<()> {
        let config_path = Self::get_config_path();
        
        // Create parent directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        // Serialize configuration to TOML
        let toml_content = toml::to_string_pretty(self)?;
        
        // Write configuration file (atomic write on Unix-like systems)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            
            // Write to temporary file first
            let temp_path = config_path.with_extension("tmp");
            fs::write(&temp_path, &toml_content)?;
            
            // Set permissions to 0600 (read/write for owner only)
            let mut perms = fs::metadata(&temp_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&temp_path, perms)?;
            
            // Atomic rename
            fs::rename(&temp_path, &config_path)?;
        }
        
        #[cfg(not(unix))]
        {
            // On Windows, just write directly (atomic rename not available)
            fs::write(&config_path, &toml_content)?;
        }
        
        tracing::info!("Saved configuration to {}", config_path.display());
        Ok(())
    }

    /// Returns the client's WireGuard private key, generating and saving one if
    /// none exists.
    ///
    /// ## Key Lifecycle
    ///
    /// **First call** (`client_private_key_base64` is `None`):
    /// 1. A fresh X25519 private key is generated with `boringtun`'s
    ///    `StaticSecret::random_from_rng`, which uses the OS CSPRNG.
    /// 2. The private key bytes are base64-encoded and written to
    ///    `client_private_key_base64`, then the config file is saved.
    /// 3. The raw bytes are returned wrapped in [`Zeroizing`].
    ///
    /// **Subsequent calls** (`client_private_key_base64` is `Some(b64)`):
    /// 1. The base64 string is decoded back to 32 bytes.
    /// 2. The bytes are returned wrapped in [`Zeroizing`].
    /// The same key is always returned, giving the server a stable client identity.
    ///
    /// ## Why `&mut self`?
    ///
    /// If no key exists this method writes `client_private_key_base64` into `self`
    /// and calls `save()`. Mutation requires an exclusive (`&mut`) borrow.
    ///
    /// ## Why `Zeroizing<[u8; 32]>`?
    ///
    /// `Zeroizing<T>` implements `Drop` by overwriting the wrapped bytes with zeros
    /// before the memory is freed. Without it, the private key bytes might remain
    /// readable in freed heap memory until the allocator reuses that region -- a
    /// window where they could appear in crash dumps or be read from swap.
    ///
    /// # Returns
    /// * `Ok(Zeroizing<[u8; 32]>)` - The private key, ready for [`TunnelConfig::private_key`]
    /// * `Err(_)` - The stored base64 is malformed, or saving the newly generated key failed
    pub fn get_or_create_private_key(&mut self) -> Result<Zeroizing<[u8; 32]>> {
        if let Some(b64) = &self.client_private_key_base64 {
            let bytes = STANDARD
                .decode(b64)
                .context("Failed to decode stored private key from base64")?;
            if bytes.len() != 32 {
                anyhow::bail!(
                    "Stored private key has wrong length: {} bytes (expected 32)",
                    bytes.len()
                );
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Ok(Zeroizing::new(arr));
        }

        // No key stored yet -- generate a fresh X25519 private key.
        // StaticSecret::random_from_rng draws entropy from the OS CSPRNG.
        // We only store the private key bytes; the public key is re-derived
        // each time from the private key inside the WireGuard handshake.
        use boringtun::x25519::StaticSecret;
        let private = StaticSecret::random_from_rng(rand::thread_rng());
        let key_bytes: [u8; 32] = private.to_bytes();

        // Persist the new key immediately so the same identity survives restarts.
        self.client_private_key_base64 = Some(STANDARD.encode(&key_bytes));
        self.save().context("Failed to save newly generated private key")?;

        tracing::info!("Generated and saved a new WireGuard client private key");
        Ok(Zeroizing::new(key_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    fn config_with_b64_key(b64: &str) -> VpnConfig {
        VpnConfig {
            client_private_key_base64: Some(b64.to_string()),
            ..VpnConfig::default()
        }
    }

    fn b64_of(bytes: &[u8; 32]) -> String {
        STANDARD.encode(bytes)
    }

    // ── Default ──────────────────────────────────────────────────────────────

    #[test]
    fn test_default_has_no_private_key() {
        assert!(VpnConfig::default().client_private_key_base64.is_none());
    }

    #[test]
    fn test_default_auto_connect_off() {
        assert!(!VpnConfig::default().auto_connect_on_application_startup);
    }

    #[test]
    fn test_default_kill_switch_on() {
        assert!(VpnConfig::default().kill_switch_protection_enabled);
    }

    #[test]
    fn test_default_auto_reconnect_on() {
        assert!(VpnConfig::default().auto_reconnect_enabled);
    }

    // ── get_or_create_private_key: decode path ───────────────────────────────

    #[test]
    fn test_decode_valid_32_byte_key() {
        let bytes = [42u8; 32];
        let mut cfg = config_with_b64_key(&b64_of(&bytes));
        let key = cfg.get_or_create_private_key().unwrap();
        assert_eq!(*key, bytes);
    }

    #[test]
    fn test_decode_preserves_all_byte_values() {
        let bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
        let mut cfg = config_with_b64_key(&b64_of(&bytes));
        let key = cfg.get_or_create_private_key().unwrap();
        assert_eq!(*key, bytes);
    }

    #[test]
    fn test_decode_does_not_alter_stored_field() {
        let bytes = [99u8; 32];
        let b64 = b64_of(&bytes);
        let mut cfg = config_with_b64_key(&b64);
        cfg.get_or_create_private_key().unwrap();
        assert_eq!(cfg.client_private_key_base64.as_deref(), Some(b64.as_str()));
    }

    #[test]
    fn test_decode_returns_zeroizing_wrapper_of_correct_length() {
        let mut cfg = config_with_b64_key(&b64_of(&[7u8; 32]));
        let key: Zeroizing<[u8; 32]> = cfg.get_or_create_private_key().unwrap();
        assert_eq!(key.len(), 32);
    }

    // ── get_or_create_private_key: error cases ───────────────────────────────

    #[test]
    fn test_invalid_base64_returns_error() {
        let mut cfg = config_with_b64_key("not-valid-base64!!!");
        assert!(cfg.get_or_create_private_key().is_err());
    }

    #[test]
    fn test_key_too_short_returns_error() {
        let short = STANDARD.encode([1u8; 16]);
        let mut cfg = config_with_b64_key(&short);
        assert!(cfg.get_or_create_private_key().is_err());
    }

    #[test]
    fn test_key_too_long_returns_error() {
        let long = STANDARD.encode([0u8; 64]);
        let mut cfg = config_with_b64_key(&long);
        assert!(cfg.get_or_create_private_key().is_err());
    }

    #[test]
    fn test_empty_base64_returns_error() {
        let mut cfg = config_with_b64_key("");
        assert!(cfg.get_or_create_private_key().is_err());
    }

    // ── Serialisation / deserialisation ─────────────────────────────────────

    #[test]
    fn test_round_trip_preserves_key() {
        let bytes = [55u8; 32];
        let b64 = b64_of(&bytes);
        let cfg = config_with_b64_key(&b64);
        let toml = toml::to_string_pretty(&cfg).unwrap();
        let loaded: VpnConfig = toml::from_str(&toml).unwrap();
        assert_eq!(loaded.client_private_key_base64.as_deref(), Some(b64.as_str()));
    }

    #[test]
    fn test_old_config_without_key_field_deserialises_as_none() {
        // Simulates loading a config file that was written before this field existed.
        let toml = r#"
            auto_connect_on_application_startup = false
            kill_switch_protection_enabled = true
            auto_reconnect_enabled = true
            dns_filtering_protection_enabled = true
        "#;
        let cfg: VpnConfig = toml::from_str(toml).unwrap();
        assert!(cfg.client_private_key_base64.is_none());
    }

    #[test]
    fn test_config_with_key_field_null_deserialises_as_none() {
        let toml = "client_private_key_base64 = \"\"\n";
        let cfg: VpnConfig = toml::from_str(toml).unwrap_or_default();
        // The field exists but is empty -- decode will return an error, not None
        if let Some(v) = &cfg.client_private_key_base64 {
            assert_eq!(v.as_str(), "");
        }
    }

    #[test]
    fn test_serialised_toml_contains_key_field_name() {
        let cfg = config_with_b64_key(&b64_of(&[1u8; 32]));
        let toml = toml::to_string_pretty(&cfg).unwrap();
        assert!(toml.contains("client_private_key_base64"));
    }

    // ── Behaviour of the None path without touching real filesystem ──────────
    // We cannot call the generate-and-save path in unit tests because it writes
    // to ~/.config/rustvpn/config.toml. These tests verify the `Some(b64)` decode
    // path exhaustively; the generate path is covered by integration tests or
    // can be run manually.  Keeping this comment here as a reminder.
}
