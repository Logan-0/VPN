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

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

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
}
