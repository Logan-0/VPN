//! # RustVPN Library
//!
//! This is the main library module for RustVPN, a secure, lightweight VPN client
//! written in Rust using the WireGuard protocol.
//!
//! ## Module Organization
//!
/// The library is organized into functional modules:
///
/// - **core**: Core VPN functionality (tunnel, kill switch, reconnect)
/// - **dns**: DNS filtering and resolution
/// - **gui**: GTK4 graphical user interface
/// - **platform**: Platform-specific networking operations
/// - **config**: Configuration management
/// - **server**: VPN server selection and management
/// - **update**: Application update checking
///
//! ## Networking Architecture
//!
/// The VPN is implemented as a layered architecture:
///
/// ```text
/// GUI Layer (gui/)
///     │ User interaction
///     ▼
/// Configuration Layer (config/, server/)
///     │ Settings and server selection
///     ▼
/// Core VPN Layer (core/)
///     │ WireGuard tunnel, encryption/decryption
///     ▼
/// Platform Layer (platform/)
///     │ TUN devices, routing, firewall
///     ▼
/// Network Interface
///     │ Actual network I/O
/// ```
//!
//! ## Security Features
//!
/// - Zero-logging architecture (no connection data stored)
/// - WireGuard protocol (modern, secure, lightweight)
/// - Kill switch (prevents IP/DNS leaks)
/// - DNS filtering (blocks ads/malware)
//! - Auto-reconnect (automatic recovery from failures)

/// Core VPN functionality module
/// 
/// Contains the essential VPN components:
/// - **tunnel**: WireGuard tunnel management and encryption/decryption
/// - **killswitch**: Firewall-based traffic blocking to prevent leaks
/// - **reconnect**: Automatic reconnection with exponential backoff
pub mod core;

/// DNS filtering and resolution module
/// 
/// Contains DNS-related functionality:
/// - **filter**: DNS query filtering against blocklists
/// - **resolver**: DNS-over-HTTPS/TLS for encrypted DNS queries
pub mod dns;

/// Graphical user interface module
/// 
/// Contains the GTK4-based GUI:
/// - **app**: Main application window and controls
pub mod gui;

/// Platform-specific networking module
/// 
/// Contains OS-specific implementations:
/// - **linux**: Linux TUN devices, iptables, routing
/// - **macos**: macOS utun devices, pf, routing
/// - **windows**: Windows WinTun driver, firewall, routing
pub mod platform;

/// Configuration management module
/// 
/// Handles user preferences and application settings:
/// - Auto-connect setting
/// - Kill switch preference
/// - DNS filtering preference
/// - Server selection
pub mod config;

/// VPN server management module
/// 
/// Handles server information and selection:
/// - Server list management
/// - Server selection algorithms
/// - Server metadata (location, load, etc.)
pub mod server;

/// Update checking module
/// 
/// Checks for application updates from GitHub releases:
/// - Version comparison
/// - Update notification
/// - Download links
pub mod update;
