//! RustVPN — Secure WireGuard VPN client library.
//!
//! # Role in RustVPN
//! This is the main library module for RustVPN, a secure, lightweight VPN client
//! written in Rust using the WireGuard protocol. It provides the core VPN
//! functionality including tunnel management, DNS filtering, kill switch,
//! auto-reconnect, and platform-specific networking operations.
//!
//! # Main Contracts
//! - Input: User configuration, server selection, GUI commands
//! - Output: Encrypted VPN tunnel, filtered DNS, firewall rules
//! - Safety: Zero-logging architecture, privilege minimization, kill switch
//!
//! # Platform Notes
//! Currently **Linux-only** (see `docs/README.md` — v0.4.0 RC is a Linux-focused
//! release). The codebase is structured for conditional compilation per platform:
//! - Linux: TUN devices with ioctl, iptables firewall — implemented (`platform::linux`,
//!   `KillSwitch::enable_linux`/`disable_linux`)
//! - macOS / Windows: no `platform::macos`/`platform::windows` module exists yet, and
//!   `KillSwitch` has no `enable_macos`/`enable_windows` implementations — the `#[cfg(...)]`
//!   call sites for those platforms will not compile. Do not advertise macOS/Windows support
//!   until these are implemented and tested.
//!
//! # Non-goals
//! This library does not include the main entry point (see main.rs).
//! It does not implement network protocols beyond WireGuard (delegated to boringtun).
//! It does not store connection logs (zero-logging architecture).

/// Core VPN functionality module.
///
/// Contains the essential VPN components:
/// - **tunnel**: WireGuard tunnel management and encryption/decryption
/// - **killswitch**: Firewall-based traffic blocking to prevent leaks
/// - **reconnect**: Automatic reconnection with exponential backoff
pub mod core;

/// DNS filtering and resolution module.
///
/// Contains DNS-related functionality:
/// - **filter**: DNS query filtering against blocklists
/// - **resolver**: DNS-over-HTTPS/TLS for encrypted DNS queries
pub mod dns;

/// Graphical user interface module.
///
/// Contains the Iced-based GUI (cross-platform, pure Rust):
/// - **app**: Main application window and controls (Elm architecture)
pub mod gui;

/// Platform-specific networking module.
///
/// Contains OS-specific implementations:
/// - **linux**: Linux TUN devices, iptables, routing — the only implemented platform today
///
/// macOS/Windows submodules do not exist yet (see `lib.rs`'s crate-level Platform Notes).
pub mod platform;

/// Configuration management module.
///
/// Handles user preferences and application settings:
/// - Auto-connect setting
/// - Kill switch preference
/// - DNS filtering preference
/// - Server selection
pub mod config;

/// VPN server management module.
///
/// Handles server information and selection:
/// - Server list management
/// - Server selection algorithms
/// - Server metadata (location, load, etc.)
pub mod server;

/// Update checking module.
///
/// Checks for application updates from GitHub releases:
/// - Version comparison
/// - Update notification
/// - Download links
pub mod update;

/// Privilege minimization (drop capabilities, capture invoking user).
///
/// Linux-specific hardening that strips every capability except
/// `CAP_NET_ADMIN` so a bug in the GUI/HTTP/config layers cannot escalate
/// to a full root compromise. On non-Linux platforms the functions are
/// no-ops.
pub mod privilege;
