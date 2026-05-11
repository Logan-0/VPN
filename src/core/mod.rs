//! Core — VPN tunnel, packet processing, and control logic.
//!
//! # Role in RustVPN
//! This module contains the core VPN functionality including WireGuard tunnel
//! management (encryption/decryption), packet processing loops (TUN↔UDP forwarding),
//! kill switch firewall management, auto-reconnect logic, and the controller that
//! bridges the GUI with the async VPN core.
//!
//! # Main Contracts
//! - Input: Configuration, server endpoints, GUI commands
//! - Output: Encrypted packets, firewall rules, connection state
//! - Safety: Zeroized private keys, encrypted traffic, kill switch protection
//!
//! # Platform Notes
//! Platform-specific packet loop implementations:
//! - Linux/Unix: File descriptor-based TUN I/O
//! - Windows: WinTun session API (no file descriptors)
//!
//! # Non-goals
//! This module does not implement TUN device creation (delegated to platform).
//! It does not implement DNS filtering (delegated to dns module).
//! It does not implement GUI rendering (delegated to gui module).

pub mod tunnel;
pub mod killswitch;
pub mod reconnect;

// The packet loop is platform-split: the Linux/Unix implementation works
// on raw file descriptors, while the Windows implementation drives the
// WinTun session API (no file descriptor exists on Windows).
#[cfg(unix)]
pub mod packet_loop;

#[cfg(target_os = "windows")]
pub mod packet_loop_windows;

pub mod controller;
