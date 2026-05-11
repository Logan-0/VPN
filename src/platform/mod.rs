//! Platform — OS-specific TUN device and network configuration.
//!
//! # Role in RustVPN
//! This module provides platform-specific networking operations including
//! TUN device creation, routing configuration, and firewall management.
//! Each supported platform (Linux, macOS, Windows) has its own implementation
//! that abstracts system-level networking APIs.
//!
//! # Main Contracts
//! - Input: TUN device IP configuration, VPN server endpoint
//! - Output: TUN device handles, routing table changes, cleanup functions
//! - Safety: Requires root/admin privileges; cleanup on Drop prevents resource leakage
//!
//! # Platform Notes
//! Platform-specific implementations via conditional compilation:
//! - Linux: Uses tun crate with ioctl-based TUN devices
//! - macOS: Uses utun devices with network setup
//! - Windows: Uses WinTun driver with session handles
//!
//! # Non-goals
//! This module does not implement packet processing (delegated to packet loop).
//! It does not handle firewall rules beyond basic routing (delegated to killswitch).
//! It does not implement cryptographic operations (delegated to tunnel module).

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;
