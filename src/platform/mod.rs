//! Platform — Linux-specific TUN device and network configuration.
//!
//! # Role in RustVPN
//! This module provides Linux-specific networking operations including
//! TUN device creation, routing configuration, and firewall management.
//!
//! # Main Contracts
//! - Input: TUN device IP configuration, VPN server endpoint
//! - Output: TUN device handles, routing table changes, cleanup functions
//! - Safety: Requires root privileges; cleanup on Drop prevents resource leakage
//!
//! # Platform Notes
//! Linux-only implementation using tun crate with ioctl-based TUN devices.
//! Requires Linux kernel 2.4.26+ with TUN/TAP support.
//!
//! # Non-goals
//! This module does not implement packet processing (delegated to packet loop).
//! It does not handle firewall rules beyond basic routing (delegated to killswitch).
//! It does not implement cryptographic operations (delegated to tunnel module).

pub mod linux;
