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
//! Linux-only: file-descriptor-based TUN I/O.
//!
//! # Non-goals
//! This module does not implement TUN device creation (delegated to platform).
//! It does not implement DNS filtering (delegated to dns module).
//! It does not implement GUI rendering (delegated to gui module).

pub mod killswitch;
pub mod reconnect;
pub mod tunnel;

// The Linux/Unix packet loop works on raw file descriptors.
#[cfg(unix)]
pub mod packet_loop;

pub mod controller;
