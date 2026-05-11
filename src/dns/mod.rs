//! DNS — DNS filtering, interception, and encrypted resolution.
//!
//! # Role in RustVPN
//! This module provides DNS-related functionality including query filtering
//! to block malicious domains, packet-level interception at the TUN layer,
//! and encrypted DNS resolution via DNS-over-HTTPS (DoH) to prevent DNS leaks.
//!
//! # Main Contracts
//! - Input: DNS queries from packet loop, blocklist configuration
//! - Output: Filtered DNS responses, encrypted DoH queries
//! - Safety: DNS queries blocked before leaving VPN; DoH prevents ISP snooping
//!
//! # Platform Notes
//! Platform-agnostic DNS parsing and filtering works on all platforms.
//! DoH resolution uses hickory-resolver with tokio async runtime.
//!
//! # Non-goals
//! This module does not implement DNS caching (handled by OS resolver).
//! It does not handle DNS server discovery (configured by user).
//! It does not implement IPv6 DNS filtering (IPv4 only currently).

pub mod filter;
pub mod intercept;
pub mod resolver;
