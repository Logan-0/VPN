//! DNS — DNS filtering, interception, and encrypted resolution.
//!
//! # Role in RustVPN
//! This module provides DNS-related functionality: query filtering to block
//! malicious domains and packet-level interception at the TUN layer are both
//! live. `resolver::DnsResolver` implements encrypted DNS-over-HTTPS (DoH) but
//! is **not currently wired into the live path** (see `docs/RoadMap.md` — this
//! was a deliberate scope decision, not an oversight); no code in `core::`
//! instantiates or calls it today, so DoH resolution is not active.
//!
//! # Main Contracts
//! - Input: DNS queries from packet loop, blocklist configuration
//! - Output: Filtered DNS responses (`filter`, `intercept`)
//! - Safety: DNS queries blocked before leaving VPN. DoH (`resolver`) would
//!   additionally prevent ISP snooping once wired in — it does not today.
//!
//! # Platform Notes
//! Platform-agnostic DNS parsing and filtering works on all platforms.
//! `resolver`'s DoH implementation uses hickory-resolver with the tokio async
//! runtime but, again, is dormant/unused code until connected to `core::`.
//!
//! # Non-goals
//! This module does not implement DNS caching (handled by OS resolver).
//! It does not handle DNS server discovery (configured by user).
//! It does not implement IPv6 DNS filtering (IPv4 only currently).

pub mod filter;
pub mod intercept;
pub mod resolver;
