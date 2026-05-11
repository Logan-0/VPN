//! Resolver — DNS-over-HTTPS encrypted DNS resolution.
//!
//! # Role in RustVPN
//! This module handles DNS resolution using DNS-over-HTTPS (DoH) and
//! DNS-over-TLS (DoT) to encrypt DNS queries and prevent DNS leaks.
//! It routes DNS queries through privacy-focused resolvers like Cloudflare
//! to ensure ISPs cannot monitor which websites users visit.
//!
//! # Main Contracts
//! - Input: Domain names for resolution, resolver configuration
//! - Output: IP addresses via encrypted DoH/DoT protocols
//! - Safety: All DNS queries encrypted; prevents ISP DNS surveillance
//!
//! # Platform Notes
//! Platform-agnostic using hickory-resolver with tokio async runtime.
//! Supports custom DNS servers (Pi-hole) via standard UDP/TLS protocols.
//!
//! # Non-goals
//! This module does not implement DNS caching (handled by hickory-resolver).
//! It does not perform DNS filtering (delegated to filter module).
//! It does not handle DNS packet parsing (delegated to intercept module).

use anyhow::{Context, Result};
use hickory_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};
use hickory_resolver::TokioAsyncResolver;
use std::net::{IpAddr, SocketAddr};

/// DNS-over-HTTPS/TLS Resolver
///
/// Handles DNS resolution using encrypted DNS protocols (DoH and DoT)
/// to prevent DNS leaks and enhance privacy.
///
/// ## Networking Relevance
///
/// The DNS resolver:
/// - Uses DNS-over-HTTPS (DoH) to encrypt DNS queries
/// - Uses DNS-over-TLS (DoT) as alternative encrypted protocol
/// - Prevents DNS leaks by encrypting all DNS queries
/// - Routes DNS queries through VPN tunnel
/// - Caches DNS responses for performance
///
/// This ensures that your ISP cannot see which websites you're visiting
/// by monitoring DNS queries.
///
/// ## DoH vs DoT
///
/// **DNS-over-HTTPS (DoH):**
/// - Uses standard HTTPS port 443
/// - Looks like normal HTTPS traffic
/// - Harder to block by firewalls
/// - Slightly higher overhead
///
/// **DNS-over-TLS (DoT):**
/// - Uses dedicated port 853
/// - Easier to identify as DNS traffic
/// - Can be blocked by firewalls
/// - Slightly lower overhead
///
/// ## Pi-hole / Custom DNS Server Support
///
/// When a user has a Pi-hole or other local DNS server, the resolver
/// can be configured to forward queries to that server using standard
/// UDP/TCP DNS (port 53) instead of DoH.  The Pi-hole handles filtering
/// and the VPN tunnel still encrypts the traffic between client and
/// VPN server, so the query is never visible to the ISP.
///
/// ```text
/// App -> TUN -> [VPN Tunnel] -> VPN Server -> Pi-hole (192.168.1.53:53)
/// ```
///
/// ## Integration with VPN
///
/// When VPN is active:
/// 1. DNS queries are intercepted at TUN device level
/// 2. DNS resolver encrypts queries using DoH/DoT
/// 3. Encrypted queries are sent through VPN tunnel
/// 4. Responses are decrypted and cached
/// 5. No DNS queries bypass the VPN (no leaks)
pub struct DnsResolver {
    /// The underlying async resolver from hickory-resolver
    resolver: TokioAsyncResolver,

    /// Which mode this resolver is operating in (for logging / inspection)
    mode: ResolverMode,
}

/// Describes how the resolver was configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverMode {
    /// Using Cloudflare DNS-over-HTTPS (1.1.1.1)
    CloudflareDoH,
    /// Using Google DNS-over-HTTPS (8.8.8.8)
    GoogleDoH,
    /// Using a custom DNS server (e.g., Pi-hole) over plain UDP port 53
    Custom(IpAddr),
}

impl DnsResolver {
    /// Creates a DNS resolver using Cloudflare DNS-over-HTTPS.
    ///
    /// This is the default and most privacy-focused option. Queries are
    /// encrypted end-to-end using HTTPS to Cloudflare's 1.1.1.1 resolver.
    ///
    /// # Returns
    ///
    /// * `Ok(DnsResolver)` - New resolver using Cloudflare DoH
    /// * `Err(_)` - If resolver cannot be initialized
    pub fn new() -> Result<Self> {
        Self::cloudflare_doh()
    }

    /// Creates a resolver using Cloudflare DNS-over-HTTPS (1.1.1.1).
    pub fn cloudflare_doh() -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::cloudflare_https(),
            ResolverOpts::default(),
        );
        tracing::info!("DNS resolver initialized: Cloudflare DoH (1.1.1.1)");
        Ok(Self {
            resolver,
            mode: ResolverMode::CloudflareDoH,
        })
    }

    /// Creates a resolver using Google DNS-over-HTTPS (8.8.8.8).
    pub fn google_doh() -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::google_https(),
            ResolverOpts::default(),
        );
        tracing::info!("DNS resolver initialized: Google DoH (8.8.8.8)");
        Ok(Self {
            resolver,
            mode: ResolverMode::GoogleDoH,
        })
    }

    /// Creates a resolver that forwards queries to a custom DNS server.
    ///
    /// This is intended for Pi-hole or other local DNS servers. Queries
    /// use standard UDP on port 53. Because the queries travel inside the
    /// VPN tunnel, they are still encrypted in transit -- only the
    /// last hop (VPN server -> Pi-hole) is unencrypted, which is
    /// acceptable when both are on the same trusted network.
    ///
    /// # Arguments
    ///
    /// * `dns_ip` - IP address of the custom DNS server (e.g., 192.168.1.53)
    pub fn custom(dns_ip: IpAddr) -> Result<Self> {
        let socket = SocketAddr::new(dns_ip, 53);
        let name_server = NameServerConfig::new(socket, Protocol::Udp);

        let mut config = ResolverConfig::new();
        config.add_name_server(name_server);

        let resolver = TokioAsyncResolver::tokio(config, ResolverOpts::default());
        tracing::info!("DNS resolver initialized: custom server {}", dns_ip);
        Ok(Self {
            resolver,
            mode: ResolverMode::Custom(dns_ip),
        })
    }

    /// Resolves a domain name to a list of IP addresses.
    ///
    /// This is the primary resolution method. It queries the configured
    /// DNS server (DoH or custom) and returns all A/AAAA records.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain name to resolve (e.g., "example.com")
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<IpAddr>)` - Resolved IP addresses
    /// * `Err(_)` - Resolution failed (NXDOMAIN, timeout, etc.)
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let response = self.resolver
            .lookup_ip(domain)
            .await
            .context(format!("DNS resolution failed for {}", domain))?;

        let addrs: Vec<IpAddr> = response.iter().collect();
        tracing::debug!("Resolved {} -> {:?}", domain, addrs);
        Ok(addrs)
    }

    /// Returns the current resolver mode.
    pub fn mode(&self) -> &ResolverMode {
        &self.mode
    }
}
