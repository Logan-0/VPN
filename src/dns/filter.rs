//! # DNS Filter Module
//!
//! This module handles DNS query filtering to block access to known
//! malicious domains, advertisements, and tracking servers.
//!
//! ## Networking Concepts
//!
/// ### DNS Filtering
///
/// DNS filtering intercepts DNS queries and checks them against blocklists
/// before allowing the query to proceed. This prevents access to:
///
/// - **Malware domains**: Known malicious websites
/// - **Advertisement servers**: Ad tracking and delivery
/// - **Tracking domains**: Analytics and user tracking
/// - **Phishing sites**: Fraudulent websites
///
/// ### How DNS Filtering Works
///
/// ```text
/// User enters URL in browser
///     ↓
/// Browser needs to resolve domain to IP
///     ↓
/// DNS query sent to DNS resolver
///     ↓
/// DNS Filter intercepts query
///     ↓
/// Check domain against blocklist
///     ↓
/// If blocked: Return 0.0.0.0 (blocked)
/// If allowed: Forward to real DNS server
/// ```
///
/// ### Blocklist Sources
///
/// Common blocklist sources include:
/// - AdGuard DNS filter
/// - Steven Black's hosts file
/// - EasyList
/// - MalwareDomainList
/// - User-defined custom lists
///
/// ### Integration with VPN
///
/// DNS filtering integrates with the VPN by:
/// 1. Intercepting DNS queries before they leave the TUN device
/// 2. Checking queries against blocklists
/// 3. Using DNS-over-HTTPS (DoH) for encrypted DNS queries
/// 4. Preventing DNS leaks by routing all DNS through VPN

use anyhow::Result;
use std::collections::HashSet;
use std::net::IpAddr;

/// DNS filtering mode that determines how queries are handled.
///
/// ## Pi-hole Integration
///
/// When a Pi-hole is present on the local network (e.g., at 192.168.1.53),
/// the VPN client can operate in `ExternalDns` mode. In this mode, all DNS
/// queries are forwarded to the Pi-hole instead of being filtered locally.
/// This avoids double-filtering and lets the Pi-hole's richer blocklists,
/// logging dashboard, and whitelisting features take precedence.
///
/// The VPN still encrypts the tunnel traffic -- only the DNS filtering
/// responsibility shifts to the external server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsFilterMode {
    /// Built-in filtering using local blocklist HashSet.
    BuiltIn,

    /// Delegate filtering to an external DNS server (e.g., Pi-hole).
    /// All queries are forwarded to this address unfiltered by the VPN.
    /// The external server is responsible for blocking.
    ExternalDns(IpAddr),

    /// No filtering at all -- pass every query through.
    Disabled,
}

/// DNS Query Filter
///
/// Intercepts and filters DNS queries to block access to known
/// malicious domains, advertisements, and tracking servers.
///
/// ## Networking Relevance
///
/// The DNS filter:
/// - Intercepts DNS queries before they reach the network
/// - Checks domain names against blocklists
/// - Blocks queries to malicious/advertising domains
/// - Returns 0.0.0.0 for blocked domains (null routing)
/// - Allows queries to legitimate domains
///
/// ## Pi-hole Compatibility
///
/// When `mode` is set to `ExternalDns`, the filter's `is_blocked()` always
/// returns `false`, and the resolver should forward queries to the Pi-hole
/// address instead. This lets users who already run a Pi-hole benefit from
/// its dashboard and custom lists without interference from the VPN's
/// built-in filter.
///
/// ## Integration with VPN
///
/// When VPN is active:
/// 1. DNS queries are intercepted at TUN device level
/// 2. DNS filter checks each query against blocklists
/// 3. Allowed queries are sent via DNS-over-HTTPS (encrypted)
/// 4. Blocked queries return 0.0.0.0 (blocked)
/// 5. All DNS traffic goes through VPN tunnel (no leaks)
pub struct DnsFilter {
    /// Set of blocked domain names (lowercase, fully-qualified without trailing dot)
    blocked_domains: HashSet<String>,

    /// Current filtering mode
    mode: DnsFilterMode,
}

impl DnsFilter {
    /// Creates a new DNS filter with the built-in blocklist.
    ///
    /// Loads a default set of blocked domains covering common ad-serving,
    /// tracking, and malware domains. Additional domains can be added at
    /// runtime via `add_blocked_domain()` or by loading a hosts-format file
    /// with `load_hosts_file()`.
    ///
    /// # Returns
    ///
    /// * `Ok(DnsFilter)` - New DNS filter instance with default blocklist
    /// * `Err(_)` - If initialization fails
    pub fn new() -> Result<Self> {
        let mut filter = Self {
            blocked_domains: HashSet::new(),
            mode: DnsFilterMode::BuiltIn,
        };

        filter.load_default_blocklist();
        tracing::info!("DNS filter initialized with {} blocked domains", filter.blocked_domains.len());
        Ok(filter)
    }

    /// Creates a DNS filter that delegates to an external DNS server.
    ///
    /// In this mode `is_blocked()` always returns `false`. The resolver
    /// layer should forward queries to the provided address (e.g., a
    /// Pi-hole at 192.168.1.53) which performs its own filtering.
    ///
    /// # Arguments
    ///
    /// * `dns_server` - IP address of the external filtering DNS server
    pub fn with_external_dns(dns_server: IpAddr) -> Result<Self> {
        tracing::info!("DNS filter delegating to external server: {}", dns_server);
        Ok(Self {
            blocked_domains: HashSet::new(),
            mode: DnsFilterMode::ExternalDns(dns_server),
        })
    }

    /// Creates a DNS filter in disabled mode (no filtering).
    pub fn disabled() -> Result<Self> {
        tracing::info!("DNS filter disabled");
        Ok(Self {
            blocked_domains: HashSet::new(),
            mode: DnsFilterMode::Disabled,
        })
    }

    /// Checks whether a domain should be blocked.
    ///
    /// When mode is `BuiltIn`, the domain is checked against the local
    /// blocklist HashSet.  Both the exact domain and its parent domains
    /// are checked so that blocking "ads.example.com" also covers
    /// "sub.ads.example.com".
    ///
    /// When mode is `ExternalDns` or `Disabled`, this always returns `false`
    /// because filtering responsibility lies elsewhere.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain name to check (e.g., "ads.example.com")
    ///
    /// # Returns
    ///
    /// `true` if the domain should be blocked, `false` if allowed
    pub fn is_blocked(&self, domain: &str) -> bool {
        match self.mode {
            DnsFilterMode::BuiltIn => {
                let normalized = domain.to_lowercase().trim_end_matches('.').to_string();

                // Check exact match first
                if self.blocked_domains.contains(&normalized) {
                    tracing::debug!("DNS blocked (exact): {}", normalized);
                    return true;
                }

                // Walk parent domains: a.b.example.com -> b.example.com -> example.com
                let mut remaining = normalized.as_str();
                while let Some(pos) = remaining.find('.') {
                    remaining = &remaining[pos + 1..];
                    if self.blocked_domains.contains(remaining) {
                        tracing::debug!("DNS blocked (parent): {} via {}", normalized, remaining);
                        return true;
                    }
                }

                false
            }
            DnsFilterMode::ExternalDns(_) | DnsFilterMode::Disabled => false,
        }
    }

    /// Adds a single domain to the blocklist.
    ///
    /// The domain is normalized to lowercase with no trailing dot.
    pub fn add_blocked_domain(&mut self, domain: &str) {
        let normalized = domain.to_lowercase().trim_end_matches('.').to_string();
        self.blocked_domains.insert(normalized);
    }

    /// Loads a hosts-format blocklist file.
    ///
    /// Hosts files map domains to IP addresses, one per line:
    /// ```text
    /// 0.0.0.0 ads.example.com
    /// 0.0.0.0 tracking.example.com
    /// # comment lines are ignored
    /// ```
    ///
    /// This is the format used by Pi-hole blocklists, Steven Black's
    /// unified hosts file, and most community blocklists.
    ///
    /// # Arguments
    ///
    /// * `content` - The hosts file content as a string
    ///
    /// # Returns
    ///
    /// Number of domains added from the file
    pub fn load_hosts_file(&mut self, content: &str) -> usize {
        let mut count = 0;
        for line in content.lines() {
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Hosts format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                let domain = parts[1].to_lowercase().trim_end_matches('.').to_string();

                // Skip localhost entries
                if domain == "localhost"
                    || domain == "localhost.localdomain"
                    || domain == "local"
                    || domain == "broadcasthost"
                {
                    continue;
                }

                self.blocked_domains.insert(domain);
                count += 1;
            }
        }
        tracing::info!("Loaded {} domains from hosts file", count);
        count
    }

    /// Returns the current filtering mode.
    pub fn mode(&self) -> &DnsFilterMode {
        &self.mode
    }

    /// Sets a new filtering mode.
    pub fn set_mode(&mut self, mode: DnsFilterMode) {
        tracing::info!("DNS filter mode changed to: {:?}", mode);
        self.mode = mode;
    }

    /// Returns the number of domains in the blocklist.
    pub fn blocked_domain_count(&self) -> usize {
        self.blocked_domains.len()
    }

    /// Populates the blocklist with a default set of well-known ad,
    /// tracking, and malware domains. This provides baseline protection
    /// without requiring the user to supply an external blocklist file.
    fn load_default_blocklist(&mut self) {
        let defaults = [
            // Ad networks
            "doubleclick.net",
            "googlesyndication.com",
            "googleadservices.com",
            "google-analytics.com",
            "googletagmanager.com",
            "googletagservices.com",
            "pagead2.googlesyndication.com",
            "adservice.google.com",
            // Facebook tracking
            "pixel.facebook.com",
            "analytics.facebook.com",
            // Common ad/tracking domains
            "ads.yahoo.com",
            "ad.doubleclick.net",
            "adnxs.com",
            "adsrvr.org",
            "adsymptotic.com",
            "adtechus.com",
            "advertising.com",
            "scorecardresearch.com",
            "taboola.com",
            "outbrain.com",
            "criteo.com",
            "rubiconproject.com",
            "pubmatic.com",
            "casalemedia.com",
            // Telemetry
            "telemetry.microsoft.com",
            "vortex.data.microsoft.com",
            "settings-win.data.microsoft.com",
            // Malware / phishing (samples)
            "malware-check.disconnect.me",
        ];

        for domain in &defaults {
            self.blocked_domains.insert(domain.to_string());
        }
    }
}
