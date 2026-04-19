//! # DNS Filter Unit Tests
//!
//! Tests for the DNS query filtering system including:
//! - Default blocklist loading
//! - Exact domain matching
//! - Parent domain (wildcard) matching
//! - Hosts file parsing
//! - Pi-hole / external DNS passthrough mode
//! - Disabled mode

use rust_vpn::dns::filter::{DnsFilter, DnsFilterMode};
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Default blocklist tests
// ---------------------------------------------------------------------------

#[test]
fn test_default_blocklist_loads() {
    let filter = DnsFilter::new().unwrap();
    assert!(
        filter.blocked_domain_count() > 0,
        "Default blocklist should contain domains"
    );
}

#[test]
fn test_known_ad_domain_blocked() {
    let filter = DnsFilter::new().unwrap();
    assert!(filter.is_blocked("doubleclick.net"));
    assert!(filter.is_blocked("googleadservices.com"));
    assert!(filter.is_blocked("taboola.com"));
}

#[test]
fn test_legitimate_domain_allowed() {
    let filter = DnsFilter::new().unwrap();
    assert!(!filter.is_blocked("example.com"));
    assert!(!filter.is_blocked("rust-lang.org"));
    assert!(!filter.is_blocked("github.com"));
}

// ---------------------------------------------------------------------------
// Domain matching behavior
// ---------------------------------------------------------------------------

#[test]
fn test_case_insensitive_matching() {
    let filter = DnsFilter::new().unwrap();
    assert!(filter.is_blocked("DoubleClick.Net"));
    assert!(filter.is_blocked("DOUBLECLICK.NET"));
}

#[test]
fn test_trailing_dot_normalized() {
    let filter = DnsFilter::new().unwrap();
    // FQDN with trailing dot should still match
    assert!(filter.is_blocked("doubleclick.net."));
}

#[test]
fn test_subdomain_blocked_via_parent() {
    let filter = DnsFilter::new().unwrap();
    // "doubleclick.net" is blocked, so subdomains should be too
    assert!(filter.is_blocked("ad.doubleclick.net"));
    assert!(filter.is_blocked("deep.sub.doubleclick.net"));
}

#[test]
fn test_partial_name_not_blocked() {
    let filter = DnsFilter::new().unwrap();
    // "notdoubleclick.net" should NOT be blocked just because
    // "doubleclick.net" is in the blocklist
    assert!(!filter.is_blocked("notdoubleclick.net"));
}

// ---------------------------------------------------------------------------
// Manual domain addition
// ---------------------------------------------------------------------------

#[test]
fn test_add_custom_domain() {
    let mut filter = DnsFilter::new().unwrap();
    assert!(!filter.is_blocked("custom-bad-site.com"));

    filter.add_blocked_domain("custom-bad-site.com");
    assert!(filter.is_blocked("custom-bad-site.com"));
    assert!(filter.is_blocked("sub.custom-bad-site.com"));
}

// ---------------------------------------------------------------------------
// Hosts file parsing
// ---------------------------------------------------------------------------

#[test]
fn test_load_hosts_file_basic() {
    let mut filter = DnsFilter::disabled().unwrap();
    filter.set_mode(DnsFilterMode::BuiltIn);

    let hosts_content = "\
# Sample blocklist
0.0.0.0 ads.example.com
0.0.0.0 tracking.example.com
127.0.0.1 malware.example.com
# Comment line
0.0.0.0 localhost
";

    let count = filter.load_hosts_file(hosts_content);
    assert_eq!(count, 3, "Should load 3 domains (localhost skipped)");
    assert!(filter.is_blocked("ads.example.com"));
    assert!(filter.is_blocked("tracking.example.com"));
    assert!(filter.is_blocked("malware.example.com"));
    assert!(!filter.is_blocked("localhost"));
}

#[test]
fn test_load_hosts_file_empty_lines_and_comments() {
    let mut filter = DnsFilter::disabled().unwrap();
    filter.set_mode(DnsFilterMode::BuiltIn);

    let hosts_content = "\
# Full comment line

    # Indented comment

0.0.0.0 single-domain.com
";

    let count = filter.load_hosts_file(hosts_content);
    assert_eq!(count, 1);
}

// ---------------------------------------------------------------------------
// Pi-hole / External DNS mode
// ---------------------------------------------------------------------------

#[test]
fn test_external_dns_mode_allows_everything() {
    let pihole_ip: IpAddr = "192.168.1.53".parse().unwrap();
    let filter = DnsFilter::with_external_dns(pihole_ip).unwrap();

    // In external DNS mode, the filter defers to the Pi-hole
    assert!(!filter.is_blocked("doubleclick.net"));
    assert!(!filter.is_blocked("malware.example.com"));
    assert_eq!(
        *filter.mode(),
        DnsFilterMode::ExternalDns(pihole_ip)
    );
}

#[test]
fn test_disabled_mode_allows_everything() {
    let filter = DnsFilter::disabled().unwrap();
    assert!(!filter.is_blocked("doubleclick.net"));
    assert_eq!(*filter.mode(), DnsFilterMode::Disabled);
}

#[test]
fn test_switch_mode_at_runtime() {
    let mut filter = DnsFilter::new().unwrap();
    assert!(filter.is_blocked("doubleclick.net"));

    // Switch to external DNS (Pi-hole)
    let pihole_ip: IpAddr = "192.168.1.53".parse().unwrap();
    filter.set_mode(DnsFilterMode::ExternalDns(pihole_ip));
    assert!(!filter.is_blocked("doubleclick.net"));

    // Switch back to built-in
    filter.set_mode(DnsFilterMode::BuiltIn);
    assert!(filter.is_blocked("doubleclick.net"));
}
