//! DNS Interception Tests
//!
//! Tests for DNS query interception and filtering.

use rust_vpn::dns::intercept::{try_block_dns_query, build_udp_segment, build_ipv4_packet, IP_PROTOCOL_UDP, parse_qname, ones_complement_sum};
use rust_vpn::dns::filter::DnsFilter;

fn make_dns_query(qname: &str) -> Vec<u8> {
    use rust_vpn::dns::intercept::{DNS_TYPE_A, DNS_CLASS_IN, DNS_PORT};
    
    let mut dns = Vec::new();
    dns.extend_from_slice(&[0x12, 0x34]);
    dns.extend_from_slice(&[0x01, 0x00]);
    dns.extend_from_slice(&[0x00, 0x01]);
    dns.extend_from_slice(&[0x00, 0x00]);
    dns.extend_from_slice(&[0x00, 0x00]);
    dns.extend_from_slice(&[0x00, 0x00]);
    for label in qname.split('.') {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0);
    dns.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    dns.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

    let udp = build_udp_segment(
        54321, DNS_PORT, &dns,
        &[10, 8, 0, 2], &[1, 1, 1, 1],
    );
    build_ipv4_packet(&[10, 8, 0, 2], &[1, 1, 1, 1], IP_PROTOCOL_UDP, &udp)
}

#[test]
fn passes_through_non_ip_packets() {
    let mut filter = DnsFilter::new().unwrap();
    filter.add_blocked_domain("ads.example.com");
    assert!(try_block_dns_query(&[0u8; 4], &filter).is_none());
}

#[test]
fn passes_through_non_udp_packets() {
    let mut filter = DnsFilter::new().unwrap();
    filter.add_blocked_domain("ads.example.com");
    let mut pkt = vec![0x45u8; 28];
    pkt[9] = 6;
    assert!(try_block_dns_query(&pkt, &filter).is_none());
}

#[test]
fn passes_through_non_dns_udp_packets() {
    use rust_vpn::dns::intercept::{DNS_TYPE_A, DNS_CLASS_IN, DNS_PORT};
    
    let mut filter = DnsFilter::new().unwrap();
    filter.add_blocked_domain("ads.example.com");
    let dns_like = vec![0u8; 12];
    let udp = build_udp_segment(
        12345, 80, &dns_like,
        &[10, 8, 0, 2], &[1, 1, 1, 1],
    );
    let pkt = build_ipv4_packet(&[10, 8, 0, 2], &[1, 1, 1, 1], IP_PROTOCOL_UDP, &udp);
    assert!(try_block_dns_query(&pkt, &filter).is_none());
}

#[test]
fn passes_through_unblocked_dns_query() {
    let filter = DnsFilter::new().unwrap();
    let pkt = make_dns_query("example.com");
    assert!(try_block_dns_query(&pkt, &filter).is_none());
}

#[test]
fn blocks_listed_domain() {
    let mut filter = DnsFilter::new().unwrap();
    filter.add_blocked_domain("ads.example.com");
    let pkt = make_dns_query("ads.example.com");
    let reply = try_block_dns_query(&pkt, &filter).expect("should block");

    assert_eq!(reply[0] >> 4, 4, "IPv4 version");
    assert_eq!(reply[9], IP_PROTOCOL_UDP, "UDP protocol");
    assert_eq!(&reply[12..16], &[1, 1, 1, 1]);
    assert_eq!(&reply[16..20], &[10, 8, 0, 2]);

    let dns = &reply[28..];
    assert!(dns[2] & 0x80 != 0, "QR bit set");
    assert_eq!(u16::from_be_bytes([dns[6], dns[7]]), 1);
}

#[test]
fn blocks_via_parent_domain() {
    let mut filter = DnsFilter::new().unwrap();
    filter.add_blocked_domain("doubleclick.net");
    let pkt = make_dns_query("ad.doubleclick.net");
    assert!(try_block_dns_query(&pkt, &filter).is_some());
}

#[test]
fn parse_qname_handles_lowercase_normalization() {
    let mut dns = vec![0u8; 12];
    for label in ["EXAMPLE", "COM"] {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0);
    let (name, _) = parse_qname(&dns, 12).unwrap();
    assert_eq!(name, "example.com");
}

#[test]
fn parse_qname_rejects_compression_pointer() {
    let mut dns = vec![0u8; 12];
    dns.extend_from_slice(&[0xC0, 0x0C]);
    assert!(parse_qname(&dns, 12).is_none());
}

#[test]
fn ones_complement_zero_input_is_ffff() {
    assert_eq!(ones_complement_sum(&[], &[]), 0xFFFF);
}
