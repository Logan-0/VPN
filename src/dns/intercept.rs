//! # DNS Interception at the TUN Layer
//!
//! This module inspects raw IPv4 packets coming out of the TUN device,
//! detects DNS queries, and either lets them pass through (default) or
//! synthesises an immediate "blocked" response for domains that match
//! the user's blocklist.
//!
//! ## Why Intercept Here Instead of Above the OS?
//!
//! Browsers, system resolvers, and individual programs all bypass any
//! library-level DNS wrapper we could install. The only place every UDP
//! packet must pass through is the TUN device, where we already have a
//! read loop. Filtering at the TUN layer therefore covers 100% of the
//! traffic the VPN sees, regardless of which application produced it.
//!
//! ## What We Do
//!
//! For each outbound packet read from the TUN device:
//!
//! 1. Inspect the IP/UDP headers cheaply -- if it's not IPv4 + UDP +
//!    `dst port == 53`, return `None` immediately (the packet flows
//!    through the tunnel as before).
//! 2. Parse just enough of the DNS message to extract the first
//!    question's QNAME.
//! 3. Ask [`DnsFilter::is_blocked`] whether to drop the query.
//! 4. If blocked, synthesise a DNS response with `RCODE=NoError` and a
//!    single `A` answer pointing to `0.0.0.0`. The browser interprets
//!    that as "host unreachable" and gives up cleanly.
//! 5. Wrap the DNS response in a UDP datagram (ports swapped) and an
//!    IPv4 packet (addresses swapped, fresh checksums).
//!
//! ## Why `A` -> `0.0.0.0` Instead of `NXDOMAIN`?
//!
//! `NXDOMAIN` is technically more correct ("this name does not exist"),
//! but many browsers and OS resolvers cache `NXDOMAIN` aggressively,
//! including across DNS server changes. `0.0.0.0` is the long-standing
//! Pi-hole convention: short TTL, no caching surprises, and the
//! connection attempt fails fast at the socket layer.
//!
//! ## Scope Limits
//!
//! - **IPv4 only.** IPv6 DNS queries (AAAA records over IPv6 transport)
//!   are passed through unmodified. Adding IPv6 support is straightforward
//!   but adds another set of headers to parse and is not needed for the
//!   minimum viable ad-blocking feature.
//! - **Single question.** The DNS protocol allows multiple questions per
//!   message but in practice every query contains exactly one. We bail
//!   out (pass through) on multi-question messages.
//! - **A and AAAA queries only.** Other record types (TXT, MX, SRV) are
//!   not blocklist-matched -- they pass through to the upstream resolver
//!   inside the VPN tunnel.

use crate::dns::filter::DnsFilter;

/// DNS protocol constants
pub const DNS_TYPE_A: u16 = 1;       // Type A: IPv4 address
pub const DNS_TYPE_AAAA: u16 = 28;   // Type AAAA: IPv6 address
pub const DNS_CLASS_IN: u16 = 1;     // Class IN: Internet
pub const DNS_PORT: u16 = 53;        // Standard DNS port
pub const IP_PROTOCOL_UDP: u8 = 17;  // UDP protocol number

/// TTL we attach to synthesised block responses, in seconds.
///
/// Short enough that an unblock takes effect within a minute, long enough
/// to spare the resolver from re-querying on every browser request.
const BLOCK_RESPONSE_TTL: u32 = 60;

/// Outcome of inspecting a single outbound packet.
///
/// `None` means "this packet is not a DNS query we want to intercept --
/// pass it through the tunnel unchanged". `Some(bytes)` is a fully formed
/// IPv4 + UDP + DNS reply that should be written *back* to the TUN device
/// so the originating application sees it as if a real resolver answered.
pub type InterceptResult = Option<Vec<u8>>;

/// Inspects an outbound IPv4 packet and, if it is a DNS query for a
/// blocked domain, builds the synthetic "blocked" reply.
///
/// ## Arguments
///
/// - `packet`: raw bytes as read from the TUN device. Includes the IPv4
///   header, the UDP header, and the DNS message.
/// - `filter`: the active blocklist. The borrow is shared (`&`) so the
///   caller does not need to clone or lock for every packet.
///
/// ## Returns
///
/// - `None` -- the packet is not an IPv4/UDP/53 DNS query, the QNAME is
///   not on the blocklist, or parsing failed at any step. The caller
///   should send the original packet through `Tunnel::encapsulate` as
///   usual.
/// - `Some(reply_bytes)` -- a fully formed IPv4 + UDP + DNS response to
///   write back into the TUN device. The caller must NOT pass these
///   bytes through `encapsulate`; they short-circuit the VPN entirely.
///
/// ## Performance
///
/// All checks short-circuit on the cheap path. A non-DNS UDP packet costs
/// at most ~20 bytes of header inspection plus one comparison. The
/// allocation only happens on the rare case of an actually blocked
/// domain.
pub fn try_block_dns_query(packet: &[u8], filter: &DnsFilter) -> InterceptResult {
    // ── Step 1: IPv4 header sanity ─────────────────────────────────────────
    // Need at minimum 20 bytes for a header with no options.
    if packet.len() < 20 {
        return None;
    }
    // High nibble of byte 0 is the IP version; we only handle IPv4.
    if packet[0] >> 4 != 4 {
        return None;
    }
    // Low nibble is the IHL (Internet Header Length) in 32-bit words.
    // Total header length in bytes = IHL * 4. Min legal value is 5 (=20).
    let ihl = (packet[0] & 0x0F) as usize;
    let ip_header_len = ihl * 4;
    if ip_header_len < 20 || packet.len() < ip_header_len + 8 {
        return None;
    }
    // Byte 9 is the protocol number; only UDP carries DNS by default.
    if packet[9] != IP_PROTOCOL_UDP {
        return None;
    }

    // Source/destination IPv4 addresses (used to swap when building reply).
    let src_ip: [u8; 4] = packet[12..16].try_into().ok()?;
    let dst_ip: [u8; 4] = packet[16..20].try_into().ok()?;

    // ── Step 2: UDP header ────────────────────────────────────────────────
    let udp = &packet[ip_header_len..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if dst_port != DNS_PORT {
        return None;
    }
    // UDP length covers the UDP header + payload. Guard against a
    // truncated packet that claims a longer length than it actually has.
    if udp_len < 8 || ip_header_len + udp_len > packet.len() {
        return None;
    }

    // ── Step 3: DNS message ───────────────────────────────────────────────
    let dns = &udp[8..udp_len];
    if dns.len() < 12 {
        return None;
    }
    // DNS header: id(2) + flags(2) + qdcount(2) + ancount(2) + nscount(2) + arcount(2)
    let qdcount = u16::from_be_bytes([dns[4], dns[5]]);
    // Real-world DNS clients send exactly one question per message. We
    // bail on anything else so we don't have to construct multi-answer
    // replies or deal with weird nameserver test suites.
    if qdcount != 1 {
        return None;
    }
    // Flags byte 0, top bit (0x80) = QR. We only intercept queries (QR=0).
    if dns[2] & 0x80 != 0 {
        return None;
    }

    // Parse the first question: QNAME (variable length, label-encoded),
    // then QTYPE (2 bytes) and QCLASS (2 bytes).
    let (qname, after_name_offset) = parse_qname(dns, 12)?;
    if dns.len() < after_name_offset + 4 {
        return None;
    }
    let qtype = u16::from_be_bytes([dns[after_name_offset], dns[after_name_offset + 1]]);
    let qclass = u16::from_be_bytes([
        dns[after_name_offset + 2],
        dns[after_name_offset + 3],
    ]);
    // Only block A/AAAA queries in the IN class -- other types (TXT, MX,
    // SRV, etc.) are rare and blocking them risks breaking applications
    // that legitimately query for them.
    if qclass != DNS_CLASS_IN {
        return None;
    }
    if qtype != DNS_TYPE_A && qtype != DNS_TYPE_AAAA {
        return None;
    }

    // ── Step 4: blocklist check ───────────────────────────────────────────
    if !filter.is_blocked(&qname) {
        return None;
    }

    tracing::info!("DNS blocked at TUN layer: {}", qname);

    // ── Step 5: build the synthetic reply ─────────────────────────────────
    // Reuse the original DNS bytes up through the question section because
    // the question is echoed verbatim in every well-formed response. The
    // answer section is appended fresh.
    let dns_question_end = after_name_offset + 4;
    let dns_reply = build_dns_block_reply(&dns[..dns_question_end], qtype);

    // Wrap in a fresh UDP header (ports swapped, length recalculated).
    let udp_reply = build_udp_segment(dst_port, src_port, &dns_reply, &dst_ip, &src_ip);

    // Wrap in a fresh IPv4 header (addresses swapped, total length and
    // header checksum recalculated, identification set to 0 since we are
    // not generating a fragmented packet).
    let ip_reply = build_ipv4_packet(&dst_ip, &src_ip, IP_PROTOCOL_UDP, &udp_reply);

    Some(ip_reply)
}

/// Parses a DNS QNAME at `dns[offset..]` and returns the decoded domain
/// (lowercase, dot-separated) along with the offset just past the
/// terminating zero label.
///
/// Returns `None` for malformed names: pointer compression in the
/// question section (technically allowed but never seen in practice and
/// risky to follow), labels longer than 63 bytes, or a name that runs
/// past the end of the buffer.
///
/// ## Why no compression support?
///
/// RFC 1035 says compression pointers in the *question* section are
/// invalid -- they only appear in answer/authority/additional sections.
/// Following them here would also enable a denial-of-service vector
/// (pointer loops) so we explicitly reject them.
pub fn parse_qname(dns: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    loop {
        if offset >= dns.len() {
            return None;
        }
        let len = dns[offset] as usize;
        if len == 0 {
            // Terminating zero label.
            return Some((name, offset + 1));
        }
        // Top two bits set = compression pointer; reject (see doc above).
        if len & 0xC0 != 0 {
            return None;
        }
        if len > 63 || offset + 1 + len > dns.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        // Labels are case-insensitive; normalize to lowercase so the
        // blocklist lookup matches regardless of the client's casing.
        for &b in &dns[offset + 1..offset + 1 + len] {
            name.push(b.to_ascii_lowercase() as char);
        }
        offset += 1 + len;
    }
}

/// Builds a DNS response payload that says "this name does not resolve
/// to anything routable".
///
/// The answer is a single A record pointing to `0.0.0.0` (or AAAA to
/// `::` for IPv6 queries). The question section is taken from
/// `query_with_question` unchanged.
fn build_dns_block_reply(query_with_question: &[u8], qtype: u16) -> Vec<u8> {
    let mut reply = Vec::with_capacity(query_with_question.len() + 32);
    reply.extend_from_slice(query_with_question);

    // Overwrite the flags field to mark this as a response with no error.
    //
    //   bit 15:    QR    = 1 (response)
    //   bit 11-14: opcode = 0 (standard query, copied in)
    //   bit 10:    AA    = 0
    //   bit 9:     TC    = 0
    //   bit 8:     RD    = preserved from query
    //   bit 7:     RA    = 1 (recursion available -- we pretend to be a real
    //                       resolver so clients don't fall back to TCP)
    //   bit 0-3:   RCODE = 0 (no error)
    //
    // We preserve the RD bit from the original query so loopback tests
    // (`dig +norecurse`) see consistent behaviour.
    let original_rd = reply[2] & 0x01;
    reply[2] = 0x80 | original_rd;
    reply[3] = 0x80; // RA=1, RCODE=0

    // ANCOUNT = 1, leave NSCOUNT/ARCOUNT at 0.
    reply[6] = 0;
    reply[7] = 1;

    // Append the answer.
    //   NAME: 0xC00C is a compression pointer to offset 12 (start of the
    //         question name). This is the standard idiom and saves us
    //         from re-encoding the QNAME.
    reply.extend_from_slice(&[0xC0, 0x0C]);
    reply.extend_from_slice(&qtype.to_be_bytes());
    reply.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    reply.extend_from_slice(&BLOCK_RESPONSE_TTL.to_be_bytes());
    if qtype == DNS_TYPE_AAAA {
        reply.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
        reply.extend_from_slice(&[0u8; 16]); // RDATA: ::
    } else {
        reply.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        reply.extend_from_slice(&[0u8; 4]); // RDATA: 0.0.0.0
    }
    reply
}

/// Wraps a DNS payload in a UDP segment, computing the checksum over the
/// IPv4 pseudo-header.
///
/// The pseudo-header is the source IP, destination IP, zero, the protocol
/// number, and the UDP length -- it is checksummed but not transmitted.
/// This is what binds the UDP checksum to the IP layer.
pub fn build_udp_segment(
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
) -> Vec<u8> {
    let total_len = (8 + payload.len()) as u16;
    let mut seg = Vec::with_capacity(total_len as usize);
    seg.extend_from_slice(&src_port.to_be_bytes());
    seg.extend_from_slice(&dst_port.to_be_bytes());
    seg.extend_from_slice(&total_len.to_be_bytes());
    seg.extend_from_slice(&[0, 0]); // checksum placeholder
    seg.extend_from_slice(payload);

    // ── Pseudo-header for checksum ─────────────────────────────────────────
    // We assemble the bytes the checksum is supposed to cover:
    //   src ip (4) + dst ip (4) + 0 + proto (1) + udp length (2)
    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(src_ip);
    pseudo.extend_from_slice(dst_ip);
    pseudo.push(0);
    pseudo.push(IP_PROTOCOL_UDP);
    pseudo.extend_from_slice(&total_len.to_be_bytes());

    let checksum = ones_complement_sum(&pseudo, &seg);
    // RFC 768 says a UDP checksum of zero means "no checksum"; if our
    // computed value happens to be zero, send 0xFFFF instead so the
    // receiver still validates it.
    let checksum = if checksum == 0 { 0xFFFF } else { checksum };
    seg[6..8].copy_from_slice(&checksum.to_be_bytes());
    seg
}

/// Wraps a transport-layer payload (UDP segment, in our case) in an IPv4
/// packet, computing the IP header checksum.
///
/// Identification is set to 0 because we never fragment our synthetic
/// replies (they fit in a single 1500-byte MTU). TTL is fixed at 64
/// which is the Linux default.
pub fn build_ipv4_packet(
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    protocol: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = (20 + payload.len()) as u16;
    let mut hdr = [0u8; 20];
    hdr[0] = 0x45; // Version=4, IHL=5
    hdr[1] = 0;    // DSCP/ECN: best effort
    hdr[2..4].copy_from_slice(&total_len.to_be_bytes());
    hdr[4..6].copy_from_slice(&[0, 0]); // identification
    hdr[6..8].copy_from_slice(&[0x40, 0]); // flags=DF, fragment offset=0
    hdr[8] = 64; // TTL
    hdr[9] = protocol;
    // hdr[10..12] = checksum, computed below
    hdr[12..16].copy_from_slice(src_ip);
    hdr[16..20].copy_from_slice(dst_ip);

    let checksum = ones_complement_sum(&hdr, &[]);
    hdr[10..12].copy_from_slice(&checksum.to_be_bytes());

    let mut packet = Vec::with_capacity(total_len as usize);
    packet.extend_from_slice(&hdr);
    packet.extend_from_slice(payload);
    packet
}

/// Computes the standard Internet 16-bit one's-complement checksum over
/// the concatenation of two byte slices.
///
/// The checksum is a 1's-complement sum of 16-bit big-endian words; the
/// result is the one's complement of the final sum.
pub fn ones_complement_sum(header: &[u8], data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let combined_len = header.len() + data.len();

    // Walk the two slices as one logical stream of 16-bit words.
    let byte = |i: usize| -> u8 {
        if i < header.len() {
            header[i]
        } else {
            data[i - header.len()]
        }
    };

    let mut i = 0;
    while i + 1 < combined_len {
        sum += u32::from(u16::from_be_bytes([byte(i), byte(i + 1)]));
        i += 2;
    }
    if i < combined_len {
        // Odd byte: treat as the high byte of a 16-bit word with low byte 0.
        sum += u32::from(byte(i)) << 8;
    }
    // Fold any 32-bit overflow into the low 16 bits.
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
