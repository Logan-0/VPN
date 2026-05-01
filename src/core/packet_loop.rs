//! # Packet Processing Loop
//!
//! This module implements the main packet processing loop that bridges
//! the TUN device with the UDP socket to the VPN server.
//!
//! ## Data Flow
//!
//! ```text
//! ┌──────────────┐        ┌────────────────┐        ┌──────────┐
//! │  Application │        │  Packet Loop   │        │   VPN    │
//! │   Traffic    │        │                │        │  Server  │
//! │              │        │  TUN ──► Encrypt│        │          │
//! │  Browser,    ├───────►│  Read   ──► UDP ├───────►│  Decrypt │
//! │  curl, etc.  │        │  Send         │        │  Forward │
//! │              │◄───────┤               │◄───────┤          │
//! │              │        │  UDP ──► Decrypt│        │  Encrypt │
//! │              │        │  Recv   ──► TUN │        │  Return  │
//! └──────────────┘        │  Write        │        └──────────┘
//!                         │               │
//!                         │  Keepalive    │
//!                         │  Timer ──► UDP │
//!                         └────────────────┘
//! ```
//!
//! ## How the Loop Works
//!
//! The packet loop uses `tokio::select!` to concurrently handle three events:
//!
//! 1. **Outgoing traffic (TUN -> UDP)**:
//!    - A packet arrives on the TUN device (an app sent data)
//!    - The packet is encrypted with `Tunnel::encapsulate()`
//!    - The encrypted packet is sent over UDP to the VPN server
//!
//! 2. **Incoming traffic (UDP -> TUN)**:
//!    - An encrypted packet arrives from the VPN server
//!    - The packet is decrypted with `Tunnel::decapsulate()`
//!    - The decrypted packet is written to the TUN device
//!    - The OS delivers it to the destination application
//!
//! 3. **Keepalive timer**:
//!    - Every 25 seconds, a keepalive packet is sent to prevent
//!      NAT table timeouts on routers between client and server
//!
//! ## Buffer Sizes
//!
//! - TUN read buffer: 1500 bytes (standard Ethernet MTU)
//! - Encryption overhead: up to 32 bytes (WireGuard header + auth tag)
//! - UDP receive buffer: 1532 bytes (MTU + overhead)
//!
//! ## Error Handling
//!
//! Individual packet errors do NOT crash the loop. Errors are logged
//! and the loop continues processing the next packet. Only a shutdown
//! signal or fatal I/O error terminates the loop.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use nix::libc;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::core::tunnel::Tunnel;
use crate::dns::filter::DnsFilter;
use crate::dns::intercept::try_block_dns_query;

/// Maximum Transmission Unit for the TUN device (standard Ethernet)
const TUN_MTU: usize = 1500;

/// Extra space for WireGuard header + Poly1305 auth tag
const WIREGUARD_OVERHEAD: usize = 32;

/// Keepalive interval in seconds (matches WireGuard default)
const KEEPALIVE_INTERVAL_SECS: u64 = 25;

/// Default batch size for UDP packet batching
const DEFAULT_BATCH_SIZE: usize = 10;

/// Default batch timeout in milliseconds
const DEFAULT_BATCH_TIMEOUT_MS: u64 = 5;

/// Result of running the packet loop -- tells the caller why it stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketLoopExit {
    /// Clean shutdown requested via the stop channel
    Shutdown,
    /// The TUN device encountered a fatal I/O error
    TunError,
    /// The UDP socket encountered a fatal I/O error
    UdpError,
}

/// Runs the main packet processing loop.
///
/// This function blocks until a shutdown signal is received or a fatal
/// error occurs. It should be spawned on its own Tokio task.
///
/// ## Arguments
///
/// * `tunnel` - Shared tunnel instance for encrypt/decrypt (wrapped in
///   `Arc<Mutex>` because the TUN device is synchronous and we use
///   `spawn_blocking` for TUN reads)
/// * `tun_fd` - Raw file descriptor of the TUN device, used for async
///   reads in a blocking thread pool
/// * `server_addr` - UDP endpoint of the VPN server
/// * `stop_rx` - Watch channel receiver; set to `true` to stop the loop
/// * `dns_filter` - Optional ad/malware blocklist applied to outbound
///   DNS queries before encryption. `None` disables DNS interception
///   and every packet is passed through to `encapsulate` as before.
///
/// ## Returns
///
/// `PacketLoopExit` indicating why the loop terminated.
pub async fn run_packet_loop(
    tunnel: Arc<Mutex<Tunnel>>,
    tun_fd: std::os::unix::io::RawFd,
    server_addr: SocketAddr,
    mut stop_rx: watch::Receiver<bool>,
    dns_filter: Option<Arc<DnsFilter>>,
) -> PacketLoopExit {
    info!("Starting packet processing loop -> {}", server_addr);

    // Bind a UDP socket for VPN traffic (OS picks the port)
    let udp = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to bind UDP socket: {}", e);
            return PacketLoopExit::UdpError;
        }
    };

    if let Err(e) = udp.connect(server_addr).await {
        error!("Failed to connect UDP socket to {}: {}", server_addr, e);
        return PacketLoopExit::UdpError;
    }

    info!("UDP socket bound and connected to {}", server_addr);

    let keepalive_interval = tokio::time::Duration::from_secs(KEEPALIVE_INTERVAL_SECS);
    let mut keepalive_timer = tokio::time::interval(keepalive_interval);

    // Channel for TUN reads (synchronous fd -> async world)
    let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    // Spawn a blocking thread to continuously read from the TUN fd
    let tun_read_stop = stop_rx.clone();
    tokio::task::spawn_blocking(move || {
        use std::os::unix::io::FromRawFd;
        // Safety: we duplicate the fd so closing this File won't close the real device
        let dup_fd = unsafe { libc::dup(tun_fd) };
        if dup_fd < 0 {
            error!("Failed to dup TUN file descriptor");
            return;
        }
        let mut file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
        let mut buf = vec![0u8; TUN_MTU];

        loop {
            if *tun_read_stop.borrow() {
                break;
            }
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tun_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break; // receiver dropped
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => {
                    error!("TUN read error: {}", e);
                    break;
                }
            }
        }
    });

    // TUN write helper (synchronous)
    let tun_write_fd = unsafe { libc::dup(tun_fd) };
    let mut tun_writer = unsafe {
        use std::os::unix::io::FromRawFd;
        std::fs::File::from_raw_fd(tun_write_fd)
    };

    // UDP receive buffer
    let mut udp_buf = vec![0u8; TUN_MTU + WIREGUARD_OVERHEAD];

    // Batching configuration
    let batch_size = std::env::var("BATCH_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BATCH_SIZE)
        .max(1);
    let batch_timeout = std::env::var("BATCH_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BATCH_TIMEOUT_MS);

    // Packet buffer for batching
    let mut packet_buffer: Vec<Vec<u8>> = Vec::with_capacity(batch_size);
    let mut batch_timer = tokio::time::interval(Duration::from_millis(batch_timeout));
    batch_timer.tick().await; // Skip first immediate tick

    loop {
        tokio::select! {
            // --- Shutdown signal ---
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    // Flush remaining packets before shutdown
                    if !packet_buffer.is_empty() {
                        flush_packet_buffer(&udp, &packet_buffer).await;
                    }
                    info!("Packet loop received shutdown signal");
                    return PacketLoopExit::Shutdown;
                }
            }

            // --- Batch timeout: flush buffer ---
            _ = batch_timer.tick() => {
                if !packet_buffer.is_empty() {
                    flush_packet_buffer(&udp, &packet_buffer).await;
                    packet_buffer.clear();
                }
            }

            // --- Outgoing: TUN -> Encrypt -> UDP ---
            Some(packet) = tun_rx.recv() => {
                // ── DNS interception ────────────────────────────────
                // Inspect the packet before it is encrypted. If it is a
                // DNS query for a blocked domain we synthesise a reply
                // and write it straight back to the TUN device, skipping
                // the tunnel entirely. The application sees a normal
                // (negative) DNS answer and never connects to the
                // blocked host.
                if let Some(filter) = dns_filter.as_ref() {
                    if let Some(reply) = try_block_dns_query(&packet, filter) {
                        if let Err(e) = tun_writer.write_all(&reply) {
                            warn!("Failed to write blocked DNS reply to TUN: {}", e);
                        } else {
                            debug!("DNS query blocked locally ({} bytes returned)", reply.len());
                        }
                        continue;
                    }
                }

                let mut encrypted = vec![0u8; packet.len() + WIREGUARD_OVERHEAD];
                let send_result = {
                    let mut tun_lock = match tunnel.lock() {
                        Ok(t) => t,
                        Err(e) => {
                            error!("Tunnel lock poisoned: {}", e);
                            continue;
                        }
                    };
                    tun_lock.encapsulate(&packet, &mut encrypted)
                };

                match send_result {
                    Ok(0) => {} // Nothing to send (e.g., handshake pending)
                    Ok(n) => {
                        // Add to buffer instead of sending immediately
                        packet_buffer.push(encrypted[..n].to_vec());

                        // Flush if buffer is full
                        if packet_buffer.len() >= batch_size {
                            flush_packet_buffer(&udp, &packet_buffer).await;
                            packet_buffer.clear();
                        }
                    }
                    Err(e) => {
                        warn!("Encapsulation error: {}", e);
                    }
                }
            }

            // --- Incoming: UDP -> Decrypt -> TUN ---
            result = udp.recv(&mut udp_buf) => {
                match result {
                    Ok(n) => {
                        let mut decrypted = vec![0u8; n];
                        let decrypt_result = {
                            let mut tun_lock = match tunnel.lock() {
                                Ok(t) => t,
                                Err(e) => {
                                    error!("Tunnel lock poisoned: {}", e);
                                    continue;
                                }
                            };
                            tun_lock.decapsulate(&udp_buf[..n], &mut decrypted)
                        };

                        match decrypt_result {
                            Ok(0) => {} // Handshake or keepalive, nothing to write
                            Ok(len) => {
                                if let Err(e) = tun_writer.write_all(&decrypted[..len]) {
                                    warn!("TUN write error: {}", e);
                                } else {
                                    debug!("Wrote {} decrypted bytes to TUN", len);
                                }
                            }
                            Err(e) => {
                                warn!("Decapsulation error: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("UDP recv error: {}", e);
                    }
                }
            }

            // --- Keepalive timer ---
            _ = keepalive_timer.tick() => {
                // Send an empty encapsulated packet as keepalive
                let mut keepalive_buf = vec![0u8; WIREGUARD_OVERHEAD];
                let ka_result = {
                    let mut tun_lock = match tunnel.lock() {
                        Ok(t) => t,
                        Err(e) => {
                            error!("Tunnel lock poisoned: {}", e);
                            continue;
                        }
                    };
                    tun_lock.encapsulate(&[], &mut keepalive_buf)
                };

                match ka_result {
                    Ok(0) => {} // Nothing to send
                    Ok(n) => {
                        if let Err(e) = udp.send(&keepalive_buf[..n]).await {
                            warn!("Keepalive send error: {}", e);
                        } else {
                            debug!("Sent keepalive ({} bytes)", n);
                        }
                    }
                    Err(e) => {
                        debug!("Keepalive encapsulate: {}", e);
                    }
                }
            }
        }
    }
}

/// Flushes the packet buffer by sending all packets via UDP.
///
/// This function sends all encrypted packets in the buffer to the VPN server.
/// Packets are sent individually since WireGuard requires each packet to be
/// in its own datagram for proper decryption.
async fn flush_packet_buffer(udp: &UdpSocket, buffer: &[Vec<u8>]) {
    for packet in buffer {
        if let Err(e) = udp.send(packet).await {
            warn!("UDP batch send error: {}", e);
        } else {
            debug!("Sent batched {} encrypted bytes to server", packet.len());
        }
    }
}
