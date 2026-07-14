//! Packet Loop — TUN device to UDP socket packet forwarding.
//!
//! # Role in RustVPN
//! This module implements the main packet processing loop that bridges
//! the TUN device with the UDP socket to the VPN server. It handles
//! outgoing traffic (TUN→UDP→VPN), incoming traffic (VPN→UDP→TUN),
//! and periodic keepalive packets to prevent NAT timeouts.
//!
//! # Main Contracts
//! - Input: TUN device fd, UDP socket, tunnel encryption/decryption
//! - Output: Encrypted packets to VPN server, decrypted packets to TUN
//! - Safety: DNS filtering blocks malicious queries; errors logged per-packet
//!
//! # Platform Notes
//! Linux-specific implementation using raw file descriptors and ioctl.
//!
//! # Non-goals
//! This module does not implement encryption/decryption (delegated to tunnel module).
//! It does not implement DNS filtering logic (delegated to dns filter module).
//! It does not handle connection state management (delegated to controller).

use nix::libc;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
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

    // Buffer free-list: the async loop returns each processed TUN buffer here so
    // the blocking reader reuses it instead of `buf[..n].to_vec()`-copying into
    // a fresh Vec on every outbound packet. On an empty pool the reader falls
    // back to a fresh allocation, so a missed return only costs one allocation
    // (never correctness). The `tun_tx` channel(64) bound keeps the number of
    // buffers in circulation — and thus the pool's memory — small.
    let (recycle_tx, recycle_rx) = std::sync::mpsc::channel::<Vec<u8>>();

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

        // Take a buffer from the pool (or allocate) and size it for a full read.
        let take_buf = |recycle_rx: &std::sync::mpsc::Receiver<Vec<u8>>| {
            let mut buf = recycle_rx.try_recv().unwrap_or_else(|_| vec![0u8; TUN_MTU]);
            buf.resize(TUN_MTU, 0);
            buf
        };
        let mut buf = take_buf(&recycle_rx);

        loop {
            if *tun_read_stop.borrow() {
                break;
            }
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    buf.truncate(n);
                    // Hand ownership of this buffer to the async loop (no copy);
                    // fetch another (recycled or fresh) for the next read.
                    if tun_tx.blocking_send(buf).is_err() {
                        break; // receiver dropped
                    }
                    buf = take_buf(&recycle_rx);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data: keep the same buffer and retry after a short nap.
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

    // Reused encrypt/decrypt scratch buffers, hoisted out of the hot loop so no
    // per-packet Vec is allocated+zeroed. Sized for the largest possible output
    // (a full-MTU TUN read plus WireGuard overhead; a decrypted plaintext is
    // always smaller than its ciphertext, which fits `udp_buf`). boringtun
    // writes exactly the output bytes and returns that subslice, so only the
    // returned `[..n]`/`[..len]` prefix is ever read — stale trailing bytes from
    // a previous larger packet are never transmitted.
    let mut encrypted = vec![0u8; TUN_MTU + WIREGUARD_OVERHEAD];
    let mut decrypted = vec![0u8; TUN_MTU + WIREGUARD_OVERHEAD];

    loop {
        tokio::select! {
            // --- Shutdown signal ---
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    info!("Packet loop received shutdown signal");
                    return PacketLoopExit::Shutdown;
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
                        let _ = recycle_tx.send(packet);
                        continue;
                    }
                }

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
                // Done reading `packet` — return its buffer to the reader's pool.
                let _ = recycle_tx.send(packet);

                match send_result {
                    Ok(0) => {} // Nothing to send (e.g., handshake pending)
                    Ok(n) => {
                        // Send immediately. The old batch loop still issued one
                        // send() per packet, so it coalesced no syscalls — it
                        // only added up to a few ms of latency plus a per-packet
                        // `.to_vec()` copy. Read only the `[..n]` boringtun wrote.
                        if let Err(e) = udp.send(&encrypted[..n]).await {
                            warn!("UDP send error: {}", e);
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
                // Send an empty encapsulated packet as keepalive, reusing the
                // hoisted `encrypted` scratch buffer.
                let ka_result = {
                    let mut tun_lock = match tunnel.lock() {
                        Ok(t) => t,
                        Err(e) => {
                            error!("Tunnel lock poisoned: {}", e);
                            continue;
                        }
                    };
                    tun_lock.encapsulate(&[], &mut encrypted)
                };

                match ka_result {
                    Ok(0) => {} // Nothing to send
                    Ok(n) => {
                        if let Err(e) = udp.send(&encrypted[..n]).await {
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
