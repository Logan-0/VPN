//! # Windows Packet Loop (WinTun)
//!
//! The Windows counterpart of `packet_loop.rs`. The two files have the
//! same job -- bridge the OS-level virtual interface and the UDP socket
//! that talks to the VPN server -- but the I/O surface differs:
//!
//! - **Linux** uses a raw file descriptor returned by `/dev/net/tun`,
//!   read with `std::fs::File::read` from a `spawn_blocking` thread.
//! - **Windows** uses the WinTun [`Session`] object's `send_packet` /
//!   `receive_blocking` methods. There is no file descriptor.
//!
//! We keep the two implementations as separate modules rather than
//! parameterising one because the platform APIs are too divergent to
//! abstract cleanly without runtime cost; gating with `#[cfg]` makes
//! each version straightforward to read on its own.
//!
//! ## Concurrency Model
//!
//! WinTun's `receive_blocking` is genuinely blocking (it parks on a
//! kernel event), so we run it in a `tokio::task::spawn_blocking`
//! thread that forwards packets to an mpsc channel. The async select
//! loop handles three sources:
//!
//!   1. Packets arriving from the TUN reader task (-> encrypt -> UDP)
//!   2. Datagrams arriving on the UDP socket (-> decrypt -> TUN write)
//!   3. The 25-second WireGuard keepalive timer
//!
//! This mirrors the Linux loop, so the only platform-specific code is
//! around the TUN reader/writer.

#![cfg(target_os = "windows")]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::core::tunnel::Tunnel;
use crate::dns::filter::DnsFilter;
use crate::dns::intercept::try_block_dns_query;

const TUN_MTU: usize = 1500;
const WIREGUARD_OVERHEAD: usize = 32;
const KEEPALIVE_INTERVAL_SECS: u64 = 25;

/// Result of the Windows packet loop. Same variants as the Linux version
/// so the controller can consume both with a single match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketLoopExit {
    Shutdown,
    TunError,
    UdpError,
}

/// Drives the bidirectional packet flow over a WinTun session.
///
/// ## Arguments
///
/// - `tunnel`: shared WireGuard tunnel for `encapsulate`/`decapsulate`.
/// - `session`: the active WinTun session returned from
///   `WindowsPlatform::create_tun`.
/// - `server_addr`: the VPN server's UDP endpoint.
/// - `stop_rx`: watch channel; flipping to `true` shuts down cleanly.
/// - `dns_filter`: optional blocklist applied to outbound DNS queries
///   before they enter the tunnel (see `dns::intercept`).
pub async fn run_packet_loop(
    tunnel: Arc<Mutex<Tunnel>>,
    session: Arc<wintun::Session>,
    server_addr: SocketAddr,
    mut stop_rx: watch::Receiver<bool>,
    dns_filter: Option<Arc<DnsFilter>>,
) -> PacketLoopExit {
    info!("Starting Windows packet processing loop -> {}", server_addr);

    // ── UDP socket bound to the server ─────────────────────────────────────
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

    let keepalive_interval = tokio::time::Duration::from_secs(KEEPALIVE_INTERVAL_SECS);
    let mut keepalive_timer = tokio::time::interval(keepalive_interval);

    // Channel between the blocking WinTun reader and the async loop.
    // Capacity 64 matches the Linux side; larger buffers don't help
    // because the bottleneck is encryption, not channel throughput.
    let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    // Spawn the blocking reader. WinTun's `receive_blocking` parks the
    // thread on a kernel event, so we cannot call it from the async
    // executor's pool without starving other tasks. The task exits when
    // the stop signal flips OR the session is dropped.
    let session_for_reader = Arc::clone(&session);
    let stop_rx_reader = stop_rx.clone();
    tokio::task::spawn_blocking(move || {
        loop {
            if *stop_rx_reader.borrow() {
                break;
            }
            match session_for_reader.receive_blocking() {
                Ok(packet) => {
                    let bytes = packet.bytes().to_vec();
                    if tun_tx.blocking_send(bytes).is_err() {
                        // Receiver dropped -- packet loop exited.
                        break;
                    }
                }
                Err(e) => {
                    // ShutdownEvent is the expected error when the
                    // session is being torn down. Anything else gets
                    // logged so users can diagnose driver issues.
                    error!("WinTun receive error: {}", e);
                    break;
                }
            }
        }
    });

    let mut udp_buf = vec![0u8; TUN_MTU + WIREGUARD_OVERHEAD];

    loop {
        tokio::select! {
            // ── Shutdown ──────────────────────────────────────────────────
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    info!("Windows packet loop received shutdown signal");
                    return PacketLoopExit::Shutdown;
                }
            }

            // ── Outgoing: TUN -> Encrypt -> UDP ───────────────────────────
            Some(packet) = tun_rx.recv() => {
                // DNS interception: if this packet is a DNS query for a
                // blocked domain, write the synthetic reply straight back
                // to the WinTun session and skip encryption.
                if let Some(filter) = dns_filter.as_ref() {
                    if let Some(reply) = try_block_dns_query(&packet, filter) {
                        if let Err(e) = write_to_session(&session, &reply) {
                            warn!("Failed to write blocked DNS reply: {}", e);
                        } else {
                            debug!("DNS query blocked locally ({} bytes)", reply.len());
                        }
                        continue;
                    }
                }
                let _ = &session; // referenced inside DNS branch above; silence unused on no-filter builds

                let mut encrypted = vec![0u8; packet.len() + WIREGUARD_OVERHEAD];
                let send_result = {
                    let mut tun_lock = match tunnel.lock() {
                        Ok(t) => t,
                        Err(e) => { error!("Tunnel lock poisoned: {}", e); continue; }
                    };
                    tun_lock.encapsulate(&packet, &mut encrypted)
                };
                match send_result {
                    Ok(0) => {}
                    Ok(n) => {
                        if let Err(e) = udp.send(&encrypted[..n]).await {
                            warn!("UDP send error: {}", e);
                        }
                    }
                    Err(e) => warn!("Encapsulation error: {}", e),
                }
            }

            // ── Incoming: UDP -> Decrypt -> TUN ───────────────────────────
            result = udp.recv(&mut udp_buf) => {
                match result {
                    Ok(n) => {
                        let mut decrypted = vec![0u8; n];
                        let decrypt_result = {
                            let mut tun_lock = match tunnel.lock() {
                                Ok(t) => t,
                                Err(e) => { error!("Tunnel lock poisoned: {}", e); continue; }
                            };
                            tun_lock.decapsulate(&udp_buf[..n], &mut decrypted)
                        };
                        match decrypt_result {
                            Ok(0) => {}
                            Ok(len) => {
                                if let Err(e) = write_to_session(&session, &decrypted[..len]) {
                                    warn!("WinTun write error: {}", e);
                                }
                            }
                            Err(e) => warn!("Decapsulation error: {}", e),
                        }
                    }
                    Err(e) => warn!("UDP recv error: {}", e),
                }
            }

            // ── Keepalive ─────────────────────────────────────────────────
            _ = keepalive_timer.tick() => {
                let mut keepalive_buf = vec![0u8; WIREGUARD_OVERHEAD];
                let ka = {
                    let mut tun_lock = match tunnel.lock() {
                        Ok(t) => t,
                        Err(e) => { error!("Tunnel lock poisoned: {}", e); continue; }
                    };
                    tun_lock.encapsulate(&[], &mut keepalive_buf)
                };
                if let Ok(n) = ka {
                    if n > 0 {
                        let _ = udp.send(&keepalive_buf[..n]).await;
                    }
                }
            }
        }
    }
}

/// Writes a single packet to the WinTun session.
///
/// WinTun expects the caller to allocate the outbound packet buffer
/// from the session's ring, copy the bytes in, and then mark it as
/// ready to send. We hide that ceremony behind one helper so the main
/// loop above stays readable.
///
/// ## Why `&Arc<Session>` and not `&Session`?
///
/// `wintun::Session::allocate_send_packet` is declared with a
/// `self: &Arc<Self>` receiver -- the implementation needs to clone the
/// arc into the returned packet handle so the session is not dropped
/// while a packet is in flight. Plain references therefore cannot call
/// it; the helper must take the arc form.
fn write_to_session(session: &Arc<wintun::Session>, bytes: &[u8]) -> anyhow::Result<()> {
    let mut packet = session
        .allocate_send_packet(bytes.len() as u16)
        .map_err(|e| anyhow::anyhow!("WinTun allocate_send_packet failed: {}", e))?;
    packet.bytes_mut().copy_from_slice(bytes);
    session.send_packet(packet);
    Ok(())
}
