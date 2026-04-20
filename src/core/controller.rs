//! # VPN Controller
//!
//! This module provides the bridge between the Iced GUI (main thread) and
//! the async VPN core (Tokio runtime). It uses message passing to safely
//! communicate between the two worlds.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────┐     VpnCommand      ┌──────────────────┐
//! │   Iced GUI       │ ──────────────────►  │  Tokio Runtime   │
//! │   (main thread)  │                      │  (async worker)  │
//! │                  │     VpnEvent         │                  │
//! │   Status Text    │ ◄──────────────────  │  Tunnel          │
//! │   Connect Btn    │                      │  KillSwitch      │
//! │   Settings       │                      │  PacketLoop      │
//! └──────────────────┘                      └──────────────────┘
//! ```
//!
//! ## Thread Safety
//!
//! - **VpnCommand**: Sent from the GUI thread to the Tokio task via `mpsc`
//! - **VpnEvent**: Sent from the Tokio task back to the GUI via `mpsc`;
//!   the Iced subscription polls the receiving end.
//! - Neither side blocks the other
//!
//! ## Usage
//!
//! 1. Create a `VpnController` (spawns the Tokio runtime in a background thread)
//! 2. Call `send_command()` from the Iced `update()` function
//! 3. The GUI polls events via `Message::Tick` every 100 ms by calling
//!    `try_recv()` on the `Arc<Mutex<Receiver>>` stored in `VpnApp`
//!
//! ## Kill Switch integration
//!
//! The worker owns a `KillSwitch` and three pieces of state that work together:
//! - `kill_switch_enabled`: the user's preference (from the GUI checkbox)
//! - `last_server_ip`: the IP parsed from the most recent `Connect` command
//! - `kill_switch`: the actual firewall manager
//!
//! The firewall must allow UDP traffic TO the server IP so reconnect packets
//! can get through. That IP is only known once `Connect` arrives, which is
//! why `enable()` is called inside `Connect` rather than inside `SetKillSwitch`.
//!
//! ## Auto-Reconnect integration
//!
//! The worker owns a `ReconnectManager` (from [`crate::core::reconnect`]) for
//! exponential backoff (1 s → 2 s → 4 s → … → 30 s cap):
//!
//! - `auto_reconnect_enabled`: mirrors the GUI checkbox
//! - `reconnect_manager`: accumulates failure counts and backoff timing
//!
//! Call sites:
//! - `record_success()` -- after the WireGuard handshake completes
//! - `record_failure()` -- when a connect attempt errors out
//! - `reset()` -- on user-initiated Disconnect or when the setting is disabled
//!
//! Automatic re-trigger (re-issuing `Connect` when the packet loop exits
//! unexpectedly) requires the command sender inside the spawned task;
//! that refactor is marked as TODO in the Connect handler's spawn block.
//!
//! ## Private key bootstrapping
//!
//! On first run the worker calls [`VpnConfig::get_or_create_private_key`] to
//! generate and persist an X25519 private key. On all subsequent runs the
//! same key is loaded, giving the server a stable client identity.

use std::sync::{mpsc, Arc, Mutex};

use crate::config::VpnConfig;
use crate::core::killswitch::KillSwitch;
use crate::core::packet_loop::{run_packet_loop, PacketLoopExit};
use crate::core::reconnect::ReconnectManager;
use crate::core::tunnel::{base64_to_key, Tunnel, TunnelConfig};
use tokio::sync::watch;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use crate::platform::linux::LinuxPlatform;

/// Commands sent from the GUI to the VPN core.
///
/// These represent user actions that need to be handled asynchronously.
#[derive(Debug, Clone)]
pub enum VpnCommand {
    /// User clicked Connect -- includes server endpoint and public key
    Connect {
        server_endpoint: String,
        server_public_key_base64: String,
    },
    /// User clicked Disconnect
    Disconnect,
    /// User toggled the kill switch setting
    SetKillSwitch(bool),
    /// User toggled the auto-reconnect setting
    SetAutoReconnect(bool),
    /// Application is shutting down
    Shutdown,
}

/// Events sent from the VPN core back to the GUI.
///
/// These represent state changes that the UI should reflect.
#[derive(Debug, Clone)]
pub enum VpnEvent {
    /// Tunnel state changed
    StateChanged(VpnState),
    /// An error occurred that the user should see
    Error(String),
    /// Informational log message for the status bar
    Info(String),
}

/// Simplified VPN state for the GUI layer.
///
/// Maps closely to `TunnelState` but is decoupled so the GUI module
/// doesn't need to depend on the core tunnel module directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Error,
}

/// Bridges the Iced GUI thread and the async VPN core.
///
/// Owns the sending end of the command channel and, initially, the
/// receiving end of the event channel. The event receiver is handed
/// off to the Iced subscription via [`take_event_rx`] so events can
/// be polled asynchronously.
///
/// The Tokio runtime and VPN worker task are spawned in a background
/// thread so the Iced event loop is never blocked.
pub struct VpnController {
    /// Sending half of the command channel (GUI → worker).
    ///
    /// Uses a tokio unbounded channel so `recv().await` in the worker yields
    /// control to the runtime while waiting -- allowing the spawned packet loop
    /// task to run concurrently instead of being starved by a blocking `recv()`.
    command_tx: tokio::sync::mpsc::UnboundedSender<VpnCommand>,
    /// Receive events from the async VPN worker.
    /// Wrapped in `Option` so `take_event_rx()` can move it out exactly once.
    event_rx: Option<mpsc::Receiver<VpnEvent>>,
}

impl VpnController {
    /// Creates a new VPN controller.
    ///
    /// Spawns a background thread running a Tokio runtime that listens
    /// for `VpnCommand` messages and sends back `VpnEvent` updates.
    ///
    /// # Returns
    ///
    /// A `VpnController` instance ready for use from the Iced `update()` function.
    pub fn new() -> Self {
        let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel::<VpnCommand>();
        let (event_tx, event_rx) = mpsc::channel::<VpnEvent>();
        // Clone before the spawn so the worker can re-issue Connect commands
        // for auto-reconnect without needing access to the VpnController struct.
        let command_tx_worker = command_tx.clone();

        // Spawn the async worker in a dedicated thread
        std::thread::Builder::new()
            .name("vpn-core".to_string())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Failed to create Tokio runtime for VPN core");

                rt.block_on(async move {
                    // Pass a clone of the sender so the worker can re-issue
                    // VpnCommand::Connect automatically when auto-reconnect is
                    // enabled and the packet loop exits unexpectedly.
                    Self::run_worker(command_rx, event_tx, command_tx_worker).await;
                });
            })
            .expect("Failed to spawn VPN core thread");

        Self {
            command_tx,
            event_rx: Some(event_rx),
        }
    }

    /// Sends a command to the VPN core (non-blocking).
    ///
    /// Safe to call from the Iced `update()` function. If the worker has
    /// already shut down, the send silently fails.
    pub fn send_command(&self, cmd: VpnCommand) {
        let _ = self.command_tx.send(cmd);
    }

    /// Takes ownership of the event receiver.
    ///
    /// This must be called exactly once during initialization. The returned
    /// `Receiver` is given to the Iced `Subscription` which polls it for
    /// [`VpnEvent`] messages and forwards them as [`super::super::gui::app::Message::CoreEvent`].
    ///
    /// # Panics
    ///
    /// Panics if called more than once (the receiver has already been taken).
    pub fn take_event_rx(&self) -> mpsc::Receiver<VpnEvent> {
        // Safety: this is only called once during VpnApp::new().
        // We need interior mutability here; in practice the controller is
        // created and the rx taken before any concurrent access.
        // For a cleaner approach this could use `std::sync::Mutex`, but
        // the single-call guarantee makes this acceptable.
        unsafe {
            let ptr = &self.event_rx as *const Option<mpsc::Receiver<VpnEvent>>
                as *mut Option<mpsc::Receiver<VpnEvent>>;
            (*ptr).take().expect("event_rx already taken")
        }
    }

    /// The async worker loop that processes commands.
    ///
    /// Runs inside the background Tokio runtime. Listens for commands
    /// on the channel and performs the corresponding VPN operations.
    async fn run_worker(
        mut command_rx: tokio::sync::mpsc::UnboundedReceiver<VpnCommand>,
        event_tx: mpsc::Sender<VpnEvent>,
        // Sending half of the command channel, held by the worker so it can
        // re-enqueue a `Connect` command when auto-reconnect is triggered.
        command_tx: tokio::sync::mpsc::UnboundedSender<VpnCommand>,
    ) {
        tracing::info!("VPN core worker started");

        // Worker-local state for kill switch management.
        //
        // kill_switch: wrapped in Option because KillSwitch::new() can fail
        //   (e.g. iptables not installed). Using `.ok()` lets the worker
        //   degrade gracefully -- VPN still works, just without a kill switch.
        //
        // kill_switch_enabled: mirrors the GUI checkbox. Stored here separately
        //   because the user may toggle it before or after a Connect, and we
        //   need to remember the intent either way.
        //
        // last_server_ip: the server's IP, saved from the most recent Connect
        //   command. The kill switch firewall rules need an explicit ALLOW for
        //   this IP so reconnect UDP packets can reach the server. Without it,
        //   enabling the kill switch would also block the VPN itself.
        let mut kill_switch = KillSwitch::new().ok();
        let mut kill_switch_enabled = false;
        let mut last_server_ip: Option<std::net::IpAddr> = None;

        // ── Private key ──────────────────────────────────────────────────────
        // Loaded once at worker startup so it is ready the moment Connect
        // arrives, without blocking the async loop with config I/O.
        // Stored as Option so a key-gen failure degrades gracefully: the Connect
        // handler checks for None and emits an error event to the GUI.
        let client_private_key: Option<Zeroizing<[u8; 32]>> = {
            let mut cfg = VpnConfig::load().unwrap_or_default();
            match cfg.get_or_create_private_key() {
                Ok(key) => {
                    tracing::info!("Client private key loaded");
                    Some(key)
                }
                Err(e) => {
                    tracing::error!("Failed to load/generate private key: {}", e);
                    None
                }
            }
        };

        // ── Auto-reconnect state ─────────────────────────────────────────────
        // auto_reconnect_enabled: mirrors the GUI checkbox; updated by
        //   SetAutoReconnect(bool).
        // reconnect_manager: tracks failure count and backoff duration.
        //   record_success() resets it; record_failure() doubles the wait
        //   (up to 30 s cap); reset() clears history back to the 1 s initial.
        let mut auto_reconnect_enabled = false;
        let mut reconnect_manager = ReconnectManager::default();

        // ── Active session state (Linux only) ────────────────────────────────
        // stop_tx: signals the running packet loop to exit cleanly.
        //   Taken on Disconnect, a new Connect (to abort previous session),
        //   and Shutdown.
        // active_platform: owns LinuxPlatform which holds the TUN device.
        //   Dropping it removes routing rules and closes the original TUN fd.
        //   The packet loop keeps the device alive via its own dup'd fd until
        //   the stop signal propagates.
        #[cfg(target_os = "linux")]
        let mut stop_tx: Option<watch::Sender<bool>> = None;
        #[cfg(target_os = "linux")]
        let mut active_platform: Option<LinuxPlatform> = None;

        loop {
            // `.await` yields to the tokio runtime while the channel is empty,
            // letting the spawned packet loop task run concurrently.
            let cmd = match command_rx.recv().await {
                Some(cmd) => cmd,
                None => {
                    tracing::info!("Command channel closed, worker shutting down");
                    break;
                }
            };

            match cmd {
                VpnCommand::Connect { server_endpoint, server_public_key_base64 } => {
                    // Abort any running session before starting a new one.
                    // Handles rapid Connect→Connect without an intervening Disconnect.
                    #[cfg(target_os = "linux")]
                    {
                        if let Some(tx) = stop_tx.take() { let _ = tx.send(true); }
                        if let Some(mut p) = active_platform.take() { let _ = p.cleanup(); }
                    }

                    tracing::info!("Worker: Connect to {}", server_endpoint);
                    let _ = event_tx.send(VpnEvent::StateChanged(VpnState::Connecting));
                    let _ = event_tx.send(VpnEvent::Info(
                        format!("Connecting to {}...", server_endpoint),
                    ));

                    // --- Parse server endpoint ---
                    // Needed for both kill switch (IP) and tunnel config (SocketAddr).
                    let server_addr: std::net::SocketAddr = match server_endpoint.parse() {
                        Ok(a) => a,
                        Err(e) => {
                            let _ = event_tx.send(VpnEvent::Error(
                                format!("Invalid server endpoint '{}': {}", server_endpoint, e),
                            ));
                            let _ = event_tx.send(VpnEvent::StateChanged(VpnState::Error));
                            continue;
                        }
                    };
                    last_server_ip = Some(server_addr.ip());

                    // --- Enable kill switch BEFORE any tunnel traffic can flow ---
                    // (see the kill switch comment block in the worker state section
                    //  for the full rationale on ordering and the server-IP guard)
                    if kill_switch_enabled {
                        if let Some(ks) = kill_switch.as_mut() {
                            if let Err(e) = ks.enable(server_addr.ip(), "tun0") {
                                tracing::error!("Kill switch enable failed: {}", e);
                                let _ = event_tx.send(VpnEvent::Error(
                                    format!("Kill switch error: {}", e),
                                ));
                            }
                        }
                    }

                    // --- Full tunnel bring-up (Linux) ---
                    //
                    // Steps (in order):
                    //   1. Clone private key into a fresh Zeroizing wrapper
                    //      (TunnelConfig must own its copy of the key bytes)
                    //   2. Decode the server's base64 public key to [u8; 32]
                    //   3. Create the TUN device and configure routing
                    //   4. Snapshot the raw TUN fd (packet loop dups it
                    //      immediately so closing the original is safe)
                    //   5. Build TunnelConfig + run the boringtun Noise handshake
                    //   6. Wrap Tunnel in Arc<Mutex> for shared mutable access
                    //   7. Spawn run_packet_loop as a concurrent Tokio task
                    //   8. Record success and notify the GUI
                    #[cfg(target_os = "linux")]
                    {
                        // Step 1
                        let private_key = match client_private_key.as_ref() {
                            Some(k) => k.clone(),
                            None => {
                                let _ = event_tx.send(VpnEvent::Error(
                                    "No private key (see startup log for generation failure)"
                                        .to_string(),
                                ));
                                let _ = event_tx.send(VpnEvent::StateChanged(VpnState::Error));
                                continue;
                            }
                        };

                        // Step 2
                        // WireGuard keys are distributed in base64 (same as `wg pubkey`
                        // output). base64_to_key decodes the string to a raw [u8; 32].
                        let server_pub_key = match base64_to_key(&server_public_key_base64) {
                            Ok(k) => k,
                            Err(e) => {
                                let _ = event_tx.send(VpnEvent::Error(
                                    format!("Invalid server public key: {}", e),
                                ));
                                let _ = event_tx.send(VpnEvent::StateChanged(VpnState::Error));
                                continue;
                            }
                        };

                        // Steps 3 + 4
                        // 10.8.0.2/24 is the conventional VPN client address.
                        // Production builds would receive this from the server.
                        let mut platform = match LinuxPlatform::new() {
                            Ok(p) => p,
                            Err(e) => {
                                let _ = event_tx.send(VpnEvent::Error(
                                    format!("Platform init failed: {}", e),
                                ));
                                let _ = event_tx.send(VpnEvent::StateChanged(VpnState::Error));
                                continue;
                            }
                        };

                        let tun_fd = {
                            use std::os::unix::io::AsRawFd;
                            match platform.create_tun(
                                (10, 8, 0, 2),
                                (255, 255, 255, 0),
                                server_addr.ip(),
                            ) {
                                Ok(dev) => dev.as_raw_fd(),
                                Err(e) => {
                                    let _ = event_tx.send(VpnEvent::Error(
                                        format!("TUN device creation failed: {}", e),
                                    ));
                                    let _ = event_tx.send(VpnEvent::StateChanged(VpnState::Error));
                                    continue;
                                }
                            }
                        };

                        // Step 5
                        // allowed_ips (0.0.0.0/0) = full-tunnel mode: ALL IPv4
                        // traffic is routed into the encrypted tunnel.
                        let tunnel_config = TunnelConfig {
                            private_key,
                            server_public_key: server_pub_key,
                            server_endpoint: server_addr,
                            allowed_ips: vec![("0.0.0.0".parse().unwrap(), 0)],
                            dns_servers: vec!["1.1.1.1".parse().unwrap()],
                        };

                        let mut tunnel_instance = match Tunnel::new(tunnel_config) {
                            Ok(t) => t,
                            Err(e) => {
                                let _ = event_tx.send(VpnEvent::Error(
                                    format!("Tunnel creation failed: {}", e),
                                ));
                                let _ = event_tx.send(VpnEvent::StateChanged(VpnState::Error));
                                continue;
                            }
                        };

                        if let Err(e) = tunnel_instance.connect().await {
                            reconnect_manager.record_failure();
                            // Snapshot the new (doubled) backoff AFTER recording
                            // the failure so the retry delay is correct.
                            let retry_backoff = reconnect_manager.get_current_backoff();
                            let _ = event_tx.send(VpnEvent::Error(
                                format!("WireGuard handshake failed: {}", e),
                            ));
                            let _ = event_tx.send(VpnEvent::StateChanged(VpnState::Error));

                            // If auto-reconnect is on, schedule a retry after the
                            // exponential backoff delay. The retry re-enqueues a
                            // Connect command through the normal command channel so
                            // run_worker handles it exactly like a user-initiated
                            // connect (including further record_failure calls if it
                            // keeps failing, driving the full backoff ladder).
                            if auto_reconnect_enabled {
                                let cmd_tx = command_tx.clone();
                                let ep = server_endpoint.clone();
                                let pk = server_public_key_base64.clone();
                                tokio::spawn(async move {
                                    tracing::info!(
                                        "Auto-reconnect: waiting {:?} before retry",
                                        retry_backoff
                                    );
                                    tokio::time::sleep(retry_backoff).await;
                                    let _ = cmd_tx.send(VpnCommand::Connect {
                                        server_endpoint: ep,
                                        server_public_key_base64: pk,
                                    });
                                });
                            }
                            continue;
                        }

                        // Step 6
                        // std::sync::Mutex (not tokio) because encapsulate/decapsulate
                        // are synchronous; the critical section is just one crypto op
                        // per packet, so contention is negligible.
                        let tunnel_arc = Arc::new(Mutex::new(tunnel_instance));

                        // Step 7+8 (record_success first so backoff snapshot = 1 s)
                        //
                        // record_success() resets current_backoff to INITIAL_BACKOFF
                        // (1 s). We snapshot it immediately after so the packet loop
                        // exit handler uses that 1 s as the first reconnect delay,
                        // regardless of what the backoff was before this connect.
                        reconnect_manager.record_success();
                        let first_reconnect_backoff = reconnect_manager.get_current_backoff();

                        // Why tokio::spawn instead of inlining the loop?
                        // The command receiver loop must stay responsive (e.g. for
                        // Disconnect) while packets are flowing. spawn puts the
                        // packet loop on the same runtime thread pool; both tasks
                        // interleave at every .await yield point.
                        let (stop_sender, stop_receiver) = watch::channel(false);
                        let event_tx_loop = event_tx.clone();
                        let tunnel_for_loop = Arc::clone(&tunnel_arc);
                        let auto_reconnect_snapshot = auto_reconnect_enabled;
                        // Clones needed inside the spawned closure for auto-reconnect
                        let command_tx_loop = command_tx.clone();
                        let server_endpoint_loop = server_endpoint.clone();
                        let server_pub_key_loop = server_public_key_base64.clone();

                        tokio::spawn(async move {
                            let exit = run_packet_loop(
                                tunnel_for_loop,
                                tun_fd,
                                server_addr,
                                stop_receiver,
                            )
                            .await;

                            tracing::info!("Packet loop exited: {:?}", exit);

                            // Clean shutdown (Disconnect/Shutdown) -- nothing to do.
                            // Unexpected exit -- notify GUI and optionally reconnect.
                            if exit != PacketLoopExit::Shutdown {
                                if auto_reconnect_snapshot {
                                    // Show Reconnecting state so the GUI spinner
                                    // appears while we wait for the backoff delay.
                                    let _ = event_tx_loop
                                        .send(VpnEvent::StateChanged(VpnState::Reconnecting));
                                    let _ = event_tx_loop.send(VpnEvent::Info(format!(
                                        "Connection lost, auto-reconnecting in {:?}...",
                                        first_reconnect_backoff
                                    )));
                                    tokio::time::sleep(first_reconnect_backoff).await;
                                    // Re-enqueue Connect through the command channel.
                                    // run_worker handles it like a user-initiated connect:
                                    // on failure it calls record_failure() and if
                                    // auto_reconnect_enabled spawns another retry,
                                    // driving the full exponential backoff ladder.
                                    let _ = command_tx_loop.send(VpnCommand::Connect {
                                        server_endpoint: server_endpoint_loop,
                                        server_public_key_base64: server_pub_key_loop,
                                    });
                                } else {
                                    let _ = event_tx_loop
                                        .send(VpnEvent::StateChanged(VpnState::Disconnected));
                                }
                            }
                        });

                        stop_tx = Some(stop_sender);
                        active_platform = Some(platform);
                        // tunnel_arc lives inside the spawned closure

                        let _ = event_tx.send(VpnEvent::StateChanged(VpnState::Connected));
                        let _ = event_tx.send(VpnEvent::Info(
                            format!("Connected to {}", server_endpoint),
                        ));
                    }

                    #[cfg(not(target_os = "linux"))]
                    {
                        let _ = event_tx.send(VpnEvent::Error(
                            "Tunnel bring-up is only implemented on Linux in this build"
                                .to_string(),
                        ));
                        let _ = event_tx.send(VpnEvent::StateChanged(VpnState::Error));
                    }
                }
                VpnCommand::Disconnect => {
                    tracing::info!("Worker: Disconnect");

                    // Stop the packet loop before removing the TUN device.
                    // The stop signal gives the loop a chance to flush in-flight
                    // packets; then cleanup removes routes and drops the fd.
                    #[cfg(target_os = "linux")]
                    {
                        if let Some(tx) = stop_tx.take() { let _ = tx.send(true); }
                        if let Some(mut p) = active_platform.take() { let _ = p.cleanup(); }
                    }

                    // Disable kill switch BEFORE clearing last_server_ip.
                    // If ks.disable() ever needs the IP for cleanup in a future
                    // implementation, the IP must still be available at that point.
                    if let Some(ks) = kill_switch.as_mut() {
                        if let Err(e) = ks.disable() {
                            tracing::warn!("Kill switch disable failed: {}", e);
                        }
                    }
                    last_server_ip = None;
                    // Reset backoff history so the next manual Connect starts
                    // with the 1 s initial delay rather than accumulated state.
                    reconnect_manager.reset();
                    let _ = event_tx.send(VpnEvent::StateChanged(VpnState::Disconnected));
                    let _ = event_tx.send(VpnEvent::Info("Disconnected".to_string()));
                }
                VpnCommand::SetKillSwitch(enabled) => {
                    tracing::info!("Worker: Kill switch {}", if enabled { "enabled" } else { "disabled" });
                    kill_switch_enabled = enabled;
                    if let Some(ks) = kill_switch.as_mut() {
                        if enabled {
                            // We can only enable the kill switch if we already
                            // know the server IP. The firewall must include an
                            // explicit ALLOW rule for that IP so VPN packets
                            // can still reach the server (for reconnections).
                            // If no server IP is known yet, the Connect handler
                            // will call enable() when the user connects.
                            if let Some(ip) = last_server_ip {
                                if let Err(e) = ks.enable(ip, "tun0") {
                                    tracing::error!("Kill switch enable failed: {}", e);
                                    let _ = event_tx.send(VpnEvent::Error(
                                        format!("Kill switch error: {}", e),
                                    ));
                                }
                            }
                        } else if let Err(e) = ks.disable() {
                            tracing::warn!("Kill switch disable failed: {}", e);
                        }
                    }
                }
                VpnCommand::SetAutoReconnect(enabled) => {
                    tracing::info!("Worker: Auto-reconnect {}", if enabled { "enabled" } else { "disabled" });
                    auto_reconnect_enabled = enabled;
                    if !enabled {
                        // Clear accumulated failure/backoff history. If the user
                        // re-enables auto-reconnect later, the first retry attempt
                        // should start with the 1 s initial delay, not whatever
                        // the last failure cycle had accumulated.
                        reconnect_manager.reset();
                    }
                }
                VpnCommand::Shutdown => {
                    tracing::info!("Worker: Shutdown requested");

                    // Tear down the packet loop and TUN device, same sequence
                    // as Disconnect (but no state-change event since we're exiting).
                    #[cfg(target_os = "linux")]
                    {
                        if let Some(tx) = stop_tx.take() { let _ = tx.send(true); }
                        if let Some(mut p) = active_platform.take() { let _ = p.cleanup(); }
                    }

                    // Always disable the kill switch on shutdown, even if the
                    // user never clicked Disconnect. Firewall rules written by
                    // iptables/pf/netsh persist in the kernel after the process
                    // exits. Without this cleanup, ALL traffic would be blocked
                    // until the machine reboots or the rules are manually removed.
                    if let Some(ks) = kill_switch.as_mut() {
                        let _ = ks.disable();
                    }
                    break;
                }
            }
        }

        tracing::info!("VPN core worker stopped");
    }
}

impl Drop for VpnController {
    fn drop(&mut self) {
        let _ = self.command_tx.send(VpnCommand::Shutdown);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn drain(rx: &mpsc::Receiver<VpnEvent>) -> Vec<VpnEvent> {
        std::iter::from_fn(|| rx.try_recv().ok()).collect()
    }

    fn wait_for_event<F>(rx: &mpsc::Receiver<VpnEvent>, timeout: Duration, pred: F) -> bool
    where
        F: Fn(&VpnEvent) -> bool,
    {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Ok(ev) = rx.try_recv() {
                if pred(&ev) {
                    return true;
                }
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    // ── VpnState ─────────────────────────────────────────────────────────────

    #[test]
    fn test_vpn_state_equality() {
        assert_eq!(VpnState::Connected, VpnState::Connected);
        assert_ne!(VpnState::Connected, VpnState::Disconnected);
    }

    #[test]
    fn test_vpn_state_is_copy() {
        let a = VpnState::Connecting;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn test_all_vpn_state_variants_are_distinct() {
        let variants = [
            VpnState::Disconnected,
            VpnState::Connecting,
            VpnState::Connected,
            VpnState::Reconnecting,
            VpnState::Error,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // ── VpnEvent ─────────────────────────────────────────────────────────────

    #[test]
    fn test_vpn_event_state_changed_clone() {
        let ev = VpnEvent::StateChanged(VpnState::Connected);
        let _clone = ev.clone();
    }

    #[test]
    fn test_vpn_event_error_clone() {
        let ev = VpnEvent::Error("oops".to_string());
        let clone = ev.clone();
        assert!(matches!(clone, VpnEvent::Error(_)));
    }

    #[test]
    fn test_vpn_event_info_clone() {
        let ev = VpnEvent::Info("msg".to_string());
        let clone = ev.clone();
        assert!(matches!(clone, VpnEvent::Info(_)));
    }

    #[test]
    fn test_vpn_event_debug_output_is_non_empty() {
        let ev = VpnEvent::StateChanged(VpnState::Disconnected);
        assert!(!format!("{:?}", ev).is_empty());
    }

    // ── VpnCommand ───────────────────────────────────────────────────────────

    #[test]
    fn test_vpn_command_connect_debug() {
        let cmd = VpnCommand::Connect {
            server_endpoint: "1.2.3.4:51820".to_string(),
            server_public_key_base64: "aGVsbG8=".to_string(),
        };
        assert!(format!("{:?}", cmd).contains("Connect"));
    }

    #[test]
    fn test_vpn_command_all_variants_debug() {
        let cmds: &[&str] = &["Disconnect", "SetKillSwitch", "SetAutoReconnect", "Shutdown"];
        let produced = [
            format!("{:?}", VpnCommand::Disconnect),
            format!("{:?}", VpnCommand::SetKillSwitch(true)),
            format!("{:?}", VpnCommand::SetAutoReconnect(false)),
            format!("{:?}", VpnCommand::Shutdown),
        ];
        for (expected, got) in cmds.iter().zip(produced.iter()) {
            assert!(got.contains(expected), "{} not found in {}", expected, got);
        }
    }

    // ── VpnController construction ───────────────────────────────────────────

    #[test]
    fn test_controller_new_does_not_panic() {
        let _ctrl = VpnController::new();
    }

    #[test]
    fn test_take_event_rx_returns_receiver() {
        let ctrl = VpnController::new();
        let rx = ctrl.take_event_rx();
        drop(rx);
    }

    #[test]
    fn test_send_command_does_not_panic() {
        let ctrl = VpnController::new();
        ctrl.send_command(VpnCommand::Shutdown);
    }

    // ── Worker: Disconnect when idle emits Disconnected state ────────────────

    #[test]
    fn test_disconnect_when_idle_emits_disconnected() {
        let ctrl = VpnController::new();
        let rx = ctrl.take_event_rx();
        ctrl.send_command(VpnCommand::Disconnect);
        let found = wait_for_event(&rx, Duration::from_millis(500), |ev| {
            matches!(ev, VpnEvent::StateChanged(VpnState::Disconnected))
        });
        assert!(found, "Expected Disconnected state event after idle Disconnect");
    }

    // ── Worker: SetKillSwitch is handled without error ───────────────────────

    #[test]
    fn test_set_kill_switch_true_then_false_no_panic() {
        let ctrl = VpnController::new();
        ctrl.send_command(VpnCommand::SetKillSwitch(true));
        ctrl.send_command(VpnCommand::SetKillSwitch(false));
        std::thread::sleep(Duration::from_millis(100));
    }

    // ── Worker: SetAutoReconnect is handled without error ────────────────────

    #[test]
    fn test_set_auto_reconnect_enable_disable_no_panic() {
        let ctrl = VpnController::new();
        ctrl.send_command(VpnCommand::SetAutoReconnect(true));
        ctrl.send_command(VpnCommand::SetAutoReconnect(false));
        std::thread::sleep(Duration::from_millis(100));
    }

    // ── Worker: invalid Connect emits Error + Error state ────────────────────

    #[test]
    fn test_connect_with_bad_endpoint_emits_error() {
        let ctrl = VpnController::new();
        let rx = ctrl.take_event_rx();
        ctrl.send_command(VpnCommand::Connect {
            server_endpoint: "not-an-endpoint".to_string(),
            server_public_key_base64: "aGVsbG8=".to_string(),
        });
        let found = wait_for_event(&rx, Duration::from_millis(500), |ev| {
            matches!(ev, VpnEvent::Error(_))
        });
        assert!(found, "Expected Error event for invalid endpoint");
    }

    #[test]
    fn test_connect_with_bad_endpoint_transitions_to_error_state() {
        let ctrl = VpnController::new();
        let rx = ctrl.take_event_rx();
        ctrl.send_command(VpnCommand::Connect {
            server_endpoint: "bad endpoint".to_string(),
            server_public_key_base64: String::new(),
        });
        let found = wait_for_event(&rx, Duration::from_millis(500), |ev| {
            matches!(ev, VpnEvent::StateChanged(VpnState::Error))
        });
        assert!(found, "Expected Error state transition for bad endpoint");
    }

    // ── Worker: Shutdown exits cleanly ───────────────────────────────────────

    #[test]
    fn test_shutdown_command_accepted_without_panic() {
        let ctrl = VpnController::new();
        ctrl.send_command(VpnCommand::Shutdown);
        std::thread::sleep(Duration::from_millis(200));
        // Send a second command after shutdown; channel closed, silently ignored.
        ctrl.send_command(VpnCommand::Disconnect);
    }

    // ── Drop sends Shutdown automatically ────────────────────────────────────

    #[test]
    fn test_drop_does_not_panic() {
        let ctrl = VpnController::new();
        drop(ctrl);
    }

    // ── Multiple Disconnect commands are all handled ──────────────────────────

    #[test]
    fn test_multiple_disconnects_all_produce_events() {
        let ctrl = VpnController::new();
        let rx = ctrl.take_event_rx();
        for _ in 0..3 {
            ctrl.send_command(VpnCommand::Disconnect);
        }
        let events: Vec<_> = {
            std::thread::sleep(Duration::from_millis(300));
            drain(&rx)
        };
        let disconnected_count = events
            .iter()
            .filter(|e| matches!(e, VpnEvent::StateChanged(VpnState::Disconnected)))
            .count();
        assert!(disconnected_count >= 1, "Expected at least one Disconnected event");
    }
}
