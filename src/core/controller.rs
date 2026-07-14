//! Controller — VPN control plane bridging GUI and async core.
//!
//! # Role in RustVPN
//! This module provides the bridge between the Iced GUI (main thread) and
//! the async VPN core (Tokio runtime). It uses message passing to safely
//! communicate between the two worlds via VpnCommand (GUI→core) and VpnEvent (core→GUI).
//!
//! # Main Contracts
//! - Input: VpnCommand messages from GUI (Connect, Disconnect, settings changes)
//! - Output: VpnEvent messages to GUI (state changes, errors, info)
//! - Safety: Thread-safe channel communication; zeroized private keys in memory
//!
//! # Platform Notes
//! Linux-only: uses a raw fd with an ioctl-based TUN device.
//!
//! # Non-goals
//! This module does not implement packet processing (delegated to packet_loop).
//! It does not implement firewall rules (delegated to killswitch module).
//! It does not perform cryptographic operations (delegated to tunnel module).

use std::sync::{mpsc, Arc, Mutex};

use crate::config::VpnConfig;
use crate::core::killswitch::KillSwitch;
use crate::core::reconnect::ReconnectManager;
use crate::core::tunnel::{base64_to_key, Tunnel, TunnelConfig};
use crate::dns::filter::DnsFilter;
use tokio::sync::watch;
use zeroize::Zeroizing;

// ── Platform abstraction ─────────────────────────────────────────────────────
//
// Linux-only implementation.
// The Platform type exposes `new()`, `create_tun()`, and `cleanup()`,
// plus a `run_packet_loop` entry point.
// TunHandle is the raw file descriptor for the TUN device.
use crate::core::packet_loop::{run_packet_loop, PacketLoopExit};
use crate::platform::linux::LinuxPlatform as Platform;
type TunHandle = std::os::unix::io::RawFd;

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
    /// A newer release is available on GitHub. The string is the version
    /// number (without leading `v`), e.g. `"0.2.0"`.
    ///
    /// Sent by the background update checker (spawned in `main`) and
    /// rendered as a dismissable banner in the GUI.
    UpdateAvailable(String),
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
    /// A clone of the event sender, exposed for code outside the worker
    /// (e.g. the background update checker spawned in `main`) that needs
    /// to push events into the GUI's event channel without going through
    /// the VPN command pipeline.
    external_event_tx: mpsc::Sender<VpnEvent>,
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
        // Clone retained on the controller so external producers (the update
        // checker in `main`) can push events without going through the worker.
        let external_event_tx = event_tx.clone();

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
            external_event_tx,
        }
    }

    /// Returns a clone of the event sender so external code (such as the
    /// background update checker spawned in `main`) can push events --
    /// notably [`VpnEvent::UpdateAvailable`] -- into the GUI's event
    /// channel without going through the VPN worker.
    pub fn external_event_sender(&self) -> mpsc::Sender<VpnEvent> {
        self.external_event_tx.clone()
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
    /// `Receiver` is drained by the GUI on each `Message::Tick`, which applies
    /// the [`VpnEvent`] messages to the GUI state.
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

    /// Emit a Connect-failure: an `Error` event paired with the
    /// `StateChanged(Error)` transition. Centralizes the "signal error + flip
    /// to Error state" invariant that every Connect failure branch shares, so
    /// the two sends can't drift apart at a call site.
    fn emit_error(event_tx: &mpsc::Sender<VpnEvent>, message: String) {
        let _ = event_tx.send(VpnEvent::Error(message));
        let _ = event_tx.send(VpnEvent::StateChanged(VpnState::Error));
    }

    /// Wait `delay`, then re-enqueue a `Connect` on the command channel so
    /// `run_worker` handles the auto-reconnect exactly like a user-initiated
    /// connect. Shared by both retry paths (handshake failure and unexpected
    /// packet-loop exit) so the backoff-then-re-Connect contract lives in one
    /// place. Caller supplies the backoff so the reconnect ladder is unchanged.
    async fn resend_connect_after(
        cmd_tx: tokio::sync::mpsc::UnboundedSender<VpnCommand>,
        server_endpoint: String,
        server_public_key_base64: String,
        delay: std::time::Duration,
    ) {
        tokio::time::sleep(delay).await;
        let _ = cmd_tx.send(VpnCommand::Connect {
            server_endpoint,
            server_public_key_base64,
        });
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

        // ── Private key + tunnel address ─────────────────────────────────────
        // Loaded once at worker startup so they are ready the moment Connect
        // arrives, without blocking the async loop with config I/O.
        // Stored as Options so a load/parse failure degrades gracefully: the
        // Connect handler checks for None and emits an error event to the GUI.
        let (client_private_key, client_tun_addr, dns_filter): (
            Option<Zeroizing<[u8; 32]>>,
            Option<((u8, u8, u8, u8), (u8, u8, u8, u8))>,
            Option<Arc<DnsFilter>>,
        ) = {
            let mut cfg = VpnConfig::load().unwrap_or_default();
            let key = match cfg.get_or_create_private_key() {
                Ok(k) => {
                    tracing::info!("Client private key loaded");
                    Some(k)
                }
                Err(e) => {
                    tracing::error!("Failed to load/generate private key: {}", e);
                    None
                }
            };
            let tun_addr = match cfg.client_tun_address() {
                Ok(a) => {
                    tracing::info!(
                        "Client TUN address: {}.{}.{}.{}/{}.{}.{}.{}",
                        a.0 .0,
                        a.0 .1,
                        a.0 .2,
                        a.0 .3,
                        a.1 .0,
                        a.1 .1,
                        a.1 .2,
                        a.1 .3
                    );
                    Some(a)
                }
                Err(e) => {
                    tracing::error!("Invalid client TUN address in config: {}", e);
                    None
                }
            };
            // ── DNS filter (built once, shared across reconnects) ───────────
            // Wrapped in Arc so the packet loop holds a cheap clone without
            // taking ownership; the same filter is reused for every Connect
            // until the worker exits.
            //
            // Build only when the user has opted into DNS filtering; if they
            // disable it we pass `None` to the packet loop, which short-
            // circuits the interception check entirely (zero overhead).
            //
            // A construction failure (e.g. blocklist parse error in a
            // future revision) is logged and treated as "no filter" rather
            // than blocking startup -- ad blocking is a feature, not a
            // hard requirement for the VPN to function.
            let dns_filter = if cfg.dns_filtering_protection_enabled {
                match DnsFilter::new() {
                    Ok(f) => {
                        tracing::info!(
                            "DNS filter ready ({} blocked domains)",
                            f.blocked_domain_count()
                        );
                        Some(Arc::new(f))
                    }
                    Err(e) => {
                        tracing::warn!("DNS filter init failed, disabling: {}", e);
                        None
                    }
                }
            } else {
                tracing::info!("DNS filtering disabled by user preference");
                None
            };

            (key, tun_addr, dns_filter)
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
        let mut active_platform: Option<Platform> = None;

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
                VpnCommand::Connect {
                    server_endpoint,
                    server_public_key_base64,
                } => {
                    // Abort any running session before starting a new one.
                    // Handles rapid Connect→Connect without an intervening Disconnect.
                    #[cfg(target_os = "linux")]
                    {
                        if let Some(tx) = stop_tx.take() {
                            let _ = tx.send(true);
                        }
                        if let Some(mut p) = active_platform.take() {
                            let _ = p.cleanup();
                        }
                    }

                    tracing::info!("Worker: Connect to {}", server_endpoint);
                    let _ = event_tx.send(VpnEvent::StateChanged(VpnState::Connecting));
                    let _ = event_tx.send(VpnEvent::Info(format!(
                        "Connecting to {}...",
                        server_endpoint
                    )));

                    // --- Parse server endpoint ---
                    // Needed for both kill switch (IP) and tunnel config (SocketAddr).
                    let server_addr: std::net::SocketAddr = match server_endpoint.parse() {
                        Ok(a) => a,
                        Err(e) => {
                            Self::emit_error(
                                &event_tx,
                                format!("Invalid server endpoint '{}': {}", server_endpoint, e),
                            );
                            continue;
                        }
                    };
                    last_server_ip = Some(server_addr.ip());

                    // --- Enable kill switch BEFORE any tunnel traffic can flow ---
                    // (see the kill switch comment block in the worker state section
                    //  for the full rationale on ordering and the server-IP guard)
                    //
                    // Fail-closed: if the user asked for kill-switch protection and we
                    // can't actually install the firewall rules, we must NOT proceed to
                    // bring up the tunnel — doing so would let traffic flow with no
                    // firewall backstop, defeating the entire point of the feature.
                    // Abort the connect attempt instead (`continue` to the next command).
                    if kill_switch_enabled {
                        if let Some(ks) = kill_switch.as_mut() {
                            if let Err(e) = ks.enable(server_addr.ip(), "tun0") {
                                tracing::error!("Kill switch enable failed: {}", e);
                                Self::emit_error(
                                    &event_tx,
                                    format!(
                                        "Kill switch error: {} — refusing to connect without \
                                         the requested protection",
                                        e
                                    ),
                                );
                                continue;
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
                                Self::emit_error(
                                    &event_tx,
                                    "No private key (see startup log for generation failure)"
                                        .to_string(),
                                );
                                continue;
                            }
                        };

                        // Step 2
                        // WireGuard keys are distributed in base64 (same as `wg pubkey`
                        // output). base64_to_key decodes the string to a raw [u8; 32].
                        let server_pub_key = match base64_to_key(&server_public_key_base64) {
                            Ok(k) => k,
                            Err(e) => {
                                Self::emit_error(
                                    &event_tx,
                                    format!("Invalid server public key: {}", e),
                                );
                                continue;
                            }
                        };

                        // Steps 3 + 4
                        // 10.8.0.2/24 is the conventional VPN client address.
                        // Production builds would receive this from the server.
                        let mut platform = match Platform::new() {
                            Ok(p) => p,
                            Err(e) => {
                                Self::emit_error(&event_tx, format!("Platform init failed: {}", e));
                                continue;
                            }
                        };

                        // Use the configured client TUN address (falls back
                        // to 10.8.0.2/24 when the user hasn't set one).
                        // If the config field was set but unparseable, the
                        // worker startup logged the error and stored None;
                        // emit a user-visible error and abort the connect
                        // rather than silently substituting the default.
                        let (tun_ip_octets, tun_mask_octets) = match client_tun_addr {
                            Some(a) => a,
                            None => {
                                Self::emit_error(
                                    &event_tx,
                                    "Invalid client_tun_ip_cidr in config (see startup log)"
                                        .to_string(),
                                );
                                continue;
                            }
                        };

                        // Create the TUN device and take its raw fd as the
                        // `TunHandle` the packet loop dups.
                        let tun_handle: TunHandle = {
                            {
                                use std::os::unix::io::AsRawFd;
                                match platform.create_tun(
                                    tun_ip_octets,
                                    tun_mask_octets,
                                    server_addr.ip(),
                                ) {
                                    Ok(dev) => dev.as_raw_fd(),
                                    Err(e) => {
                                        Self::emit_error(
                                            &event_tx,
                                            format!("TUN device creation failed: {}", e),
                                        );
                                        continue;
                                    }
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
                                Self::emit_error(
                                    &event_tx,
                                    format!("Tunnel creation failed: {}", e),
                                );
                                continue;
                            }
                        };

                        if let Err(e) = tunnel_instance.connect().await {
                            reconnect_manager.record_failure();
                            // Snapshot the new (doubled) backoff AFTER recording
                            // the failure so the retry delay is correct.
                            let retry_backoff = reconnect_manager.get_current_backoff();
                            Self::emit_error(
                                &event_tx,
                                format!("WireGuard handshake failed: {}", e),
                            );

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
                                    Self::resend_connect_after(cmd_tx, ep, pk, retry_backoff).await;
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
                        // Cheap Arc clone -- the filter itself is built once
                        // at worker startup and shared across reconnects.
                        let dns_filter_loop = dns_filter.clone();

                        tokio::spawn(async move {
                            let exit = run_packet_loop(
                                tunnel_for_loop,
                                tun_handle,
                                server_addr,
                                stop_receiver,
                                dns_filter_loop,
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
                                    // Re-enqueue Connect through the command channel after
                                    // the backoff. run_worker handles it like a user-initiated
                                    // connect: on failure it calls record_failure() and, if
                                    // auto_reconnect_enabled, spawns another retry — driving the
                                    // full exponential backoff ladder.
                                    Self::resend_connect_after(
                                        command_tx_loop,
                                        server_endpoint_loop,
                                        server_pub_key_loop,
                                        first_reconnect_backoff,
                                    )
                                    .await;
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
                        let _ = event_tx
                            .send(VpnEvent::Info(format!("Connected to {}", server_endpoint)));
                    }
                }
                VpnCommand::Disconnect => {
                    tracing::info!("Worker: Disconnect");

                    // Stop the packet loop before removing the TUN device.
                    // The stop signal gives the loop a chance to flush in-flight
                    // packets; then cleanup removes routes and drops the fd.
                    #[cfg(target_os = "linux")]
                    {
                        if let Some(tx) = stop_tx.take() {
                            let _ = tx.send(true);
                        }
                        if let Some(mut p) = active_platform.take() {
                            let _ = p.cleanup();
                        }
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
                    tracing::info!(
                        "Worker: Kill switch {}",
                        if enabled { "enabled" } else { "disabled" }
                    );
                    kill_switch_enabled = enabled;
                    if let Some(ks) = kill_switch.as_mut() {
                        if enabled {
                            // We can only enable the kill switch if we already
                            // know the server IP. The firewall must include an
                            // explicit ALLOW rule for that IP so VPN packets
                            // can still reach the server (for reconnections).
                            // If no server IP is known yet, the Connect handler
                            // will call enable() when the user connects (and will
                            // itself fail closed there if that call fails).
                            if let Some(ip) = last_server_ip {
                                if let Err(e) = ks.enable(ip, "tun0") {
                                    tracing::error!("Kill switch enable failed: {}", e);
                                    // Don't leave `kill_switch_enabled = true` lying
                                    // about protection state — no firewall rule
                                    // actually exists, so the flag must say so too.
                                    kill_switch_enabled = false;
                                    let _ = event_tx.send(VpnEvent::Error(format!(
                                        "Kill switch error: {} — protection is NOT active",
                                        e
                                    )));
                                }
                            }
                        } else if let Err(e) = ks.disable() {
                            tracing::warn!("Kill switch disable failed: {}", e);
                        }
                    }
                }
                VpnCommand::SetAutoReconnect(enabled) => {
                    tracing::info!(
                        "Worker: Auto-reconnect {}",
                        if enabled { "enabled" } else { "disabled" }
                    );
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
                        if let Some(tx) = stop_tx.take() {
                            let _ = tx.send(true);
                        }
                        if let Some(mut p) = active_platform.take() {
                            let _ = p.cleanup();
                        }
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
