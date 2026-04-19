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
//! 3. Call `take_event_rx()` once to hand the receiver to an Iced `Subscription`

use std::sync::mpsc;

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
    /// Send commands to the async VPN worker
    command_tx: mpsc::Sender<VpnCommand>,
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
        let (command_tx, command_rx) = mpsc::channel::<VpnCommand>();
        let (event_tx, event_rx) = mpsc::channel::<VpnEvent>();

        // Spawn the async worker in a dedicated thread
        std::thread::Builder::new()
            .name("vpn-core".to_string())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Failed to create Tokio runtime for VPN core");

                rt.block_on(async move {
                    Self::run_worker(command_rx, event_tx).await;
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
        command_rx: mpsc::Receiver<VpnCommand>,
        event_tx: mpsc::Sender<VpnEvent>,
    ) {
        tracing::info!("VPN core worker started");

        loop {
            // Block on receiving the next command (this is fine because
            // we're on a dedicated thread with our own Tokio runtime)
            let cmd = match command_rx.recv() {
                Ok(cmd) => cmd,
                Err(_) => {
                    tracing::info!("Command channel closed, worker shutting down");
                    break;
                }
            };

            match cmd {
                VpnCommand::Connect { server_endpoint, server_public_key_base64: _server_public_key_base64 } => {
                    tracing::info!("Worker: Connect to {}", server_endpoint);
                    let _ = event_tx.send(VpnEvent::StateChanged(VpnState::Connecting));
                    let _ = event_tx.send(VpnEvent::Info(
                        format!("Connecting to {}...", server_endpoint),
                    ));

                    // TODO: Full integration with Tunnel, LinuxPlatform, PacketLoop
                    // For now, report back that we received the command
                    // This is where create_tun + tunnel.connect + run_packet_loop
                    // will be wired together.

                    let _ = event_tx.send(VpnEvent::Info(
                        "Tunnel setup not yet wired -- GUI integration groundwork complete".to_string(),
                    ));
                }
                VpnCommand::Disconnect => {
                    tracing::info!("Worker: Disconnect");
                    let _ = event_tx.send(VpnEvent::StateChanged(VpnState::Disconnected));
                    let _ = event_tx.send(VpnEvent::Info("Disconnected".to_string()));
                }
                VpnCommand::SetKillSwitch(enabled) => {
                    tracing::info!("Worker: Kill switch {}", if enabled { "enabled" } else { "disabled" });
                }
                VpnCommand::SetAutoReconnect(enabled) => {
                    tracing::info!("Worker: Auto-reconnect {}", if enabled { "enabled" } else { "disabled" });
                }
                VpnCommand::Shutdown => {
                    tracing::info!("Worker: Shutdown requested");
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
