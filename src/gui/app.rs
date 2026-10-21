//! App — Main VPN application state and Iced UI rendering.
//!
//! # Role in RustVPN
//! This module implements the main VPN application using Iced's Elm architecture.
//! It manages application state (connection status, settings, server selection),
//! handles user interactions via the Message enum, and renders the UI widgets.
//! All VPN operations are delegated to the VpnController running in a background thread.
//!
//! # Main Contracts
//! - Input: User actions (connect, disconnect, settings changes)
//! - Output: VpnCommand messages to controller, GUI state updates
//! - Safety: No direct network operations; all VPN work delegated to core
//!
//! # Platform Notes
//! Cross-platform using Iced framework (Linux, macOS, Windows).
//! Elm architecture ensures state mutations only occur in update() function.
//!
//! # Non-goals
//! This module does not perform VPN operations (delegated to controller).
//! It does not implement networking (delegated to core modules).
//! It does not manage system-level resources (delegated to platform module).

use iced::widget::{button, checkbox, column, container, pick_list, row, text};
use iced::{Element, Length, Subscription, Task, Theme};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::VpnConfig;
use crate::core::controller::{VpnCommand, VpnController, VpnEvent, VpnState};
use crate::server::{Server, ServerManager};
use crate::update::UpdateChecker;

// ────────────────────────────────────────────────────────────────────────────
// Connection State
// ────────────────────────────────────────────────────────────────────────────

/// VPN Connection State
///
/// Represents the current state of the VPN connection.
/// This is used to update the GUI display and control user interactions.
///
/// ## Networking Relevance
///
/// The connection state reflects the actual VPN tunnel status:
/// - **Disconnected**: No active VPN tunnel, traffic not protected
/// - **Connecting**: Establishing WireGuard handshake, not yet protected
/// - **Connected**: VPN tunnel active, all traffic encrypted
/// - **Reconnecting**: Connection lost, attempting to restore
/// - **Error**: Fatal error occurred, manual intervention needed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// No active VPN connection
    ///
    /// The VPN tunnel is not established. Traffic flows normally
    /// through the default network interface without encryption.
    Disconnected,

    /// VPN connection is being established
    ///
    /// The WireGuard handshake is in progress. The kill switch should
    /// be active to prevent traffic leaks during this transition.
    Connecting,

    /// VPN connection is active and working
    ///
    /// The WireGuard tunnel is established. All traffic is encrypted
    /// and routed through the VPN server. The kill switch is active.
    Connected,

    /// VPN connection was lost, attempting to reconnect
    ///
    /// The connection dropped unexpectedly. The reconnect manager
    /// is attempting to restore the connection with exponential backoff.
    /// The kill switch remains active to prevent leaks.
    Reconnecting,

    /// VPN connection encountered a fatal error
    ///
    /// An unrecoverable error occurred. Manual user intervention
    /// is required to resolve the issue and reconnect.
    Error,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected => write!(f, "Disconnected"),
            Self::Connecting => write!(f, "Connecting..."),
            Self::Connected => write!(f, "Connected"),
            Self::Reconnecting => write!(f, "Reconnecting..."),
            Self::Error => write!(f, "Error"),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Display wrapper for Server (required by pick_list)
// ────────────────────────────────────────────────────────────────────────────

/// Wrapper around [`Server`] that implements `Display` for the Iced pick list.
///
/// Iced's `pick_list` widget requires each option to implement `Display` so it
/// knows what text to render. The wrapper delegates to `server_display_name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerOption(pub Server);

impl std::fmt::Display for ServerOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.server_display_name)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Message enum (every possible user action / external event)
// ────────────────────────────────────────────────────────────────────────────

/// Messages the UI can produce.
///
/// In the Elm architecture every user interaction and every external event is
/// represented as a variant of a single `Message` enum. The `update()` function
/// pattern-matches on this enum to decide how to mutate `VpnApp`.
#[derive(Debug, Clone)]
pub enum Message {
    /// The user pressed the Connect / Disconnect button.
    ConnectPressed,
    /// The user selected a different server from the dropdown.
    ServerSelected(ServerOption),
    /// The user toggled the Kill Switch checkbox.
    KillSwitchToggled(bool),
    /// The user toggled the Auto-reconnect checkbox.
    AutoReconnectToggled(bool),
    /// The user toggled the DNS Filtering checkbox.
    DnsFilteringToggled(bool),
    /// 1 s timer tick: drains the VPN core event channel and refreshes the uptime display.
    Tick,
    /// The user dismissed the "update available" banner.
    DismissUpdateBanner,
}

// ────────────────────────────────────────────────────────────────────────────
// Application state (the Model)
// ────────────────────────────────────────────────────────────────────────────

/// Main VPN application state (Iced Model).
///
/// In the Elm architecture this struct **is** the model. Every piece of data
/// the GUI can read or write lives here. There is no `Rc<RefCell>` like in the
/// GTK4 version because Iced passes `&mut self` to `update()`, giving you
/// exclusive mutable access in a safe, single-threaded manner.
///
/// ## Fields
///
/// - `connection_state`: Current tunnel state (drives status text and button label).
/// - `config`: User preferences loaded from disk; mutated and saved on every toggle.
/// - `servers`: Available VPN servers loaded from `resources/servers.toml`.
/// - `selected_server`: Currently selected entry in the server dropdown.
/// - `controller`: Bridge to the async VPN core (send commands, receive events).
/// - `event_rx`: Receiving half of the event channel, polled by `subscription()`.
pub struct VpnApp {
    /// Current VPN connection state, drives status text and button label.
    connection_state: ConnectionState,
    /// User preferences loaded from disk; mutated and saved on every toggle.
    config: VpnConfig,
    /// Available VPN servers loaded from `resources/servers.toml`.
    servers: Vec<ServerOption>,
    /// Currently selected server in the dropdown.
    selected_server: Option<ServerOption>,
    /// Bridge to the async VPN core (commands go out, events come in).
    controller: VpnController,
    /// Receiving half of the event channel, polled on every `Tick`.
    event_rx: Arc<Mutex<mpsc::Receiver<VpnEvent>>>,
    /// Wall-clock time the current VPN session was established, drives the uptime display.
    connected_since: Option<Instant>,
    /// Latest version string reported by the background update checker, or
    /// `None` if no update is available or the user dismissed the banner.
    pending_update: Option<String>,
}

impl VpnApp {
    /// Bootstrap the application: load config, servers, create controller.
    ///
    /// This is called once by Iced before the first `view()`. It replaces the
    /// GTK4 `build_ui` function -- in the Elm architecture initialization
    /// returns the initial model and an optional startup command (Task).
    fn new() -> (Self, Task<Message>) {
        let config = VpnConfig::load().unwrap_or_default();
        let servers: Vec<ServerOption> = match ServerManager::new() {
            Ok(server_manager) => server_manager
                .get_servers()
                .iter()
                .cloned()
                .map(ServerOption)
                .collect(),
            Err(e) => {
                tracing::warn!("Failed to load server list, starting with none: {}", e);
                Vec::new()
            }
        };

        // Resolve the saved server selection to an actual ServerOption
        let selected_server = config
            .selected_vpn_server_identifier
            .as_deref()
            .and_then(|id| servers.iter().find(|s| s.0.server_identifier == id))
            .cloned()
            .or_else(|| servers.first().cloned());

        let controller = VpnController::new();
        let event_rx = Arc::new(Mutex::new(controller.take_event_rx()));

        // Spawn the background update check. We do it here (rather than in
        // `main`) because we need a handle to the controller's event channel
        // so the result can render as a dismissable banner. The check runs on
        // its own short-lived, single-threaded Tokio runtime (one sequential
        // HTTP GET doesn't need the `num_cpus` worker pool a multi-thread
        // runtime spawns) and fires exactly one `VpnEvent::UpdateAvailable` if a
        // newer release is found.
        let update_event_tx = controller.external_event_sender();
        std::thread::Builder::new()
            .name("update-check".to_string())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::warn!("Failed to start update check runtime: {}", e);
                        return;
                    }
                };
                rt.block_on(async move {
                    let checker = UpdateChecker::new(env!("CARGO_PKG_VERSION").to_string());
                    match checker.check_for_updates().await {
                        Ok(Some(version)) => {
                            tracing::info!("Update available: {}", version);
                            let _ = update_event_tx.send(VpnEvent::UpdateAvailable(version));
                        }
                        Ok(None) => tracing::debug!("No updates available"),
                        Err(e) => tracing::warn!("Update check failed: {}", e),
                    }
                });
            })
            .expect("Failed to spawn update-check thread");

        (
            Self {
                connection_state: ConnectionState::Disconnected,
                config,
                servers,
                selected_server,
                controller,
                event_rx,
                connected_since: None,
                pending_update: None,
            },
            Task::none(),
        )
    }

    /// Returns the window title.
    fn title(&self) -> String {
        String::from("RustVPN")
    }

    /// The **Update** step of the Elm architecture.
    ///
    /// Receives a [`Message`], mutates state, optionally returns a [`Task`]
    /// that Iced will execute asynchronously (e.g. saving config to disk).
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            // ── Connect / Disconnect button ─────────────────────────────
            Message::ConnectPressed => match self.connection_state {
                ConnectionState::Disconnected | ConnectionState::Error => {
                    if let Some(ref srv) = self.selected_server {
                        self.controller.send_command(VpnCommand::Connect {
                            server_endpoint: srv.0.server_endpoint_address.clone(),
                            server_public_key_base64: srv.0.server_public_key_base64.clone(),
                        });
                        self.connection_state = ConnectionState::Connecting;
                    }
                }
                ConnectionState::Connected | ConnectionState::Connecting => {
                    self.controller.send_command(VpnCommand::Disconnect);
                    self.connection_state = ConnectionState::Disconnected;
                }
                _ => {}
            },

            // ── Server dropdown changed ─────────────────────────────────
            Message::ServerSelected(server) => {
                self.config.selected_vpn_server_identifier =
                    Some(server.0.server_identifier.clone());
                self.selected_server = Some(server);
                if let Err(e) = self.config.save() {
                    tracing::warn!("Failed to save config: {}", e);
                }
            }

            // ── Settings checkboxes ─────────────────────────────────────
            Message::KillSwitchToggled(enabled) => {
                self.config.kill_switch_protection_enabled = enabled;
                if let Err(e) = self.config.save() {
                    tracing::warn!("Failed to save config: {}", e);
                }
                self.controller
                    .send_command(VpnCommand::SetKillSwitch(enabled));
            }
            Message::AutoReconnectToggled(enabled) => {
                self.config.auto_reconnect_enabled = enabled;
                if let Err(e) = self.config.save() {
                    tracing::warn!("Failed to save config: {}", e);
                }
                self.controller
                    .send_command(VpnCommand::SetAutoReconnect(enabled));
            }
            Message::DnsFilteringToggled(enabled) => {
                self.config.dns_filtering_protection_enabled = enabled;
                if let Err(e) = self.config.save() {
                    tracing::warn!("Failed to save config: {}", e);
                }
            }

            // ── Timer tick: drain event channel, refresh uptime display ──
            //
            // Why collect into a Vec before processing?
            // -----------------------------------------
            // `event_rx.try_lock()` returns a MutexGuard that holds a shared
            // borrow on `self.event_rx` (a field of `self`). Calling
            // `self.apply_core_event()` inside that block would need `&mut self`,
            // which conflicts with the existing shared borrow. Collecting all
            // pending events into an owned Vec first lets the MutexGuard drop
            // at the end of the inner block, freeing `self` for mutation.
            // This "collect, drop guard, then process" pattern is the standard
            // Rust solution for borrow-through-field conflicts.
            Message::Tick => {
                let events: Vec<VpnEvent> = self
                    .event_rx
                    .try_lock()
                    .map(|rx| {
                        let mut v = Vec::new();
                        while let Ok(e) = rx.try_recv() {
                            v.push(e);
                        }
                        v
                    })
                    .unwrap_or_default();
                for evt in events {
                    self.apply_core_event(evt);
                }
            }

            // ── User dismissed the update banner ────────────────────────
            Message::DismissUpdateBanner => {
                self.pending_update = None;
            }
        }

        Task::none()
    }

    /// The **View** step of the Elm architecture.
    ///
    /// Reads the current state and returns a declarative widget tree. Iced
    /// diffs the previous tree against the new one and only repaints what
    /// changed -- similar to how React works in the browser.
    fn view(&self) -> Element<'_, Message> {
        // ── Status section ──────────────────────────────────────────────
        let status_color = match self.connection_state {
            ConnectionState::Connected => iced::Color::from_rgb(0.0, 0.8, 0.0),
            ConnectionState::Connecting | ConnectionState::Reconnecting => {
                iced::Color::from_rgb(1.0, 0.65, 0.0)
            }
            ConnectionState::Error => iced::Color::from_rgb(1.0, 0.0, 0.0),
            ConnectionState::Disconnected => iced::Color::WHITE,
        };

        let status_text = text(format!("Status: {}", self.connection_state))
            .size(24)
            .color(status_color);

        let server_display = self
            .selected_server
            .as_ref()
            .map(|s| format!("Server: {}", s.0.server_display_name))
            .unwrap_or_else(|| "Server: None".to_string());

        let ip_display = self
            .selected_server
            .as_ref()
            .map(|s| format!("Endpoint: {}", s.0.server_endpoint_address))
            .unwrap_or_else(|| "Endpoint: --".to_string());

        // ── Connect / Disconnect button ─────────────────────────────────
        let button_label = match self.connection_state {
            ConnectionState::Disconnected | ConnectionState::Error => "CONNECT",
            ConnectionState::Connected => "DISCONNECT",
            ConnectionState::Connecting => "CONNECTING...",
            ConnectionState::Reconnecting => "RECONNECTING...",
        };

        let connect_button = button(text(button_label).size(18))
            .padding(12)
            .width(Length::Fill)
            .on_press(Message::ConnectPressed);

        // ── Server dropdown ─────────────────────────────────────────────
        let server_picker = pick_list(
            self.servers.as_slice(),
            self.selected_server.clone(),
            Message::ServerSelected,
        )
        .placeholder("Choose a server...")
        .width(Length::Fill);

        // ── Settings checkboxes ─────────────────────────────────────────
        let kill_switch_cb = checkbox(self.config.kill_switch_protection_enabled)
            .label("Kill Switch (blocks traffic when VPN disconnected)")
            .on_toggle(Message::KillSwitchToggled);

        let auto_reconnect_cb = checkbox(self.config.auto_reconnect_enabled)
            .label("Auto-reconnect (automatically reconnect on failure)")
            .on_toggle(Message::AutoReconnectToggled);

        let dns_filtering_cb = checkbox(self.config.dns_filtering_protection_enabled)
            .label("DNS Filtering (block ads and malware)")
            .on_toggle(Message::DnsFilteringToggled);

        // ── Assemble layout ─────────────────────────────────────────────
        //
        // The update banner is only included when `pending_update` is `Some`.
        // We build a `Vec<Element>` so the banner can be conditionally
        // pushed into the layout without the macro-based `column![]` having
        // to special-case its presence at compile time.
        let mut items: Vec<Element<Message>> = Vec::new();

        if let Some(version) = self.pending_update.as_ref() {
            // A simple two-row banner: message + dismiss button. Iced's
            // theming will already give it some visual separation; we keep
            // the markup minimal so the styling stays in the theme.
            let banner = container(
                row![
                    text(format!(
                        "Update available: v{} -- download from GitHub releases",
                        version
                    ))
                    .size(14)
                    .width(Length::Fill),
                    button(text("Dismiss").size(14)).on_press(Message::DismissUpdateBanner),
                ]
                .spacing(10)
                .padding(8),
            )
            .width(Length::Fill);
            items.push(banner.into());
        }

        items.push(text("RustVPN").size(32).into());
        items.push(status_text.into());
        items.push(text(server_display).size(16).into());
        items.push(text(ip_display).size(16).into());
        items.push(text(self.format_uptime()).size(16).into());
        items.push(connect_button.into());
        items.push(text("Select Server:").size(18).into());
        items.push(server_picker.into());
        items.push(text("Settings:").size(18).into());
        items.push(kill_switch_cb.into());
        items.push(auto_reconnect_cb.into());
        items.push(dns_filtering_cb.into());

        let content = column(items).spacing(14).padding(30).width(Length::Fill);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    /// Drives the GUI's async update loop with a recurring 100 ms timer.
    ///
    /// `iced::time::every` returns a `Subscription` that fires on a fixed
    /// interval. Each tick emits `Message::Tick`, which causes `update()` to
    /// drain any pending events from the VPN core channel and re-render the
    /// uptime counter.
    ///
    /// ## Why polling instead of a push-based subscription?
    ///
    /// The VPN core uses a `std::sync::mpsc` channel, which is *synchronous*.
    /// A push-based Iced subscription would need a blocking thread sitting on
    /// `recv()` plus async bridging code. A 100 ms polling timer is simpler,
    /// zero-overhead for a UI (state changes are rare), and avoids extra
    /// threads entirely.
    ///
    /// ## Why `Arc<Mutex<Receiver>>` on `event_rx`?
    ///
    /// `subscription()` receives `&self` (immutable). We cannot move the
    /// `Receiver` out of `self`. Wrapping it in `Arc<Mutex<...>>` lets
    /// `update()` call `try_lock()` to borrow the receiver without violating
    /// Rust's ownership rules. The `Mutex` is never actually contended --
    /// only `update()` ever touches the receiver -- but the type system
    /// requires it to prove the access is safe.
    fn subscription(&self) -> Subscription<Message> {
        // 1 s is exact for the only time-varying widget (HH:MM:SS uptime) and
        // still drains the worker->GUI event channel each tick. The previous
        // 100 ms tick rebuilt/re-diffed the whole view 10×/s forever (mostly
        // byte-identical frames) — pure idle CPU. Worker-driven state changes
        // are set optimistically in update() so the button never lags.
        iced::time::every(Duration::from_secs(1)).map(|_| Message::Tick)
    }

    /// Application theme.
    fn theme(&self) -> Theme {
        Theme::Dark
    }

    /// Applies a single [`VpnEvent`] from the async worker to the GUI state.
    ///
    /// Called from `Message::Tick`, which batch-drains the `mpsc` event channel
    /// once per second.
    ///
    /// ## Uptime tracking rules
    ///
    /// | New state     | `connected_since` action                          |
    /// |---------------|---------------------------------------------------|
    /// | `Connected`   | Set to `Instant::now()` (only if not already set) |
    /// | `Connecting`  | Unchanged -- no timer while handshaking           |
    /// | `Reconnecting`| Reset to `None` -- the previous session ended     |
    /// | `Disconnected`| Reset to `None`                                   |
    /// | `Error`       | Reset to `None`                                   |
    ///
    /// `Reconnecting` resets the timer because the old tunnel session is gone.
    /// When `Connected` fires again, a fresh timer starts -- showing the
    /// uptime of the *new* session rather than including the reconnect gap.
    fn apply_core_event(&mut self, event: VpnEvent) {
        match event {
            VpnEvent::StateChanged(state) => {
                self.connection_state = match state {
                    VpnState::Disconnected => {
                        self.connected_since = None;
                        ConnectionState::Disconnected
                    }
                    VpnState::Connecting => ConnectionState::Connecting,
                    VpnState::Connected => {
                        if self.connected_since.is_none() {
                            self.connected_since = Some(Instant::now());
                        }
                        ConnectionState::Connected
                    }
                    VpnState::Reconnecting => {
                        self.connected_since = None;
                        ConnectionState::Reconnecting
                    }
                    VpnState::Error => {
                        self.connected_since = None;
                        ConnectionState::Error
                    }
                };
            }
            VpnEvent::Error(msg) => tracing::error!("VPN error: {}", msg),
            VpnEvent::Info(msg) => tracing::info!("VPN info: {}", msg),
            VpnEvent::UpdateAvailable(version) => {
                tracing::info!("Update banner shown: v{}", version);
                self.pending_update = Some(version);
            }
        }
    }

    /// Formats elapsed session time as `Uptime: HH:MM:SS`.
    ///
    /// Returns `Uptime: --:--:--` whenever `connected_since` is `None`
    /// (i.e. not connected, connecting, reconnecting, or errored).
    /// Called on every `view()` pass -- the 100 ms `Tick` subscription
    /// triggers frequent repaints so the counter increments in real time.
    fn format_uptime(&self) -> String {
        match self.connected_since {
            Some(t) => {
                let secs = t.elapsed().as_secs();
                format!(
                    "Uptime: {:02}:{:02}:{:02}",
                    secs / 3600,
                    (secs % 3600) / 60,
                    secs % 60
                )
            }
            None => "Uptime: --:--:--".to_string(),
        }
    }

    /// Runs the Iced application.
    ///
    /// This replaces the GTK4 `Application::builder()...run()` pattern.
    /// Iced takes ownership of the main thread and runs its own event loop.
    ///
    /// ## Application Lifecycle (Iced)
    ///
    /// 1. `iced::application()` is called with title, update, and view functions.
    /// 2. Iced calls `VpnApp::new()` to obtain the initial model.
    /// 3. `view()` renders the first frame.
    /// 4. User interactions produce `Message` values.
    /// 5. `update()` processes each `Message` and mutates state.
    /// 6. `view()` is called again to re-render.
    /// 7. `subscription()` polls the VPN core for async events.
    /// 8. Loop continues until the window is closed.
    pub fn run() {
        iced::application(VpnApp::new, VpnApp::update, VpnApp::view)
            .title(VpnApp::title)
            .subscription(VpnApp::subscription)
            .theme(VpnApp::theme)
            .window_size(iced::Size::new(500.0, 650.0))
            .run()
            .expect("Failed to run Iced application");
    }
}
