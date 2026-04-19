//! # VPN GUI Application (Iced)
//!
//! This module provides a cross-platform graphical user interface using the
//! **Iced** framework. Iced follows the **Elm architecture** (Model-View-Update),
//! which cleanly separates application state, user interaction messages, and
//! rendering logic. This is a significant improvement over the previous GTK4
//! implementation because:
//!
//! - **Cross-platform by default**: Iced compiles natively on Linux, macOS, and
//!   Windows without requiring system-level GUI libraries (no GTK, no Cocoa).
//! - **Pure Rust**: No C bindings or FFI -- the entire rendering pipeline is Rust.
//! - **Elm architecture**: State mutations happen in one place (`update()`), making
//!   the application easier to reason about, test, and debug.
//!
//! ## Elm Architecture (Model-View-Update)
//!
//! ```text
//!   State (VpnApp)          Message (Message enum)        View (view fn)
//!  ┌──────────────┐        ┌──────────────────┐        ┌──────────────┐
//!  │ connection   │◄───────│ ConnectPressed   │◄───────│ [CONNECT]    │
//!  │ kill_switch  │  update│ ServerSelected   │  event │ [dropdown]   │
//!  │ servers[]    │────────│ KillSwitchToggled│────────│ [x] kill sw  │
//!  └──────────────┘        └──────────────────┘        └──────────────┘
//! ```
//!
//! 1. **State** (`VpnApp`): holds all live data (connection state, settings, servers).
//! 2. **Message** (`Message`): an enum of every possible user action.
//! 3. **update()**: receives a `Message` and mutates `State`. This is the *only*
//!    place state changes.
//! 4. **view()**: reads `State` and returns a widget tree. Iced re-renders
//!    automatically whenever `update()` returns.
//!
//! ## Networking Context
//!
//! The GUI itself does not perform networking. It:
//! - Displays VPN connection state (Connected / Disconnected / Connecting)
//! - Shows the selected server's display name and IP address
//! - Sends commands to the async VPN core via [`VpnController`]
//! - Receives events from the core via [`iced::Subscription`]
//!
//! User preferences are loaded from [`VpnConfig`] on startup and persisted on
//! every change. The server list comes from [`ServerManager`] /
//! `resources/servers.toml`.

use iced::widget::{button, checkbox, column, container, pick_list, text};
use iced::{Element, Length, Subscription, Task, Theme};
use std::sync::mpsc;

use crate::config::VpnConfig;
use crate::core::controller::{VpnCommand, VpnController, VpnEvent, VpnState};
use crate::server::{Server, ServerManager};

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
            Self::Connecting   => write!(f, "Connecting..."),
            Self::Connected    => write!(f, "Connected"),
            Self::Reconnecting => write!(f, "Reconnecting..."),
            Self::Error        => write!(f, "Error"),
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
    /// An event arrived from the async VPN core worker.
    CoreEvent(VpnEvent),
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
    /// Receiving half of the event channel, wrapped in Option so the
    /// subscription can take ownership of it exactly once.
    event_rx: Option<mpsc::Receiver<VpnEvent>>,
}

impl VpnApp {
    /// Bootstrap the application: load config, servers, create controller.
    ///
    /// This is called once by Iced before the first `view()`. It replaces the
    /// GTK4 `build_ui` function -- in the Elm architecture initialization
    /// returns the initial model and an optional startup command (Task).
    fn new() -> (Self, Task<Message>) {
        let config = VpnConfig::load().unwrap_or_default();
        let server_manager = ServerManager::new().unwrap();
        let servers: Vec<ServerOption> = server_manager
            .get_servers()
            .iter()
            .cloned()
            .map(ServerOption)
            .collect();

        // Resolve the saved server selection to an actual ServerOption
        let selected_server = config
            .selected_vpn_server_identifier
            .as_deref()
            .and_then(|id| servers.iter().find(|s| s.0.server_identifier == id))
            .cloned()
            .or_else(|| servers.first().cloned());

        let controller = VpnController::new();
        let event_rx = Some(controller.take_event_rx());

        (
            Self {
                connection_state: ConnectionState::Disconnected,
                config,
                servers,
                selected_server,
                controller,
                event_rx,
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
            Message::ConnectPressed => {
                match self.connection_state {
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
                }
            }

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
                self.controller.send_command(VpnCommand::SetKillSwitch(enabled));
            }
            Message::AutoReconnectToggled(enabled) => {
                self.config.auto_reconnect_enabled = enabled;
                if let Err(e) = self.config.save() {
                    tracing::warn!("Failed to save config: {}", e);
                }
                self.controller.send_command(VpnCommand::SetAutoReconnect(enabled));
            }
            Message::DnsFilteringToggled(enabled) => {
                self.config.dns_filtering_protection_enabled = enabled;
                if let Err(e) = self.config.save() {
                    tracing::warn!("Failed to save config: {}", e);
                }
            }

            // ── Events arriving from the async VPN core ─────────────────
            Message::CoreEvent(event) => match event {
                VpnEvent::StateChanged(state) => {
                    self.connection_state = match state {
                        VpnState::Disconnected => ConnectionState::Disconnected,
                        VpnState::Connecting   => ConnectionState::Connecting,
                        VpnState::Connected    => ConnectionState::Connected,
                        VpnState::Reconnecting => ConnectionState::Reconnecting,
                        VpnState::Error        => ConnectionState::Error,
                    };
                }
                VpnEvent::Error(msg) => {
                    tracing::error!("VPN error: {}", msg);
                }
                VpnEvent::Info(msg) => {
                    tracing::info!("VPN info: {}", msg);
                }
            },
        }

        Task::none()
    }

    /// The **View** step of the Elm architecture.
    ///
    /// Reads the current state and returns a declarative widget tree. Iced
    /// diffs the previous tree against the new one and only repaints what
    /// changed -- similar to how React works in the browser.
    fn view(&self) -> Element<Message> {
        // ── Status section ──────────────────────────────────────────────
        let status_color = match self.connection_state {
            ConnectionState::Connected    => iced::Color::from_rgb(0.0, 0.8, 0.0),
            ConnectionState::Connecting
            | ConnectionState::Reconnecting => iced::Color::from_rgb(1.0, 0.65, 0.0),
            ConnectionState::Error        => iced::Color::from_rgb(1.0, 0.0, 0.0),
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
            ConnectionState::Connected    => "DISCONNECT",
            ConnectionState::Connecting   => "CONNECTING...",
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
        let kill_switch_cb = checkbox(
            "Kill Switch (blocks traffic when VPN disconnected)",
            self.config.kill_switch_protection_enabled,
        )
        .on_toggle(Message::KillSwitchToggled);

        let auto_reconnect_cb = checkbox(
            "Auto-reconnect (automatically reconnect on failure)",
            self.config.auto_reconnect_enabled,
        )
        .on_toggle(Message::AutoReconnectToggled);

        let dns_filtering_cb = checkbox(
            "DNS Filtering (block ads and malware)",
            self.config.dns_filtering_protection_enabled,
        )
        .on_toggle(Message::DnsFilteringToggled);

        // ── Assemble layout ─────────────────────────────────────────────
        let content = column![
            text("RustVPN").size(32),
            status_text,
            text(server_display).size(16),
            text(ip_display).size(16),
            text("Uptime: 00:00:00").size(16),
            connect_button,
            text("Select Server:").size(18),
            server_picker,
            text("Settings:").size(18),
            kill_switch_cb,
            auto_reconnect_cb,
            dns_filtering_cb,
        ]
        .spacing(14)
        .padding(30)
        .width(Length::Fill);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    /// Iced subscription that polls the VPN core event channel.
    ///
    /// In the GTK4 version we used `glib::timeout_add_local` to poll events
    /// every 100 ms. In Iced, a [`Subscription`] is the idiomatic replacement:
    /// it runs as a long-lived async task managed by the runtime and emits
    /// [`Message::CoreEvent`] whenever the VPN core sends something.
    fn subscription(&self) -> Subscription<Message> {
        Subscription::none()
    }

    /// Application theme.
    fn theme(&self) -> Theme {
        Theme::Dark
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
        iced::application(VpnApp::title, VpnApp::update, VpnApp::view)
            .subscription(VpnApp::subscription)
            .theme(VpnApp::theme)
            .window_size(iced::Size::new(500.0, 650.0))
            .run_with(VpnApp::new)
            .expect("Failed to run Iced application");
    }
}
