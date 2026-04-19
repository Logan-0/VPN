//! # VPN GUI Application (GTK4)
//!
//! This module provides a cross-platform graphical user interface using GTK4.
//! It displays VPN connection status, allows server selection, and provides
//! settings toggles for kill switch, auto-reconnect, and DNS filtering.
//!
//! ## Networking Concepts
//!
/// The GUI itself doesn't directly handle networking, but it:
/// - Displays VPN connection state (Connected/Disconnected/Connecting)
/// - Shows server information (IP, location)
/// - Allows user to control networking features (kill switch, auto-reconnect, DNS filtering)
/// - Displays uptime and connection statistics
///
/// User preferences are loaded from `VpnConfig` on startup and persisted on every
/// change. The server list is populated dynamically from `ServerManager` /
/// `resources/servers.toml`. The connect/disconnect button currently only updates
/// GUI state; tunnel integration is pending.

use gtk4::prelude::*;
use gtk4::{
    Application, ApplicationWindow, Box as GtkBox, Button, CheckButton, ComboBoxText, Label,
    Orientation,
};
use gtk4::glib;
use std::cell::RefCell;
use std::rc::Rc;
use crate::config::VpnConfig;
use crate::core::controller::{VpnCommand, VpnController, VpnEvent, VpnState};
use crate::server::ServerManager;

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


/// Main VPN Application State
///
/// Holds the live runtime state of the VPN connection for use in GTK4 callbacks.
/// User preferences (kill switch, auto-reconnect, DNS filtering, server selection)
/// are managed directly through `VpnConfig` in `build_ui` and are not sourced
/// from the fields below at runtime.
///
/// ## Fields
///
/// - `current_vpn_connection_state`: Live tunnel state, toggled by the
///   connect/disconnect button and (future) by actual tunnel state events.
/// - `kill_switch_protection_enabled`: Reserved for future tunnel integration.
/// - `auto_reconnect_enabled`: Reserved for future tunnel integration.
/// - `dns_filtering_protection_enabled`: Reserved for future tunnel integration.
pub struct VpnApp {
    /// Current VPN connection state
    /// 
    /// Uses `Rc<RefCell>` for interior mutability so GTK4 callbacks can update
    /// the state without requiring `Send`. Updated by the connect/disconnect
    /// button and, in the future, by actual tunnel state change events.
    pub current_vpn_connection_state: Rc<RefCell<ConnectionState>>,
    
    /// Kill switch enabled flag
    /// 
    /// Reserved for future use when the GUI is wired to the `KillSwitch` core.
    /// The current GUI reads this setting from `VpnConfig` directly.
    pub kill_switch_protection_enabled: Rc<RefCell<bool>>,
    
    /// Auto-reconnect enabled flag
    /// 
    /// Reserved for future use when the GUI is wired to the `ReconnectManager` core.
    /// The current GUI reads this setting from `VpnConfig` directly.
    pub auto_reconnect_enabled: Rc<RefCell<bool>>,
    
    /// DNS filtering enabled flag
    /// 
    /// Reserved for future use when the GUI is wired to the `DnsFilter` core.
    /// The current GUI reads this setting from `VpnConfig` directly.
    pub dns_filtering_protection_enabled: Rc<RefCell<bool>>,
}

impl VpnApp {
    /// Creates a new VPN application instance
    /// 
    /// Initializes `current_vpn_connection_state` to `Disconnected`. The settings
    /// fields (`kill_switch_protection_enabled`, etc.) are set to secure defaults
    /// but are not read by the current UI, which sources those values directly
    /// from the loaded `VpnConfig` in `build_ui`. They are retained for future
    /// wiring to the VPN tunnel core.
    /// 
    /// # Returns
    /// 
    /// New `VpnApp` instance
    pub fn new() -> Self {
        Self {
            current_vpn_connection_state: Rc::new(RefCell::new(ConnectionState::Disconnected)),
            kill_switch_protection_enabled: Rc::new(RefCell::new(true)),
            auto_reconnect_enabled: Rc::new(RefCell::new(true)),
            dns_filtering_protection_enabled: Rc::new(RefCell::new(true)),
        }
    }

    /// Builds and displays the GTK4 user interface
    /// 
    /// Constructs the complete GUI including connection status display,
    /// server selection dropdown, connect/disconnect button, and settings toggles.
    /// 
    /// ## Networking Context
    /// 
    /// The GUI provides user control over VPN networking:
    /// - Connect button triggers VPN tunnel establishment
    /// - Server selection determines which VPN server to use
    /// - Settings toggles control networking features
    /// - Status display shows current VPN connection state
    /// 
    /// ## GUI Components
    /// 
    /// 1. **Title**: Application name ("RustVPN")
    /// 2. **Status label**: Current connection state (Disconnected/Connected/etc.)
    /// 3. **Server info**: Selected VPN server and IP address
    /// 4. **Uptime**: Connection duration timer
    /// 5. **Connect button**: Toggles VPN connection on/off
    /// 6. **Server dropdown**: Selects VPN server from available list
    /// 7. **Settings checkboxes**: Toggle kill switch, auto-reconnect, DNS filtering
    /// 
    /// ## Implemented
    /// 
    /// - Server dropdown populated from `ServerManager` / `resources/servers.toml`
    /// - Checkboxes initialized from `VpnConfig` loaded from disk at startup
    /// - All checkbox and server selection changes immediately persisted via `VpnConfig::save`
    /// 
    /// ## Pending
    /// 
    /// The connect button currently only updates local GUI state. Still needed:
    /// 1. Wire connect button to `Tunnel::connect()`
    /// 2. Wire disconnect button to `Tunnel::disconnect()`
    /// 3. Update status label from actual tunnel state change events
    /// 
    /// # Arguments
    /// 
    /// * `app` - GTK4 Application instance
    pub fn build_ui(app: &Application) {
        let vpn_app = VpnApp::new();
        let config = VpnConfig::load().unwrap_or_default();
        let config_rc = Rc::new(RefCell::new(config));
        let server_manager = ServerManager::new().unwrap();
        let servers: Vec<_> = server_manager.get_servers().to_vec();

        // Create the VPN controller (spawns async worker thread)
        let controller = Rc::new(VpnController::new());

        // Create main window
        let main_application_window = ApplicationWindow::builder()
            .application(app)
            .title("RustVPN")
            .default_width(500)
            .default_height(600)
            .build();

        // Main vertical box container
        let main_vertical_box_container = GtkBox::new(Orientation::Vertical, 20);
        main_vertical_box_container.set_margin_top(30);
        main_vertical_box_container.set_margin_bottom(30);
        main_vertical_box_container.set_margin_start(30);
        main_vertical_box_container.set_margin_end(30);

        // Application title
        let application_title_label = Label::new(Some("RustVPN"));
        application_title_label.set_markup("<span size='xx-large' weight='bold'>RustVPN</span>");
        main_vertical_box_container.append(&application_title_label);

        // Connection status label
        let connection_status_display_label = Label::new(Some("Status: Disconnected"));
        connection_status_display_label.set_markup("<span size='large'>Status: Disconnected</span>");
        main_vertical_box_container.append(&connection_status_display_label);

        // Server information label
        let selected_server_info_label = Label::new(Some("Server: US-California-1"));
        selected_server_info_label.set_markup("<span size='medium'>Server: US-California-1</span>");
        main_vertical_box_container.append(&selected_server_info_label);

        // VPN IP address label
        let vpn_ip_address_display_label = Label::new(Some("IP: 203.0.113.1"));
        vpn_ip_address_display_label.set_markup("<span size='medium'>IP: 203.0.113.1</span>");
        main_vertical_box_container.append(&vpn_ip_address_display_label);

        // Connection uptime label
        let connection_uptime_display_label = Label::new(Some("Uptime: 00:00:00"));
        connection_uptime_display_label.set_markup("<span size='medium'>Uptime: 00:00:00</span>");
        main_vertical_box_container.append(&connection_uptime_display_label);

        // Connect/Disconnect button
        let vpn_connection_toggle_button = Button::with_label("CONNECT");
        vpn_connection_toggle_button.set_size_request(200, 50);

        // Clone state for button callback
        let connection_state_clone = vpn_app.current_vpn_connection_state.clone();
        let status_label_clone = connection_status_display_label.clone();
        let button_clone = vpn_connection_toggle_button.clone();
        let controller_btn = controller.clone();
        let servers_btn = servers.clone();
        let config_rc_btn = config_rc.clone();
        
        // Button click handler -- sends commands to VPN core worker
        vpn_connection_toggle_button.connect_clicked(move |_| {
            let mut current_state = connection_state_clone.borrow_mut();
            match *current_state {
                ConnectionState::Disconnected | ConnectionState::Error => {
                    // Determine which server to connect to
                    let config = config_rc_btn.borrow();
                    let server = config.selected_vpn_server_identifier
                        .as_deref()
                        .and_then(|id| servers_btn.iter().find(|s| s.server_identifier == id))
                        .or_else(|| servers_btn.first());

                    if let Some(srv) = server {
                        controller_btn.send_command(VpnCommand::Connect {
                            server_endpoint: srv.server_endpoint_address.clone(),
                            server_public_key_base64: srv.server_public_key_base64.clone(),
                        });
                        *current_state = ConnectionState::Connecting;
                        status_label_clone.set_markup("<span size='large' foreground='orange'>Status: Connecting...</span>");
                        button_clone.set_label("CONNECTING...");
                    }
                }
                ConnectionState::Connected | ConnectionState::Connecting => {
                    controller_btn.send_command(VpnCommand::Disconnect);
                    *current_state = ConnectionState::Disconnected;
                    status_label_clone.set_markup("<span size='large'>Status: Disconnected</span>");
                    button_clone.set_label("CONNECT");
                }
                _ => {}
            }
        });

        // GTK timer to poll VPN events and update the UI (every 100ms)
        let event_state = vpn_app.current_vpn_connection_state.clone();
        let event_status_label = connection_status_display_label.clone();
        let event_button = vpn_connection_toggle_button.clone();
        let controller_timer = controller.clone();
        glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
            while let Some(event) = controller_timer.try_recv_event() {
                match event {
                    VpnEvent::StateChanged(state) => {
                        let mut current = event_state.borrow_mut();
                        match state {
                            VpnState::Connected => {
                                *current = ConnectionState::Connected;
                                event_status_label.set_markup("<span size='large' foreground='green'>Status: Connected</span>");
                                event_button.set_label("DISCONNECT");
                            }
                            VpnState::Disconnected => {
                                *current = ConnectionState::Disconnected;
                                event_status_label.set_markup("<span size='large'>Status: Disconnected</span>");
                                event_button.set_label("CONNECT");
                            }
                            VpnState::Connecting => {
                                *current = ConnectionState::Connecting;
                                event_status_label.set_markup("<span size='large' foreground='orange'>Status: Connecting...</span>");
                                event_button.set_label("CONNECTING...");
                            }
                            VpnState::Reconnecting => {
                                *current = ConnectionState::Reconnecting;
                                event_status_label.set_markup("<span size='large' foreground='orange'>Status: Reconnecting...</span>");
                                event_button.set_label("RECONNECTING...");
                            }
                            VpnState::Error => {
                                *current = ConnectionState::Error;
                                event_status_label.set_markup("<span size='large' foreground='red'>Status: Error</span>");
                                event_button.set_label("CONNECT");
                            }
                        }
                    }
                    VpnEvent::Error(msg) => {
                        tracing::error!("VPN error: {}", msg);
                    }
                    VpnEvent::Info(msg) => {
                        tracing::info!("VPN info: {}", msg);
                    }
                }
            }
            glib::ControlFlow::Continue
        });

        main_vertical_box_container.append(&vpn_connection_toggle_button);

        // Server selection header
        let server_selection_header_label = Label::new(Some("Select Server:"));
        server_selection_header_label.set_markup("<span size='medium' weight='bold'>Select Server:</span>");
        main_vertical_box_container.append(&server_selection_header_label);

        let server_selection_dropdown = ComboBoxText::new();
        for server in &servers {
            server_selection_dropdown.append(
                Some(server.server_identifier.as_str()),
                &server.server_display_name,
            );
        }
        {
            let config = config_rc.borrow();
            if let Some(ref id) = config.selected_vpn_server_identifier {
                let _ = server_selection_dropdown.set_active_id(Some(id.as_str()));
            } else {
                server_selection_dropdown.set_active(Some(0));
            }
        }
        let config_rc_server = config_rc.clone();
        server_selection_dropdown.connect_changed(move |dropdown| {
            if let Some(id) = dropdown.active_id() {
                let mut config = config_rc_server.borrow_mut();
                config.selected_vpn_server_identifier = Some(id.to_string());
                if let Err(e) = config.save() {
                    tracing::warn!("Failed to save config: {}", e);
                }
            }
        });
        main_vertical_box_container.append(&server_selection_dropdown);

        // Settings header
        let vpn_settings_header_label = Label::new(Some("Settings:"));
        vpn_settings_header_label.set_markup("<span size='medium' weight='bold'>Settings:</span>");
        main_vertical_box_container.append(&vpn_settings_header_label);

        let kill_switch_protection_checkbox = CheckButton::with_label("Kill Switch (blocks traffic when VPN disconnected)");
        kill_switch_protection_checkbox.set_active(config_rc.borrow().kill_switch_protection_enabled);
        let config_rc_ks = config_rc.clone();
        let controller_ks = controller.clone();
        kill_switch_protection_checkbox.connect_toggled(move |checkbox| {
            let active = checkbox.is_active();
            let mut config = config_rc_ks.borrow_mut();
            config.kill_switch_protection_enabled = active;
            if let Err(e) = config.save() {
                tracing::warn!("Failed to save config: {}", e);
            }
            controller_ks.send_command(VpnCommand::SetKillSwitch(active));
        });
        main_vertical_box_container.append(&kill_switch_protection_checkbox);

        let auto_reconnect_protection_checkbox = CheckButton::with_label("Auto-reconnect (automatically reconnect on failure)");
        auto_reconnect_protection_checkbox.set_active(config_rc.borrow().auto_reconnect_enabled);
        let config_rc_ar = config_rc.clone();
        let controller_ar = controller.clone();
        auto_reconnect_protection_checkbox.connect_toggled(move |checkbox| {
            let active = checkbox.is_active();
            let mut config = config_rc_ar.borrow_mut();
            config.auto_reconnect_enabled = active;
            if let Err(e) = config.save() {
                tracing::warn!("Failed to save config: {}", e);
            }
            controller_ar.send_command(VpnCommand::SetAutoReconnect(active));
        });
        main_vertical_box_container.append(&auto_reconnect_protection_checkbox);

        let dns_filtering_protection_checkbox = CheckButton::with_label("DNS Filtering (block ads and malware)");
        dns_filtering_protection_checkbox.set_active(config_rc.borrow().dns_filtering_protection_enabled);
        let config_rc_dns = config_rc.clone();
        dns_filtering_protection_checkbox.connect_toggled(move |checkbox| {
            let mut config = config_rc_dns.borrow_mut();
            config.dns_filtering_protection_enabled = checkbox.is_active();
            if let Err(e) = config.save() {
                tracing::warn!("Failed to save config: {}", e);
            }
        });
        main_vertical_box_container.append(&dns_filtering_protection_checkbox);

        main_application_window.set_child(Some(&main_vertical_box_container));
        main_application_window.present();
    }

    /// Runs the GTK4 application main loop
    /// 
    /// Creates the GTK4 Application instance, connects the activate signal
    /// to build the UI, and starts the main event loop.
    /// 
    /// ## Networking Context
    /// 
    /// This is the entry point for the GUI application. The main loop
    /// handles user interactions (button clicks, checkbox toggles, etc.)
    /// which trigger VPN networking operations.
    /// 
    /// ## Application Lifecycle
    /// 
    /// 1. Application is created with unique ID
    /// 2. Activate signal is connected to build_ui()
    /// 3. Main loop starts, waiting for events
    /// 4. User interactions trigger callbacks
    /// 5. Callbacks update state or trigger VPN operations
    /// 6. Loop continues until application exits
    /// 
    /// ## Pending Integration
    /// 
    /// 1. Initialize VPN core components (Tunnel, KillSwitch, ReconnectManager)
    /// 2. Wire GUI callbacks to core operations
    /// 3. Drive status label updates from tunnel state change events
    pub fn run() {
        let gtk4_application_instance = Application::builder()
            .application_id("com.rustvpn.app")
            .build();

        gtk4_application_instance.connect_activate(|application_reference| {
            VpnApp::build_ui(application_reference);
        });

        gtk4_application_instance.run();
    }
}
