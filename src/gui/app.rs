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
/// - Allows user to control networking features (kill switch, etc.)
/// - Displays uptime and connection statistics
///
/// The GUI communicates with the VPN core through state management.
/// When the user clicks "Connect", the GUI triggers the VPN tunnel connection.
/// When the VPN state changes, the GUI updates to reflect the current status.

use gtk4::prelude::*;
use gtk4::{
    Application, ApplicationWindow, Box as GtkBox, Button, CheckButton, ComboBoxText, Label,
    Orientation,
};
use std::cell::RefCell;
use std::rc::Rc;

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
/// Contains the application state including connection status and user preferences.
/// This state is shared between the GUI and the VPN core components.
///
/// ## Networking Relevance
///
/// The application state controls VPN networking behavior:
/// - `current_vpn_connection_state`: Determines if VPN tunnel is active
/// - `kill_switch_protection_enabled`: Controls firewall rule activation
/// - `auto_reconnect_enabled`: Controls automatic reconnection on failure
/// - `dns_filtering_protection_enabled`: Controls DNS query filtering
///
/// These settings are toggled by the user and affect how network traffic
/// is handled when the VPN is active.
pub struct VpnApp {
    /// Current VPN connection state (thread-safe reference)
    /// 
    /// Uses Rc<RefCell> for interior mutability, allowing the GUI
    /// to update the state from callbacks. The state is shared
    /// with the VPN core to synchronize connection status.
    pub current_vpn_connection_state: Rc<RefCell<ConnectionState>>,
    
    /// Kill switch protection enabled state
    /// 
    /// When true, the kill switch is activated before connecting
    /// and blocks all non-VPN traffic when disconnected.
    /// This prevents IP address leaks.
    pub kill_switch_protection_enabled: Rc<RefCell<bool>>,
    
    /// Auto-reconnect enabled state
    /// 
    /// When true, the VPN will automatically attempt to reconnect
    /// if the connection is lost, using exponential backoff.
    pub auto_reconnect_enabled: Rc<RefCell<bool>>,
    
    /// DNS filtering protection enabled state
    /// 
    /// When true, DNS queries are filtered against blocklists
    /// and encrypted using DNS-over-HTTPS to prevent DNS leaks.
    pub dns_filtering_protection_enabled: Rc<RefCell<bool>>,
}

impl VpnApp {
    /// Creates a new VPN application instance with default settings
    /// 
    /// Initializes the application state with security-focused defaults:
    /// - Connection state: Disconnected
    /// - Kill switch: Enabled (prevents leaks)
    /// - Auto-reconnect: Enabled (automatic recovery)
    /// - DNS filtering: Enabled (blocks ads/malware)
    /// 
    /// ## Networking Context
    /// 
    /// Application creation occurs during GUI initialization.
    /// The default settings prioritize security and privacy protection.
    /// 
    /// # Returns
    /// 
    /// New VpnApp instance with default state
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
    /// ## Future Integration
    /// 
    /// Currently the connect button only updates the GUI state.
    /// Future implementation will:
    /// 1. Wire connect button to Tunnel::connect()
    /// 2. Wire disconnect button to Tunnel::disconnect()
    /// 3. Update status from actual tunnel state
    /// 4. Wire settings checkboxes to actual feature toggles
    /// 5. Load server list from ServerManager
    /// 
    /// # Arguments
    /// 
    /// * `app` - GTK4 Application instance
    pub fn build_ui(app: &Application) {
        let vpn_app = VpnApp::new();

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
        
        // Button click handler (future: integrate with VPN core)
        vpn_connection_toggle_button.connect_clicked(move |_| {
            let mut current_state = connection_state_clone.borrow_mut();
            match *current_state {
                ConnectionState::Disconnected | ConnectionState::Error => {
                    // TODO: Call Tunnel::connect() here
                    *current_state = ConnectionState::Connected;
                    status_label_clone.set_markup("<span size='large' foreground='green'>Status: Connected</span>");
                    button_clone.set_label("DISCONNECT");
                }
                ConnectionState::Connected => {
                    // TODO: Call Tunnel::disconnect() here
                    *current_state = ConnectionState::Disconnected;
                    status_label_clone.set_markup("<span size='large'>Status: Disconnected</span>");
                    button_clone.set_label("CONNECT");
                }
                _ => {}
            }
        });

        main_vertical_box_container.append(&vpn_connection_toggle_button);

        // Server selection header
        let server_selection_header_label = Label::new(Some("Select Server:"));
        server_selection_header_label.set_markup("<span size='medium' weight='bold'>Select Server:</span>");
        main_vertical_box_container.append(&server_selection_header_label);

        // Server selection dropdown (future: load from ServerManager)
        let server_selection_dropdown = ComboBoxText::new();
        server_selection_dropdown.append_text("US-California-1");
        server_selection_dropdown.append_text("US-NewYork-1");
        server_selection_dropdown.append_text("Sweden-Stockholm-1");
        server_selection_dropdown.set_active(Some(0));
        main_vertical_box_container.append(&server_selection_dropdown);

        // Settings header
        let vpn_settings_header_label = Label::new(Some("Settings:"));
        vpn_settings_header_label.set_markup("<span size='medium' weight='bold'>Settings:</span>");
        main_vertical_box_container.append(&vpn_settings_header_label);

        // Kill switch checkbox (future: wire to KillSwitch)
        let kill_switch_protection_checkbox = CheckButton::with_label("Kill Switch (blocks traffic when VPN disconnected)");
        kill_switch_protection_checkbox.set_active(true);
        main_vertical_box_container.append(&kill_switch_protection_checkbox);

        // Auto-reconnect checkbox (future: wire to ReconnectManager)
        let auto_reconnect_protection_checkbox = CheckButton::with_label("Auto-reconnect (automatically reconnect on failure)");
        auto_reconnect_protection_checkbox.set_active(true);
        main_vertical_box_container.append(&auto_reconnect_protection_checkbox);

        // DNS filtering checkbox (future: wire to DnsFilter)
        let dns_filtering_protection_checkbox = CheckButton::with_label("DNS Filtering (block ads and malware)");
        dns_filtering_protection_checkbox.set_active(true);
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
    /// # Future Integration
    /// 
    /// Future implementation will:
    /// 1. Load configuration on startup
    /// 2. Initialize VPN core components
    /// 3. Wire GUI callbacks to VPN operations
    /// 4. Handle VPN state changes and update GUI
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
