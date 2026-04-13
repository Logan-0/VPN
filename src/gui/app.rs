//! # VPN GUI Application (GTK4)
//!
//! Simple, reliable cross-platform GUI using GTK4.

use gtk4::prelude::*;
use gtk4::{
    Application, ApplicationWindow, Box as GtkBox, Button, CheckButton, ComboBoxText, Label,
    Orientation,
};
use std::cell::RefCell;
use std::rc::Rc;

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Error,
}


/// Main VPN application state
pub struct VpnApp {
    pub connection_state: Rc<RefCell<ConnectionState>>,
    pub kill_switch_enabled: Rc<RefCell<bool>>,
    pub auto_reconnect_enabled: Rc<RefCell<bool>>,
    pub dns_filtering_enabled: Rc<RefCell<bool>>,
}

impl VpnApp {
    pub fn new() -> Self {
        Self {
            connection_state: Rc::new(RefCell::new(ConnectionState::Disconnected)),
            kill_switch_enabled: Rc::new(RefCell::new(true)),
            auto_reconnect_enabled: Rc::new(RefCell::new(true)),
            dns_filtering_enabled: Rc::new(RefCell::new(true)),
        }
    }

    pub fn build_ui(app: &Application) {
        let vpn_app = VpnApp::new();

        // Create main window
        let window = ApplicationWindow::builder()
            .application(app)
            .title("RustVPN")
            .default_width(500)
            .default_height(600)
            .build();

        // Main vertical box
        let vbox = GtkBox::new(Orientation::Vertical, 20);
        vbox.set_margin_top(30);
        vbox.set_margin_bottom(30);
        vbox.set_margin_start(30);
        vbox.set_margin_end(30);

        // Title
        let title = Label::new(Some("RustVPN"));
        title.set_markup("<span size='xx-large' weight='bold'>RustVPN</span>");
        vbox.append(&title);

        // Status label
        let status_label = Label::new(Some("Status: Disconnected"));
        status_label.set_markup("<span size='large'>Status: Disconnected</span>");
        vbox.append(&status_label);

        // Server info
        let server_label = Label::new(Some("Server: US-California-1"));
        server_label.set_markup("<span size='medium'>Server: US-California-1</span>");
        vbox.append(&server_label);

        let ip_label = Label::new(Some("IP: 203.0.113.1"));
        ip_label.set_markup("<span size='medium'>IP: 203.0.113.1</span>");
        vbox.append(&ip_label);

        // Uptime
        let uptime_label = Label::new(Some("Uptime: 00:00:00"));
        uptime_label.set_markup("<span size='medium'>Uptime: 00:00:00</span>");
        vbox.append(&uptime_label);

        // Connect button
        let connect_button = Button::with_label("CONNECT");
        connect_button.set_size_request(200, 50);

        let state_clone = vpn_app.connection_state.clone();
        let status_clone = status_label.clone();
        let button_clone = connect_button.clone();
        
        connect_button.connect_clicked(move |_| {
            let mut state = state_clone.borrow_mut();
            match *state {
                ConnectionState::Disconnected | ConnectionState::Error => {
                    *state = ConnectionState::Connected;
                    status_clone.set_markup("<span size='large' foreground='green'>Status: Connected</span>");
                    button_clone.set_label("DISCONNECT");
                }
                ConnectionState::Connected => {
                    *state = ConnectionState::Disconnected;
                    status_clone.set_markup("<span size='large'>Status: Disconnected</span>");
                    button_clone.set_label("CONNECT");
                }
                _ => {}
            }
        });

        vbox.append(&connect_button);

        // Server selection
        let server_label_header = Label::new(Some("Select Server:"));
        server_label_header.set_markup("<span size='medium' weight='bold'>Select Server:</span>");
        vbox.append(&server_label_header);

        let server_combo = ComboBoxText::new();
        server_combo.append_text("US-California-1");
        server_combo.append_text("US-NewYork-1");
        server_combo.append_text("Sweden-Stockholm-1");
        server_combo.set_active(Some(0));
        vbox.append(&server_combo);

        // Settings
        let settings_label = Label::new(Some("Settings:"));
        settings_label.set_markup("<span size='medium' weight='bold'>Settings:</span>");
        vbox.append(&settings_label);

        // Kill switch checkbox
        let kill_switch_cb = CheckButton::with_label("Kill Switch (blocks traffic when VPN disconnected)");
        kill_switch_cb.set_active(true);
        vbox.append(&kill_switch_cb);

        // Auto-reconnect checkbox
        let auto_reconnect_cb = CheckButton::with_label("Auto-reconnect (automatically reconnect on failure)");
        auto_reconnect_cb.set_active(true);
        vbox.append(&auto_reconnect_cb);

        // DNS filtering checkbox
        let dns_filtering_cb = CheckButton::with_label("DNS Filtering (block ads and malware)");
        dns_filtering_cb.set_active(true);
        vbox.append(&dns_filtering_cb);

        window.set_child(Some(&vbox));
        window.present();
    }

    pub fn run() {
        let app = Application::builder()
            .application_id("com.rustvpn.app")
            .build();

        app.connect_activate(|app| {
            VpnApp::build_ui(app);
        });

        app.run();
    }
}
