use rust_vpn::gui::app::VpnApp;

fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Run the GTK4 GUI application
    VpnApp::run();
}
