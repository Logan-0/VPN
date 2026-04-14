//! # RustVPN Main Entry Point
//!
//! This is the main entry point for the RustVPN application.
//! It initializes logging and starts the GTK4 graphical user interface.
//!
//! ## Networking Concepts
//!
/// The main function doesn't directly handle networking, but it:
/// - Initializes logging for network operations debugging
/// - Starts the GUI which controls VPN networking components
/// - Sets up the application runtime environment
///
/// ## Application Startup Sequence
///
/// 1. Initialize tracing subscriber for structured logging
/// 2. Create and run GTK4 application
/// 3. Build user interface
/// 4. Wait for user interactions
/// 5. Handle VPN connection requests from GUI

use rust_vpn::gui::app::VpnApp;

/// Main entry point for the RustVPN application
/// 
/// Initializes logging infrastructure and starts the GTK4 GUI application.
/// This is the first function executed when the application launches.
/// 
/// ## Networking Context
/// 
/// The main function sets up the environment for VPN operations:
/// - Logging: Captures network operations for debugging
/// - GUI: Provides user interface for VPN control
/// - Runtime: Manages async tasks for VPN tunnel
/// 
/// ## Logging
/// 
/// Uses tracing-subscriber for structured logging. This logs:
/// - VPN connection attempts
/// - Packet encryption/decryption operations
/// - Tunnel state changes
/// - Error conditions
/// - Health check results
/// 
/// ## Future Implementation
/// 
/// Future main function will:
/// 1. Load configuration from disk
/// 2. Check for required privileges (root/admin)
/// 3. Initialize VPN core components
/// 4. Check for application updates
/// 5. Handle command-line arguments
/// 6. Start GUI with VPN core integration
fn main() {
    // Initialize structured logging for network operations
    // This captures all VPN-related events for debugging and monitoring
    tracing_subscriber::fmt::init();
    
    // Run the GTK4 GUI application
    // The GUI provides user control over VPN networking operations
    VpnApp::run();
}
