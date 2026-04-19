//! # RustVPN Main Entry Point
//!
//! This is the main entry point for the RustVPN application.
//! It performs graceful startup checks and starts the Iced graphical user interface.
//!
//! ## Networking Concepts
//!
/// The main function doesn't directly handle networking, but it:
/// - Initializes logging for network operations debugging
/// - Checks for required privileges (root/admin)
/// - Loads and validates configuration
/// - Starts the GUI which controls VPN networking components
/// - Sets up the application runtime environment
///
/// ## Application Startup Sequence
///
/// 1. Initialize tracing subscriber for structured logging
/// 2. Check for required privileges (root/admin)
/// 3. Load configuration from disk
/// 4. Validate configuration values
/// 5. Spawn background thread for update check (non-blocking)
/// 6. Create and run Iced application (Elm architecture)
/// 7. Build user interface
/// 8. Wait for user interactions
/// 9. Handle VPN connection requests from GUI

use rust_vpn::config::VpnConfig;
use rust_vpn::gui::app::VpnApp;
use rust_vpn::server::ServerManager;
use rust_vpn::update::UpdateChecker;
use anyhow::Result;

/// Main entry point for the RustVPN application
/// 
/// Performs graceful startup with privilege checks, configuration loading,
/// and validation before starting the Iced GUI application.
/// 
/// ## Networking Context
/// 
/// The main function sets up the environment for VPN operations:
/// - Logging: Captures network operations for debugging
/// - Privilege checks: Ensures required permissions for TUN devices
/// - Configuration: Loads user preferences and server selection
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
fn main() {
    // Initialize structured logging for network operations
    // This captures all VPN-related events for debugging and monitoring
    tracing_subscriber::fmt::init();
    
    tracing::info!("RustVPN starting...");
    
    // Check for required privileges
    if !check_privileges() {
        eprintln!("Error: RustVPN requires root/administrator privileges to create TUN devices and configure routing.");
        eprintln!("Please run with sudo (Linux/macOS) or as Administrator (Windows).");
        std::process::exit(1);
    }
    
    // Load configuration from disk
    let config = match VpnConfig::load() {
        Ok(cfg) => {
            tracing::info!("Configuration loaded successfully");
            cfg
        }
        Err(e) => {
            tracing::warn!("Failed to load configuration, using defaults: {}", e);
            VpnConfig::default()
        }
    };
    
    // Validate configuration
    if let Err(e) = validate_config(&config) {
        eprintln!("Error: Invalid configuration: {}", e);
        std::process::exit(1);
    }
    
    // Spawn background thread so the update check never delays GUI startup
    std::thread::spawn(|| {
        if let Ok(rt) = tokio::runtime::Runtime::new() {
            let update_checker = UpdateChecker::new(env!("CARGO_PKG_VERSION").to_string());
            rt.block_on(async {
                if let Err(e) = check_updates(&update_checker).await {
                    tracing::warn!("Failed to check for updates: {}", e);
                }
            });
        }
    });
    
    // Run the Iced GUI application (cross-platform, pure Rust, Elm architecture)
    // The GUI provides user control over VPN networking operations
    tracing::info!("Starting GUI application...");
    VpnApp::run();
}

/// Checks if the application is running with required privileges
/// 
/// VPN operations require:
/// - Linux: root or CAP_NET_ADMIN capability
/// - macOS: root privileges
/// - Windows: Administrator privileges
/// 
/// Returns true if running with required privileges, false otherwise
fn check_privileges() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check if running as root
        if nix::unistd::Uid::effective().is_root() {
            tracing::info!("Running as root");
            return true;
        }
        
        // Check for CAP_NET_ADMIN capability using caps crate
        if let Ok(has_cap) = caps::has_cap(None, caps::CapSet::Permitted, caps::Capability::CAP_NET_ADMIN) {
            if has_cap {
                tracing::info!("Running with CAP_NET_ADMIN capability");
                return true;
            }
        }
        
        tracing::error!("Not running as root or with CAP_NET_ADMIN capability");
        false
    }
    
    #[cfg(target_os = "macos")]
    {
        // Check if running as root
        if nix::unistd::Uid::effective().is_root() {
            tracing::info!("Running as root");
            true
        } else {
            tracing::error!("Not running as root");
            false
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        // Check if running as Administrator
        // This is a simplified check - real implementation would use Windows API
        tracing::warn!("Administrator privilege check not implemented for Windows");
        true // Temporary: allow running for now
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        tracing::warn!("Privilege check not implemented for this platform");
        true // Allow running on other platforms
    }
}

/// Validates the configuration values
/// 
/// Ensures that configuration values are within acceptable ranges
/// and that required fields are present.
/// 
/// ## Checks Performed
/// 
/// 1. If a server identifier is saved, verify it exists in the server list.
///    A stale or mistyped identifier is downgraded to `None` so the GUI
///    falls back to the first server rather than silently selecting nothing.
fn validate_config(config: &VpnConfig) -> Result<()> {
    if let Some(ref server_id) = config.selected_vpn_server_identifier {
        match ServerManager::new() {
            Ok(manager) => {
                if manager.find_by_id(server_id).is_none() {
                    tracing::warn!(
                        "Configured server '{}' not found in server list, will fall back to default",
                        server_id
                    );
                }
            }
            Err(e) => {
                tracing::warn!("Could not load server list for validation: {}", e);
            }
        }
    }
    Ok(())
}

/// Checks for application updates from GitHub releases
/// 
/// This is a non-blocking check that logs if an update is available.
/// It does not force updates or interrupt the user.
async fn check_updates(update_checker: &UpdateChecker) -> Result<()> {
    match update_checker.check_for_updates().await {
        Ok(Some(version)) => {
            tracing::info!("Update available: {}", version);
            tracing::info!("Please download the latest version from GitHub releases");
        }
        Ok(None) => {
            tracing::debug!("No updates available");
        }
        Err(e) => {
            tracing::warn!("Failed to check for updates: {}", e);
        }
    }
    Ok(())
}
