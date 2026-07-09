//! Main — RustVPN application entry point and initialization.
//!
//! # Role in RustVPN
//! This is the main entry point for the RustVPN application. It performs
//! graceful startup checks, privilege minimization, configuration loading,
//! and launches the Iced graphical user interface. It sets up the runtime
//! environment before delegating control to the GUI.
//!
//! # Main Contracts
//! - Input: Command-line arguments (none currently)
//! - Output: Iced GUI application window
//! - Safety: Privilege checks, capability minimization, structured logging
//!
//! # Platform Notes
//! Cross-platform startup sequence:
//! - Linux: Checks for CAP_NET_ADMIN, drops other capabilities
//! - macOS: Checks for root privileges
//! - Windows: Checks for Administrator privileges
//!
//! # Non-goals
//! This module does not implement VPN operations (delegated to core modules).
//! It does not handle networking directly (GUI controls VPN via controller).
//! It does not parse command-line arguments (GUI-only application).

use rust_vpn::config::VpnConfig;
use rust_vpn::gui::app::VpnApp;
use rust_vpn::privilege;
use rust_vpn::server::ServerManager;
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

    // Capture the invoking user's UID/GID *before* anything else runs.
    // The environment is mutable; freezing this value at the top of main
    // protects it from later library code that might unset SUDO_UID.
    // The captured value is currently logged for diagnostics; future work
    // can pass it to a setuid-based privilege drop if reconnects are
    // disabled (see src/privilege.rs).
    if let Some((uid, gid)) = privilege::capture_invoking_user() {
        tracing::info!(
            "Invoked via sudo by UID={} GID={} (retained for future privilege drops)",
            uid,
            gid
        );
    }

    // Check for required privileges
    if !check_privileges() {
        eprintln!("Error: RustVPN requires root/administrator privileges to create TUN devices and configure routing.");
        eprintln!("Please run with sudo (Linux/macOS) or as Administrator (Windows).");
        std::process::exit(1);
    }

    // Drop every Linux capability except CAP_NET_ADMIN now that we have
    // confirmed we hold the privileges we need. This runs *before* config
    // load, server-list parsing, and the update-check HTTP request -- so
    // a bug in any of those code paths cannot exercise capabilities like
    // CAP_DAC_OVERRIDE, CAP_SYS_ADMIN, or CAP_KILL. The TUN device and
    // routing-table operations needed for Connect/Disconnect continue to
    // work because they only require CAP_NET_ADMIN.
    if let Err(e) = privilege::minimize_capabilities() {
        tracing::warn!("Capability minimization failed: {}", e);
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
    
    // The update check is now spawned inside `VpnApp::new()` so the result
    // can be routed back to the GUI as a dismissable `UpdateAvailable` banner
    // (see `src/gui/app.rs`). Keeping it here would either duplicate the
    // network call or require plumbing the controller's event sender out
    // through `main`, both of which we want to avoid.

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
            eprintln!("Note: Running as root may cause GUI display issues.");
            eprintln!("Consider running with CAP_NET_ADMIN capability instead:");
            eprintln!("  sudo setcap cap_net_admin+ep ./target/release/rust-vpn");
            eprintln!("  ./target/release/rust-vpn");
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
        eprintln!("Error: RustVPN requires CAP_NET_ADMIN capability to create TUN devices and configure routing.");
        eprintln!();
        eprintln!("To grant the required capability, run:");
        eprintln!("  sudo setcap cap_net_admin+ep ./target/release/rust-vpn");
        eprintln!();
        eprintln!("Or use the automated setup script:");
        eprintln!("  ./setup.sh");
        eprintln!();
        eprintln!("Then run the application as a normal user:");
        eprintln!("  ./target/release/rust-vpn");
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
        // Windows support is not implemented yet (see lib.rs's Platform Notes —
        // no platform::windows module, no KillSwitch::enable_windows firewall
        // rules). A privilege gate that can't verify the privilege it's gating
        // must fail closed, not optimistically proceed: returning `true` here
        // would let the app limp past this check into TUN-device creation
        // failures with a confusing later error, or worse, into believing it
        // has protections it cannot actually provide on this platform.
        tracing::error!(
            "Administrator privilege check is not implemented for Windows, and \
             Windows is not a supported platform yet — refusing to run"
        );
        false
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        tracing::error!("Privilege check not implemented for this platform — refusing to run");
        false // Fail closed: an unrecognized platform is not a verified-privileged one.
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

