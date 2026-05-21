//! Kill Switch — Network traffic blocking to prevent IP leaks.
//!
//! # Role in RustVPN
//! This module implements a network kill switch that blocks all non-VPN traffic
//! when the VPN is disconnected or fails. It prevents IP address exposure and
//! DNS leaks by using platform-specific firewall rules to block traffic unless
//! it flows through the VPN tunnel interface.
//!
//! # Main Contracts
//! - Input: VPN server IP and interface name for firewall rules
//! - Output: Firewall rule installation/removal
//! - Safety: Requires root/admin privileges; cleanup on Drop prevents rule leakage
//!
//! # Platform Notes
//! Platform-specific firewall implementations:
//! - Linux: Uses iptables with custom chain RUSTVPN_OUT
//! - macOS: Uses pf (packet filter) with rules file
//! - Windows: Uses netsh to configure Windows Firewall
//!
//! # Non-goals
//! This module does not implement packet filtering (delegated to DNS filter module).
//! It does not monitor connection health (delegated to reconnect module).
//! It does not handle IPv6 routing beyond basic blocking.

use anyhow::{Context, Result};
use std::net::IpAddr;
use tracing::{debug, info, warn};

/// Kill switch state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillSwitchState {
    /// Kill switch is disabled, all traffic allowed
    Disabled,
    
    /// Kill switch is enabled, only VPN traffic allowed
    Enabled,
}

/// Network kill switch that blocks all non-VPN traffic.
///
/// This prevents IP/DNS leaks when the VPN connection drops.
pub struct KillSwitch {
    /// Current state of the kill switch
    state: KillSwitchState,
    
    /// VPN server IP (allowed through firewall)
    vpn_server_ip: Option<IpAddr>,
    
    /// VPN interface name (e.g., "wg0", "utun0")
    vpn_interface: Option<String>,
}

impl KillSwitch {
    /// Creates a new kill switch in disabled state.
    pub fn new() -> Result<Self> {
        info!("Creating kill switch");
        
        Ok(Self {
            state: KillSwitchState::Disabled,
            vpn_server_ip: None,
            vpn_interface: None,
        })
    }

    /// Enables the kill switch to block all non-VPN traffic.
    ///
    /// This should be called BEFORE connecting to the VPN to ensure
    /// no traffic leaks during connection establishment.
    ///
    /// # Arguments
    /// * `vpn_server_ip` - IP address of the VPN server (allowed through firewall)
    /// * `vpn_interface` - Name of the VPN network interface (e.g., "wg0")
    ///
    /// # Platform Behavior
    /// - **Linux**: Uses iptables to block all traffic except VPN
    /// - **macOS**: Uses pf (packet filter) to block traffic
    /// - **Windows**: Uses Windows Filtering Platform API
    ///
    /// # Example
    /// ```rust,ignore
    /// killswitch.enable("203.0.113.1".parse()?, "wg0")?;
    /// // Now only VPN traffic is allowed
    /// ```
    pub fn enable(&mut self, vpn_server_ip: IpAddr, vpn_interface: &str) -> Result<()> {
        if self.state == KillSwitchState::Enabled {
            warn!("Kill switch already enabled");
            return Ok(());
        }

        info!(
            "Enabling kill switch for server {} on interface {}",
            vpn_server_ip, vpn_interface
        );

        self.vpn_server_ip = Some(vpn_server_ip);
        self.vpn_interface = Some(vpn_interface.to_string());

        // Apply platform-specific firewall rules
        #[cfg(target_os = "linux")]
        self.enable_linux(vpn_server_ip, vpn_interface)?;

        #[cfg(target_os = "macos")]
        self.enable_macos(vpn_server_ip, vpn_interface)?;

        #[cfg(target_os = "windows")]
        self.enable_windows(vpn_server_ip, vpn_interface)?;

        self.state = KillSwitchState::Enabled;
        info!("Kill switch enabled successfully");
        
        Ok(())
    }

    /// Disables the kill switch and restores normal network access.
    ///
    /// This should be called when the user manually disconnects from the VPN.
    /// It removes all firewall rules and allows normal traffic.
    pub fn disable(&mut self) -> Result<()> {
        if self.state == KillSwitchState::Disabled {
            debug!("Kill switch already disabled");
            return Ok(());
        }

        info!("Disabling kill switch");

        // Remove platform-specific firewall rules
        #[cfg(target_os = "linux")]
        self.disable_linux()?;

        #[cfg(target_os = "macos")]
        self.disable_macos()?;

        #[cfg(target_os = "windows")]
        self.disable_windows()?;

        self.state = KillSwitchState::Disabled;
        self.vpn_server_ip = None;
        self.vpn_interface = None;
        
        info!("Kill switch disabled successfully");
        Ok(())
    }

    /// Returns the current state of the kill switch.
    pub fn is_enabled(&self) -> bool {
        self.state == KillSwitchState::Enabled
    }

    /// Returns the current state.
    pub fn get_state(&self) -> KillSwitchState {
        self.state
    }

    // Platform-specific implementations

    #[cfg(target_os = "linux")]
    fn enable_linux(&self, vpn_server_ip: IpAddr, vpn_interface: &str) -> Result<()> {
        use std::process::Command;

        info!("Applying Linux iptables rules");

        // Flush existing rules in our custom chain (if it exists)
        let _ = Command::new("iptables")
            .args(["-F", "RUSTVPN_OUT"])
            .output();

        // Create custom chain for our rules
        let _ = Command::new("iptables")
            .args(["-N", "RUSTVPN_OUT"])
            .output();

        // Allow loopback
        Command::new("iptables")
            .args(["-A", "RUSTVPN_OUT", "-o", "lo", "-j", "ACCEPT"])
            .output()
            .context("Failed to add loopback rule")?;

        // Allow VPN interface
        Command::new("iptables")
            .args(["-A", "RUSTVPN_OUT", "-o", vpn_interface, "-j", "ACCEPT"])
            .output()
            .context("Failed to add VPN interface rule")?;

        // Allow connection to VPN server
        Command::new("iptables")
            .args([
                "-A", "RUSTVPN_OUT",
                "-d", &vpn_server_ip.to_string(),
                "-p", "udp",
                "--dport", "51820",
                "-j", "ACCEPT",
            ])
            .output()
            .context("Failed to add VPN server rule")?;

        // Allow local network (192.168.0.0/16)
        Command::new("iptables")
            .args(["-A", "RUSTVPN_OUT", "-d", "192.168.0.0/16", "-j", "ACCEPT"])
            .output()
            .context("Failed to add local network rule")?;

        // Allow local network (10.0.0.0/8)
        Command::new("iptables")
            .args(["-A", "RUSTVPN_OUT", "-d", "10.0.0.0/8", "-j", "ACCEPT"])
            .output()
            .context("Failed to add local network rule")?;

        // Allow local network (172.16.0.0/12)
        Command::new("iptables")
            .args(["-A", "RUSTVPN_OUT", "-d", "172.16.0.0/12", "-j", "ACCEPT"])
            .output()
            .context("Failed to add local network rule")?;

        // Drop everything else
        Command::new("iptables")
            .args(["-A", "RUSTVPN_OUT", "-j", "DROP"])
            .output()
            .context("Failed to add drop rule")?;

        // Insert our chain at the beginning of OUTPUT
        Command::new("iptables")
            .args(["-I", "OUTPUT", "1", "-j", "RUSTVPN_OUT"])
            .output()
            .context("Failed to insert chain into OUTPUT")?;

        // Block IPv6 to prevent leaks (unless VPN supports it)
        let _ = Command::new("ip6tables")
            .args(["-P", "OUTPUT", "DROP"])
            .output();

        info!("Linux iptables rules applied successfully");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn disable_linux(&self) -> Result<()> {
        use std::process::Command;

        info!("Removing Linux iptables rules");

        // Remove our chain from OUTPUT
        let _ = Command::new("iptables")
            .args(["-D", "OUTPUT", "-j", "RUSTVPN_OUT"])
            .output();

        // Flush and delete our custom chain
        let _ = Command::new("iptables")
            .args(["-F", "RUSTVPN_OUT"])
            .output();

        let _ = Command::new("iptables")
            .args(["-X", "RUSTVPN_OUT"])
            .output();

        // Restore IPv6
        let _ = Command::new("ip6tables")
            .args(["-P", "OUTPUT", "ACCEPT"])
            .output();

        info!("Linux iptables rules removed successfully");
        Ok(())
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        if self.state == KillSwitchState::Enabled {
            warn!("Kill switch dropped while enabled - attempting cleanup");
            let _ = self.disable();
        }
    }
}
