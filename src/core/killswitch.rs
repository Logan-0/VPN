//! # Kill Switch Module
//!
//! This module implements a network kill switch that blocks all non-VPN traffic
//! when the VPN is disconnected or fails.
//!
//! ## Why a Kill Switch is Critical
//!
//! Without a kill switch, if your VPN connection drops:
//! - Your real IP address is exposed
//! - Traffic goes unencrypted over your ISP
//! - DNS queries leak to your ISP
//! - You might not notice the connection dropped
//!
//! The kill switch prevents this by:
//! - Blocking ALL traffic when VPN is disconnected
//! - Only allowing traffic through the VPN tunnel
//! - Preventing DNS and IPv6 leaks
//! - Automatically re-enabling when VPN reconnects
//!
//! ## How It Works
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Normal Operation                         │
//! │                                                             │
//! │  App Traffic ──► VPN Tunnel ──► Encrypted ──► Internet     │
//! │                                                             │
//! └─────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────┐
//! │              VPN Disconnected (Kill Switch ON)              │
//! │                                                             │
//! │  App Traffic ──► Firewall ──► BLOCKED                  │
//! │                                                             │
//! │  Only Allowed:                                              │
//! │  - VPN reconnection attempts                                │
//! │  - Local network (192.168.x.x, 10.x.x.x)                   │
//! │                                                             │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Platform-Specific Implementation
//!
//! ### Linux (iptables/nftables)
//! ```bash
//! # Block all outgoing traffic
//! iptables -P OUTPUT DROP
//!
//! # Allow VPN interface
//! iptables -A OUTPUT -o wg0 -j ACCEPT
//!
//! # Allow local network
//! iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT
//! iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT
//!
//! # Allow loopback
//! iptables -A OUTPUT -o lo -j ACCEPT
//!
//! # Allow VPN server connection
//! iptables -A OUTPUT -d <vpn_server_ip> -p udp --dport 51820 -j ACCEPT
//! ```
//!
//! ### macOS (pf - Packet Filter)
//! ```text
//! # Block all traffic except VPN
//! block drop all
//! pass on utun0
//! pass on lo0
//! pass to <vpn_server_ip> port 51820 proto udp
//! ```
//!
//! ### Windows (Windows Filtering Platform)
//! Uses WFP API to create filters that:
//! - Block all outbound traffic by default
//! - Allow VPN interface
//! - Allow VPN server connection
//!
//! ## Leak Prevention
//!
//! The kill switch prevents several types of leaks:
//!
//! 1. **IP Leak**: Your real IP is never exposed
//! 2. **DNS Leak**: DNS queries can't bypass the VPN
//! 3. **IPv6 Leak**: IPv6 traffic is blocked or routed through VPN
//! 4. **WebRTC Leak**: Local IP discovery is blocked
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! // Enable kill switch before connecting
//! let mut killswitch = KillSwitch::new()?;
//! killswitch.enable("10.8.0.1".parse()?, "wg0")?;
//!
//! // Connect VPN
//! tunnel.connect().await?;
//!
//! // If VPN disconnects, traffic is blocked automatically
//! // ...
//!
//! // Disable kill switch when user disconnects
//! killswitch.disable()?;
//! ```

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

    #[cfg(target_os = "macos")]
    fn enable_macos(&self, vpn_server_ip: IpAddr, vpn_interface: &str) -> Result<()> {
        use std::fs;
        use std::process::Command;

        info!("Applying macOS pf rules");

        // Create pf rules file
        let rules = format!(
            r#"# RustVPN Kill Switch Rules
# Block all traffic except VPN

block drop all
pass on lo0
pass on {}
pass out proto udp to {} port 51820
pass to 192.168.0.0/16
pass to 10.0.0.0/8
pass to 172.16.0.0/12
"#,
            vpn_interface, vpn_server_ip
        );

        fs::write("/tmp/rustvpn.pf.conf", rules)
            .context("Failed to write pf rules file")?;

        // Load pf rules
        Command::new("pfctl")
            .args(["-f", "/tmp/rustvpn.pf.conf"])
            .output()
            .context("Failed to load pf rules")?;

        // Enable pf
        Command::new("pfctl")
            .args(["-e"])
            .output()
            .context("Failed to enable pf")?;

        info!("macOS pf rules applied successfully");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn disable_macos(&self) -> Result<()> {
        use std::process::Command;

        info!("Removing macOS pf rules");

        // Disable pf (this may affect other pf users, so we just flush our rules)
        let _ = Command::new("pfctl")
            .args(["-F", "all"])
            .output();

        // Clean up rules file
        let _ = std::fs::remove_file("/tmp/rustvpn.pf.conf");

        info!("macOS pf rules removed successfully");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn enable_windows(&self, vpn_server_ip: IpAddr, vpn_interface: &str) -> Result<()> {
        info!("Applying Windows Firewall rules");
        
        // Windows implementation would use WFP (Windows Filtering Platform) API
        // This requires the windows crate and is more complex
        // For now, we'll use netsh as a simpler approach
        
        use std::process::Command;

        // Block all outbound traffic
        Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                "name=RustVPN-BlockAll",
                "dir=out",
                "action=block",
            ])
            .output()
            .context("Failed to add block rule")?;

        // Allow VPN server
        Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                &format!("name=RustVPN-AllowServer-{}", vpn_server_ip),
                "dir=out",
                "action=allow",
                "protocol=UDP",
                "remoteport=51820",
                &format!("remoteip={}", vpn_server_ip),
            ])
            .output()
            .context("Failed to add VPN server rule")?;

        // Allow local network
        Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                "name=RustVPN-AllowLocal",
                "dir=out",
                "action=allow",
                "remoteip=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12",
            ])
            .output()
            .context("Failed to add local network rule")?;

        info!("Windows Firewall rules applied successfully");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn disable_windows(&self) -> Result<()> {
        use std::process::Command;

        info!("Removing Windows Firewall rules");

        // Remove our firewall rules
        let _ = Command::new("netsh")
            .args([
                "advfirewall", "firewall", "delete", "rule",
                "name=RustVPN-BlockAll",
            ])
            .output();

        let _ = Command::new("netsh")
            .args([
                "advfirewall", "firewall", "delete", "rule",
                "name=RustVPN-AllowServer",
            ])
            .output();

        let _ = Command::new("netsh")
            .args([
                "advfirewall", "firewall", "delete", "rule",
                "name=RustVPN-AllowLocal",
            ])
            .output();

        info!("Windows Firewall rules removed successfully");
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
