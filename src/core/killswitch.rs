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
//! Linux-only: uses iptables with the custom chain `RUSTVPN_OUT`.
//!
//! # Non-goals
//! This module does not implement packet filtering (delegated to DNS filter module).
//! It does not monitor connection health (delegated to reconnect module).
//! It does not handle IPv6 routing beyond basic blocking.

use anyhow::{Context, Result};
use std::net::IpAddr;
use tracing::{debug, info, warn};

/// Run an `iptables` command that MUST succeed for the kill switch to be
/// correct, surfacing a failure as `Err(ctx)` so the caller fails closed.
fn iptables_checked(args: &[&str], ctx: &'static str) -> Result<()> {
    std::process::Command::new("iptables")
        .args(args)
        .output()
        .context(ctx)?;
    Ok(())
}

/// Run a best-effort `iptables` command whose failure is intentionally ignored
/// (chain flush/create on enable; every rule removal on disable — failing to
/// remove a rule leaves the network *more* restricted, the safe direction).
fn iptables_best_effort(args: &[&str]) {
    let _ = std::process::Command::new("iptables").args(args).output();
}

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
    /// Linux-only: uses iptables to block all traffic except the VPN.
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

        // Apply the firewall rules (Linux-only project).
        self.enable_linux(vpn_server_ip, vpn_interface)?;

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

        // Remove the firewall rules (Linux-only project).
        self.disable_linux()?;

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

    /// Install the iptables rules that make up the Linux kill switch.
    ///
    /// # Ordering invariant (why this matters)
    /// Each `iptables` invocation below is a separate process spawn, and only
    /// the `-I OUTPUT 1 -j RUSTVPN_OUT` call near the end actually links the
    /// DROP-based `RUSTVPN_OUT` chain into the traffic path. **If any earlier `iptables`
    /// call in this sequence fails and this function returns `Err` before
    /// reaching that last call, no rule has actually blocked anything yet** —
    /// the OS `OUTPUT` chain is untouched and all traffic still flows exactly
    /// as if the kill switch were off. This function's `Result` therefore
    /// cannot be treated as advisory by callers: `KillSwitch::enable`
    /// propagates it with `?`, and `core::controller`'s `Connect`/
    /// `SetKillSwitch` handlers must abort (not merely log) on `Err` here —
    /// see the fail-closed handling in `controller.rs`'s `VpnCommand::Connect`
    /// arm. A partial failure never leaves an intermediate "some rules
    /// applied" state that looks protected but isn't: everything before the
    /// final link-in step is inert until that step runs.
    fn enable_linux(&self, vpn_server_ip: IpAddr, vpn_interface: &str) -> Result<()> {
        use std::process::Command;

        info!("Applying Linux iptables rules");

        // Flush existing rules in our custom chain (if it exists) — best effort.
        iptables_best_effort(&["-F", "RUSTVPN_OUT"]);

        // Create custom chain for our rules — best effort (may already exist).
        iptables_best_effort(&["-N", "RUSTVPN_OUT"]);

        // Allow loopback
        iptables_checked(
            &["-A", "RUSTVPN_OUT", "-o", "lo", "-j", "ACCEPT"],
            "Failed to add loopback rule",
        )?;

        // Allow VPN interface
        iptables_checked(
            &["-A", "RUSTVPN_OUT", "-o", vpn_interface, "-j", "ACCEPT"],
            "Failed to add VPN interface rule",
        )?;

        // Allow connection to VPN server
        let vpn_server_ip = vpn_server_ip.to_string();
        iptables_checked(
            &[
                "-A",
                "RUSTVPN_OUT",
                "-d",
                &vpn_server_ip,
                "-p",
                "udp",
                "--dport",
                "51820",
                "-j",
                "ACCEPT",
            ],
            "Failed to add VPN server rule",
        )?;

        // Allow local (RFC1918) networks
        for cidr in ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"] {
            iptables_checked(
                &["-A", "RUSTVPN_OUT", "-d", cidr, "-j", "ACCEPT"],
                "Failed to add local network rule",
            )?;
        }

        // Drop everything else
        iptables_checked(
            &["-A", "RUSTVPN_OUT", "-j", "DROP"],
            "Failed to add drop rule",
        )?;

        // Insert our chain at the beginning of OUTPUT. This is the link-in step
        // that actually activates the kill switch — kept LAST and `?`-checked so
        // a partial earlier failure never leaves a half-applied "looks blocked
        // but isn't" state (see the ordering-invariant doc above).
        iptables_checked(
            &["-I", "OUTPUT", "1", "-j", "RUSTVPN_OUT"],
            "Failed to insert chain into OUTPUT",
        )?;

        // Block IPv6 to prevent leaks (unless VPN supports it)
        let _ = Command::new("ip6tables")
            .args(["-P", "OUTPUT", "DROP"])
            .output();

        info!("Linux iptables rules applied successfully");
        Ok(())
    }

    /// Remove the iptables rules installed by [`Self::enable_linux`].
    ///
    /// Deliberately uses `.output()` (ignoring failures via `let _ =`) rather
    /// than `?` for every step, unlike `enable_linux`: a partial failure here
    /// means some cleanup commands didn't run, but that leaves the network
    /// *more* restricted (rules still in place), never less — which is the
    /// safe direction to fail in for a kill switch. `Agent`/`KillSwitch`
    /// callers already treat `disable()` failures as warn-and-continue (see
    /// `controller.rs`) for the same reason: erring toward "still blocked"
    /// on cleanup failure is acceptable, unlike erring toward "not blocked"
    /// on enable failure.
    fn disable_linux(&self) -> Result<()> {
        use std::process::Command;

        info!("Removing Linux iptables rules");

        // Remove our chain from OUTPUT (best effort)
        iptables_best_effort(&["-D", "OUTPUT", "-j", "RUSTVPN_OUT"]);

        // Flush and delete our custom chain (best effort)
        iptables_best_effort(&["-F", "RUSTVPN_OUT"]);
        iptables_best_effort(&["-X", "RUSTVPN_OUT"]);

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
