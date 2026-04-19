//! # Linux Platform Module
//!
//! This module handles Linux-specific networking operations including
//! TUN device creation, routing configuration, and firewall management.
//!
//! ## Networking Concepts
//!
/// ### TUN Devices on Linux
///
/// Linux TUN devices are virtual network interfaces that operate at Layer 3 (Network layer).
/// They allow user-space programs to intercept IP packets.
///
/// Device naming convention: tun0, tun1, tun2, etc.
///
/// ### Linux Networking Commands
///
/// **ip command (iproute2):**
/// - Create TUN device: `ip tuntap add dev tun0 mode tun`
/// - Assign IP: `ip addr add 10.8.0.2/24 dev tun0`
/// - Bring up: `ip link set tun0 up`
/// - Add route: `ip route add 0.0.0.0/0 dev tun0`
///
/// **iptables (firewall):**
/// - Create chain: `iptables -N CHAIN_NAME`
/// - Add rule: `iptables -A CHAIN_NAME -j ACCEPT`
/// - Insert chain: `iptables -I OUTPUT 1 -j CHAIN_NAME`
///
/// ### Permissions
///
/// Creating TUN devices and modifying routing requires:
/// - Root privileges OR
/// - CAP_NET_ADMIN capability
///
/// This is because these operations affect system-wide networking.

use anyhow::{Context, Result};
use std::net::IpAddr;
use std::process::Command;
use tun::Device as TunDevice;

/// WireGuard standard MTU (accounts for WireGuard overhead on a 1500-byte link)
const WIREGUARD_MTU: u32 = 1420;

/// Linux Platform-Specific Networking Operations
///
/// Handles Linux-specific networking operations including TUN device
/// creation, routing configuration, and firewall management using iptables.
///
/// ## Networking Relevance
///
/// The Linux platform module:
/// - Creates TUN devices using tun crate or ioctl
/// - Configures IP addresses and routing tables
/// - Manages firewall rules using iptables
/// - Sets MTU (Maximum Transmission Unit) for VPN interface
/// - Handles Linux-specific network interface operations
///
/// ## Integration with VPN
///
/// When VPN connects:
/// 1. Create TUN device (tun0)
/// 2. Assign IP address (e.g., 10.8.0.2)
/// 3. Set MTU to 1420 (WireGuard standard)
/// 4. Bring interface up
/// 5. Add default route through TUN device
/// 6. Add explicit route to VPN server via original gateway
///
/// When VPN disconnects:
/// 1. Remove routes through TUN device
/// 2. Bring interface down
/// 3. Destroy TUN device
/// 4. Restore original routing
pub struct LinuxPlatform {
    /// Name of the TUN device created (e.g., "tun0")
    tun_device_name: Option<String>,

    /// The tun::platform::Device handle (owns the file descriptor)
    tun_device: Option<tun::platform::Device>,

    /// Original default gateway IP, saved so we can restore routing on cleanup
    original_gateway: Option<String>,

    /// VPN server IP, used to create a host route that bypasses the tunnel
    vpn_server_ip: Option<IpAddr>,
}

impl LinuxPlatform {
    /// Creates a new Linux platform handler.
    ///
    /// Verifies that required tools (`ip`) are available on the system.
    ///
    /// ## Permissions Required
    ///
    /// Creating TUN devices and modifying routing requires:
    /// - Root privileges (running with sudo), OR
    /// - CAP_NET_ADMIN capability
    ///
    /// # Returns
    ///
    /// * `Ok(LinuxPlatform)` - New Linux platform handler
    /// * `Err(_)` - If required tools are not available
    pub fn new() -> Result<Self> {
        // Verify iproute2 is available
        let output = Command::new("ip")
            .arg("-V")
            .output()
            .context("iproute2 (`ip` command) is required but not found")?;

        if !output.status.success() {
            anyhow::bail!("iproute2 (`ip` command) returned an error");
        }

        tracing::info!("Linux platform handler initialized");
        Ok(Self {
            tun_device_name: None,
            tun_device: None,
            original_gateway: None,
            vpn_server_ip: None,
        })
    }

    /// Creates a TUN device, assigns an IP address, and configures routing.
    ///
    /// This is the main setup method called when the VPN connects.
    ///
    /// ## What Happens
    ///
    /// 1. Save the current default gateway (so we can restore it later)
    /// 2. Create a TUN device via the `tun` crate
    /// 3. Set MTU to 1420 (WireGuard standard -- leaves room for the
    ///    32-byte WireGuard header inside a 1500-byte Ethernet frame)
    /// 4. Add a host route to the VPN server via the original gateway
    ///    (so VPN packets themselves don't get routed back into the tunnel)
    /// 5. Add a default route through the TUN device
    ///
    /// # Arguments
    ///
    /// * `tun_ip` - IP address to assign to the TUN interface (e.g., 10.8.0.2)
    /// * `tun_netmask` - Subnet mask (e.g., 255.255.255.0)
    /// * `vpn_server_ip` - IP of the VPN server (gets a bypass route)
    ///
    /// # Returns
    ///
    /// A mutable reference to the raw `tun::Device` for packet I/O
    pub fn create_tun(
        &mut self,
        tun_ip: (u8, u8, u8, u8),
        tun_netmask: (u8, u8, u8, u8),
        vpn_server_ip: IpAddr,
    ) -> Result<&mut tun::platform::Device> {
        tracing::info!(
            "Creating TUN device with IP {}.{}.{}.{}",
            tun_ip.0, tun_ip.1, tun_ip.2, tun_ip.3
        );

        // 1. Save original default gateway
        self.original_gateway = Self::get_default_gateway();
        if let Some(ref gw) = self.original_gateway {
            tracing::info!("Saved original default gateway: {}", gw);
        }

        self.vpn_server_ip = Some(vpn_server_ip);

        // 2. Create TUN device using the tun crate
        let mut config = tun::Configuration::default();
        config
            .address(tun_ip)
            .netmask(tun_netmask)
            .mtu(WIREGUARD_MTU as i32)
            .up();

        let device = tun::create(&config)
            .context("Failed to create TUN device (do you have root / CAP_NET_ADMIN?)")?;

        let dev_name = device.name()
            .context("Failed to get TUN device name")?
            .to_string();

        tracing::info!("TUN device created: {}", dev_name);
        self.tun_device_name = Some(dev_name.clone());
        self.tun_device = Some(device);

        // 3. Add host route for VPN server via original gateway
        if let Some(ref gw) = self.original_gateway {
            let _ = Command::new("ip")
                .args([
                    "route", "add",
                    &vpn_server_ip.to_string(),
                    "via", gw,
                ])
                .output();
            tracing::info!("Added host route to VPN server {} via {}", vpn_server_ip, gw);
        }

        // 4. Add default route through TUN device
        //    Two half-default routes avoid conflicting with the existing 0.0.0.0/0
        let _ = Command::new("ip")
            .args(["route", "add", "0.0.0.0/1", "dev", &dev_name])
            .output();
        let _ = Command::new("ip")
            .args(["route", "add", "128.0.0.0/1", "dev", &dev_name])
            .output();
        tracing::info!("Default routes added through {}", dev_name);

        Ok(self.tun_device.as_mut().unwrap())
    }

    /// Returns a mutable reference to the TUN device for packet I/O.
    ///
    /// The device implements `std::io::Read` and `std::io::Write`:
    /// - `read()` returns packets destined for the VPN (outgoing)
    /// - `write()` injects packets into the local network stack (incoming)
    pub fn get_tun_device(&mut self) -> Option<&mut tun::platform::Device> {
        self.tun_device.as_mut()
    }

    /// Returns the TUN device name (e.g., "tun0").
    pub fn tun_device_name(&self) -> Option<&str> {
        self.tun_device_name.as_deref()
    }

    /// Tears down the TUN device and restores original routing.
    ///
    /// Called when the VPN disconnects. Reverses everything done by `create_tun()`:
    /// 1. Removes the half-default routes through the TUN device
    /// 2. Removes the host route to the VPN server
    /// 3. Drops the TUN device (closing the fd destroys the interface)
    pub fn cleanup(&mut self) -> Result<()> {
        tracing::info!("Cleaning up Linux TUN device and routing");

        if let Some(ref dev_name) = self.tun_device_name {
            // Remove half-default routes
            let _ = Command::new("ip")
                .args(["route", "del", "0.0.0.0/1", "dev", dev_name])
                .output();
            let _ = Command::new("ip")
                .args(["route", "del", "128.0.0.0/1", "dev", dev_name])
                .output();
        }

        // Remove VPN server host route
        if let Some(ref server_ip) = self.vpn_server_ip {
            let _ = Command::new("ip")
                .args(["route", "del", &server_ip.to_string()])
                .output();
        }

        // Drop the TUN device (closing the fd removes the interface)
        self.tun_device = None;
        tracing::info!(
            "TUN device {} destroyed",
            self.tun_device_name.as_deref().unwrap_or("unknown")
        );

        self.tun_device_name = None;
        self.vpn_server_ip = None;
        self.original_gateway = None;

        Ok(())
    }

    /// Reads the current default gateway from the routing table.
    ///
    /// Parses `ip route show default` to extract the gateway address.
    /// Returns `None` if no default route is found.
    fn get_default_gateway() -> Option<String> {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Format: "default via 192.168.1.1 dev eth0 ..."
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[0] == "default" && parts[1] == "via" {
                return Some(parts[2].to_string());
            }
        }
        None
    }
}

impl Drop for LinuxPlatform {
    fn drop(&mut self) {
        if self.tun_device.is_some() {
            tracing::warn!("LinuxPlatform dropped with active TUN device -- cleaning up");
            let _ = self.cleanup();
        }
    }
}
