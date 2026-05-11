//! Windows — WinTun driver-based TUN adapter and routing via netsh.
//!
//! # Role in RustVPN
//! This module handles Windows-specific networking operations including WinTun
//! adapter creation, IP configuration, and routing table management via netsh.
//! It uses the WinTun kernel driver (signed by WireGuard authors) for Layer-3
//! virtual adapter functionality.
//!
//! # Main Contracts
//! - Input: TUN IP configuration, VPN server endpoint
//! - Output: WinTun session handle, routing table changes
//! - Safety: Requires Administrator privileges; cleanup on Drop removes routes
//!
//! # Platform Notes
//! Windows-specific using WinTun driver with ring-buffer API (no file descriptors).
//! Uses netsh for routing configuration and adapter management.
//! Requires Administrator privileges for adapter creation and routing.
//! Bundles wintun.dll dynamically from executable directory or PATH.
//!
//! # Non-goals
//! This module does not implement firewall rules (delegated to killswitch).
//! It does not handle packet I/O directly (uses WinTun session API).
//! It does not implement cryptographic operations (delegated to tunnel module).

#![cfg(target_os = "windows")]

use anyhow::{anyhow, Context, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::Arc;

/// MTU we configure on the TUN adapter. 1420 leaves room for the
/// 32-byte WireGuard header inside a 1500-byte path MTU, matching the
/// Linux implementation.
const WIREGUARD_MTU: u32 = 1420;

/// Adapter pool name passed to WinTun. Not user-visible; appears only
/// in driver internals and `Get-NetAdapter` output. We use a stable
/// string so reconnects can find and reclaim previous adapters.
const ADAPTER_POOL: &str = "RustVPN";

/// Adapter display name. Visible in the Windows Network and Sharing
/// Center. Matches the executable name so users can identify it.
const ADAPTER_NAME: &str = "RustVPN";

/// Owns the WinTun adapter, the active session, and the routing-table
/// changes that need to be reverted on disconnect.
///
/// Dropping this struct does **not** automatically clean up routes:
/// the explicit [`cleanup`] method is called by the controller before
/// drop so any errors can be surfaced to the user. `Drop` falls back to
/// best-effort cleanup as a safety net for panic paths.
pub struct WindowsPlatform {
    /// The WinTun adapter handle. Wrapped in `Arc` because the session
    /// borrows from it and we need both alive for the lifetime of the
    /// connection.
    adapter: Option<Arc<wintun::Adapter>>,

    /// Active send/receive session. `None` until `create_tun` succeeds.
    /// The session must be dropped *before* the adapter -- otherwise
    /// WinTun will refuse to delete the adapter because it still has
    /// open sessions.
    session: Option<Arc<wintun::Session>>,

    /// Original IPv4 default-gateway address parsed from `route print`,
    /// stored so the server bypass route can be re-added on reconnect
    /// and removed on disconnect.
    original_gateway: Option<Ipv4Addr>,

    /// VPN server IP, saved so [`cleanup`] can delete the bypass route
    /// without re-parsing the routing table.
    vpn_server_ip: Option<IpAddr>,
}

impl WindowsPlatform {
    /// Loads `wintun.dll` and prepares an empty platform handle.
    ///
    /// This does not yet create an adapter -- that happens in
    /// [`create_tun`] when the user clicks Connect. Loading the DLL up
    /// front gives us an early error if the file is missing, rather
    /// than failing on the first connect attempt.
    ///
    /// # Errors
    ///
    /// Fails if `wintun.dll` cannot be located. Bundle the DLL alongside
    /// the executable or install the WinTun MSI from <https://www.wintun.net/>.
    pub fn new() -> Result<Self> {
        // Loading `wintun.dll` proves the driver is reachable. The
        // returned handle is dropped immediately because the
        // `wintun::Adapter::create` call we make later loads it again
        // internally; we just want the diagnostic up front.
        unsafe { wintun::load() }
            .map_err(|e| anyhow!("Failed to load wintun.dll: {}. Bundle wintun.dll alongside the executable.", e))?;

        tracing::info!("WinTun driver loaded");
        Ok(Self {
            adapter: None,
            session: None,
            original_gateway: None,
            vpn_server_ip: None,
        })
    }

    /// Creates and configures the WinTun adapter, then adds the routes
    /// that send traffic through the tunnel.
    ///
    /// ## Steps
    ///
    /// 1. Save the current default gateway so we can build a bypass
    ///    route to the VPN server.
    /// 2. Create (or reopen) the WinTun adapter named [`ADAPTER_NAME`]
    ///    in pool [`ADAPTER_POOL`].
    /// 3. Set the adapter's IPv4 address using `netsh`.
    /// 4. Set the adapter MTU to 1420.
    /// 5. Add a host route to the VPN server via the original gateway.
    /// 6. Add two half-default routes through the new adapter.
    /// 7. Start a session and return a clone for the packet loop.
    ///
    /// Returns an `Arc<wintun::Session>` instead of a raw fd because
    /// WinTun's I/O API is method-based, not fd-based. The packet loop
    /// holds onto this handle and uses `session.send_packet()` /
    /// `session.receive_blocking()`.
    ///
    /// # Arguments
    ///
    /// - `tun_ip`: client tunnel address as `(a, b, c, d)`.
    /// - `_tun_netmask`: subnet mask as `(a, b, c, d)`. Currently the
    ///   netmask is encoded into the prefix length passed to `netsh`,
    ///   so this argument is accepted for API symmetry with Linux but
    ///   is converted internally rather than passed through.
    /// - `vpn_server_ip`: the VPN server's IP, used to add the bypass
    ///   route via the original gateway.
    pub fn create_tun(
        &mut self,
        tun_ip: (u8, u8, u8, u8),
        tun_netmask: (u8, u8, u8, u8),
        vpn_server_ip: IpAddr,
    ) -> Result<Arc<wintun::Session>> {
        let addr = Ipv4Addr::new(tun_ip.0, tun_ip.1, tun_ip.2, tun_ip.3);
        let mask = Ipv4Addr::new(tun_netmask.0, tun_netmask.1, tun_netmask.2, tun_netmask.3);
        let prefix_len = netmask_to_prefix_len(mask);

        tracing::info!("Creating WinTun adapter ({}/{})", addr, prefix_len);

        // 1. Capture the existing default gateway. If this fails we
        //    continue without a bypass route -- the connection will
        //    still come up but tunnel reconnection traffic will try to
        //    flow through the tunnel itself, which will fail. We log
        //    loudly so the user can investigate.
        self.original_gateway = read_default_gateway();
        if let Some(gw) = self.original_gateway {
            tracing::info!("Saved original default gateway: {}", gw);
        } else {
            tracing::warn!("Could not determine original default gateway");
        }
        self.vpn_server_ip = Some(vpn_server_ip);

        // 2. Create the WinTun adapter. The third argument is an
        //    optional GUID; passing `None` lets WinTun pick a stable
        //    GUID derived from the pool/name pair, so reconnects reuse
        //    the same adapter rather than spawning duplicates.
        let wintun = unsafe { wintun::load() }
            .context("wintun.dll not loadable at create time")?;
        let adapter = match wintun::Adapter::open(&wintun, ADAPTER_NAME) {
            Ok(existing) => {
                tracing::info!("Reusing existing WinTun adapter");
                existing
            }
            Err(_) => wintun::Adapter::create(&wintun, ADAPTER_POOL, ADAPTER_NAME, None)
                .context("Failed to create WinTun adapter (Administrator required?)")?,
        };
        let adapter = Arc::new(adapter);
        self.adapter = Some(Arc::clone(&adapter));

        // 3. Configure the IP address using netsh. We use the GUID-
        //    based interface alias because `netsh` accepts either the
        //    friendly name or the LUID; the friendly name is what we
        //    set with `ADAPTER_NAME` and is guaranteed to be unique.
        run_netsh(&[
            "interface", "ip", "set", "address",
            &format!("name={}", ADAPTER_NAME),
            "static",
            &addr.to_string(),
            &mask.to_string(),
        ])
        .context("Failed to assign IP to WinTun adapter")?;

        // 4. Set the MTU to leave headroom for the WireGuard header.
        run_netsh(&[
            "interface", "ipv4", "set", "subinterface",
            ADAPTER_NAME,
            &format!("mtu={}", WIREGUARD_MTU),
            "store=active",
        ])
        .context("Failed to set MTU on WinTun adapter")?;

        // 5. Add the server bypass route. Skip silently if we never
        //    learned the original gateway; the user will get UDP
        //    timeouts which is recoverable, vs. a panic which is not.
        if let Some(gw) = self.original_gateway {
            run_netsh(&[
                "interface", "ipv4", "add", "route",
                &format!("{}/32", vpn_server_ip),
                ADAPTER_NAME, // ignored when nexthop is given but required syntactically
                &gw.to_string(),
                "store=active",
            ])
            .context("Failed to add bypass route to VPN server")?;
        }

        // 6. Half-default routes through the tunnel.
        for prefix in &["0.0.0.0/1", "128.0.0.0/1"] {
            run_netsh(&[
                "interface", "ipv4", "add", "route",
                prefix,
                ADAPTER_NAME,
                "store=active",
            ])
            .with_context(|| format!("Failed to add tunnel route {}", prefix))?;
        }

        // 7. Start the WinTun session. Capacity is the ring buffer
        //    size in bytes; the WinTun authors recommend 0x40_0000
        //    (4 MiB), which holds ~2700 1500-byte packets.
        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .context("Failed to start WinTun session")?;
        let session = Arc::new(session);
        self.session = Some(Arc::clone(&session));

        tracing::info!("WinTun adapter '{}' is up", ADAPTER_NAME);
        Ok(session)
    }

    /// Returns a clone of the active session, if any. Used by the
    /// Windows packet loop to share the session with its read/write
    /// halves.
    pub fn get_session(&self) -> Option<Arc<wintun::Session>> {
        self.session.as_ref().map(Arc::clone)
    }

    /// Reverts everything `create_tun` did, in the opposite order:
    /// drops the session, removes the routes, deletes the adapter.
    ///
    /// Errors are logged at `warn` level rather than propagated -- by
    /// the time this runs the connection is already torn down, and
    /// failing to delete a route that no longer exists is not a state
    /// the user can act on.
    pub fn cleanup(&mut self) -> Result<()> {
        tracing::info!("Cleaning up Windows TUN adapter and routing");

        // Drop the session before the adapter; WinTun refuses to delete
        // an adapter while sessions are still open.
        self.session = None;

        // Half-default routes.
        for prefix in &["0.0.0.0/1", "128.0.0.0/1"] {
            let _ = run_netsh(&[
                "interface", "ipv4", "delete", "route",
                prefix,
                ADAPTER_NAME,
            ]);
        }

        // Server bypass route.
        if let (Some(gw), Some(server)) = (self.original_gateway, self.vpn_server_ip) {
            let _ = run_netsh(&[
                "interface", "ipv4", "delete", "route",
                &format!("{}/32", server),
                ADAPTER_NAME,
                &gw.to_string(),
            ]);
        }

        // Drop the adapter handle. WinTun deletes the underlying
        // adapter when the last reference goes away.
        self.adapter = None;
        self.original_gateway = None;
        self.vpn_server_ip = None;

        Ok(())
    }
}

impl Drop for WindowsPlatform {
    fn drop(&mut self) {
        if self.session.is_some() || self.adapter.is_some() {
            tracing::warn!("WindowsPlatform dropped with active adapter -- cleaning up");
            let _ = self.cleanup();
        }
    }
}

/// Converts an IPv4 netmask to its prefix length (e.g., 255.255.255.0 -> 24).
/// This is the inverse of the standard prefix-to-netmask conversion.
pub fn netmask_to_prefix_len(netmask: Ipv4Addr) -> u8 {
    u32::from(netmask).leading_ones() as u8
}

/// Spawns `netsh.exe` with the given arguments, returning an error if
/// the process exits non-zero.
///
/// We capture both stdout and stderr so the error message includes the
/// full diagnostic netsh prints when a route is duplicated, the adapter
/// is missing, etc.
fn run_netsh(args: &[&str]) -> Result<()> {
    let output = Command::new("netsh.exe")
        .args(args)
        .output()
        .with_context(|| format!("Failed to spawn netsh.exe with args {:?}", args))?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "netsh {:?} exited with {}: stdout={} stderr={}",
            args,
            output.status,
            stdout.trim(),
            stderr.trim(),
        );
    }
    Ok(())
}

/// Parses `route print 0.0.0.0` to find the IPv4 default gateway.
///
/// Returns `None` if no default route is present (e.g. the user is
/// offline) or if the output is not in the expected format. Errors are
/// not surfaced -- the caller treats `None` as "skip the bypass route"
/// which is the safest fallback.
fn read_default_gateway() -> Option<Ipv4Addr> {
    let output = Command::new("route.exe").args(["print", "0.0.0.0"]).output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    // The "Active Routes" table looks like:
    //   Network Destination        Netmask          Gateway       Interface  Metric
    //             0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.42      25
    //
    // Match any line whose first column is exactly "0.0.0.0" and whose
    // third column parses as IPv4. We accept the first such line; if
    // multiple default routes exist we prefer the one Windows lists
    // first (typically the one with the lowest metric).
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "0.0.0.0" {
            if let Ok(gw) = parts[2].parse::<Ipv4Addr>() {
                return Some(gw);
            }
        }
    }
    None
}
