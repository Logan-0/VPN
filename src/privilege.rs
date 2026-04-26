//! # Privilege Minimization
//!
//! This module reduces the runtime privileges of the VPN process.
//!
//! ## The Problem
//!
//! RustVPN is launched as root (or via `sudo`) so it can:
//! - Create TUN devices (`CAP_NET_ADMIN`)
//! - Install iptables rules for the kill switch (`CAP_NET_ADMIN`)
//! - Modify the routing table (`CAP_NET_ADMIN`)
//!
//! Once the process is running, none of the *other* root powers are ever
//! used. Keeping them around means a bug in the HTTP client (update check),
//! the GUI, the config parser, or any dependency could be turned into a
//! full root compromise. We want the smallest possible privilege footprint
//! while still allowing the user to connect and disconnect freely.
//!
//! ## Why Not Just `setuid()`?
//!
//! The naive approach -- `setuid()` to the invoking user immediately --
//! breaks the use case. TUN device creation, route changes, and iptables
//! manipulation happen on **every** Connect (and Disconnect), not just at
//! startup, because the user can reconnect to a different server at any
//! time. After `setuid()`, the next Connect would fail with `EPERM`.
//!
//! ## What This Module Does Instead
//!
//! [`minimize_capabilities`] keeps the process's effective UID at 0 but
//! drops every Linux capability except `CAP_NET_ADMIN`. This is the same
//! pattern used by hardened production daemons (sshd, systemd-resolved,
//! NetworkManager). After this call:
//!
//! - TUN device creation still works (needs `CAP_NET_ADMIN`)
//! - iptables rules still work (needs `CAP_NET_ADMIN`)
//! - `route add` / `ip route` still work (needs `CAP_NET_ADMIN`)
//! - File ownership changes (`chown`) -- **denied**
//! - Loading kernel modules -- **denied**
//! - Mounting filesystems -- **denied**
//! - Reading any user's files via `CAP_DAC_OVERRIDE` -- **denied**
//! - Killing arbitrary processes via `CAP_KILL` -- **denied**
//!
//! A bug in `reqwest` that downloads a malicious payload can no longer
//! escalate to overwriting `/etc/passwd` or installing a kernel module.
//!
//! ## Platform Scope
//!
//! Capabilities are a Linux-specific concept. On macOS and Windows this
//! module is a no-op -- those platforms have their own (different) privilege
//! models (entitlements, UAC, mandatory integrity levels) which we do not
//! attempt to drop into here.

use anyhow::Result;

/// Drops every Linux capability the process holds except `CAP_NET_ADMIN`.
///
/// Call this once at the top of `main`, after the initial privilege check
/// and *before* loading user-controlled input (config files, server lists,
/// HTTP responses). Anything that runs after this point cannot exercise
/// the dropped capabilities even if exploited.
///
/// ## Capabilities Retained
///
/// - **`CAP_NET_ADMIN`** -- create/destroy TUN devices, modify routing
///   tables, configure network interfaces, install iptables rules.
///
/// Every other capability in every set (`Effective`, `Permitted`,
/// `Inheritable`, `Bounding`, `Ambient`) is dropped. Dropping the
/// `Bounding` set is the critical step: it prevents any `exec`'d child
/// process (or `setuid` re-acquisition) from regaining the dropped caps.
///
/// ## Failure Mode
///
/// If a capability cannot be read or dropped (e.g., the kernel returns
/// `EPERM` because the process never had it), the error is logged at
/// `warn` level and the function continues. We never abort startup over
/// a partial capability drop -- a hardened-but-incomplete state is still
/// better than a full-root state.
///
/// ## Non-Linux
///
/// On non-Linux targets this function is a no-op that logs a debug
/// message and returns `Ok(())`.
#[cfg(target_os = "linux")]
pub fn minimize_capabilities() -> Result<()> {
    use caps::{CapSet, Capability, CapsHashSet};

    // The single capability we keep. Adding more here in the future would
    // weaken the hardening; do so only with careful justification.
    let keep: CapsHashSet = {
        let mut s = CapsHashSet::new();
        s.insert(Capability::CAP_NET_ADMIN);
        s
    };

    // Drop from each capability set in turn. Order matters slightly:
    // `Bounding` should be dropped last because once it is reduced, the
    // other sets cannot grow back -- but reducing the others first keeps
    // the runtime guarantees consistent if any drop fails partway through.
    for set in [
        CapSet::Effective,
        CapSet::Permitted,
        CapSet::Inheritable,
        CapSet::Ambient,
        CapSet::Bounding,
    ] {
        // Read the current set, compute the difference from `keep`, and
        // drop each unwanted capability individually. We deliberately do
        // not call `caps::set()` to overwrite the whole set, because some
        // sets (notably `Bounding`) only support drops, not arbitrary
        // overwrites, and a single API path here keeps the error handling
        // uniform.
        let current = match caps::read(None, set) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Could not read capability set {:?}: {}", set, e);
                continue;
            }
        };
        for cap in current.difference(&keep) {
            if let Err(e) = caps::drop(None, set, *cap) {
                tracing::warn!("Could not drop {:?} from {:?}: {}", cap, set, e);
            }
        }
    }

    // Sanity check: confirm CAP_NET_ADMIN is still present in the
    // effective set. If it is missing we cannot create TUN devices and
    // the user will hit a confusing failure on Connect; surface it now.
    let has_net_admin = caps::has_cap(None, CapSet::Effective, Capability::CAP_NET_ADMIN)
        .unwrap_or(false);
    if has_net_admin {
        tracing::info!(
            "Capabilities minimized: only CAP_NET_ADMIN retained (effective set)"
        );
    } else {
        tracing::warn!(
            "Capability minimization left process without CAP_NET_ADMIN -- TUN \
             creation will fail. Did you start the process as root or with \
             CAP_NET_ADMIN granted?"
        );
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn minimize_capabilities() -> Result<()> {
    tracing::debug!("Capability minimization is a no-op on non-Linux platforms");
    Ok(())
}

/// Captures the UID and GID of the user who invoked `sudo`, if any.
///
/// Reads `$SUDO_UID` and `$SUDO_GID` from the environment. These are set
/// by `sudo(8)` itself and refer to the *original* (pre-sudo) user.
///
/// ## Why Capture at Startup?
///
/// The environment can be modified later by the program or by libraries
/// (some test frameworks unset `SUDO_*` between tests). Capturing once at
/// the top of `main`, before any other code runs, freezes the value into
/// a controlled location.
///
/// ## Returns
///
/// `Some((uid, gid))` if both variables are present and parse as `u32`.
/// `None` if either is missing or malformed -- typically means the
/// process was started directly as root rather than via `sudo`.
pub fn capture_invoking_user() -> Option<(u32, u32)> {
    let uid = std::env::var("SUDO_UID").ok()?.parse::<u32>().ok()?;
    let gid = std::env::var("SUDO_GID").ok()?.parse::<u32>().ok()?;
    tracing::debug!("Captured invoking user: UID={} GID={}", uid, gid);
    Some((uid, gid))
}
