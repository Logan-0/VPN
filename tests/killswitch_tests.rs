//! Kill Switch — Unit tests for the parts of `KillSwitch` that don't touch
//! real firewall state.
//!
//! # Test Coverage
//! `KillSwitch::enable`/`disable` shell out to real `iptables`/`ip6tables`
//! (Linux) and require root — they cannot be exercised hermetically without
//! either running this suite as root against a real (or namespaced) network
//! stack, or refactoring `KillSwitch` to take an injectable command-runner
//! (tracked as the top testing priority in
//! `docs/TestingStrategyExecutionSpec.md` — the `mockall` dev-dependency is
//! reserved for that future refactor and is intentionally unused today).
//!
//! What *is* safely testable without root is covered here: construction
//! state and the state-query accessors.
//!
//! # Regression Prevention
//! These tests prevent a regression where `KillSwitch::new()` starts in any
//! state other than `Disabled` — since the fail-closed connect-flow fix in
//! `core::controller` (`VpnCommand::Connect`) checks `kill_switch_enabled`
//! before calling `enable()`, a wrong default here would either force an
//! unwanted firewall lockdown on first run, or (worse) cause the connect
//! flow's kill-switch gating to be skipped when it shouldn't be.

use rust_vpn::core::killswitch::{KillSwitch, KillSwitchState};

/// A freshly constructed kill switch must start disabled — no firewall
/// rules have been installed yet, so `is_enabled()`/`get_state()` must
/// agree that nothing is blocking traffic.
///
/// Prevents regression where a wrong default state either falsely claims
/// protection that doesn't exist yet, or skips the enable step a caller
/// gates on.
#[test]
fn new_kill_switch_starts_disabled() {
    let kill_switch =
        KillSwitch::new().expect("KillSwitch::new() does not perform I/O and cannot fail");

    assert_eq!(kill_switch.get_state(), KillSwitchState::Disabled);
    assert!(!kill_switch.is_enabled());
}

/// `KillSwitchState` equality must be structural (derive-based), not
/// pointer/identity based, since call sites compare it directly
/// (`self.state == KillSwitchState::Enabled`) rather than via a method.
///
/// Prevents regression where a future refactor of `KillSwitchState` (e.g.
/// adding fields to the variants) accidentally breaks the simple equality
/// checks the enable/disable idempotency short-circuits rely on.
#[test]
fn kill_switch_state_equality_is_structural() {
    assert_eq!(KillSwitchState::Disabled, KillSwitchState::Disabled);
    assert_eq!(KillSwitchState::Enabled, KillSwitchState::Enabled);
    assert_ne!(KillSwitchState::Disabled, KillSwitchState::Enabled);
}
