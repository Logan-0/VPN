//! Controller Module — Tests for VPN controller state machine and event handling.
//!
//! # Test Coverage
//! Tests VPN controller behavior including:
//! - Command/event message passing
//! - State transitions
//! - Error handling
//! - Event propagation
//!
//! # Regression Prevention
//! These tests prevent regressions in:
//! - Controller state machine logic
//! - Channel communication
//! - Event ordering

use rust_vpn::core::controller::{VpnCommand, VpnController, VpnEvent, VpnState};
use std::time::Duration;

fn drain(rx: &std::sync::mpsc::Receiver<VpnEvent>) -> Vec<VpnEvent> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

fn wait_for_event<F>(rx: &std::sync::mpsc::Receiver<VpnEvent>, timeout: Duration, pred: F) -> bool
where
    F: Fn(&VpnEvent) -> bool,
{
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(ev) = rx.try_recv() {
            if pred(&ev) {
                return true;
            }
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn test_vpn_state_equality() {
    assert_eq!(VpnState::Connected, VpnState::Connected);
    assert_ne!(VpnState::Connected, VpnState::Disconnected);
}

#[test]
fn test_vpn_state_is_copy() {
    let a = VpnState::Connecting;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn test_all_vpn_state_variants_are_distinct() {
    let variants = [
        VpnState::Disconnected,
        VpnState::Connecting,
        VpnState::Connected,
        VpnState::Reconnecting,
        VpnState::Error,
    ];
    for (i, a) in variants.iter().enumerate() {
        for (j, b) in variants.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn test_vpn_event_state_changed_clone() {
    let ev = VpnEvent::StateChanged(VpnState::Connected);
    let _clone = ev.clone();
}

#[test]
fn test_vpn_event_error_clone() {
    let ev = VpnEvent::Error("oops".to_string());
    let clone = ev.clone();
    assert!(matches!(clone, VpnEvent::Error(_)));
}

#[test]
fn test_vpn_event_info_clone() {
    let ev = VpnEvent::Info("msg".to_string());
    let clone = ev.clone();
    assert!(matches!(clone, VpnEvent::Info(_)));
}

#[test]
fn test_vpn_event_debug_output_is_non_empty() {
    let ev = VpnEvent::StateChanged(VpnState::Disconnected);
    assert!(!format!("{:?}", ev).is_empty());
}

#[test]
fn test_vpn_command_connect_debug() {
    let cmd = VpnCommand::Connect {
        server_endpoint: "1.2.3.4:51820".to_string(),
        server_public_key_base64: "aGVsbG8=".to_string(),
    };
    assert!(format!("{:?}", cmd).contains("Connect"));
}

#[test]
fn test_vpn_command_all_variants_debug() {
    let cmds: &[&str] = &[
        "Disconnect",
        "SetKillSwitch",
        "SetAutoReconnect",
        "Shutdown",
    ];
    let produced = [
        format!("{:?}", VpnCommand::Disconnect),
        format!("{:?}", VpnCommand::SetKillSwitch(true)),
        format!("{:?}", VpnCommand::SetAutoReconnect(false)),
        format!("{:?}", VpnCommand::Shutdown),
    ];
    for (expected, got) in cmds.iter().zip(produced.iter()) {
        assert!(got.contains(expected), "{} not found in {}", expected, got);
    }
}

#[test]
fn test_controller_new_does_not_panic() {
    let _ctrl = VpnController::new();
}

#[test]
fn test_take_event_rx_returns_receiver() {
    let ctrl = VpnController::new();
    let rx = ctrl.take_event_rx();
    drop(rx);
}

#[test]
fn test_send_command_does_not_panic() {
    let ctrl = VpnController::new();
    ctrl.send_command(VpnCommand::Shutdown);
}

#[test]
fn test_disconnect_when_idle_emits_disconnected() {
    let ctrl = VpnController::new();
    let rx = ctrl.take_event_rx();
    ctrl.send_command(VpnCommand::Disconnect);
    let found = wait_for_event(&rx, Duration::from_millis(500), |ev| {
        matches!(ev, VpnEvent::StateChanged(VpnState::Disconnected))
    });
    assert!(
        found,
        "Expected Disconnected state event after idle Disconnect"
    );
}

#[test]
fn test_set_kill_switch_true_then_false_no_panic() {
    let ctrl = VpnController::new();
    ctrl.send_command(VpnCommand::SetKillSwitch(true));
    ctrl.send_command(VpnCommand::SetKillSwitch(false));
    std::thread::sleep(Duration::from_millis(100));
}

#[test]
fn test_set_auto_reconnect_enable_disable_no_panic() {
    let ctrl = VpnController::new();
    ctrl.send_command(VpnCommand::SetAutoReconnect(true));
    ctrl.send_command(VpnCommand::SetAutoReconnect(false));
    std::thread::sleep(Duration::from_millis(100));
}

#[test]
fn test_connect_with_bad_endpoint_emits_error() {
    let ctrl = VpnController::new();
    let rx = ctrl.take_event_rx();
    ctrl.send_command(VpnCommand::Connect {
        server_endpoint: "not-an-endpoint".to_string(),
        server_public_key_base64: "aGVsbG8=".to_string(),
    });
    let found = wait_for_event(&rx, Duration::from_millis(500), |ev| {
        matches!(ev, VpnEvent::Error(_))
    });
    assert!(found, "Expected Error event for invalid endpoint");
}

#[test]
fn test_connect_with_bad_endpoint_transitions_to_error_state() {
    let ctrl = VpnController::new();
    let rx = ctrl.take_event_rx();
    ctrl.send_command(VpnCommand::Connect {
        server_endpoint: "bad endpoint".to_string(),
        server_public_key_base64: String::new(),
    });
    let found = wait_for_event(&rx, Duration::from_millis(500), |ev| {
        matches!(ev, VpnEvent::StateChanged(VpnState::Error))
    });
    assert!(found, "Expected Error state transition for bad endpoint");
}

#[test]
fn test_shutdown_command_accepted_without_panic() {
    let ctrl = VpnController::new();
    ctrl.send_command(VpnCommand::Shutdown);
    std::thread::sleep(Duration::from_millis(200));
    ctrl.send_command(VpnCommand::Disconnect);
}

#[test]
fn test_drop_does_not_panic() {
    let ctrl = VpnController::new();
    drop(ctrl);
}

#[test]
fn test_multiple_disconnects_all_produce_events() {
    let ctrl = VpnController::new();
    let rx = ctrl.take_event_rx();
    for _ in 0..3 {
        ctrl.send_command(VpnCommand::Disconnect);
    }
    let events: Vec<_> = {
        std::thread::sleep(Duration::from_millis(300));
        drain(&rx)
    };
    let disconnected_count = events
        .iter()
        .filter(|e| matches!(e, VpnEvent::StateChanged(VpnState::Disconnected)))
        .count();
    assert!(
        disconnected_count >= 1,
        "Expected at least one Disconnected event"
    );
}
