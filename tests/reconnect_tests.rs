//! # Reconnect Manager Unit Tests
//!
//! Tests for the exponential backoff reconnection logic including:
//! - Initial state
//! - Backoff progression
//! - Maximum backoff cap
//! - Success resets
//! - Failure counting

use rust_vpn::core::reconnect::ReconnectManager;
use std::time::Duration;

#[test]
fn test_initial_state() {
    let manager = ReconnectManager::new().unwrap();
    assert_eq!(manager.get_consecutive_failures(), 0);
    assert_eq!(manager.get_current_backoff(), Duration::from_secs(1));
    assert!(manager.should_attempt_reconnect());
}

#[test]
fn test_failure_increments_counter() {
    let mut manager = ReconnectManager::new().unwrap();
    manager.record_failure();
    assert_eq!(manager.get_consecutive_failures(), 1);

    manager.record_failure();
    assert_eq!(manager.get_consecutive_failures(), 2);
}

#[test]
fn test_exponential_backoff_progression() {
    let mut manager = ReconnectManager::new().unwrap();

    // Initial backoff is 1s
    assert_eq!(manager.get_current_backoff(), Duration::from_secs(1));

    // After 1st failure: 1s * 2 = 2s
    manager.record_failure();
    assert_eq!(manager.get_current_backoff(), Duration::from_secs(2));

    // After 2nd failure: 2s * 2 = 4s
    manager.record_failure();
    assert_eq!(manager.get_current_backoff(), Duration::from_secs(4));

    // After 3rd failure: 4s * 2 = 8s
    manager.record_failure();
    assert_eq!(manager.get_current_backoff(), Duration::from_secs(8));

    // After 4th failure: 8s * 2 = 16s
    manager.record_failure();
    assert_eq!(manager.get_current_backoff(), Duration::from_secs(16));
}

#[test]
fn test_backoff_capped_at_30_seconds() {
    let mut manager = ReconnectManager::new().unwrap();

    // Drive backoff past the cap
    for _ in 0..10 {
        manager.record_failure();
    }

    assert_eq!(
        manager.get_current_backoff(),
        Duration::from_secs(30),
        "Backoff should be capped at 30 seconds"
    );
}

#[test]
fn test_success_resets_backoff() {
    let mut manager = ReconnectManager::new().unwrap();

    // Accumulate some failures
    manager.record_failure();
    manager.record_failure();
    manager.record_failure();
    assert_eq!(manager.get_consecutive_failures(), 3);

    // Record success
    manager.record_success();
    assert_eq!(manager.get_consecutive_failures(), 0);
    assert_eq!(manager.get_current_backoff(), Duration::from_secs(1));
}

#[test]
fn test_reset_clears_state() {
    let mut manager = ReconnectManager::new().unwrap();

    manager.record_failure();
    manager.record_failure();
    manager.reset();

    assert_eq!(manager.get_consecutive_failures(), 0);
    assert_eq!(manager.get_current_backoff(), Duration::from_secs(1));
    assert!(manager.should_attempt_reconnect());
}

#[test]
fn test_time_since_last_success_initially_none() {
    let manager = ReconnectManager::new().unwrap();
    assert!(manager.time_since_last_success().is_none());
}

#[test]
fn test_time_since_last_success_after_success() {
    let mut manager = ReconnectManager::new().unwrap();
    manager.record_success();
    let elapsed = manager.time_since_last_success();
    assert!(elapsed.is_some());
    // Should be very recent (within 1 second)
    assert!(elapsed.unwrap() < Duration::from_secs(1));
}
