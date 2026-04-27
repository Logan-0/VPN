//! Reconnect Manager Tests
//!
//! Tests for the exponential backoff reconnect manager.

use rust_vpn::core::reconnect::ReconnectManager;
use std::time::Duration;

fn new_mgr() -> ReconnectManager {
    ReconnectManager::new().unwrap()
}

#[test]
fn test_new_starts_with_zero_failures() {
    assert_eq!(new_mgr().get_consecutive_failures(), 0);
}

#[test]
fn test_new_starts_with_one_second_backoff() {
    assert_eq!(new_mgr().get_current_backoff(), Duration::from_secs(1));
}

#[test]
fn test_new_should_attempt_reconnect_immediately() {
    assert!(new_mgr().should_attempt_reconnect());
}

#[test]
fn test_new_has_no_last_success() {
    assert!(new_mgr().time_since_last_success().is_none());
}

#[test]
fn test_record_failure_increments_count() {
    let mut mgr = new_mgr();
    mgr.record_failure();
    assert_eq!(mgr.get_consecutive_failures(), 1);
}

#[test]
fn test_three_failures_counted() {
    let mut mgr = new_mgr();
    mgr.record_failure();
    mgr.record_failure();
    mgr.record_failure();
    assert_eq!(mgr.get_consecutive_failures(), 3);
}

#[test]
fn test_one_failure_doubles_backoff() {
    let mut mgr = new_mgr();
    mgr.record_failure();
    assert_eq!(mgr.get_current_backoff(), Duration::from_secs(2));
}

#[test]
fn test_two_failures_quadruple_backoff() {
    let mut mgr = new_mgr();
    mgr.record_failure();
    mgr.record_failure();
    assert_eq!(mgr.get_current_backoff(), Duration::from_secs(4));
}

#[test]
fn test_backoff_caps_at_thirty_seconds() {
    let mut mgr = new_mgr();
    for _ in 0..20 {
        mgr.record_failure();
    }
    assert_eq!(mgr.get_current_backoff(), Duration::from_secs(30));
}

#[test]
fn test_backoff_never_exceeds_thirty_seconds() {
    let mut mgr = new_mgr();
    for _ in 0..100 {
        mgr.record_failure();
    }
    assert!(mgr.get_current_backoff() <= Duration::from_secs(30));
}

#[test]
fn test_success_resets_failure_count_to_zero() {
    let mut mgr = new_mgr();
    mgr.record_failure();
    mgr.record_failure();
    mgr.record_success();
    assert_eq!(mgr.get_consecutive_failures(), 0);
}

#[test]
fn test_success_resets_backoff_to_one_second() {
    let mut mgr = new_mgr();
    for _ in 0..5 {
        mgr.record_failure();
    }
    mgr.record_success();
    assert_eq!(mgr.get_current_backoff(), Duration::from_secs(1));
}

#[test]
fn test_success_records_timestamp() {
    let mut mgr = new_mgr();
    mgr.record_success();
    assert!(mgr.time_since_last_success().is_some());
}

#[test]
fn test_elapsed_since_success_is_small() {
    let mut mgr = new_mgr();
    mgr.record_success();
    let elapsed = mgr.time_since_last_success().unwrap();
    assert!(elapsed < Duration::from_secs(1));
}

#[test]
fn test_reset_clears_failure_count() {
    let mut mgr = new_mgr();
    mgr.record_failure();
    mgr.reset();
    assert_eq!(mgr.get_consecutive_failures(), 0);
}

#[test]
fn test_reset_restores_one_second_backoff() {
    let mut mgr = new_mgr();
    for _ in 0..5 {
        mgr.record_failure();
    }
    mgr.reset();
    assert_eq!(mgr.get_current_backoff(), Duration::from_secs(1));
}

#[test]
fn test_reset_clears_attempt_timestamp_so_reconnect_is_immediate() {
    let mut mgr = new_mgr();
    mgr.record_failure();
    mgr.reset();
    assert!(mgr.should_attempt_reconnect());
}

#[test]
fn test_default_is_equivalent_to_new() {
    let a = new_mgr();
    let b = ReconnectManager::default();
    assert_eq!(a.get_consecutive_failures(), b.get_consecutive_failures());
    assert_eq!(a.get_current_backoff(), b.get_current_backoff());
}
