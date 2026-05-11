//! Update — Unit tests for version comparison and update checking.
//!
//! # Test Coverage
//! Tests version comparison and update checking logic including:
//! - Version string storage and retrieval
//! - Semantic versioning comparison (major, minor, patch)
//! - Newer version detection
//!
//! # Regression Prevention
//! These tests prevent regressions in:
//! - Version parsing and comparison algorithm
//! - SemVer ordering rules
//! - Update notification logic

use rust_vpn::update::UpdateChecker;
use rust_vpn::update::GITHUB_RELEASES_API_URL;

#[test]
fn test_new_stores_version() {
    let checker = UpdateChecker::new("1.2.3".to_string());
    assert_eq!(checker.current_version(), "1.2.3");
}

#[test]
fn test_current_version_returns_exact_string() {
    let checker = UpdateChecker::new("0.0.1-alpha".to_string());
    assert_eq!(checker.current_version(), "0.0.1-alpha");
}

#[test]
fn test_same_version_is_not_newer() {
    assert!(!UpdateChecker::is_newer_version("0.1.0", "0.1.0"));
}

#[test]
fn test_same_major_minor_patch_is_not_newer() {
    assert!(!UpdateChecker::is_newer_version("1.2.3", "1.2.3"));
}

#[test]
fn test_zero_version_same_is_not_newer() {
    assert!(!UpdateChecker::is_newer_version("0.0.0", "0.0.0"));
}

#[test]
fn test_newer_patch_is_newer() {
    assert!(UpdateChecker::is_newer_version("0.1.0", "0.1.1"));
}

#[test]
fn test_newer_minor_is_newer() {
    assert!(UpdateChecker::is_newer_version("0.1.0", "0.2.0"));
}

#[test]
fn test_newer_major_is_newer() {
    assert!(UpdateChecker::is_newer_version("0.9.9", "1.0.0"));
}

#[test]
fn test_minor_bump_with_zero_patch_is_newer() {
    assert!(UpdateChecker::is_newer_version("1.0.0", "1.1.0"));
}

#[test]
fn test_older_minor_is_not_newer() {
    assert!(!UpdateChecker::is_newer_version("0.2.0", "0.1.0"));
}

#[test]
fn test_older_patch_is_not_newer() {
    assert!(!UpdateChecker::is_newer_version("0.1.5", "0.1.3"));
}

#[test]
fn test_older_major_is_not_newer() {
    assert!(!UpdateChecker::is_newer_version("2.0.0", "1.9.9"));
}

#[test]
fn test_longer_version_is_newer_when_prefix_equal() {
    assert!(UpdateChecker::is_newer_version("1.0.0", "1.0.0.1"));
}

#[test]
fn test_shorter_version_is_not_newer_when_prefix_equal() {
    assert!(!UpdateChecker::is_newer_version("1.0.0.1", "1.0.0"));
}

#[test]
fn test_large_version_numbers() {
    assert!(UpdateChecker::is_newer_version("99.0.0", "100.0.0"));
    assert!(!UpdateChecker::is_newer_version("100.0.0", "99.0.0"));
}

#[test]
fn test_version_with_leading_zeros_parsed_numerically() {
    assert!(UpdateChecker::is_newer_version("1.09.0", "1.010.0"));
}

#[test]
fn test_api_url_contains_api_github() {
    assert!(GITHUB_RELEASES_API_URL.contains("api.github.com"));
}

#[test]
fn test_api_url_contains_releases_latest() {
    assert!(GITHUB_RELEASES_API_URL.contains("releases/latest"));
}
