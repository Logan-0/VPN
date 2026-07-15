//! Configuration — Unit tests for VPN configuration management.
//!
//! # Test Coverage
//! Tests VPN configuration load/save/default behavior including:
//! - Default values for all configuration fields
//! - TOML serialization round-trip
//! - Custom DNS server (Pi-hole) field handling
//! - Missing field handling with defaults
//!
//! # Regression Prevention
//! These tests prevent regressions in:
//! - Configuration serialization/deserialization
//! - Default value initialization
//! - Field addition/removal compatibility

use rust_vpn::config::VpnConfig;

#[test]
fn test_default_config_values() {
    let config = VpnConfig::default();
    assert!(!config.auto_connect_on_application_startup);
    assert!(config.kill_switch_protection_enabled);
    assert!(config.auto_reconnect_enabled);
    assert!(config.dns_filtering_protection_enabled);
    assert!(config.selected_vpn_server_identifier.is_none());
    assert!(config.custom_dns_server_address.is_none());
}

#[test]
fn test_config_toml_round_trip() {
    let config = VpnConfig {
        auto_connect_on_application_startup: true,
        kill_switch_protection_enabled: false,
        selected_vpn_server_identifier: Some("us-california-1".to_string()),
        custom_dns_server_address: Some("192.168.1.53".to_string()),
        ..Default::default()
    };

    // Serialize to TOML
    let toml_str = toml::to_string_pretty(&config).unwrap();

    // Deserialize back
    let restored: VpnConfig = toml::from_str(&toml_str).unwrap();

    assert!(restored.auto_connect_on_application_startup);
    assert!(!restored.kill_switch_protection_enabled);
    assert!(restored.auto_reconnect_enabled);
    assert!(restored.dns_filtering_protection_enabled);
    assert_eq!(
        restored.selected_vpn_server_identifier.as_deref(),
        Some("us-california-1")
    );
    assert_eq!(
        restored.custom_dns_server_address.as_deref(),
        Some("192.168.1.53")
    );
}

#[test]
fn test_config_deserialize_with_missing_fields_uses_defaults() {
    // Simulate a minimal config file that only has one field
    let toml_str = r#"
auto_connect_on_application_startup = true
"#;

    let config: VpnConfig = toml::from_str(toml_str).unwrap();
    assert!(config.auto_connect_on_application_startup);
    // All other fields should have their defaults
    assert!(config.kill_switch_protection_enabled);
    assert!(config.auto_reconnect_enabled);
    assert!(config.dns_filtering_protection_enabled);
    assert!(config.selected_vpn_server_identifier.is_none());
    assert!(config.custom_dns_server_address.is_none());
}

#[test]
fn test_config_deserialize_empty_string() {
    let config: VpnConfig = toml::from_str("").unwrap();
    // Should be equivalent to default
    assert!(!config.auto_connect_on_application_startup);
    assert!(config.kill_switch_protection_enabled);
}
