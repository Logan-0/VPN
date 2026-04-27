//! VPN Configuration Tests
//!
//! Tests for VPN configuration management and private key handling.

use rust_vpn::config::VpnConfig;
use base64::{engine::general_purpose::STANDARD, Engine as _};

fn config_with_b64_key(b64: &str) -> VpnConfig {
    VpnConfig {
        client_private_key_base64: Some(b64.to_string()),
        ..VpnConfig::default()
    }
}

fn b64_of(bytes: &[u8; 32]) -> String {
    STANDARD.encode(bytes)
}

#[test]
fn test_default_has_no_private_key() {
    assert!(VpnConfig::default().client_private_key_base64.is_none());
}

#[test]
fn test_default_auto_connect_off() {
    assert!(!VpnConfig::default().auto_connect_on_application_startup);
}

#[test]
fn test_default_kill_switch_on() {
    assert!(VpnConfig::default().kill_switch_protection_enabled);
}

#[test]
fn test_default_auto_reconnect_on() {
    assert!(VpnConfig::default().auto_reconnect_enabled);
}

#[test]
fn test_decode_valid_32_byte_key() {
    let bytes = [42u8; 32];
    let mut cfg = config_with_b64_key(&b64_of(&bytes));
    let key = cfg.get_or_create_private_key().unwrap();
    assert_eq!(*key, bytes);
}

#[test]
fn test_decode_preserves_all_byte_values() {
    let bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
    let mut cfg = config_with_b64_key(&b64_of(&bytes));
    let key = cfg.get_or_create_private_key().unwrap();
    assert_eq!(*key, bytes);
}

#[test]
fn test_decode_does_not_alter_stored_field() {
    let bytes = [99u8; 32];
    let b64 = b64_of(&bytes);
    let mut cfg = config_with_b64_key(&b64);
    cfg.get_or_create_private_key().unwrap();
    assert_eq!(cfg.client_private_key_base64.as_deref(), Some(b64.as_str()));
}

#[test]
fn test_decode_returns_zeroizing_wrapper_of_correct_length() {
    let mut cfg = config_with_b64_key(&b64_of(&[7u8; 32]));
    let key: zeroize::Zeroizing<[u8; 32]> = cfg.get_or_create_private_key().unwrap();
    assert_eq!(key.len(), 32);
}

#[test]
fn test_invalid_base64_returns_error() {
    let mut cfg = config_with_b64_key("not-valid-base64!!!");
    assert!(cfg.get_or_create_private_key().is_err());
}

#[test]
fn test_key_too_short_returns_error() {
    let short = STANDARD.encode([1u8; 16]);
    let mut cfg = config_with_b64_key(&short);
    assert!(cfg.get_or_create_private_key().is_err());
}

#[test]
fn test_key_too_long_returns_error() {
    let long = STANDARD.encode([0u8; 64]);
    let mut cfg = config_with_b64_key(&long);
    assert!(cfg.get_or_create_private_key().is_err());
}

#[test]
fn test_empty_base64_returns_error() {
    let mut cfg = config_with_b64_key("");
    assert!(cfg.get_or_create_private_key().is_err());
}

#[test]
fn test_round_trip_preserves_key() {
    let bytes = [55u8; 32];
    let b64 = b64_of(&bytes);
    let cfg = config_with_b64_key(&b64);
    let toml = toml::to_string_pretty(&cfg).unwrap();
    let loaded: VpnConfig = toml::from_str(&toml).unwrap();
    assert_eq!(loaded.client_private_key_base64.as_deref(), Some(b64.as_str()));
}

#[test]
fn test_old_config_without_key_field_deserialises_as_none() {
    let toml = r#"
        auto_connect_on_application_startup = false
        kill_switch_protection_enabled = true
        auto_reconnect_enabled = true
        dns_filtering_protection_enabled = true
    "#;
    let cfg: VpnConfig = toml::from_str(toml).unwrap();
    assert!(cfg.client_private_key_base64.is_none());
}

#[test]
fn test_config_with_key_field_null_deserialises_as_none() {
    let toml = "client_private_key_base64 = \"\"\n";
    let cfg: VpnConfig = toml::from_str(toml).unwrap_or_default();
    if let Some(v) = &cfg.client_private_key_base64 {
        assert_eq!(v.as_str(), "");
    }
}

#[test]
fn test_serialised_toml_contains_key_field_name() {
    let cfg = config_with_b64_key(&b64_of(&[1u8; 32]));
    let toml = toml::to_string_pretty(&cfg).unwrap();
    assert!(toml.contains("client_private_key_base64"));
}
