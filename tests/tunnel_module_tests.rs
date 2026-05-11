//! Tunnel Module — Tests for WireGuard tunnel configuration and key management.
//!
//! # Test Coverage
//! Tests WireGuard tunnel functionality including:
//! - Key generation and validation
//! - Base64 encoding/decoding
//! - Tunnel configuration
//! - State management
//!
//! # Regression Prevention
//! These tests prevent regressions in:
//! - Cryptographic key handling
//! - Configuration validation
//! - State transitions

use rust_vpn::core::tunnel::{Tunnel, TunnelConfig, TunnelState};
use rust_vpn::core::tunnel::generate_keypair;
use rust_vpn::core::tunnel::base64_to_key;
use rust_vpn::core::tunnel::key_to_base64;
use zeroize::Zeroizing;

fn dummy_config() -> TunnelConfig {
    let (private_key, server_public_key) = generate_keypair();
    TunnelConfig {
        private_key: Zeroizing::new(private_key),
        server_public_key,
        server_endpoint: "127.0.0.1:51820".parse().unwrap(),
        allowed_ips: vec![("0.0.0.0".parse().unwrap(), 0)],
        dns_servers: vec![],
    }
}

#[test]
fn test_generate_keypair_private_key_is_32_bytes() {
    let (priv_key, _) = generate_keypair();
    assert_eq!(priv_key.len(), 32);
}

#[test]
fn test_generate_keypair_public_key_is_32_bytes() {
    let (_, pub_key) = generate_keypair();
    assert_eq!(pub_key.len(), 32);
}

#[test]
fn test_generate_keypair_produces_different_keys_each_call() {
    let (priv1, _) = generate_keypair();
    let (priv2, _) = generate_keypair();
    assert_ne!(priv1, priv2, "Two consecutive keypairs should not be identical");
}

#[test]
fn test_generate_keypair_private_and_public_differ() {
    let (priv_key, pub_key) = generate_keypair();
    assert_ne!(priv_key, pub_key, "Private key must not equal derived public key");
}

#[test]
fn test_base64_to_key_roundtrip_with_known_bytes() {
    let original = [42u8; 32];
    let b64 = key_to_base64(&original);
    let decoded = base64_to_key(&b64).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn test_base64_to_key_invalid_base64_returns_error() {
    assert!(
        base64_to_key("not!valid$base64").is_err(),
        "Invalid base64 should return Err"
    );
}

#[test]
fn test_base64_to_key_wrong_length_too_short_returns_error() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let short = STANDARD.encode([1u8; 16]);
    assert!(
        base64_to_key(&short).is_err(),
        "16-byte key should return Err (expected 32)"
    );
}

#[test]
fn test_base64_to_key_wrong_length_too_long_returns_error() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let long = STANDARD.encode([0u8; 64]);
    assert!(
        base64_to_key(&long).is_err(),
        "64-byte key should return Err (expected 32)"
    );
}

#[test]
fn test_base64_to_key_empty_string_returns_error() {
    assert!(base64_to_key("").is_err());
}

#[test]
fn test_key_to_base64_is_valid_base64() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let (priv_key, _) = generate_keypair();
    let b64 = key_to_base64(&priv_key);
    assert!(
        STANDARD.decode(&b64).is_ok(),
        "key_to_base64 must produce valid base64"
    );
}

#[test]
fn test_key_to_base64_roundtrip_for_generated_keys() {
    let (priv_key, pub_key) = generate_keypair();
    assert_eq!(base64_to_key(&key_to_base64(&priv_key)).unwrap(), priv_key);
    assert_eq!(base64_to_key(&key_to_base64(&pub_key)).unwrap(), pub_key);
}

#[test]
fn test_key_to_base64_all_zeros_is_stable() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let zeros = [0u8; 32];
    let b64 = key_to_base64(&zeros);
    let expected = STANDARD.encode(&zeros);
    assert_eq!(b64, expected);
}

#[test]
fn test_tunnel_new_succeeds() {
    assert!(Tunnel::new(dummy_config()).is_ok());
}

#[test]
fn test_tunnel_new_is_not_connected() {
    let tunnel = Tunnel::new(dummy_config()).unwrap();
    assert!(!tunnel.is_connected(), "New tunnel should not be connected");
}

#[tokio::test]
async fn test_tunnel_initial_state_is_disconnected() {
    let tunnel = Tunnel::new(dummy_config()).unwrap();
    assert_eq!(tunnel.get_state().await, TunnelState::Disconnected);
}

#[tokio::test]
async fn test_tunnel_set_state_changes_state() {
    let tunnel = Tunnel::new(dummy_config()).unwrap();
    tunnel.set_state(TunnelState::Connecting).await;
    assert_eq!(tunnel.get_state().await, TunnelState::Connecting);
}

#[tokio::test]
async fn test_tunnel_set_state_to_error() {
    let tunnel = Tunnel::new(dummy_config()).unwrap();
    tunnel.set_state(TunnelState::Error).await;
    assert_eq!(tunnel.get_state().await, TunnelState::Error);
}

#[test]
fn test_tunnel_state_equality() {
    assert_eq!(TunnelState::Connected, TunnelState::Connected);
    assert_ne!(TunnelState::Connected, TunnelState::Disconnected);
}

#[test]
fn test_tunnel_state_copy() {
    let a = TunnelState::Reconnecting;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn test_tunnel_config_clone() {
    let cfg = dummy_config();
    let _clone = cfg.clone();
}

#[test]
fn test_tunnel_config_allowed_ips_stored() {
    let cfg = dummy_config();
    assert!(!cfg.allowed_ips.is_empty());
}
