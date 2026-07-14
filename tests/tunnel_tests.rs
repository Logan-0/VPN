//! Tunnel — Unit tests for WireGuard tunnel module.
//!
//! # Test Coverage
//! Tests WireGuard tunnel functionality including:
//! - Key generation (X25519 key pairs)
//! - Base64 encoding/decoding round-trip
//! - Tunnel creation and initial state
//! - State transitions
//!
//! Note: Actual encryption/decryption tests require a running WireGuard
//! peer and are covered in the E2E integration tests.
//!
//! # Regression Prevention
//! These tests prevent regressions in:
//! - Cryptographic key generation
//! - Key encoding/decoding
//! - Tunnel state management

use rust_vpn::core::tunnel::{
    base64_to_key, generate_keypair, key_to_base64, Tunnel, TunnelConfig, TunnelState,
};
use std::net::{IpAddr, SocketAddr};
use zeroize::Zeroizing;

fn make_test_config() -> TunnelConfig {
    let (private_key, _public_key) = generate_keypair();
    let (_, server_public_key) = generate_keypair();

    TunnelConfig {
        private_key: Zeroizing::new(private_key),
        server_public_key,
        server_endpoint: "127.0.0.1:51820".parse::<SocketAddr>().unwrap(),
        allowed_ips: vec![("0.0.0.0".parse::<IpAddr>().unwrap(), 0)],
        dns_servers: vec!["1.1.1.1".parse::<IpAddr>().unwrap()],
    }
}

// ---------------------------------------------------------------------------
// Key generation and encoding
// ---------------------------------------------------------------------------

#[test]
fn test_generate_keypair_produces_32_byte_keys() {
    let (private_key, public_key) = generate_keypair();
    assert_eq!(private_key.len(), 32);
    assert_eq!(public_key.len(), 32);
}

#[test]
fn test_generate_keypair_produces_different_keys() {
    let (priv1, pub1) = generate_keypair();
    let (priv2, pub2) = generate_keypair();
    assert_ne!(
        priv1, priv2,
        "Two keypairs should have different private keys"
    );
    assert_ne!(pub1, pub2, "Two keypairs should have different public keys");
}

#[test]
fn test_private_key_differs_from_public_key() {
    let (private_key, public_key) = generate_keypair();
    assert_ne!(private_key, public_key);
}

#[test]
fn test_base64_round_trip() {
    let (_, public_key) = generate_keypair();
    let encoded = key_to_base64(&public_key);
    let decoded = base64_to_key(&encoded).unwrap();
    assert_eq!(decoded, public_key);
}

#[test]
fn test_base64_to_key_invalid_base64() {
    let result = base64_to_key("not-valid-base64!!!");
    assert!(result.is_err());
}

#[test]
fn test_base64_to_key_wrong_length() {
    // Valid base64 but only 16 bytes -- should fail because keys must be 32 bytes
    use base64::{engine::general_purpose, Engine as _};
    let short = general_purpose::STANDARD.encode([0u8; 16]);
    let result = base64_to_key(&short);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Tunnel creation and state
// ---------------------------------------------------------------------------

#[test]
fn test_tunnel_created_in_disconnected_state() {
    let config = make_test_config();
    let tunnel = Tunnel::new(config).unwrap();
    assert!(!tunnel.is_connected());
}

#[tokio::test]
async fn test_tunnel_state_is_disconnected_initially() {
    let config = make_test_config();
    let tunnel = Tunnel::new(config).unwrap();
    assert_eq!(tunnel.get_state().await, TunnelState::Disconnected);
}

#[tokio::test]
async fn test_tunnel_connect_changes_state() {
    let config = make_test_config();
    let mut tunnel = Tunnel::new(config).unwrap();

    tunnel.connect().await.unwrap();
    assert_eq!(tunnel.get_state().await, TunnelState::Connected);
    assert!(tunnel.is_connected());
}

#[tokio::test]
async fn test_tunnel_disconnect_changes_state() {
    let config = make_test_config();
    let mut tunnel = Tunnel::new(config).unwrap();

    tunnel.connect().await.unwrap();
    tunnel.disconnect().await.unwrap();
    assert_eq!(tunnel.get_state().await, TunnelState::Disconnected);
    assert!(!tunnel.is_connected());
}

#[tokio::test]
async fn test_tunnel_set_state() {
    let config = make_test_config();
    let tunnel = Tunnel::new(config).unwrap();

    tunnel.set_state(TunnelState::Reconnecting).await;
    assert_eq!(tunnel.get_state().await, TunnelState::Reconnecting);
}

#[test]
fn test_tunnel_config_accessible() {
    let config = make_test_config();
    let endpoint = config.server_endpoint;
    let tunnel = Tunnel::new(config).unwrap();
    assert_eq!(tunnel.get_config().server_endpoint, endpoint);
}
