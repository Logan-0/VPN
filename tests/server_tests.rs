//! Server — Unit tests for VPN server management.
//!
//! # Test Coverage
//! Tests server loading, lookup, and selection including:
//! - Loading servers from resources/servers.toml
//! - Finding servers by ID
//! - Finding servers by country
//! - Display list generation
//! - Best server selection
//!
//! # Regression Prevention
//! These tests prevent regressions in:
//! - Server list parsing from TOML
//! - Server lookup algorithms
//! - Server metadata integrity

use rust_vpn::server::ServerManager;

#[test]
fn test_server_manager_loads_servers() {
    let manager = ServerManager::new().unwrap();
    assert!(
        manager.server_count() > 0,
        "Should load servers from resources/servers.toml"
    );
}

#[test]
fn test_server_count_matches_toml() {
    let manager = ServerManager::new().unwrap();
    // resources/servers.toml has 9 servers
    assert_eq!(manager.server_count(), 9);
}

#[test]
fn test_find_server_by_id() {
    let manager = ServerManager::new().unwrap();

    let server = manager.find_by_id("us-california-1");
    assert!(server.is_some());
    let server = server.unwrap();
    assert_eq!(server.server_display_name, "US-California-1");
    assert_eq!(server.server_country_code, "US");
}

#[test]
fn test_find_server_by_id_not_found() {
    let manager = ServerManager::new().unwrap();
    assert!(manager.find_by_id("nonexistent-server").is_none());
}

#[test]
fn test_find_servers_by_country_us() {
    let manager = ServerManager::new().unwrap();
    let us_servers = manager.find_by_country("US");
    assert_eq!(us_servers.len(), 4, "Should have 4 US servers");
}

#[test]
fn test_find_servers_by_country_sweden() {
    let manager = ServerManager::new().unwrap();
    let se_servers = manager.find_by_country("SE");
    assert_eq!(se_servers.len(), 3, "Should have 3 Sweden servers");
}

#[test]
fn test_find_servers_by_country_germany() {
    let manager = ServerManager::new().unwrap();
    let de_servers = manager.find_by_country("DE");
    assert_eq!(de_servers.len(), 2, "Should have 2 Germany servers");
}

#[test]
fn test_find_servers_by_country_none() {
    let manager = ServerManager::new().unwrap();
    let xx_servers = manager.find_by_country("XX");
    assert!(xx_servers.is_empty());
}

#[test]
fn test_server_display_list() {
    let manager = ServerManager::new().unwrap();
    let display_list = manager.get_server_display_list();
    assert_eq!(display_list.len(), 9);

    // First entry should be California
    assert_eq!(display_list[0].0, "us-california-1");
    assert_eq!(display_list[0].1, "US-California-1");
}

#[test]
fn test_select_best_server() {
    let manager = ServerManager::new().unwrap();
    let best = manager.select_best_server();
    assert!(best.is_some(), "Should return a server when list is non-empty");
}

#[test]
fn test_server_has_endpoint() {
    let manager = ServerManager::new().unwrap();
    for server in manager.get_servers() {
        assert!(
            server.server_endpoint_address.contains(':'),
            "Server {} endpoint should contain port separator",
            server.server_identifier
        );
    }
}

#[test]
fn test_server_has_public_key() {
    let manager = ServerManager::new().unwrap();
    for server in manager.get_servers() {
        assert!(
            !server.server_public_key_base64.is_empty(),
            "Server {} should have a public key",
            server.server_identifier
        );
    }
}
