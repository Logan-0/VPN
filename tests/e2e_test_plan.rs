//! E2E Test Plan — End-to-end test documentation for VPN system validation.
//!
//! # Test Environment
//! Tests marked `#[ignore]` require root privileges and a running WireGuard server.
//! Run with: `sudo cargo test --test e2e_test_plan -- --ignored`
//!
//! Requirements:
//! - Linux with iproute2 and iptables installed
//! - Root or CAP_NET_ADMIN capability
//! - WireGuard server endpoint for tunnel tests
//! - Pi-hole instance for DNS tests
//!
//! # Test Matrix
//! | # | Test Case                              | Components Exercised                        |
//! |---|----------------------------------------|---------------------------------------------|
//! | 1 | TUN device lifecycle                   | LinuxPlatform                               |
//! | 2 | Tunnel handshake + encrypt/decrypt     | Tunnel, boringtun                           |
//! | 3 | Full connect flow                      | Controller -> Tunnel -> TUN -> PacketLoop   |
//! | 4 | Kill switch blocks traffic on drop     | KillSwitch + iptables                       |
//! | 5 | Kill switch allows VPN traffic         | KillSwitch + TUN routing                    |
//! | 6 | Auto-reconnect after simulated failure | ReconnectManager + Tunnel                   |
//! | 7 | DNS filter blocks ad domain            | DnsFilter -> is_blocked                     |
//! | 8 | DNS resolver via DoH                   | DnsResolver (Cloudflare)                    |
//! | 9 | DNS resolver via custom (Pi-hole)      | DnsResolver::custom                         |
//! |10 | Config round-trip persistence           | VpnConfig save -> load                      |
//! |11 | Server selection from config           | ServerManager + VpnConfig                   |
//! |12 | GUI -> Controller command flow         | VpnController + VpnCommand/VpnEvent         |
//! |13 | Packet loop shutdown on signal         | PacketLoop + watch channel                  |
//! |14 | Graceful cleanup on disconnect         | LinuxPlatform::cleanup + KillSwitch::disable|
//!
//! ## How to Add a WireGuard Test Server
//!
//! For tests 2, 3, 5, 6 you need a WireGuard peer. The simplest setup:
//!
//! ```bash
//! # On the test server (or same machine in a network namespace):
//! wg genkey | tee server_private | wg pubkey > server_public
//! ip link add wg-test type wireguard
//! ip addr add 10.8.0.1/24 dev wg-test
//! wg set wg-test listen-port 51820 private-key ./server_private
//! ip link set wg-test up
//! ```
//!
//! Then set `TEST_WG_SERVER_IP` and `TEST_WG_SERVER_PUBKEY` environment
//! variables when running the ignored tests.

use rust_vpn::config::VpnConfig;
use rust_vpn::core::controller::{VpnCommand, VpnController, VpnEvent, VpnState};
use rust_vpn::core::reconnect::ReconnectManager;
use rust_vpn::dns::filter::{DnsFilter, DnsFilterMode};
use rust_vpn::dns::resolver::DnsResolver;
use rust_vpn::server::ServerManager;
use std::time::Duration;

// ============================================================================
// E2E 1: TUN device lifecycle (requires root)
// ============================================================================

#[test]
#[ignore]
fn e2e_tun_device_create_and_cleanup() {
    // This test requires root / CAP_NET_ADMIN
    use rust_vpn::platform::linux::LinuxPlatform;

    let mut platform = LinuxPlatform::new().unwrap();

    // Create TUN device
    let _device = platform
        .create_tun(
            (10, 8, 0, 2),
            (255, 255, 255, 0),
            "127.0.0.1".parse().unwrap(),
        )
        .expect("Failed to create TUN device");

    // Verify device name was assigned
    let dev_name = platform
        .tun_device_name()
        .expect("Should have a device name");
    assert!(
        dev_name.starts_with("tun"),
        "Device name should start with 'tun'"
    );

    // Cleanup
    platform.cleanup().unwrap();
    assert!(platform.tun_device_name().is_none());
}

// ============================================================================
// E2E 7: DNS filter blocks ad domain (no special privileges needed)
// ============================================================================

#[test]
fn e2e_dns_filter_full_flow() {
    // 1. Create filter with built-in blocklist
    let mut filter = DnsFilter::new().unwrap();

    // 2. Verify built-in ads are blocked
    assert!(filter.is_blocked("doubleclick.net"));
    assert!(!filter.is_blocked("example.com"));

    // 3. Load additional hosts file
    let extra_hosts = "0.0.0.0 extra-bad-domain.com\n0.0.0.0 another-bad.org\n";
    filter.load_hosts_file(extra_hosts);
    assert!(filter.is_blocked("extra-bad-domain.com"));

    // 4. Switch to Pi-hole mode
    filter.set_mode(DnsFilterMode::ExternalDns("192.168.1.53".parse().unwrap()));
    assert!(
        !filter.is_blocked("doubleclick.net"),
        "Pi-hole mode should defer"
    );

    // 5. Switch back
    filter.set_mode(DnsFilterMode::BuiltIn);
    assert!(filter.is_blocked("doubleclick.net"));
}

// ============================================================================
// E2E 8: DNS resolver via DoH (requires network access)
// ============================================================================

#[tokio::test]
#[ignore]
async fn e2e_dns_resolver_cloudflare_doh() {
    let resolver = DnsResolver::new().unwrap();
    let addrs = resolver.resolve("example.com").await.unwrap();
    assert!(
        !addrs.is_empty(),
        "Should resolve example.com to at least one IP"
    );
}

// ============================================================================
// E2E 9: DNS resolver via custom server / Pi-hole (requires Pi-hole)
// ============================================================================

#[tokio::test]
#[ignore]
async fn e2e_dns_resolver_custom_pihole() {
    // Set TEST_PIHOLE_IP=192.168.1.53 to run this test
    let pihole_ip =
        std::env::var("TEST_PIHOLE_IP").expect("Set TEST_PIHOLE_IP env var to run this test");

    let resolver = DnsResolver::custom(pihole_ip.parse().unwrap()).unwrap();
    let addrs = resolver.resolve("example.com").await.unwrap();
    assert!(!addrs.is_empty());
}

// ============================================================================
// E2E 10: Config round-trip persistence
// ============================================================================

#[test]
fn e2e_config_round_trip() {
    let config = VpnConfig {
        selected_vpn_server_identifier: Some("us-california-1".to_string()),
        custom_dns_server_address: Some("192.168.1.53".to_string()),
        kill_switch_protection_enabled: false,
        ..Default::default()
    };

    let toml_str = toml::to_string_pretty(&config).unwrap();
    let restored: VpnConfig = toml::from_str(&toml_str).unwrap();

    assert_eq!(
        restored.selected_vpn_server_identifier,
        config.selected_vpn_server_identifier
    );
    assert_eq!(
        restored.custom_dns_server_address,
        config.custom_dns_server_address
    );
    assert_eq!(
        restored.kill_switch_protection_enabled,
        config.kill_switch_protection_enabled
    );
}

// ============================================================================
// E2E 11: Server selection from config
// ============================================================================

#[test]
fn e2e_server_selection_from_config() {
    let manager = ServerManager::new().unwrap();
    let config = VpnConfig {
        selected_vpn_server_identifier: Some("sweden-stockholm-1".to_string()),
        ..VpnConfig::default()
    };

    let server = config
        .selected_vpn_server_identifier
        .as_deref()
        .and_then(|id| manager.find_by_id(id));

    assert!(server.is_some());
    let server = server.unwrap();
    assert_eq!(server.server_country_code, "SE");
    assert_eq!(server.server_endpoint_address, "203.0.113.10:51820");
}

// ============================================================================
// E2E 12: GUI -> Controller command flow
// ============================================================================

#[test]
fn e2e_controller_connect_disconnect_flow() {
    let controller = VpnController::new();

    // Take the event receiver -- in the Iced GUI this is handed to a
    // Subscription; in tests we poll it directly with try_recv().
    let event_rx = controller.take_event_rx();

    // Send connect command
    controller.send_command(VpnCommand::Connect {
        server_endpoint: "203.0.113.1:51820".to_string(),
        server_public_key_base64: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=".to_string(),
    });

    // Give worker thread time to process
    std::thread::sleep(Duration::from_millis(200));

    // Should receive Connecting state event
    let mut saw_connecting = false;
    while let Ok(event) = event_rx.try_recv() {
        if let VpnEvent::StateChanged(VpnState::Connecting) = event {
            saw_connecting = true;
        }
    }
    assert!(saw_connecting, "Should receive Connecting state event");

    // Send disconnect
    controller.send_command(VpnCommand::Disconnect);
    std::thread::sleep(Duration::from_millis(200));

    let mut saw_disconnected = false;
    while let Ok(event) = event_rx.try_recv() {
        if let VpnEvent::StateChanged(VpnState::Disconnected) = event {
            saw_disconnected = true;
        }
    }
    assert!(saw_disconnected, "Should receive Disconnected state event");
}

// ============================================================================
// E2E 6: Auto-reconnect after simulated failure
// ============================================================================

#[test]
fn e2e_reconnect_manager_backoff_sequence() {
    let mut manager = ReconnectManager::new().unwrap();

    // Simulate 3 failures with exponential backoff
    assert!(manager.should_attempt_reconnect());

    manager.record_failure(); // 1st fail -> backoff 2s
    manager.record_failure(); // 2nd fail -> backoff 4s
    manager.record_failure(); // 3rd fail -> backoff 8s

    assert_eq!(manager.get_consecutive_failures(), 3);
    assert_eq!(manager.get_current_backoff(), Duration::from_secs(8));

    // Simulate success
    manager.record_success();
    assert_eq!(manager.get_consecutive_failures(), 0);
    assert_eq!(manager.get_current_backoff(), Duration::from_secs(1));
    assert!(manager.time_since_last_success().is_some());
}
