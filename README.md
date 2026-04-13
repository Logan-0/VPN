# RustVPN

A secure, lightweight VPN client written in Rust with zero logging, DNS filtering, and kill switch protection.

## Features

- **Zero Logs**: No connection data, timestamps, or IP addresses stored
- **WireGuard Protocol**: Modern, secure, and lightweight
- **Kill Switch**: Prevents traffic leaks if VPN disconnects
- **DNS Filtering**: Built-in DNS-over-HTTPS/TLS with ad/malware blocking
- **Auto-Reconnect**: Automatic reconnection with exponential backoff
- **Cross-Platform**: Linux, macOS, and Windows support
- **Minimal GUI**: Clean interface using Iced framework

## Server Coverage

- **United States**: One server per state (50 locations)
- **Sweden**: Multiple locations (Stockholm, Gothenburg, Malmö)

## Building

```bash
cargo build --release
```

## Running

```bash
sudo ./target/release/rust-vpn
```

Note: Root/admin privileges required for network interface management.

## License

MIT
