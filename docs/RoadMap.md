# RustVPN — Roadmap

**Status**: Stable · **Version**: 1.0.0 · **Last Updated**: 2026-08-09

v1.0.0 is the documented, stable release. The Linux-only implementation is
feature-complete and operationally validated, and the documented scope is
frozen — there is no "before 1.0" backlog left open. Windows and macOS were
evaluated and **permanently retired** in commit `bf1a8a7` ("Remove macOS and
Windows platform support - Linux only"); `src/platform/windows.rs` and
`src/platform/macos.rs` do not exist in the tree and there is no intention to
revisit either. The automated suite — currently 158 passing, 0 failures, 10
ignored (7 of those are `ignore`d doc-tests) — is the release gate for any
change.

Everything already built and shipped is recorded in `docs/ChangeLog.md`; the
reasoning behind the notable design decisions lives in `docs/Education.md`.
Neither belongs here.

## Open work

One item, and it is operational upkeep rather than development: adding real
server endpoints to `resources/servers.toml` as they become available. The
nine entries shipped today are placeholders — cryptographically valid base64
X25519 public keys paired with RFC 5737 documentation addresses from
`203.0.113.0/24`. Because the keys are the correct shape, the entire connect
path runs end to end (TUN creation, kill-switch activation, Noise handshake
start) and only the handshake itself fails, since no real server holds the
matching private key. That is exactly the expected outcome for placeholder
infrastructure. Swapping in a real server means replacing
`server_endpoint_address` and `server_public_key_base64`; the file documents
the procedure inline.

## Scope note

RustVPN is **unrelated to MediaServer's Tailscale remote access**. This is a
client-side WireGuard VPN that routes a workstation's own traffic through a
remote server. Tailscale, in the MediaServer project, is a mesh overlay used
to reach a NAS behind double-NAT. The two have been conflated before; they
share no code, no configuration, and no roadmap.
