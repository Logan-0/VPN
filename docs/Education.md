# Education — RustVPN

This document is a teaching guide to the RustVPN project. It's written for a
motivated high-school or early-college reader who knows *some* programming
(variables, loops, functions) but hasn't necessarily touched raw sockets,
kernel network interfaces, or cryptography before. Every section explains
**what** the code does, **why** it's built that way, and **what general
concept** it's teaching you — so you can carry the idea to other projects
even if you never touch this codebase again.

> **Scope note:** RustVPN is Linux-only (v1.0.0, feature-complete). Windows
> and macOS support were evaluated and deliberately retired — see
> `docs/RoadMap.md`. Everything below describes the Linux implementation.

---

## 1. The Big Picture: What Problem Does a VPN Actually Solve?

Normally, when your laptop talks to the internet, every packet you send
carries your real IP address, and it's visible — to your ISP, to the
Wi-Fi network you're on, to anyone positioned between you and the
destination server — that it came from *you*, and (unless the app itself
encrypts it) what's inside it.

A VPN (Virtual Private Network) inserts itself into that path:

```
Before:  Your laptop  ---plain packets--->  Internet  --->  example.com

After:   Your laptop --[encrypt]--> VPN server --[forward]--> Internet ---> example.com
                (looks like random bytes to
                 anyone watching the Wi-Fi/ISP)
```

Two things happen:
1. **Encryption** — everything between your laptop and the VPN server is
   unreadable to anyone snooping in between.
2. **IP substitution** — `example.com` sees the VPN server's IP address as
   the source, not yours.

RustVPN is a **client**: it runs on your machine, builds an encrypted tunnel
to a VPN server (whose address is *not* included in this repo — see
`resources/servers.toml`'s placeholder note), and reroutes your machine's
traffic through that tunnel. It uses **WireGuard**, a modern VPN protocol,
via the `boringtun` crate — a pure-Rust userspace implementation of
WireGuard's cryptography (`src/core/tunnel.rs`).

Unlike a typical "three programs talking over HTTP" web app, RustVPN's shape
is fundamentally different: it's **one process that sits between your OS's
network stack and the internet**, doing per-packet encryption in a tight
loop. That single fact — operating below the application layer, on raw IP
packets — drives almost every design decision in this codebase.

---

## 2. Networking Concepts You Need First

This is the deep end. RustVPN teaches concepts most web projects never
touch, because it operates at a much lower layer of the network stack.

### 2.1 The Layered Network Stack, and Where RustVPN Lives

Networking is usually described as a stack of layers, each one wrapping the
layer above it in its own header before handing it down:

```
Layer 7  Application   HTTP, DNS queries, etc.        (your browser's data)
Layer 4  Transport     TCP or UDP                      (ports, reliability)
Layer 3  Network       IP                               (addressing, routing)
Layer 2  Link          Ethernet/Wi-Fi frames            (local hardware)
```

A normal application (like a browser) only ever touches Layer 7 — it calls
`fetch()` or opens a socket, and the OS kernel handles everything below
that. RustVPN is different: it operates at **Layer 3**. It reads and writes
whole IP packets directly (source/destination IP, protocol number, payload)
via a **TUN device** (§2.3), encrypts each one, and ships the encrypted
result over **UDP** at Layer 4 to the VPN server. This is why
`src/dns/intercept.rs` has to manually parse IP and UDP headers byte-by-byte
(more on that in §2.5) — nothing in the standard library does that for you
when you're working one layer below normal application code.

### 2.2 IP Addresses, Ports, and Routing Tables

An **IP address** identifies a machine on a network (e.g. `10.8.0.2` or
`203.0.113.1`). A **port** (a number 0–65535) identifies *which program* on
that machine a packet is for — WireGuard servers conventionally listen on
UDP port `51820` (see `server_endpoint_address` in
`resources/servers.toml`, and the doc comment on `Server::server_endpoint_address`
explaining "WireGuard uses UDP port 51820 by default").

Your OS decides *where* to send each outgoing packet using a **routing
table** — a list of rules like "packets to 10.x.x.x go out interface eth0"
or "everything else (0.0.0.0/0) goes to the default gateway." RustVPN's
entire job, at the OS level, boils down to **rewriting that routing table**
so "everything" routes into its own tunnel interface instead of straight to
the internet. That happens in `src/platform/linux.rs`'s `create_tun`:

```rust
// Add default route through TUN device
//    Two half-default routes avoid conflicting with the existing 0.0.0.0/0
let _ = Command::new("ip")
    .args(["route", "add", "0.0.0.0/1", "dev", &dev_name])
    .output();
let _ = Command::new("ip")
    .args(["route", "add", "128.0.0.0/1", "dev", &dev_name])
    .output();
```

**Why two half-ranges instead of one `0.0.0.0/0`?** Routing tables use
**longest-prefix-match**: the router picks whichever matching rule has the
*most specific* (longest) prefix. `0.0.0.0/1` covers the first half of all
IPv4 addresses and `128.0.0.0/1` covers the second half — together they
cover 100% of the address space, but each one is *more specific* (a /1 beats
a /0) than the machine's pre-existing default route. So both new rules win
over the old default route without the code ever having to delete or
replace it — a clever trick that also makes `cleanup()` simpler, since
un-doing two `ip route add` calls with two `ip route del` calls perfectly
restores the original state.

Before installing those routes, the code also carves out one exception:

```rust
// Add host route for VPN server via original gateway
if let Some(ref gw) = self.original_gateway {
    let _ = Command::new("ip")
        .args(["route", "add", &vpn_server_ip.to_string(), "via", gw])
        .output();
```

This is a **more specific route** (a single host, `/32` implicitly) for the
VPN server's own IP, sent via the *original* gateway rather than through the
tunnel. Without it you'd have a routing loop: packets to the VPN server
would themselves try to go through the VPN tunnel, which needs to reach the
VPN server, which needs the tunnel... This "the tunnel's own traffic must
bypass the tunnel" rule is one of the first things every VPN implementation
has to get right, and it shows up again in the kill switch (§2.6).

### 2.3 TUN Devices: A Virtual Network Card Made of Software

Normally a network interface (`eth0`, `wlan0`) is backed by real hardware.
A **TUN device** is a *virtual* one, created entirely in software, that the
kernel treats exactly like a real one for routing purposes — except instead
of sending bits over a wire, it hands raw IP packets to whatever userspace
program opened it (and vice versa). This is the standard technique every
VPN client uses to intercept traffic without needing a kernel driver of its
own.

`src/platform/linux.rs`'s `create_tun` creates one using the `tun` crate:

```rust
let mut config = tun::Configuration::default();
config
    .address(tun_ip)
    .netmask(tun_netmask)
    .mtu(WIREGUARD_MTU as i32)
    .up();

let device = tun::create(&config)
    .context("Failed to create TUN device (do you have root / CAP_NET_ADMIN?)")?;
```

Once created (as `tun0`), any packet the OS routes to `tun0` (which, after
§2.2's route changes, is *all* of them) gets handed to RustVPN as raw bytes
via a file descriptor that behaves like a file: `read()` gets you the next
outgoing packet, `write()` injects a packet as if it arrived from the
network. `src/core/packet_loop.rs` is built entirely around this read/write
pair — see §5 for the full loop.

**MTU** (`WIREGUARD_MTU = 1420`, set in the same `Configuration`) is the
Maximum Transmission Unit — the biggest packet size the interface will pass
without fragmenting. It's set below the usual Ethernet default of 1500
specifically to leave room for the ~32-40 bytes of WireGuard header and
encryption overhead the packet will grow by before it goes out over the
*real* network interface, whose own MTU is still 1500. Get this number
wrong and packets silently get fragmented or dropped somewhere on the path
— a classic, hard-to-diagnose VPN bug.

### 2.4 Encapsulation and Tunneling

**Tunneling** means wrapping one protocol's packets inside another
protocol's packets so they can travel across a network that wasn't built to
carry the inner protocol directly. RustVPN's tunnel does exactly this: a
plain IP packet (say, your laptop trying to reach `93.184.216.34:443`)
becomes the *payload* of an encrypted WireGuard message, which itself
travels as the payload of a normal UDP packet to the VPN server:

```
Original packet:  [IP header: you -> 93.184.216.34][TCP][HTTPS data]
                                  |
                                  v  encapsulate() in src/core/tunnel.rs
Wire format:      [IP: you -> VPN server][UDP:51820][WireGuard header][ChaCha20-Poly1305(original packet)]
```

The VPN server decrypts the WireGuard payload, recovers your original
packet, and forwards *that* onward to `93.184.216.34` using its own
identity as the source IP — which is the "IP substitution" from §1. The
reverse happens for the reply. This wrap-encrypt-send / receive-decrypt-
unwrap pair is called **encapsulation** and **decapsulation**, and it's
implemented directly in `Tunnel::encapsulate` / `Tunnel::decapsulate`
(`src/core/tunnel.rs`), which are thin wrappers around `boringtun`'s
`Tunn::encapsulate` / `decapsulate`.

### 2.5 Parsing Raw Packets by Hand

Because RustVPN operates below the application layer, some of its code has
to do what your OS's network stack normally does invisibly: parse binary
packet formats byte by byte. `src/dns/intercept.rs`'s `try_block_dns_query`
is the clearest example — it inspects a raw packet read from the TUN device
to figure out "is this a DNS query, and if so, for which domain?" *before*
handing it off to encryption:

```rust
// High nibble of byte 0 is the IP version; we only handle IPv4.
if packet[0] >> 4 != 4 {
    return None;
}
// Low nibble is the IHL (Internet Header Length) in 32-bit words.
let ihl = (packet[0] & 0x0F) as usize;
let ip_header_len = ihl * 4;
```

This is your first real exposure to **binary protocol parsing**: every
field lives at a fixed byte offset or bit position, defined by an RFC (here,
RFC 791 for IPv4, RFC 1035 for DNS), and getting an offset wrong doesn't
throw a friendly exception — it silently reads garbage. Note the defensive
style throughout: every length is checked against the buffer's actual size
*before* it's used to index into that buffer (`if packet.len() < 20 {
return None; }`), because a malformed or truncated packet must never be
allowed to cause an out-of-bounds read. `parse_qname` similarly refuses to
follow DNS "compression pointers" in the question section — not just
because the RFC says they shouldn't appear there, but because following a
malicious pointer could create an infinite loop (a classic **denial-of-
service** vector in parser code, worth remembering any time you write a
parser for attacker-controlled input).

The same file's `ones_complement_sum` implements the **Internet checksum**
algorithm (RFC 1071) used by both IP and UDP headers — a 16-bit
one's-complement sum designed to be cheap to compute on 1970s-era hardware
and still detect most single- and double-bit transmission errors. When
`try_block_dns_query` synthesizes a fake "domain not found" reply, it must
compute this checksum correctly (`build_udp_segment`, `build_ipv4_packet`)
or the OS network stack on the *receiving* end will silently discard the
packet as corrupt.

### 2.6 The Kill Switch: Firewall Rules as a Safety Net

Encryption only helps while the tunnel is actually up. If the VPN process
crashes or the connection drops, your OS's normal routing kicks back in and
your traffic goes out *unencrypted, with your real IP* — a **leak**. A
**kill switch** prevents this by using the OS firewall to block all traffic
except what's explicitly allowed, so a dead tunnel means "no internet" (safe)
instead of "silently unprotected" (dangerous).

`src/core/killswitch.rs` implements this with `iptables`, Linux's
traditional firewall configuration tool, by building a custom chain:

```rust
// Drop everything else
iptables_checked(
    &["-A", "RUSTVPN_OUT", "-j", "DROP"],
    "Failed to add drop rule",
)?;

// Insert our chain at the beginning of OUTPUT. This is the link-in step
// that actually activates the kill switch...
iptables_checked(
    &["-I", "OUTPUT", "1", "-j", "RUSTVPN_OUT"],
    "Failed to insert chain into OUTPUT",
)?;
```

`iptables` rules are evaluated top-to-bottom, first match wins. The chain
`RUSTVPN_OUT` is built with explicit `ACCEPT` rules first (loopback, the
`tun0` interface, the VPN server's own IP+port so reconnection traffic can
still reach it, and RFC 1918 local network ranges like `192.168.0.0/16`) and
a catch-all `DROP` last. That chain is inert on its own until it's spliced
into the kernel's real `OUTPUT` chain — this is a **default-deny** firewall
policy: block everything, then carve out narrow exceptions, rather than the
much less safe "allow everything, then block known-bad things."

The code comment on `enable_linux` explains a subtle but critical ordering
bug class: every step before the final `-I OUTPUT` call is just building an
*inactive* chain — if any earlier `iptables` call fails and the function
returns `Err`, **nothing has actually blocked anything yet**, even though
several commands "succeeded." That's why `controller.rs`'s `Connect` handler
treats a kill-switch `enable()` failure as **fail-closed** — it refuses to
bring up the tunnel at all rather than connecting with a kill switch that
looks configured but isn't:

```rust
if let Err(e) = ks.enable(server_addr.ip(), "tun0") {
    Self::emit_error(&event_tx, format!(
        "Kill switch error: {} — refusing to connect without the requested protection", e));
    continue;
}
```

Compare that to `disable_linux`, which deliberately ignores every command's
result (`iptables_best_effort`, using `let _ =`): a partial failure while
*removing* rules leaves the network **more** restricted, never less — the
safe direction to fail in for a kill switch. Noticing which direction is
"safe to fail toward" and coding defensively in that direction is a general
security-engineering habit, not just an iptables trick.

### 2.7 DNS: The Internet's Phonebook, and Why It Leaks

Before your browser can connect to `example.com`, it has to translate that
name into an IP address — a **DNS query**. Historically, DNS travels as
plaintext UDP on port 53, which means anyone watching your network traffic
(your ISP, in particular) can build a list of every domain you've ever
visited, *even if the actual connection afterward is HTTPS-encrypted* — a
**DNS leak**.

RustVPN addresses this two ways, both centered on the fact that a TUN
device sees literally every packet leaving the machine, DNS included:

- **Blocking** (`src/dns/intercept.rs` + `src/dns/filter.rs`): before
  encrypting an outgoing packet, `try_block_dns_query` checks whether it's
  a DNS query for a domain on `DnsFilter`'s blocklist (ad networks,
  trackers, malware domains). If so, it synthesizes a fake "not found"
  answer and writes it straight back to the TUN device — the blocked
  domain's query never leaves the machine at all, encrypted or not.
- **Encryption-by-tunnel** for everything else: allowed DNS queries are
  *not* specially encrypted — they just flow through the same WireGuard
  tunnel as any other packet. Because the whole IP packet (destination port
  53 and all) is encrypted before it leaves your machine, your ISP sees
  only opaque UDP traffic to the VPN server's IP, never the domain names
  inside.

Interestingly, `src/dns/resolver.rs` implements a *third*, more elaborate
technique — **DNS-over-HTTPS (DoH)**, which disguises DNS queries as normal
HTTPS traffic to a resolver like Cloudflare's `1.1.1.1`, using the
`hickory-resolver` crate. It's fully implemented and documented but,
per this project's `docs/RoadMap.md`, it's **not wired into the live
packet path** — since DNS already rides inside the encrypted tunnel, a
second layer of DNS-specific encryption on top would be redundant for this
project's threat model. It's a good example of a codebase keeping a
fully-built, tested feature (see `tests/dns_intercept_tests.rs`) *dormant*
rather than deleting it, in case requirements change (e.g. split-tunnel
modes where DNS wouldn't ride the tunnel).

### 2.8 The WireGuard Protocol and Its Cryptography

**WireGuard** is a modern VPN protocol whose entire design goal was to be
small and auditable — the reference implementation is famously a few
thousand lines, versus the hundreds of thousands in OpenVPN or IPsec.
RustVPN uses `boringtun` (`src/core/tunnel.rs`), a pure-Rust implementation
of WireGuard's data-plane cryptography, rather than shelling out to the
kernel's WireGuard module or the `wg` CLI tool — meaning the crypto runs
entirely in RustVPN's own process, in Rust, no unsafe FFI into C libraries.

Three cryptographic primitives do the real work, all visible in this
codebase:

- **X25519** (Curve25519 Diffie-Hellman) — each peer (client and server)
  has a static keypair. `generate_keypair()` in `tunnel.rs` creates one
  using `boringtun::x25519::StaticSecret::random_from_rng`. Two peers who
  each know their own private key and the other's *public* key can compute
  the exact same shared secret without ever transmitting it — this is the
  mathematical trick that makes public-key cryptography possible at all.
  `Server::server_public_key_base64`'s doc comment spells out the
  handshake: *"Both parties compute shared secret: X25519(my_private,
  their_public)."*
- **ChaCha20-Poly1305** — a fast authenticated stream cipher. "Authenticated"
  means it doesn't just hide the data, it also detects tampering: any bit
  flipped in transit (by an attacker, or by network corruption) causes
  decryption to fail loudly rather than silently returning corrupted
  plaintext. This is what actually encrypts/decrypts every packet inside
  `Tunn::encapsulate`/`decapsulate`.
- **The Noise Protocol** — WireGuard's handshake (performed inside
  `boringtun::noise::Tunn::new` when `Tunnel::connect` is called) uses the
  Noise Protocol Framework to have both peers authenticate each other and
  derive fresh per-session encryption keys — so even if a session key were
  somehow compromised later, past traffic captured off the wire still can't
  be decrypted (**forward secrecy**).

RustVPN never re-implements any of this math itself — the entire point of
using `boringtun` and treating the private key as `Zeroizing<[u8; 32]>` (see
§3.7) is that cryptographic primitives are notoriously easy to get subtly,
catastrophically wrong if you write them yourself. The lesson generalizes:
**for anything security-critical, use an audited library, never roll your
own.**

Every 25 seconds (`KEEPALIVE_INTERVAL`), the tunnel sends an empty
encapsulated packet as a **NAT keepalive** — home routers and firewalls
forget about a UDP "connection" if no traffic crosses it for a while
(there's no persistent connection state in UDP the way there is in TCP), so
without a keepalive, an idle VPN tunnel would silently stop being able to
receive replies until the client sent something new.

---

## 3. Rust Systems Concepts, Taught Through This Codebase

RustVPN is Rust code operating in a domain (raw sockets, kernel devices,
signal-sensitive cleanup) where the language's core guarantees — no null
pointers, no data races without an explicit lock, deterministic destructors
— matter enormously more than in a typical web backend.

### 3.1 The Crate Layout, Traced from `Cargo.toml`

`Cargo.toml`'s `[dependencies]` section is a map of the project's actual
capabilities:

```toml
tokio = { version = "1.41", features = ["rt", "rt-multi-thread", "macros", "sync", "time", "net"] }
boringtun = "0.6"                 # WireGuard protocol
hickory-resolver = { version = "0.24", ... }  # DNS resolution
iced = { version = "0.13", features = ["tokio", "wgpu"] }  # GUI framework
zeroize = "1.8"                   # Security - memory wiping
tun = "0.6"                       # Network interface management
[target.'cfg(unix)'.dependencies]
nix = { version = "0.29", features = ["net", "socket", "ioctl", "user"] }
caps = "0.5"
```

Notice each dependency is scoped tightly to what's actually used — the
comment above `tokio`'s line even documents that its feature list was
*trimmed* down to exactly what the codebase needs (`rt`, `sync`, `time`,
`net`, etc.) rather than pulling in `features = ["full"]`, which would bloat
compile times and binary size for capabilities the project never calls. This
mirrors a broader systems-engineering habit: dependencies aren't free, so
audit what you actually import.

### 3.2 `Drop` as RAII: Guaranteed Cleanup

Rust doesn't have garbage collection; instead, every value's destructor
(`Drop::drop`) runs automatically and deterministically the instant it goes
out of scope. This pattern — tying a resource's cleanup to its owner's
lifetime — is called **RAII** (Resource Acquisition Is Initialization), and
RustVPN leans on it heavily for exactly the kind of resource that must
*never* leak: firewall rules and network interfaces.

```rust
impl Drop for KillSwitch {
    fn drop(&mut self) {
        if self.state == KillSwitchState::Enabled {
            warn!("Kill switch dropped while enabled - attempting cleanup");
            let _ = self.disable();
        }
    }
}
```

The same pattern appears on `LinuxPlatform` (removes routes, destroys the
TUN device) and `Tunnel` (logs a warning if dropped while still connected).
This is why `Cargo.toml`'s `[profile.release]` section explicitly does
*not* set `panic = "abort"`, with a comment explaining the tradeoff:

```
# panic = "abort" intentionally NOT set: KillSwitch/LinuxPlatform/Tunnel all
# rely on Drop to remove firewall rules / TUN devices if something goes wrong.
# "abort" skips unwinding, so those Drop impls would never run on a panic,
```

That's a genuinely subtle, important Rust lesson: `panic = "abort"` is a
common size/performance optimization, but it silently defeats every `Drop`
impl's safety-net behavior on panic, because "abort" means the process dies
*without* unwinding the stack (and therefore without running destructors).
For a project where a stray `unwrap()` panic leaving iptables rules
permanently installed would be a real user-facing bug, `panic = "unwind"`
(the default) is the correct tradeoff even though it costs a bit of binary
size.

### 3.3 `Result`, `?`, and `anyhow`: Rust's Error Handling

Rust has no exceptions; a function that can fail returns `Result<T, E>`.
The `?` operator, used at the end of an expression, means "if this is
`Err`, return that error immediately from the enclosing function;
otherwise unwrap the `Ok` value and keep going":

```rust
let output = Command::new("ip")
    .arg("-V")
    .output()
    .context("iproute2 (`ip` command) is required but not found")?;
```

`anyhow::Result<T>` (an alias for `Result<T, anyhow::Error>`) is used
throughout instead of hand-rolled error enums, because this is an
application binary, not a library other crates will programmatically match
errors from — callers just need *a* descriptive error to log or show the
user. `.context("...")`, from the same `anyhow` crate, attaches a
human-readable explanation to whatever underlying error occurred, so a
failure three layers deep (say, `tun::create` failing because the process
lacks `CAP_NET_ADMIN`) surfaces as a message that actually tells the user
what to do about it, not just "Permission denied (os error 13)".

### 3.4 Enums as State Machines

`TunnelState` (`src/core/tunnel.rs`) models the tunnel's lifecycle as a
Rust `enum`:

```rust
pub enum TunnelState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Error,
}
```

Because Rust enums are **sum types** — a value is *exactly one* of these
variants, never a combination and never "none of the above" — the compiler
can force you (via `match`) to handle every possible state explicitly.
`VpnState` in `src/core/controller.rs` mirrors this with its own, GUI-facing
enum rather than reusing `TunnelState` directly — a deliberate decoupling so
the GUI module never needs to `use crate::core::tunnel` at all. Draw a
boundary between two layers, and don't let one side's internal
representation leak across it — the same principle that shows up as
interfaces in other languages.

### 3.5 Concurrency: Threads, Tokio Tasks, and Channels

RustVPN mixes three different concurrency primitives, each for a different
reason:

**A dedicated OS thread** for the entire VPN core, spawned in
`VpnController::new()`:

```rust
std::thread::Builder::new()
    .name("vpn-core".to_string())
    .spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create Tokio runtime for VPN core");
        rt.block_on(async move { Self::run_worker(...).await; });
    })
```

**Why a whole thread just to run an async runtime?** The GUI framework
(Iced) owns the main thread and runs its own event loop there; if VPN work
ran on that thread it would freeze mouse clicks and redraws every time a
packet needed encrypting. Putting a `tokio::runtime::Builder::new_current_thread()`
runtime on its own OS thread gives the async VPN code (which needs
`await`-based concurrency for things like `tokio::select!` in the packet
loop) a home that can never block the UI.

**`tokio::spawn`** for the packet loop itself, inside that dedicated
runtime — so the command-processing loop (`run_worker`'s `match cmd { ... }`)
stays responsive to a `Disconnect` command even while packets are actively
flowing, because both tasks interleave at every `.await` point on the same
runtime.

**Channels**, not shared mutable state, for cross-thread/cross-task
communication — the philosophy "don't communicate by sharing memory; share
memory by communicating" — and RustVPN uses several different flavors
deliberately:
- `tokio::sync::mpsc::unbounded_channel` for GUI→core commands
  (`command_tx`), because a burst of rapid clicks shouldn't ever block the
  GUI thread waiting for the worker to catch up.
- `std::sync::mpsc::channel` for core→GUI events (`event_rx`), polled by
  Iced's subscription mechanism on each UI tick rather than awaited.
- `tokio::sync::watch::channel` for the packet loop's stop signal
  (`stop_tx`/`stop_rx`) — a *watch* channel is specifically designed for
  "broadcast the latest value of some state" (here, `bool` — "should I
  stop?") rather than a queue of discrete messages, which is exactly the
  right shape for a shutdown flag.

Where actual shared mutable state genuinely can't be avoided — the
`Tunnel` instance itself, whose `encapsulate`/`decapsulate` methods are
called from the same spawned task on both the TUN-read arm and the UDP-recv
arm of a `select!` — it's wrapped in `Arc<Mutex<Tunnel>>` (`packet_loop.rs`),
a synchronous `std::sync::Mutex` rather than an async one, with a comment
explaining why: *"the critical section is just one crypto op per packet, so
contention is negligible."* Choosing a plain (blocking) mutex over an async
one when the critical section is short and CPU-bound (not I/O-bound) is a
real, common performance judgment call in async Rust.

### 3.6 `unsafe` and Raw File Descriptors

Most Rust code never needs `unsafe`. `src/core/packet_loop.rs` does,
because it needs to hand the *same* TUN device to two different execution
contexts at once — a blocking OS thread that reads from it, and the async
world that writes to it — and Rust's ownership rules normally forbid two
owners of one resource:

```rust
// Safety: we duplicate the fd so closing this File won't close the real device
let dup_fd = unsafe { libc::dup(tun_fd) };
...
let mut file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
```

`libc::dup` is a raw OS syscall that creates a second file descriptor
pointing at the *same* underlying kernel file object — so both the
original TUN device and this duplicate can be read/written independently,
and dropping either one doesn't close the other. Every `unsafe` block here
is preceded by a `// Safety:` comment justifying *why* the operation is
actually sound despite bypassing the compiler's checks — that comment
convention (documenting the invariant a human is now responsible for
upholding, since the compiler can't check it) is the standard discipline
around `unsafe` in any serious Rust codebase.

### 3.7 Zeroing Secrets from Memory

A private key sitting in ordinary heap memory doesn't vanish the instant
it's logically "done" — the bytes stay in RAM (and potentially get copied
to swap, or appear in a crash dump) until something else overwrites that
memory region. `src/config.rs` wraps the WireGuard private key in
`Zeroizing<[u8; 32]>` specifically to close that window:

```rust
/// `Zeroizing<T>` implements `Drop` by overwriting the wrapped bytes with zeros
/// before the memory is freed. Without it, the private key bytes might remain
/// readable in freed heap memory until the allocator reuses that region
```

This combines two ideas from earlier sections: it's another `Drop`-based
RAII guarantee (§3.2), applied specifically to defend against a real
security threat model (a crash dump or a swap file being read by someone
who shouldn't have access to it).

---

## 4. Privilege Management: Doing Dangerous Things Safely

Creating a TUN device and rewriting the routing table are inherently
privileged operations — an unprivileged process can't touch them, for
obvious reasons (imagine any random program being able to reroute your
entire internet traffic). RustVPN needs *some* elevated privilege, but its
`src/privilege.rs` module goes out of its way to grant the absolute minimum.

### 4.1 Linux Capabilities vs. Root

Traditionally, "elevated privilege on Linux" meant "run as root" (UID 0),
which grants *every* privileged operation the kernel supports — far more
than a VPN client needs. Modern Linux instead offers **capabilities**: root's
power split into dozens of independent, individually grantable pieces.
RustVPN only ever needs one: `CAP_NET_ADMIN` (create network interfaces,
modify routing tables, install firewall rules).

`setup.sh` and `debian/postinst` both grant exactly that, and nothing more:

```bash
sudo setcap cap_net_admin+ep ./target/release/rust-vpn
```

This lets the compiled binary run as an ordinary user — important because
`main.rs` explicitly warns that running as full root "may cause GUI display
issues" (many desktop environments refuse GUI windows from a root process
for security reasons) — while still being able to create the TUN device.
This is the **principle of least privilege** in its most concrete, literal
form: grant exactly the one capability the code actually uses, not "root,"
which would also grant hundreds of capabilities it never touches.

### 4.2 Dropping Capabilities After Startup

`main.rs` doesn't stop at *starting* with minimal privilege — it actively
*reduces* its own privilege further, right after confirming it has what it
needs:

```rust
if let Err(e) = privilege::minimize_capabilities() {
    tracing::warn!("Capability minimization failed: {}", e);
}
// Load configuration from disk
let config = match VpnConfig::load() { ... };
```

`privilege::minimize_capabilities()` (`src/privilege.rs`) drops every
capability except `CAP_NET_ADMIN` from every capability set the kernel
tracks (`Effective`, `Permitted`, `Inheritable`, `Ambient`, and critically
`Bounding` — the "ceiling" that even a future `exec()`'d child process can't
exceed). The comment explains exactly why this runs *before* config
loading, server-list parsing, or the update-check HTTP request:

```
// ...so that a bug in any of those code paths cannot exercise
// capabilities like CAP_DAC_OVERRIDE, CAP_SYS_ADMIN, or CAP_KILL.
```

This is **defense in depth**: even if a parsing bug in the TOML config
loader or a malicious response from the (HTTPS) update-check server were
somehow exploited into arbitrary code execution, the exploited code would
run *without* any of root's other powers — it couldn't read arbitrary
files, kill arbitrary processes, or load a kernel module, because those
capabilities are already gone by the time that code runs. Minimizing your
attack surface *after* startup, not just *before* it, is the more advanced
half of this lesson — most beginner security advice stops at "check
privileges once at the door."

---

## 5. The Packet Loop: RustVPN's Steady-State Heart

`src/core/packet_loop.rs`'s `run_packet_loop` is the function that runs, in
a tight loop, for the entire duration of an active VPN connection. It's
worth reading closely because it demonstrates several performance and
concurrency lessons at once, on real, live network traffic.

### 5.1 The Core `select!` Loop

```rust
loop {
    tokio::select! {
        _ = stop_rx.changed() => { /* shutdown */ }
        Some(packet) = tun_rx.recv() => { /* TUN -> encrypt -> UDP */ }
        result = udp.recv(&mut udp_buf) => { /* UDP -> decrypt -> TUN */ }
        _ = keepalive_timer.tick() => { /* send empty encapsulated packet */ }
    }
}
```

`tokio::select!` waits on *multiple* async operations simultaneously and
runs whichever one completes first — this is what lets one task handle
"outgoing packet arrived," "incoming packet arrived," "time to send a
keepalive," and "shutdown requested" all in a single loop, without needing
four separate threads polling each other. This pattern — one event loop,
several event sources, react to whichever fires — is the async equivalent
of a Unix `select()`/`epoll()` loop, and it's the standard shape for any
program (game engines, servers, GUI toolkits) that must respond to several
independent input streams at once.

### 5.2 Bridging a Blocking Device into an Async World

A TUN device's file descriptor is a classic **blocking** OS resource — a
`read()` call on it blocks the calling OS thread until a packet arrives,
which is fundamentally incompatible with Tokio's model where a task must
never block the thread it's running on (doing so would freeze every other
task sharing that thread). The fix is `tokio::task::spawn_blocking`, which
hands the blocking work to a dedicated thread pool reserved for exactly
this purpose:

```rust
tokio::task::spawn_blocking(move || {
    ...
    loop {
        match file.read(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                if tun_tx.blocking_send(buf).is_err() { break; }
                ...
            }
```

That blocking thread hands each packet it reads to the async world through
an `mpsc` channel (`tun_tx`/`tun_rx`), which is itself safe to use from a
blocking context (`.blocking_send`) or an async one (`.recv().await`). This
"one blocking thread pumps data into a channel that async code drains" is
the standard pattern for wrapping *any* blocking API (a slow disk read, a
legacy C library, a synchronous database driver) so it can coexist with an
async runtime without starving it.

### 5.3 Buffer Reuse: Avoiding Per-Packet Allocation

The hot path reuses fixed-size buffers across iterations instead of
allocating a fresh `Vec` for every single packet:

```rust
// Reused encrypt/decrypt scratch buffers, hoisted out of the hot loop so no
// per-packet Vec is allocated+zeroed.
let mut encrypted = vec![0u8; TUN_MTU + WIREGUARD_OVERHEAD];
let mut decrypted = vec![0u8; TUN_MTU + WIREGUARD_OVERHEAD];
```

And on the TUN-reading side, a small **free-list** (`recycle_tx`/
`recycle_rx`) lets the async loop hand a used buffer *back* to the blocking
reader thread once it's done with it, instead of the reader allocating a
brand-new `Vec` for every packet:

```rust
// Buffer free-list: the async loop returns each processed TUN buffer here so
// the blocking reader reuses it instead of `buf[..n].to_vec()`-copying into
// a fresh Vec on every outbound packet.
```

On a VPN tunnel carrying real traffic, this loop can run thousands of times
per second. Allocating and freeing a new heap buffer every single iteration
would add measurable latency and CPU overhead (and GC-like allocator
pressure) purely from memory-management churn — work that has nothing to
do with the actual job (encrypting a packet). **Hoisting allocations out of
a hot loop and reusing buffers** is one of the most broadly applicable
performance techniques in systems programming, in any language with manual
or semi-manual memory management.

### 5.4 Interception Before Encryption

Notice where the DNS check happens in the TUN-read arm — *before* the
packet ever reaches `tunnel.lock().encapsulate(...)`:

```rust
if let Some(filter) = dns_filter.as_ref() {
    if let Some(reply) = try_block_dns_query(&packet, filter) {
        if let Err(e) = tun_writer.write_all(&reply) { ... }
        let _ = recycle_tx.send(packet);
        continue;
    }
}
```

A blocked DNS query never gets encrypted or sent to the VPN server at all —
it's short-circuited entirely, with a synthetic reply written straight back
to the TUN device. This ordering matters: filtering has to happen on the
*plaintext* packet, because once a packet is encrypted, RustVPN itself has
no way to know what's inside it (which is, after all, the entire point of
encryption).

---

## 6. Full Connection Lifecycle, Start to Finish

### Startup (`main()`, `src/main.rs`)

1. `tracing_subscriber::fmt::init()` sets up structured logging.
2. `privilege::capture_invoking_user()` snapshots `SUDO_UID`/`SUDO_GID`
   before anything can tamper with the environment.
3. `check_privileges()` confirms root or `CAP_NET_ADMIN`; exits with a
   helpful message pointing at `setup.sh` if neither is present.
4. `privilege::minimize_capabilities()` drops every capability except
   `CAP_NET_ADMIN` (§4.2) — a hardening step, not a functional requirement.
5. `VpnConfig::load()` reads `~/.config/rustvpn/config.toml`, falling back
   to secure defaults (kill switch **on**, auto-reconnect **on**, DNS
   filtering **on**) if the file is missing or unreadable.
6. `VpnApp::run()` hands control to the Iced GUI event loop.

### `VpnController::new()` (`src/core/controller.rs`)

Spawns the dedicated `vpn-core` OS thread with its own Tokio runtime
(§3.5), then `run_worker` loads (or generates, via
`get_or_create_private_key()`) the client's WireGuard private key, resolves
the configured TUN address, and — only if the user has DNS filtering
enabled — builds the `DnsFilter` blocklist once, up front.

### User clicks Connect → `VpnCommand::Connect`

1. Any previous session is torn down first (stop signal + `platform.cleanup()`)
   so rapid reconnects can't leak a stale TUN device.
2. `server_endpoint` is parsed to a `SocketAddr`; its IP is remembered as
   `last_server_ip` for the kill switch's allow-rule.
3. **If kill-switch protection is on, it is enabled here, before any
   tunnel traffic can flow** — and a failure here aborts the connect
   attempt entirely (fail-closed, §2.6).
4. `Platform::new()` verifies `iproute2` is present; `platform.create_tun()`
   creates `tun0`, assigns its IP/netmask, sets MTU 1420, and installs the
   routing changes from §2.2.
5. A `TunnelConfig` is built (private key, decoded server public key,
   `allowed_ips: [(0.0.0.0, 0)]` — i.e. full-tunnel mode routing *all*
   IPv4 traffic) and `Tunnel::connect()` performs the WireGuard Noise
   handshake via `boringtun::noise::Tunn::new` (§2.8).
6. On handshake failure: `reconnect_manager.record_failure()` doubles the
   backoff, and — if auto-reconnect is on — a retry is scheduled after
   that delay by re-sending a `Connect` command on the same channel.
7. On success: `Tunnel` is wrapped in `Arc<Mutex<_>>`,
   `run_packet_loop` is `tokio::spawn`ed (§5), and `VpnEvent::StateChanged
   (Connected)` is sent to the GUI.

### Steady state

`run_packet_loop` runs the `select!` loop from §5: encrypting/forwarding
outbound packets (with DNS interception first), decrypting/delivering
inbound ones, and sending a keepalive every 25 seconds — indefinitely,
until told to stop or it hits a fatal I/O error.

### Unexpected drop

If the packet loop exits for any reason other than a clean shutdown signal,
and auto-reconnect is enabled, the GUI is told `Reconnecting`, and — after
`reconnect_manager`'s current exponential backoff delay (1s → 2s → 4s → 8s
→ ... capped at 30s, `src/core/reconnect.rs`) — a fresh `Connect` command is
re-enqueued automatically, running the entire connect sequence above again.

### User clicks Disconnect, or app shuts down

The stop signal is sent to the packet loop, `platform.cleanup()` reverses
every route change from `create_tun`, the kill switch is explicitly
disabled (with the comment noting *why* this must always run, even on
crash-adjacent paths: "iptables/pf/netsh persist in the kernel after the
process exits... ALL traffic would be blocked until reboot" otherwise), and
`reconnect_manager.reset()` clears backoff history so the next manual
Connect starts fresh at 1 second.

---

## 7. Configuration and Deployment

### 7.1 TOML Configuration, and Why Defaults Favor Safety

`src/config.rs`'s `VpnConfig` is loaded from
`~/.config/rustvpn/config.toml` via `serde` + the `toml` crate — a
"declarative settings file, deserialized into a typed struct" pattern using
TOML (a format designed to be easy for *humans* to hand-edit, which is why
config files commonly use it instead of raw JSON). Its `Default` impl is
worth reading closely:

```rust
kill_switch_protection_enabled: true,
auto_reconnect_enabled: true,
dns_filtering_protection_enabled: true,
```

Security-relevant features default **on**; only `auto_connect_on_application_startup`
defaults off (since immediately connecting without asking is a surprising
thing for software to do on first run). This is **secure-by-default**
design: a user who never touches the settings screen still gets the safer
behavior, rather than having to discover and manually enable protection
features.

### 7.2 `setup.sh` vs. `debian/postinst`: Two Paths to the Same Capability

`setup.sh` is the "I built from source" path — it checks whether
`CAP_NET_ADMIN` is already set (via `getcap`), and if not, calls `sudo
setcap` and verifies it stuck. `debian/postinst` is the equivalent step run
*automatically* by `dpkg` the moment the `.deb` package is installed:

```bash
BINARY_PATH="/usr/bin/rust-vpn"
if setcap cap_net_admin+ep "$BINARY_PATH"; then
    echo "CAP_NET_ADMIN capability set successfully on $BINARY_PATH"
```

Both exist because a project might be installed either way (from a release
`.deb`, or built and run locally), and the capability step is not something
`cargo build` itself can do — it's a filesystem-extended-attribute
operation that has to happen on the *installed* binary, as a distinct
post-install action, every single time the binary is rebuilt or replaced.

### 7.3 Debian Packaging (`cargo deb`, `debian/control`)

`Cargo.toml`'s `[package.metadata.deb]` section, combined with
`debian/control`, `debian/postinst`, and `debian/rust-vpn.desktop`, lets a
single `cargo deb` command produce a real installable `.deb` package:

```toml
assets = [
    ["target/release/rust-vpn", "usr/bin/rust-vpn", "755"],
    ["README.md", "usr/share/doc/rust-vpn/README", "644"],
    ["debian/rust-vpn.desktop", "usr/share/applications/rust-vpn.desktop", "644"],
]
maintainer-scripts = "debian/"
```

This teaches the general shape of **OS-level packaging**: metadata (name,
maintainer, license, dependencies — `depends = "$auto"` tells `cargo-deb` to
scan the compiled binary's dynamic library dependencies and generate the
`.deb`'s dependency list automatically), a list of files to install and
where, and optional scripts (`postinst`) that run at install time to handle
anything a plain file copy can't (like setting a capability). Every major
Linux distribution's package format (`.deb`, `.rpm`, etc.) follows this
same "declare files + metadata + install-time hooks" shape.

### 7.4 The Release Profile: Optimizing for a Real Workload

```toml
[profile.release]
opt-level = 3       # Favor packet-loop throughput/latency over binary size
lto = true          # Link-time optimization
codegen-units = 1   # Better optimization
strip = true        # Strip symbols
```

`opt-level = 3` (maximum optimization, versus e.g. `"z"` for minimum binary
size) is a deliberate choice justified by the comment: this binary spends
its life running the packet loop's per-packet crypto/routing hot path, not
sitting idle on constrained embedded storage — so trading a larger binary
for faster steady-state execution is the right call. `lto` (link-time
optimization) lets the compiler optimize *across* crate boundaries instead
of just within each one, and `codegen-units = 1` sacrifices parallel
compilation for a more thoroughly optimized final binary. This is a good
worked example of "there's no universally correct release profile — the
right settings depend on what the binary actually spends its time doing,"
tied to real, cited reasoning rather than defaults copy-pasted from a
template.

---

## 8. Testing a Networking Project That Can't Always Touch the Network

`tests/` contains a dozen files, and their names hint at a deliberate split
in testing strategy: `tunnel_tests.rs`/`tunnel_module_tests.rs`,
`dns_filter_tests.rs`, `dns_intercept_tests.rs`, `killswitch_tests.rs`,
`reconnect_tests.rs`, `config_tests.rs`, `server_tests.rs`,
`update_tests.rs`, `controller_module_tests.rs`, and one that stands apart:
`e2e_test_plan.rs`.

The unit-style tests target pure, self-contained logic that doesn't need
root, a real network, or a real VPN server to exercise — `tunnel_module_tests.rs`'s
`test_generate_keypair_private_key_is_32_bytes` calls `generate_keypair()`
and asserts on the byte length; nothing there touches an actual socket.
`dns_intercept_tests.rs` can hand-construct a raw IPv4/UDP/DNS byte buffer
and feed it directly to `try_block_dns_query` without any real network
traffic at all — because that function is a pure `&[u8] -> Option<Vec<u8>>`
transformation. This is the general lesson: **isolate the logic that
doesn't strictly need a real environment, and test that logic in complete
isolation** — it's faster, more deterministic, and doesn't require root or
special CI permissions.

The things that genuinely *do* need a real environment — actually creating
a TUN device, actually installing iptables rules, actually completing a
WireGuard handshake against a real server — are exactly why `mockall` is a
`[dev-dependencies]` entry in `Cargo.toml` (for creating fake trait
implementations to swap in during tests) and why `resources/servers.toml`
uses RFC 5737 TEST-NET-1 addresses (`203.0.113.0/24`, reserved specifically
so that documentation and test configs never accidentally point at a real
machine) with syntactically-valid-but-cryptographically-meaningless public
keys — enough to exercise "does the code path run without crashing" without
requiring live VPN infrastructure. `e2e_test_plan.rs` documents (rather than
fully automates) the remaining scenarios that really do need `CAP_NET_ADMIN`
and a live server pair — a common, honest compromise for testing
privileged, environment-dependent systems software.

---

## 9. Ideas Worth Exploring Next

If this project sparked your curiosity, here are natural next questions to
chase, each rooted in something you just saw:

- **What would it take to add split-tunneling** (route only some apps or
  IP ranges through the VPN, not all traffic)? Trace how `allowed_ips` in
  `TunnelConfig` and the `0.0.0.0/1` + `128.0.0.0/1` routes in
  `platform/linux.rs` would need to change, and what happens to the
  "VPN server bypass route" trick from §2.2 if the ranges get narrower.
- **Why does `try_block_dns_query` reject DNS compression pointers in the
  question section entirely**, rather than trying to follow them safely?
  Research "DNS pointer loop denial of service" and think about what a
  malicious or malformed packet could do to a parser that *did* follow
  them.
- **What happens if two `Connect` commands race** — one from
  auto-reconnect's scheduled retry, one from the user manually clicking
  Connect again a moment later? Trace the "abort any running session
  first" block at the top of the `Connect` handler in `controller.rs` and
  think about whether it's actually race-free.
- **Why is the DNS-over-HTTPS resolver (`src/dns/resolver.rs`) built,
  tested, and fully functional, yet never called from the live packet
  path?** Read the reasoning in `docs/RoadMap.md` and consider: under what
  future feature (split-tunnel? a "DNS-only" mode?) would wiring it in
  actually add value over relying on the WireGuard tunnel alone?
- **What's the actual attack surface if `CAP_NET_ADMIN` alone is
  compromised** (say, through a bug in packet parsing)? `CAP_NET_ADMIN`
  can still create raw sockets and manipulate arbitrary interfaces —
  research what a process holding *only* that one capability can and
  can't do to a Linux machine, now that you've seen exactly which
  capability RustVPN keeps and which forty-some it deliberately drops.
