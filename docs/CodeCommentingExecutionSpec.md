# Code Commenting Execution Spec - RustVPN

This document is an **execution spec** for another model (or maintainer) to add comments directly in code.

This is **not** a general educational overview.
This is the operational standard for producing complete, consistent in-code comments across:

- every Rust source file in `src/`,
- every important method/function,
- every test file and test case.

---

## Objective

Annotate the repository so a student can open any file and understand:

1. what each file does,
2. what each important method does,
3. why each test exists,
4. how each piece fits into the VPN architecture and Rust language features.

The result should be **in code comments**, not only external markdown.

---

## Hard requirements

1. Do not change runtime behavior.
2. Do not rename symbols for style-only reasons.
3. Do not add comments that merely restate code syntax.
4. Prefer concise comments, but do not skip critical context.
5. Every edited file must compile exactly as before.
6. Keep comments accurate to current behavior (no wishful comments).
7. Use ASCII unless file already uses Unicode.

---

## Scope of commenting

### A) File-level comments (required)

Every `src/**/*.rs` file must have top-level module docs (`//!`) that explain:

- subsystem role (core, dns, gui, platform, tunnel),
- architectural position (VPN control plane, data plane, platform abstraction),
- key input/output contract,
- safety constraints (privilege requirements, firewall rules, crypto operations),
- non-goals (what this module intentionally does not do),
- platform-specific notes (if using `#[cfg(target_os = "...")]`).

Every `tests/**/*.rs` file must have a top-of-file description:

- what behavior family is tested,
- what is mocked vs real,
- why this test file matters for safety/regression prevention.

### B) Method/function comments (required where meaningful)

Add or improve `///` docs for:

- all `pub` functions/methods/types,
- VPN control functions (connect, disconnect, reconnect),
- kill switch activation/deactivation,
- DNS filtering and interception logic,
- TUN device creation and configuration,
- firewall rule installation and removal,
- packet processing loop logic,
- GUI state management and event handlers,
- platform-specific operations (Linux iptables, macOS pf, Windows firewall).

### C) Inline comments (selective)

Inline comments are required for:

- non-obvious network operations and socket configuration,
- firewall rule syntax and their security implications,
- TUN device configuration parameters,
- cryptographic handshake steps and key derivation,
- packet parsing and routing logic,
- platform-specific system calls and their error handling,
- privilege escalation and capability checks,
- cross-platform conditional compilation blocks.

Inline comments should be avoided for trivial operations (`let x = ...`).

### D) Test-level comments (required)

Every test should include a concise "why" explanation directly above it.

Each test comment should answer:

- what behavior contract is pinned,
- what regression this prevents,
- why this case is distinct from neighboring tests.

---

## Required comment content model

For each significant function, comments should cover these fields when applicable:

1. **Purpose**: what this function is for.
2. **Inputs**: key parameters and assumptions.
3. **Outputs**: return value meaning.
4. **Failure modes**: what errors can happen.
5. **Side effects**: system calls, network operations, firewall changes, state mutation.
6. **Safety/security**: privilege requirements, crypto safety, leak prevention, path validation.
7. **Rust concept callout** (if educationally useful): ownership, borrowing, `Result`, async, unsafe blocks, platform-specific cfg.

Do not force all fields if irrelevant, but cover meaningful ones.

---

## Style templates

### File template (`//!`)

```rust
//! <Module> — <one-line role>.
//!
//! # Role in RustVPN
//! <How this module fits into the VPN architecture>
//!
//! # Main Contracts
//! - Input: <...>
//! - Output: <...>
//! - Safety: <...>
//!
//! # Platform Notes
//! <Any platform-specific behavior or requirements>
//!
//! # Non-goals
//! <What this module intentionally does not do>
```

### Function template (`///`)

```rust
/// <One-line summary>
///
/// <Short conceptual explanation in student-friendly language.>
///
/// # Arguments
/// - `arg`: <meaning and constraints>
///
/// # Returns
/// <Meaning of Ok/Err or state changes>
///
/// # Why this matters
/// <What security/VPN behavior this protects>
```

### Test template

```rust
/// <Behavior contract under test>.
/// Prevents regression where <failure mode>.
#[test]
fn ...() { ... }
```

---

## Execution workflow (for another model)

Follow this order:

1. **Inventory**
   - Enumerate all `src/**/*.rs` and `tests/**/*.rs` files.
   - Build a coverage tracker table (see below).

2. **Comment pass by subsystem**
   - `src/config.rs`, `src/server.rs` first.
   - Then `src/core/controller.rs`, `src/core/killswitch.rs`, `src/core/reconnect.rs`.
   - Then `src/core/packet_loop.rs`, `src/core/tunnel.rs`.
   - Then `src/dns/` module.
   - Then `src/gui/` module.
   - Then `src/platform/` (linux.rs, macos.rs, windows.rs).
   - Then `src/privilege.rs`, `src/update.rs`.
   - Then `tests/` files.

3. **Safety-critical verification pass**
   - Re-check firewall rule logic and cleanup.
   - Ensure TUN device cleanup on error paths.
   - Verify privilege checks are documented.
   - Ensure crypto operations are properly explained.
   - Verify kill switch activation/deactivation is clear.
   - Ensure comments do not imply behavior that does not exist.

4. **Compilation + tests**
   - Run targeted tests per touched area.
   - Run broad suite once at end.

5. **Coverage closeout**
   - Mark each file as done in tracker.
   - Record any intentionally skipped trivial private methods with reason.

---

## Coverage tracker format

Use this table while executing:

| File | File docs | Public API docs | Complex private docs | Test docs | Status |
|---|---|---|---|---|---|
| `src/config.rs` | yes/no | yes/no | yes/no | n/a | todo/in_progress/done |
| `src/core/controller.rs` | yes/no | yes/no | yes/no | n/a | todo/in_progress/done |
| `src/core/killswitch.rs` | yes/no | yes/no | yes/no | n/a | todo/in_progress/done |
| `tests/` | yes/no | n/a | n/a | yes/no | todo/in_progress/done |

A file is only "done" when all applicable columns are complete.

---

## Quality gates (must pass)

### Gate 1: Accuracy

- Comments match current implementation exactly.
- No stale references to removed architecture.
- Platform-specific claims are accurate.

### Gate 2: Educational value

- A younger Rust learner can understand *why* each module/function exists.
- Rust-specific concepts are explained where they matter.
- VPN/networking concepts are clearly explained.
- Cross-platform patterns are documented.

### Gate 3: Signal-to-noise

- No redundant comments for obvious lines.
- High-value explanatory comments retained.

### Gate 4: Consistency

- Same tone/style across files.
- Similar function types documented similarly.
- Platform-specific code follows consistent documentation patterns.

### Gate 5: Verification

- Build/tests still pass after comment pass.

---

## Anti-patterns to avoid

1. "This increments a counter" for `x += 1` style comments.
2. Huge paragraphs in every function; keep concise.
3. Contradicting docs between file header and method docs.
4. Security claims not backed by implementation (especially firewall rules, crypto).
5. Repeating exact same comment boilerplate everywhere.
6. Commenting generated code or vendored dependencies.
7. Failing to document `unsafe` blocks and their safety invariants.

---

## Priority map for this repository

When time is limited, comment in this order:

1. `src/core/controller.rs`
2. `src/core/killswitch.rs`
3. `src/core/packet_loop.rs`
4. `src/core/tunnel.rs`
5. `src/dns/intercept.rs`
6. `src/dns/filter.rs`
7. `src/platform/linux.rs`
8. `src/platform/macos.rs`
9. `src/platform/windows.rs`
10. `src/gui/app.rs`
11. `src/config.rs`
12. `src/privilege.rs`
13. remaining modules
14. all test files

Reason: these files define VPN control flow, security boundaries, platform-specific operations, and packet processing.

---

## Rust concept checklist (teach through comments)

Ensure comments include practical explanation of these language features where used:

- `Result<T, E>` and `?` propagation.
- Ownership vs borrowing (`String` vs `&str`, cloning choices).
- Async/await with Tokio runtime.
- `unsafe` blocks and their safety invariants.
- Platform-specific conditional compilation (`#[cfg(target_os = "...")]`).
- Trait-based abstraction for platform independence.
- Serde serialization/deserialization.
- Error handling with `anyhow` and `thiserror`.
- Zeroization of sensitive data (crypto keys).

Do not explain all concepts in every file; only where they appear.

---

## VPN and networking-specific concepts

Ensure comments explain these domain-specific concepts where used:

- WireGuard protocol handshake and key exchange.
- TUN/TAP device creation and configuration.
- Firewall rule syntax (iptables, pf, Windows Firewall).
- Kill switch activation and leak prevention.
- DNS filtering and interception.
- DNS-over-HTTPS (DoH) implementation.
- Packet routing and NAT traversal.
- Exponential backoff for reconnection.
- Privilege escalation and capability management (CAP_NET_ADMIN).
- Cross-platform system call differences.

---

## Platform-specific documentation requirements

For files in `src/platform/`, explicitly document:

- What system calls are made and why.
- Error handling for platform-specific failures.
- Privilege requirements and how they're enforced.
- Differences between Linux, macOS, and Windows implementations.
- Fallback behavior when platform features are unavailable.

---

## "Future additions" documentation rule

When adding a new feature in the future, update comments in this order:

1. Add/adjust file-level `//!` docs in new/changed modules.
2. Add `///` docs for new public interfaces and complex logic.
3. Document any new platform-specific code paths.
4. Add test-level why-comments for every new test.
5. Update this spec only if the documentation process itself changes.

No feature PR is complete unless these comment updates are included.

---

## Pull request checklist for commenting work

- [ ] Every touched source file has accurate file-level docs.
- [ ] Public APIs and complex private methods are documented.
- [ ] Safety-critical behavior (firewall, crypto, TUN devices) is explicitly explained.
- [ ] Platform-specific code has clear documentation of system calls and requirements.
- [ ] Every touched test has a clear contract explanation.
- [ ] Comments are concise and non-redundant.
- [ ] Build/tests pass.
- [ ] Coverage tracker is complete.

---

## Deliverable definition

This effort is complete when:

1. All project files in `src/` and `tests/` are covered by this standard.
2. Another student can navigate from module to module and understand the VPN from in-code comments alone.
3. A future model can continue documentation work using this spec without guessing style or scope.
