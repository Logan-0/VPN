# Testing Strategy Execution Spec — RustVPN

This document is the **execution instance** of the root [`TestingStrategySpec.md`](../../TestingStrategySpec.md) for RustVPN.

**Baseline (measured 2026-07-09):** 13 files under `tests/` (12 pre-existing + `killswitch_tests.rs` added this pass), ~161 test functions, 4 marked `#[ignore]` (root/network-dependent). No CI config exists anywhere in the repo (no `.github/`). No coverage tool configured. `mockall` is a declared dev-dependency but currently unused anywhere in `src/`/`tests/`.

---

## Crown jewel: `killswitch.rs` + `privilege.rs` + `dns/filter.rs`/`dns/intercept.rs`

For a VPN, the kill switch and DNS filtering are the entire safety value proposition — a regression here is a silent traffic/DNS leak, the worst possible failure class.

### `src/core/killswitch.rs` — was 0% covered, now minimally covered

No test exercised `KillSwitch::enable()`, `disable()`, `is_enabled()`, or the Drop-based cleanup before this pass. `tests/e2e_test_plan.rs`'s own test matrix lists "Kill switch blocks traffic on drop" and "Kill switch allows VPN traffic" as planned rows with **no corresponding `#[test]` function anywhere** — not even an `#[ignore]` stub.

**Added this pass:** `tests/killswitch_tests.rs` — two hermetic tests (`new_kill_switch_starts_disabled`, `kill_switch_state_equality_is_structural`) covering what's safely testable without root or a real firewall.

**Still not covered (Priority 0, biggest remaining gap):** `enable_linux`/`disable_linux`'s actual iptables rule construction and — critically — the ordering invariant behind the P0 fail-open bug fixed in `ErrorHandlingExecutionSpec.md` (a partial rule-application failure must never leave traffic unblocked). This can't be tested hermetically without either running as root against a real/namespaced network stack, or refactoring `KillSwitch` to take an injectable command-runner trait so `enable_linux`/`disable_linux`'s `Command::new("iptables")` calls go through a mockable seam.

**Recommendation, not attempted this pass:** the `mockall` dev-dependency already in `Cargo.toml` is exactly the right tool for that seam — a `CommandRunner` trait (`fn run(&self, program: &str, args: &[&str]) -> io::Result<Output>`) that `KillSwitch` holds, injected via constructor, with a `#[derive(mockall::Automock)]` for tests. This is deliberately **not** attempted in this audit pass: refactoring the most safety-critical file in the project without the ability to test the refactor against a real system is exactly the kind of change that needs focused, dedicated review rather than being rushed inside a broad multi-project sweep (see `OptimizationPlaybookSpec.md`'s "What NOT to Mechanize"). Flagged as the top priority for a follow-up session.

### `src/privilege.rs` — 0% covered

No test file references `privilege.rs`. `capture_invoking_user()` is a pure function of `SUDO_UID`/`SUDO_GID` env vars — trivially unit-testable hermetically (`std::env::set_var` in a test, restore after) — and isn't tested.

**Recommendation:** add `tests/privilege_tests.rs` covering `capture_invoking_user()` with `SUDO_UID`/`SUDO_GID` set, unset, and malformed.

### `src/platform/linux.rs` — effectively 0% covered

Only `tests/e2e_test_plan.rs::e2e_tun_device_create_and_cleanup` touches it, and it's `#[ignore]`d (requires root). `get_default_gateway()` is a pure parser of `ip route show default` output — testable without root, and untested.

**Recommendation:** extract the parsing logic (if not already separable from the `Command` invocation) and add pure-function tests for known `ip route` output formats.

### `dns/filter.rs` / `dns/intercept.rs` — reasonably well covered

13 tests (`dns_filter_tests.rs`) and 9 tests (`dns_intercept_tests.rs`) cover blocklist matching, parent-domain walk, QNAME parsing, and reply synthesis at the pure-function level. This part of the crown jewel is in good shape — no action needed.

---

## Other gaps

**Untested I/O boundary:** `update.rs::check_for_updates()` makes a real `reqwest` call with no mocked-boundary test — `tests/update_tests.rs` (18 tests) only exercises the pure `is_newer_version`/`parse_version` logic. Stand up a `wiremock`/`mockito` server (or an injectable base URL) to assert 200/404/500/timeout responses each behave correctly, especially now that `error_for_status()` + a timeout were added (`ErrorHandlingExecutionSpec.md`) — those specifically deserve a test.

**No CI pipeline:** `docs/RoadMap.md` states the automated suite "is the release gate for changes" but nothing enforces that — only a human running `cargo test` locally catches a regression. Add a GitHub Actions workflow: `cargo fmt --check`, `cargo clippy`, `cargo test` (non-`#[ignore]` subset), `cargo build --release`.

**No coverage visibility:** wire up `cargo llvm-cov`; the killswitch/privilege 0%-coverage gap above would have been immediately visible in a coverage report instead of only discoverable by manual file inventory.

**What's already good:** `reconnect_module_tests.rs`/`reconnect_tests.rs` (26 tests) thoroughly test the exponential-backoff state machine deterministically. `controller_module_tests.rs` (20 tests) exercises `VpnController`'s command/event plumbing including a fail-closed bad-endpoint path — though it only asserts `SetKillSwitch` "does not panic," not that kill-switch state is actually correct, which is a weak assertion for the most safety-critical toggle in the app (worth strengthening once the `CommandRunner` mock seam above exists).

---

## Recommended next steps (in order)

1. Refactor `KillSwitch` to take an injectable `CommandRunner` (using the already-present `mockall` dependency), then write real `enable_linux`/`disable_linux` tests covering the P0 ordering-invariant fix. **Top priority — dedicated session, not a quick pass.**
2. Add `tests/privilege_tests.rs` for `capture_invoking_user()` (cheap, hermetic).
3. Add mocked-boundary tests for `update.rs::check_for_updates()`, especially the new timeout/status-check paths.
4. Stand up CI (fmt + clippy + hermetic tests + build).
5. Wire up `cargo llvm-cov`, set a floor, and specifically watch the killswitch/privilege modules climb from 0%.
