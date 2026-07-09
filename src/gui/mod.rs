//! GUI — Cross-platform VPN interface using Iced framework.
//!
//! # Role in RustVPN
//! This module provides the graphical user interface using the Iced framework.
//! It follows the Elm architecture (Model-View-Update) to manage application
//! state, user interactions, and rendering. The GUI communicates with the
//! VPN core via VpnController for commands and receives events via subscriptions.
//!
//! # Main Contracts
//! - Input: User actions (connect, disconnect, settings changes)
//! - Output: VpnCommand messages to controller, GUI state updates
//! - Safety: No direct network operations; all VPN work delegated to core
//!
//! # Platform Notes
//! The Iced framework itself renders on Linux, macOS, and Windows, but the VPN
//! core it drives (`core::killswitch`, `platform`) is Linux-only today (see
//! `lib.rs`'s crate-level Platform Notes) — this GUI is not currently usable
//! end-to-end on macOS/Windows even though the widget toolkit would build there.
//! Pure Rust implementation with no C bindings or FFI.
//!
//! # Non-goals
//! This module does not perform VPN operations (delegated to controller).
//! It does not implement networking (delegated to core modules).
//! It does not manage system-level resources (delegated to platform module).

pub mod app;
