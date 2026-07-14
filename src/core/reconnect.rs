//! Reconnect — Automatic VPN reconnection with exponential backoff.
//!
//! # Role in RustVPN
//! This module handles automatic reconnection when the VPN connection is lost.
//! It implements exponential backoff to avoid hammering the server with constant
//! retry attempts, and provides a health check loop to detect zombie connections.
//!
//! # Main Contracts
//! - Input: Connection success/failure events from packet loop
//! - Output: Reconnect timing and health check status
//! - Safety: Backoff capped at 30 seconds to prevent excessive retry attempts
//!
//! # Platform Notes
//! Platform-agnostic logic; health checks work on all platforms.
//! Reconnection timing uses tokio::time for async sleep operations.
//!
//! # Non-goals
//! This module does not perform actual reconnection (delegated to controller).
//! It does not implement network health checks (caller provides check function).
//! It does not handle user-initiated disconnects (controller calls reset()).

use anyhow::Result;
use std::time::Duration;
use tokio::time::Instant;
use tracing::{debug, info, warn};

/// Initial backoff duration for first reconnection attempt
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Maximum backoff duration (prevents waiting too long)
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Multiplier for exponential backoff (doubles each time)
const BACKOFF_MULTIPLIER: u32 = 2;

/// Manages automatic reconnection with exponential backoff.
///
/// Tracks connection attempts, failures, and timing to implement
/// intelligent reconnection logic.
pub struct ReconnectManager {
    /// Current backoff duration (increases with each failure)
    current_backoff: Duration,

    /// Number of consecutive failed connection attempts
    consecutive_failures: u32,

    /// When the last connection attempt was made
    last_connection_attempt: Option<Instant>,

    /// When the last successful connection was established
    last_successful_connection: Option<Instant>,
}

impl ReconnectManager {
    /// Creates a new reconnect manager with default settings.
    ///
    /// Starts with:
    /// - 1 second initial backoff
    /// - 0 failures
    /// - No connection attempts yet
    pub fn new() -> Result<Self> {
        Ok(Self {
            current_backoff: INITIAL_BACKOFF,
            consecutive_failures: 0,
            last_connection_attempt: None,
            last_successful_connection: None,
        })
    }

    /// Records a failed connection attempt.
    ///
    /// This:
    /// 1. Increments the failure counter
    /// 2. Doubles the backoff duration (up to MAX_BACKOFF)
    /// 3. Logs the failure
    ///
    /// Call this after each failed connection attempt.
    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;

        // Double the backoff, but cap at MAX_BACKOFF (30 seconds)
        self.current_backoff = std::cmp::min(
            Duration::from_secs(self.current_backoff.as_secs() * BACKOFF_MULTIPLIER as u64),
            MAX_BACKOFF,
        );

        warn!(
            "Connection attempt failed (failures: {}, next backoff: {:?})",
            self.consecutive_failures, self.current_backoff
        );
    }

    /// Records a successful connection.
    ///
    /// This:
    /// 1. Resets the failure counter to 0
    /// 2. Resets backoff to initial value (1 second)
    /// 3. Records the success timestamp
    /// 4. Logs success (especially if there were previous failures)
    ///
    /// Call this after successfully establishing a connection.
    pub fn record_success(&mut self) {
        if self.consecutive_failures > 0 {
            info!(
                "Connection successful after {} failed attempts",
                self.consecutive_failures
            );
        }

        // Reset everything back to initial state
        self.consecutive_failures = 0;
        self.current_backoff = INITIAL_BACKOFF;
        self.last_successful_connection = Some(Instant::now());
    }

    /// Checks if enough time has passed to attempt reconnection.
    ///
    /// Returns `true` if:
    /// - No previous attempt was made, OR
    /// - Enough time has passed since the last attempt (based on current backoff)
    ///
    /// # Returns
    /// * `true` - Ready to attempt reconnection
    /// * `false` - Still in backoff period, wait longer
    pub fn should_attempt_reconnect(&self) -> bool {
        if let Some(last_attempt) = self.last_connection_attempt {
            last_attempt.elapsed() >= self.current_backoff
        } else {
            true
        }
    }

    /// Returns the number of consecutive failed connection attempts.
    pub fn get_consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Returns the current backoff duration.
    pub fn get_current_backoff(&self) -> Duration {
        self.current_backoff
    }

    /// Resets the reconnect manager to initial state.
    ///
    /// This clears all failure history and backoff state.
    /// Useful when user manually disconnects or changes servers.
    pub fn reset(&mut self) {
        debug!("Resetting reconnect manager");
        self.consecutive_failures = 0;
        self.current_backoff = INITIAL_BACKOFF;
        self.last_connection_attempt = None;
    }

    /// Returns how long it's been since the last successful connection.
    ///
    /// # Returns
    /// * `Some(Duration)` - Time since last success
    /// * `None` - No successful connection has been made yet
    pub fn time_since_last_success(&self) -> Option<Duration> {
        self.last_successful_connection
            .map(|instant| instant.elapsed())
    }
}

impl Default for ReconnectManager {
    fn default() -> Self {
        Self::new().expect("Failed to create ReconnectManager")
    }
}
