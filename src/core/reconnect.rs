//! # Auto-Reconnect Manager
//!
//! This module handles automatic reconnection when the VPN connection is lost.
//!
//! ## Why Auto-Reconnect is Important
//!
//! VPN connections can drop for many reasons:
//! - Network changes (WiFi to cellular, different WiFi network)
//! - Server maintenance or restarts
//! - Temporary internet outages
//! - NAT timeout on routers
//! - Firewall interference
//!
//! Without auto-reconnect, users would have to manually reconnect every time,
//! which is inconvenient and leaves gaps where traffic isn't protected.
//!
//! ## Exponential Backoff Strategy
//!
//! When reconnection fails, we don't want to hammer the server with constant
//! retry attempts. Instead, we use exponential backoff:
//!
//! ```text
//! Attempt 1: Wait 1 second   (INITIAL_BACKOFF)
//! Attempt 2: Wait 2 seconds  (1s × 2)
//! Attempt 3: Wait 4 seconds  (2s × 2)
//! Attempt 4: Wait 8 seconds  (4s × 2)
//! Attempt 5: Wait 16 seconds (8s × 2)
//! Attempt 6: Wait 30 seconds (16s × 2, capped at MAX_BACKOFF)
//! Attempt 7+: Wait 30 seconds (stays at MAX_BACKOFF)
//! ```
//!
//! This approach:
//! - Quickly recovers from brief outages (1-2 second retry)
//! - Reduces server load during extended outages
//! - Prevents battery drain from constant reconnection attempts
//! - Gives network time to stabilize
//!
//! ## Health Check Loop
//!
//! Even when connected, we periodically verify the connection is working:
//! - Runs every 30 seconds
//! - Can trigger reconnection if health check fails
//! - Helps detect "zombie" connections (connected but not working)
//!
//! ## Example Reconnection Flow
//!
//! ```text
//! [Connected] ──┐
//!               │
//!               ▼
//!         Connection Lost!
//!               │
//!               ▼
//!         [Reconnecting]
//!               │
//!               ├─► Attempt 1 (wait 1s) ──► Failed
//!               │                            │
//!               ├─◄──────────────────────────┘
//!               │
//!               ├─► Attempt 2 (wait 2s) ──► Failed
//!               │                            │
//!               ├─◄──────────────────────────┘
//!               │
//!               ├─► Attempt 3 (wait 4s) ──► Success!
//!               │                            │
//!               ▼                            ▼
//!         [Connected] ◄──────────────────────┘
//! ```

use anyhow::Result;
use std::time::Duration;
use tokio::time::{sleep, Instant};
use tracing::{debug, info, warn};

/// Initial backoff duration for first reconnection attempt
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Maximum backoff duration (prevents waiting too long)
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Multiplier for exponential backoff (doubles each time)
const BACKOFF_MULTIPLIER: u32 = 2;

/// How often to run health checks on active connections
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);


/// Reason for initiating a reconnection attempt.
///
/// This helps with logging and debugging connection issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconnectReason {
    /// Connection was lost unexpectedly (network change, timeout, etc.)
    ConnectionLost,
    
    /// Health check detected the connection isn't working
    HealthCheckFailed,
    
    /// Cannot reach the VPN server
    ServerUnreachable,
    
    /// User manually requested reconnection
    UserRequested,
}

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

    /// Waits for the appropriate backoff duration before attempting reconnection.
    ///
    /// On the first attempt, this returns immediately. On subsequent attempts,
    /// it waits for the current backoff duration (which increases exponentially).
    ///
    /// # Arguments
    /// * `reason` - Why we're reconnecting (for logging)
    ///
    /// # Example
    /// ```rust,ignore
    /// // First attempt - no wait
    /// manager.wait_before_reconnect(ReconnectReason::ConnectionLost).await;
    /// // Try to connect...
    /// manager.record_failure();
    ///
    /// // Second attempt - waits 1 second
    /// manager.wait_before_reconnect(ReconnectReason::ConnectionLost).await;
    /// // Try to connect...
    /// manager.record_failure();
    ///
    /// // Third attempt - waits 2 seconds
    /// manager.wait_before_reconnect(ReconnectReason::ConnectionLost).await;
    /// ```
    pub async fn wait_before_reconnect(&mut self, reason: ReconnectReason) {
        info!("Waiting before reconnect attempt (reason: {:?})", reason);
        
        if self.consecutive_failures > 0 {
            debug!(
                "Backing off for {:?} (attempt {})",
                self.current_backoff, self.consecutive_failures + 1
            );
            sleep(self.current_backoff).await;
        }
        
        self.last_connection_attempt = Some(Instant::now());
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
            Duration::from_secs(
                self.current_backoff.as_secs() * BACKOFF_MULTIPLIER as u64
            ),
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

/// Runs a periodic health check loop for an active VPN connection.
///
/// This function runs continuously in the background, checking the connection
/// health every 30 seconds. If a health check fails, it logs a warning (the
/// caller should monitor for these and trigger reconnection).
///
/// # How Health Checks Work
///
/// ```text
/// [Start] ──► Wait 30s ──► Run Check ──► Healthy? ──┐
///              ▲                           │        │
///              │                           │        │
///              └───────────────────────────┘        │
///                      (loop continues)             │
///                                                    │
///                                                    ▼
///                                              Not Healthy
///                                                    │
///                                                    ▼
///                                            Log Warning
///                                         (Caller triggers
///                                          reconnection)
/// ```
///
/// # Arguments
/// * `check_fn` - Async function that returns `true` if healthy, `false` if not
/// * `should_stop` - Watch channel to signal when to stop the loop
///
/// # Example
/// ```rust,ignore
/// let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
///
/// tokio::spawn(async move {
///     health_check_loop(
///         || async {
///             // Ping the server or check if packets are flowing
///             tunnel.is_connected()
///         },
///         stop_rx,
///     ).await;
/// });
///
/// // Later, to stop:
/// stop_tx.send(true)?;
/// ```
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn new_mgr() -> ReconnectManager {
        ReconnectManager::new().unwrap()
    }

    // ── Initial state ────────────────────────────────────────────────────────

    #[test]
    fn test_new_starts_with_zero_failures() {
        assert_eq!(new_mgr().get_consecutive_failures(), 0);
    }

    #[test]
    fn test_new_starts_with_one_second_backoff() {
        assert_eq!(new_mgr().get_current_backoff(), Duration::from_secs(1));
    }

    #[test]
    fn test_new_should_attempt_reconnect_immediately() {
        // No previous attempt recorded, so should be ready right away.
        assert!(new_mgr().should_attempt_reconnect());
    }

    #[test]
    fn test_new_has_no_last_success() {
        assert!(new_mgr().time_since_last_success().is_none());
    }

    // ── record_failure ───────────────────────────────────────────────────────

    #[test]
    fn test_record_failure_increments_count() {
        let mut mgr = new_mgr();
        mgr.record_failure();
        assert_eq!(mgr.get_consecutive_failures(), 1);
    }

    #[test]
    fn test_three_failures_counted() {
        let mut mgr = new_mgr();
        mgr.record_failure();
        mgr.record_failure();
        mgr.record_failure();
        assert_eq!(mgr.get_consecutive_failures(), 3);
    }

    #[test]
    fn test_one_failure_doubles_backoff() {
        let mut mgr = new_mgr();
        mgr.record_failure();
        assert_eq!(mgr.get_current_backoff(), Duration::from_secs(2));
    }

    #[test]
    fn test_two_failures_quadruple_backoff() {
        let mut mgr = new_mgr();
        mgr.record_failure();
        mgr.record_failure();
        assert_eq!(mgr.get_current_backoff(), Duration::from_secs(4));
    }

    #[test]
    fn test_backoff_caps_at_thirty_seconds() {
        let mut mgr = new_mgr();
        for _ in 0..20 {
            mgr.record_failure();
        }
        assert_eq!(mgr.get_current_backoff(), Duration::from_secs(30));
    }

    #[test]
    fn test_backoff_never_exceeds_thirty_seconds() {
        let mut mgr = new_mgr();
        for _ in 0..100 {
            mgr.record_failure();
        }
        assert!(mgr.get_current_backoff() <= Duration::from_secs(30));
    }

    // ── record_success ───────────────────────────────────────────────────────

    #[test]
    fn test_success_resets_failure_count_to_zero() {
        let mut mgr = new_mgr();
        mgr.record_failure();
        mgr.record_failure();
        mgr.record_success();
        assert_eq!(mgr.get_consecutive_failures(), 0);
    }

    #[test]
    fn test_success_resets_backoff_to_one_second() {
        let mut mgr = new_mgr();
        for _ in 0..5 {
            mgr.record_failure();
        }
        mgr.record_success();
        assert_eq!(mgr.get_current_backoff(), Duration::from_secs(1));
    }

    #[test]
    fn test_success_records_timestamp() {
        let mut mgr = new_mgr();
        mgr.record_success();
        assert!(mgr.time_since_last_success().is_some());
    }

    #[test]
    fn test_elapsed_since_success_is_small() {
        let mut mgr = new_mgr();
        mgr.record_success();
        let elapsed = mgr.time_since_last_success().unwrap();
        assert!(elapsed < Duration::from_secs(1));
    }

    // ── reset ────────────────────────────────────────────────────────────────

    #[test]
    fn test_reset_clears_failure_count() {
        let mut mgr = new_mgr();
        mgr.record_failure();
        mgr.reset();
        assert_eq!(mgr.get_consecutive_failures(), 0);
    }

    #[test]
    fn test_reset_restores_one_second_backoff() {
        let mut mgr = new_mgr();
        for _ in 0..5 {
            mgr.record_failure();
        }
        mgr.reset();
        assert_eq!(mgr.get_current_backoff(), Duration::from_secs(1));
    }

    #[test]
    fn test_reset_clears_attempt_timestamp_so_reconnect_is_immediate() {
        let mut mgr = new_mgr();
        mgr.record_failure();
        mgr.reset();
        // After reset there is no recorded attempt, so should be ready immediately.
        assert!(mgr.should_attempt_reconnect());
    }

    // ── Default ──────────────────────────────────────────────────────────────

    #[test]
    fn test_default_is_equivalent_to_new() {
        let a = new_mgr();
        let b = ReconnectManager::default();
        assert_eq!(a.get_consecutive_failures(), b.get_consecutive_failures());
        assert_eq!(a.get_current_backoff(), b.get_current_backoff());
    }
}

pub async fn health_check_loop<F, Fut>(
    mut check_fn: F,
    mut should_stop: tokio::sync::watch::Receiver<bool>,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    info!("Starting health check loop");
    
    loop {
        tokio::select! {
            _ = sleep(HEALTH_CHECK_INTERVAL) => {
                debug!("Running health check");
                
                let is_healthy = check_fn().await;
                
                if !is_healthy {
                    warn!("Health check failed");
                }
            }
            _ = should_stop.changed() => {
                if *should_stop.borrow() {
                    info!("Stopping health check loop");
                    break;
                }
            }
        }
    }
}
