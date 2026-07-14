//! Update — GitHub release checking for application updates.
//!
//! # Role in RustVPN
//! This module checks for application updates by querying the GitHub releases API.
//! It compares the current version with the latest release and notifies users
//! via VpnEvent when a new version is available.
//!
//! # Main Contracts
//! - Input: Current version from CARGO_PKG_VERSION
//! - Output: UpdateAvailable events to GUI if newer version found
//! - Safety: HTTP requests use standard HTTPS; no authentication required
//!
//! # Platform Notes
//! Platform-agnostic using HTTP client (reqwest).
//! GitHub API endpoint must be configured before first release.
//! Runs as background task independent of VPN operations.
//!
//! # Non-goals
//! This module does not perform automatic updates (user notification only).
//! It does not download or install update packages.
//! It does not affect VPN tunnel operations.

use anyhow::{Context, Result};
use serde::Deserialize;

/// GitHub Releases API endpoint queried for update checks.
///
/// ## Format
///
/// `https://api.github.com/repos/<owner>/<repo>/releases/latest`
///
/// This project uses:
/// `"https://api.github.com/repos/Logan-0/VPN/releases/latest"`
///
/// ## What the API Returns
///
/// A single JSON object describing the newest non-pre-release:
/// ```json
/// { "tag_name": "v0.2.0", "name": "RustVPN 0.2.0", "html_url": "..." }
/// ```
/// `check_for_updates` strips the leading `v` from `tag_name` and then
/// compares the result against [`CARGO_PKG_VERSION`] using semver ordering.
///
/// ## Why a Constant?
///
/// A named constant is easier to locate with a project-wide search than a
/// URL buried in implementation code, and makes it obvious this value must
/// be changed before publishing.
pub const GITHUB_RELEASES_API_URL: &str =
    "https://api.github.com/repos/Logan-0/VPN/releases/latest";

/// GitHub API response for latest release
#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    html_url: String,
}

/// VPN Application Update Checker
///
/// Monitors GitHub releases for new versions of the VPN application.
/// Checks periodically and notifies users when updates are available.
///
/// ## Networking Relevance
///
/// The update checker:
/// - Makes HTTP requests to GitHub API
/// - Parses JSON responses with version information
/// - Compares versions to detect updates
/// - Does not affect VPN tunnel operations
///
/// This is a background task that runs independently of VPN networking.
pub struct UpdateChecker {
    /// The current version of the VPN application
    ///
    /// Stored as a string in semantic versioning format (e.g., "0.1.0").
    /// This is compared against the latest version from GitHub to determine
    /// if an update is available.
    current_application_version_string: String,
}

impl UpdateChecker {
    /// Creates a new update checker
    ///
    /// Initializes the checker with the current application version.
    /// This version will be compared against the latest release from GitHub.
    ///
    /// ## Networking Context
    ///
    /// The update checker is created during application initialization.
    /// It does not perform any network operations until `check_for_updates()`
    /// is called.
    ///
    /// # Arguments
    ///
    /// * `version` - Current application version string (e.g., "0.1.0")
    ///
    /// # Returns
    ///
    /// New UpdateChecker instance
    pub fn new(version: String) -> Self {
        Self {
            current_application_version_string: version,
        }
    }

    /// Returns the current application version
    ///
    /// Provides access to the version string for display or comparison purposes.
    ///
    /// # Returns
    ///
    /// Reference to the current version string
    pub fn current_version(&self) -> &str {
        &self.current_application_version_string
    }

    /// Checks for available updates from GitHub releases
    ///
    /// Makes an HTTP request to the GitHub API to fetch the latest release
    /// information, then compares it with the current version.
    ///
    /// ## Networking Details
    ///
    /// This method performs:
    /// 1. HTTP GET request to GitHub releases API
    /// 2. JSON response parsing
    /// 3. Version string comparison
    /// 4. Returns latest version if newer than current
    ///
    /// ### GitHub API Endpoint
    ///
    /// `https://api.github.com/repos/Logan-0/VPN/releases/latest`
    ///
    /// Response format (simplified):
    /// ```json
    /// {
    ///   "tag_name": "v0.2.0",
    ///   "name": "RustVPN 0.2.0",
    ///   "body": "Release notes...",
    ///   "html_url": "https://github.com/Logan-0/VPN/releases/tag/v0.2.0"
    /// }
    /// ```
    ///
    /// ### Version Comparison
    ///
    /// Uses semantic versioning comparison:
    /// - Extract version numbers (MAJOR.MINOR.PATCH)
    /// - Compare each component numerically
    /// - Return latest if any component is greater
    ///
    /// # Returns
    ///
    /// * `Ok(Some(version))` - Latest version string if update available
    /// * `Ok(None)` - No update available
    /// * `Err(_)` - Network error or API failure
    pub async fn check_for_updates(&self) -> Result<Option<String>> {
        let api_url = GITHUB_RELEASES_API_URL;

        // reqwest::Client::new() has no default timeout, so an unresponsive
        // GitHub API would otherwise hang this call indefinitely.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("failed to build update-check HTTP client")?;
        let response = client
            .get(api_url)
            .header("User-Agent", "RustVPN")
            .send()
            .await?;

        // Check the status before parsing so a rate-limit (403) or outage
        // (5xx) response surfaces as a clear "GitHub API returned <status>"
        // error instead of a misleading "failed to parse JSON" one.
        let response = response
            .error_for_status()
            .context("GitHub releases API returned an error status")?;

        // Parse JSON response
        let release: GitHubRelease = response.json().await?;

        // Extract version from tag_name (remove 'v' prefix if present)
        let latest_version = release
            .tag_name
            .strip_prefix('v')
            .unwrap_or(&release.tag_name);

        // Compare versions
        if Self::is_newer_version(&self.current_application_version_string, latest_version) {
            tracing::info!(
                "New version available: {} (current: {})",
                latest_version,
                self.current_application_version_string
            );
            Ok(Some(latest_version.to_string()))
        } else {
            tracing::debug!(
                "No update available (current: {}, latest: {})",
                self.current_application_version_string,
                latest_version
            );
            Ok(None)
        }
    }

    /// Compares two version strings to determine if version_b is newer than version_a
    /// Supports semantic versioning with optional additional components
    pub fn is_newer_version(version_a: &str, version_b: &str) -> bool {
        let parts_a = parse_version(version_a);
        let parts_b = parse_version(version_b);

        // Compare each component
        for (a, b) in parts_a.iter().zip(parts_b.iter()) {
            if b > a {
                return true;
            } else if b < a {
                return false;
            }
        }

        // If all compared components are equal, the longer version is newer
        parts_b.len() > parts_a.len()
    }
}

// Parses a version string into numeric components
fn parse_version(version: &str) -> Vec<u64> {
    version.split('.').filter_map(|s| s.parse().ok()).collect()
}
