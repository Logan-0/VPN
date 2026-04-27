//! # VPN Update Checker Module
//!
//! This module checks for application updates from GitHub releases.
//! It notifies users when a new version is available for download.
//!
//! ## Networking Concepts
//!
/// The update checker uses HTTP to:
/// 1. Fetch GitHub releases API
/// 2. Parse JSON response with version information
/// 3. Compare current version with latest release
/// 4. Notify user if newer version is available
///
/// ### HTTP Requests
///
/// The update checker makes HTTP GET requests to:
/// - GitHub API: `https://api.github.com/repos/owner/repo/releases/latest`
/// 
/// This is a standard REST API call that returns JSON data about the
/// latest release including version number, release notes, and download URLs.
///
/// ### Version Comparison
///
/// Versions are compared using semantic versioning (SemVer):
/// - Format: MAJOR.MINOR.PATCH (e.g., 0.1.0)
/// - MAJOR: Incompatible API changes
/// - MINOR: Backwards-compatible functionality
/// - PATCH: Backwards-compatible bug fixes
///
/// Example comparison:
/// - 0.1.0 < 0.2.0 (newer minor version)
/// - 0.1.0 < 0.1.1 (newer patch version)
/// - 1.0.0 > 0.9.9 (newer major version)

use anyhow::Result;
use serde::Deserialize;

/// GitHub Releases API endpoint queried for update checks.
///
/// ## Format
///
/// `https://api.github.com/repos/<owner>/<repo>/releases/latest`
///
/// Replace `owner/repo` with the actual GitHub user and repository name
/// before the first public release. For example, if the project lives at
/// `https://github.com/acme/rustvpn`, set this to:
/// `"https://api.github.com/repos/acme/rustvpn/releases/latest"`
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
///
/// TODO: replace `owner/repo` with the real repository path before release.
pub const GITHUB_RELEASES_API_URL: &str =
    "https://api.github.com/repos/owner/repo/releases/latest";

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
    /// `https://api.github.com/repos/owner/repo/releases/latest`
    /// 
    /// Response format (simplified):
    /// ```json
    /// {
    ///   "tag_name": "v0.2.0",
    ///   "name": "RustVPN 0.2.0",
    ///   "body": "Release notes...",
    ///   "html_url": "https://github.com/owner/repo/releases/tag/v0.2.0"
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
        
        // Make HTTP GET request
        let client = reqwest::Client::new();
        let response = client
            .get(api_url)
            .header("User-Agent", "RustVPN")
            .send()
            .await?;
        
        // Parse JSON response
        let release: GitHubRelease = response.json().await?;
        
        // Extract version from tag_name (remove 'v' prefix if present)
        let latest_version = release.tag_name.strip_prefix('v').unwrap_or(&release.tag_name);
        
        // Compare versions
        if Self::is_newer_version(&self.current_application_version_string, latest_version) {
            tracing::info!("New version available: {} (current: {})", latest_version, self.current_application_version_string);
            Ok(Some(latest_version.to_string()))
        } else {
            tracing::debug!("No update available (current: {}, latest: {})", self.current_application_version_string, latest_version);
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
    version
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect()
}
