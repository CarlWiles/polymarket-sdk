//! Profiles API Client
//!
//! Provides access to Polymarket's Profiles API for user data and leaderboards.
//!
//! ## Example
//!
//! ```rust,ignore
//! use polymarket_sdk::profiles::{ProfilesClient, ProfilesConfig};
//!
//! let client = ProfilesClient::new(ProfilesConfig::default())?;
//!
//! // Get trader profile by address
//! let profile = client.get_profile("0x...").await?;
//!
//! // Get leaderboard
//! let leaders = client.get_leaderboard(None).await?;
//! ```

use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, instrument};

use crate::core::profiles_api_url;
use crate::core::{PolymarketError, Result};
use crate::types::{LeaderboardEntry, TraderProfile};

/// Profiles API configuration
#[derive(Debug, Clone)]
pub struct ProfilesConfig {
    /// Base URL for the Profiles API
    pub base_url: String,
    /// Request timeout
    pub timeout: Duration,
    /// User agent string
    pub user_agent: String,
}

impl Default for ProfilesConfig {
    fn default() -> Self {
        Self {
            // Use helper function to support env var override (POLYMARKET_PROFILES_URL)
            base_url: profiles_api_url(),
            timeout: Duration::from_secs(30),
            user_agent: "polymarket-sdk/0.1.0".to_string(),
        }
    }
}

impl ProfilesConfig {
    /// Create a new configuration builder
    #[must_use]
    pub fn builder() -> Self {
        Self::default()
    }

    /// Set base URL
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Set request timeout
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set user agent string
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Create config from environment variables.
    ///
    /// **Deprecated**: Use `ProfilesConfig::default()` instead.
    /// The default implementation already supports `POLYMARKET_PROFILES_URL` env var override.
    #[must_use]
    #[deprecated(
        since = "0.1.0",
        note = "Use ProfilesConfig::default() instead. URL override via POLYMARKET_PROFILES_URL env var is already supported."
    )]
    pub fn from_env() -> Self {
        Self::default()
    }
}

/// Profiles API client
#[derive(Debug, Clone)]
pub struct ProfilesClient {
    config: ProfilesConfig,
    client: Client,
}

impl ProfilesClient {
    /// Create a new Profiles client
    pub fn new(config: ProfilesConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .user_agent(&config.user_agent)
            .gzip(true)
            .build()
            .map_err(|e| PolymarketError::config(format!("Failed to create HTTP client: {e}")))?;

        Ok(Self { config, client })
    }

    /// Create client with default configuration
    pub fn with_defaults() -> Result<Self> {
        Self::new(ProfilesConfig::default())
    }

    /// Create client from environment variables.
    ///
    /// **Deprecated**: Use `ProfilesClient::with_defaults()` instead.
    #[deprecated(since = "0.1.0", note = "Use ProfilesClient::with_defaults() instead")]
    #[allow(deprecated)]
    pub fn from_env() -> Result<Self> {
        Self::new(ProfilesConfig::from_env())
    }

    /// Get trader profile by wallet address
    #[instrument(skip(self), level = "debug")]
    pub async fn get_profile(&self, address: &str) -> Result<Option<TraderProfile>> {
        let url = format!(
            "{}/profiles/{}",
            self.config.base_url,
            address.to_lowercase()
        );
        debug!(%url, "Fetching profile");

        let response = self.client.get(&url).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        self.handle_response::<TraderProfile>(response)
            .await
            .map(Some)
    }

    /// Get multiple profiles by addresses
    #[instrument(skip(self), level = "debug")]
    pub async fn get_profiles(&self, addresses: &[String]) -> Result<Vec<TraderProfile>> {
        if addresses.is_empty() {
            return Ok(Vec::new());
        }

        // Batch request with addresses as query parameter
        let addresses_param = addresses
            .iter()
            .map(|a| a.to_lowercase())
            .collect::<Vec<_>>()
            .join(",");

        let url = format!(
            "{}/profiles?addresses={}",
            self.config.base_url, addresses_param
        );
        debug!(%url, count = addresses.len(), "Fetching profiles batch");

        let response = self.client.get(&url).send().await?;
        self.handle_response::<Vec<TraderProfile>>(response).await
    }

    /// Search profiles by username or name
    #[instrument(skip(self), level = "debug")]
    pub async fn search_profiles(
        &self,
        query: &str,
        limit: Option<u32>,
    ) -> Result<Vec<TraderProfile>> {
        let mut url = format!(
            "{}/profiles/search?q={}",
            self.config.base_url,
            urlencoding::encode(query)
        );

        if let Some(limit) = limit {
            url.push_str(&format!("&limit={limit}"));
        }

        debug!(%url, "Searching profiles");

        let response = self.client.get(&url).send().await?;
        self.handle_response::<Vec<TraderProfile>>(response).await
    }

    /// Get leaderboard with optional time period
    #[instrument(skip(self), level = "debug")]
    pub async fn get_leaderboard(
        &self,
        params: Option<LeaderboardParams>,
    ) -> Result<Vec<LeaderboardEntry>> {
        let mut url = format!("{}/leaderboard", self.config.base_url);

        if let Some(params) = params {
            let mut query_parts = Vec::new();

            if let Some(period) = params.period {
                query_parts.push(format!("period={period}"));
            }
            if let Some(limit) = params.limit {
                query_parts.push(format!("limit={limit}"));
            }
            if let Some(offset) = params.offset {
                query_parts.push(format!("offset={offset}"));
            }

            if !query_parts.is_empty() {
                url.push('?');
                url.push_str(&query_parts.join("&"));
            }
        }

        debug!(%url, "Fetching leaderboard");

        let response = self.client.get(&url).send().await?;
        self.handle_response::<Vec<LeaderboardEntry>>(response)
            .await
    }

    /// Get top traders by volume
    #[instrument(skip(self), level = "debug")]
    pub async fn get_top_traders(&self, limit: Option<u32>) -> Result<Vec<TraderProfile>> {
        let mut url = format!("{}/traders/top", self.config.base_url);

        if let Some(limit) = limit {
            url.push_str(&format!("?limit={limit}"));
        }

        debug!(%url, "Fetching top traders");

        let response = self.client.get(&url).send().await?;
        self.handle_response::<Vec<TraderProfile>>(response).await
    }

    /// Get trader's trading history/positions
    #[instrument(skip(self), level = "debug")]
    pub async fn get_positions(&self, address: &str) -> Result<Vec<Position>> {
        let url = format!(
            "{}/profiles/{}/positions",
            self.config.base_url,
            address.to_lowercase()
        );
        debug!(%url, "Fetching positions");

        let response = self.client.get(&url).send().await?;
        self.handle_response::<Vec<Position>>(response).await
    }

    /// Handle API response
    async fn handle_response<T: for<'de> Deserialize<'de>>(
        &self,
        response: reqwest::Response,
    ) -> Result<T> {
        let status = response.status();

        if status.is_success() {
            let body = response.text().await?;
            serde_json::from_str(&body).map_err(|e| {
                PolymarketError::parse_with_source(format!("Failed to parse response: {e}"), e)
            })
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(PolymarketError::api(status.as_u16(), body))
        }
    }
}

/// Parameters for leaderboard queries
#[derive(Debug, Clone, Default)]
pub struct LeaderboardParams {
    /// Time period (daily, weekly, monthly, all-time)
    pub period: Option<String>,
    /// Maximum results to return
    pub limit: Option<u32>,
    /// Offset for pagination
    pub offset: Option<u32>,
}

impl LeaderboardParams {
    /// Create new parameters
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set time period
    #[must_use]
    pub fn with_period(mut self, period: impl Into<String>) -> Self {
        self.period = Some(period.into());
        self
    }

    /// Set limit
    #[must_use]
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set offset
    #[must_use]
    pub fn with_offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Daily leaderboard
    #[must_use]
    pub fn daily() -> Self {
        Self::new().with_period("daily")
    }

    /// Weekly leaderboard
    #[must_use]
    pub fn weekly() -> Self {
        Self::new().with_period("weekly")
    }

    /// Monthly leaderboard
    #[must_use]
    pub fn monthly() -> Self {
        Self::new().with_period("monthly")
    }

    /// All-time leaderboard
    #[must_use]
    pub fn all_time() -> Self {
        Self::new().with_period("all-time")
    }
}

/// Trader position information
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Position {
    /// Market condition ID
    pub condition_id: String,
    /// Token ID
    pub token_id: Option<String>,
    /// Position size
    pub size: f64,
    /// Average entry price
    pub avg_price: Option<f64>,
    /// Current value
    pub value: Option<f64>,
    /// Realized profit/loss
    pub realized_pnl: Option<f64>,
    /// Unrealized profit/loss
    pub unrealized_pnl: Option<f64>,
    /// Outcome (Yes/No)
    pub outcome: Option<String>,
    /// Market title
    pub title: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = ProfilesConfig::builder()
            .with_base_url("https://custom.example.com")
            .with_timeout(Duration::from_secs(60));

        assert_eq!(config.base_url, "https://custom.example.com");
        assert_eq!(config.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_leaderboard_params() {
        let params = LeaderboardParams::weekly().with_limit(100);
        assert_eq!(params.period, Some("weekly".to_string()));
        assert_eq!(params.limit, Some(100));
    }
}
