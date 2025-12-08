//! Data API Client
//!
//! Provides access to Polymarket's Data API for trader profiles, positions,
//! trades, activity, and leaderboards.
//!
//! ## Example
//!
//! ```rust,ignore
//! use polymarket_sdk::data::{DataClient, DataConfig};
//!
//! let client = DataClient::new(DataConfig::default())?;
//!
//! // Get trader profile
//! let profile = client.get_trader_profile("0x...").await?;
//!
//! // Get biggest winners
//! let winners = client.get_biggest_winners(&BiggestWinnersQuery::default()).await?;
//! ```

use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, instrument};

use crate::core::{clob_api_url, data_api_url};
use crate::core::{PolymarketError, Result};
use crate::types::{
    BiggestWinner, BiggestWinnersQuery, ClosedPosition, DataApiActivity, DataApiPosition,
    DataApiTrade, DataApiTrader,
};

/// Data API configuration
#[derive(Debug, Clone)]
pub struct DataConfig {
    /// Base URL for the Data API
    pub base_url: String,
    /// CLOB API base URL
    pub clob_base_url: String,
    /// Request timeout
    pub timeout: Duration,
    /// User agent string
    pub user_agent: String,
}

impl Default for DataConfig {
    fn default() -> Self {
        Self {
            // Use helper functions to support env var overrides
            base_url: data_api_url(),
            clob_base_url: clob_api_url(),
            timeout: Duration::from_secs(30),
            user_agent: "polymarket-sdk/0.1.0".to_string(),
        }
    }
}

impl DataConfig {
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

    /// Set CLOB base URL
    #[must_use]
    pub fn with_clob_base_url(mut self, url: impl Into<String>) -> Self {
        self.clob_base_url = url.into();
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
    /// **Deprecated**: Use `DataConfig::default()` instead.
    /// The default implementation already supports env var overrides.
    #[must_use]
    #[deprecated(
        since = "0.1.0",
        note = "Use DataConfig::default() instead. URL overrides via \
                POLYMARKET_DATA_URL and POLYMARKET_CLOB_URL env vars are already supported."
    )]
    pub fn from_env() -> Self {
        Self::default()
    }
}

/// Data API client for trader data, positions, and leaderboards
#[derive(Debug, Clone)]
pub struct DataClient {
    config: DataConfig,
    client: Client,
}

impl DataClient {
    /// Create a new Data API client
    pub fn new(config: DataConfig) -> Result<Self> {
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
        Self::new(DataConfig::default())
    }

    /// Create client from environment variables.
    ///
    /// **Deprecated**: Use `DataClient::with_defaults()` instead.
    #[deprecated(since = "0.1.0", note = "Use DataClient::with_defaults() instead")]
    #[allow(deprecated)]
    pub fn from_env() -> Result<Self> {
        Self::new(DataConfig::from_env())
    }

    /// Get trader profile by wallet address
    #[instrument(skip(self), level = "debug")]
    pub async fn get_trader_profile(&self, address: &str) -> Result<DataApiTrader> {
        let url = format!("{}/profile/{}", self.config.base_url, address);
        debug!(%url, "Fetching trader profile");

        let response = self.client.get(&url).send().await?;
        self.handle_response::<DataApiTrader>(response).await
    }

    /// Get positions for a wallet address
    #[instrument(skip(self), level = "debug")]
    pub async fn get_positions(&self, address: &str) -> Result<Vec<DataApiPosition>> {
        let url = format!("{}/positions?user={}", self.config.base_url, address);
        debug!(%url, "Fetching positions");

        let response = self.client.get(&url).send().await?;
        self.handle_response::<Vec<DataApiPosition>>(response).await
    }

    /// Get trades for a wallet address
    #[instrument(skip(self), level = "debug")]
    pub async fn get_trades(&self, address: &str, limit: Option<u32>) -> Result<Vec<DataApiTrade>> {
        let limit = limit.unwrap_or(100);
        let url = format!(
            "{}/trades?user={}&limit={}",
            self.config.base_url, address, limit
        );
        debug!(%url, "Fetching trades");

        let response = self.client.get(&url).send().await?;
        self.handle_response::<Vec<DataApiTrade>>(response).await
    }

    /// Get user activity (trades, position changes)
    #[instrument(skip(self), level = "debug")]
    pub async fn get_user_activity(
        &self,
        address: &str,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<DataApiActivity>> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);
        let url = format!(
            "{}/activity?user={}&limit={}&offset={}",
            self.config.base_url, address, limit, offset
        );
        debug!(%url, "Fetching user activity");

        let response = self.client.get(&url).send().await?;
        self.handle_response::<Vec<DataApiActivity>>(response).await
    }

    /// Get closed positions for a user (for PnL calculation)
    #[instrument(skip(self), level = "debug")]
    pub async fn get_closed_positions(
        &self,
        address: &str,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<ClosedPosition>> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);
        let url = format!(
            "{}/closed-positions?user={}&limit={}&offset={}",
            self.config.base_url, address, limit, offset
        );
        debug!(%url, "Fetching closed positions");

        let response = self.client.get(&url).send().await?;
        self.handle_response::<Vec<ClosedPosition>>(response).await
    }

    /// Get biggest winners by category and time period
    #[instrument(skip(self), level = "debug")]
    pub async fn get_biggest_winners(
        &self,
        query: &BiggestWinnersQuery,
    ) -> Result<Vec<BiggestWinner>> {
        let url = format!(
            "{}/v1/biggest-winners?timePeriod={}&limit={}&offset={}&category={}",
            self.config.base_url, query.time_period, query.limit, query.offset, query.category
        );
        debug!(%url, "Fetching biggest winners");

        let response = self.client.get(&url).send().await?;
        self.handle_response::<Vec<BiggestWinner>>(response).await
    }

    /// Get top biggest winners with auto-pagination
    ///
    /// Fetches winners in batches of 100 until reaching total_limit
    #[instrument(skip(self), level = "debug")]
    pub async fn get_top_biggest_winners(
        &self,
        category: &str,
        time_period: &str,
        total_limit: usize,
    ) -> Result<Vec<BiggestWinner>> {
        let mut all_winners = Vec::new();
        let batch_size = 100; // API max per request
        let mut offset = 0;

        while all_winners.len() < total_limit {
            let remaining = total_limit - all_winners.len();
            let limit = std::cmp::min(batch_size, remaining);

            let query = BiggestWinnersQuery {
                time_period: time_period.to_string(),
                limit,
                offset,
                category: category.to_string(),
            };

            debug!(
                category,
                time_period, offset, limit, "Fetching biggest winners batch"
            );

            let batch = self.get_biggest_winners(&query).await?;

            if batch.is_empty() {
                debug!(category, "No more winners available");
                break;
            }

            let batch_len = batch.len();
            all_winners.extend(batch);
            offset += batch_len;

            debug!(
                category,
                batch_count = batch_len,
                total = all_winners.len(),
                "Fetched biggest winners batch"
            );

            // If we got less than requested, no more pages
            if batch_len < limit {
                break;
            }

            // Small delay to avoid rate limiting
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Truncate to exact limit
        all_winners.truncate(total_limit);

        tracing::info!(
            category,
            total = all_winners.len(),
            "Fetched all biggest winners"
        );

        Ok(all_winners)
    }

    /// Get token midpoint price from CLOB
    #[instrument(skip(self), level = "debug")]
    pub async fn get_token_midpoint(&self, token_id: &str) -> Result<f64> {
        let url = format!(
            "{}/midpoint?token_id={}",
            self.config.clob_base_url, token_id
        );
        debug!(%url, "Fetching token midpoint");

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            // Return default 0.5 for failed requests
            return Ok(0.5);
        }

        let data: serde_json::Value = response.json().await.map_err(|e| {
            PolymarketError::parse_with_source(format!("Failed to parse midpoint response: {e}"), e)
        })?;

        let price = data["mid"]
            .as_str()
            .and_then(|p| p.parse::<f64>().ok())
            .unwrap_or(0.5);

        Ok(price)
    }

    /// Get order book for a token
    #[instrument(skip(self), level = "debug")]
    pub async fn get_order_book(&self, token_id: &str) -> Result<serde_json::Value> {
        let url = format!("{}/book?token_id={}", self.config.clob_base_url, token_id);
        debug!(%url, "Fetching order book");

        let response = self.client.get(&url).send().await?;
        self.handle_response::<serde_json::Value>(response).await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = DataConfig::builder()
            .with_base_url("https://custom.example.com")
            .with_timeout(Duration::from_secs(60));

        assert_eq!(config.base_url, "https://custom.example.com");
        assert_eq!(config.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_biggest_winners_query() {
        let query = BiggestWinnersQuery::new()
            .with_category("politics")
            .with_time_period("week")
            .with_limit(50);

        assert_eq!(query.category, "politics");
        assert_eq!(query.time_period, "week");
        assert_eq!(query.limit, 50);
    }
}
