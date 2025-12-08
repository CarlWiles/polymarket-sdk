//! Gamma API Client
//!
//! Provides access to Polymarket's Gamma API for market discovery and metadata.
//!
//! ## Example
//!
//! ```rust,ignore
//! use polymarket_sdk::gamma::{GammaClient, GammaConfig};
//!
//! let client = GammaClient::new(GammaConfig::default())?;
//!
//! // Get all active markets
//! let markets = client.get_markets(None).await?;
//!
//! // Get a specific market by condition ID
//! let market = client.get_market("0x...").await?;
//!
//! // Get events
//! let events = client.get_events(None).await?;
//! ```

use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, info, instrument};
use url::Url;

use crate::core::gamma_api_url;
use crate::core::{PolymarketError, Result};
use crate::types::{Event, ListParams, Market, Tag};

/// Gamma API configuration
#[derive(Debug, Clone)]
pub struct GammaConfig {
    /// Base URL for the Gamma API
    pub base_url: String,
    /// Request timeout
    pub timeout: Duration,
    /// User agent string
    pub user_agent: String,
}

impl Default for GammaConfig {
    fn default() -> Self {
        Self {
            // Use helper function to support env var override (POLYMARKET_GAMMA_URL)
            base_url: gamma_api_url(),
            timeout: Duration::from_secs(30),
            user_agent: "polymarket-sdk/0.1.0".to_string(),
        }
    }
}

impl GammaConfig {
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
    /// **Deprecated**: Use `GammaConfig::default()` instead.
    /// The default implementation already supports `POLYMARKET_GAMMA_URL` env var override.
    #[must_use]
    #[deprecated(
        since = "0.1.0",
        note = "Use GammaConfig::default() instead. URL override via POLYMARKET_GAMMA_URL env var is already supported."
    )]
    pub fn from_env() -> Self {
        Self::default()
    }
}

/// Gamma API client
#[derive(Debug, Clone)]
pub struct GammaClient {
    config: GammaConfig,
    client: Client,
}

impl GammaClient {
    /// Create a new Gamma client
    pub fn new(config: GammaConfig) -> Result<Self> {
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
        Self::new(GammaConfig::default())
    }

    /// Create client from environment variables.
    ///
    /// **Deprecated**: Use `GammaClient::with_defaults()` instead.
    #[deprecated(since = "0.1.0", note = "Use GammaClient::with_defaults() instead")]
    #[allow(deprecated)]
    pub fn from_env() -> Result<Self> {
        Self::new(GammaConfig::from_env())
    }

    /// Get all markets with optional filtering
    #[instrument(skip(self), level = "debug")]
    pub async fn get_markets(&self, params: Option<ListParams>) -> Result<Vec<Market>> {
        let mut url = format!("{}/markets", self.config.base_url);
        let query_params = self.build_list_query_params(params);

        if !query_params.is_empty() {
            url.push('?');
            url.push_str(&query_params);
        }

        debug!(%url, "Fetching markets");

        let response = self.client.get(&url).send().await?;
        self.handle_response::<Vec<Market>>(response).await
    }

    /// Get a specific market by condition ID
    #[instrument(skip(self), level = "debug")]
    pub async fn get_market(&self, condition_id: &str) -> Result<Option<Market>> {
        let url = format!("{}/markets/{}", self.config.base_url, condition_id);
        debug!(%url, "Fetching market");

        let response = self.client.get(&url).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        self.handle_response::<Market>(response).await.map(Some)
    }

    /// Search markets by query
    #[instrument(skip(self), level = "debug")]
    pub async fn search_markets(&self, query: &str, limit: Option<u32>) -> Result<Vec<Market>> {
        let mut url = format!(
            "{}/markets?search={}",
            self.config.base_url,
            urlencoding::encode(query)
        );

        if let Some(limit) = limit {
            url.push_str(&format!("&limit={limit}"));
        }

        debug!(%url, "Searching markets");

        let response = self.client.get(&url).send().await?;
        self.handle_response::<Vec<Market>>(response).await
    }

    /// Get all events with optional filtering
    #[instrument(skip(self), level = "debug")]
    pub async fn get_events(&self, params: Option<ListParams>) -> Result<Vec<Event>> {
        let mut url = format!("{}/events", self.config.base_url);
        let query_params = self.build_list_query_params(params);

        if !query_params.is_empty() {
            url.push('?');
            url.push_str(&query_params);
        }

        debug!(%url, "Fetching events");

        let response = self.client.get(&url).send().await?;
        self.handle_response::<Vec<Event>>(response).await
    }

    /// Get a specific event by ID
    #[instrument(skip(self), level = "debug")]
    pub async fn get_event(&self, event_id: &str) -> Result<Option<Event>> {
        let url = format!("{}/events/{}", self.config.base_url, event_id);
        debug!(%url, "Fetching event");

        let response = self.client.get(&url).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        self.handle_response::<Event>(response).await.map(Some)
    }

    /// Get tags with optional pagination
    #[instrument(skip(self), level = "debug")]
    pub async fn get_tags_paginated(&self, limit: u32, offset: u32) -> Result<Vec<Tag>> {
        let url = format!(
            "{}/tags?limit={}&offset={}",
            self.config.base_url, limit, offset
        );
        debug!(%url, "Fetching tags page");

        let response = self.client.get(&url).send().await?;
        self.handle_response::<Vec<Tag>>(response).await
    }

    /// Get all tags (single page, for backwards compatibility)
    #[instrument(skip(self), level = "debug")]
    pub async fn get_tags(&self) -> Result<Vec<Tag>> {
        // For backwards compatibility, get all tags with pagination
        self.get_all_tags().await
    }

    /// Get all tags using pagination loop
    ///
    /// Fetches all tags from the Gamma API using pagination.
    /// Page size is 300 (maximum allowed by API).
    #[instrument(skip(self), level = "debug")]
    pub async fn get_all_tags(&self) -> Result<Vec<Tag>> {
        let mut all_tags = Vec::new();
        let page_size = 300u32; // Maximum page size
        let mut offset = 0u32;

        tracing::info!(
            "Starting to fetch all tags with pagination (page_size={})",
            page_size
        );

        loop {
            tracing::debug!(
                "Fetching tags page {} (offset={})",
                offset / page_size + 1,
                offset
            );

            let tags = self.get_tags_paginated(page_size, offset).await?;
            let count = tags.len();

            if count == 0 {
                tracing::debug!("Reached last page, stopping pagination");
                break;
            }

            tracing::info!(
                "Page {}: fetched {} tags, total so far: {}",
                offset / page_size + 1,
                count,
                all_tags.len() + count
            );

            all_tags.extend(tags);

            // If we got less than page_size, we've reached the last page
            if count < page_size as usize {
                tracing::debug!("Last page reached (got {} < {})", count, page_size);
                break;
            }

            offset += page_size;
        }

        tracing::info!("Finished fetching all tags, total: {}", all_tags.len());
        Ok(all_tags)
    }

    /// Get markets by tag
    #[instrument(skip(self), level = "debug")]
    pub async fn get_markets_by_tag(
        &self,
        tag_slug: &str,
        params: Option<ListParams>,
    ) -> Result<Vec<Market>> {
        let mut url = format!("{}/markets?tag_slug={}", self.config.base_url, tag_slug);

        if let Some(params) = params {
            if let Some(limit) = params.pagination.limit {
                url.push_str(&format!("&limit={limit}"));
            }
            if let Some(offset) = params.pagination.offset {
                url.push_str(&format!("&offset={offset}"));
            }
        }

        debug!(%url, "Fetching markets by tag");

        let response = self.client.get(&url).send().await?;
        self.handle_response::<Vec<Market>>(response).await
    }

    /// Get markets by CLOB token IDs (asset IDs)
    ///
    /// Fetches market information for the given list of CLOB token IDs.
    /// Useful for enriching feed/activity data with market details.
    ///
    /// # Arguments
    /// * `clob_token_ids` - List of CLOB token IDs (asset IDs) to query
    ///
    /// # Example
    /// ```rust,ignore
    /// let client = GammaClient::with_defaults()?;
    /// let token_ids = vec![
    ///     "21742633143463906290569050155826241533067272736897614950488156847949938836455".to_string(),
    ///     "48331043336612883890938759509493159234755048973500640148014422747788308965732".to_string(),
    /// ];
    /// let markets = client.get_markets_by_clob_token_ids(&token_ids).await?;
    /// ```
    #[instrument(skip(self, clob_token_ids), level = "debug", fields(token_count = clob_token_ids.len()))]
    pub async fn get_markets_by_clob_token_ids(
        &self,
        clob_token_ids: &[String],
    ) -> Result<Vec<Market>> {
        if clob_token_ids.is_empty() {
            return Ok(vec![]);
        }

        // Build URL with repeated clob_token_ids params (clob_token_ids=...&clob_token_ids=...)
        let mut url = Url::parse(&format!("{}/markets", self.config.base_url))?;
        {
            let mut pairs = url.query_pairs_mut();
            for token in clob_token_ids {
                pairs.append_pair("clob_token_ids", token);
            }
        }

        let url_str = url.to_string();
        debug!(%url_str, token_count = clob_token_ids.len(), "Fetching markets by CLOB token IDs");
        info!(%url_str, token_count = clob_token_ids.len(), "Gamma get_markets_by_clob_token_ids request");

        let response = self.client.get(url).send().await?;
        self.handle_response::<Vec<Market>>(response).await
    }

    /// Get markets by CLOB token IDs with batching support
    ///
    /// For large lists of token IDs, this method batches requests to avoid
    /// URL length limits. Default batch size is 50 tokens per request.
    ///
    /// # Arguments
    /// * `clob_token_ids` - List of CLOB token IDs to query
    /// * `batch_size` - Optional batch size (default: 50)
    #[instrument(skip(self, clob_token_ids), level = "debug", fields(token_count = clob_token_ids.len()))]
    pub async fn get_markets_by_clob_token_ids_batched(
        &self,
        clob_token_ids: &[String],
        batch_size: Option<usize>,
    ) -> Result<Vec<Market>> {
        if clob_token_ids.is_empty() {
            return Ok(vec![]);
        }

        let batch_size = batch_size.unwrap_or(50);
        let mut all_markets = Vec::new();

        for chunk in clob_token_ids.chunks(batch_size) {
            let markets = self.get_markets_by_clob_token_ids(chunk).await?;
            all_markets.extend(markets);
        }

        Ok(all_markets)
    }

    // =========================================================================
    // Public Search API
    // =========================================================================

    /// Search Polymarket via /public-search endpoint
    ///
    /// This endpoint searches across events, profiles (traders), and tags.
    ///
    /// # Arguments
    /// * `request` - Search request parameters
    ///
    /// # Example
    /// ```rust,ignore
    /// use polymarket_sdk::gamma::GammaClient;
    /// use polymarket_sdk::types::SearchRequest;
    ///
    /// let client = GammaClient::with_defaults()?;
    /// let response = client.public_search(SearchRequest::new("bitcoin")
    ///     .with_limit(10)
    ///     .with_profiles(true)
    /// ).await?;
    ///
    /// println!("Found {} profiles", response.profiles.len());
    /// ```
    #[instrument(skip(self), level = "debug")]
    pub async fn public_search(
        &self,
        request: crate::types::SearchRequest,
    ) -> Result<crate::types::SearchResponse> {
        let url = format!("{}/public-search", self.config.base_url);

        debug!(
            %url,
            query = %request.q,
            limit = ?request.limit_per_type,
            "Performing public search"
        );

        let response = self.client.get(&url).query(&request).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(PolymarketError::api(status.as_u16(), body));
        }

        let text = response.text().await?;

        // Debug log response preview
        if text.len() > 500 {
            debug!("Search response (first 500 chars): {}", &text[..500]);
        } else {
            debug!("Search response: {}", text);
        }

        let search_response: crate::types::SearchResponse =
            serde_json::from_str(&text).map_err(|e| {
                tracing::error!("Failed to parse search response: {}", e);
                PolymarketError::parse_with_source(format!("Search JSON parse error: {e}"), e)
            })?;

        Ok(search_response)
    }

    /// Search for traders/profiles only
    ///
    /// Convenience method that calls public_search with profiles enabled.
    ///
    /// # Arguments
    /// * `query` - Search query string
    /// * `limit` - Maximum number of results
    #[instrument(skip(self), level = "debug")]
    pub async fn search_traders(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<Vec<crate::types::SearchProfile>> {
        let request = crate::types::SearchRequest::new(query)
            .with_limit(limit)
            .with_profiles(true)
            .with_tags(false);

        let response = self.public_search(request).await?;
        Ok(response.profiles)
    }

    /// Search for all types (events, profiles, tags)
    ///
    /// # Arguments
    /// * `query` - Search query string
    /// * `limit` - Maximum number of results per type
    #[instrument(skip(self), level = "debug")]
    pub async fn search_all(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<crate::types::SearchResponse> {
        let request = crate::types::SearchRequest::new(query)
            .with_limit(limit)
            .with_profiles(true)
            .with_tags(true);

        self.public_search(request).await
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Build query parameters from ListParams
    fn build_list_query_params(&self, params: Option<ListParams>) -> String {
        let Some(params) = params else {
            return String::new();
        };

        let mut query_parts = Vec::new();

        if let Some(limit) = params.pagination.limit {
            query_parts.push(format!("limit={limit}"));
        }
        if let Some(offset) = params.pagination.offset {
            query_parts.push(format!("offset={offset}"));
        }
        if let Some(closed) = params.closed {
            query_parts.push(format!("closed={closed}"));
        }
        if let Some(active) = params.active {
            query_parts.push(format!("active={active}"));
        }
        if let Some(order) = params.order {
            query_parts.push(format!("order={order}"));
        }
        if let Some(ascending) = params.ascending {
            query_parts.push(format!("ascending={ascending}"));
        }

        query_parts.join("&")
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

/// Response wrapper for paginated results
#[derive(Debug, Deserialize)]
pub struct PaginatedResponse<T> {
    /// Results
    pub data: Vec<T>,
    /// Total count
    pub count: Option<i64>,
    /// Limit used
    pub limit: Option<i64>,
    /// Next cursor for pagination
    pub next_cursor: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = GammaConfig::builder()
            .with_base_url("https://custom.example.com")
            .with_timeout(Duration::from_secs(60));

        assert_eq!(config.base_url, "https://custom.example.com");
        assert_eq!(config.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_query_params_building() {
        let client = GammaClient::with_defaults().unwrap();

        let params = ListParams::new()
            .with_limit(10)
            .with_offset(20)
            .with_closed(false);

        let query = client.build_list_query_params(Some(params));
        assert!(query.contains("limit=10"));
        assert!(query.contains("offset=20"));
        assert!(query.contains("closed=false"));
    }
}
