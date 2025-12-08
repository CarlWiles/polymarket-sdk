//! Polymarket CLOB REST API Client
//!
//! This module provides a high-level client for interacting with the
//! Polymarket CLOB (Central Limit Order Book) REST API.
//!
//! ## Features
//!
//! - **API Credential Management**: Create, derive, and manage API credentials
//! - **Order Submission**: Submit, cancel, and query orders
//! - **Market Data**: Get order books and market information
//!
//! ## Example
//!
//! ```rust,ignore
//! use polymarket_sdk::clob::{ClobClient, ClobConfig};
//! use alloy_signer_local::PrivateKeySigner;
//!
//! let signer: PrivateKeySigner = "0x...".parse()?;
//! let client = ClobClient::new(ClobConfig::default(), signer)?;
//!
//! // Create API credentials (first time)
//! let creds = client.create_api_credentials().await?;
//!
//! // Submit an order
//! let order = client.submit_order(&signed_order).await?;
//! ```

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::U256;
use alloy_signer_local::PrivateKeySigner;
use governor::{Quota, RateLimiter as GovRateLimiter};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

use crate::auth::{
    create_l1_headers, create_l2_headers, create_l2_headers_with_body_string,
    get_current_unix_time_secs,
};
use crate::core::clob_api_url;
use crate::core::{PolymarketError, Result};
use crate::types::{ApiCredentials, SignedOrderRequest};

// Builder API authentication
use crate::auth::{BuilderApiKeyCreds, BuilderSigner};

type RateLimiter = GovRateLimiter<
    governor::state::NotKeyed,
    governor::state::InMemoryState,
    governor::clock::DefaultClock,
>;

/// CLOB API configuration
#[derive(Debug, Clone)]
pub struct ClobConfig {
    /// CLOB API base URL
    pub base_url: String,
    /// Request timeout
    pub timeout: Duration,
    /// Rate limit (requests per second)
    pub rate_limit_per_second: u32,
    /// User agent string
    pub user_agent: String,
}

impl Default for ClobConfig {
    fn default() -> Self {
        Self {
            // Use helper function to support env var override (POLYMARKET_CLOB_URL)
            base_url: clob_api_url(),
            timeout: Duration::from_secs(30),
            rate_limit_per_second: 5,
            user_agent: "polymarket-sdk/0.1.0".to_string(),
        }
    }
}

impl ClobConfig {
    /// Create a new configuration builder with defaults.
    #[must_use]
    pub fn builder() -> Self {
        Self::default()
    }

    /// Create config from environment variables.
    ///
    /// **Deprecated**: Use `ClobConfig::default()` instead.
    /// The default implementation already supports `POLYMARKET_CLOB_URL` env var override.
    #[must_use]
    #[deprecated(
        since = "0.1.0",
        note = "Use ClobConfig::default() instead. URL override via POLYMARKET_CLOB_URL env var is already supported."
    )]
    pub fn from_env() -> Self {
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

    /// Set rate limit (requests per second)
    #[must_use]
    pub fn with_rate_limit(mut self, rate_limit: u32) -> Self {
        self.rate_limit_per_second = rate_limit;
        self
    }

    /// Set user agent string
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }
}

/// Derive API key response
#[derive(Debug, Deserialize)]
pub struct DeriveApiKeyResponse {
    /// The derived API key
    #[serde(rename = "apiKey")]
    pub api_key: String,
    /// The API secret (base64 encoded)
    pub secret: String,
    /// The passphrase
    pub passphrase: String,
}

/// API key response
#[derive(Debug, Deserialize)]
pub struct ApiKeyResponse {
    /// API key
    #[serde(rename = "apiKey")]
    pub api_key: String,
    /// API secret
    pub secret: String,
    /// Passphrase
    pub passphrase: String,
}

/// Create API key request
#[derive(Debug, Serialize)]
struct CreateApiKeyRequest {
    /// Nonce from derive endpoint
    nonce: String,
}

/// Order response from CLOB
/// Matches official Polymarket API response format
#[derive(Debug, Deserialize)]
pub struct OrderResponse {
    /// Whether the order submission was successful
    pub success: bool,
    /// Error message (empty string if no error)
    #[serde(rename = "errorMsg")]
    pub error_msg: String,
    /// Order ID assigned by the CLOB
    #[serde(rename = "orderID")]
    pub order_id: String,
    /// Transaction hashes if any
    #[serde(rename = "transactionsHashes", default)]
    pub transactions_hashes: Vec<String>,
    /// Order status
    pub status: String,
}

/// Open order from CLOB
#[derive(Debug, Deserialize)]
pub struct OpenOrder {
    /// Order ID
    pub id: String,
    /// Token ID
    #[serde(rename = "tokenId")]
    pub token_id: String,
    /// Maker address
    pub maker: String,
    /// Signer address
    pub signer: String,
    /// Side (BUY/SELL)
    pub side: String,
    /// Price
    pub price: String,
    /// Original size
    #[serde(rename = "originalSize")]
    pub original_size: String,
    /// Size remaining
    #[serde(rename = "sizeMatched")]
    pub size_matched: String,
    /// Status
    pub status: String,
    /// Created at timestamp
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
}

/// Cancel orders request
#[derive(Debug, Serialize)]
struct CancelOrdersRequest {
    /// Order IDs to cancel
    #[serde(rename = "orderIds")]
    order_ids: Vec<String>,
}

/// Cancel response
#[derive(Debug, Deserialize)]
pub struct CancelResponse {
    /// Cancelled order IDs
    pub canceled: Vec<String>,
    /// Failed cancellations
    pub failed: Option<Vec<String>>,
}

/// Neg risk response from /neg-risk endpoint
#[derive(Debug, Deserialize)]
pub struct NegRiskResponse {
    /// Whether the token is a negative risk market
    pub neg_risk: bool,
}

/// Tick size response from /tick-size endpoint
#[derive(Debug, Deserialize)]
pub struct TickSizeResponse {
    /// The tick size for the token (e.g., "0.01", "0.001")
    pub minimum_tick_size: String,
}

/// Fee rate response from /fee-rate endpoint
#[derive(Debug, Deserialize)]
pub struct FeeRateResponse {
    /// The base fee rate in basis points (e.g., 0 for 0%, 100 for 1%)
    pub base_fee: u32,
}

/// CLOB API client
#[derive(Clone)]
pub struct ClobClient {
    config: ClobConfig,
    client: Client,
    signer: PrivateKeySigner,
    rate_limiter: Arc<RateLimiter>,
    /// Stored API credentials (set after creation)
    api_credentials: Option<ApiCredentials>,
    /// Optional explicit address for Builder API auth (when signer ≠ API key owner)
    auth_address: Option<String>,
    /// Optional Builder signer for Integrator authentication
    builder_signer: Option<BuilderSigner>,
}

impl ClobClient {
    /// Create a new CLOB client
    pub fn new(config: ClobConfig, signer: PrivateKeySigner) -> Result<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .user_agent(&config.user_agent)
            .gzip(true)
            .build()
            .map_err(|e| PolymarketError::config(format!("Failed to create HTTP client: {e}")))?;

        let quota = Quota::per_second(
            NonZeroU32::new(config.rate_limit_per_second).unwrap_or(NonZeroU32::new(5).unwrap()),
        );
        let rate_limiter = Arc::new(GovRateLimiter::direct(quota));

        Ok(Self {
            config,
            client,
            signer,
            rate_limiter,
            api_credentials: None,
            auth_address: None,
            builder_signer: None,
        })
    }

    /// Create client from environment variables.
    ///
    /// **Deprecated**: Use `ClobClient::new(ClobConfig::default(), signer)` instead.
    #[deprecated(
        since = "0.1.0",
        note = "Use ClobClient::new(ClobConfig::default(), signer) instead"
    )]
    #[allow(deprecated)]
    pub fn from_env(signer: PrivateKeySigner) -> Result<Self> {
        Self::new(ClobConfig::from_env(), signer)
    }

    /// Set API credentials for L2 authentication
    #[must_use]
    pub fn with_api_credentials(mut self, credentials: ApiCredentials) -> Self {
        self.api_credentials = Some(credentials);
        self
    }

    /// Set explicit auth address (for Builder API authentication)
    ///
    /// Use this when the order signer and API credentials owner are different addresses.
    /// This is common when using Builder API credentials.
    #[must_use]
    pub fn with_auth_address(mut self, address: impl Into<String>) -> Self {
        self.auth_address = Some(address.into());
        self
    }

    /// Set Builder API signer for Integrator authentication
    ///
    /// Use this when submitting orders on behalf of users via Builder API.
    /// The Builder credentials authenticate the Integrator, while the order
    /// signature authenticates the user's wallet.
    ///
    /// # Example
    /// ```ignore
    /// let clob_client = ClobClient::from_env(dummy_signer)
    ///     .with_api_credentials(builder_credentials)
    ///     .with_builder_signer(builder_credentials)  // Enables Builder headers
    ///     .with_auth_address(server_wallet_address);
    /// ```
    #[must_use]
    pub fn with_builder_signer(mut self, credentials: ApiCredentials) -> Self {
        let builder_creds = BuilderApiKeyCreds {
            key: credentials.api_key,
            secret: credentials.secret, // Base64 encoded
            passphrase: credentials.passphrase,
        };
        self.builder_signer = Some(BuilderSigner::new(builder_creds));
        self
    }

    /// Get the signer's address
    #[must_use]
    pub fn address(&self) -> String {
        format!("{:?}", self.signer.address())
    }

    /// Wait for rate limiter
    async fn wait_for_rate_limit(&self) {
        self.rate_limiter.until_ready().await;
    }

    /// Derive API key (step 1 of credential creation)
    ///
    /// This gets a nonce and derives the API key from the wallet signature.
    #[instrument(skip(self))]
    pub async fn derive_api_key(&self, nonce: Option<U256>) -> Result<DeriveApiKeyResponse> {
        self.wait_for_rate_limit().await;

        let endpoint = "/auth/derive-api-key";
        let url = format!("{}{}", self.config.base_url, endpoint);

        let headers = create_l1_headers(&self.signer, nonce)?;

        debug!(address = %self.address(), "Deriving API key");

        let mut req_builder = self.client.get(&url);
        for (key, value) in &headers {
            req_builder = req_builder.header(*key, value);
        }

        let response = req_builder.send().await?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(PolymarketError::api(status.as_u16(), body));
        }

        let result: DeriveApiKeyResponse = response.json().await.map_err(|e| {
            PolymarketError::parse_with_source(format!("Failed to parse derive response: {e}"), e)
        })?;

        info!(address = %self.address(), "API key derived successfully");

        Ok(result)
    }

    /// Derive API key with pre-computed signature (for Privy ServerWallet)
    ///
    /// This variant accepts a pre-computed EIP-712 signature, useful when using
    /// external signing services like Privy ServerWallet that don't expose private keys.
    ///
    /// # Workflow
    ///
    /// 1. Generate timestamp and nonce
    /// 2. Use `build_clob_auth_typed_data` from auth module to construct typed data
    /// 3. Call Privy ServerWallet API to sign the typed data
    /// 4. Call this method with the signature
    ///
    /// # Arguments
    ///
    /// * `address` - Wallet address (hex string with or without 0x prefix)
    /// * `signature` - EIP-712 signature (hex string with 0x prefix)
    /// * `timestamp` - Unix timestamp string used in signature
    /// * `nonce` - Nonce value used in signature
    ///
    /// # Returns
    ///
    /// Derived API credentials (api_key, secret, passphrase)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use polymarket_sdk::auth::{build_clob_auth_typed_data, get_current_unix_time_secs};
    /// use alloy_primitives::{Address, U256};
    ///
    /// // 1. Prepare signature data
    /// let address: Address = "0x1234...".parse()?;
    /// let timestamp = get_current_unix_time_secs().to_string();
    /// let nonce = U256::ZERO;
    ///
    /// // 2. Build typed data for Privy
    /// let typed_data = build_clob_auth_typed_data(address, &timestamp, nonce);
    ///
    /// // 3. Call Privy ServerWallet API (pseudo-code)
    /// let signature = privy_client.sign_typed_data(server_wallet_id, typed_data).await?;
    ///
    /// // 4. Derive API key with signature
    /// let credentials = clob_client
    ///     .derive_api_key_with_signature(&format!("{:?}", address), &signature, &timestamp, nonce)
    ///     .await?;
    /// ```
    #[instrument(skip(self, signature))]
    pub async fn derive_api_key_with_signature(
        &self,
        address: &str,
        signature: &str,
        timestamp: &str,
        nonce: U256,
    ) -> Result<DeriveApiKeyResponse> {
        self.wait_for_rate_limit().await;

        let endpoint = "/auth/derive-api-key";
        let url = format!("{}{}", self.config.base_url, endpoint);

        // Ensure address has 0x prefix
        let address = if address.starts_with("0x") {
            address.to_string()
        } else {
            format!("0x{}", address)
        };

        // Ensure signature has 0x prefix
        let signature = if signature.starts_with("0x") {
            signature.to_string()
        } else {
            format!("0x{}", signature)
        };

        // Build L1 auth headers manually with pre-computed signature
        let headers = HashMap::from([
            ("poly_address", address.clone()),
            ("poly_signature", signature),
            ("poly_timestamp", timestamp.to_string()),
            ("poly_nonce", nonce.to_string()),
        ]);

        debug!(address = %address, "Deriving API key with pre-computed signature");

        let mut req_builder = self.client.get(&url);
        for (key, value) in &headers {
            req_builder = req_builder.header(*key, value);
        }

        let response = req_builder.send().await?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(PolymarketError::api(status.as_u16(), body));
        }

        let result: DeriveApiKeyResponse = response.json().await.map_err(|e| {
            PolymarketError::parse_with_source(format!("Failed to parse derive response: {e}"), e)
        })?;

        info!(address = %address, "API key derived successfully with pre-computed signature");

        Ok(result)
    }

    /// Create API key with pre-computed signature (for server wallet registration)
    ///
    /// This is the first-time registration step that tells Polymarket about this wallet.
    /// After calling this once, you can use derive_api_key_with_signature for subsequent requests.
    #[instrument(skip(self, signature))]
    pub async fn create_api_key_with_signature(
        &self,
        address: &str,
        signature: &str,
        timestamp: &str,
        nonce: U256,
    ) -> Result<ApiKeyResponse> {
        self.wait_for_rate_limit().await;

        let endpoint = "/auth/api-key";
        let url = format!("{}{}", self.config.base_url, endpoint);

        // Ensure address has 0x prefix
        let address = if address.starts_with("0x") {
            address.to_string()
        } else {
            format!("0x{}", address)
        };

        // Ensure signature has 0x prefix
        let signature = if signature.starts_with("0x") {
            signature.to_string()
        } else {
            format!("0x{}", signature)
        };

        // Build L1 auth headers manually with pre-computed signature
        let headers = HashMap::from([
            ("poly_address", address.clone()),
            ("poly_signature", signature),
            ("poly_timestamp", timestamp.to_string()),
            ("poly_nonce", nonce.to_string()),
        ]);

        let body = CreateApiKeyRequest {
            nonce: nonce.to_string(),
        };

        debug!(address = %address, "Creating API key with pre-computed signature (first-time registration)");

        let mut req_builder = self.client.post(&url).json(&body);
        for (key, value) in &headers {
            req_builder = req_builder.header(*key, value);
        }

        let response = req_builder.send().await?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(PolymarketError::api(status.as_u16(), body));
        }

        let result: ApiKeyResponse = response.json().await.map_err(|e| {
            PolymarketError::parse_with_source(format!("Failed to parse create response: {e}"), e)
        })?;

        info!(address = %address, "API key created successfully (wallet registered)");

        Ok(result)
    }

    /// Create API key (step 2 of credential creation)
    ///
    /// This registers the derived API key with the CLOB.
    #[instrument(skip(self))]
    pub async fn create_api_key(&self, nonce: U256) -> Result<ApiKeyResponse> {
        self.wait_for_rate_limit().await;

        let endpoint = "/auth/api-key";
        let url = format!("{}{}", self.config.base_url, endpoint);

        let headers = create_l1_headers(&self.signer, Some(nonce))?;

        let body = CreateApiKeyRequest {
            nonce: nonce.to_string(),
        };

        debug!(address = %self.address(), "Creating API key");

        let mut req_builder = self.client.post(&url).json(&body);
        for (key, value) in &headers {
            req_builder = req_builder.header(*key, value);
        }

        let response = req_builder.send().await?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(PolymarketError::api(status.as_u16(), body));
        }

        let result: ApiKeyResponse = response.json().await.map_err(|e| {
            PolymarketError::parse_with_source(format!("Failed to parse create response: {e}"), e)
        })?;

        info!(address = %self.address(), "API key created successfully");

        Ok(result)
    }

    /// Create API credentials (complete flow)
    ///
    /// This performs the full API credential creation flow:
    /// 1. Derive API key with L1 signature
    /// 2. Create/register API key
    ///
    /// # Returns
    /// Complete API credentials ready for L2 authentication
    #[instrument(skip(self))]
    pub async fn create_api_credentials(&self) -> Result<ApiCredentials> {
        info!(address = %self.address(), "Creating API credentials");

        // Step 1: Derive API key (ensures the key derivation is set up)
        let _derive_result = self.derive_api_key(None).await?;

        // Step 2: Create API key with nonce 0 (typical for new credentials)
        let create_result = self.create_api_key(U256::ZERO).await?;

        let credentials = ApiCredentials {
            api_key: create_result.api_key,
            secret: create_result.secret,
            passphrase: create_result.passphrase,
        };

        info!(address = %self.address(), "API credentials created successfully");

        Ok(credentials)
    }

    /// Submit an order
    ///
    /// Requires API credentials to be set via `with_api_credentials`.
    #[instrument(skip(self, order))]
    pub async fn submit_order(&self, order: &SignedOrderRequest) -> Result<OrderResponse> {
        use crate::types::{NewOrder, OrderType};

        self.wait_for_rate_limit().await;

        let api_creds = self.api_credentials.as_ref().ok_or_else(|| {
            PolymarketError::config("API credentials required for order submission")
        })?;

        let endpoint = "/order";
        let url = format!("{}{}", self.config.base_url, endpoint);

        // IMPORTANT: Convert SignedOrderRequest to NewOrder format
        // - Use api_key as owner (NOT wallet address) - matches TypeScript SDK behavior
        // - Wrap order data in nested structure with orderType and deferExec
        let new_order =
            NewOrder::from_signed_order(order, &api_creds.api_key, OrderType::GTC, false);

        // CRITICAL FIX: Serialize JSON ONCE and reuse for all operations
        // This ensures L2 HMAC, Builder HMAC, and HTTP body all use identical JSON
        let body_str = serde_json::to_string(&new_order)
            .map_err(|e| PolymarketError::parse(format!("Failed to serialize order: {}", e)))?;

        // CRITICAL FIX: Get timestamp ONCE and reuse for L2 and Builder headers
        // This ensures both headers use the same timestamp, avoiding signature mismatches
        let timestamp = get_current_unix_time_secs();

        // Get the auth address (either explicit or derived from signer)
        let address = if let Some(ref addr) = self.auth_address {
            if addr.starts_with("0x") {
                addr.clone()
            } else {
                format!("0x{}", addr)
            }
        } else {
            format!("{:?}", self.signer.address())
        };

        // 1. Create standard L2 headers (POLY_*) using pre-serialized body string and shared timestamp
        let mut headers = create_l2_headers_with_body_string(
            &address, api_creds, "POST", endpoint, &body_str, timestamp,
        )?;

        // 2. Inject Builder headers (POLY_BUILDER_*) if Builder signer is configured
        // Use the SAME body_str and SAME timestamp for consistency
        if let Some(ref builder) = self.builder_signer {
            info!("Builder signer configured, generating Builder headers");

            let builder_headers = builder
                .create_builder_header_payload(
                    "POST",
                    endpoint,
                    Some(&body_str),
                    Some(timestamp as i64),
                )
                .map_err(|e| PolymarketError::internal(format!("Builder header error: {}", e)))?;

            info!(
                header_count = builder_headers.len(),
                timestamp = timestamp,
                "Builder headers generated with shared timestamp"
            );

            // Merge Builder headers into existing headers
            // Note: We leak the strings to get 'static lifetime for HashMap keys
            for (key, value) in builder_headers {
                let static_key: &'static str = Box::leak(key.into_boxed_str());
                headers.insert(static_key, value);
            }

            info!(token_id = %order.token_id, side = %order.side, "Submitting order with Builder authentication");
        } else {
            warn!("Builder signer NOT configured - order may fail with 401 Unauthorized");
            info!(token_id = %order.token_id, side = %order.side, "Submitting order WITHOUT Builder authentication");
        }

        // Debug: Print the actual JSON being sent (NewOrder format)
        info!(order_json = %body_str, timestamp = timestamp, "Order JSON payload being sent to Polymarket (NewOrder format)");

        // CRITICAL FIX: Use pre-serialized body string instead of re-serializing with .json()
        // This ensures HTTP body matches exactly what was used for HMAC calculation
        let mut req_builder = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body_str.clone());
        for (key, value) in &headers {
            req_builder = req_builder.header(*key, value);
        }

        let response = req_builder.send().await?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(PolymarketError::api(status.as_u16(), body));
        }

        let result: OrderResponse = response.json().await.map_err(|e| {
            PolymarketError::parse_with_source(format!("Failed to parse order response: {e}"), e)
        })?;

        // Check if order submission was successful
        if !result.success {
            return Err(PolymarketError::api(
                400,
                format!(
                    "Order rejected: {} (status: {})",
                    result.error_msg, result.status
                ),
            ));
        }

        info!(
            order_id = %result.order_id,
            status = %result.status,
            success = result.success,
            "Order submitted successfully"
        );

        Ok(result)
    }

    /// Get open orders for the signer
    #[instrument(skip(self))]
    pub async fn get_open_orders(&self) -> Result<Vec<OpenOrder>> {
        self.wait_for_rate_limit().await;

        let api_creds = self.api_credentials.as_ref().ok_or_else(|| {
            PolymarketError::config("API credentials required for querying orders")
        })?;

        let endpoint = "/orders";
        let url = format!("{}{}", self.config.base_url, endpoint);

        let headers = create_l2_headers::<String>(&self.signer, api_creds, "GET", endpoint, None)?;

        debug!(address = %self.address(), "Getting open orders");

        let mut req_builder = self.client.get(&url);
        for (key, value) in &headers {
            req_builder = req_builder.header(*key, value);
        }

        let response = req_builder.send().await?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(PolymarketError::api(status.as_u16(), body));
        }

        let result: Vec<OpenOrder> = response.json().await.map_err(|e| {
            PolymarketError::parse_with_source(format!("Failed to parse orders response: {e}"), e)
        })?;

        debug!(count = %result.len(), "Retrieved open orders");

        Ok(result)
    }

    /// Cancel orders by IDs
    #[instrument(skip(self))]
    pub async fn cancel_orders(&self, order_ids: Vec<String>) -> Result<CancelResponse> {
        self.wait_for_rate_limit().await;

        let api_creds = self.api_credentials.as_ref().ok_or_else(|| {
            PolymarketError::config("API credentials required for cancelling orders")
        })?;

        let endpoint = "/order";
        let url = format!("{}{}", self.config.base_url, endpoint);

        let body = CancelOrdersRequest { order_ids };
        let headers = create_l2_headers(&self.signer, api_creds, "DELETE", endpoint, Some(&body))?;

        debug!("Cancelling orders");

        let mut req_builder = self.client.delete(&url).json(&body);
        for (key, value) in &headers {
            req_builder = req_builder.header(*key, value);
        }

        let response = req_builder.send().await?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(PolymarketError::api(status.as_u16(), body));
        }

        let result: CancelResponse = response.json().await.map_err(|e| {
            PolymarketError::parse_with_source(format!("Failed to parse cancel response: {e}"), e)
        })?;

        info!(cancelled = ?result.canceled, "Orders cancelled");

        Ok(result)
    }

    /// Cancel all open orders
    #[instrument(skip(self))]
    pub async fn cancel_all_orders(&self) -> Result<CancelResponse> {
        self.wait_for_rate_limit().await;

        let api_creds = self.api_credentials.as_ref().ok_or_else(|| {
            PolymarketError::config("API credentials required for cancelling orders")
        })?;

        let endpoint = "/order/cancel-all";
        let url = format!("{}{}", self.config.base_url, endpoint);

        let headers =
            create_l2_headers::<String>(&self.signer, api_creds, "DELETE", endpoint, None)?;

        debug!(address = %self.address(), "Cancelling all orders");

        let mut req_builder = self.client.delete(&url);
        for (key, value) in &headers {
            req_builder = req_builder.header(*key, value);
        }

        let response = req_builder.send().await?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(PolymarketError::api(status.as_u16(), body));
        }

        let result: CancelResponse = response.json().await.map_err(|e| {
            PolymarketError::parse_with_source(format!("Failed to parse cancel response: {e}"), e)
        })?;

        info!(cancelled = ?result.canceled, "All orders cancelled");

        Ok(result)
    }

    /// Get the neg_risk status for a token ID
    ///
    /// Queries the Polymarket CLOB API to determine if a market/token uses
    /// negative risk contracts. This is crucial for signing orders with the
    /// correct exchange contract address.
    ///
    /// # Arguments
    /// * `token_id` - The token ID (condition token) to check
    ///
    /// # Returns
    /// * `true` if the market uses negative risk contracts (use negRiskExchange)
    /// * `false` if the market uses standard contracts (use exchange)
    #[instrument(skip(self))]
    pub async fn get_neg_risk(&self, token_id: &str) -> Result<bool> {
        self.wait_for_rate_limit().await;

        let endpoint = "/neg-risk";
        let url = format!("{}{}?token_id={}", self.config.base_url, endpoint, token_id);

        debug!(token_id = %token_id, "Querying neg_risk status");

        let response = self.client.get(&url).send().await?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(PolymarketError::api(status.as_u16(), body));
        }

        let result: NegRiskResponse = response.json().await.map_err(|e| {
            PolymarketError::parse_with_source(format!("Failed to parse neg_risk response: {e}"), e)
        })?;

        debug!(token_id = %token_id, neg_risk = %result.neg_risk, "Got neg_risk status");

        Ok(result.neg_risk)
    }

    /// Get the tick size for a token ID
    ///
    /// Queries the Polymarket CLOB API to get the minimum tick size for
    /// price rounding on a specific market.
    ///
    /// # Arguments
    /// * `token_id` - The token ID (condition token) to check
    ///
    /// # Returns
    /// The tick size as a string (e.g., "0.01", "0.001", "0.0001")
    #[instrument(skip(self))]
    pub async fn get_tick_size(&self, token_id: &str) -> Result<String> {
        self.wait_for_rate_limit().await;

        let endpoint = "/tick-size";
        let url = format!("{}{}?token_id={}", self.config.base_url, endpoint, token_id);

        debug!(token_id = %token_id, "Querying tick size");

        let response = self.client.get(&url).send().await?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(PolymarketError::api(status.as_u16(), body));
        }

        let result: TickSizeResponse = response.json().await.map_err(|e| {
            PolymarketError::parse_with_source(
                format!("Failed to parse tick_size response: {e}"),
                e,
            )
        })?;

        debug!(token_id = %token_id, tick_size = %result.minimum_tick_size, "Got tick size");

        Ok(result.minimum_tick_size)
    }

    /// Get the fee rate for a token ID
    ///
    /// Queries the Polymarket CLOB API to get the fee rate (in basis points)
    /// for a specific market/token. This is crucial for signing orders with
    /// the correct fee rate that matches what the API expects.
    ///
    /// # Arguments
    /// * `token_id` - The token ID (condition token) to check
    ///
    /// # Returns
    /// The fee rate in basis points (e.g., 0 for 0%, 100 for 1%)
    ///
    /// # Note
    /// Orders MUST use the fee rate returned by this API, otherwise the
    /// EIP-712 signature will not match and the order will be rejected
    /// with "invalid signature".
    #[instrument(skip(self))]
    pub async fn get_fee_rate(&self, token_id: &str) -> Result<u32> {
        self.wait_for_rate_limit().await;

        let endpoint = "/fee-rate";
        let url = format!("{}{}?token_id={}", self.config.base_url, endpoint, token_id);

        debug!(token_id = %token_id, "Querying fee rate");

        let response = self.client.get(&url).send().await?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(PolymarketError::api(status.as_u16(), body));
        }

        let result: FeeRateResponse = response.json().await.map_err(|e| {
            PolymarketError::parse_with_source(format!("Failed to parse fee_rate response: {e}"), e)
        })?;

        debug!(token_id = %token_id, fee_rate_bps = %result.base_fee, "Got fee rate");

        Ok(result.base_fee)
    }

    /// Check if an orderbook exists for a token ID
    ///
    /// Queries the Polymarket CLOB `/book` endpoint to verify that an
    /// active orderbook exists for the given token. This should be called
    /// before submitting orders to avoid "orderbook does not exist" errors.
    ///
    /// # Arguments
    /// * `token_id` - The token ID (CLOB token / asset ID) to check
    ///
    /// # Returns
    /// * `true` if the orderbook exists and is active
    /// * `false` if the orderbook does not exist or the market is closed
    ///
    /// # Note
    /// Markets can have valid neg_risk and fee_rate data but no active
    /// orderbook (e.g., resolved or closed markets). Always verify
    /// orderbook existence before submitting orders.
    #[instrument(skip(self))]
    pub async fn check_orderbook_exists(&self, token_id: &str) -> Result<bool> {
        self.wait_for_rate_limit().await;

        let endpoint = "/book";
        let url = format!("{}{}?token_id={}", self.config.base_url, endpoint, token_id);

        debug!(token_id = %token_id, "Checking orderbook existence");

        let response = self.client.get(&url).send().await?;
        let status = response.status();

        // Check response body for error
        let body = response.text().await.unwrap_or_default();

        // API returns 200 with {"error": "..."} for non-existent orderbooks
        if body.contains("does not exist") || body.contains("No orderbook") {
            info!(token_id = %token_id, "Orderbook does not exist");
            return Ok(false);
        }

        if !status.is_success() {
            // Other API errors
            return Err(PolymarketError::api(status.as_u16(), body));
        }

        // If we got here, the orderbook exists
        debug!(token_id = %token_id, "Orderbook exists");
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clob_config_default() {
        let config = ClobConfig::default();
        // URL uses helper function which may be overridden by env var
        assert_eq!(config.base_url, clob_api_url());
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.rate_limit_per_second, 5);
    }

    #[test]
    fn test_clob_config_with_base_url() {
        let config = ClobConfig::default().with_base_url("https://custom.example.com");
        assert_eq!(config.base_url, "https://custom.example.com");
    }
}
