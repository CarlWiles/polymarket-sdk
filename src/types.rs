//! Common types for Polymarket SDK
//!
//! This module contains shared types used across different API clients,
//! including trading types, market data structures, and authentication types.

#[cfg(feature = "auth")]
use alloy_primitives::U256;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::str::FromStr;

// ============================================================================
// Trading Types
// ============================================================================

/// Trading side for orders
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Side {
    Buy,
    Sell,
}

impl Side {
    /// Get string representation
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Buy => "BUY",
            Self::Sell => "SELL",
        }
    }

    /// Get opposite side
    #[must_use]
    pub fn opposite(&self) -> Self {
        match self {
            Self::Buy => Self::Sell,
            Self::Sell => Self::Buy,
        }
    }
}

/// Order book level (price/size pair)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookLevel {
    #[serde(with = "rust_decimal::serde::str")]
    pub price: Decimal,
    #[serde(with = "rust_decimal::serde::str")]
    pub size: Decimal,
}

// ============================================================================
// Authentication Types
// ============================================================================

/// API credentials for Polymarket authentication
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApiCredentials {
    /// API key
    #[serde(rename = "apiKey")]
    pub api_key: String,
    /// API secret (base64 encoded)
    pub secret: String,
    /// API passphrase
    pub passphrase: String,
}

impl ApiCredentials {
    /// Create new API credentials
    #[must_use]
    pub fn new(
        api_key: impl Into<String>,
        secret: impl Into<String>,
        passphrase: impl Into<String>,
    ) -> Self {
        Self {
            api_key: api_key.into(),
            secret: secret.into(),
            passphrase: passphrase.into(),
        }
    }

    /// Check if credentials are configured
    #[must_use]
    pub fn is_configured(&self) -> bool {
        !self.api_key.is_empty() && !self.secret.is_empty() && !self.passphrase.is_empty()
    }
}

// ============================================================================
// Order Types
// ============================================================================

/// Configuration options for order creation
#[derive(Debug, Clone, Default)]
pub struct OrderOptions {
    /// Tick size for price rounding
    pub tick_size: Option<Decimal>,
    /// Whether to use negative risk contracts
    pub neg_risk: Option<bool>,
    /// Fee rate in basis points
    pub fee_rate_bps: Option<u32>,
}

impl OrderOptions {
    /// Create new order options
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set tick size
    #[must_use]
    pub fn with_tick_size(mut self, tick_size: Decimal) -> Self {
        self.tick_size = Some(tick_size);
        self
    }

    /// Set negative risk flag
    #[must_use]
    pub fn with_neg_risk(mut self, neg_risk: bool) -> Self {
        self.neg_risk = Some(neg_risk);
        self
    }

    /// Set fee rate in basis points
    #[must_use]
    pub fn with_fee_rate_bps(mut self, fee_rate_bps: u32) -> Self {
        self.fee_rate_bps = Some(fee_rate_bps);
        self
    }
}

/// Extra arguments for order creation
#[cfg(feature = "auth")]
#[derive(Debug, Clone)]
pub struct ExtraOrderArgs {
    /// Fee rate in basis points
    pub fee_rate_bps: u32,
    /// Nonce for replay protection
    pub nonce: U256,
    /// Taker address (usually zero address)
    pub taker: String,
}

#[cfg(feature = "auth")]
impl Default for ExtraOrderArgs {
    fn default() -> Self {
        Self {
            fee_rate_bps: 0,
            nonce: U256::ZERO,
            taker: "0x0000000000000000000000000000000000000000".to_string(),
        }
    }
}

#[cfg(feature = "auth")]
impl ExtraOrderArgs {
    /// Create new extra order args
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set fee rate in basis points
    #[must_use]
    pub fn with_fee_rate_bps(mut self, fee_rate_bps: u32) -> Self {
        self.fee_rate_bps = fee_rate_bps;
        self
    }

    /// Set nonce
    #[must_use]
    pub fn with_nonce(mut self, nonce: U256) -> Self {
        self.nonce = nonce;
        self
    }

    /// Set taker address
    #[must_use]
    pub fn with_taker(mut self, taker: impl Into<String>) -> Self {
        self.taker = taker.into();
        self
    }
}

/// Market order arguments
#[derive(Debug, Clone)]
pub struct MarketOrderArgs {
    /// Token ID (condition token)
    pub token_id: String,
    /// Amount to trade
    pub amount: Decimal,
}

impl MarketOrderArgs {
    /// Create new market order args
    #[must_use]
    pub fn new(token_id: impl Into<String>, amount: Decimal) -> Self {
        Self {
            token_id: token_id.into(),
            amount,
        }
    }
}

/// Signed order request ready for submission
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedOrderRequest {
    /// Random salt for uniqueness
    pub salt: u64,
    /// Maker/funder address
    pub maker: String,
    /// Signer address
    pub signer: String,
    /// Taker address (usually zero)
    pub taker: String,
    /// Token ID
    pub token_id: String,
    /// Maker amount in token units
    pub maker_amount: String,
    /// Taker amount in token units
    pub taker_amount: String,
    /// Expiration timestamp
    pub expiration: String,
    /// Nonce for replay protection
    pub nonce: String,
    /// Fee rate in basis points
    pub fee_rate_bps: String,
    /// Order side (BUY/SELL)
    pub side: String,
    /// Signature type
    pub signature_type: u8,
    /// EIP-712 signature
    pub signature: String,
}

/// Order type for CLOB orders
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum OrderType {
    /// Good Till Cancelled (default for limit orders)
    GTC,
    /// Fill Or Kill (for market orders)
    FOK,
    /// Good Till Date
    GTD,
    /// Fill And Kill
    FAK,
}

impl Default for OrderType {
    fn default() -> Self {
        OrderType::GTC
    }
}

/// NewOrder is the payload structure for posting orders to the Polymarket API
/// It wraps order data with orderType, owner, and deferExec fields
/// IMPORTANT: Field order MUST match TypeScript SDK for HMAC signature compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewOrder {
    /// Whether to defer execution (MUST be first field for JSON field order)
    #[serde(default)]
    pub defer_exec: bool,
    /// The order data
    pub order: NewOrderData,
    /// Owner - should be the API key, NOT the wallet address
    pub owner: String,
    /// Order type (GTC, FOK, etc.)
    pub order_type: OrderType,

    pub post_only: bool,
}

/// NewOrderData contains the actual order fields
/// Note: salt must be a number (i64) in JSON, not a string
/// IMPORTANT: Field order MUST match TypeScript SDK for HMAC signature compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewOrderData {
    /// Random salt for uniqueness - MUST be a number in JSON
    pub salt: i64,
    /// Maker/funder address
    pub maker: String,
    /// Signer address
    pub signer: String,
    /// Taker address (usually zero)
    pub taker: String,
    /// Token ID
    pub token_id: String,
    /// Maker amount in token units
    pub maker_amount: String,
    /// Taker amount in token units
    pub taker_amount: String,
    /// Order side (BUY/SELL) - MUST come after takerAmount, before expiration
    pub side: String,
    /// Expiration timestamp
    pub expiration: String,
    /// Nonce for replay protection
    pub nonce: String,
    /// Fee rate in basis points
    pub fee_rate_bps: String,
    /// Signature type (0=EOA, 1=PolyProxy, 2=PolyGnosisSafe)
    pub signature_type: u8,
    /// EIP-712 signature
    pub signature: String,
}

impl NewOrder {
    /// Convert SignedOrderRequest to NewOrder format for API submission
    /// Field initialization order matches struct field order for consistency
    pub fn from_signed_order(
        order: &SignedOrderRequest,
        api_key: &str,
        order_type: OrderType,
        defer_exec: bool,
        post_only: bool
    ) -> Self {
        NewOrder {
            defer_exec,
            order: NewOrderData {
                // Salt must be i64 for JSON serialization as number
                salt: order.salt as i64,
                maker: order.maker.clone(),
                signer: order.signer.clone(),
                taker: order.taker.clone(),
                token_id: order.token_id.clone(),
                maker_amount: order.maker_amount.clone(),
                taker_amount: order.taker_amount.clone(),
                side: order.side.clone(),
                expiration: order.expiration.clone(),
                nonce: order.nonce.clone(),
                fee_rate_bps: order.fee_rate_bps.clone(),
                signature_type: order.signature_type,
                signature: order.signature.clone(),
            },
            owner: api_key.to_string(),
            order_type,
            post_only,
        }
    }
}

// ============================================================================
// Market Types
// ============================================================================

/// Market token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Token ID (condition token)
    pub token_id: String,
    /// Outcome name (e.g., "Yes", "No")
    pub outcome: String,
    /// Current price if available
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, deserialize_with = "deserialize_decimal_opt")]
    pub price: Option<Decimal>,
}

/// Market information from Gamma API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Market {
    /// Condition ID (market identifier)
    pub condition_id: String,
    /// Market slug for URL
    pub slug: String,
    /// Market question/title
    #[serde(default)]
    pub question: Option<String>,
    /// Market description
    #[serde(default)]
    pub description: Option<String>,
    /// Category/tag
    #[serde(default)]
    pub category: Option<String>,
    /// Whether market is active
    pub active: bool,
    /// Whether market is closed
    pub closed: bool,
    /// Market end date
    #[serde(default)]
    pub end_date: Option<String>,
    /// Market icon URL
    #[serde(default)]
    pub icon: Option<String>,
    /// CLOB token IDs (JSON string array)
    #[serde(default)]
    pub clob_token_ids: Option<String>,
    /// Outcomes (JSON string array)
    #[serde(default)]
    pub outcomes: Option<String>,
    /// Outcome prices (JSON string array, e.g. "[\"0.95\", \"0.05\"]")
    #[serde(default)]
    pub outcome_prices: Option<String>,
    /// Liquidity
    #[serde(default, deserialize_with = "deserialize_decimal_opt")]
    pub liquidity_num: Option<Decimal>,
    /// 24-hour volume
    #[serde(
        default,
        rename = "volume24hr",
        deserialize_with = "deserialize_decimal_opt"
    )]
    pub volume_24hr: Option<Decimal>,
    /// Total volume
    #[serde(default, deserialize_with = "deserialize_decimal_opt")]
    pub volume_num: Option<Decimal>,
    /// Minimum order size
    #[serde(default, deserialize_with = "deserialize_decimal_opt")]
    pub order_min_size: Option<Decimal>,
    /// Price tick size
    #[serde(
        default,
        rename = "orderPriceMinTickSize",
        deserialize_with = "deserialize_decimal_opt"
    )]
    pub order_tick_size: Option<Decimal>,
}

impl Market {
    /// Parse CLOB token IDs from JSON string
    #[must_use]
    pub fn parse_token_ids(&self) -> Vec<String> {
        self.clob_token_ids
            .as_ref()
            .and_then(|raw| serde_json::from_str(raw).ok())
            .unwrap_or_default()
    }

    /// Parse outcomes from JSON string
    #[must_use]
    pub fn parse_outcomes(&self) -> Vec<String> {
        self.outcomes
            .as_ref()
            .and_then(|raw| serde_json::from_str(raw).ok())
            .unwrap_or_else(|| vec!["Yes".to_string(), "No".to_string()])
    }

    /// Parse outcome prices from JSON string
    /// Returns (yes_price, no_price) as `Option<f64>` values
    #[must_use]
    pub fn parse_outcome_prices(&self) -> (Option<f64>, Option<f64>) {
        let prices: Vec<String> = self
            .outcome_prices
            .as_ref()
            .and_then(|raw| serde_json::from_str(raw).ok())
            .unwrap_or_default();

        let yes_price = prices.first().and_then(|s| s.parse::<f64>().ok());
        let no_price = prices.get(1).and_then(|s| s.parse::<f64>().ok());

        (yes_price, no_price)
    }
}

/// Deserialize Option<Decimal> from string/number/null.
fn deserialize_decimal_opt<'de, D>(deserializer: D) -> Result<Option<Decimal>, D::Error>
where
    D: Deserializer<'de>,
{
    match Value::deserialize(deserializer)? {
        Value::Null => Ok(None),
        Value::String(s) => {
            if s.is_empty() {
                Ok(None)
            } else {
                Decimal::from_str(&s).map(Some).map_err(de::Error::custom)
            }
        }
        Value::Number(n) => Decimal::from_str(&n.to_string())
            .map(Some)
            .map_err(de::Error::custom),
        other => Err(de::Error::custom(format!("expected decimal, got {other}"))),
    }
}

/// Event metadata from Gamma API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Event ID
    pub id: String,
    /// Event slug
    pub slug: String,
    /// Event name
    #[serde(default)]
    pub name: Option<String>,
    /// Event description
    #[serde(default)]
    pub description: Option<String>,
    /// Whether event is active
    #[serde(default)]
    pub active: Option<bool>,
    /// Whether event is closed
    #[serde(default)]
    pub closed: Option<bool>,
    /// Start date
    #[serde(default)]
    pub start_date_iso: Option<String>,
    /// End date
    #[serde(default)]
    pub end_date_iso: Option<String>,
    /// Sport type (for sports events)
    #[serde(default)]
    pub sport: Option<String>,
    /// Associated markets
    #[serde(default)]
    pub markets: Vec<EventMarket>,
}

/// Lightweight market info in events
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventMarket {
    /// Condition ID
    pub condition_id: String,
    /// Market ID
    #[serde(default)]
    pub market_id: Option<String>,
    /// CLOB token IDs
    #[serde(default)]
    pub clob_token_ids: Option<String>,
    /// Market slug
    #[serde(default)]
    pub slug: Option<String>,
}

/// Tag metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    /// Tag ID
    #[serde(default)]
    pub id: Option<String>,
    /// Tag slug
    #[serde(default)]
    pub slug: Option<String>,
    /// Tag name
    #[serde(default)]
    pub name: Option<String>,
    /// Tag description
    #[serde(default)]
    pub description: Option<String>,
}

// ============================================================================
// Profile Types
// ============================================================================

/// Trader profile information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraderProfile {
    /// Wallet address
    pub address: String,
    /// Display name
    #[serde(default)]
    pub name: Option<String>,
    /// Username/pseudonym
    #[serde(default)]
    pub username: Option<String>,
    /// Profile image URL
    #[serde(default, rename = "profileImage")]
    pub profile_image: Option<String>,
    /// Bio/description
    #[serde(default)]
    pub bio: Option<String>,
    /// Total volume traded
    #[serde(default)]
    pub volume: Option<Decimal>,
    /// Number of markets traded
    #[serde(default, rename = "marketsTraded")]
    pub markets_traded: Option<i32>,
    /// Profit and loss
    #[serde(default)]
    pub pnl: Option<Decimal>,
}

/// Leaderboard entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderboardEntry {
    /// Rank position
    pub rank: i32,
    /// Wallet address
    pub address: String,
    /// Display name
    #[serde(default)]
    pub name: Option<String>,
    /// Username
    #[serde(default)]
    pub username: Option<String>,
    /// Profile image
    #[serde(default, rename = "profileImage")]
    pub profile_image: Option<String>,
    /// Volume for the period
    pub volume: Decimal,
    /// Profit for the period
    #[serde(default)]
    pub profit: Option<Decimal>,
}

// ============================================================================
// Query Parameter Types
// ============================================================================

/// Pagination parameters
#[derive(Debug, Clone, Default)]
pub struct PaginationParams {
    /// Maximum number of results
    pub limit: Option<u32>,
    /// Offset for pagination
    pub offset: Option<u32>,
    /// Cursor for cursor-based pagination
    pub cursor: Option<String>,
}

impl PaginationParams {
    /// Create new pagination params
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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

    /// Set cursor
    #[must_use]
    pub fn with_cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }
}

/// Common query parameters for listing endpoints
#[derive(Debug, Clone, Default)]
pub struct ListParams {
    /// Pagination
    pub pagination: PaginationParams,
    /// Filter by closed status
    pub closed: Option<bool>,
    /// Filter by active status
    pub active: Option<bool>,
    /// Sort field
    pub order: Option<String>,
    /// Sort ascending
    pub ascending: Option<bool>,
}

impl ListParams {
    /// Create new list params
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set limit
    #[must_use]
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.pagination.limit = Some(limit);
        self
    }

    /// Set offset
    #[must_use]
    pub fn with_offset(mut self, offset: u32) -> Self {
        self.pagination.offset = Some(offset);
        self
    }

    /// Filter by closed status
    #[must_use]
    pub fn with_closed(mut self, closed: bool) -> Self {
        self.closed = Some(closed);
        self
    }

    /// Filter by active status
    #[must_use]
    pub fn with_active(mut self, active: bool) -> Self {
        self.active = Some(active);
        self
    }

    /// Set sort order
    #[must_use]
    pub fn with_order(mut self, field: impl Into<String>, ascending: bool) -> Self {
        self.order = Some(field.into());
        self.ascending = Some(ascending);
        self
    }
}

// ============================================================================
// Connection Statistics
// ============================================================================

/// WebSocket connection statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Number of messages received
    pub messages_received: u64,
    /// Number of reconnection attempts
    pub reconnect_attempts: u32,
    /// Last message timestamp
    pub last_message_at: Option<DateTime<Utc>>,
    /// Connection established timestamp
    pub connected_at: Option<DateTime<Utc>>,
}

impl ConnectionStats {
    /// Create new stats
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a message received
    pub fn record_message(&mut self) {
        self.messages_received += 1;
        self.last_message_at = Some(Utc::now());
    }

    /// Record a reconnection attempt
    pub fn record_reconnect(&mut self) {
        self.reconnect_attempts += 1;
    }

    /// Record connection established
    pub fn record_connected(&mut self) {
        self.connected_at = Some(Utc::now());
        self.reconnect_attempts = 0;
    }
}

// ============================================================================
// Data API Types (for data-api.polymarket.com)
// ============================================================================

/// Polymarket trader profile from Data API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataApiTrader {
    /// Wallet address
    pub address: String,
    /// Display name
    #[serde(rename = "displayName", default)]
    pub display_name: Option<String>,
    /// Profile image URL
    #[serde(rename = "profileImage", default)]
    pub profile_image: Option<String>,
    /// Total PnL (as string)
    #[serde(rename = "totalPnl", default)]
    pub total_pnl: Option<String>,
    /// Total volume (as string)
    #[serde(rename = "totalVolume", default)]
    pub total_volume: Option<String>,
    /// Number of markets traded
    #[serde(rename = "marketsTraded", default)]
    pub markets_traded: Option<i32>,
    /// Win rate (0.0-1.0)
    #[serde(rename = "winRate", default)]
    pub win_rate: Option<f64>,
}

/// Polymarket position from Data API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataApiPosition {
    /// Position ID
    pub id: String,
    /// Market condition ID
    #[serde(rename = "conditionId")]
    pub condition_id: String,
    /// Outcome (Yes/No)
    pub outcome: String,
    /// Position size
    pub size: String,
    /// Average entry price
    #[serde(rename = "avgPrice")]
    pub avg_price: String,
    /// Current value
    #[serde(rename = "currentValue", default)]
    pub current_value: Option<String>,
    /// Realized PnL
    #[serde(rename = "realizedPnl", default)]
    pub realized_pnl: Option<String>,
    /// Position status
    pub status: String,
    /// Created timestamp
    #[serde(rename = "createdAt", default)]
    pub created_at: Option<String>,
    /// Closed timestamp
    #[serde(rename = "closedAt", default)]
    pub closed_at: Option<String>,
}

/// Polymarket trade from Data API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataApiTrade {
    /// Trade ID
    pub id: String,
    /// Market condition ID
    #[serde(rename = "conditionId")]
    pub condition_id: String,
    /// Maker address
    pub maker: String,
    /// Taker address
    pub taker: String,
    /// Trade side
    pub side: String,
    /// Outcome
    pub outcome: String,
    /// Trade size
    pub size: String,
    /// Trade price
    pub price: String,
    /// Trade timestamp
    pub timestamp: String,
    /// Transaction hash
    #[serde(rename = "transactionHash", default)]
    pub transaction_hash: Option<String>,
}

/// User activity (trade/position change) from Data API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataApiActivity {
    /// Transaction hash
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    /// Activity timestamp (unix)
    pub timestamp: i64,
    /// User's proxy wallet address
    #[serde(rename = "proxyWallet")]
    pub proxy_wallet: String,
    /// User display name
    #[serde(default)]
    pub name: Option<String>,
    /// User pseudonym
    #[serde(default)]
    pub pseudonym: Option<String>,
    /// User bio
    #[serde(default)]
    pub bio: Option<String>,
    /// User profile image
    #[serde(rename = "profileImage", default)]
    pub profile_image: Option<String>,
    /// Optimized profile image
    #[serde(rename = "profileImageOptimized", default)]
    pub profile_image_optimized: Option<String>,
    /// Trade side (BUY/SELL)
    pub side: String,
    /// Outcome (Yes/No)
    pub outcome: String,
    /// Outcome index (0 or 1)
    #[serde(rename = "outcomeIndex")]
    pub outcome_index: i32,
    /// Trade price
    pub price: f64,
    /// Trade size
    pub size: f64,
    /// USDC size
    #[serde(rename = "usdcSize", default)]
    pub usdc_size: Option<f64>,
    /// Asset/token ID
    pub asset: String,
    /// Market condition ID
    #[serde(rename = "conditionId")]
    pub condition_id: String,
    /// Market title
    pub title: String,
    /// Market slug
    pub slug: String,
    /// Event slug
    #[serde(rename = "eventSlug")]
    pub event_slug: String,
    /// Market icon
    #[serde(default)]
    pub icon: Option<String>,
}

/// Biggest Winner entry from Data API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiggestWinner {
    /// Rank (string format)
    #[serde(rename = "winRank")]
    pub win_rank: String,
    /// Wallet address (0x...)
    #[serde(rename = "proxyWallet")]
    pub proxy_wallet: String,
    /// User name
    #[serde(rename = "userName", default)]
    pub user_name: String,
    /// Event slug
    #[serde(rename = "eventSlug")]
    pub event_slug: String,
    /// Event title
    #[serde(rename = "eventTitle")]
    pub event_title: String,
    /// Initial value (USD)
    #[serde(rename = "initialValue")]
    pub initial_value: f64,
    /// Final value (USD)
    #[serde(rename = "finalValue")]
    pub final_value: f64,
    /// Realized profit (USD)
    pub pnl: f64,
    /// Profile image URL
    #[serde(rename = "profileImage", default)]
    pub profile_image: String,
}

/// Query parameters for biggest winners API
#[derive(Debug, Clone)]
pub struct BiggestWinnersQuery {
    /// Time period: day, week, month, all_time
    pub time_period: String,
    /// Max results (max 100 per request)
    pub limit: usize,
    /// Pagination offset
    pub offset: usize,
    /// Category filter (lowercase): all, politics, sports, crypto, etc.
    pub category: String,
}

impl Default for BiggestWinnersQuery {
    fn default() -> Self {
        Self {
            time_period: "all_time".to_string(),
            limit: 100,
            offset: 0,
            category: "all".to_string(),
        }
    }
}

impl BiggestWinnersQuery {
    /// Create new query with defaults
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set time period
    #[must_use]
    pub fn with_time_period(mut self, period: impl Into<String>) -> Self {
        self.time_period = period.into();
        self
    }

    /// Set limit
    #[must_use]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Set offset
    #[must_use]
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = offset;
        self
    }

    /// Set category
    #[must_use]
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = category.into();
        self
    }
}

// ============================================================================
// Public Search API Types
// ============================================================================

/// Search request parameters for /public-search endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchRequest {
    /// Search query string
    pub q: String,
    /// Limit per result type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_per_type: Option<u32>,
    /// Whether to search profiles (traders)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_profiles: Option<bool>,
    /// Whether to search tags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_tags: Option<bool>,
}

impl SearchRequest {
    /// Create a new search request
    #[must_use]
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            q: query.into(),
            limit_per_type: None,
            search_profiles: None,
            search_tags: None,
        }
    }

    /// Set limit per type
    #[must_use]
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit_per_type = Some(limit);
        self
    }

    /// Set whether to search profiles
    #[must_use]
    pub fn with_profiles(mut self, search_profiles: bool) -> Self {
        self.search_profiles = Some(search_profiles);
        self
    }

    /// Set whether to search tags
    #[must_use]
    pub fn with_tags(mut self, search_tags: bool) -> Self {
        self.search_tags = Some(search_tags);
        self
    }
}

/// Search response from /public-search endpoint
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SearchResponse {
    /// Matching events/markets
    #[serde(default)]
    pub events: Vec<SearchEvent>,
    /// Matching profiles/traders
    #[serde(default)]
    pub profiles: Vec<SearchProfile>,
    /// Matching tags
    #[serde(default)]
    pub tags: Vec<SearchTag>,
}

/// Search event result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchEvent {
    /// Event ID
    #[serde(default)]
    pub id: String,
    /// Event slug
    #[serde(default)]
    pub slug: String,
    /// Event question/title
    #[serde(default)]
    pub question: Option<String>,
    /// Event image
    #[serde(default)]
    pub image: Option<String>,
    /// Whether event is active
    #[serde(default)]
    pub active: bool,
    /// Whether event is closed
    #[serde(default)]
    pub closed: bool,
    /// Total volume
    #[serde(default)]
    pub volume: f64,
    /// 24-hour volume
    #[serde(rename = "volume24hr", default)]
    pub volume_24hr: Option<f64>,
    /// End date
    #[serde(rename = "endDate", default)]
    pub end_date: Option<String>,
}

/// Search profile/trader result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchProfile {
    /// Profile ID
    #[serde(default)]
    pub id: Option<String>,
    /// Display name
    #[serde(default)]
    pub name: Option<String>,
    /// Old API field: imageURI
    #[serde(rename = "imageURI", default)]
    pub image_uri: Option<String>,
    /// New API field: profileImage
    #[serde(rename = "profileImage", default)]
    pub profile_image: Option<String>,
    /// Bio/description
    #[serde(default)]
    pub bio: Option<String>,
    /// Pseudonym
    #[serde(default)]
    pub pseudonym: Option<String>,
    /// Whether to display username publicly
    #[serde(rename = "displayUsernamePublic", default)]
    pub display_username_public: bool,
    /// Old API field: walletAddress
    #[serde(rename = "walletAddress", default)]
    pub wallet_address: Option<String>,
    /// New API field: proxyWallet
    #[serde(rename = "proxyWallet", default)]
    pub proxy_wallet: Option<String>,
}

impl SearchProfile {
    /// Get wallet address (prefer proxy_wallet, fallback to wallet_address)
    #[must_use]
    pub fn get_wallet_address(&self) -> Option<String> {
        self.proxy_wallet
            .clone()
            .or_else(|| self.wallet_address.clone())
    }

    /// Get profile image (prefer profile_image, fallback to image_uri)
    #[must_use]
    pub fn get_profile_image(&self) -> Option<String> {
        self.profile_image
            .clone()
            .or_else(|| self.image_uri.clone())
    }

    /// Get display name (prefer name, fallback to pseudonym)
    #[must_use]
    pub fn get_display_name(&self) -> Option<String> {
        self.name.clone().or_else(|| self.pseudonym.clone())
    }
}

/// Search tag result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchTag {
    /// Tag ID
    pub id: String,
    /// Tag label
    pub label: String,
    /// Tag slug
    #[serde(default)]
    pub slug: Option<String>,
}

/// Closed position from Data API (for PnL calculation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosedPosition {
    /// Position ID
    #[serde(default)]
    pub id: Option<String>,
    /// Proxy wallet address
    #[serde(rename = "proxyWallet", default)]
    pub proxy_wallet: Option<String>,
    /// Token asset ID
    #[serde(default)]
    pub asset: Option<String>,
    /// Market condition ID
    #[serde(rename = "conditionId")]
    pub condition_id: String,
    /// Market title
    pub title: String,
    /// Market slug
    pub slug: String,
    /// Event slug
    #[serde(rename = "eventSlug")]
    pub event_slug: String,
    /// Outcome (Yes/No)
    pub outcome: String,
    /// Outcome index
    #[serde(rename = "outcomeIndex")]
    pub outcome_index: i32,
    /// Entry price
    #[serde(rename = "avgPrice")]
    pub avg_price: f64,
    /// Current price
    #[serde(rename = "curPrice", default)]
    pub cur_price: Option<f64>,
    /// Exit price
    #[serde(rename = "exitPrice", default)]
    pub exit_price: Option<f64>,
    /// Position size (shares)
    #[serde(default)]
    pub size: Option<f64>,
    /// Total bought amount (USDC)
    #[serde(rename = "totalBought", default)]
    pub total_bought: Option<f64>,
    /// Realized PnL
    #[serde(rename = "realizedPnl", default)]
    pub realized_pnl: Option<f64>,
    /// Cash out amount
    #[serde(rename = "cashOut", default)]
    pub cash_out: Option<f64>,
    /// Is winning position
    #[serde(rename = "isWinner", default)]
    pub is_winner: Option<bool>,
    /// Closed timestamp (unix)
    #[serde(default)]
    pub timestamp: Option<i64>,
    /// Closed timestamp (ISO string)
    #[serde(rename = "closedAt", default)]
    pub closed_at: Option<String>,
    /// End date
    #[serde(rename = "endDate", default)]
    pub end_date: Option<String>,
    /// Market icon
    #[serde(default)]
    pub icon: Option<String>,
    /// Opposite outcome name
    #[serde(rename = "oppositeOutcome", default)]
    pub opposite_outcome: Option<String>,
    /// Opposite asset ID
    #[serde(rename = "oppositeAsset", default)]
    pub opposite_asset: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that NewOrder JSON serialization matches TypeScript SDK field order
    /// This is critical for HMAC signature compatibility
    #[test]
    fn test_new_order_json_field_order() {
        let order = NewOrder {
            defer_exec: false,
            order: NewOrderData {
                salt: 2915952280710976,
                maker: "0xc2ca793cf057d48a054bedabf625f301b40d38aa".to_string(),
                signer: "0xd13765b3e68431bf2b6e9994a0f4c3d2495799e9".to_string(),
                taker: "0x0000000000000000000000000000000000000000".to_string(),
                token_id: "21489772516410038586556744342392982044189999368638682594741395650226594484811".to_string(),
                maker_amount: "10000".to_string(),
                taker_amount: "1000000".to_string(),
                side: "BUY".to_string(),
                expiration: "0".to_string(),
                nonce: "0".to_string(),
                fee_rate_bps: "0".to_string(),
                signature_type: 1,
                signature: "0x0cfb0e318afe33e1189f23d4b11a1092963865d7ff7f7a035110d50d71a2ab484ae4828b3fcfcac2ada92fbd825eedfe4eb21d4e1cdd5aa1a47e23bf5d539b781c".to_string(),
            },
            owner: "fe9fb6b1-9ae6-6c5b-3cca-1ace6a8b1f29".to_string(),
            order_type: OrderType::GTC,
        };

        let json = serde_json::to_string(&order).unwrap();

        // Expected format from TypeScript SDK (field order matters for HMAC)
        let expected = r#"{"deferExec":false,"order":{"salt":2915952280710976,"maker":"0xc2ca793cf057d48a054bedabf625f301b40d38aa","signer":"0xd13765b3e68431bf2b6e9994a0f4c3d2495799e9","taker":"0x0000000000000000000000000000000000000000","tokenId":"21489772516410038586556744342392982044189999368638682594741395650226594484811","makerAmount":"10000","takerAmount":"1000000","side":"BUY","expiration":"0","nonce":"0","feeRateBps":"0","signatureType":1,"signature":"0x0cfb0e318afe33e1189f23d4b11a1092963865d7ff7f7a035110d50d71a2ab484ae4828b3fcfcac2ada92fbd825eedfe4eb21d4e1cdd5aa1a47e23bf5d539b781c"},"owner":"fe9fb6b1-9ae6-6c5b-3cca-1ace6a8b1f29","orderType":"GTC"}"#;

        assert_eq!(
            json, expected,
            "\nJSON field order mismatch!\n\nGot:\n{}\n\nExpected:\n{}\n",
            json, expected
        );
    }
}
