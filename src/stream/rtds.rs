//! WebSocket Streaming Module
//!
//! Provides high-performance WebSocket streaming for Polymarket data:
//!
//! - **RTDS Client**: Real-Time Data Stream for trade activity (`wss://ws-live-data.polymarket.com`)
//! - **WebSocket Stream**: Generic WebSocket streaming with auto-reconnect
//! - **Stream Manager**: Multi-stream management and aggregation
//!
//! ## RTDS Example
//!
//! ```rust,ignore
//! use polymarket_sdk::ws::{RtdsClient, RtdsConfig, RtdsEvent};
//!
//! let config = RtdsConfig::default();
//! let mut client = RtdsClient::new(config);
//!
//! let mut rx = client.connect().await?;
//! while let Some(event) = rx.recv().await {
//!     match event {
//!         RtdsEvent::Trade(trade) => {
//!             println!("Trade: {} {} @ {}",
//!                 trade.display_name(),
//!                 trade.side.as_deref().unwrap_or("?"),
//!                 trade.price.unwrap_or(0.0)
//!             );
//!         }
//!         RtdsEvent::Connected => println!("Connected!"),
//!         _ => {}
//!     }
//! }
//! ```
//!
//! ## Generic WebSocket Stream Example
//!
//! ```rust,ignore
//! use polymarket_sdk::ws::{WebSocketStream, MarketStream};
//! use futures::StreamExt;
//!
//! let mut stream = WebSocketStream::new("wss://example.com/ws");
//! // ... subscribe and process messages
//! ```

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use futures::{SinkExt, Stream, StreamExt};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time::{interval, sleep};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Error as WsError, Message},
};
use tracing::{debug, error, info, trace, warn};

use crate::core::rtds_wss_url;
use crate::core::{PolymarketError, Result, StreamErrorKind};
use crate::types::{ConnectionStats, Side};

// ============================================================================
// Stream Types and Messages
// ============================================================================

/// Stream message types for WebSocket events
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StreamMessage {
    /// Order book update
    #[serde(rename = "book_update")]
    BookUpdate { data: OrderDelta },
    /// Trade event
    #[serde(rename = "trade")]
    Trade { data: FillEvent },
    /// Order update
    #[serde(rename = "order_update")]
    OrderUpdate { data: OrderData },
    /// Heartbeat message
    #[serde(rename = "heartbeat")]
    Heartbeat { timestamp: DateTime<Utc> },
    /// User channel order update
    #[serde(rename = "user_order_update")]
    UserOrderUpdate { data: OrderData },
    /// User channel trade
    #[serde(rename = "user_trade")]
    UserTrade { data: FillEvent },
    /// Market channel book update
    #[serde(rename = "market_book_update")]
    MarketBookUpdate { data: OrderDelta },
    /// Market channel trade
    #[serde(rename = "market_trade")]
    MarketTrade { data: FillEvent },
}

/// Order book delta for streaming updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderDelta {
    /// Token ID
    pub token_id: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Side (BUY/SELL)
    pub side: Side,
    /// Price
    #[serde(with = "rust_decimal::serde::str")]
    pub price: Decimal,
    /// Size (0 means remove level)
    #[serde(with = "rust_decimal::serde::str")]
    pub size: Decimal,
    /// Sequence number
    pub sequence: u64,
}

/// Fill/trade event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FillEvent {
    /// Event ID
    pub id: String,
    /// Order ID
    pub order_id: String,
    /// Token ID
    pub token_id: String,
    /// Side
    pub side: Side,
    /// Price
    #[serde(with = "rust_decimal::serde::str")]
    pub price: Decimal,
    /// Size
    #[serde(with = "rust_decimal::serde::str")]
    pub size: Decimal,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Maker address
    #[serde(default)]
    pub maker_address: Option<String>,
    /// Taker address
    #[serde(default)]
    pub taker_address: Option<String>,
    /// Fee
    #[serde(default)]
    pub fee: Option<Decimal>,
}

/// Order data for streaming updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderData {
    /// Order ID
    pub id: String,
    /// Token ID
    pub token_id: String,
    /// Side
    pub side: Side,
    /// Price
    #[serde(with = "rust_decimal::serde::str")]
    pub price: Decimal,
    /// Original size
    #[serde(with = "rust_decimal::serde::str")]
    pub original_size: Decimal,
    /// Filled size
    #[serde(with = "rust_decimal::serde::str")]
    pub filled_size: Decimal,
    /// Remaining size
    #[serde(with = "rust_decimal::serde::str")]
    pub remaining_size: Decimal,
    /// Status
    pub status: String,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Updated at
    pub updated_at: DateTime<Utc>,
}

// ============================================================================
// WebSocket Authentication
// ============================================================================

/// WebSocket authentication for Polymarket API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WssAuth {
    /// User's Ethereum address
    pub address: String,
    /// EIP-712 signature
    pub signature: String,
    /// Unix timestamp
    pub timestamp: u64,
    /// Nonce for replay protection
    pub nonce: String,
}

/// WebSocket subscription request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WssSubscription {
    /// Authentication information
    pub auth: WssAuth,
    /// Array of markets (condition IDs) for USER channel
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markets: Option<Vec<String>>,
    /// Array of asset IDs (token IDs) for MARKET channel
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_ids: Option<Vec<String>>,
    /// Channel type: "USER" or "MARKET"
    #[serde(rename = "type")]
    pub channel_type: String,
}

/// Subscription parameters for streaming
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    /// Token IDs to subscribe
    pub token_ids: Vec<String>,
    /// Channels to subscribe
    pub channels: Vec<String>,
}

// ============================================================================
// Stream Statistics
// ============================================================================

/// Stream statistics for monitoring
#[derive(Debug, Clone, Default)]
pub struct StreamStats {
    /// Messages received count
    pub messages_received: u64,
    /// Messages sent count
    pub messages_sent: u64,
    /// Error count
    pub errors: u64,
    /// Last message timestamp
    pub last_message_time: Option<DateTime<Utc>>,
    /// Connection uptime
    pub connection_uptime: Duration,
    /// Reconnection count
    pub reconnect_count: u32,
}

impl StreamStats {
    /// Create new stats
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a message received
    pub fn record_message(&mut self) {
        self.messages_received += 1;
        self.last_message_time = Some(Utc::now());
    }

    /// Record a message sent
    pub fn record_sent(&mut self) {
        self.messages_sent += 1;
    }

    /// Record an error
    pub fn record_error(&mut self) {
        self.errors += 1;
    }

    /// Record a reconnection
    pub fn record_reconnect(&mut self) {
        self.reconnect_count += 1;
    }
}

// ============================================================================
// MarketStream Trait
// ============================================================================

/// Trait for market data streams
pub trait MarketStream: Stream<Item = Result<StreamMessage>> + Send + Sync {
    /// Subscribe to market data for specific tokens
    fn subscribe(&mut self, subscription: Subscription) -> Result<()>;

    /// Unsubscribe from market data
    fn unsubscribe(&mut self, token_ids: &[String]) -> Result<()>;

    /// Check if the stream is connected
    fn is_connected(&self) -> bool;

    /// Get connection statistics
    fn get_stats(&self) -> StreamStats;
}

// ============================================================================
// WebSocketStream - Generic WebSocket Client
// ============================================================================

/// WebSocket-based market stream implementation
#[derive(Debug)]
pub struct WebSocketStream {
    /// WebSocket connection
    connection: Option<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    /// URL for the WebSocket connection
    url: String,
    /// Authentication credentials
    auth: Option<WssAuth>,
    /// Current subscriptions
    subscriptions: Vec<WssSubscription>,
    /// Connection statistics
    stats: StreamStats,
    /// Timestamp when connection was established
    connected_since: Option<Instant>,
}

impl WebSocketStream {
    /// Create a new WebSocket stream
    #[must_use]
    pub fn new(url: &str) -> Self {
        Self {
            connection: None,
            url: url.to_string(),
            auth: None,
            subscriptions: Vec::new(),
            stats: StreamStats::new(),
            connected_since: None,
        }
    }

    /// Set authentication credentials
    #[must_use]
    pub fn with_auth(mut self, auth: WssAuth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Connect to the WebSocket
    pub async fn connect(&mut self) -> Result<()> {
        let (ws_stream, _) = tokio_tungstenite::connect_async(&self.url)
            .await
            .map_err(|e| {
                PolymarketError::stream(
                    format!("WebSocket connection failed: {}", e),
                    StreamErrorKind::ConnectionFailed,
                )
            })?;

        self.connection = Some(ws_stream);
        self.connected_since = Some(Instant::now());
        self.stats.connection_uptime = Duration::ZERO;
        info!("Connected to WebSocket stream at {}", self.url);
        Ok(())
    }

    /// Send a message to the WebSocket
    pub async fn send_message(&mut self, message: Value) -> Result<()> {
        if let Some(connection) = &mut self.connection {
            let text = serde_json::to_string(&message).map_err(|e| {
                PolymarketError::parse(format!("Failed to serialize message: {}", e))
            })?;

            let ws_message = Message::Text(text.into());
            connection.send(ws_message).await.map_err(|e| {
                PolymarketError::stream(
                    format!("Failed to send message: {}", e),
                    StreamErrorKind::MessageCorrupted,
                )
            })?;

            self.stats.record_sent();
        }
        Ok(())
    }

    /// Subscribe to market data using official Polymarket WebSocket API
    pub async fn subscribe_async(&mut self, subscription: WssSubscription) -> Result<()> {
        if self.connection.is_none() {
            self.connect().await?;
        }

        let message = serde_json::json!({
            "auth": subscription.auth,
            "markets": subscription.markets,
            "asset_ids": subscription.asset_ids,
            "type": subscription.channel_type,
        });

        self.send_message(message).await?;
        self.subscriptions.push(subscription.clone());

        info!("Subscribed to {} channel", subscription.channel_type);
        Ok(())
    }

    /// Subscribe to user channel (orders and trades)
    pub async fn subscribe_user_channel(&mut self, markets: Vec<String>) -> Result<()> {
        let auth = self
            .auth
            .as_ref()
            .ok_or_else(|| PolymarketError::auth("No authentication provided for WebSocket"))?
            .clone();

        let subscription = WssSubscription {
            auth,
            markets: Some(markets),
            asset_ids: None,
            channel_type: "USER".to_string(),
        };

        self.subscribe_async(subscription).await
    }

    /// Subscribe to market channel (order book and trades)
    pub async fn subscribe_market_channel(&mut self, asset_ids: Vec<String>) -> Result<()> {
        let auth = self
            .auth
            .as_ref()
            .ok_or_else(|| PolymarketError::auth("No authentication provided for WebSocket"))?
            .clone();

        let subscription = WssSubscription {
            auth,
            markets: None,
            asset_ids: Some(asset_ids),
            channel_type: "MARKET".to_string(),
        };

        self.subscribe_async(subscription).await
    }

    /// Unsubscribe from market data
    pub async fn unsubscribe_async(&mut self, token_ids: &[String]) -> Result<()> {
        self.subscriptions
            .retain(|sub| match sub.channel_type.as_str() {
                "USER" => {
                    if let Some(markets) = &sub.markets {
                        !token_ids.iter().any(|id| markets.contains(id))
                    } else {
                        true
                    }
                }
                "MARKET" => {
                    if let Some(asset_ids) = &sub.asset_ids {
                        !token_ids.iter().any(|id| asset_ids.contains(id))
                    } else {
                        true
                    }
                }
                _ => true,
            });

        info!("Unsubscribed from {} tokens", token_ids.len());
        Ok(())
    }

    fn update_connection_uptime(&mut self) {
        if let Some(started) = self.connected_since {
            self.stats.connection_uptime = started.elapsed();
        }
    }

    /// Parse Polymarket WebSocket message format
    fn parse_message(&self, text: &str) -> Result<StreamMessage> {
        let value: Value = serde_json::from_str(text).map_err(|e| {
            PolymarketError::parse(format!("Failed to parse WebSocket message: {}", e))
        })?;

        let message_type = value
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PolymarketError::parse("Missing 'type' field in WebSocket message"))?;

        match message_type {
            "book_update" => {
                let data =
                    serde_json::from_value(value.get("data").unwrap_or(&Value::Null).clone())
                        .map_err(|e| {
                            PolymarketError::parse(format!("Failed to parse book update: {}", e))
                        })?;
                Ok(StreamMessage::BookUpdate { data })
            }
            "trade" => {
                let data =
                    serde_json::from_value(value.get("data").unwrap_or(&Value::Null).clone())
                        .map_err(|e| {
                            PolymarketError::parse(format!("Failed to parse trade: {}", e))
                        })?;
                Ok(StreamMessage::Trade { data })
            }
            "order_update" => {
                let data =
                    serde_json::from_value(value.get("data").unwrap_or(&Value::Null).clone())
                        .map_err(|e| {
                            PolymarketError::parse(format!("Failed to parse order update: {}", e))
                        })?;
                Ok(StreamMessage::OrderUpdate { data })
            }
            "user_order_update" => {
                let data =
                    serde_json::from_value(value.get("data").unwrap_or(&Value::Null).clone())
                        .map_err(|e| {
                            PolymarketError::parse(format!(
                                "Failed to parse user order update: {}",
                                e
                            ))
                        })?;
                Ok(StreamMessage::UserOrderUpdate { data })
            }
            "user_trade" => {
                let data =
                    serde_json::from_value(value.get("data").unwrap_or(&Value::Null).clone())
                        .map_err(|e| {
                            PolymarketError::parse(format!("Failed to parse user trade: {}", e))
                        })?;
                Ok(StreamMessage::UserTrade { data })
            }
            "market_book_update" => {
                let data =
                    serde_json::from_value(value.get("data").unwrap_or(&Value::Null).clone())
                        .map_err(|e| {
                            PolymarketError::parse(format!(
                                "Failed to parse market book update: {}",
                                e
                            ))
                        })?;
                Ok(StreamMessage::MarketBookUpdate { data })
            }
            "market_trade" => {
                let data =
                    serde_json::from_value(value.get("data").unwrap_or(&Value::Null).clone())
                        .map_err(|e| {
                            PolymarketError::parse(format!("Failed to parse market trade: {}", e))
                        })?;
                Ok(StreamMessage::MarketTrade { data })
            }
            "heartbeat" => {
                let timestamp = value
                    .get("timestamp")
                    .and_then(|v| v.as_i64())
                    .and_then(|ts| DateTime::from_timestamp(ts, 0))
                    .unwrap_or_else(Utc::now);
                Ok(StreamMessage::Heartbeat { timestamp })
            }
            _ => {
                warn!("Unknown message type: {}", message_type);
                Ok(StreamMessage::Heartbeat {
                    timestamp: Utc::now(),
                })
            }
        }
    }
}

impl Stream for WebSocketStream {
    type Item = Result<StreamMessage>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let connection = match self.connection.as_mut() {
            Some(connection) => connection,
            None => return Poll::Ready(None),
        };

        match connection.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(message))) => match message {
                Message::Text(text) => match self.parse_message(&text) {
                    Ok(stream_msg) => {
                        self.stats.record_message();
                        self.update_connection_uptime();
                        Poll::Ready(Some(Ok(stream_msg)))
                    }
                    Err(err) => {
                        self.stats.record_error();
                        Poll::Ready(Some(Err(err)))
                    }
                },
                Message::Close(_) => {
                    info!("WebSocket connection closed by server");
                    self.connection = None;
                    self.connected_since = None;
                    Poll::Ready(None)
                }
                Message::Ping(_) | Message::Pong(_) => Poll::Pending,
                Message::Binary(_) | Message::Frame(_) => {
                    warn!("Received unsupported message type");
                    Poll::Pending
                }
            },
            Poll::Ready(Some(Err(e))) => {
                error!("WebSocket error: {}", e);
                self.stats.record_error();
                self.connected_since = None;
                Poll::Ready(Some(Err(PolymarketError::stream(
                    e.to_string(),
                    StreamErrorKind::Unknown,
                ))))
            }
            Poll::Ready(None) => {
                self.connected_since = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl MarketStream for WebSocketStream {
    fn subscribe(&mut self, _subscription: Subscription) -> Result<()> {
        Ok(())
    }

    fn unsubscribe(&mut self, _token_ids: &[String]) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    fn get_stats(&self) -> StreamStats {
        let mut stats = self.stats.clone();
        if let Some(started) = self.connected_since {
            stats.connection_uptime = started.elapsed();
        }
        stats
    }
}

// ============================================================================
// MockStream - Testing Support
// ============================================================================

/// Mock stream for testing
#[derive(Debug)]
pub struct MockStream {
    messages: Vec<Result<StreamMessage>>,
    index: usize,
    connected: bool,
}

impl MockStream {
    /// Create a new mock stream
    #[must_use]
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            index: 0,
            connected: true,
        }
    }

    /// Add a message to the mock stream
    pub fn add_message(&mut self, message: StreamMessage) {
        self.messages.push(Ok(message));
    }

    /// Add an error to the mock stream
    pub fn add_error(&mut self, error: PolymarketError) {
        self.messages.push(Err(error));
    }

    /// Set connected state
    pub fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
    }
}

impl Default for MockStream {
    fn default() -> Self {
        Self::new()
    }
}

impl Stream for MockStream {
    type Item = Result<StreamMessage>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.index >= self.messages.len() {
            Poll::Ready(None)
        } else {
            let message = self.messages[self.index].clone();
            self.index += 1;
            Poll::Ready(Some(message))
        }
    }
}

impl MarketStream for MockStream {
    fn subscribe(&mut self, _subscription: Subscription) -> Result<()> {
        Ok(())
    }

    fn unsubscribe(&mut self, _token_ids: &[String]) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn get_stats(&self) -> StreamStats {
        StreamStats {
            messages_received: self.messages.len() as u64,
            messages_sent: 0,
            errors: self.messages.iter().filter(|m| m.is_err()).count() as u64,
            last_message_time: None,
            connection_uptime: Duration::ZERO,
            reconnect_count: 0,
        }
    }
}

// ============================================================================
// StreamManager - Multi-stream Management
// ============================================================================

/// Stream manager for handling multiple streams
pub struct StreamManager {
    streams: Vec<Box<dyn MarketStream>>,
    message_tx: mpsc::UnboundedSender<StreamMessage>,
}

impl StreamManager {
    /// Create a new stream manager
    #[must_use]
    pub fn new() -> Self {
        let (message_tx, _message_rx) = mpsc::unbounded_channel();
        Self {
            streams: Vec::new(),
            message_tx,
        }
    }

    /// Add a stream to manage
    pub fn add_stream(&mut self, stream: Box<dyn MarketStream>) {
        self.streams.push(stream);
    }

    /// Broadcast a message to all listeners
    pub fn broadcast_message(&self, message: StreamMessage) -> Result<()> {
        self.message_tx
            .send(message)
            .map_err(|_| PolymarketError::internal("Failed to broadcast message"))
    }
}

impl Default for StreamManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// RTDS (Real-Time Data Stream) Client
// ============================================================================

/// RTDS WebSocket configuration
#[derive(Debug, Clone)]
pub struct RtdsConfig {
    /// WebSocket host URL
    pub host: String,
    /// Topic to subscribe (default: "activity")
    pub topic: String,
    /// Message type filter (default: "*" for all)
    pub msg_type: String,
    /// Optional filters (JSON string)
    pub filters: Option<String>,
    /// Ping interval in milliseconds
    pub ping_interval_ms: u64,
    /// Maximum reconnection backoff in seconds
    pub max_backoff_secs: u64,
    /// Enable auto-reconnect
    pub auto_reconnect: bool,
    /// Event channel buffer size
    pub channel_buffer_size: usize,
}

impl Default for RtdsConfig {
    fn default() -> Self {
        Self {
            // Use helper function to support env var override (POLYMARKET_RTDS_URL)
            host: rtds_wss_url(),
            topic: "activity".to_string(),
            msg_type: "*".to_string(),
            filters: None,
            ping_interval_ms: 5000,
            max_backoff_secs: 30,
            auto_reconnect: true,
            channel_buffer_size: 1000,
        }
    }
}

impl RtdsConfig {
    /// Create a new configuration builder
    #[must_use]
    pub fn builder() -> Self {
        Self::default()
    }

    /// Set WebSocket host URL
    #[must_use]
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    /// Set subscription topic
    #[must_use]
    pub fn with_topic(mut self, topic: impl Into<String>) -> Self {
        self.topic = topic.into();
        self
    }

    /// Set message type filter
    #[must_use]
    pub fn with_msg_type(mut self, msg_type: impl Into<String>) -> Self {
        self.msg_type = msg_type.into();
        self
    }

    /// Set custom filters (JSON string)
    #[must_use]
    pub fn with_filters(mut self, filters: impl Into<String>) -> Self {
        self.filters = Some(filters.into());
        self
    }

    /// Set ping interval
    #[must_use]
    pub fn with_ping_interval_ms(mut self, ms: u64) -> Self {
        self.ping_interval_ms = ms;
        self
    }

    /// Set maximum backoff for reconnection
    #[must_use]
    pub fn with_max_backoff_secs(mut self, secs: u64) -> Self {
        self.max_backoff_secs = secs;
        self
    }

    /// Enable or disable auto-reconnect
    #[must_use]
    pub fn with_auto_reconnect(mut self, enabled: bool) -> Self {
        self.auto_reconnect = enabled;
        self
    }

    /// Set channel buffer size
    #[must_use]
    pub fn with_channel_buffer_size(mut self, size: usize) -> Self {
        self.channel_buffer_size = size;
        self
    }

    // =========================================================================
    // Preset Configurations
    // =========================================================================

    /// Create config for subscribing to trades only.
    ///
    /// This is the most common configuration for trade activity monitoring.
    #[must_use]
    pub fn for_trades() -> Self {
        Self::default().with_msg_type("trades")
    }

    /// Create config for subscribing to all activity types.
    #[must_use]
    pub fn for_all_activity() -> Self {
        Self::default() // msg_type defaults to "*"
    }

    /// Create config from environment variables.
    ///
    /// **Deprecated**: Use `RtdsConfig::default()` or `RtdsConfig::for_trades()` instead.
    /// The default implementation already supports `POLYMARKET_RTDS_URL` env var override.
    #[must_use]
    #[deprecated(
        since = "0.1.0",
        note = "Use RtdsConfig::default() or RtdsConfig::for_trades() instead. \
                URL override via POLYMARKET_RTDS_URL env var is already supported."
    )]
    pub fn from_env() -> Self {
        Self::default()
    }
}

/// Events emitted by the RTDS client
#[derive(Debug, Clone)]
pub enum RtdsEvent {
    /// Successfully connected to RTDS
    Connected,
    /// Disconnected from RTDS
    Disconnected,
    /// Received a trade event
    Trade(TradePayload),
    /// Received a raw message (for other message types)
    RawMessage(RtdsMessage),
    /// An error occurred
    Error(String),
    /// Reconnecting after disconnect
    Reconnecting {
        /// Reconnection attempt number
        attempt: u32,
        /// Backoff duration in seconds
        backoff_secs: u64,
    },
}

/// Raw message from RTDS WebSocket
#[derive(Debug, Clone, Deserialize)]
pub struct RtdsMessage {
    /// Topic name (may be absent in some message types like subscribed confirmation)
    #[serde(default)]
    pub topic: Option<String>,
    /// Message type (trades, orders_matched, etc.)
    #[serde(rename = "type", default)]
    pub msg_type: String,
    /// Server timestamp
    pub timestamp: Option<i64>,
    /// Connection ID
    pub connection_id: Option<String>,
    /// Message payload (may be absent in control messages)
    #[serde(default)]
    pub payload: Value,
}

/// Trade activity payload from RTDS
///
/// Contains all data needed for trade activities, traders, and notifications.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TradePayload {
    /// Token/Asset ID
    pub asset: Option<String>,
    /// Trader bio
    pub bio: Option<String>,
    /// Market condition ID
    pub condition_id: Option<String>,
    /// Event slug (for event grouping)
    pub event_slug: Option<String>,
    /// Market icon URL
    pub icon: Option<String>,
    /// Trader display name
    pub name: Option<String>,
    /// Trade outcome (Yes/No)
    pub outcome: Option<String>,
    /// Outcome index (0 or 1)
    pub outcome_index: Option<i32>,
    /// Trade price
    pub price: Option<f64>,
    /// Trader profile image URL
    pub profile_image: Option<String>,
    /// Trader wallet address (proxy wallet)
    pub proxy_wallet: Option<String>,
    /// Trader pseudonym
    pub pseudonym: Option<String>,
    /// Trade side (BUY/SELL)
    pub side: Option<String>,
    /// Trade size (shares)
    pub size: Option<f64>,
    /// Market slug
    pub slug: Option<String>,
    /// Trade timestamp (unix seconds)
    pub timestamp: Option<i64>,
    /// Market title/question
    pub title: Option<String>,
    /// Transaction hash
    pub transaction_hash: Option<String>,
    /// Event title (for multi-market events)
    pub event_title: Option<String>,
    /// Fee paid
    pub fee: Option<f64>,
    /// Fee rate in basis points
    pub fee_bps: Option<u32>,
    /// Maker address
    pub maker_address: Option<String>,
    /// Trade type (e.g., "CLOB", "AMM")
    pub trade_type: Option<String>,
}

impl TradePayload {
    /// Get trader address (required field)
    #[must_use]
    pub fn trader_address(&self) -> Option<&str> {
        self.proxy_wallet.as_deref()
    }

    /// Get display name with fallback to pseudonym or truncated address
    #[must_use]
    pub fn display_name(&self) -> String {
        if let Some(name) = &self.name {
            if !name.is_empty() {
                return name.clone();
            }
        }
        if let Some(pseudonym) = &self.pseudonym {
            if !pseudonym.is_empty() {
                return pseudonym.clone();
            }
        }
        if let Some(addr) = &self.proxy_wallet {
            if addr.len() >= 10 {
                return format!("{}...{}", &addr[..6], &addr[addr.len() - 4..]);
            }
            return addr.clone();
        }
        "Unknown".to_string()
    }

    /// Check if this is a valid trade payload
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.proxy_wallet.is_some()
            && self.condition_id.is_some()
            && self.side.is_some()
            && self.price.is_some()
            && self.size.is_some()
    }

    /// Get trade value in USDC
    #[must_use]
    pub fn value_usdc(&self) -> f64 {
        self.price.unwrap_or(0.0) * self.size.unwrap_or(0.0)
    }

    /// Check if this is a buy trade
    #[must_use]
    pub fn is_buy(&self) -> bool {
        self.side
            .as_deref()
            .map_or(false, |s| s.eq_ignore_ascii_case("BUY"))
    }

    /// Check if this is a sell trade
    #[must_use]
    pub fn is_sell(&self) -> bool {
        self.side
            .as_deref()
            .map_or(false, |s| s.eq_ignore_ascii_case("SELL"))
    }

    /// Get token ID (alias for asset)
    #[must_use]
    pub fn token_id(&self) -> Option<&str> {
        self.asset.as_deref()
    }
}

/// Subscription message for RTDS
#[derive(Debug, Serialize)]
pub struct RtdsSubscriptionMessage {
    /// Action type
    pub action: String,
    /// Subscriptions list
    pub subscriptions: Vec<RtdsSubscription>,
}

/// Single RTDS subscription configuration
#[derive(Debug, Serialize)]
pub struct RtdsSubscription {
    /// Topic to subscribe
    pub topic: String,
    /// Message type filter
    #[serde(rename = "type")]
    pub sub_type: String,
    /// Optional JSON filters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filters: Option<String>,
}

impl RtdsSubscriptionMessage {
    /// Create a new subscription message
    #[must_use]
    pub fn new(topic: &str, msg_type: &str, filters: Option<String>) -> Self {
        Self {
            action: "subscribe".to_string(),
            subscriptions: vec![RtdsSubscription {
                topic: topic.to_string(),
                sub_type: msg_type.to_string(),
                filters,
            }],
        }
    }

    /// Create subscription for trades only
    #[must_use]
    pub fn trades_only() -> Self {
        Self::new("activity", "trades", None)
    }

    /// Create subscription for all activity
    #[must_use]
    pub fn all_activity() -> Self {
        Self::new("activity", "*", None)
    }
}

/// RTDS WebSocket client with auto-reconnect
pub struct RtdsClient {
    config: RtdsConfig,
    shutdown_tx: Option<mpsc::Sender<()>>,
    stats: ConnectionStats,
}

impl RtdsClient {
    /// Create a new RTDS client
    #[must_use]
    pub fn new(config: RtdsConfig) -> Self {
        Self {
            config,
            shutdown_tx: None,
            stats: ConnectionStats::new(),
        }
    }

    /// Create client with default configuration (all activity types).
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(RtdsConfig::default())
    }

    /// Create client for trades only (most common use case).
    #[must_use]
    pub fn for_trades() -> Self {
        Self::new(RtdsConfig::for_trades())
    }

    /// Create client from environment variables.
    ///
    /// **Deprecated**: Use `RtdsClient::for_trades()` or `RtdsClient::new(config)` instead.
    #[must_use]
    #[deprecated(
        since = "0.1.0",
        note = "Use RtdsClient::for_trades() or RtdsClient::new(RtdsConfig::default()) instead"
    )]
    #[allow(deprecated)]
    pub fn from_env() -> Self {
        Self::new(RtdsConfig::from_env())
    }

    /// Get current connection statistics
    #[must_use]
    pub fn stats(&self) -> &ConnectionStats {
        &self.stats
    }

    /// Start the WebSocket connection and return an event receiver
    pub async fn connect(&mut self) -> Result<mpsc::Receiver<RtdsEvent>> {
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
        let (event_tx, event_rx) = mpsc::channel::<RtdsEvent>(self.config.channel_buffer_size);

        self.shutdown_tx = Some(shutdown_tx);

        let config = self.config.clone();

        tokio::spawn(async move {
            Self::run_loop(config, event_tx, shutdown_rx).await;
        });

        Ok(event_rx)
    }

    /// Stop the WebSocket connection
    pub async fn disconnect(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
    }

    /// Check if client is connected
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.shutdown_tx.is_some()
    }

    /// Internal run loop with reconnection logic
    async fn run_loop(
        config: RtdsConfig,
        event_tx: mpsc::Sender<RtdsEvent>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        let mut backoff_secs = 1u64;

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("RTDS client received shutdown signal");
                    let _ = event_tx.send(RtdsEvent::Disconnected).await;
                    break;
                }
                result = Self::connect_and_run(&config, &event_tx) => {
                    match result {
                        Ok(()) => {
                            info!("RTDS connection closed gracefully");
                            backoff_secs = 1;
                        }
                        Err(e) => {
                            error!(?e, "RTDS connection error");
                            let _ = event_tx.send(RtdsEvent::Error(e.to_string())).await;
                        }
                    }

                    let _ = event_tx.send(RtdsEvent::Disconnected).await;

                    if config.auto_reconnect {
                        let _ = event_tx.send(RtdsEvent::Reconnecting {
                            attempt: (backoff_secs as u32).saturating_sub(1) / 2 + 1,
                            backoff_secs,
                        }).await;

                        info!(backoff_secs, "Reconnecting to RTDS");
                        sleep(Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(config.max_backoff_secs);
                    } else {
                        break;
                    }
                }
            }
        }
    }

    /// Connect to RTDS and process messages
    async fn connect_and_run(
        config: &RtdsConfig,
        event_tx: &mpsc::Sender<RtdsEvent>,
    ) -> Result<()> {
        info!(host = %config.host, "Connecting to RTDS WebSocket");

        let (ws_stream, _) = connect_async(&config.host).await.map_err(|e| {
            PolymarketError::stream(
                format!("Failed to connect: {e}"),
                StreamErrorKind::ConnectionFailed,
            )
        })?;

        let (mut write, mut read) = ws_stream.split();

        // Send subscription message
        let sub_msg =
            RtdsSubscriptionMessage::new(&config.topic, &config.msg_type, config.filters.clone());
        let sub_json = serde_json::to_string(&sub_msg)?;

        info!(
            subscription_message = %sub_json,
            "Sending RTDS subscription"
        );

        write
            .send(Message::Text(sub_json.into()))
            .await
            .map_err(|e| {
                PolymarketError::stream(
                    format!("Failed to subscribe: {e}"),
                    StreamErrorKind::SubscriptionFailed,
                )
            })?;

        info!(topic = %config.topic, msg_type = %config.msg_type, "Subscribed to RTDS");
        let _ = event_tx.send(RtdsEvent::Connected).await;

        let mut ping_interval = interval(Duration::from_millis(config.ping_interval_ms));

        loop {
            tokio::select! {
                _ = ping_interval.tick() => {
                    // Send ping silently (no log needed for routine keepalive)
                    if let Err(e) = write.send(Message::Ping(vec![].into())).await {
                        error!(?e, "Failed to send ping");
                        return Err(PolymarketError::stream(
                            format!("Ping failed: {e}"),
                            StreamErrorKind::ConnectionLost,
                        ));
                    }
                }
                msg = read.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            Self::handle_message(&text, event_tx).await;
                        }
                        Some(Ok(Message::Pong(_))) => {
                            // Pong received, connection is alive (no log needed)
                        }
                        Some(Ok(Message::Close(frame))) => {
                            info!(?frame, "RTDS connection closed by server");
                            return Ok(());
                        }
                        Some(Err(WsError::ConnectionClosed)) => {
                            info!("RTDS connection closed");
                            return Ok(());
                        }
                        Some(Err(e)) => {
                            return Err(PolymarketError::stream(
                                format!("WebSocket error: {e}"),
                                StreamErrorKind::ConnectionLost,
                            ));
                        }
                        None => {
                            info!("RTDS stream ended");
                            return Ok(());
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Handle incoming RTDS message
    async fn handle_message(text: &str, event_tx: &mpsc::Sender<RtdsEvent>) {
        // Skip empty messages (e.g., heartbeat acknowledgments)
        if text.is_empty() || text.trim().is_empty() {
            return;
        }

        let message: RtdsMessage = match serde_json::from_str(text) {
            Ok(m) => m,
            Err(e) => {
                // Only warn for non-empty messages that fail to parse
                warn!(?e, text_len = text.len(), "Failed to parse RTDS message");
                return;
            }
        };

        // Trace log for debugging - only visible with RUST_LOG=trace
        trace!(
            msg_type = %message.msg_type,
            topic = ?message.topic,
            payload_preview = %format!("{:.200}", message.payload.to_string()),
            "RTDS message received"
        );

        // Match both "trades" and "trade" message types (Polymarket may use either)
        if message.msg_type == "trades" || message.msg_type == "trade" {
            let payload: TradePayload = match serde_json::from_value(message.payload.clone()) {
                Ok(p) => p,
                Err(e) => {
                    warn!(?e, "Failed to parse trade payload");
                    return;
                }
            };

            // Full structured output at debug level (RUST_LOG=polymarket_sdk=debug)
            debug!(
                proxy_wallet = ?payload.proxy_wallet,
                pseudonym = ?payload.pseudonym,
                side = ?payload.side,
                outcome = ?payload.outcome,
                size = ?payload.size,
                price = ?payload.price,
                title = ?payload.title,
                asset = ?payload.asset,
                condition_id = ?payload.condition_id,
                transaction_hash = ?payload.transaction_hash,
                timestamp = ?payload.timestamp,
                event_title = ?payload.event_title,
                "TradePayload received"
            );

            if payload.is_valid() {
                let _ = event_tx.send(RtdsEvent::Trade(payload)).await;
            } else {
                debug!("Skipping invalid trade payload");
            }
        } else {
            debug!(msg_type = %message.msg_type, "Received non-trade message");
            let _ = event_tx.send(RtdsEvent::RawMessage(message)).await;
        }
    }
}

impl Drop for RtdsClient {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.try_send(());
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtds_client_creation() {
        let client = RtdsClient::with_defaults();
        assert!(!client.is_connected());
    }

    #[test]
    fn test_rtds_config_default() {
        let config = RtdsConfig::default();
        // URL uses helper function which may be overridden by env var
        assert_eq!(config.host, rtds_wss_url());
        assert_eq!(config.topic, "activity");
        assert_eq!(config.msg_type, "*");
        assert!(config.ping_interval_ms > 0);
    }

    #[test]
    fn test_rtds_config_for_trades() {
        let config = RtdsConfig::for_trades();
        assert_eq!(config.msg_type, "trades");
        assert_eq!(config.topic, "activity");
    }

    #[test]
    fn test_rtds_config_builder() {
        let config = RtdsConfig::builder()
            .with_topic("custom")
            .with_msg_type("orders")
            .with_ping_interval_ms(10000);
        assert_eq!(config.topic, "custom");
        assert_eq!(config.msg_type, "orders");
        assert_eq!(config.ping_interval_ms, 10000);
    }

    #[test]
    fn test_subscription_message() {
        let msg = RtdsSubscriptionMessage::trades_only();
        assert_eq!(msg.action, "subscribe");
        assert_eq!(msg.subscriptions.len(), 1);
        assert_eq!(msg.subscriptions[0].topic, "activity");
        assert_eq!(msg.subscriptions[0].sub_type, "trades");
    }

    #[test]
    fn test_trade_payload_display_name() {
        let payload = TradePayload {
            name: Some("TestTrader".to_string()),
            proxy_wallet: Some("0x1234567890abcdef1234567890abcdef12345678".to_string()),
            ..Default::default()
        };
        assert_eq!(payload.display_name(), "TestTrader");

        let payload_with_pseudonym = TradePayload {
            pseudonym: Some("CryptoWhale".to_string()),
            proxy_wallet: Some("0x1234567890abcdef1234567890abcdef12345678".to_string()),
            ..Default::default()
        };
        assert_eq!(payload_with_pseudonym.display_name(), "CryptoWhale");

        let payload_no_name = TradePayload {
            proxy_wallet: Some("0x1234567890abcdef1234567890abcdef12345678".to_string()),
            ..Default::default()
        };
        assert_eq!(payload_no_name.display_name(), "0x1234...5678");
    }

    #[test]
    fn test_trade_payload_validation() {
        let valid_payload = TradePayload {
            proxy_wallet: Some("0x123".to_string()),
            condition_id: Some("cond_123".to_string()),
            side: Some("BUY".to_string()),
            price: Some(0.65),
            size: Some(100.0),
            ..Default::default()
        };
        assert!(valid_payload.is_valid());

        let invalid_payload = TradePayload::default();
        assert!(!invalid_payload.is_valid());
    }

    #[test]
    fn test_trade_payload_side() {
        let buy = TradePayload {
            side: Some("BUY".to_string()),
            ..Default::default()
        };
        assert!(buy.is_buy());
        assert!(!buy.is_sell());

        let sell = TradePayload {
            side: Some("sell".to_string()),
            ..Default::default()
        };
        assert!(!sell.is_buy());
        assert!(sell.is_sell());
    }

    #[test]
    fn test_rtds_config_builder() {
        let config = RtdsConfig::builder()
            .with_host("wss://custom.example.com")
            .with_topic("custom_topic")
            .with_auto_reconnect(false);

        assert_eq!(config.host, "wss://custom.example.com");
        assert_eq!(config.topic, "custom_topic");
        assert!(!config.auto_reconnect);
    }

    #[test]
    fn test_mock_stream() {
        let mut stream = MockStream::new();
        stream.add_message(StreamMessage::Heartbeat {
            timestamp: Utc::now(),
        });
        assert!(stream.is_connected());
        assert_eq!(stream.get_stats().messages_received, 1);
    }

    #[test]
    fn test_stream_stats() {
        let mut stats = StreamStats::new();
        stats.record_message();
        stats.record_sent();
        stats.record_error();
        stats.record_reconnect();

        assert_eq!(stats.messages_received, 1);
        assert_eq!(stats.messages_sent, 1);
        assert_eq!(stats.errors, 1);
        assert_eq!(stats.reconnect_count, 1);
    }
}
