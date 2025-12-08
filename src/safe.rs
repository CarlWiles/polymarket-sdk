//! Polymarket Relayer Module
//!
//! This module provides comprehensive Safe wallet deployment and management
//! functionality for interacting with Polymarket's Relayer API.
//!
//! ## Features
//!
//! - **Safe Address Derivation**: Deterministic Safe address computation using CREATE2
//! - **SafeCreate Signing**: EIP-712 typed data for Safe deployment
//! - **RelayerClient**: Full client for deploying and managing Safe wallets
//! - **Builder API Authentication**: HMAC-based authentication for Relayer API
//!
//! ## Example
//!
//! ```rust,ignore
//! use polymarket_sdk::{RelayerClient, RelayerConfig, derive_safe_address};
//!
//! // Derive Safe address deterministically
//! let owner = "0x1234...";
//! let safe_address = derive_safe_address(owner)?;
//!
//! // Create client and deploy Safe
//! let client = RelayerClient::new(RelayerConfig::default())?;
//! let result = client.deploy_safe_with_signature(owner, &signature).await?;
//! ```

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::Signature as AlloySignature;
use alloy_primitives::{hex, keccak256, Address, B256, U256};
use alloy_provider::{Provider, ProviderBuilder};
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use governor::{Quota, RateLimiter as GovRateLimiter};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{debug, info, instrument, warn};

use crate::core::{data_api_url, relayer_api_url};
use crate::core::{PolymarketError, Result};

type RateLimiter = GovRateLimiter<
    governor::state::NotKeyed,
    governor::state::InMemoryState,
    governor::clock::DefaultClock,
>;

// ============================================================================
// Constants
// ============================================================================

/// Safe Factory address on Polygon
pub const SAFE_FACTORY: &str = "0xaacFeEa03eb1561C4e67d661e40682Bd20E3541b";

/// Safe init code hash for CREATE2 derivation
pub const SAFE_INIT_CODE_HASH: &str =
    "0x2bce2127ff07fb632d16c8347c4ebf501f4841168bed00d9e6ef715ddb6fcecf";

/// Default Polygon RPC (used for on-chain checks, can be overridden by env `POLYGON_RPC_URL`)
pub const DEFAULT_POLYGON_RPC: &str = "https://polygon-rpc.com";

/// USDC contract address on Polygon (PoS bridged USDC.e)
pub const USDC_CONTRACT_ADDRESS: &str = "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174";

/// Native USDC contract address on Polygon (Circle's native USDC)
pub const NATIVE_USDC_CONTRACT_ADDRESS: &str = "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359";

/// Polymarket ConditionalTokens (CTF) ERC1155 contract address on Polygon
/// This holds the outcome tokens for prediction markets
/// Reference: <https://polygonscan.com/address/0x4d97dcd97ec945f40cf65f87097ace5ea0476045>
pub const CONDITIONAL_TOKENS_ADDRESS: &str = "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045";

/// Alias for backward compatibility
pub const CTF_EXCHANGE_ADDRESS: &str = CONDITIONAL_TOKENS_ADDRESS;

/// Polymarket Exchange contract address on Polygon (for standard markets)
/// Reference: <https://polygonscan.com/address/0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e>
pub const EXCHANGE_ADDRESS: &str = "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E";

/// Polymarket NegRisk CTF Exchange contract address on Polygon (for neg-risk markets)
/// Reference: <https://polygonscan.com/address/0xc5d563a36ae78145c45a50134d48a1215220f80a>
pub const NEG_RISK_CTF_EXCHANGE_ADDRESS: &str = "0xC5d563A36AE78145C45a50134d48A1215220f80a";

/// Polymarket NegRiskAdapter contract address on Polygon
/// Used for split/merge operations in neg-risk markets
/// Reference: <https://polygonscan.com/address/0xd91e80cf2e7be2e162c6513ced06f1dd0da35296>
pub const NEG_RISK_ADAPTER_ADDRESS: &str = "0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296";

/// CreateProxy EIP-712 type string (Polymarket SafeProxyFactory)
/// Reference: https://polygonscan.com/address/0xaacfeea03eb1561c4e67d661e40682bd20e3541b
const CREATE_PROXY_TYPE_STR: &str =
    "CreateProxy(address paymentToken,uint256 payment,address paymentReceiver)";

/// EIP712Domain type string for Polymarket SafeProxyFactory (includes name field)
const DOMAIN_TYPE_STR: &str = "EIP712Domain(string name,uint256 chainId,address verifyingContract)";

/// Domain name for Polymarket SafeProxyFactory
const DOMAIN_NAME: &str = "Polymarket Contract Proxy Factory";

/// Default chain ID for Polygon
const DEFAULT_CHAIN_ID: u64 = 137;

// ============================================================================
// EIP-712 Digest Computation
// ============================================================================

/// Compute the EIP-712 digest for CreateProxy (Polymarket SafeProxyFactory)
///
/// This is used to verify signatures before sending to the Relayer.
/// The digest matches the Polymarket SafeProxyFactory contract's expected format.
fn compute_safe_create_digest_internal(_owner_address: &str, chain_id: u64) -> Result<B256> {
    let factory_addr: Address = SAFE_FACTORY
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid factory address: {e}")))?;

    let payment_token: Address = Address::ZERO;
    let payment = U256::ZERO;
    let payment_receiver: Address = Address::ZERO;

    // Domain type hash
    let domain_type_hash = keccak256(DOMAIN_TYPE_STR.as_bytes());

    // CreateProxy type hash
    let create_proxy_type_hash = keccak256(CREATE_PROXY_TYPE_STR.as_bytes());

    // Name hash
    let name_hash = keccak256(DOMAIN_NAME.as_bytes());

    // Domain separator: keccak256(domainTypeHash || keccak256(name) || chainId || verifyingContract)
    let mut domain_encoded = Vec::with_capacity(128);
    domain_encoded.extend_from_slice(domain_type_hash.as_slice());
    domain_encoded.extend_from_slice(name_hash.as_slice());
    domain_encoded.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    let mut factory_bytes = [0u8; 32];
    factory_bytes[12..].copy_from_slice(factory_addr.as_slice());
    domain_encoded.extend_from_slice(&factory_bytes);
    let domain_separator = keccak256(&domain_encoded);

    // Struct hash: keccak256(typeHash || paymentToken || payment || paymentReceiver)
    // Note: Polymarket's CreateProxy does NOT include owner or nonce
    let mut struct_encoded = Vec::with_capacity(128);
    struct_encoded.extend_from_slice(create_proxy_type_hash.as_slice());
    let mut payment_token_bytes = [0u8; 32];
    payment_token_bytes[12..].copy_from_slice(payment_token.as_slice());
    struct_encoded.extend_from_slice(&payment_token_bytes);
    struct_encoded.extend_from_slice(&payment.to_be_bytes::<32>());
    let mut payment_receiver_bytes = [0u8; 32];
    payment_receiver_bytes[12..].copy_from_slice(payment_receiver.as_slice());
    struct_encoded.extend_from_slice(&payment_receiver_bytes);
    let struct_hash = keccak256(&struct_encoded);

    // Final digest: keccak256(0x1901 || domainSeparator || structHash)
    let mut bytes = Vec::with_capacity(66);
    bytes.push(0x19);
    bytes.push(0x01);
    bytes.extend_from_slice(domain_separator.as_slice());
    bytes.extend_from_slice(struct_hash.as_slice());

    Ok(keccak256(&bytes))
}

// ============================================================================
// Types
// ============================================================================

/// Transaction type for Relayer API
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionType {
    /// Standard Safe transaction
    #[serde(rename = "SAFE")]
    Safe,
    /// Safe creation transaction
    #[serde(rename = "SAFE-CREATE")]
    SafeCreate,
}

/// Transaction state from Relayer API
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionState {
    /// Transaction is new/pending
    #[serde(rename = "STATE_NEW")]
    New,
    /// Transaction has been executed
    #[serde(rename = "STATE_EXECUTED")]
    Executed,
    /// Transaction has been mined
    #[serde(rename = "STATE_MINED")]
    Mined,
    /// Transaction is confirmed
    #[serde(rename = "STATE_CONFIRMED")]
    Confirmed,
    /// Transaction failed
    #[serde(rename = "STATE_FAILED")]
    Failed,
    /// Transaction is invalid
    #[serde(rename = "STATE_INVALID")]
    Invalid,
}

impl TransactionState {
    /// Check if this is a terminal state
    ///
    /// For Polymarket Relayer, `Mined` is considered terminal because the transaction
    /// has been included in a block. `Confirmed` indicates additional block confirmations.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Mined | Self::Confirmed | Self::Failed | Self::Invalid
        )
    }

    /// Check if this is a success state
    ///
    /// Both `Mined` and `Confirmed` are considered successful.
    /// - `Mined`: Transaction included in a block (sufficient for Safe deployment)
    /// - `Confirmed`: Additional block confirmations received
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Mined | Self::Confirmed)
    }
}

// ====================================================================================
// Manual debug helper (not part of library API)
// ====================================================================================
#[cfg(test)]
mod manual_debug {
    use super::*;

    /// 手动从 .env 读取配置，调用 /transaction?id=... 打印回执
    ///
    /// 注意：这会访问网络，仅用于本地调试，不会在 CI 运行。
    #[tokio::test]
    async fn fetch_transaction_status_from_env() {
        // 目标 tx_id（来自当前排查）
        let tx_id = "019ad6a5-fe80-7b44-a075-2af31ea399dd";

        // 用环境变量构建 relayer 客户端
        let cfg = RelayerConfig::from_env();
        let mut client = RelayerClient::new(cfg).expect("create relayer client");

        // NOTE: 仅用于本地调试，按需求硬编码 Builder 凭据
        let hardcoded_creds = BuilderApiCredentials::new(
            "019acb98-c6b1-7bd3-b31a-a62881ee200e",
            "IRYvSFDwdGcG67cmpXFoqV_l9vWmi8n40x0j5UwkSpA=",
            "67e95965fca9af2eff7700c768e40406efad1610324fd94e5005be8300f63d10",
        );
        client = client.with_builder_credentials(hardcoded_creds);

        // 调用 /transaction?id=...
        let receipt = client
            .get_transaction_status(tx_id)
            .await
            .expect("fetch transaction status");

        eprintln!("=== Transaction Receipt ===\n{:#?}", receipt);
    }
}

/// Transaction request for Relayer API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRequest {
    /// Transaction type
    #[serde(rename = "type")]
    pub r#type: TransactionType,
    /// From address (signer)
    pub from: String,
    /// To address (target contract)
    pub to: String,
    /// Proxy wallet address (for Safe transactions)
    #[serde(skip_serializing_if = "Option::is_none", rename = "proxyWallet")]
    pub proxy_wallet: Option<String>,
    /// Transaction data
    pub data: String,
    /// Nonce (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Signature
    pub signature: String,
    /// Signature parameters
    #[serde(rename = "signatureParams")]
    pub signature_params: SignatureParams,
    /// Optional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
}

/// Signature parameters for transaction
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignatureParams {
    /// Payment token address (for SafeCreate)
    #[serde(skip_serializing_if = "Option::is_none", rename = "paymentToken")]
    pub payment_token: Option<String>,
    /// Payment amount (for SafeCreate)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment: Option<String>,
    /// Payment receiver (for SafeCreate)
    #[serde(skip_serializing_if = "Option::is_none", rename = "paymentReceiver")]
    pub payment_receiver: Option<String>,
    /// Operation type (0 = Call, 1 = DelegateCall) - for Safe transactions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// Safe transaction gas - for Safe transactions
    #[serde(skip_serializing_if = "Option::is_none", rename = "safeTxnGas")]
    pub safe_tx_gas: Option<String>,
    /// Base gas - for Safe transactions
    #[serde(skip_serializing_if = "Option::is_none", rename = "baseGas")]
    pub base_gas: Option<String>,
    /// Gas price - for Safe transactions
    #[serde(skip_serializing_if = "Option::is_none", rename = "gasPrice")]
    pub gas_price: Option<String>,
    /// Gas token - for Safe transactions
    #[serde(skip_serializing_if = "Option::is_none", rename = "gasToken")]
    pub gas_token: Option<String>,
    /// Refund receiver - for Safe transactions
    #[serde(skip_serializing_if = "Option::is_none", rename = "refundReceiver")]
    pub refund_receiver: Option<String>,
}

/// Transaction receipt from Relayer API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    /// Transaction ID (Polymarket uses "transactionID", we alias it)
    #[serde(
        alias = "transactionID",
        alias = "transactionId",
        alias = "transaction_id",
        alias = "id"
    )]
    pub id: String,
    /// Transaction state
    #[serde(alias = "status")]
    pub state: TransactionState,
    /// Transaction hash (if submitted)
    #[serde(
        alias = "transactionHash",
        alias = "txHash",
        skip_serializing_if = "Option::is_none"
    )]
    pub transaction_hash: Option<String>,
    /// Some relayer responses include `hash` field (alias of transaction_hash)
    #[serde(alias = "hash", skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// Proxy address (for Safe creation)
    #[serde(alias = "proxyWallet", skip_serializing_if = "Option::is_none")]
    pub proxy_address: Option<String>,
    /// From / to (for debugging / compatibility with builder-relayer types)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Error message (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Created timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Updated timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Builder API credentials for authenticated requests
#[derive(Debug, Clone)]
pub struct BuilderApiCredentials {
    /// API key
    pub api_key: String,
    /// API secret (base64 encoded)
    pub secret: String,
    /// Passphrase
    pub passphrase: String,
}

impl BuilderApiCredentials {
    /// Create new credentials
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

    /// Load from environment variables
    ///
    /// Expected env vars:
    /// - `POLY_BUILDER_API_KEY`
    /// - `POLY_BUILDER_SECRET`
    /// - `POLY_BUILDER_PASSPHRASE`
    pub fn from_env() -> std::result::Result<Self, std::env::VarError> {
        Ok(Self {
            api_key: std::env::var("POLY_BUILDER_API_KEY")?,
            secret: std::env::var("POLY_BUILDER_SECRET")?,
            passphrase: std::env::var("POLY_BUILDER_PASSPHRASE")?,
        })
    }
}

/// Nonce type for Relayer API
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NonceType {
    /// Standard transaction nonce
    Transaction,
    /// Safe creation nonce
    SafeCreate,
}

// ============================================================================
// Safe Address Derivation
// ============================================================================

/// Derive Safe address from owner address using CREATE2
///
/// The Safe address is deterministically computed based on:
/// - Factory address
/// - Salt (keccak256 of owner address)
/// - Init code hash
///
/// This means the same owner will always produce the same Safe address.
///
/// # Arguments
/// * `owner` - The owner's wallet address (0x prefixed hex string)
///
/// # Returns
/// The derived Safe address as a 0x prefixed hex string
///
/// # Example
///
/// ```rust,ignore
/// use polymarket_sdk::derive_safe_address;
///
/// let owner = "0x1234567890123456789012345678901234567890";
/// let safe_address = derive_safe_address(owner)?;
/// println!("Safe address: {}", safe_address);
/// ```
pub fn derive_safe_address(owner: &str) -> Result<String> {
    derive_safe_address_with_factory(owner, SAFE_FACTORY)
}

/// Derive Safe address with custom factory
///
/// # Arguments
/// * `owner` - The owner's wallet address
/// * `factory` - The Safe factory address
pub fn derive_safe_address_with_factory(owner: &str, factory: &str) -> Result<String> {
    let factory_addr: Address = factory
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid factory address: {e}")))?;

    let owner_addr: Address = owner
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid owner address: {e}")))?;

    let init_code_hash: B256 = SAFE_INIT_CODE_HASH
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid init code hash: {e}")))?;

    // Compute salt = keccak256(abi.encode(owner))
    let mut salt_input = [0u8; 32];
    salt_input[12..32].copy_from_slice(owner_addr.as_slice());
    let salt = keccak256(salt_input);

    // CREATE2 address computation
    let safe_addr = compute_create2_address(factory_addr, salt, init_code_hash);

    Ok(format!("{safe_addr:?}"))
}

/// Compute CREATE2 address
fn compute_create2_address(deployer: Address, salt: B256, init_code_hash: B256) -> Address {
    let mut bytes = Vec::with_capacity(1 + 20 + 32 + 32);
    bytes.push(0xff);
    bytes.extend_from_slice(deployer.as_slice());
    bytes.extend_from_slice(salt.as_slice());
    bytes.extend_from_slice(init_code_hash.as_slice());

    let hash = keccak256(&bytes);
    Address::from_slice(&hash[12..])
}

// ============================================================================
// Signature Utilities
// ============================================================================

/// Pack an ECDSA signature for the Relayer API
///
/// The Relayer API expects signatures with transformed v values:
/// - v=0 or v=1 → v=31 or v=32
/// - v=27 or v=28 → v=31 or v=32
///
/// Input format: `0x{r(32)}{s(32)}{v(1)}` (65 bytes hex = 130 chars + 0x)
/// Output format: `0x{r(32)}{s(32)}{v(1)}` with transformed v
///
/// # Arguments
/// * `signature` - The original ECDSA signature (hex with 0x prefix)
///
/// # Returns
/// The packed signature ready for Relayer API
pub fn pack_signature(signature: &str) -> Result<String> {
    let sig = signature.trim_start_matches("0x");

    debug!(sig_len = sig.len(), "Packing signature");

    if sig.len() < 130 {
        return Err(PolymarketError::validation(format!(
            "Signature too short: {} chars, expected at least 130",
            sig.len()
        )));
    }

    let r_hex = &sig[0..64];
    let s_hex = &sig[64..128];
    let v_hex = &sig[128..130];

    let original_v = u8::from_str_radix(v_hex, 16)
        .map_err(|e| PolymarketError::validation(format!("Invalid v value in signature: {e}")))?;

    let mut v = original_v;

    // Transform v value for Polymarket Relayer API
    //
    // The Polymarket SafeProxyFactory uses OpenZeppelin's ECDSA.recover which expects
    // standard Ethereum v values (27/28). Privy's sign_secp256k1 returns raw recovery id (0/1).
    //
    // For raw recovery ids (0/1), we convert to standard Ethereum format (27/28).
    // For v=27/28, we keep as-is.
    match v {
        0 | 1 => v += 27, // 0/1 → 27/28 (raw k256 recovery id → standard Ethereum)
        27 | 28 => {}     // Standard Ethereum format, keep as-is
        _ => {
            warn!(v = v, "Unexpected v value in signature, using as-is");
        }
    }

    debug!(
        original_v = original_v,
        transformed_v = v,
        v_hex = %v_hex,
        r_hex_prefix = %&r_hex[0..8],
        s_hex_prefix = %&s_hex[0..8],
        "Signature v value transformation"
    );

    // Parse r and s as U256 for proper padding
    let r = U256::from_str_radix(r_hex, 16)
        .map_err(|e| PolymarketError::validation(format!("Invalid r value in signature: {e}")))?;
    let s = U256::from_str_radix(s_hex, 16)
        .map_err(|e| PolymarketError::validation(format!("Invalid s value in signature: {e}")))?;

    // Pack as 32-byte r, 32-byte s, 1-byte v
    let mut packed = Vec::with_capacity(65);
    packed.extend_from_slice(&r.to_be_bytes::<32>());
    packed.extend_from_slice(&s.to_be_bytes::<32>());
    packed.push(v);

    let packed_hex = format!("0x{}", hex::encode(&packed));

    // Log full details for debugging
    debug!(
        original_sig = %signature,
        packed_sig = %packed_hex,
        packed_len = packed.len(),
        packed_v = packed[64],
        "Packed signature for Relayer"
    );

    Ok(packed_hex)
}

/// Pack a signature for Safe execTransaction (SafeTx)
///
/// Safe's `checkNSignatures` function uses a special signature format where the v value
/// must be transformed to indicate an eth_sign signature type:
/// - v=0 → v=31 (0x1f)
/// - v=1 → v=32 (0x20)
/// - v=27 → v=31 (0x1f)
/// - v=28 → v=32 (0x20)
///
/// This matches the official Polymarket builder-relayer-client-rust implementation:
/// <https://github.com/Polymarket/builder-relayer-client-rust>
///
/// This is different from SafeCreate which uses standard v=27/28 format.
///
/// # Arguments
/// * `signature` - The ECDSA signature (hex string with optional 0x prefix)
///
/// # Returns
/// The packed signature with transformed v for Safe execTransaction
pub fn pack_signature_for_safe_tx(signature: &str) -> Result<String> {
    let sig = signature.trim_start_matches("0x");

    debug!(sig_len = sig.len(), "Packing signature for SafeTx");

    if sig.len() < 130 {
        return Err(PolymarketError::validation(format!(
            "Signature too short: {} chars, expected at least 130",
            sig.len()
        )));
    }

    let r_hex = &sig[0..64];
    let s_hex = &sig[64..128];
    let v_hex = &sig[128..130];

    let original_v = u8::from_str_radix(v_hex, 16)
        .map_err(|e| PolymarketError::validation(format!("Invalid v value in signature: {e}")))?;

    // Transform v value for Safe execTransaction (eth_sign format)
    // This matches Polymarket's official implementation:
    // - 0/1 → 31/32 (raw recovery id + 31)
    // - 27/28 → 31/32 (standard Ethereum + 4)
    let v = match original_v {
        0 | 1 => original_v + 31,  // 0→31, 1→32 (raw k256 recovery id)
        27 | 28 => original_v + 4, // 27→31, 28→32 (standard Ethereum)
        31 | 32 => original_v,     // Already in Safe eth_sign format
        _ => {
            warn!(
                v = original_v,
                "Unexpected v value in signature, using as-is"
            );
            original_v
        }
    };

    debug!(
        original_v = original_v,
        transformed_v = v,
        v_hex = %v_hex,
        r_hex_prefix = %&r_hex[0..8],
        s_hex_prefix = %&s_hex[0..8],
        "Signature v value transformation for SafeTx"
    );

    // Parse r and s as U256 for proper padding
    let r = U256::from_str_radix(r_hex, 16)
        .map_err(|e| PolymarketError::validation(format!("Invalid r value in signature: {e}")))?;
    let s = U256::from_str_radix(s_hex, 16)
        .map_err(|e| PolymarketError::validation(format!("Invalid s value in signature: {e}")))?;

    // Pack as 32-byte r, 32-byte s, 1-byte v
    let mut packed = Vec::with_capacity(65);
    packed.extend_from_slice(&r.to_be_bytes::<32>());
    packed.extend_from_slice(&s.to_be_bytes::<32>());
    packed.push(v);

    let packed_hex = format!("0x{}", hex::encode(&packed));

    debug!(
        original_sig = %signature,
        packed_sig = %packed_hex,
        packed_len = packed.len(),
        packed_v = packed[64],
        "Packed signature for SafeTx"
    );

    Ok(packed_hex)
}

/// Verify a signature can recover to the expected address
///
/// This function verifies that an EIP-712 signature was created by the expected signer
/// by recovering the address from the signature and comparing it.
///
/// # Arguments
/// * `signature` - The ECDSA signature (hex string with 0x prefix)
/// * `digest` - The EIP-712 digest that was signed (hex string with 0x prefix)
/// * `expected_address` - The expected signer address (hex string with 0x prefix)
///
/// # Returns
/// Ok(recovered_address) if verification succeeds, Err if it fails
pub fn verify_signature(signature: &str, digest: &str, expected_address: &str) -> Result<String> {
    // Parse the digest as B256
    let digest_bytes: B256 = digest
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid digest: {e}")))?;

    // Parse the signature - alloy can handle both v=0/1 and v=27/28 formats
    let sig: AlloySignature = signature
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid signature format: {e}")))?;

    // Recover the signer address
    let recovered = sig
        .recover_address_from_prehash(&digest_bytes)
        .map_err(|e| {
            PolymarketError::validation(format!("Failed to recover address from signature: {e}"))
        })?;

    let recovered_str = format!("{recovered:#x}");
    let expected_lower = expected_address.to_lowercase();

    debug!(
        recovered_address = %recovered_str,
        expected_address = %expected_address,
        signature_v = sig.v(),
        "Signature verification"
    );

    if recovered_str.to_lowercase() != expected_lower {
        return Err(PolymarketError::validation(format!(
            "Signature verification failed: recovered {} but expected {}",
            recovered_str, expected_address
        )));
    }

    Ok(recovered_str)
}

// ============================================================================
// SafeCreate EIP-712 Typed Data
// ============================================================================

/// CreateProxy typed data for EIP-712 signing (Polymarket SafeProxyFactory)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeCreateTypedData {
    /// Domain data
    pub domain: SafeCreateDomain,
    /// Message data
    pub message: SafeCreateMessage,
    /// Primary type name
    pub primary_type: String,
    /// Type definitions
    pub types: SafeCreateTypes,
}

/// EIP-712 Domain for Polymarket SafeProxyFactory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeCreateDomain {
    /// Domain name (required for Polymarket)
    pub name: String,
    /// Chain ID (137 for Polygon)
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    /// Safe Factory address
    #[serde(rename = "verifyingContract")]
    pub verifying_contract: String,
}

impl Default for SafeCreateDomain {
    fn default() -> Self {
        Self {
            name: DOMAIN_NAME.to_string(),
            chain_id: 137,
            verifying_contract: SAFE_FACTORY.to_string(),
        }
    }
}

/// CreateProxy message for EIP-712 signing (Polymarket SafeProxyFactory)
/// Note: The owner is NOT part of the signed message - it's recovered from the signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeCreateMessage {
    /// Payment token address (usually zero address)
    #[serde(rename = "paymentToken")]
    pub payment_token: String,
    /// Payment amount (usually 0)
    pub payment: String,
    /// Payment receiver address (usually zero address)
    #[serde(rename = "paymentReceiver")]
    pub payment_receiver: String,
}

impl SafeCreateMessage {
    /// Create a standard CreateProxy message with no payment
    #[must_use]
    pub fn new(_owner: &str) -> Self {
        // Note: owner is not part of the message for Polymarket CreateProxy
        Self {
            payment_token: "0x0000000000000000000000000000000000000000".to_string(),
            payment: "0".to_string(),
            payment_receiver: "0x0000000000000000000000000000000000000000".to_string(),
        }
    }

    /// Create with custom payment parameters
    #[must_use]
    pub fn with_payment(
        _owner: &str,
        payment_token: &str,
        payment: &str,
        payment_receiver: &str,
    ) -> Self {
        Self {
            payment_token: payment_token.to_string(),
            payment: payment.to_string(),
            payment_receiver: payment_receiver.to_string(),
        }
    }
}

/// Type definitions for CreateProxy (Polymarket SafeProxyFactory)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeCreateTypes {
    /// EIP712Domain type
    #[serde(rename = "EIP712Domain")]
    pub eip712_domain: Vec<TypedDataField>,
    /// CreateProxy type
    #[serde(rename = "CreateProxy")]
    pub safe_create: Vec<TypedDataField>,
}

impl Default for SafeCreateTypes {
    fn default() -> Self {
        Self {
            eip712_domain: vec![
                TypedDataField {
                    name: "name".to_string(),
                    r#type: "string".to_string(),
                },
                TypedDataField {
                    name: "chainId".to_string(),
                    r#type: "uint256".to_string(),
                },
                TypedDataField {
                    name: "verifyingContract".to_string(),
                    r#type: "address".to_string(),
                },
            ],
            safe_create: vec![
                TypedDataField {
                    name: "paymentToken".to_string(),
                    r#type: "address".to_string(),
                },
                TypedDataField {
                    name: "payment".to_string(),
                    r#type: "uint256".to_string(),
                },
                TypedDataField {
                    name: "paymentReceiver".to_string(),
                    r#type: "address".to_string(),
                },
            ],
        }
    }
}

/// A single field in a type definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedDataField {
    /// Field name
    pub name: String,
    /// Field type
    pub r#type: String,
}

/// Build CreateProxy typed data for EIP-712 signing (Polymarket SafeProxyFactory)
///
/// # Arguments
/// * `owner` - The owner address for the Safe (not included in signed message, but validated)
/// * `chain_id` - The chain ID (default 137 for Polygon)
///
/// # Returns
/// Complete typed data structure ready for signing
///
/// # Example
///
/// ```rust,ignore
/// use polymarket_sdk::build_safe_create_typed_data;
///
/// let owner = "0x1234567890123456789012345678901234567890";
/// let typed_data = build_safe_create_typed_data(owner, None)?;
///
/// // Sign with Privy or other signer
/// let signature = signer.sign_typed_data(&typed_data).await?;
/// ```
pub fn build_safe_create_typed_data(
    owner: &str,
    chain_id: Option<u64>,
) -> Result<SafeCreateTypedData> {
    // Validate owner address format (even though it's not part of the signed message)
    let _: Address = owner
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid owner address: {e}")))?;

    Ok(SafeCreateTypedData {
        domain: SafeCreateDomain {
            chain_id: chain_id.unwrap_or(137),
            ..Default::default()
        },
        message: SafeCreateMessage::new(owner),
        primary_type: "CreateProxy".to_string(),
        types: SafeCreateTypes::default(),
    })
}

/// Compute the EIP-712 digest for SafeCreate
///
/// This computes the hash that needs to be signed:
/// `keccak256(0x1901 || domainSeparator || structHash)`
///
/// # Arguments
/// * `typed_data` - The SafeCreate typed data
///
/// # Returns
/// The 32-byte digest to be signed
pub fn compute_safe_create_digest(typed_data: &SafeCreateTypedData) -> Result<B256> {
    let domain_separator = compute_domain_separator(typed_data)?;
    let struct_hash = compute_struct_hash(typed_data)?;

    let mut bytes = Vec::with_capacity(2 + 32 + 32);
    bytes.push(0x19);
    bytes.push(0x01);
    bytes.extend_from_slice(domain_separator.as_slice());
    bytes.extend_from_slice(struct_hash.as_slice());

    Ok(keccak256(&bytes))
}

fn compute_domain_separator(typed_data: &SafeCreateTypedData) -> Result<B256> {
    let domain_type_hash = keccak256(DOMAIN_TYPE_STR.as_bytes());

    let chain_id = U256::from(typed_data.domain.chain_id);
    let verifying_contract: Address = typed_data
        .domain
        .verifying_contract
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid verifying contract: {e}")))?;

    let mut encoded = Vec::with_capacity(32 + 32 + 32);
    encoded.extend_from_slice(domain_type_hash.as_slice());
    encoded.extend_from_slice(&chain_id.to_be_bytes::<32>());

    let mut addr_bytes = [0u8; 32];
    addr_bytes[12..].copy_from_slice(verifying_contract.as_slice());
    encoded.extend_from_slice(&addr_bytes);

    Ok(keccak256(&encoded))
}

fn compute_struct_hash(typed_data: &SafeCreateTypedData) -> Result<B256> {
    // Use Polymarket CreateProxy type hash
    let type_hash = keccak256(CREATE_PROXY_TYPE_STR.as_bytes());

    let payment_token: Address = typed_data
        .message
        .payment_token
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid payment token: {e}")))?;

    let payment: U256 = typed_data
        .message
        .payment
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid payment: {e}")))?;

    let payment_receiver: Address = typed_data
        .message
        .payment_receiver
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid payment receiver: {e}")))?;

    // Polymarket CreateProxy only has 4 fields: typeHash + paymentToken + payment + paymentReceiver
    let mut encoded = Vec::with_capacity(32 * 4);
    encoded.extend_from_slice(type_hash.as_slice());

    let mut payment_token_bytes = [0u8; 32];
    payment_token_bytes[12..].copy_from_slice(payment_token.as_slice());
    encoded.extend_from_slice(&payment_token_bytes);

    encoded.extend_from_slice(&payment.to_be_bytes::<32>());

    let mut payment_receiver_bytes = [0u8; 32];
    payment_receiver_bytes[12..].copy_from_slice(payment_receiver.as_slice());
    encoded.extend_from_slice(&payment_receiver_bytes);

    Ok(keccak256(&encoded))
}

// ============================================================================
// Relayer Client
// ============================================================================

/// Relayer API configuration
#[derive(Debug, Clone)]
pub struct RelayerConfig {
    /// Relayer API base URL
    pub base_url: String,
    /// Data API base URL (for profile queries)
    pub data_api_base_url: String,
    /// Request timeout
    pub timeout: Duration,
    /// Rate limit (requests per second)
    pub rate_limit_per_second: u32,
    /// User agent string
    pub user_agent: String,
}

impl Default for RelayerConfig {
    fn default() -> Self {
        Self {
            // Use helper functions to support env var overrides
            base_url: relayer_api_url(),
            data_api_base_url: data_api_url(),
            timeout: Duration::from_secs(60),
            rate_limit_per_second: 2,
            user_agent: "polymarket-sdk/0.1.0".to_string(),
        }
    }
}

impl RelayerConfig {
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

    /// Set Data API base URL
    #[must_use]
    pub fn with_data_api_base_url(mut self, url: impl Into<String>) -> Self {
        self.data_api_base_url = url.into();
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

    /// Create config from environment variables.
    ///
    /// **Deprecated**: Use `RelayerConfig::default()` instead.
    /// The default implementation already supports env var overrides.
    #[must_use]
    #[deprecated(
        since = "0.1.0",
        note = "Use RelayerConfig::default() instead. URL overrides via \
                POLYMARKET_RELAYER_URL and POLYMARKET_DATA_URL env vars are already supported."
    )]
    pub fn from_env() -> Self {
        Self::default()
    }
}

/// Deploy Safe request
#[derive(Debug, Serialize)]
#[allow(dead_code)]
struct DeploySafeRequest {
    owner: String,
}

/// Deploy Safe response
#[derive(Debug, Deserialize)]
pub struct DeploySafeResponse {
    /// Transaction hash if deployment was submitted
    /// Relayer v2 API may return this as "hash" or "transactionHash"
    #[serde(alias = "transactionHash", alias = "hash")]
    pub transaction_hash: Option<String>,
    /// Proxy wallet address if already deployed or immediately available
    #[serde(alias = "proxyAddress", alias = "proxy_address")]
    pub proxy_address: Option<String>,
    /// Status of the deployment
    pub status: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Relayer API client for Safe wallet deployment and proxy wallet management
#[derive(Clone)]
pub struct RelayerClient {
    config: RelayerConfig,
    client: Client,
    rate_limiter: Arc<RateLimiter>,
    builder_credentials: Option<BuilderApiCredentials>,
    /// Optional default RPC endpoint for on-chain checks (e.g., eth_getCode)
    default_rpc: Option<String>,
}

impl RelayerClient {
    /// Create a new Relayer API client
    pub fn new(config: RelayerConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .user_agent(&config.user_agent)
            .gzip(true)
            .build()
            .map_err(|e| PolymarketError::config(format!("Failed to create HTTP client: {e}")))?;

        let quota = Quota::per_second(
            NonZeroU32::new(config.rate_limit_per_second).unwrap_or(NonZeroU32::new(2).unwrap()),
        );
        let rate_limiter = Arc::new(GovRateLimiter::direct(quota));

        Ok(Self {
            config,
            client,
            rate_limiter,
            builder_credentials: None,
            default_rpc: None,
        })
    }

    /// Create client with default configuration
    pub fn with_defaults() -> Result<Self> {
        Self::new(RelayerConfig::default())
    }

    /// Create client from environment variables.
    ///
    /// **Deprecated**: Use `RelayerClient::with_defaults()` instead.
    #[deprecated(since = "0.1.0", note = "Use RelayerClient::with_defaults() instead")]
    #[allow(deprecated)]
    pub fn from_env() -> Result<Self> {
        Self::new(RelayerConfig::from_env())
    }

    /// Add Builder API credentials for authenticated requests
    #[must_use]
    pub fn with_builder_credentials(mut self, credentials: BuilderApiCredentials) -> Self {
        self.builder_credentials = Some(credentials);
        self
    }

    /// Set a default RPC endpoint for on-chain checks (e.g., proxy deployment detection)
    #[must_use]
    pub fn with_default_rpc(mut self, rpc_url: impl Into<String>) -> Self {
        self.default_rpc = Some(rpc_url.into());
        self
    }

    /// Check whether the CREATE2-derived proxy wallet for `owner_address` is already deployed.
    ///
    /// - Computes the expected proxy address via SafeProxyFactory CREATE2 rules.
    /// - Uses alloy provider to call `eth_getCode` on the given RPC.
    /// - Returns `Some(proxy_address)` if code exists, otherwise `None`.
    pub async fn check_proxy_deployed(
        &self,
        owner_address: &str,
        rpc_url: Option<&str>,
    ) -> Result<Option<String>> {
        let rpc = rpc_url
            .map(|s| s.to_string())
            .or_else(|| self.default_rpc.clone())
            .or_else(|| std::env::var("POLYGON_RPC_URL").ok())
            .unwrap_or_else(|| DEFAULT_POLYGON_RPC.to_string());

        let proxy_address = derive_safe_address(owner_address)?;

        // Parse proxy address to alloy Address type
        let addr: Address = proxy_address
            .parse()
            .map_err(|e| PolymarketError::validation(format!("Invalid proxy address: {e}")))?;

        // Build provider using alloy
        let rpc_url: url::Url = rpc
            .parse()
            .map_err(|e| PolymarketError::validation(format!("Invalid RPC URL {rpc}: {e}")))?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        // Use alloy provider to get code at address
        let code = provider
            .get_code_at(addr)
            .await
            .map_err(|e| PolymarketError::internal(format!("eth_getCode failed: {e}")))?;

        let deployed = !code.is_empty();

        debug!(
            owner = %owner_address,
            proxy = %proxy_address,
            rpc = %rpc,
            code_len = code.len(),
            deployed = deployed,
            "Checked proxy deployment via alloy provider"
        );

        if deployed {
            Ok(Some(proxy_address))
        } else {
            Ok(None)
        }
    }

    /// Get USDC balance for an address on Polygon
    ///
    /// Returns the balance in USDC (with 6 decimals precision).
    /// Queries both bridged USDC.e and native USDC contracts.
    ///
    /// # Arguments
    /// * `address` - The wallet address to check balance for
    /// * `rpc_url` - Optional RPC URL (defaults to POLYGON_RPC_URL env or DEFAULT_POLYGON_RPC)
    ///
    /// # Returns
    /// `(usdc_e_balance, native_usdc_balance)` as f64 values (human readable, e.g., 100.50 = $100.50)
    pub async fn get_usdc_balance(
        &self,
        address: &str,
        rpc_url: Option<&str>,
    ) -> Result<(f64, f64)> {
        let rpc = rpc_url
            .map(|s| s.to_string())
            .or_else(|| self.default_rpc.clone())
            .or_else(|| std::env::var("POLYGON_RPC_URL").ok())
            .unwrap_or_else(|| DEFAULT_POLYGON_RPC.to_string());

        // Parse wallet address to validate format
        let wallet_addr: Address = address
            .parse()
            .map_err(|e| PolymarketError::validation(format!("Invalid wallet address: {e}")))?;

        // Query both USDC contracts using raw JSON-RPC
        let usdc_e_balance = self
            .query_erc20_balance_rpc(&rpc, USDC_CONTRACT_ADDRESS, &wallet_addr)
            .await
            .unwrap_or(0.0);

        let native_usdc_balance = self
            .query_erc20_balance_rpc(&rpc, NATIVE_USDC_CONTRACT_ADDRESS, &wallet_addr)
            .await
            .unwrap_or(0.0);

        debug!(
            address = %address,
            usdc_e = %usdc_e_balance,
            native_usdc = %native_usdc_balance,
            "USDC balance query completed"
        );

        Ok((usdc_e_balance, native_usdc_balance))
    }

    /// Query ERC20 balanceOf for a specific token contract using raw JSON-RPC
    async fn query_erc20_balance_rpc(
        &self,
        rpc_url: &str,
        token_contract: &str,
        wallet: &Address,
    ) -> Result<f64> {
        // Build balanceOf call data: 0x70a08231 + address (padded to 32 bytes)
        // Function selector for balanceOf(address) = keccak256("balanceOf(address)")[:4]
        let mut call_data = vec![0x70, 0xa0, 0x82, 0x31]; // balanceOf selector
        let mut addr_padded = [0u8; 32];
        addr_padded[12..].copy_from_slice(wallet.as_slice());
        call_data.extend_from_slice(&addr_padded);
        let call_data_hex = format!("0x{}", hex::encode(&call_data));

        // Build JSON-RPC request for eth_call
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [
                {
                    "to": token_contract,
                    "data": call_data_hex
                },
                "latest"
            ],
            "id": 1
        });

        let response = self
            .client
            .post(rpc_url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| PolymarketError::internal(format!("RPC request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(PolymarketError::api(
                response.status().as_u16(),
                "RPC call failed".to_string(),
            ));
        }

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| PolymarketError::parse(format!("Failed to parse RPC response: {e}")))?;

        // Check for RPC error
        if let Some(error) = json.get("error") {
            return Err(PolymarketError::internal(format!("RPC error: {}", error)));
        }

        // Parse result
        let result_hex = json["result"]
            .as_str()
            .ok_or_else(|| PolymarketError::parse("Missing result in RPC response"))?;

        // Remove 0x prefix and parse as hex
        let result_bytes = hex::decode(result_hex.trim_start_matches("0x"))
            .map_err(|e| PolymarketError::parse(format!("Invalid hex result: {e}")))?;

        if result_bytes.len() < 32 {
            return Ok(0.0);
        }

        let balance_raw = U256::from_be_slice(&result_bytes[..32]);

        // Convert to f64 with 6 decimals (USDC has 6 decimals)
        let balance = balance_raw.to::<u128>() as f64 / 1_000_000.0;

        Ok(balance)
    }

    /// Create Builder API authentication headers using HMAC-SHA256
    fn create_builder_headers(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<HashMap<String, String>> {
        let credentials = self
            .builder_credentials
            .as_ref()
            .ok_or_else(|| PolymarketError::config("Builder API credentials not configured"))?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| PolymarketError::config(format!("Failed to get timestamp: {e}")))?
            .as_secs() as i64;

        let mut message = format!("{timestamp}{method}{path}");
        if let Some(b) = body {
            message.push_str(b);
        }

        // Try URL-safe base64 first (handles _ and - characters), fallback to standard
        let secret_bytes = URL_SAFE
            .decode(&credentials.secret)
            .or_else(|_| URL_SAFE_NO_PAD.decode(&credentials.secret))
            .or_else(|_| STANDARD.decode(&credentials.secret))
            .map_err(|e| PolymarketError::config(format!("Invalid base64 secret: {e}")))?;

        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&secret_bytes)
            .map_err(|e| PolymarketError::config(format!("Invalid HMAC key: {e}")))?;
        mac.update(message.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();

        let signature = STANDARD
            .encode(&signature_bytes)
            .replace('+', "-")
            .replace('/', "_");

        let mut headers = HashMap::new();
        headers.insert(
            "POLY_BUILDER_API_KEY".to_string(),
            credentials.api_key.clone(),
        );
        headers.insert(
            "POLY_BUILDER_PASSPHRASE".to_string(),
            credentials.passphrase.clone(),
        );
        headers.insert("POLY_BUILDER_SIGNATURE".to_string(), signature);
        headers.insert("POLY_BUILDER_TIMESTAMP".to_string(), timestamp.to_string());

        Ok(headers)
    }

    async fn wait_for_rate_limit(&self) {
        self.rate_limiter.until_ready().await;
    }

    /// Deploy a Safe wallet for a user via Relayer v2 API
    ///
    /// This method requires Builder API credentials to be configured.
    /// The Relayer v2 API uses HMAC authentication with Builder credentials.
    #[instrument(skip(self), fields(owner = %owner_address))]
    pub async fn deploy_safe(&self, owner_address: &str) -> Result<DeploySafeResponse> {
        self.wait_for_rate_limit().await;

        // Relayer v2 API uses /submit endpoint for Safe creation
        let endpoint = "/submit";
        let url = format!("{}{}", self.config.base_url, endpoint);

        info!(owner = %owner_address, url = %url, "Deploying Safe wallet via Relayer");

        // Build SafeCreate request body
        let request_body = serde_json::json!({
            "type": "SAFE-CREATE",
            "from": owner_address,
            "chainId": 137,
            "paymentToken": "0x0000000000000000000000000000000000000000",
            "payment": "0",
            "paymentReceiver": "0x0000000000000000000000000000000000000000"
        });
        let body_str = serde_json::to_string(&request_body)
            .map_err(|e| PolymarketError::config(format!("Failed to serialize request: {e}")))?;

        // Build request with Builder authentication headers
        let mut req_builder = self.client.post(&url);

        // Add Builder API authentication headers (required for Relayer v2)
        if self.builder_credentials.is_some() {
            let headers = self.create_builder_headers("POST", endpoint, Some(&body_str))?;
            for (key, value) in headers {
                req_builder = req_builder.header(&key, &value);
            }
        } else {
            return Err(PolymarketError::config(
                "Builder API credentials required for Safe deployment",
            ));
        }

        // Add POLY_ADDRESS header with the owner wallet address
        req_builder = req_builder
            .header("POLY_ADDRESS", owner_address)
            .header("Content-Type", "application/json")
            .body(body_str.clone());

        debug!(body = %body_str, "Sending SafeCreate request");

        let response = req_builder.send().await?;
        let status = response.status();
        let response_body = response.text().await.unwrap_or_default();

        debug!(status = %status, response = %response_body, "Relayer response received");

        if !status.is_success() {
            warn!(
                status = %status,
                endpoint = %endpoint,
                body = %response_body,
                "Relayer SafeCreate request failed"
            );
            return Err(PolymarketError::api(status.as_u16(), response_body));
        }

        let result: DeploySafeResponse = serde_json::from_str(&response_body).map_err(|e| {
            PolymarketError::parse_with_source(
                format!("Failed to parse Relayer response: {e}. Body: {response_body}"),
                e,
            )
        })?;

        info!(
            owner = %owner_address,
            proxy_address = ?result.proxy_address,
            tx_hash = ?result.transaction_hash,
            "Safe deployment response received"
        );

        Ok(result)
    }

    /// Get proxy wallet address for an owner address from Data API
    #[instrument(skip(self), fields(owner = %owner_address))]
    pub async fn get_proxy_wallet_address(&self, owner_address: &str) -> Result<Option<String>> {
        self.wait_for_rate_limit().await;

        let endpoint = format!("/profile/{owner_address}");
        let url = format!("{}{}", self.config.data_api_base_url, endpoint);

        debug!(owner = %owner_address, "Querying proxy wallet address");

        let response = self.client.get(&url).send().await?;
        let status = response.status();

        if status.as_u16() == 404 {
            debug!(owner = %owner_address, "No proxy wallet found (404)");
            return Ok(None);
        }

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            warn!(status = %status.as_u16(), response_body = %body, "Data API profile query failed");
            return Ok(None);
        }

        let body = response.text().await.unwrap_or_default();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();

        let proxy_address = json["proxyWallet"]
            .as_str()
            .or_else(|| json["polyProxy"].as_str())
            .or_else(|| json["safeAddress"].as_str())
            .or_else(|| json["proxy_wallet"].as_str())
            .map(String::from);

        if let Some(ref addr) = proxy_address {
            info!(owner = %owner_address, proxy = %addr, "Found proxy wallet");
        }

        Ok(proxy_address)
    }

    /// Deploy Safe and wait for proxy address
    #[instrument(skip(self), fields(owner = %owner_address))]
    pub async fn ensure_proxy_wallet(
        &self,
        owner_address: &str,
        max_wait_secs: Option<u64>,
    ) -> Result<Option<String>> {
        let max_wait = Duration::from_secs(max_wait_secs.unwrap_or(60));
        let poll_interval = Duration::from_secs(3);
        let start = std::time::Instant::now();

        if let Some(proxy_address) = self.get_proxy_wallet_address(owner_address).await? {
            info!(owner = %owner_address, proxy = %proxy_address, "Proxy wallet already exists");
            return Ok(Some(proxy_address));
        }

        info!(owner = %owner_address, "No existing proxy wallet, deploying new Safe");

        let deploy_result = self.deploy_safe(owner_address).await?;

        if let Some(proxy_address) = deploy_result.proxy_address {
            info!(owner = %owner_address, proxy = %proxy_address, "Safe deployed immediately");
            return Ok(Some(proxy_address));
        }

        if let Some(ref tx_hash) = deploy_result.transaction_hash {
            info!(owner = %owner_address, tx_hash = %tx_hash, "Safe deployment submitted, polling");
        }

        while start.elapsed() < max_wait {
            tokio::time::sleep(poll_interval).await;

            match self.get_proxy_wallet_address(owner_address).await {
                Ok(Some(proxy_address)) => {
                    info!(owner = %owner_address, proxy = %proxy_address, "Proxy wallet now available");
                    return Ok(Some(proxy_address));
                }
                Ok(None) => {
                    debug!(owner = %owner_address, "Proxy wallet not yet available");
                }
                Err(e) => {
                    warn!(owner = %owner_address, error = %e, "Error polling for proxy wallet");
                }
            }
        }

        warn!(owner = %owner_address, "Proxy wallet not available after max wait time");
        Ok(None)
    }

    /// Deploy Safe with an EIP-712 signature
    ///
    /// This method requires the user's EIP-712 signature on SafeCreate typed data.
    /// The signature should be created by signing the data from `build_safe_create_typed_data`.
    ///
    /// # Arguments
    /// * `owner_address` - The owner's embedded wallet address
    /// * `signature` - The EIP-712 signature (hex string with 0x prefix)
    #[instrument(skip(self, signature), fields(owner = %owner_address))]
    pub async fn deploy_safe_with_signature(
        &self,
        owner_address: &str,
        signature: &str,
    ) -> Result<TransactionReceipt> {
        self.wait_for_rate_limit().await;

        let safe_address = derive_safe_address(owner_address)?;

        info!(owner = %owner_address, safe_address = %safe_address, "Deploying Safe with signature");

        // Compute the digest and verify signature BEFORE sending to relayer
        let digest = compute_safe_create_digest_internal(owner_address, DEFAULT_CHAIN_ID)?;
        let digest_hex = format!("{digest:#x}");

        debug!(digest = %digest_hex, owner = %owner_address, "Computed SafeCreate digest for verification");

        // Verify the signature recovers to the expected owner address
        match verify_signature(signature, &digest_hex, owner_address) {
            Ok(recovered) => {
                debug!(recovered_address = %recovered, owner_address = %owner_address, "Signature verification PASSED");
            }
            Err(e) => {
                // Log the error but continue for now to see what the relayer says
                // In production, we might want to fail fast here
                warn!(
                    error = %e,
                    signature = %signature,
                    digest = %digest_hex,
                    owner = %owner_address,
                    "Signature verification FAILED - this will likely cause relayer rejection"
                );
            }
        }

        // Pack the signature for Relayer API (transforms v value)
        let packed_signature = pack_signature(signature)?;
        debug!(original_sig = %signature, packed_sig = %packed_signature, "Signature packed");

        // Build SignatureParams for SafeCreate (no payment)
        let sig_params = SignatureParams {
            payment_token: Some("0x0000000000000000000000000000000000000000".to_string()),
            payment: Some("0".to_string()),
            payment_receiver: Some("0x0000000000000000000000000000000000000000".to_string()),
            ..Default::default()
        };

        let tx_request = TransactionRequest {
            r#type: TransactionType::SafeCreate,
            from: owner_address.to_string(),
            to: SAFE_FACTORY.to_string(),
            proxy_wallet: Some(safe_address.clone()),
            data: "0x".to_string(),
            nonce: None,
            signature: packed_signature,
            signature_params: sig_params,
            metadata: None,
        };

        // Use /submit endpoint for SafeCreate
        let receipt = self.submit_safe_create(&tx_request).await?;

        info!(owner = %owner_address, tx_id = %receipt.id, state = ?receipt.state, "Safe deployment submitted");

        Ok(receipt)
    }

    /// Submit a SafeCreate transaction to the Relayer /submit endpoint
    #[instrument(skip(self, request))]
    async fn submit_safe_create(&self, request: &TransactionRequest) -> Result<TransactionReceipt> {
        self.wait_for_rate_limit().await;

        let endpoint = "/submit";
        let url = format!("{}{}", self.config.base_url, endpoint);

        let body = serde_json::to_string(request)
            .map_err(|e| PolymarketError::config(format!("Failed to serialize request: {e}")))?;

        // Log the full request body for debugging
        debug!(
            endpoint = %endpoint,
            from = %request.from,
            to = %request.to,
            proxy_wallet = ?request.proxy_wallet,
            signature_len = %request.signature.len(),
            "Submitting SafeCreate to Relayer"
        );
        debug!(body = %body, "SafeCreate request body");

        let mut req_builder = self.client.post(&url);

        if self.builder_credentials.is_some() {
            let headers = self.create_builder_headers("POST", endpoint, Some(&body))?;
            let header_keys: Vec<String> = headers.iter().map(|(k, _)| k.to_string()).collect();
            debug!(headers = ?header_keys, "Applying builder headers for SafeCreate");
            for (key, value) in headers {
                req_builder = req_builder.header(&key, &value);
            }
        } else {
            return Err(PolymarketError::config(
                "Builder API credentials required for Safe deployment",
            ));
        }

        // Add POLY_ADDRESS header
        req_builder = req_builder
            .header("POLY_ADDRESS", &request.from)
            .header("Content-Type", "application/json")
            .body(body);

        let response = req_builder.send().await?;
        let status = response.status();
        let response_body = response.text().await.unwrap_or_default();

        debug!(status = %status, response = %response_body, "Relayer /submit response");

        if !status.is_success() {
            warn!(status = %status, endpoint = %endpoint, body = %response_body, "Relayer /submit failed");
            return Err(PolymarketError::api(status.as_u16(), response_body));
        }

        let receipt: TransactionReceipt = serde_json::from_str(&response_body).map_err(|e| {
            PolymarketError::parse_with_source(
                format!("Failed to parse receipt: {e}. Body: {response_body}"),
                e,
            )
        })?;

        Ok(receipt)
    }

    /// Submit a transaction to the Relayer API
    ///
    /// Uses the `/submit` endpoint for both SafeCreate and Safe execution transactions.
    /// Note: `/transaction` is only for querying transaction status (GET), not submitting.
    #[instrument(skip(self, request))]
    pub async fn submit_transaction(
        &self,
        request: &TransactionRequest,
    ) -> Result<TransactionReceipt> {
        self.wait_for_rate_limit().await;

        let endpoint = "/submit";
        let url = format!("{}{}", self.config.base_url, endpoint);

        let body = serde_json::to_string(request)
            .map_err(|e| PolymarketError::config(format!("Failed to serialize request: {e}")))?;

        debug!(endpoint = %endpoint, "Submitting transaction to Relayer");

        let mut req_builder = self.client.post(&url);

        if self.builder_credentials.is_some() {
            let headers = self.create_builder_headers("POST", endpoint, Some(&body))?;
            for (key, value) in headers {
                req_builder = req_builder.header(&key, &value);
            }
        }

        // Add POLY_ADDRESS header (required for Safe transactions)
        let response = req_builder
            .header("POLY_ADDRESS", &request.from)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await?;

        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            warn!(status = %status, url = %url, body = %body, "Relayer /submit request failed");
            return Err(PolymarketError::api(status.as_u16(), body));
        }

        let receipt: TransactionReceipt = response.json().await.map_err(|e| {
            PolymarketError::parse_with_source(format!("Failed to parse receipt: {e}"), e)
        })?;

        Ok(receipt)
    }

    /// Get the status of a transaction
    ///
    /// Uses the `/transaction?id=xxx` endpoint (query parameter, not path parameter)
    /// as per the official Polymarket builder-relayer-client SDK.
    #[instrument(skip(self), fields(tx_id = %transaction_id))]
    pub async fn get_transaction_status(&self, transaction_id: &str) -> Result<TransactionReceipt> {
        self.wait_for_rate_limit().await;

        // Official SDK uses query parameter: /transaction?id=xxx
        let endpoint = "/transaction";
        let url = format!("{}{}?id={}", self.config.base_url, endpoint, transaction_id);

        debug!(tx_id = %transaction_id, url = %url, "Querying transaction status");

        let mut req_builder = self.client.get(&url);

        if self.builder_credentials.is_some() {
            let headers = self.create_builder_headers("GET", endpoint, None)?;
            for (key, value) in headers {
                req_builder = req_builder.header(&key, &value);
            }
        }

        let response = req_builder.send().await?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(PolymarketError::api(status.as_u16(), body));
        }

        // The API returns an array of transactions, we need the first one
        let receipts: Vec<TransactionReceipt> = response.json().await.map_err(|e| {
            PolymarketError::parse_with_source(format!("Failed to parse status: {e}"), e)
        })?;

        receipts.into_iter().next().ok_or_else(|| {
            PolymarketError::api(404, format!("Transaction not found: {}", transaction_id))
        })
    }

    /// Poll until a transaction is confirmed or reaches a terminal state
    #[instrument(skip(self), fields(tx_id = %transaction_id))]
    pub async fn poll_until_confirmed(
        &self,
        transaction_id: &str,
        max_wait_secs: Option<u64>,
        poll_interval_secs: Option<u64>,
    ) -> Result<TransactionReceipt> {
        let max_wait = Duration::from_secs(max_wait_secs.unwrap_or(120));
        let poll_interval = Duration::from_secs(poll_interval_secs.unwrap_or(3));
        let start = std::time::Instant::now();

        info!(tx_id = %transaction_id, max_wait_secs = %max_wait.as_secs(), "Polling until confirmed");

        loop {
            let receipt = self.get_transaction_status(transaction_id).await?;

            if receipt.state.is_terminal() {
                if receipt.state.is_success() {
                    info!(tx_id = %transaction_id, "Transaction confirmed");
                } else {
                    warn!(
                        tx_id = %transaction_id,
                        state = ?receipt.state,
                        tx_hash = ?receipt.transaction_hash,
                        error = ?receipt.error,
                        "Transaction failed"
                    );
                    debug!(tx_id = %transaction_id, receipt = ?receipt, "Full transaction receipt");
                }
                return Ok(receipt);
            }

            if start.elapsed() >= max_wait {
                warn!(tx_id = %transaction_id, "Polling timeout reached");
                return Ok(receipt);
            }

            debug!(tx_id = %transaction_id, state = ?receipt.state, "Pending, continuing poll");
            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Get the next nonce for an address
    ///
    /// # Arguments
    /// * `address` - The signer address (EOA/embedded wallet, NOT proxy wallet)
    /// * `nonce_type` - The type of nonce to query (SAFE for transactions, SAFECREATE for deployment)
    ///
    /// # API Format
    /// `GET /nonce?address={address}&type={SAFE|SAFECREATE}`
    #[instrument(skip(self), fields(address = %address))]
    pub async fn get_next_nonce(&self, address: &str, nonce_type: NonceType) -> Result<u64> {
        self.wait_for_rate_limit().await;

        // Polymarket Relayer API uses uppercase type values
        let nonce_type_str = match nonce_type {
            NonceType::Transaction => "SAFE",
            NonceType::SafeCreate => "SAFECREATE",
        };

        // Correct API format: /nonce?address=...&type=...
        let endpoint = format!("/nonce?address={address}&type={nonce_type_str}");
        let url = format!("{}{}", self.config.base_url, endpoint);

        debug!(address = %address, nonce_type = %nonce_type_str, url = %url, "Getting next nonce");

        let mut req_builder = self.client.get(&url);

        if self.builder_credentials.is_some() {
            // For GET requests with query params, sign with just the path portion
            let sign_endpoint = format!("/nonce?address={address}&type={nonce_type_str}");
            let headers = self.create_builder_headers("GET", &sign_endpoint, None)?;
            for (key, value) in headers {
                req_builder = req_builder.header(&key, &value);
            }
        }

        let response = req_builder.send().await?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(PolymarketError::api(status.as_u16(), body));
        }

        // Polymarket returns nonce as string, need to parse
        #[derive(Deserialize)]
        struct NonceResponse {
            nonce: String,
        }

        let nonce_resp: NonceResponse = response.json().await.map_err(|e| {
            PolymarketError::parse_with_source(format!("Failed to parse nonce response: {e}"), e)
        })?;

        let nonce: u64 = nonce_resp.nonce.parse().map_err(|e| {
            PolymarketError::parse(format!(
                "Failed to parse nonce value '{}': {}",
                nonce_resp.nonce, e
            ))
        })?;

        debug!(address = %address, nonce = %nonce, "Got next nonce");

        Ok(nonce)
    }

    /// Deploy Safe with signature and wait for confirmation
    #[instrument(skip(self, signature), fields(owner = %owner_address))]
    pub async fn deploy_safe_and_wait(
        &self,
        owner_address: &str,
        signature: &str,
        max_wait_secs: Option<u64>,
    ) -> Result<String> {
        let receipt = self
            .deploy_safe_with_signature(owner_address, signature)
            .await?;
        let final_receipt = self
            .poll_until_confirmed(&receipt.id, max_wait_secs, None)
            .await?;

        if !final_receipt.state.is_success() {
            return Err(PolymarketError::api(
                500,
                format!(
                    "Safe deployment failed: {:?} - {:?}",
                    final_receipt.state, final_receipt.error
                ),
            ));
        }

        final_receipt
            .proxy_address
            .ok_or_else(|| PolymarketError::api(500, "No proxy address returned"))
    }

    // ========================================================================
    // Approve Service Methods
    // ========================================================================

    /// Check ERC20 token allowance via RPC
    ///
    /// # Arguments
    /// * `token_address` - ERC20 token contract address (USDC)
    /// * `owner` - Token owner address (proxy wallet)
    /// * `spender` - Spender address (Exchange contract)
    ///
    /// # Returns
    /// Current allowance amount in raw units (6 decimals for USDC)
    #[instrument(skip(self), fields(owner = %owner, spender = %spender))]
    pub async fn check_erc20_allowance(
        &self,
        token_address: &str,
        owner: &str,
        spender: &str,
    ) -> Result<U256> {
        let rpc = self
            .default_rpc
            .as_ref()
            .ok_or_else(|| PolymarketError::config("RPC URL not configured"))?;

        let calldata = encode_erc20_allowance_query(owner, spender)?;

        let params = serde_json::json!([
            {
                "to": token_address,
                "data": calldata
            },
            "latest"
        ]);

        let response: serde_json::Value = self
            .client
            .post(rpc)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": params,
                "id": 1
            }))
            .send()
            .await?
            .json()
            .await?;

        let result = response["result"]
            .as_str()
            .ok_or_else(|| PolymarketError::api(500, "Invalid RPC response"))?;

        // Parse hex result to U256
        let result_bytes = hex::decode(result.trim_start_matches("0x"))
            .map_err(|e| PolymarketError::validation(format!("Invalid hex: {e}")))?;

        if result_bytes.len() != 32 {
            return Err(PolymarketError::validation(
                "Invalid allowance response length",
            ));
        }

        Ok(U256::from_be_slice(&result_bytes))
    }

    /// Check ERC1155 approval status via RPC
    ///
    /// # Arguments
    /// * `token_address` - ERC1155 token contract address (CTF)
    /// * `owner` - Token owner address (proxy wallet)
    /// * `operator` - Operator address (Exchange contract)
    ///
    /// # Returns
    /// Whether the operator is approved for all tokens
    #[instrument(skip(self), fields(owner = %owner, operator = %operator))]
    pub async fn check_erc1155_approval(
        &self,
        token_address: &str,
        owner: &str,
        operator: &str,
    ) -> Result<bool> {
        let rpc = self
            .default_rpc
            .as_ref()
            .ok_or_else(|| PolymarketError::config("RPC URL not configured"))?;

        let calldata = encode_erc1155_is_approved_for_all(owner, operator)?;

        let params = serde_json::json!([
            {
                "to": token_address,
                "data": calldata
            },
            "latest"
        ]);

        let response: serde_json::Value = self
            .client
            .post(rpc)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": params,
                "id": 1
            }))
            .send()
            .await?
            .json()
            .await?;

        let result = response["result"]
            .as_str()
            .ok_or_else(|| PolymarketError::api(500, "Invalid RPC response"))?;

        // Parse hex result - returns true (1) or false (0)
        let result_bytes = hex::decode(result.trim_start_matches("0x"))
            .map_err(|e| PolymarketError::validation(format!("Invalid hex: {e}")))?;

        if result_bytes.is_empty() || result_bytes.len() > 32 {
            return Ok(false);
        }

        // Check if last byte is 1 (true)
        Ok(result_bytes.last() == Some(&1))
    }

    /// Check if proxy wallet has sufficient USDC allowance for trading
    ///
    /// # Arguments
    /// * `proxy_wallet` - Proxy wallet address
    /// * `spender` - Exchange contract address
    /// * `required_amount` - Required allowance amount in raw USDC (6 decimals)
    /// * `use_native_usdc` - Whether to use native USDC or bridged USDC.e
    ///
    /// # Returns
    /// (has_sufficient_allowance, current_allowance)
    pub async fn check_usdc_allowance(
        &self,
        proxy_wallet: &str,
        spender: &str,
        required_amount: U256,
        use_native_usdc: bool,
    ) -> Result<(bool, U256)> {
        let token = if use_native_usdc {
            NATIVE_USDC_CONTRACT_ADDRESS
        } else {
            USDC_CONTRACT_ADDRESS
        };

        let current = self
            .check_erc20_allowance(token, proxy_wallet, spender)
            .await?;
        let sufficient = current >= required_amount;

        debug!(
            proxy_wallet = %proxy_wallet,
            spender = %spender,
            required = %required_amount,
            current = %current,
            sufficient = %sufficient,
            "Checked USDC allowance"
        );

        Ok((sufficient, current))
    }

    /// Check if proxy wallet has CTF approval for trading
    ///
    /// # Arguments
    /// * `proxy_wallet` - Proxy wallet address
    /// * `operator` - Exchange contract address
    ///
    /// # Returns
    /// Whether the operator is approved
    pub async fn check_ctf_approval(&self, proxy_wallet: &str, operator: &str) -> Result<bool> {
        let approved = self
            .check_erc1155_approval(CONDITIONAL_TOKENS_ADDRESS, proxy_wallet, operator)
            .await?;

        debug!(
            proxy_wallet = %proxy_wallet,
            operator = %operator,
            approved = %approved,
            "Checked CTF approval"
        );

        Ok(approved)
    }

    /// Check all required approvals for a market type
    ///
    /// # Arguments
    /// * `proxy_wallet` - Proxy wallet address
    /// * `market_type` - Standard or NegRisk market
    /// * `use_native_usdc` - Whether to use native USDC
    ///
    /// # Returns
    /// ApprovalStatus indicating which approvals are missing
    pub async fn check_approvals(
        &self,
        proxy_wallet: &str,
        market_type: MarketType,
        use_native_usdc: bool,
    ) -> Result<ApprovalStatus> {
        let targets = ApprovalTargets::for_market_type(market_type);

        // Check USDC allowance for exchange
        let (usdc_approved, usdc_allowance) = self
            .check_usdc_allowance(
                proxy_wallet,
                targets.usdc_spender,
                U256::from(1),
                use_native_usdc,
            )
            .await?;

        // Check CTF approval for exchange
        let ctf_approved = self
            .check_ctf_approval(proxy_wallet, targets.ctf_operator)
            .await?;

        // For neg-risk markets, also check adapter approval
        let adapter_approved = if let Some(adapter) = targets.ctf_adapter_operator {
            self.check_ctf_approval(proxy_wallet, adapter).await?
        } else {
            true
        };

        Ok(ApprovalStatus {
            usdc_approved,
            usdc_allowance,
            ctf_approved,
            adapter_approved,
            all_approved: usdc_approved && ctf_approved && adapter_approved,
        })
    }
}

/// Status of token approvals for trading
#[derive(Debug, Clone)]
pub struct ApprovalStatus {
    /// Whether USDC is approved for exchange
    pub usdc_approved: bool,
    /// Current USDC allowance
    pub usdc_allowance: U256,
    /// Whether CTF is approved for exchange
    pub ctf_approved: bool,
    /// Whether CTF is approved for adapter (neg-risk only)
    pub adapter_approved: bool,
    /// Whether all required approvals are in place
    pub all_approved: bool,
}

impl ApprovalStatus {
    /// Get list of missing approvals
    pub fn missing_approvals(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.usdc_approved {
            missing.push("USDC → Exchange");
        }
        if !self.ctf_approved {
            missing.push("CTF → Exchange");
        }
        if !self.adapter_approved {
            missing.push("CTF → Adapter");
        }
        missing
    }
}

// ============================================================================
// Safe Transaction EIP-712 (for USDC transfers)
// ============================================================================

/// Safe transaction domain name
#[allow(dead_code)]
const SAFE_DOMAIN_NAME: &str = "Gnosis Safe";

/// Safe transaction domain version
#[allow(dead_code)]
const SAFE_DOMAIN_VERSION: &str = "1.3.0";

/// SafeTx type string for EIP-712
const SAFE_TX_TYPE_STR: &str = "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)";

/// EIP712Domain type string for Safe (includes version)
const SAFE_DOMAIN_TYPE_STR: &str = "EIP712Domain(uint256 chainId,address verifyingContract)";

/// ERC20 transfer function selector: keccak256("transfer(address,uint256)")[:4]
const ERC20_TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// ERC20 approve function selector: keccak256("approve(address,uint256)")[:4]
const ERC20_APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

/// ERC20 allowance function selector: keccak256("allowance(address,address)")[:4]
const ERC20_ALLOWANCE_SELECTOR: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e];

/// ERC1155 setApprovalForAll function selector: keccak256("setApprovalForAll(address,bool)")[:4]
const ERC1155_SET_APPROVAL_FOR_ALL_SELECTOR: [u8; 4] = [0xa2, 0x2c, 0xb4, 0x65];

/// ERC1155 isApprovedForAll function selector: keccak256("isApprovedForAll(address,address)")[:4]
const ERC1155_IS_APPROVED_FOR_ALL_SELECTOR: [u8; 4] = [0xe9, 0x85, 0xe9, 0xc5];

/// Safe Transaction typed data for EIP-712 signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeTxTypedData {
    /// Domain data
    pub domain: SafeTxDomain,
    /// Message data
    pub message: SafeTxMessage,
    /// Primary type name (must be "primaryType" for EIP-712)
    #[serde(rename = "primaryType")]
    pub primary_type: String,
    /// Type definitions
    pub types: SafeTxTypes,
}

/// EIP-712 Domain for Safe transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeTxDomain {
    /// Chain ID (137 for Polygon)
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    /// Safe wallet address (proxy wallet)
    #[serde(rename = "verifyingContract")]
    pub verifying_contract: String,
}

/// SafeTx message for EIP-712 signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeTxMessage {
    /// Target contract address (USDC contract for transfers)
    pub to: String,
    /// ETH value (0 for ERC20 transfers)
    pub value: String,
    /// Encoded function call data
    pub data: String,
    /// Operation type (0 = Call, 1 = DelegateCall)
    pub operation: u8,
    /// Gas for Safe internal call
    #[serde(rename = "safeTxGas")]
    pub safe_tx_gas: String,
    /// Base gas for transaction
    #[serde(rename = "baseGas")]
    pub base_gas: String,
    /// Gas price (0 for gasless)
    #[serde(rename = "gasPrice")]
    pub gas_price: String,
    /// Gas token address (zero for ETH)
    #[serde(rename = "gasToken")]
    pub gas_token: String,
    /// Refund receiver address
    #[serde(rename = "refundReceiver")]
    pub refund_receiver: String,
    /// Safe nonce
    pub nonce: String,
}

/// Type definitions for SafeTx
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeTxTypes {
    /// EIP712Domain type
    #[serde(rename = "EIP712Domain")]
    pub eip712_domain: Vec<TypedDataField>,
    /// SafeTx type
    #[serde(rename = "SafeTx")]
    pub safe_tx: Vec<TypedDataField>,
}

impl Default for SafeTxTypes {
    fn default() -> Self {
        Self {
            eip712_domain: vec![
                TypedDataField {
                    name: "chainId".to_string(),
                    r#type: "uint256".to_string(),
                },
                TypedDataField {
                    name: "verifyingContract".to_string(),
                    r#type: "address".to_string(),
                },
            ],
            safe_tx: vec![
                TypedDataField {
                    name: "to".to_string(),
                    r#type: "address".to_string(),
                },
                TypedDataField {
                    name: "value".to_string(),
                    r#type: "uint256".to_string(),
                },
                TypedDataField {
                    name: "data".to_string(),
                    r#type: "bytes".to_string(),
                },
                TypedDataField {
                    name: "operation".to_string(),
                    r#type: "uint8".to_string(),
                },
                TypedDataField {
                    name: "safeTxGas".to_string(),
                    r#type: "uint256".to_string(),
                },
                TypedDataField {
                    name: "baseGas".to_string(),
                    r#type: "uint256".to_string(),
                },
                TypedDataField {
                    name: "gasPrice".to_string(),
                    r#type: "uint256".to_string(),
                },
                TypedDataField {
                    name: "gasToken".to_string(),
                    r#type: "address".to_string(),
                },
                TypedDataField {
                    name: "refundReceiver".to_string(),
                    r#type: "address".to_string(),
                },
                TypedDataField {
                    name: "nonce".to_string(),
                    r#type: "uint256".to_string(),
                },
            ],
        }
    }
}

/// Encode ERC20 transfer calldata
///
/// # Arguments
/// * `recipient` - The recipient address
/// * `amount` - The amount in token units (e.g., USDC with 6 decimals: 1 USDC = 1_000_000)
///
/// # Returns
/// Hex-encoded calldata with 0x prefix
pub fn encode_erc20_transfer(recipient: &str, amount: u128) -> Result<String> {
    let recipient_addr: Address = recipient
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid recipient address: {e}")))?;

    let mut calldata = Vec::with_capacity(68);
    // Function selector
    calldata.extend_from_slice(&ERC20_TRANSFER_SELECTOR);
    // Recipient address (padded to 32 bytes)
    let mut addr_bytes = [0u8; 32];
    addr_bytes[12..].copy_from_slice(recipient_addr.as_slice());
    calldata.extend_from_slice(&addr_bytes);
    // Amount (32 bytes)
    let amount_u256 = U256::from(amount);
    calldata.extend_from_slice(&amount_u256.to_be_bytes::<32>());

    Ok(format!("0x{}", hex::encode(&calldata)))
}

/// Encode ERC20 approve function call
///
/// # Arguments
/// * `spender` - The address authorized to spend tokens
/// * `amount` - Amount to approve (use U256::MAX for unlimited)
///
/// # Returns
/// Encoded calldata for approve(address,uint256)
pub fn encode_erc20_approve(spender: &str, amount: U256) -> Result<String> {
    let spender_addr: Address = spender
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid spender address: {e}")))?;

    let mut calldata = Vec::with_capacity(68);
    // Function selector
    calldata.extend_from_slice(&ERC20_APPROVE_SELECTOR);
    // Spender address (padded to 32 bytes)
    let mut addr_bytes = [0u8; 32];
    addr_bytes[12..].copy_from_slice(spender_addr.as_slice());
    calldata.extend_from_slice(&addr_bytes);
    // Amount (32 bytes)
    calldata.extend_from_slice(&amount.to_be_bytes::<32>());

    Ok(format!("0x{}", hex::encode(&calldata)))
}

/// Encode ERC20 allowance query function call
///
/// # Arguments
/// * `owner` - The token owner address
/// * `spender` - The spender address
///
/// # Returns
/// Encoded calldata for allowance(address,address)
pub fn encode_erc20_allowance_query(owner: &str, spender: &str) -> Result<String> {
    let owner_addr: Address = owner
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid owner address: {e}")))?;
    let spender_addr: Address = spender
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid spender address: {e}")))?;

    let mut calldata = Vec::with_capacity(68);
    // Function selector
    calldata.extend_from_slice(&ERC20_ALLOWANCE_SELECTOR);
    // Owner address (padded to 32 bytes)
    let mut owner_bytes = [0u8; 32];
    owner_bytes[12..].copy_from_slice(owner_addr.as_slice());
    calldata.extend_from_slice(&owner_bytes);
    // Spender address (padded to 32 bytes)
    let mut spender_bytes = [0u8; 32];
    spender_bytes[12..].copy_from_slice(spender_addr.as_slice());
    calldata.extend_from_slice(&spender_bytes);

    Ok(format!("0x{}", hex::encode(&calldata)))
}

/// Encode ERC1155 setApprovalForAll function call
///
/// # Arguments
/// * `operator` - The address to grant/revoke approval for all tokens
/// * `approved` - Whether to approve or revoke
///
/// # Returns
/// Encoded calldata for setApprovalForAll(address,bool)
pub fn encode_erc1155_set_approval_for_all(operator: &str, approved: bool) -> Result<String> {
    let operator_addr: Address = operator
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid operator address: {e}")))?;

    let mut calldata = Vec::with_capacity(68);
    // Function selector
    calldata.extend_from_slice(&ERC1155_SET_APPROVAL_FOR_ALL_SELECTOR);
    // Operator address (padded to 32 bytes)
    let mut addr_bytes = [0u8; 32];
    addr_bytes[12..].copy_from_slice(operator_addr.as_slice());
    calldata.extend_from_slice(&addr_bytes);
    // Approved bool (padded to 32 bytes, 1 or 0 in last byte)
    let mut bool_bytes = [0u8; 32];
    bool_bytes[31] = if approved { 1 } else { 0 };
    calldata.extend_from_slice(&bool_bytes);

    Ok(format!("0x{}", hex::encode(&calldata)))
}

/// Encode ERC1155 isApprovedForAll query function call
///
/// # Arguments
/// * `owner` - The token owner address
/// * `operator` - The operator address to check approval for
///
/// # Returns
/// Encoded calldata for isApprovedForAll(address,address)
pub fn encode_erc1155_is_approved_for_all(owner: &str, operator: &str) -> Result<String> {
    let owner_addr: Address = owner
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid owner address: {e}")))?;
    let operator_addr: Address = operator
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid operator address: {e}")))?;

    let mut calldata = Vec::with_capacity(68);
    // Function selector
    calldata.extend_from_slice(&ERC1155_IS_APPROVED_FOR_ALL_SELECTOR);
    // Owner address (padded to 32 bytes)
    let mut owner_bytes = [0u8; 32];
    owner_bytes[12..].copy_from_slice(owner_addr.as_slice());
    calldata.extend_from_slice(&owner_bytes);
    // Operator address (padded to 32 bytes)
    let mut operator_bytes = [0u8; 32];
    operator_bytes[12..].copy_from_slice(operator_addr.as_slice());
    calldata.extend_from_slice(&operator_bytes);

    Ok(format!("0x{}", hex::encode(&calldata)))
}

/// Build SafeTx typed data for USDC transfer
///
/// # Arguments
/// * `proxy_wallet` - The Safe (proxy wallet) address
/// * `recipient` - The recipient address for USDC
/// * `amount_usdc` - Amount in USDC (human readable, e.g., 100.50 = $100.50)
/// * `nonce` - Safe nonce
/// * `use_native_usdc` - Whether to use native USDC (true) or bridged USDC.e (false)
/// * `chain_id` - Chain ID (default 137 for Polygon)
///
/// # Returns
/// Complete SafeTx typed data ready for EIP-712 signing
pub fn build_usdc_transfer_typed_data(
    proxy_wallet: &str,
    recipient: &str,
    amount_usdc: f64,
    nonce: u64,
    use_native_usdc: bool,
    chain_id: Option<u64>,
) -> Result<SafeTxTypedData> {
    // Validate addresses
    let _: Address = proxy_wallet
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid proxy wallet address: {e}")))?;
    let _: Address = recipient
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid recipient address: {e}")))?;

    // Convert USDC amount to raw units (6 decimals)
    let amount_raw = (amount_usdc * 1_000_000.0) as u128;

    // Select USDC contract
    let usdc_contract = if use_native_usdc {
        NATIVE_USDC_CONTRACT_ADDRESS
    } else {
        USDC_CONTRACT_ADDRESS
    };

    // Encode transfer calldata
    let calldata = encode_erc20_transfer(recipient, amount_raw)?;

    Ok(SafeTxTypedData {
        domain: SafeTxDomain {
            chain_id: chain_id.unwrap_or(137),
            verifying_contract: proxy_wallet.to_string(),
        },
        message: SafeTxMessage {
            to: usdc_contract.to_string(),
            value: "0".to_string(),
            data: calldata,
            operation: 0, // Call
            safe_tx_gas: "0".to_string(),
            base_gas: "0".to_string(),
            gas_price: "0".to_string(),
            gas_token: "0x0000000000000000000000000000000000000000".to_string(),
            refund_receiver: "0x0000000000000000000000000000000000000000".to_string(),
            nonce: nonce.to_string(),
        },
        primary_type: "SafeTx".to_string(),
        types: SafeTxTypes::default(),
    })
}

/// Build EIP-712 typed data for token approval (ERC20 approve)
///
/// Creates a Safe transaction that approves a spender (typically Exchange contract)
/// to spend unlimited USDC tokens from the proxy wallet.
///
/// # Arguments
/// * `proxy_wallet` - Safe proxy wallet address performing the approval
/// * `spender` - Address to approve (Exchange contract)
/// * `nonce` - Safe nonce from Relayer API
/// * `use_native_usdc` - Whether to use native USDC (true) or bridged USDC.e (false)
/// * `chain_id` - Chain ID (default: 137 for Polygon)
///
/// # Returns
/// EIP-712 typed data ready for user signature
pub fn build_token_approve_typed_data(
    proxy_wallet: &str,
    spender: &str,
    nonce: u64,
    use_native_usdc: bool,
    chain_id: Option<u64>,
) -> Result<SafeTxTypedData> {
    use alloy_primitives::U256;

    // Validate addresses
    let _: Address = proxy_wallet
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid proxy wallet address: {e}")))?;
    let _: Address = spender
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid spender address: {e}")))?;

    // Select USDC contract
    let usdc_contract = if use_native_usdc {
        NATIVE_USDC_CONTRACT_ADDRESS
    } else {
        USDC_CONTRACT_ADDRESS
    };

    // Encode approve calldata with unlimited approval (U256::MAX)
    let calldata = encode_erc20_approve(spender, U256::MAX)?;

    Ok(SafeTxTypedData {
        domain: SafeTxDomain {
            chain_id: chain_id.unwrap_or(137),
            verifying_contract: proxy_wallet.to_string(),
        },
        message: SafeTxMessage {
            to: usdc_contract.to_string(),
            value: "0".to_string(),
            data: calldata,
            operation: 0, // Call
            safe_tx_gas: "0".to_string(),
            base_gas: "0".to_string(),
            gas_price: "0".to_string(),
            gas_token: "0x0000000000000000000000000000000000000000".to_string(),
            refund_receiver: "0x0000000000000000000000000000000000000000".to_string(),
            nonce: nonce.to_string(),
        },
        primary_type: "SafeTx".to_string(),
        types: SafeTxTypes::default(),
    })
}

/// Market type for determining which contracts to approve
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketType {
    /// Standard prediction markets
    Standard,
    /// Negative risk markets (multi-outcome)
    NegRisk,
}

/// Build EIP-712 typed data for CTF (ERC1155) approval
///
/// Creates a Safe transaction that approves an operator (Exchange or NegRiskExchange)
/// to transfer all CTF tokens (outcome shares) from the proxy wallet.
///
/// # Arguments
/// * `proxy_wallet` - Safe proxy wallet address performing the approval
/// * `operator` - Address to approve (Exchange or NegRiskExchange contract)
/// * `nonce` - Safe nonce from Relayer API
/// * `chain_id` - Chain ID (default: 137 for Polygon)
///
/// # Returns
/// EIP-712 typed data ready for user signature
pub fn build_ctf_approve_typed_data(
    proxy_wallet: &str,
    operator: &str,
    nonce: u64,
    chain_id: Option<u64>,
) -> Result<SafeTxTypedData> {
    // Validate addresses
    let _: Address = proxy_wallet
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid proxy wallet address: {e}")))?;
    let _: Address = operator
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid operator address: {e}")))?;

    // Encode setApprovalForAll calldata
    let calldata = encode_erc1155_set_approval_for_all(operator, true)?;

    Ok(SafeTxTypedData {
        domain: SafeTxDomain {
            chain_id: chain_id.unwrap_or(137),
            verifying_contract: proxy_wallet.to_string(),
        },
        message: SafeTxMessage {
            to: CONDITIONAL_TOKENS_ADDRESS.to_string(),
            value: "0".to_string(),
            data: calldata,
            operation: 0, // Call
            safe_tx_gas: "0".to_string(),
            base_gas: "0".to_string(),
            gas_price: "0".to_string(),
            gas_token: "0x0000000000000000000000000000000000000000".to_string(),
            refund_receiver: "0x0000000000000000000000000000000000000000".to_string(),
            nonce: nonce.to_string(),
        },
        primary_type: "SafeTx".to_string(),
        types: SafeTxTypes::default(),
    })
}

/// Approval target configuration based on market type
#[derive(Debug, Clone)]
pub struct ApprovalTargets {
    /// USDC spender (Exchange or NegRiskExchange)
    pub usdc_spender: &'static str,
    /// CTF operator (Exchange or NegRiskExchange)
    pub ctf_operator: &'static str,
    /// Additional USDC spender for split/merge (CTF or NegRiskAdapter)
    pub usdc_split_spender: Option<&'static str>,
    /// Additional CTF operator for neg-risk (NegRiskAdapter)
    pub ctf_adapter_operator: Option<&'static str>,
}

impl ApprovalTargets {
    /// Get approval targets for standard markets
    pub fn standard() -> Self {
        Self {
            usdc_spender: EXCHANGE_ADDRESS,
            ctf_operator: EXCHANGE_ADDRESS,
            usdc_split_spender: Some(CONDITIONAL_TOKENS_ADDRESS),
            ctf_adapter_operator: None,
        }
    }

    /// Get approval targets for neg-risk markets
    pub fn neg_risk() -> Self {
        Self {
            usdc_spender: NEG_RISK_CTF_EXCHANGE_ADDRESS,
            ctf_operator: NEG_RISK_CTF_EXCHANGE_ADDRESS,
            usdc_split_spender: Some(NEG_RISK_ADAPTER_ADDRESS),
            ctf_adapter_operator: Some(NEG_RISK_ADAPTER_ADDRESS),
        }
    }

    /// Get all approval targets (supports both market types)
    pub fn all() -> Self {
        Self {
            usdc_spender: EXCHANGE_ADDRESS, // Standard exchange
            ctf_operator: EXCHANGE_ADDRESS,
            usdc_split_spender: Some(CONDITIONAL_TOKENS_ADDRESS),
            ctf_adapter_operator: None,
        }
    }

    /// Get targets for a specific market type
    pub fn for_market_type(market_type: MarketType) -> Self {
        match market_type {
            MarketType::Standard => Self::standard(),
            MarketType::NegRisk => Self::neg_risk(),
        }
    }
}

/// Compute the EIP-712 domain separator for Safe transactions
fn compute_safe_domain_separator(typed_data: &SafeTxTypedData) -> Result<B256> {
    let domain_type_hash = keccak256(SAFE_DOMAIN_TYPE_STR.as_bytes());

    let chain_id = U256::from(typed_data.domain.chain_id);
    let verifying_contract: Address = typed_data
        .domain
        .verifying_contract
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid verifying contract: {e}")))?;

    // Domain separator: keccak256(typeHash || chainId || verifyingContract)
    let mut encoded = Vec::with_capacity(96);
    encoded.extend_from_slice(domain_type_hash.as_slice());
    encoded.extend_from_slice(&chain_id.to_be_bytes::<32>());
    let mut addr_bytes = [0u8; 32];
    addr_bytes[12..].copy_from_slice(verifying_contract.as_slice());
    encoded.extend_from_slice(&addr_bytes);

    Ok(keccak256(&encoded))
}

/// Compute the struct hash for SafeTx
fn compute_safe_tx_struct_hash(typed_data: &SafeTxTypedData) -> Result<B256> {
    let type_hash = keccak256(SAFE_TX_TYPE_STR.as_bytes());

    let to: Address = typed_data
        .message
        .to
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid to address: {e}")))?;

    let value: U256 = typed_data
        .message
        .value
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid value: {e}")))?;

    // Decode data and hash it
    let data_bytes = hex::decode(typed_data.message.data.trim_start_matches("0x"))
        .map_err(|e| PolymarketError::validation(format!("Invalid data hex: {e}")))?;
    let data_hash = keccak256(&data_bytes);

    let operation = U256::from(typed_data.message.operation);
    let safe_tx_gas: U256 = typed_data
        .message
        .safe_tx_gas
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid safeTxGas: {e}")))?;
    let base_gas: U256 = typed_data
        .message
        .base_gas
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid baseGas: {e}")))?;
    let gas_price: U256 = typed_data
        .message
        .gas_price
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid gasPrice: {e}")))?;
    let gas_token: Address = typed_data
        .message
        .gas_token
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid gasToken: {e}")))?;
    let refund_receiver: Address = typed_data
        .message
        .refund_receiver
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid refundReceiver: {e}")))?;
    let nonce: U256 = typed_data
        .message
        .nonce
        .parse()
        .map_err(|e| PolymarketError::validation(format!("Invalid nonce: {e}")))?;

    // Encode struct: typeHash || to || value || dataHash || operation || safeTxGas || baseGas || gasPrice || gasToken || refundReceiver || nonce
    let mut encoded = Vec::with_capacity(352);
    encoded.extend_from_slice(type_hash.as_slice());

    let mut to_bytes = [0u8; 32];
    to_bytes[12..].copy_from_slice(to.as_slice());
    encoded.extend_from_slice(&to_bytes);

    encoded.extend_from_slice(&value.to_be_bytes::<32>());
    encoded.extend_from_slice(data_hash.as_slice());
    encoded.extend_from_slice(&operation.to_be_bytes::<32>());
    encoded.extend_from_slice(&safe_tx_gas.to_be_bytes::<32>());
    encoded.extend_from_slice(&base_gas.to_be_bytes::<32>());
    encoded.extend_from_slice(&gas_price.to_be_bytes::<32>());

    let mut gas_token_bytes = [0u8; 32];
    gas_token_bytes[12..].copy_from_slice(gas_token.as_slice());
    encoded.extend_from_slice(&gas_token_bytes);

    let mut refund_receiver_bytes = [0u8; 32];
    refund_receiver_bytes[12..].copy_from_slice(refund_receiver.as_slice());
    encoded.extend_from_slice(&refund_receiver_bytes);

    encoded.extend_from_slice(&nonce.to_be_bytes::<32>());

    Ok(keccak256(&encoded))
}

/// Compute the EIP-712 digest for SafeTx
///
/// This computes the hash that needs to be signed:
/// `keccak256(0x1901 || domainSeparator || structHash)`
///
/// # Arguments
/// * `typed_data` - The SafeTx typed data
///
/// # Returns
/// The 32-byte digest to be signed
pub fn compute_safe_tx_digest(typed_data: &SafeTxTypedData) -> Result<B256> {
    let domain_separator = compute_safe_domain_separator(typed_data)?;
    let struct_hash = compute_safe_tx_struct_hash(typed_data)?;

    let mut bytes = Vec::with_capacity(66);
    bytes.push(0x19);
    bytes.push(0x01);
    bytes.extend_from_slice(domain_separator.as_slice());
    bytes.extend_from_slice(struct_hash.as_slice());

    Ok(keccak256(&bytes))
}

/// Build TransactionRequest for submitting signed Safe transaction to Relayer
///
/// Uses `pack_signature_for_safe_tx` which adds +4 to v value for Safe's
/// `checkNSignatures` eth_sign format (v=31/32 instead of v=27/28).
///
/// # Arguments
/// * `typed_data` - The SafeTx typed data that was signed
/// * `signer` - The address that signed the transaction (server wallet)
/// * `signature` - The ECDSA signature (will be packed with v+4)
/// * `nonce` - The Safe nonce
///
/// # Returns
/// TransactionRequest ready for Relayer API
pub fn build_safe_tx_request(
    typed_data: &SafeTxTypedData,
    signer: &str,
    signature: &str,
    nonce: u64,
) -> Result<TransactionRequest> {
    // Use pack_signature_for_safe_tx which adds +4 to v for Safe execTransaction
    let packed_signature = pack_signature_for_safe_tx(signature)?;

    Ok(TransactionRequest {
        r#type: TransactionType::Safe,
        from: signer.to_string(),
        to: typed_data.message.to.clone(),
        proxy_wallet: Some(typed_data.domain.verifying_contract.clone()),
        data: typed_data.message.data.clone(),
        nonce: Some(nonce.to_string()),
        signature: packed_signature,
        signature_params: SignatureParams {
            operation: Some(typed_data.message.operation.to_string()),
            safe_tx_gas: Some(typed_data.message.safe_tx_gas.clone()),
            base_gas: Some(typed_data.message.base_gas.clone()),
            gas_price: Some(typed_data.message.gas_price.clone()),
            gas_token: Some(typed_data.message.gas_token.clone()),
            refund_receiver: Some(typed_data.message.refund_receiver.clone()),
            ..Default::default()
        },
        metadata: None,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Derive Tests ---

    #[test]
    fn test_derive_safe_address() {
        let owner = "0x1234567890123456789012345678901234567890";
        let result = derive_safe_address(owner);

        assert!(result.is_ok());
        let safe_addr = result.unwrap();
        assert!(safe_addr.starts_with("0x"));
        assert_eq!(safe_addr.len(), 42);
    }

    #[test]
    fn test_derive_safe_address_deterministic() {
        let owner = "0xabcdef1234567890abcdef1234567890abcdef12";

        let result1 = derive_safe_address(owner).unwrap();
        let result2 = derive_safe_address(owner).unwrap();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_derive_safe_address_different_owners() {
        let owner1 = "0x1234567890123456789012345678901234567890";
        let owner2 = "0x0987654321098765432109876543210987654321";

        let safe1 = derive_safe_address(owner1).unwrap();
        let safe2 = derive_safe_address(owner2).unwrap();

        assert_ne!(safe1, safe2);
    }

    #[test]
    fn test_invalid_owner_address() {
        let invalid = "not-a-valid-address";
        let result = derive_safe_address(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_constants() {
        let factory: std::result::Result<Address, _> = SAFE_FACTORY.parse();
        assert!(factory.is_ok());

        let hash: std::result::Result<B256, _> = SAFE_INIT_CODE_HASH.parse();
        assert!(hash.is_ok());
    }

    // --- SafeCreate Tests ---

    #[test]
    fn test_build_safe_create_typed_data() {
        let owner = "0x1234567890123456789012345678901234567890";
        let result = build_safe_create_typed_data(owner, None);

        assert!(result.is_ok());
        let typed_data = result.unwrap();

        assert_eq!(typed_data.primary_type, "CreateProxy");
        assert_eq!(typed_data.domain.chain_id, 137);
    }

    #[test]
    fn test_build_safe_create_typed_data_custom_chain() {
        let owner = "0x1234567890123456789012345678901234567890";
        let result = build_safe_create_typed_data(owner, Some(80001));

        assert!(result.is_ok());
        let typed_data = result.unwrap();
        assert_eq!(typed_data.domain.chain_id, 80001);
    }

    #[test]
    fn test_compute_digest() {
        let owner = "0x1234567890123456789012345678901234567890";
        let typed_data = build_safe_create_typed_data(owner, None).unwrap();

        let result = compute_safe_create_digest(&typed_data);
        assert!(result.is_ok());

        let digest = result.unwrap();
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_digest_deterministic() {
        let owner = "0x1234567890123456789012345678901234567890";
        let typed_data = build_safe_create_typed_data(owner, None).unwrap();

        let digest1 = compute_safe_create_digest(&typed_data).unwrap();
        let digest2 = compute_safe_create_digest(&typed_data).unwrap();

        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_invalid_owner_typed_data() {
        let result = build_safe_create_typed_data("invalid-address", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_safe_create_message() {
        let msg = SafeCreateMessage::new("0x1234567890123456789012345678901234567890");

        assert_eq!(msg.payment, "0");
        assert_eq!(
            msg.payment_receiver,
            "0x0000000000000000000000000000000000000000"
        );
        assert_eq!(
            msg.payment_token,
            "0x0000000000000000000000000000000000000000"
        );
    }

    // --- Client Tests ---

    #[test]
    fn test_relayer_config_default() {
        let config = RelayerConfig::default();
        assert_eq!(config.base_url, RELAYER_API_BASE);
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.rate_limit_per_second, 2);
    }

    #[test]
    fn test_relayer_config_builder() {
        let config = RelayerConfig::builder()
            .with_base_url("https://custom.example.com")
            .with_timeout(Duration::from_secs(120))
            .with_rate_limit(5);

        assert_eq!(config.base_url, "https://custom.example.com");
        assert_eq!(config.timeout, Duration::from_secs(120));
        assert_eq!(config.rate_limit_per_second, 5);
    }
}
