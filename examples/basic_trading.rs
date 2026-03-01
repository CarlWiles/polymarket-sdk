//! Basic Trading Example
//!
//! This example demonstrates how to interact with the CLOB API for trading.
//! Shows order creation concepts and API interactions.
//!
//! Environment variables required:
//! - `POLY_PRIVATE_KEY`: Your wallet private key (for signing)
//! - `POLY_API_KEY`: Your CLOB API key
//! - `POLY_API_SECRET`: Your CLOB API secret (base64 encoded)
//! - `POLY_API_PASSPHRASE`: Your CLOB API passphrase
//!
//! Run with: `cargo run --example basic_trading --features full`

use alloy_signer_local::PrivateKeySigner;
use polymarket_sdk::order::get_contract_config;
use polymarket_sdk::prelude::*;
use rust_decimal::Decimal;
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    println!("=== Polymarket Trading Example ===\n");

    // Check for required private key
    let private_key = match std::env::var("POLY_PRIVATE_KEY") {
        Ok(pk) => pk,
        Err(_) => {
            println!("POLY_PRIVATE_KEY not set - showing concepts only\n");
            show_concepts_only();
            return Ok(());
        }
    };

    // 1. Create signer from private key
    println!("1. Creating signer...");
    let signer: PrivateKeySigner = private_key
        .parse()
        .map_err(|e| PolymarketError::config(format!("Invalid private key: {}", e)))?;
    println!("   Signer address: {}", signer.address());

    // 2. Initialize CLOB client
    println!("\n2. Initializing CLOB client...");
    let clob_config = ClobConfig::from_env();
    let clob = ClobClient::new(clob_config, signer.clone())?;
    println!("   CLOB client initialized");

    // 3. Create order builder
    println!("\n3. Creating order builder...");
    let order_builder = OrderBuilder::new(signer.clone(), None, None);
    println!("   Funder/Maker: {}", order_builder.funder_address());

    // 4. Example order
    println!("\n4. Example Order Structure:");
    let token_id = "21742633143463906290569050155826241533067272736897614950488156847949938836455";
    let order_args = OrderArgs {
        token_id: token_id.to_string(),
        side: Side::Buy,
        price: Decimal::from_str("0.50").unwrap(),
        size: Decimal::from_str("10.0").unwrap(),
    };

    println!("   Token: {}...", &token_id[..20]);
    println!("   Side: {:?}", order_args.side);
    println!("   Price: ${}", order_args.price);
    println!("   Size: {} shares", order_args.size);

    // 5. Try to fetch open orders
    println!("\n5. Fetching open orders...");
    match clob.get_open_orders().await {
        Ok(orders) => {
            if orders.is_empty() {
                println!("   No open orders");
            } else {
                println!("   {} open order(s):", orders.len());
                for order in orders.iter().take(3) {
                    println!(
                        "     - {} {} @ {} ({})",
                        order.side, order.original_size, order.price, order.status
                    );
                }
            }
        }
        Err(e) => {
            println!("   Could not fetch orders: {}", e);
            println!("   (Expected if API credentials are not set)");
        }
    }

    // 6. Contract configuration
    println!("\n6. Contract Configuration:");
    if let Some(config) = get_contract_config(137, false) {
        println!("   Standard Exchange: {}", config.exchange);
    }
    if let Some(config) = get_contract_config(137, true) {
        println!("   Neg Risk Exchange: {}", config.exchange);
    }

    println!("\n=== Example Complete ===");
    Ok(())
}

fn show_concepts_only() {
    println!("Trading API Concepts:");
    println!("---------------------");
    println!();
    println!("1. ClobClient - Main trading client");
    println!("   let clob = ClobClient::new(config, signer)?;");
    println!();
    println!("2. OrderBuilder - Creates and signs orders");
    println!("   let builder = OrderBuilder::new(signer, None, None);");
    println!();
    println!("3. OrderArgs - Order parameters");
    println!("   OrderArgs {{ token_id, side, price, size }}");
    println!();
    println!("4. Signature Types:");
    println!("   - SigType::Eoa (0) - Direct wallet signature");
    println!("   - SigType::PolyProxy (1) - Proxy wallet signature");
    println!("   - SigType::PolyGnosisSafe (2) - Safe wallet signature");
    println!();
    println!("5. Key Methods:");
    println!("   - clob.get_open_orders()");
    println!("   - clob.submit_order(&signed_order, post_only)");
    println!("   - clob.cancel_orders(order_ids)");
    println!("   - clob.cancel_all_orders()");
    println!();
    println!("Set POLY_PRIVATE_KEY to run the full example.");
}
