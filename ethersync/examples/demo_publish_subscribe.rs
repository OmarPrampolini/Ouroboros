//! Demo: Publish/Subscribe with EtherSync
//!
//! This example demonstrates basic EtherSync usage:
//! - Create two nodes
//! - Subscribe to a passphrase on node B
//! - Publish messages from node A
//! - Receive messages on node B
//!
//! Run with: cargo run --example demo_publish_subscribe -p ethersync

use ethersync::{EtherNode, EtherSyncError, NodeConfig};
use std::time::Duration;
use tokio::time::timeout;

#[tokio::main]
async fn main() -> Result<(), EtherSyncError> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    println!("=== EtherSync Publish/Subscribe Demo ===\n");

    // Create Node A (publisher)
    println!("[1] Creating Node A (publisher)...");
    let config_a = NodeConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        ..Default::default()
    };
    let node_a = EtherNode::new(config_a).await?;
    let addr_a = node_a.local_addr();
    println!("    Node A listening on {}", addr_a);

    // Create Node B (subscriber) with Node A as bootstrap
    println!("\n[2] Creating Node B (subscriber)...");
    let config_b = NodeConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        bootstrap_peers: vec![addr_a],
        ..Default::default()
    };
    let node_b = EtherNode::new(config_b).await?;
    let addr_b = node_b.local_addr();
    println!("    Node B listening on {}", addr_b);

    // Shared passphrase
    let passphrase = "demo-secret-room";
    println!("\n[3] Using passphrase: '{}'", passphrase);

    // Subscribe on Node B
    println!("\n[4] Subscribing on Node B...");
    let mut rx = node_b.subscribe(passphrase).await?;
    println!("    Subscribed! Waiting for messages...");

    // Give subscription time to set up
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Publish messages from Node A
    println!("\n[5] Publishing 3 messages from Node A...");
    let messages = vec![
        "Hello from Node A!",
        "This is message #2",
        "Final message - demo complete!",
    ];

    for (i, text) in messages.iter().enumerate() {
        let msg = node_a.publish(passphrase, text.as_bytes()).await?;
        println!(
            "    [{}] Published: '{}' (slot {})",
            i + 1,
            text,
            msg.header.slot_id
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Wait for messages to propagate and be received
    println!("\n[6] Waiting for messages on Node B...");
    let mut received = 0;
    let deadline = Duration::from_secs(5);

    while received < messages.len() {
        match timeout(deadline, rx.recv()).await {
            Ok(Some(msg)) => {
                // Decrypt and display
                match msg.decrypt(passphrase) {
                    Ok(payload) => {
                        let text = String::from_utf8_lossy(&payload);
                        println!("    [{}] Received: '{}'", received + 1, text);
                        received += 1;
                    }
                    Err(e) => {
                        println!("    [!] Failed to decrypt: {:?}", e);
                    }
                }
            }
            Ok(None) => {
                println!("    [!] Channel closed");
                break;
            }
            Err(_) => {
                println!("    [!] Timeout waiting for message");
                break;
            }
        }
    }

    // Summary
    println!("\n=== Demo Complete ===");
    println!("Published: {} messages", messages.len());
    println!("Received:  {} messages", received);

    if received == messages.len() {
        println!("\n✅ SUCCESS: All messages received!");
    } else {
        println!(
            "\n⚠️  PARTIAL: Only {} of {} messages received",
            received,
            messages.len()
        );
    }

    Ok(())
}
