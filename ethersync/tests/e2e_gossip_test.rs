//! End-to-end gossip test for EtherSync
//!
//! Verifies that two nodes can communicate via gossip protocol:
//! 1. Node A publishes a message
//! 2. Node B receives it via gossip + subscription routing

use ethersync::{EtherNode, NodeConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::timeout;

/// Timeout for the entire test
const TEST_TIMEOUT_SECS: u64 = 5;

#[tokio::test]
async fn test_e2e_gossip_message_propagation() {
    // Shared passphrase for both nodes
    let passphrase = "test-space-42";
    let payload = b"Hello from Node A!";

    // Create Node A (publisher)
    let config_a = NodeConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        gossip_interval_secs: 1, // Fast gossip for testing
        ..Default::default()
    };

    let node_a = Arc::new(
        EtherNode::new(config_a)
            .await
            .expect("Failed to create Node A"),
    );
    let addr_a = node_a.local_addr();
    println!("Node A listening on {}", addr_a);

    // Create Node B (subscriber) with bootstrap to Node A
    let config_b = NodeConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        bootstrap_peers: vec![addr_a],
        gossip_interval_secs: 1,
        ..Default::default()
    };

    let node_b = Arc::new(
        EtherNode::new(config_b)
            .await
            .expect("Failed to create Node B"),
    );
    let addr_b = node_b.local_addr();
    println!("Node B listening on {}", addr_b);

    // Add Node B as peer to Node A (bidirectional bootstrap)
    node_a.add_peer(addr_b).await;

    // Wait for nodes to be ready
    println!("Waiting for gossip engines to be ready...");
    node_a
        .wait_for_gossip_ready(5)
        .await
        .expect("Node A gossip not ready");
    node_b
        .wait_for_gossip_ready(5)
        .await
        .expect("Node B gossip not ready");
    println!("Both nodes ready!");

    // Subscribe Node B to the passphrase
    let mut rx_b = node_b
        .subscribe(passphrase)
        .await
        .expect("Failed to subscribe Node B");

    // Create shutdown channels
    let (shutdown_tx_a, shutdown_rx_a) = watch::channel(false);
    let (shutdown_tx_b, shutdown_rx_b) = watch::channel(false);

    // Start Node B in background (receiver)
    let node_b_clone = Arc::clone(&node_b);
    let node_b_handle = tokio::spawn(async move {
        let _ = node_b_clone.run(shutdown_rx_b).await;
    });

    // Start Node A in background (publisher)
    let node_a_clone = Arc::clone(&node_a);
    let node_a_handle = tokio::spawn(async move {
        let _ = node_a_clone.run(shutdown_rx_a).await;
    });

    // Wait for gossip handshake
    println!("Waiting for gossip handshake...");
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Check peers
    let peers_a = node_a.peer_count().await;
    let peers_b = node_b.peer_count().await;
    println!("Node A has {} peers, Node B has {} peers", peers_a, peers_b);

    // Publish message from Node A
    println!("Publishing message from Node A...");
    let msg_a = node_a
        .publish(passphrase, payload)
        .await
        .expect("Failed to publish message");

    println!("Published message with slot {}", msg_a.header.slot_id);

    // Wait for message to propagate via gossip
    println!("Waiting for message to reach Node B...");

    let received_msg = timeout(Duration::from_secs(TEST_TIMEOUT_SECS), rx_b.recv())
        .await
        .expect("Test timed out waiting for message")
        .expect("Channel closed unexpectedly");

    // Verify message content
    println!("Message received on Node B!");

    // Decrypt and verify
    let decrypted = received_msg
        .decrypt(passphrase)
        .expect("Failed to decrypt received message");

    assert_eq!(
        decrypted, payload,
        "Received payload doesn't match original"
    );

    // Verify slot matches
    assert_eq!(
        received_msg.header.slot_id, msg_a.header.slot_id,
        "Received message from wrong slot"
    );

    println!("✅ Test passed! Message propagated correctly via gossip.");

    // Cleanup: graceful shutdown
    let _ = shutdown_tx_a.send(true);
    let _ = shutdown_tx_b.send(true);

    // Wait for nodes to shut down
    let _ = tokio::time::timeout(Duration::from_secs(1), node_a_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), node_b_handle).await;
}

#[tokio::test]
async fn test_e2e_multiple_messages() {
    // Test with multiple sequential messages
    let passphrase = "batch-test-space";
    let payloads = vec![
        b"Message 1".to_vec(),
        b"Message 2".to_vec(),
        b"Message 3".to_vec(),
    ];

    // Create Node A (publisher)
    let config_a = NodeConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        gossip_interval_secs: 1,
        ..Default::default()
    };

    let node_a = Arc::new(
        EtherNode::new(config_a)
            .await
            .expect("Failed to create Node A"),
    );
    let addr_a = node_a.local_addr();

    // Create Node B (subscriber)
    let config_b = NodeConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        bootstrap_peers: vec![addr_a],
        gossip_interval_secs: 1,
        ..Default::default()
    };

    let node_b = Arc::new(
        EtherNode::new(config_b)
            .await
            .expect("Failed to create Node B"),
    );
    let addr_b = node_b.local_addr();

    // Bidirectional bootstrap
    node_a.add_peer(addr_b).await;

    // Subscribe Node B
    let mut rx_b = node_b
        .subscribe(passphrase)
        .await
        .expect("Failed to subscribe Node B");

    // Create shutdown channels
    let (shutdown_tx_a, shutdown_rx_a) = watch::channel(false);
    let (shutdown_tx_b, shutdown_rx_b) = watch::channel(false);

    // Start both nodes
    let node_b_clone = Arc::clone(&node_b);
    let node_b_handle = tokio::spawn(async move {
        let _ = node_b_clone.run(shutdown_rx_b).await;
    });

    let node_a_clone = Arc::clone(&node_a);
    let node_a_handle = tokio::spawn(async move {
        let _ = node_a_clone.run(shutdown_rx_a).await;
    });

    // Wait for startup
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Publish all messages from Node A
    println!("Publishing {} messages from Node A...", payloads.len());
    for (i, payload) in payloads.iter().enumerate() {
        node_a
            .publish(passphrase, payload)
            .await
            .expect(&format!("Failed to publish message {}", i));
    }

    // Collect all received messages
    println!("Waiting for all messages on Node B...");
    let mut received = Vec::new();

    for i in 0..payloads.len() {
        let msg = timeout(Duration::from_secs(TEST_TIMEOUT_SECS), rx_b.recv())
            .await
            .expect(&format!("Timeout waiting for message {}", i))
            .expect("Channel closed");

        let decrypted = msg.decrypt(passphrase).expect("Failed to decrypt");
        received.push(decrypted);
        println!(
            "Received message {}: {:?}",
            i + 1,
            String::from_utf8_lossy(&received[i])
        );
    }

    // Verify all payloads received
    for (_expected, actual) in payloads.iter().zip(received.iter()) {
        assert!(payloads.contains(actual), "Received unexpected message");
    }

    println!("✅ All {} messages received correctly!", payloads.len());

    // Cleanup
    let _ = shutdown_tx_a.send(true);
    let _ = shutdown_tx_b.send(true);

    let _ = tokio::time::timeout(Duration::from_secs(1), node_a_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), node_b_handle).await;
}

#[tokio::test]
async fn test_e2e_wrong_passphrase_no_receive() {
    // Verify messages with different passphrase are NOT received
    let passphrase_a = "space-for-a";
    let passphrase_b = "space-for-b";

    // Create nodes
    let config_a = NodeConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        gossip_interval_secs: 1,
        ..Default::default()
    };

    let node_a = Arc::new(
        EtherNode::new(config_a)
            .await
            .expect("Failed to create Node A"),
    );
    let addr_a = node_a.local_addr();

    let config_b = NodeConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        bootstrap_peers: vec![addr_a],
        gossip_interval_secs: 1,
        ..Default::default()
    };

    let node_b = Arc::new(
        EtherNode::new(config_b)
            .await
            .expect("Failed to create Node B"),
    );
    let addr_b = node_b.local_addr();

    node_a.add_peer(addr_b).await;

    // Subscribe Node B to passphrase_b
    let mut rx_b = node_b
        .subscribe(passphrase_b)
        .await
        .expect("Failed to subscribe");

    // Create shutdown channels
    let (shutdown_tx_a, shutdown_rx_a) = watch::channel(false);
    let (shutdown_tx_b, shutdown_rx_b) = watch::channel(false);

    // Start both nodes
    let node_b_clone = Arc::clone(&node_b);
    let node_b_handle = tokio::spawn(async move {
        let _ = node_b_clone.run(shutdown_rx_b).await;
    });

    let node_a_clone = Arc::clone(&node_a);
    let node_a_handle = tokio::spawn(async move {
        let _ = node_a_clone.run(shutdown_rx_a).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Publish from Node A with passphrase_a (different from Node B's subscription)
    println!("Publishing message with passphrase '{}'...", passphrase_a);
    node_a
        .publish(passphrase_a, b"secret message")
        .await
        .expect("Failed to publish");

    // Wait briefly - message should NOT arrive
    println!("Waiting to confirm message does NOT arrive (should timeout)...");
    let result = timeout(Duration::from_millis(2000), rx_b.recv()).await;

    assert!(
        result.is_err() || result.unwrap().is_none(),
        "Should not receive message with different passphrase"
    );

    println!("✅ Correctly did NOT receive message with wrong passphrase!");

    // Cleanup
    let _ = shutdown_tx_a.send(true);
    let _ = shutdown_tx_b.send(true);

    let _ = tokio::time::timeout(Duration::from_secs(1), node_a_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), node_b_handle).await;
}
