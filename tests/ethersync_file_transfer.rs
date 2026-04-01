use base64::{engine::general_purpose, Engine as _};
use handshacke::state::{AppState, EtherSyncStartConfig};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::timeout;

#[derive(Debug, Deserialize)]
struct EventView {
    kind: String,
    space_id: Option<String>,
    payload_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FileChunkEnvelopeView {
    kind: String,
    transfer_id: String,
    filename: String,
    total_bytes: usize,
    chunk_index: usize,
    total_chunks: usize,
    chunk_b64: String,
}

fn build_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

async fn start_node(app: &AppState) -> anyhow::Result<()> {
    let cfg = EtherSyncStartConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        ..EtherSyncStartConfig::default()
    };
    app.ethersync_start(cfg).await?;
    Ok(())
}

async fn wait_for_space_joined(
    rx: &mut broadcast::Receiver<String>,
    space_id: &str,
) -> anyhow::Result<()> {
    timeout(Duration::from_secs(10), async {
        loop {
            let raw = match rx.recv().await {
                Ok(v) => v,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(e) => return Err(anyhow::anyhow!("event channel closed: {}", e)),
            };

            let evt: EventView = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => continue,
            };

            if evt.kind == "space_joined" && evt.space_id.as_deref() == Some(space_id) {
                return Ok(());
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("timeout waiting for space_joined event"))?
}

async fn collect_transfer_payload(
    rx: &mut broadcast::Receiver<String>,
    transfer_id: &str,
    expected_filename: &str,
    expected_chunks: usize,
    expected_total_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    timeout(Duration::from_secs(15), async {
        let mut chunks: HashMap<usize, Vec<u8>> = HashMap::new();

        while chunks.len() < expected_chunks {
            let raw = match rx.recv().await {
                Ok(v) => v,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(e) => return Err(anyhow::anyhow!("event channel closed: {}", e)),
            };

            let evt: EventView = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => continue,
            };

            if evt.kind != "space_file_chunk" {
                continue;
            }

            let Some(payload_b64) = evt.payload_b64 else {
                continue;
            };

            let payload = general_purpose::STANDARD
                .decode(payload_b64)
                .map_err(|e| anyhow::anyhow!("invalid payload_b64: {}", e))?;
            let envelope: FileChunkEnvelopeView = serde_json::from_slice(&payload)
                .map_err(|e| anyhow::anyhow!("invalid chunk envelope: {}", e))?;

            if envelope.kind != "file_chunk" || envelope.transfer_id != transfer_id {
                continue;
            }

            if envelope.total_chunks != expected_chunks
                || envelope.total_bytes != expected_total_bytes
            {
                return Err(anyhow::anyhow!(
                    "unexpected envelope dimensions chunks={} bytes={}",
                    envelope.total_chunks,
                    envelope.total_bytes
                ));
            }
            if envelope.filename != expected_filename {
                return Err(anyhow::anyhow!(
                    "unexpected envelope filename {}",
                    envelope.filename
                ));
            }

            let chunk = general_purpose::STANDARD
                .decode(envelope.chunk_b64)
                .map_err(|e| anyhow::anyhow!("invalid chunk_b64: {}", e))?;
            chunks.entry(envelope.chunk_index).or_insert(chunk);
        }

        let mut rebuilt = Vec::with_capacity(expected_total_bytes);
        for idx in 0..expected_chunks {
            let chunk = chunks
                .remove(&idx)
                .ok_or_else(|| anyhow::anyhow!("missing chunk index {}", idx))?;
            rebuilt.extend_from_slice(&chunk);
        }
        Ok(rebuilt)
    })
    .await
    .map_err(|_| anyhow::anyhow!("timeout waiting for file chunk events"))?
}

#[tokio::test]
async fn ethersync_file_transfer_e2e_two_nodes() -> anyhow::Result<()> {
    let sender = AppState::default();
    let receiver = AppState::default();

    let run = async {
        start_node(&sender).await?;
        start_node(&receiver).await?;

        let receiver_status = receiver.ethersync_status().await?;
        let receiver_addr: SocketAddr = receiver_status
            .local_addr
            .ok_or_else(|| anyhow::anyhow!("receiver local_addr missing"))?
            .parse()
            .map_err(|e| anyhow::anyhow!("receiver local_addr parse failed: {}", e))?;
        sender.ethersync_add_peer(receiver_addr).await?;

        let mut receiver_events = receiver.ethersync_subscribe_events().await?;
        let passphrase = "crystal orbit tide";
        let join = receiver
            .ethersync_join_space(passphrase.to_string(), None)
            .await?;
        wait_for_space_joined(&mut receiver_events, &join.space_id).await?;

        let payload = build_payload(4096);
        let publish = sender
            .ethersync_publish_file(
                passphrase.to_string(),
                "transfer.bin".to_string(),
                payload.clone(),
                Some(700),
            )
            .await?;

        assert_eq!(publish.total_bytes, payload.len());
        assert_eq!(publish.total_chunks, payload.len().div_ceil(700));
        assert_eq!(publish.published_chunks, publish.total_chunks);

        let rebuilt = collect_transfer_payload(
            &mut receiver_events,
            &publish.transfer_id,
            &publish.filename,
            publish.total_chunks,
            publish.total_bytes,
        )
        .await?;
        assert_eq!(rebuilt, payload);

        Ok::<(), anyhow::Error>(())
    }
    .await;

    let _ = sender.ethersync_stop().await;
    let _ = receiver.ethersync_stop().await;
    run
}

#[tokio::test]
async fn ethersync_publish_file_clamps_chunk_size_and_sanitizes_filename() -> anyhow::Result<()> {
    let app = AppState::default();

    let run = async {
        start_node(&app).await?;
        let payload = build_payload(300);
        let result = app
            .ethersync_publish_file(
                "violet dusk river".to_string(),
                "bad:*name?.txt".to_string(),
                payload,
                Some(1),
            )
            .await?;

        assert_eq!(result.filename, "badname.txt");
        assert_eq!(result.total_bytes, 300);
        assert_eq!(result.total_chunks, 2);
        assert_eq!(result.published_chunks, 2);

        Ok::<(), anyhow::Error>(())
    }
    .await;

    let _ = app.ethersync_stop().await;
    run
}
