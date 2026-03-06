//! Assist inbox: B mantiene canale verso C per ricevere richieste

use crate::config::{ASSIST_INBOX_CHANNEL_CAPACITY, ASSIST_INBOX_RETRY_SECS};
use crate::protocol_assist_v5::{verify_assist_mac_v5, AssistRequestV5};
use crate::transport::dandelion::{dandelion_tag_for_request, DandelionAggregator, DandelionMode};
use crate::{
    config::Config,
    crypto::{deserialize_cipher_packet_with_limit, open, MAX_TCP_FRAME_BYTES},
    derive::RendezvousParams,
    protocol::Control,
    protocol_assist::AssistRequest,
    transport::{framing, wan::wan_tor},
};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;

use tokio::time::Duration;

#[derive(Debug, Error)]
pub enum AssistInboxError {
    #[error("failed to connect to assist relay: {0}")]
    Connect(String),
    #[error("framing error: {0}")]
    Framing(#[from] framing::FramingError),
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("bincode error: {0}")]
    Bincode(String),
    #[error("Invalid assist request")]
    InvalidAssistRequest,
}

type Result<T> = std::result::Result<T, AssistInboxError>;

pub struct AssistInbox {
    relay_onion: String,
    params: RendezvousParams,
    request_tx: mpsc::Sender<AssistInboxRequest>,
    aggregator: DandelionAggregator,
    mode: DandelionMode,
}

#[derive(Debug)]
pub enum AssistInboxRequest {
    V4(AssistRequest),
    V5(AssistRequestV5),
}

impl AssistInbox {
    /// Crea inbox per relay specifico
    pub fn new(
        relay_onion: String,
        params: RendezvousParams,
    ) -> (Self, mpsc::Receiver<AssistInboxRequest>) {
        let (tx, rx) = mpsc::channel(ASSIST_INBOX_CHANNEL_CAPACITY);
        (
            Self {
                relay_onion,
                params,
                request_tx: tx,
                aggregator: DandelionAggregator::new(),
                mode: DandelionMode::from_env(),
            },
            rx,
        )
    }

    /// Mantiene connessione a C e ricevi richieste
    pub async fn run(self, cfg: &Config) -> Result<()> {
        // Spawn dandelion fluff task if enabled
        if self.mode != DandelionMode::Off {
            let aggregator = self.aggregator.clone();
            let tx = self.request_tx.clone();
            let mode = self.mode;
            tokio::spawn(async move {
                Self::fluff_loop(aggregator, tx, mode).await;
            });
        }

        loop {
            // Riconnettiti se necessario
            let stream = wan_tor::try_tor_connect(
                &cfg.tor_socks_addr,
                &self.relay_onion,
                None,
                Some(&self.relay_onion),
            )
            .await
            .map_err(|e| AssistInboxError::Connect(e.to_string()));

            match stream {
                Ok(s) => {
                    let (reader, writer) = s.into_split();
                    if let Err(e) = self.handle_connection(reader, writer).await {
                        tracing::warn!(
                            "Assist inbox: connection error: {}, retrying in {}s",
                            e,
                            ASSIST_INBOX_RETRY_SECS
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Assist inbox: connect error: {}, retrying in {}s",
                        e,
                        ASSIST_INBOX_RETRY_SECS
                    );
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(ASSIST_INBOX_RETRY_SECS)).await;
        }
    }

    /// Fluff loop: periodically check for ready batches and forward them.
    async fn fluff_loop(
        aggregator: DandelionAggregator,
        request_tx: mpsc::Sender<AssistInboxRequest>,
        mode: DandelionMode,
    ) {
        let policy = mode.effective_policy();
        let mut interval = tokio::time::interval(Duration::from_millis(policy.fluff_tick_ms));

        tracing::info!(
            "Dandelion fluff loop started (mode={}, tick={}ms)",
            mode.as_str(),
            policy.fluff_tick_ms
        );

        loop {
            interval.tick().await;

            // Get all ready batches
            let ready = aggregator.ready_batches().await;

            for (requests, tag) in ready {
                tracing::info!(
                    "Dandelion: forwarding batch {} with {} requests",
                    hex::encode(tag),
                    requests.len()
                );

                // Forward each request in batch
                for (req, _addr) in requests {
                    if request_tx.send(AssistInboxRequest::V5(req)).await.is_err() {
                        tracing::warn!("Fluff loop: receiver dropped");
                        return;
                    }
                }
            }
        }
    }

    async fn handle_connection(
        &self,
        mut reader: OwnedReadHalf,
        _writer: OwnedWriteHalf,
    ) -> Result<()> {
        loop {
            // Leggi frame
            let frame = framing::read_frame(&mut reader).await?;
            let pkt = deserialize_cipher_packet_with_limit(&frame, MAX_TCP_FRAME_BYTES)?;

            // Decripta con key_enc locale
            let clear = open(
                &self.params.key_enc,
                &pkt,
                self.params.tag16,
                self.params.tag8,
            )
            .ok_or(AssistInboxError::InvalidAssistRequest)?;

            let ctrl: Control = bincode::deserialize(&clear.data)
                .map_err(|e| AssistInboxError::Bincode(e.to_string()))?;
            match ctrl {
                Control::AssistRequest(req) => {
                    // Verifica MAC (opzionale se C trustato)
                    let expected_mac = match crate::protocol_assist::compute_assist_mac(
                        &self.params.key_enc,
                        &req,
                    ) {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::warn!("Assist inbox: MAC compute failed: {}", e);
                            continue;
                        }
                    };
                    if !bool::from(req.mac.ct_eq(&expected_mac)) {
                        tracing::warn!("Assist inbox: invalid MAC, dropping");
                        continue;
                    }

                    // Inoltra immediatamente (no dandelion for v4)
                    if self
                        .request_tx
                        .send(AssistInboxRequest::V4(req))
                        .await
                        .is_err()
                    {
                        tracing::warn!("Assist inbox: receiver dropped, stopping");
                        return Ok(());
                    }
                }
                Control::AssistRequestV5(req) => {
                    if !verify_assist_mac_v5(&self.params.key_enc, &req) {
                        tracing::warn!("Assist inbox: invalid V5 MAC, dropping");
                        continue;
                    }

                    // Handle dandelion if enabled
                    if self.mode != DandelionMode::Off && req.dandelion_stem {
                        let tag = dandelion_tag_for_request(&req);
                        let is_first = self
                            .aggregator
                            .add_request_with_mode(
                                tag,
                                req,
                                std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
                                self.mode,
                            )
                            .await;

                        if is_first {
                            let policy = self.mode.effective_policy();
                            tracing::debug!(
                                "Dandelion: stem queued (mode={}, flush {}-{}s or batch>={})",
                                self.mode.as_str(),
                                policy.min_delay_secs,
                                policy.max_delay_secs,
                                policy.target_batch_size
                            );
                        }
                    } else {
                        // Dandelion off or client requests immediate forward
                        if self
                            .request_tx
                            .send(AssistInboxRequest::V5(req))
                            .await
                            .is_err()
                        {
                            tracing::warn!("Assist inbox: receiver dropped, stopping");
                            return Ok(());
                        }
                    }
                }
                _ => {
                    // Ignora altri messaggi
                }
            }
        }
    }
}
