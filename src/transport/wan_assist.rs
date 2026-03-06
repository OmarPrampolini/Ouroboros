//! WAN Assist: hole punching coordinato tramite relay temporaneo
//! Zero-infrastructure, ephemeral, zero-trust

use crate::config::UDP_MAX_PACKET_SIZE;
use crate::protocol_assist_v5::{
    compute_assist_mac_v5, derive_entry_nonce_v5_improved, derive_obfuscation_key_v5,
    is_usable_candidate, make_blinded_candidates_v5_shuffled, verify_assist_go_mac_v5, AssistGoV5,
    AssistRequestV5,
};
use crate::{
    config::Config,
    crypto::{
        deserialize_cipher_packet_with_limit, now_ms, open, seal_with_nonce,
        serialize_cipher_packet, ClearPayload, NonceSeq, MAX_TCP_FRAME_BYTES, NONCE_DOMAIN_ASSIST,
    },
    derive::RendezvousParams,
    protocol::Control,
    protocol_assist::{compute_assist_mac, AssistGo, AssistRequest, TargetRef},
    transport::{
        framing, lan,
        wan::{wan_direct, wan_tor},
    },
};
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{sleep, sleep_until, timeout};

#[derive(Debug, Error)]
pub enum WanAssistError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("framing error: {0}")]
    Framing(#[from] crate::transport::framing::FramingError),
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("derive error: {0}")]
    Derive(#[from] crate::derive::DeriveError),
    #[error("offer error: {0}")]
    Offer(#[from] crate::offer::OfferError),
    #[error("protocol assist error: {0}")]
    ProtocolAssist(#[from] crate::protocol_assist::ProtocolAssistError),
    #[error("protocol assist v5 error: {0}")]
    ProtocolAssistV5(#[from] crate::protocol_assist_v5::ProtocolAssistV5Error),
    #[error("lan error: {0}")]
    Lan(#[from] crate::transport::lan::LanError),
    #[error("wan direct error: {0}")]
    WanDirect(#[from] crate::transport::wan::wan_direct::WanDirectError),
    #[error("wan tor error: {0}")]
    WanTor(#[from] crate::transport::wan::wan_tor::WanTorError),
    #[error("timer elapsed: {0}")]
    Elapsed(#[from] tokio::time::error::Elapsed),
    #[error("time error: {0}")]
    Time(#[from] std::time::SystemTimeError),
    #[error("bincode error: {0}")]
    Bincode(String),
    #[error("All {0} relays failed")]
    AllRelaysFailed(usize),
    #[error("Invalid AssistGo packet")]
    InvalidAssistGoPacket,
    #[error("Unexpected control message")]
    UnexpectedControlMessage,
    #[error("AssistGo timeout")]
    AssistGoTimeout,
    #[error("Invalid AssistGoV5 packet")]
    InvalidAssistGoV5Packet,
    #[error("WAN Assist: no response from peer")]
    NoResponseFromPeer,
    #[error("Offer hash mismatch: expected {expected}, got {got}")]
    OfferHashMismatch { expected: String, got: String },
    #[error("Simultaneous open not enabled")]
    SimultaneousOpenNotEnabled,
    #[error("Simultaneous open requires assist relays configured")]
    SimultaneousOpenRequiresRelays,
}

type Result<T> = std::result::Result<T, WanAssistError>;

/// Generic relay stream trait
pub trait RelayStream: AsyncRead + AsyncWrite + Unpin + Send {
    fn stream_type(&self) -> &'static str;
}

impl RelayStream for TcpStream {
    fn stream_type(&self) -> &'static str {
        "tcp"
    }
}

/// Tenta hole punching assistito da relay
pub async fn try_assisted_punch(
    params: &RendezvousParams,
    relay_onions: &[String],
    cfg: &Config,
) -> Result<crate::transport::Connection> {
    for (idx, relay_onion) in relay_onions.iter().enumerate() {
        tracing::info!(
            "WAN Assist: trying relay {}/{}",
            idx + 1,
            relay_onions.len()
        );

        // 1. Connettiti a C via Tor
        let c_stream = match timeout(
            Duration::from_secs(cfg.wan_connect_timeout_ms.max(5000) / 1000),
            wan_tor::try_tor_connect(&cfg.tor_socks_addr, relay_onion, None, Some(relay_onion)),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::warn!("Relay {} unreachable: {}", relay_onion, e);
                continue;
            }
            Err(_) => {
                tracing::warn!("Relay {} connect timeout", relay_onion);
                continue;
            }
        };

        // 2. Coordina il punch
        match coordinate_with_relay(c_stream, params, cfg).await {
            Ok(conn) => {
                tracing::info!("WAN Assist: success via {}", relay_onion);
                return Ok(conn);
            }
            Err(e) => {
                tracing::warn!("Relay {} coordination failed: {}", relay_onion, e);
                continue;
            }
        }
    }

    Err(WanAssistError::AllRelaysFailed(relay_onions.len()))
}

/// Coordina con C: invia richiesta, ricevi GO, esegui punch
async fn coordinate_with_relay(
    c_stream: TcpStream,
    params: &RendezvousParams,
    cfg: &Config,
) -> Result<crate::transport::Connection> {
    let (mut c_reader, mut c_writer) = c_stream.into_split();

    // 1. Prepara AssistRequest
    let request_id = rand::thread_rng().gen::<[u8; 8]>();
    let my_udp_candidates = gather_udp_candidates(params.port).await?;
    let ttl_ms = cfg.wan_connect_timeout_ms.min(10000) as u16;
    let (control, request_id) = if cfg.assist_obfuscation_v5 {
        let obf_key = derive_obfuscation_key_v5(&params.key_enc, params.tag16)?;
        let blinded =
            make_blinded_candidates_v5_shuffled(&my_udp_candidates, &obf_key, &request_id)?;
        let mut request = AssistRequestV5 {
            request_id,
            blinded_candidates: blinded,
            ttl_ms,
            dandelion_stem: false, // Default: no Dandelion for V5
            dandelion_tag: None,   // Default: relay generates tag
            mac: [0u8; 32],
        };
        request.mac = compute_assist_mac_v5(&params.key_enc, &request)?;
        (Control::AssistRequestV5(request), request_id)
    } else {
        let mut request = AssistRequest {
            request_id,
            target_ref: TargetRef::Tag16Only(params.tag16),
            my_udp_candidates,
            ttl_ms,
            mac: [0u8; 32],
        };
        request.mac = compute_assist_mac(&params.key_enc, &request)?;
        (Control::AssistRequest(request), request_id)
    };

    // 2. Invia richiesta a C (framed TCP)
    let payload =
        bincode::serialize(&control).map_err(|e| WanAssistError::Bincode(e.to_string()))?;
    let mut nonce_seq = NonceSeq::new_boot_random(&params.key_enc, NONCE_DOMAIN_ASSIST, 0x01)?;
    let (nonce, seq) = nonce_seq.next_nonce_and_seq()?;
    let clear = ClearPayload {
        ts_ms: now_ms(),
        seq,
        data: payload,
    };
    let pkt = seal_with_nonce(&params.key_enc, params.tag16, params.tag8, &clear, &nonce)?;
    let raw = serialize_cipher_packet(&pkt)?;
    framing::write_frame(&mut c_writer, &raw).await?;

    // 3. Ricevi AssistGo da C
    let go = timeout(Duration::from_millis(ttl_ms as u64 + 1000), async {
        let frame = framing::read_frame(&mut c_reader).await?;
        let pkt = deserialize_cipher_packet_with_limit(&frame, MAX_TCP_FRAME_BYTES)?;
        let clear = open(&params.key_enc, &pkt, params.tag16, params.tag8)
            .ok_or(WanAssistError::InvalidAssistGoPacket)?;
        let ctrl: Control = bincode::deserialize(&clear.data)
            .map_err(|e| WanAssistError::Bincode(e.to_string()))?;
        match (cfg.assist_obfuscation_v5, ctrl) {
            (true, Control::AssistGoV5(go)) if go.request_id == request_id => {
                Ok(AssistGoOrV5::V5(go))
            }
            (false, Control::AssistGo(go)) if go.request_id == request_id => {
                Ok(AssistGoOrV5::V4(go))
            }
            _ => Err(WanAssistError::UnexpectedControlMessage),
        }
    })
    .await
    .map_err(|_| WanAssistError::AssistGoTimeout)??;

    // 4. Chiudi connessione a C
    drop(c_reader);
    drop(c_writer);

    // 5. Esegui UDP burst punch
    match go {
        AssistGoOrV5::V4(go) => udp_burst_punch(&go, params.tag16).await,
        AssistGoOrV5::V5(go) => {
            if !verify_assist_go_mac_v5(&params.key_enc, &go) {
                return Err(WanAssistError::InvalidAssistGoV5Packet);
            }
            let obf_key = derive_obfuscation_key_v5(&params.key_enc, params.tag16)?;
            let candidates = unblind_candidates_v5(&go, &obf_key, cfg.assist_candidate_policy);
            let go_v4 = AssistGo {
                request_id: go.request_id,
                peer_udp_candidates: candidates,
                go_after_ms: go.go_after_ms,
                burst_duration_ms: go.burst_duration_ms,
                punch_profile: go.punch_profile.clone(),
            };
            udp_burst_punch(&go_v4, params.tag16).await
        }
    }
}

enum AssistGoOrV5 {
    V4(AssistGo),
    V5(AssistGoV5),
}

fn parse_tagged_sender(buf: &[u8], from: SocketAddr, tag16: u16, n: usize) -> Option<SocketAddr> {
    if n >= 2 && u16::from_le_bytes([buf[0], buf[1]]) == tag16 {
        return Some(from);
    }
    None
}

fn unblind_candidates_v5(
    go: &AssistGoV5,
    obf_key: &[u8; 32],
    policy: crate::protocol_assist_v5::CandidatePolicy,
) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for (idx, cand) in go.peer_candidates.iter().enumerate() {
        let nonce = match derive_entry_nonce_v5_improved(&go.request_id, idx, obf_key) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("Assist V5 nonce derivation failed: {}", e);
                continue;
            }
        };
        if let Some(addr) = cand.unblind(obf_key, &nonce) {
            if is_usable_candidate(&addr, policy) {
                out.push(addr);
            }
        }
    }
    out
}

/// Raccoglie i candidati UDP dell'attuale peer
async fn gather_udp_candidates(port: u16) -> Result<Vec<SocketAddr>> {
    let mut candidates = Vec::new();

    // Aggiungi interfacce locali
    for ip in lan::get_local_ip_addresses()? {
        candidates.push(SocketAddr::new(ip, port));
    }

    // Best-effort: prova UPnP
    if let Ok((_sock, ext_addr)) = wan_direct::try_direct_port_forward(port).await {
        candidates.push(ext_addr);
    }

    Ok(candidates)
}

/// Esegue burst UDP coordinato verso B
async fn udp_burst_punch(go: &AssistGo, tag16: u16) -> Result<crate::transport::Connection> {
    // Bind socket UDP
    let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    // Prepara probe template (alloca una volta)
    let probe = {
        let size = go.punch_profile.probe_size.max(2) as usize;
        let mut pkt = vec![0u8; size];
        pkt[0..2].copy_from_slice(&tag16.to_le_bytes());
        pkt
    };

    // Timer per coordinazione
    let start = tokio::time::Instant::now();
    let go_after = go.go_after_ms.clamp(10, 3000); // Guardrail 10ms-3s
    let go_at = start + Duration::from_millis(go_after as u64);

    // Burst + listen simultanei
    let burst_duration_ms = go.burst_duration_ms;
    let burst_handle = {
        let sock = sock.clone();
        let endpoints = go.peer_udp_candidates.clone();
        let profile = go.punch_profile.clone();
        tokio::spawn(async move {
            sleep_until(go_at).await;

            let end_at = go_at + Duration::from_millis(burst_duration_ms as u64);
            let tick_ms = (1000u16 / profile.pps.max(1)).max(5); // Anti-panic + min 5ms
            let mut interval = tokio::time::interval(Duration::from_millis(tick_ms as u64));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            while tokio::time::Instant::now() < end_at {
                // Jitter casuale
                let jitter = rand::thread_rng().gen_range(0..=profile.jitter_ms);
                sleep(Duration::from_millis(jitter as u64)).await;

                // Invia a tutti i candidati
                for endpoint in &endpoints {
                    if let Err(e) = sock.send_to(&probe, endpoint).await {
                        tracing::debug!("Probe send failed to {}: {}", endpoint, e);
                    }
                }

                interval.tick().await;
            }
        })
    };

    // Listen per risposta da B
    let mut buf = vec![0u8; UDP_MAX_PACKET_SIZE];
    let listen_timeout = go.burst_duration_ms + 500;

    let result: std::result::Result<Result<SocketAddr>, tokio::time::error::Elapsed> =
        timeout(Duration::from_millis(listen_timeout as u64), async {
            loop {
                let (n, from) = sock.recv_from(&mut buf).await?;

                if let Some(hit) = parse_tagged_sender(&buf, from, tag16, n) {
                    return Ok::<SocketAddr, WanAssistError>(hit);
                }
            }
        })
        .await;

    // Attendi che burst finisca
    let _ = burst_handle.await;

    match result {
        Ok(Ok(peer_addr)) => {
            tracing::info!("WAN Assist: received probe from {}", peer_addr);
            Ok(crate::transport::Connection::Wan(sock, peer_addr))
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(WanAssistError::NoResponseFromPeer),
    }
}

/// Coordinazione temporale per simultaneous open
pub mod coordination {
    use super::*;
    use crate::offer::OfferPayload;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Timestamped offer per sincronizzazione
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct TimestampedOffer {
        pub offer_hash: [u8; 32],
        pub timestamp_ms: u64,
        pub ntp_offset: Option<i64>,
        pub simultaneous_open: bool,
    }

    /// Pubblica offerta sulla relay con timestamp
    pub async fn publish_offer_with_timestamp<S>(
        relay_stream: &mut S,
        offer: &OfferPayload,
        offer_hash: [u8; 32],
    ) -> Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin + Send,
    {
        let timestamp_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;

        let timestamped = TimestampedOffer {
            offer_hash,
            timestamp_ms,
            ntp_offset: offer.ntp_offset,
            simultaneous_open: offer.simultaneous_open,
        };

        // Serializza e invia
        let data =
            bincode::serialize(&timestamped).map_err(|e| WanAssistError::Bincode(e.to_string()))?;
        let len = data.len() as u32;

        relay_stream.write_all(&len.to_be_bytes()).await?;
        relay_stream.write_all(&data).await?;
        relay_stream.flush().await?;

        tracing::debug!(
            "Published timestamped offer: hash={}, ts={}, simultaneous={}",
            hex::encode(&offer_hash[..8]),
            timestamp_ms,
            offer.simultaneous_open
        );

        Ok(())
    }

    /// Leggi offerta del peer e calcola offset NTP-like
    pub async fn read_their_offer_and_sync<S>(
        relay_stream: &mut S,
    ) -> Result<(TimestampedOffer, i64)>
    where
        S: tokio::io::AsyncRead + Unpin + Send,
    {
        // Leggi lunghezza
        let mut len_buf = [0u8; 4];
        relay_stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // Leggi dati
        let mut data = vec![0u8; len];
        relay_stream.read_exact(&mut data).await?;

        let their_offer: TimestampedOffer =
            bincode::deserialize(&data).map_err(|e| WanAssistError::Bincode(e.to_string()))?;

        let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;

        let offset = (their_offer.timestamp_ms as i64) - (now_ms as i64);

        tracing::debug!(
            "Read their offer: hash={}, ts={}, offset={}ms",
            hex::encode(&their_offer.offer_hash[..8]),
            their_offer.timestamp_ms,
            offset
        );

        Ok((their_offer, offset))
    }

    fn apply_signed_offset_ms(base_ms: u64, offset_ms: i64) -> u64 {
        let adjusted = (base_ms as i128) + (offset_ms as i128);
        adjusted.clamp(0, u64::MAX as i128) as u64
    }

    /// Coordinazione simultaneous open con rendezvous window
    pub async fn coordinate_simultaneous_open(
        my_offer: &OfferPayload,
        their_hash: [u8; 32],
        relay: &str,
        cfg: &Config,
    ) -> Result<crate::transport::Connection> {
        // Connettiti al relay
        let relay_stream = timeout(
            Duration::from_secs(5),
            wan_tor::try_tor_connect(&cfg.tor_socks_addr, relay, None, Some(relay)),
        )
        .await??;

        let (mut reader, mut writer) = relay_stream.into_split();

        // 1. Pubblica la nostra offerta con timestamp
        let my_hash = crate::crypto::hash_offer(my_offer);
        publish_offer_with_timestamp(&mut writer, my_offer, my_hash).await?;

        // 2. Leggi la loro offerta e calcola offset
        let (their_offer, _offset) = read_their_offer_and_sync(&mut reader).await?;

        // Verifica che sia l'offerta corretta
        if their_offer.offer_hash != their_hash {
            return Err(WanAssistError::OfferHashMismatch {
                expected: hex::encode(&their_hash[..8]),
                got: hex::encode(&their_offer.offer_hash[..8]),
            });
        }

        // 3. Determina se possiamo fare simultaneous open
        if !their_offer.simultaneous_open || !my_offer.simultaneous_open {
            tracing::info!("Simultaneous open disabled, falling back to sequential");
            // Fallback a tentativi sequenziali
            return Err(WanAssistError::SimultaneousOpenNotEnabled);
        }

        // 4. Calcola rendezvous time (30 secondi window)
        let rendezvous_window_ms = 30000u64;
        let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;

        // Applica offset per sincronizzazione in modo safe (no wraparound).
        let adjusted_now = if let Some(ntp_offset) = my_offer.ntp_offset {
            apply_signed_offset_ms(now_ms, ntp_offset)
        } else {
            now_ms
        };

        let rendezvous_at_ms = adjusted_now.saturating_add(rendezvous_window_ms);

        // 5. Attendi fino al rendezvous time
        let sleep_duration = if rendezvous_at_ms > now_ms {
            Duration::from_millis(rendezvous_at_ms - now_ms)
        } else {
            tracing::warn!("Rendezvous time is in the past, starting immediately");
            Duration::from_millis(100) // Breve delay
        };

        tracing::info!(
            "Waiting for rendezvous at {} (in {}ms)",
            rendezvous_at_ms,
            sleep_duration.as_millis()
        );

        tokio::time::sleep(sleep_duration).await;

        // 6. Esegui l'handshake simultaneo su tutti gli endpoint
        // Proviamo UPnP, STUN, e relay in parallelo
        tracing::info!("Starting simultaneous open handshake");

        // Prepara i parametri (la versione protocollo resta invariata).
        let params = crate::derive::RendezvousParams {
            port: my_offer.rendezvous.port,
            key_enc: my_offer.rendezvous.key_enc,
            key_mac: [0u8; 32],
            tag16: my_offer.rendezvous.tag16,
            tag8: crate::derive::derive_tag8_from_key(&my_offer.rendezvous.key_enc)?,
            version: my_offer.ver,
        };

        // Prova hole punching simultaneo
        match crate::transport::wan_direct::try_direct_port_forward(params.port).await {
            Ok((sock, peer_addr)) => {
                tracing::info!(
                    "Simultaneous open success via direct connection: {}",
                    peer_addr
                );
                Ok(crate::transport::Connection::Wan(sock.into(), peer_addr))
            }
            Err(e) => {
                tracing::warn!(
                    "Direct simultaneous open failed: {}, trying relay fallback",
                    e
                );

                // Fallback: usa il relay corrente come mediatore
                let relay_stream = timeout(
                    Duration::from_secs(5),
                    wan_tor::try_tor_connect(&cfg.tor_socks_addr, relay, None, Some(relay)),
                )
                .await??;

                coordinate_with_relay(relay_stream, &params, cfg).await
            }
        }
    }

    /// Wrapper che prova simultaneo, fallback a sequenziale
    ///
    /// NOTE: Simultaneous Open requires assist relays to be configured.
    pub async fn try_simultaneous_or_sequential(
        my_offer: &OfferPayload,
        their_hash: [u8; 32],
        relay_onions: &[String],
        cfg: &Config,
    ) -> Result<crate::transport::Connection> {
        if relay_onions.is_empty() {
            tracing::info!("Simultaneous open skipped: no assist relays configured");
            return Err(WanAssistError::SimultaneousOpenRequiresRelays);
        }

        // Prova simultaneo sul primo relay (con retry + backoff)
        let max_attempts: u8 = 3;
        let mut attempt: u8 = 0;
        while attempt < max_attempts {
            match coordinate_simultaneous_open(my_offer, their_hash, &relay_onions[0], cfg).await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    tracing::warn!(
                        "Simultaneous open failed (attempt {}/{}): {}",
                        attempt + 1,
                        max_attempts,
                        e
                    );
                }
            }
            attempt += 1;
            if attempt < max_attempts {
                let backoff_ms = 500u64.saturating_mul(1u64 << attempt);
                sleep(Duration::from_millis(backoff_ms)).await;
            }
        }

        // Fallback: tentativi sequenziali
        let params = crate::derive::RendezvousParams {
            port: my_offer.rendezvous.port,
            key_enc: my_offer.rendezvous.key_enc,
            key_mac: [0u8; 32],
            tag16: my_offer.rendezvous.tag16,
            tag8: crate::derive::derive_tag8_from_key(&my_offer.rendezvous.key_enc)?,
            version: my_offer.ver,
        };

        try_assisted_punch(&params, relay_onions, cfg).await
    }

    #[cfg(test)]
    mod tests {
        use super::apply_signed_offset_ms;

        #[test]
        fn signed_offset_clamps_at_zero() {
            assert_eq!(apply_signed_offset_ms(100, -150), 0);
        }

        #[test]
        fn signed_offset_adds_positive_offsets() {
            assert_eq!(apply_signed_offset_ms(100, 50), 150);
        }
    }
}
