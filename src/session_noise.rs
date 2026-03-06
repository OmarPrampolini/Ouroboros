use crate::config::UDP_MAX_PACKET_SIZE;
#[cfg(feature = "pq")]
use crate::crypto::post_quantum::NOISE_PARAMS_PQ;
use crate::crypto::{
    self, deserialize_cipher_packet_with_limit, open, seal_with_nonce, ClearPayload, NonceSeq,
    MAX_TCP_FRAME_BYTES, MAX_UDP_PACKET_BYTES, NONCE_DOMAIN_NOISE, NONCE_DOMAIN_RESUME,
};
use crate::protocol::Control;
use crate::resume::ResumeParams;
use crate::transport::Connection;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use snow::{Builder, HandshakeState};
use std::future::Future;
use thiserror::Error;
use tokio::time::{timeout, Duration};

const NOISE_PARAMS_CLASSIC: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const MAX_NOISE_MESSAGE_BYTES: usize = 8 * 1024;
const RESUME_TIMEOUT_MS: u64 = 2000;
const RESUME_MAX_SKEW_MS: u64 = 5000;
const NOISE_HANDSHAKE_MAX_SKEW_MS: u64 = 15_000;

#[derive(Debug, Error)]
pub enum SessionNoiseError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("noise params parse failed: {0}")]
    NoiseParams(String),
    #[error("PQ feature disabled; enable with --features pq")]
    PqDisabled,
    #[error("resume ticket expired")]
    ResumeTicketExpired,
    #[error("message too large: {0}")]
    MessageTooLarge(String),
    #[error("invalid base packet: {0}")]
    InvalidBasePacket(&'static str),
    #[error("unexpected resume response")]
    UnexpectedResumeResponse,
    #[error("unexpected resume hello")]
    UnexpectedResumeHello,
    #[error("resume token mismatch")]
    ResumeTokenMismatch,
    #[error("resume server nonce invalid")]
    ResumeServerNonceInvalid,
    #[error("resume client nonce invalid")]
    ResumeClientNonceInvalid,
    #[error("resume hello expired")]
    ResumeHelloExpired,
    #[error("hkdf expand failed: {0}")]
    Hkdf(String),
    #[error("noise handshake message size invalid")]
    NoiseHandshakeMessageSizeInvalid,
    #[error("protocol violation: {0}")]
    ProtocolViolation(String),
    #[error("noise handshake too large")]
    NoiseHandshakeTooLarge,
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("deserialization failed: {0}")]
    Deserialization(String),
    #[error("noise operation failed: {0}")]
    Noise(String),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
}

type Result<T> = std::result::Result<T, SessionNoiseError>;

/// Protocol state validation to prevent state machine attacks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolState {
    Handshake,
    Transport,
    Closed,
}

/// Comprehensive protocol validation result
pub struct ProtocolValidation {
    pub is_valid: bool,
    pub state: ProtocolState,
    pub error: Option<String>,
}

/// Validate protocol transition and message in current state
pub fn validate_protocol_transition(
    current_state: ProtocolState,
    message_type: &crate::protocol::Control,
    is_handshake_complete: bool,
) -> ProtocolValidation {
    use crate::protocol::Control;

    match (current_state, message_type) {
        // Valid handshake messages during handshake
        (ProtocolState::Handshake, Control::NoiseHandshake(_)) => ProtocolValidation {
            is_valid: true,
            state: ProtocolState::Handshake,
            error: None,
        },
        // SessionKey only valid after handshake complete
        (ProtocolState::Handshake, Control::SessionKey(_)) => {
            if is_handshake_complete {
                ProtocolValidation {
                    is_valid: true,
                    state: ProtocolState::Handshake,
                    error: None,
                }
            } else {
                ProtocolValidation {
                    is_valid: false,
                    state: ProtocolState::Handshake,
                    error: Some("SessionKey received before handshake completion".to_string()),
                }
            }
        }
        (ProtocolState::Handshake, Control::SessionKeyAck(_)) => ProtocolValidation {
            is_valid: false,
            state: ProtocolState::Handshake,
            error: Some("SessionKeyAck received during handshake".to_string()),
        },
        (ProtocolState::Handshake, Control::ResumeHello { .. }) => ProtocolValidation {
            is_valid: true,
            state: ProtocolState::Handshake,
            error: None,
        },
        (ProtocolState::Handshake, Control::ResumeAccept { .. }) => ProtocolValidation {
            is_valid: true,
            state: ProtocolState::Handshake,
            error: None,
        },
        // Invalid messages during handshake
        (ProtocolState::Handshake, Control::App(_)) => ProtocolValidation {
            is_valid: false,
            state: ProtocolState::Handshake,
            error: Some("Application data received during handshake".to_string()),
        },
        (ProtocolState::Handshake, Control::AssistRequest(_)) => ProtocolValidation {
            is_valid: false,
            state: ProtocolState::Handshake,
            error: Some("AssistRequest received during handshake".to_string()),
        },
        (ProtocolState::Handshake, Control::AssistGo(_)) => ProtocolValidation {
            is_valid: false,
            state: ProtocolState::Handshake,
            error: Some("AssistGo received during handshake".to_string()),
        },
        (ProtocolState::Handshake, Control::AssistRequestV5(_)) => ProtocolValidation {
            is_valid: false,
            state: ProtocolState::Handshake,
            error: Some("AssistRequestV5 received during handshake".to_string()),
        },
        (ProtocolState::Handshake, Control::AssistGoV5(_)) => ProtocolValidation {
            is_valid: false,
            state: ProtocolState::Handshake,
            error: Some("AssistGoV5 received during handshake".to_string()),
        },
        // Invalid messages during transport
        (ProtocolState::Transport, Control::NoiseHandshake(_)) => ProtocolValidation {
            is_valid: false,
            state: ProtocolState::Transport,
            error: Some("Handshake message received in transport mode".to_string()),
        },
        // Valid messages during transport
        (ProtocolState::Transport, Control::App(_)) => ProtocolValidation {
            is_valid: true,
            state: ProtocolState::Transport,
            error: None,
        },
        (ProtocolState::Transport, Control::SessionKey(_)) => ProtocolValidation {
            is_valid: true,
            state: ProtocolState::Transport,
            error: None,
        },
        (ProtocolState::Transport, Control::SessionKeyAck(_)) => ProtocolValidation {
            is_valid: true,
            state: ProtocolState::Transport,
            error: None,
        },
        (ProtocolState::Transport, Control::ResumeHello { .. }) => ProtocolValidation {
            is_valid: false,
            state: ProtocolState::Transport,
            error: Some("ResumeHello received in transport mode".to_string()),
        },
        (ProtocolState::Transport, Control::ResumeAccept { .. }) => ProtocolValidation {
            is_valid: false,
            state: ProtocolState::Transport,
            error: Some("ResumeAccept received in transport mode".to_string()),
        },
        (ProtocolState::Transport, Control::AssistRequest(_) | Control::AssistGo(_)) => {
            ProtocolValidation {
                is_valid: true,
                state: ProtocolState::Transport,
                error: None,
            }
        }
        (ProtocolState::Transport, Control::AssistRequestV5(_) | Control::AssistGoV5(_)) => {
            ProtocolValidation {
                is_valid: true,
                state: ProtocolState::Transport,
                error: None,
            }
        }
        // Invalid messages on closed connection
        (ProtocolState::Closed, _) => ProtocolValidation {
            is_valid: false,
            state: ProtocolState::Closed,
            error: Some("Message received on closed connection".to_string()),
        },
    }
}

impl ProtocolState {
    /// Check if current state allows message transmission
    pub fn can_send_message(&self, message_type: &crate::protocol::Control) -> bool {
        use crate::protocol::Control;
        matches!(
            (self, message_type),
            (ProtocolState::Handshake, Control::NoiseHandshake(_))
                | (ProtocolState::Handshake, Control::ResumeHello { .. })
                | (ProtocolState::Handshake, Control::ResumeAccept { .. })
                | (ProtocolState::Transport, _)
        )
    }

    /// Check if current state allows message reception
    pub fn can_receive_message(&self, message_type: &crate::protocol::Control) -> bool {
        use crate::protocol::Control;
        matches!(
            (self, message_type),
            (ProtocolState::Handshake, Control::NoiseHandshake(_))
                | (ProtocolState::Handshake, Control::ResumeHello { .. })
                | (ProtocolState::Handshake, Control::ResumeAccept { .. })
                | (ProtocolState::Transport, _)
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub enum NoiseRole {
    Initiator,
    Responder,
}

/// Abstract raw packet sending over any connection type
async fn send_raw(conn: &Connection, data: Vec<u8>) -> Result<()> {
    match conn {
        Connection::Lan(sock, addr) | Connection::Wan(sock, addr) => {
            sock.send_to(&data, *addr)
                .await
                .map_err(|e| SessionNoiseError::Transport(e.to_string()))?;
        }
        Connection::WanTorStream { writer, .. } => {
            let mut guard = writer.lock().await;
            crate::transport::framing::write_frame(&mut *guard, &data)
                .await
                .map_err(|e| SessionNoiseError::Transport(e.to_string()))?;
        }
        Connection::WanTcpStream { writer, .. } => {
            let mut guard = writer.lock().await;
            crate::transport::framing::write_frame(&mut *guard, &data)
                .await
                .map_err(|e| SessionNoiseError::Transport(e.to_string()))?;
        }
        Connection::Quic(quic) => {
            quic.send(&data)
                .await
                .map_err(|e| SessionNoiseError::Transport(e.to_string()))?;
        }
        Connection::WebRtc(webrtc) => {
            webrtc
                .send(&data)
                .await
                .map_err(|e| SessionNoiseError::Transport(e.to_string()))?;
        }
    }
    Ok(())
}

/// Abstract raw packet receiving over any connection type
async fn recv_raw(conn: &Connection) -> Result<Vec<u8>> {
    match conn {
        Connection::Lan(sock, _) | Connection::Wan(sock, _) => {
            let mut buf = vec![0u8; UDP_MAX_PACKET_SIZE];
            let (n, _) = sock
                .recv_from(&mut buf)
                .await
                .map_err(|e| SessionNoiseError::Transport(e.to_string()))?;
            Ok(buf[..n].to_vec())
        }
        Connection::WanTorStream { reader, .. } => {
            let mut guard = reader.lock().await;
            crate::transport::framing::read_frame(&mut *guard)
                .await
                .map_err(|e| SessionNoiseError::Transport(e.to_string()))
        }
        Connection::WanTcpStream { reader, .. } => {
            let mut guard = reader.lock().await;
            crate::transport::framing::read_frame(&mut *guard)
                .await
                .map_err(|e| SessionNoiseError::Transport(e.to_string()))
        }
        Connection::Quic(quic) => quic
            .recv()
            .await
            .map_err(|e| SessionNoiseError::Transport(e.to_string())),
        Connection::WebRtc(webrtc) => webrtc
            .recv()
            .await
            .map_err(|e| SessionNoiseError::Transport(e.to_string())),
    }
}

fn max_packet_limit(conn: &Connection) -> u64 {
    match conn {
        Connection::WebRtc(_) => crate::transport::webrtc::WEBRTC_MAX_MESSAGE_BYTES as u64,
        _ if conn.is_stream() => MAX_TCP_FRAME_BYTES,
        _ => MAX_UDP_PACKET_BYTES,
    }
}

fn parse_noise_params(params_str: &str, needs_pq: bool) -> Result<snow::params::NoiseParams> {
    params_str.parse().map_err(|e| {
        if needs_pq {
            SessionNoiseError::NoiseParams(format!(
                "{}: {}. Ensure snow features hfs + pqclean_kyber1024 are enabled.",
                params_str, e
            ))
        } else {
            SessionNoiseError::NoiseParams(format!("{}: {}.", params_str, e))
        }
    })
}

fn validate_packet_timestamp(ts_ms: u64, max_skew_ms: u64, context: &'static str) -> Result<()> {
    let now = crypto::now_ms();
    if ts_ms > now.saturating_add(max_skew_ms) || now.saturating_sub(ts_ms) > max_skew_ms {
        return Err(SessionNoiseError::ProtocolViolation(format!(
            "{} timestamp outside window",
            context
        )));
    }
    Ok(())
}

pub fn classic_noise_params() -> Result<snow::params::NoiseParams> {
    parse_noise_params(NOISE_PARAMS_CLASSIC, false)
}

pub fn pq_noise_params() -> Result<snow::params::NoiseParams> {
    #[cfg(feature = "pq")]
    {
        parse_noise_params(NOISE_PARAMS_PQ, true)
    }
    #[cfg(not(feature = "pq"))]
    {
        Err(SessionNoiseError::PqDisabled)
    }
}

/// Run Noise handshake upgrade over an established connection.
///
/// Messages are encrypted with the `base_key` (derived from passphrase)
/// wrapping a `Control::NoiseHandshake` payload.
pub async fn run_noise_upgrade(
    role: NoiseRole,
    conn: &Connection,
    base_key: &[u8; 32],
    tag16: u16,
    tag8: u8,
) -> Result<[u8; 32]> {
    let limit = max_packet_limit(conn);

    if conn.is_stream() {
        #[cfg(feature = "pq")]
        {
            match pq_noise_params() {
                Ok(params) => {
                    match run_noise_upgrade_io(
                        role,
                        |data: Vec<u8>| async move { send_raw(conn, data).await },
                        || async move { recv_raw(conn).await },
                        base_key,
                        tag16,
                        tag8,
                        params,
                        limit,
                    )
                    .await
                    {
                        Ok(k) => return Ok(k),
                        Err(e) => {
                            tracing::warn!(
                                "Noise PQ handshake failed ({}), falling back to classic",
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Noise PQ params unavailable ({}), falling back to classic",
                        e
                    );
                }
            }
        }
        #[cfg(not(feature = "pq"))]
        {
            tracing::info!("Noise PQ feature disabled; using classic XX");
        }
    } else {
        tracing::info!("Noise PQ disabled for UDP; using classic XX to fit MTU");
    }

    let params = classic_noise_params()?;
    run_noise_upgrade_io(
        role,
        |data: Vec<u8>| async move { send_raw(conn, data).await },
        || async move { recv_raw(conn).await },
        base_key,
        tag16,
        tag8,
        params,
        limit,
    )
    .await
}

pub async fn run_resume_upgrade(
    role: NoiseRole,
    conn: &Connection,
    base_key: &[u8; 32],
    tag16: u16,
    tag8: u8,
    resume: &ResumeParams,
) -> Result<[u8; 32]> {
    let limit = max_packet_limit(conn);
    run_resume_upgrade_io(
        role,
        |data: Vec<u8>| async move { send_raw(conn, data).await },
        || async move { recv_raw(conn).await },
        base_key,
        tag16,
        tag8,
        resume,
        limit,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_resume_upgrade_io<FSend, FRecv, FS, FR, ESend, ERecv>(
    role: NoiseRole,
    send: FSend,
    mut recv: FRecv,
    base_key: &[u8; 32],
    tag16: u16,
    tag8: u8,
    resume: &ResumeParams,
    limit: u64,
) -> Result<[u8; 32]>
where
    FSend: Fn(Vec<u8>) -> FS + Send + Sync,
    FS: Future<Output = std::result::Result<(), ESend>> + Send,
    FRecv: FnMut() -> FR + Send,
    FR: Future<Output = std::result::Result<Vec<u8>, ERecv>> + Send,
    ESend: std::fmt::Display,
    ERecv: std::fmt::Display,
{
    if resume.is_expired() {
        return Err(SessionNoiseError::ResumeTicketExpired);
    }

    let role_byte = match role {
        NoiseRole::Initiator => 0x01,
        NoiseRole::Responder => 0x02,
    };
    let mut nonce_seq = NonceSeq::new_boot_random(base_key, NONCE_DOMAIN_RESUME, role_byte)?;
    match role {
        NoiseRole::Initiator => {
            let mut client_nonce = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut client_nonce);
            client_nonce[0] = 0x01;
            let ctrl = Control::ResumeHello {
                token_id: resume.token_id,
                client_nonce,
                ts_ms: crypto::now_ms(),
            };
            let payload_bytes = bincode::serialize(&ctrl)
                .map_err(|e| SessionNoiseError::Serialization(e.to_string()))?;
            let (nonce, seq) = nonce_seq.next_nonce_and_seq()?;
            let clear = ClearPayload {
                ts_ms: crypto::now_ms(),
                seq,
                data: payload_bytes,
            };
            let pkt = seal_with_nonce(base_key, tag16, tag8, &clear, &nonce)?;
            let raw_bytes = crypto::serialize_cipher_packet(&pkt)?;
            send(raw_bytes)
                .await
                .map_err(|e| SessionNoiseError::Transport(e.to_string()))?;

            let raw = recv()
                .await
                .map_err(|e| SessionNoiseError::Transport(e.to_string()))?;
            if raw.len() > limit as usize {
                return Err(SessionNoiseError::MessageTooLarge(format!(
                    "{} > {}",
                    raw.len(),
                    limit
                )));
            }
            let pkt = deserialize_cipher_packet_with_limit(&raw, limit)?;
            let clear = open(base_key, &pkt, tag16, tag8)
                .ok_or(SessionNoiseError::InvalidBasePacket("resume handshake"))?;
            validate_packet_timestamp(clear.ts_ms, RESUME_MAX_SKEW_MS, "resume packet")?;
            let ctrl: Control = bincode::deserialize(&clear.data)
                .map_err(|e| SessionNoiseError::Deserialization(e.to_string()))?;
            let (token_id, server_nonce) = match ctrl {
                Control::ResumeAccept {
                    token_id,
                    server_nonce,
                } => (token_id, server_nonce),
                _ => return Err(SessionNoiseError::UnexpectedResumeResponse),
            };
            if token_id != resume.token_id {
                return Err(SessionNoiseError::ResumeTokenMismatch);
            }
            if server_nonce[0] != 0x02 {
                return Err(SessionNoiseError::ResumeServerNonceInvalid);
            }
            Ok(derive_resume_session_key(
                &resume.resume_secret,
                &client_nonce,
                &server_nonce,
            )?)
        }
        NoiseRole::Responder => {
            let raw = recv()
                .await
                .map_err(|e| SessionNoiseError::Transport(e.to_string()))?;
            if raw.len() > limit as usize {
                return Err(SessionNoiseError::MessageTooLarge(format!(
                    "{} > {}",
                    raw.len(),
                    limit
                )));
            }
            let pkt = deserialize_cipher_packet_with_limit(&raw, limit)?;
            let clear = open(base_key, &pkt, tag16, tag8)
                .ok_or(SessionNoiseError::InvalidBasePacket("resume handshake"))?;
            validate_packet_timestamp(clear.ts_ms, RESUME_MAX_SKEW_MS, "resume packet")?;
            let ctrl: Control = bincode::deserialize(&clear.data)
                .map_err(|e| SessionNoiseError::Deserialization(e.to_string()))?;
            let (token_id, client_nonce, ts_ms) = match ctrl {
                Control::ResumeHello {
                    token_id,
                    client_nonce,
                    ts_ms,
                } => (token_id, client_nonce, ts_ms),
                _ => return Err(SessionNoiseError::UnexpectedResumeHello),
            };
            if token_id != resume.token_id {
                return Err(SessionNoiseError::ResumeTokenMismatch);
            }
            if client_nonce[0] != 0x01 {
                return Err(SessionNoiseError::ResumeClientNonceInvalid);
            }
            let now = crypto::now_ms();
            if ts_ms > now.saturating_add(RESUME_MAX_SKEW_MS)
                || now.saturating_sub(ts_ms) > RESUME_MAX_SKEW_MS
            {
                return Err(SessionNoiseError::ResumeHelloExpired);
            }
            let mut server_nonce = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut server_nonce);
            server_nonce[0] = 0x02;
            let ctrl = Control::ResumeAccept {
                token_id,
                server_nonce,
            };
            let payload_bytes = bincode::serialize(&ctrl)
                .map_err(|e| SessionNoiseError::Serialization(e.to_string()))?;
            let (nonce, seq) = nonce_seq.next_nonce_and_seq()?;
            let clear = ClearPayload {
                ts_ms: crypto::now_ms(),
                seq,
                data: payload_bytes,
            };
            let pkt = seal_with_nonce(base_key, tag16, tag8, &clear, &nonce)?;
            let raw_bytes = crypto::serialize_cipher_packet(&pkt)?;
            send(raw_bytes)
                .await
                .map_err(|e| SessionNoiseError::Transport(e.to_string()))?;

            Ok(derive_resume_session_key(
                &resume.resume_secret,
                &client_nonce,
                &server_nonce,
            )?)
        }
    }
}

pub async fn run_resume_or_noise(
    role: NoiseRole,
    conn: &Connection,
    base_key: &[u8; 32],
    tag16: u16,
    tag8: u8,
    resume: &ResumeParams,
) -> Result<([u8; 32], bool)> {
    if resume.is_expired() {
        let key = run_noise_upgrade(role, conn, base_key, tag16, tag8).await?;
        return Ok((key, false));
    }
    match timeout(
        Duration::from_millis(RESUME_TIMEOUT_MS),
        run_resume_upgrade(role, conn, base_key, tag16, tag8, resume),
    )
    .await
    {
        Ok(Ok(k)) => Ok((k, true)),
        Ok(Err(e)) => {
            tracing::warn!("Resume failed, falling back to Noise: {:?}", e);
            let key = run_noise_upgrade(role, conn, base_key, tag16, tag8).await?;
            Ok((key, false))
        }
        Err(_) => {
            tracing::warn!("Resume timeout, falling back to Noise");
            let key = run_noise_upgrade(role, conn, base_key, tag16, tag8).await?;
            Ok((key, false))
        }
    }
}

fn derive_resume_session_key(
    resume_secret: &[u8; 32],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(client_nonce);
    salt.extend_from_slice(server_nonce);
    let hk = Hkdf::<Sha256>::new(Some(&salt), resume_secret);
    let mut out = [0u8; 32];
    hk.expand(b"handshacke-resume-v1", &mut out)
        .map_err(|e| SessionNoiseError::Hkdf(format!("{:?}", e)))?;
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub async fn run_noise_upgrade_io<FSend, FRecv, FS, FR, ESend, ERecv>(
    role: NoiseRole,
    send: FSend,
    mut recv: FRecv,
    base_key: &[u8; 32],
    tag16: u16,
    tag8: u8,
    params: snow::params::NoiseParams,
    limit: u64,
) -> Result<[u8; 32]>
where
    FSend: Fn(Vec<u8>) -> FS + Send + Sync,
    FS: Future<Output = std::result::Result<(), ESend>> + Send,
    FRecv: FnMut() -> FR + Send,
    FR: Future<Output = std::result::Result<Vec<u8>, ERecv>> + Send,
    ESend: std::fmt::Display,
    ERecv: std::fmt::Display,
{
    tracing::info!("Starting Noise session upgrade...");

    let builder = Builder::new(params);
    let keypair = builder
        .generate_keypair()
        .map_err(|e| SessionNoiseError::Noise(e.to_string()))?;
    let builder = builder.local_private_key(&keypair.private);
    let mut noise: HandshakeState = match role {
        NoiseRole::Initiator => builder
            .build_initiator()
            .map_err(|e| SessionNoiseError::Noise(e.to_string()))?,
        NoiseRole::Responder => builder
            .build_responder()
            .map_err(|e| SessionNoiseError::Noise(e.to_string()))?,
    };

    let mut buf = vec![0u8; MAX_NOISE_MESSAGE_BYTES];
    let role_byte = match role {
        NoiseRole::Initiator => 0x01,
        NoiseRole::Responder => 0x02,
    };
    let mut nonce_seq = NonceSeq::new_boot_random(base_key, NONCE_DOMAIN_NOISE, role_byte)?;

    loop {
        if noise.is_handshake_finished() {
            break;
        }

        if noise.is_my_turn() {
            let len = noise
                .write_message(&[], &mut buf)
                .map_err(|e| SessionNoiseError::Noise(e.to_string()))?;
            if len == 0 || len > MAX_NOISE_MESSAGE_BYTES {
                return Err(SessionNoiseError::NoiseHandshakeMessageSizeInvalid);
            }
            let noise_msg = buf[..len].to_vec();

            let ctrl = Control::NoiseHandshake(noise_msg);
            let payload_bytes = bincode::serialize(&ctrl)
                .map_err(|e| SessionNoiseError::Serialization(e.to_string()))?;

            let (nonce, seq) = nonce_seq.next_nonce_and_seq()?;
            let clear = ClearPayload {
                ts_ms: crypto::now_ms(),
                seq,
                data: payload_bytes,
            };
            let pkt = seal_with_nonce(base_key, tag16, tag8, &clear, &nonce)?;
            let raw_bytes = crypto::serialize_cipher_packet(&pkt)?;

            send(raw_bytes)
                .await
                .map_err(|e| SessionNoiseError::Transport(e.to_string()))?;
            tracing::debug!("Sent Noise handshake message ({} bytes)", len);
        } else {
            let raw_bytes = recv()
                .await
                .map_err(|e| SessionNoiseError::Transport(e.to_string()))?;

            // Importante: controllo dimensione dal primo file
            if raw_bytes.len() > limit as usize {
                return Err(SessionNoiseError::MessageTooLarge(format!(
                    "{} > {} bytes",
                    raw_bytes.len(),
                    limit
                )));
            }

            let pkt = deserialize_cipher_packet_with_limit(&raw_bytes, limit)?;
            let clear = open(base_key, &pkt, tag16, tag8)
                .ok_or(SessionNoiseError::InvalidBasePacket("noise handshake"))?;
            validate_packet_timestamp(
                clear.ts_ms,
                NOISE_HANDSHAKE_MAX_SKEW_MS,
                "noise handshake packet",
            )?;

            let ctrl: Control = bincode::deserialize(&clear.data)
                .map_err(|e| SessionNoiseError::Deserialization(e.to_string()))?;

            // Usa la validazione del protocollo
            let validation = validate_protocol_transition(
                ProtocolState::Handshake,
                &ctrl,
                false, // handshake non ancora completato
            );

            if !validation.is_valid {
                return Err(SessionNoiseError::ProtocolViolation(
                    validation.error.unwrap_or_default(),
                ));
            }

            match ctrl {
                Control::NoiseHandshake(msg) => {
                    if msg.is_empty() || msg.len() > MAX_NOISE_MESSAGE_BYTES {
                        return Err(SessionNoiseError::NoiseHandshakeTooLarge);
                    }
                    noise
                        .read_message(&msg, &mut [])
                        .map_err(|e| SessionNoiseError::Noise(e.to_string()))?;
                    tracing::debug!("Received Noise handshake message ({} bytes)", msg.len());
                }
                // Questi casi ora sono gestiti da validate_protocol_transition
                _ => unreachable!(), // Non dovrebbe mai succedere grazie alla validazione
            }
        }
    }

    let mut transport = noise
        .into_transport_mode()
        .map_err(|e| SessionNoiseError::Noise(e.to_string()))?;

    match role {
        NoiseRole::Initiator => {
            // Usa OsRng dal primo file (più sicuro di thread_rng)
            let mut session_key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut session_key);

            let ctrl = Control::SessionKey(session_key);
            let payload_bytes = bincode::serialize(&ctrl)
                .map_err(|e| SessionNoiseError::Serialization(e.to_string()))?;

            let len = transport
                .write_message(&payload_bytes, &mut buf)
                .map_err(|e| SessionNoiseError::Noise(e.to_string()))?;
            send(buf[..len].to_vec())
                .await
                .map_err(|e| SessionNoiseError::Transport(e.to_string()))?;
            tracing::debug!("Session key sent over Noise channel ({} bytes)", len);

            tracing::info!("Noise session upgrade completed successfully.");
            Ok(session_key)
        }
        NoiseRole::Responder => {
            let raw = recv()
                .await
                .map_err(|e| SessionNoiseError::Transport(e.to_string()))?;
            let len = transport
                .read_message(&raw, &mut buf)
                .map_err(|e| SessionNoiseError::Noise(e.to_string()))?;
            let ctrl: Control = bincode::deserialize(&buf[..len])
                .map_err(|e| SessionNoiseError::Deserialization(e.to_string()))?;

            // Validazione per il SessionKey
            let validation = validate_protocol_transition(
                ProtocolState::Handshake,
                &ctrl,
                true, // handshake completato
            );

            if !validation.is_valid {
                return Err(SessionNoiseError::ProtocolViolation(
                    validation.error.unwrap_or_default(),
                ));
            }

            match ctrl {
                Control::SessionKey(sk) => {
                    tracing::debug!("Session key received over Noise channel");
                    tracing::info!("Noise session upgrade completed successfully.");
                    Ok(sk)
                }
                _ => unreachable!(), // Non dovrebbe mai succedere grazie alla validazione
            }
        }
    }
}
