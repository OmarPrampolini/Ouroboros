use crate::config::UDP_MAX_PACKET_SIZE;
use crate::transport::io::{ConnectionIo, TransportIo};
use crate::{
    api::Streams,
    crypto::{
        deserialize_cipher_packet_with_limit, key_id_from_key, now_ms, seal_with_nonce,
        serialize_cipher_packet, ClearPayload, KeyRotationPolicy, NonceSeq, SessionKeyState,
        MAX_CLEAR_PAYLOAD_BYTES, MAX_UDP_PACKET_BYTES, NONCE_DOMAIN_APP,
    },
    protocol::Control,
    security::RateLimiter,
    state::MetricsCollector,
    transport::Connection,
};
use bincode::Options;
use rand::RngCore;
use std::sync::Arc;
use tokio::sync::mpsc;

type TaskError = Box<dyn std::error::Error + Send + Sync + 'static>;
type TaskResult<T> = std::result::Result<T, TaskError>;

fn is_valid_app_role(role: u8) -> bool {
    matches!(role, 0x01 | 0x02)
}

fn deserialize_control_limited(data: &[u8]) -> Result<Control, bincode::Error> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(MAX_CLEAR_PAYLOAD_BYTES as u64)
        .deserialize::<Control>(data)
}

#[allow(clippy::too_many_arguments)]
async fn maybe_rotate_udp(
    nonce_seq: &mut NonceSeq,
    rotation_policy: &KeyRotationPolicy,
    cipher_state: &Arc<tokio::sync::RwLock<SessionKeyState>>,
    connection: &Connection,
    tag16: u16,
    tag8: u8,
    sent_count: &mut u64,
    last_rotate_ms: &mut u64,
    pending_key_id: &mut Option<u64>,
    pending_key: &mut [u8; 32],
    pending_next_retry_ms: &mut u64,
    pending_retries_left: &mut u8,
    app_role: u8,
) -> TaskResult<()> {
    if !rotation_policy.enabled() {
        return Ok(());
    }
    let now = now_ms();
    if let Some(pending_id) = *pending_key_id {
        let acked = {
            let guard = cipher_state.read().await;
            guard.last_ack_id() == Some(pending_id)
        };
        if acked {
            *pending_key_id = None;
            *pending_retries_left = 0;
        } else if *pending_retries_left > 0 && now >= *pending_next_retry_ms {
            let ctrl = Control::SessionKey(*pending_key);
            let payload_bytes = bincode::serialize(&ctrl)?;
            let (nonce, seq) = nonce_seq.next_nonce_and_seq()?;
            let clear = ClearPayload {
                ts_ms: now_ms(),
                seq,
                data: payload_bytes,
            };
            let current_key = {
                let guard = cipher_state.read().await;
                *guard.current_key()
            };
            let pkt = seal_with_nonce(&current_key, tag16, tag8, &clear, &nonce)?;
            let raw_bytes = serialize_cipher_packet(&pkt)?;
            let sock = match connection.get_socket() {
                Some(s) => s,
                None => return Ok(()),
            };
            let remote_addr = match &connection {
                Connection::Lan(_, peer) => *peer,
                Connection::Wan(_, addr) => *addr,
                _ => return Ok(()),
            };
            let _ = sock.send_to(&raw_bytes, remote_addr).await;
            *pending_retries_left = pending_retries_left.saturating_sub(1);
            *pending_next_retry_ms = now.saturating_add(500);
        }
        return Ok(());
    }
    let time_due = rotation_policy.interval_ms > 0
        && now.saturating_sub(*last_rotate_ms) >= rotation_policy.interval_ms;
    let count_due = rotation_policy.max_messages > 0 && *sent_count >= rotation_policy.max_messages;
    if !time_due && !count_due {
        return Ok(());
    }

    let mut new_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut new_key);
    let key_id = key_id_from_key(&new_key);
    let ctrl = Control::SessionKey(new_key);
    let payload_bytes = bincode::serialize(&ctrl)?;

    let (nonce, seq) = nonce_seq.next_nonce_and_seq()?;
    let clear = ClearPayload {
        ts_ms: now_ms(),
        seq,
        data: payload_bytes,
    };

    let current_key = {
        let guard = cipher_state.read().await;
        *guard.current_key()
    };

    let pkt = seal_with_nonce(&current_key, tag16, tag8, &clear, &nonce)?;
    let raw_bytes = serialize_cipher_packet(&pkt)?;

    let sock = match connection.get_socket() {
        Some(s) => s,
        None => return Ok(()),
    };
    let remote_addr = match &connection {
        Connection::Lan(_, peer) => *peer,
        Connection::Wan(_, addr) => *addr,
        _ => return Ok(()),
    };
    sock.send_to(&raw_bytes, remote_addr).await?;

    {
        let mut guard = cipher_state.write().await;
        guard.rotate_to(new_key);
    }

    *nonce_seq = NonceSeq::new(&new_key, NONCE_DOMAIN_APP, app_role)?;
    *sent_count = 0;
    *last_rotate_ms = now;
    *pending_key_id = Some(key_id);
    *pending_key = new_key;
    *pending_retries_left = 2;
    *pending_next_retry_ms = now.saturating_add(500);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn maybe_rotate_io(
    nonce_seq: &mut NonceSeq,
    rotation_policy: &KeyRotationPolicy,
    cipher_state: &Arc<tokio::sync::RwLock<SessionKeyState>>,
    io: &Arc<dyn TransportIo>,
    tag16: u16,
    tag8: u8,
    metrics: &MetricsCollector,
    sent_count: &mut u64,
    last_rotate_ms: &mut u64,
    pending_key_id: &mut Option<u64>,
    pending_key: &mut [u8; 32],
    pending_next_retry_ms: &mut u64,
    pending_retries_left: &mut u8,
    app_role: u8,
) -> TaskResult<()> {
    if !rotation_policy.enabled() {
        return Ok(());
    }
    let now = now_ms();
    if let Some(pending_id) = *pending_key_id {
        let acked = {
            let guard = cipher_state.read().await;
            guard.last_ack_id() == Some(pending_id)
        };
        if acked {
            *pending_key_id = None;
            *pending_retries_left = 0;
        } else if *pending_retries_left > 0 && now >= *pending_next_retry_ms {
            let ctrl = Control::SessionKey(*pending_key);
            let payload_bytes = bincode::serialize(&ctrl)?;
            let (nonce, seq) = nonce_seq.next_nonce_and_seq()?;
            let clear = ClearPayload {
                ts_ms: now_ms(),
                seq,
                data: payload_bytes,
            };
            let current_key = {
                let guard = cipher_state.read().await;
                *guard.current_key()
            };
            let pkt = seal_with_nonce(&current_key, tag16, tag8, &clear, &nonce)?;
            let raw_bytes = serialize_cipher_packet(&pkt)?;
            let _ = io.send(raw_bytes).await;
            *pending_retries_left = pending_retries_left.saturating_sub(1);
            *pending_next_retry_ms = now.saturating_add(500);
        }
        return Ok(());
    }
    let time_due = rotation_policy.interval_ms > 0
        && now.saturating_sub(*last_rotate_ms) >= rotation_policy.interval_ms;
    let count_due = rotation_policy.max_messages > 0 && *sent_count >= rotation_policy.max_messages;
    if !time_due && !count_due {
        return Ok(());
    }

    let mut new_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut new_key);
    let key_id = key_id_from_key(&new_key);
    let ctrl = Control::SessionKey(new_key);
    let payload_bytes = bincode::serialize(&ctrl)?;

    let (nonce, seq) = nonce_seq.next_nonce_and_seq()?;
    let clear = ClearPayload {
        ts_ms: now_ms(),
        seq,
        data: payload_bytes,
    };

    let current_key = {
        let guard = cipher_state.read().await;
        *guard.current_key()
    };

    let pkt = seal_with_nonce(&current_key, tag16, tag8, &clear, &nonce)?;
    let raw_bytes = serialize_cipher_packet(&pkt)?;

    let len = raw_bytes.len();
    io.send(raw_bytes).await?;
    metrics.record_packet_sent(len).await;

    {
        let mut guard = cipher_state.write().await;
        guard.rotate_to(new_key);
    }

    *nonce_seq = NonceSeq::new(&new_key, NONCE_DOMAIN_APP, app_role)?;
    *sent_count = 0;
    *last_rotate_ms = now;
    *pending_key_id = Some(key_id);
    *pending_key = new_key;
    *pending_retries_left = 2;
    *pending_next_retry_ms = now.saturating_add(500);
    Ok(())
}

/// Task di ricezione con shutdown channel
pub async fn spawn_receiver_task_with_stop(
    connection: Connection,
    streams: Streams,
    cipher_state: Arc<tokio::sync::RwLock<SessionKeyState>>,
    rate_limiter: RateLimiter,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    if connection.is_stream() {
        let io = Arc::new(ConnectionIo::new(connection));
        return spawn_receiver_task_with_stop_io(io, streams, cipher_state, rate_limiter, stop)
            .await;
    }

    tokio::spawn(async move {
        let (tag16, tag8) = {
            let guard = cipher_state.read().await;
            (guard.tag16(), guard.tag8())
        };
        let sock = match connection.get_socket() {
            Some(s) => s,
            None => return,
        };
        let mut buf = vec![0u8; UDP_MAX_PACKET_SIZE];
        let mut rw = crate::crypto::replay::ReplayWindow::new();

        loop {
            tokio::select! {
                _ = stop.changed() => {
                    tracing::info!("Receiver task stopping");
                    break;
                },
                result = sock.recv_from(&mut buf) => {
                    match result {
                        Ok((n, source)) => {
                            // 1. Early drop by tag
                            if crate::security::early_drop_packet(&buf[..n], tag16, tag8) {
                                continue;
                            }
                            // 2. Rate limit
                            if !rate_limiter.check(source).await {
                                tracing::warn!("Rate limit exceeded for {}", source);
                                continue;
                            }
                            // 3. Process packet
                            if let Ok(cipher_packet) = deserialize_cipher_packet_with_limit(&buf[..n], MAX_UDP_PACKET_BYTES) {
                                let clear_payload = {
                                    let mut guard = cipher_state.write().await;
                                    guard.open_packet(&cipher_packet)
                                };
                                if let Some(clear_payload) = clear_payload {
                                    match rw.accept_classified(clear_payload.seq) {
                                        crate::crypto::replay::ReplayDecision::Accepted => {
                                        // Handle Control Packet
                                        if let Ok(ctrl) = deserialize_control_limited(&clear_payload.data) {
                                            match ctrl {
                                                Control::App(msg) => {
                                                     if streams.tx.send(msg).await.is_err() {
                                                         break;
                                                     }
                                                },
                                                Control::NoiseHandshake(_) => {
                                                    // Ignore post-handshake noise messages
                                                }
                                                Control::SessionKey(new_key) => {
                                                    let key_id = key_id_from_key(&new_key);
                                                    {
                                                        let mut guard = cipher_state.write().await;
                                                        guard.rotate_to(new_key);
                                                    }
                                                    // Send ack best-effort using the new key.
                                                    let mut ack_nonce_seq = match NonceSeq::new(
                                                        &new_key,
                                                        NONCE_DOMAIN_APP,
                                                        0x03,
                                                    ) {
                                                        Ok(ns) => ns,
                                                        Err(e) => {
                                                            tracing::warn!(
                                                                "Ack nonce seq re-init failed: {:?}",
                                                                e
                                                            );
                                                            continue;
                                                        }
                                                    };
                                                    let ctrl = Control::SessionKeyAck(key_id);
                                                    if let Ok(payload_bytes) = bincode::serialize(&ctrl) {
                                                        if let Ok((nonce, seq)) =
                                                            ack_nonce_seq.next_nonce_and_seq()
                                                        {
                                                            let clear = ClearPayload {
                                                                ts_ms: now_ms(),
                                                                seq,
                                                                data: payload_bytes,
                                                            };
                                                            let pkt = {
                                                                let guard = cipher_state.read().await;
                                                                seal_with_nonce(
                                                                    guard.current_key(),
                                                                    tag16,
                                                                    tag8,
                                                                    &clear,
                                                                    &nonce,
                                                                )
                                                            };
                                                            if let Ok(pkt) = pkt {
                                                                if let Ok(raw) =
                                                                    serialize_cipher_packet(&pkt)
                                                                {
                                                                    let _ = sock.send_to(&raw, source).await;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                Control::SessionKeyAck(ack_id) => {
                                                    let mut guard = cipher_state.write().await;
                                                    guard.set_ack_id(ack_id);
                                                }
                                                Control::ResumeHello { .. } => {
                                                    // Ignore resume messages on app channel
                                                }
                                                Control::ResumeAccept { .. } => {
                                                    // Ignore resume messages on app channel
                                                }
                                                Control::AssistRequest(_) => {
                                                    // Ignore assist control on app channel
                                                }
                                                Control::AssistGo(_) => {
                                                    // Ignore assist control on app channel
                                                }
                                                Control::AssistRequestV5(_) => {
                                                    // Ignore assist control on app channel
                                                }
                                                Control::AssistGoV5(_) => {
                                                    // Ignore assist control on app channel
                                                }
                                            }
                                        }
                                        }
                                        crate::crypto::replay::ReplayDecision::Replay => {}
                                        crate::crypto::replay::ReplayDecision::Overflow => {
                                            tracing::warn!(
                                                "Replay window overflow detected on UDP receiver; resetting replay window"
                                            );
                                            let _ = rw.recover_after_overflow(clear_payload.seq);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("RX error: {:?}", e);
                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
    })
}

/// Task di ricezione con shutdown channel per TransportIo (Guaranteed)
pub async fn spawn_receiver_task_with_stop_io(
    io: Arc<dyn TransportIo>,
    streams: Streams,
    cipher_state: Arc<tokio::sync::RwLock<SessionKeyState>>,
    rate_limiter: RateLimiter,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (tag16, tag8) = {
            let guard = cipher_state.read().await;
            (guard.tag16(), guard.tag8())
        };
        let mut rw = crate::crypto::replay::ReplayWindow::new();
        let relay_addr = io.rate_limit_addr();
        let limit = io.max_packet_limit();

        loop {
            tokio::select! {
                _ = stop.changed() => {
                    tracing::info!("Receiver task stopping");
                    break;
                },
                result = io.recv() => {
                    match result {
                        Ok(bytes) => {
                            if bytes.is_empty() {
                                continue;
                            }
                            if crate::security::early_drop_packet(&bytes, tag16, tag8) {
                                continue;
                            }
                            if !rate_limiter.check(relay_addr).await {
                                tracing::warn!("Rate limit exceeded for relay stream ({})", relay_addr);
                                continue;
                            }
                            if let Ok(cipher_packet) = deserialize_cipher_packet_with_limit(&bytes, limit) {
                                let clear_payload = {
                                    let mut guard = cipher_state.write().await;
                                    guard.open_packet(&cipher_packet)
                                };
                                if let Some(clear_payload) = clear_payload {
                                    match rw.accept_classified(clear_payload.seq) {
                                        crate::crypto::replay::ReplayDecision::Accepted => {
                                        if let Ok(ctrl) = deserialize_control_limited(&clear_payload.data) {
                                            match ctrl {
                                                Control::App(msg) => {
                                                    if streams.tx.send(msg).await.is_err() {
                                                        break;
                                                    }
                                                },
                                                Control::NoiseHandshake(_) => {}
                                                Control::SessionKey(new_key) => {
                                                    let key_id = key_id_from_key(&new_key);
                                                    {
                                                        let mut guard = cipher_state.write().await;
                                                        guard.rotate_to(new_key);
                                                    }
                                                    let mut ack_nonce_seq = match NonceSeq::new(
                                                        &new_key,
                                                        NONCE_DOMAIN_APP,
                                                        0x03,
                                                    ) {
                                                        Ok(ns) => ns,
                                                        Err(e) => {
                                                            tracing::warn!(
                                                                "Ack nonce seq re-init failed: {:?}",
                                                                e
                                                            );
                                                            continue;
                                                        }
                                                    };
                                                    let ctrl = Control::SessionKeyAck(key_id);
                                                    if let Ok(payload_bytes) = bincode::serialize(&ctrl) {
                                                        if let Ok((nonce, seq)) =
                                                            ack_nonce_seq.next_nonce_and_seq()
                                                        {
                                                            let clear = ClearPayload {
                                                                ts_ms: now_ms(),
                                                                seq,
                                                                data: payload_bytes,
                                                            };
                                                            let pkt = {
                                                                let guard = cipher_state.read().await;
                                                                seal_with_nonce(
                                                                    guard.current_key(),
                                                                    tag16,
                                                                    tag8,
                                                                    &clear,
                                                                    &nonce,
                                                                )
                                                            };
                                                            if let Ok(pkt) = pkt {
                                                                if let Ok(raw) =
                                                                    serialize_cipher_packet(&pkt)
                                                                {
                                                                    let _ = io.send(raw).await;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                Control::SessionKeyAck(ack_id) => {
                                                    let mut guard = cipher_state.write().await;
                                                    guard.set_ack_id(ack_id);
                                                }
                                                Control::ResumeHello { .. } => {}
                                                Control::ResumeAccept { .. } => {}
                                                Control::AssistRequest(_) => {}
                                                Control::AssistGo(_) => {}
                                                Control::AssistRequestV5(_) => {}
                                                Control::AssistGoV5(_) => {}
                                            }
                                        }
                                        }
                                        crate::crypto::replay::ReplayDecision::Replay => {}
                                        crate::crypto::replay::ReplayDecision::Overflow => {
                                            tracing::warn!(
                                                "Replay window overflow detected on guaranteed receiver; resetting replay window"
                                            );
                                            let _ = rw.recover_after_overflow(clear_payload.seq);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("RX error: {:?}", e);
                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
    })
}

/// Task di invio con shutdown channel + metriche + Session Encryption
pub async fn spawn_sender_task_with_stop(
    connection: Connection,
    rx_out: mpsc::Receiver<Vec<u8>>,
    stop: tokio::sync::watch::Receiver<bool>,
    metrics: MetricsCollector,
    cipher_state: Arc<tokio::sync::RwLock<SessionKeyState>>,
    rotation_policy: KeyRotationPolicy,
    app_role: u8,
) -> tokio::task::JoinHandle<()> {
    if connection.is_stream() {
        let io = Arc::new(ConnectionIo::new(connection));
        return spawn_sender_task_with_stop_io(
            io,
            rx_out,
            stop,
            metrics,
            cipher_state,
            rotation_policy,
            app_role,
        )
        .await;
    }

    tokio::spawn(async move {
        let mut rx_out = rx_out;
        let mut stop = stop;
        let (tag16, tag8) = {
            let guard = cipher_state.read().await;
            (guard.tag16(), guard.tag8())
        };
        debug_assert!(is_valid_app_role(app_role));
        let nonce_init = {
            let guard = cipher_state.read().await;
            NonceSeq::new(guard.current_key(), NONCE_DOMAIN_APP, app_role)
        };
        let mut nonce_seq = match nonce_init {
            Ok(ns) => ns,
            Err(e) => {
                tracing::error!("Nonce sequence init failed: {:?}", e);
                return;
            }
        };
        let mut sent_count: u64 = 0;
        let mut last_rotate_ms: u64 = now_ms();
        let mut pending_key_id: Option<u64> = None;
        let mut pending_key: [u8; 32] = [0u8; 32];
        let mut pending_next_retry_ms: u64 = 0;
        let mut pending_retries_left: u8 = 0;

        loop {
            tokio::select! {
                _ = stop.changed() => {
                    tracing::info!("Sender task stopping");
                    break;
                },
                maybe = rx_out.recv() => {
                    if let Some(data) = maybe {
                        if let Err(e) = maybe_rotate_udp(
                            &mut nonce_seq,
                            &rotation_policy,
                            &cipher_state,
                            &connection,
                            tag16,
                            tag8,
                            &mut sent_count,
                            &mut last_rotate_ms,
                            &mut pending_key_id,
                            &mut pending_key,
                            &mut pending_next_retry_ms,
                            &mut pending_retries_left,
                            app_role,
                        )
                        .await
                        {
                            tracing::warn!("Key rotation failed: {:?}", e);
                        }
                        // 1. Wrap in Control::App
                        let ctrl = Control::App(data);
                        let payload_bytes = match bincode::serialize(&ctrl) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };

                        // 2. Encrypt with session key
                        let (nonce, seq) = match nonce_seq.next_nonce_and_seq() {
                            Ok(result) => result,
                            Err(e) => {
                                tracing::error!("Nonce generation failed: {:?}", e);
                                continue;
                            }
                        };
                        let clear = ClearPayload {
                            ts_ms: now_ms(),
                            seq,
                            data: payload_bytes,
                        };

                        let key_enc = {
                            let guard = cipher_state.read().await;
                            *guard.current_key()
                        };
                        let pkt = match seal_with_nonce(&key_enc, tag16, tag8, &clear, &nonce) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                        let raw_bytes = match serialize_cipher_packet(&pkt) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };

                        // 3. Send
                        let sock = match connection.get_socket() {
                            Some(s) => s,
                            None => break,
                        };
                        let remote_addr = match &connection {
                            Connection::Lan(_, peer) => *peer,
                            Connection::Wan(_, addr) => *addr,
                            _ => break,
                        };
                        match sock.send_to(&raw_bytes, remote_addr).await {
                            Ok(sent) => {
                                metrics.record_packet_sent(sent).await;
                                tracing::debug!("Sent {} bytes", sent);
                                sent_count = sent_count.saturating_add(1);
                            }
                            Err(e) => {
                                metrics.record_connection_error().await;
                                tracing::error!("TX error: {:?}", e);
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
        }
        tracing::debug!("Sender task terminated");
    })
}

/// Task di invio con shutdown channel + metriche per TransportIo (Guaranteed)
pub async fn spawn_sender_task_with_stop_io(
    io: Arc<dyn TransportIo>,
    rx_out: mpsc::Receiver<Vec<u8>>,
    stop: tokio::sync::watch::Receiver<bool>,
    metrics: MetricsCollector,
    cipher_state: Arc<tokio::sync::RwLock<SessionKeyState>>,
    rotation_policy: KeyRotationPolicy,
    app_role: u8,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut rx_out = rx_out;
        let mut stop = stop;
        let (tag16, tag8) = {
            let guard = cipher_state.read().await;
            (guard.tag16(), guard.tag8())
        };
        debug_assert!(is_valid_app_role(app_role));
        let nonce_init = {
            let guard = cipher_state.read().await;
            NonceSeq::new(guard.current_key(), NONCE_DOMAIN_APP, app_role)
        };
        let mut nonce_seq = match nonce_init {
            Ok(ns) => ns,
            Err(e) => {
                tracing::error!("Nonce sequence init failed: {:?}", e);
                return;
            }
        };
        let mut sent_count: u64 = 0;
        let mut last_rotate_ms: u64 = now_ms();
        let mut pending_key_id: Option<u64> = None;
        let mut pending_key: [u8; 32] = [0u8; 32];
        let mut pending_next_retry_ms: u64 = 0;
        let mut pending_retries_left: u8 = 0;

        loop {
            tokio::select! {
                _ = stop.changed() => {
                    tracing::info!("Sender task stopping");
                    break;
                },
                maybe = rx_out.recv() => {
                    if let Some(data) = maybe {
                        if let Err(e) = maybe_rotate_io(
                            &mut nonce_seq,
                            &rotation_policy,
                            &cipher_state,
                            &io,
                            tag16,
                            tag8,
                            &metrics,
                            &mut sent_count,
                            &mut last_rotate_ms,
                            &mut pending_key_id,
                            &mut pending_key,
                            &mut pending_next_retry_ms,
                            &mut pending_retries_left,
                            app_role,
                        )
                        .await
                        {
                            tracing::warn!("Key rotation failed: {:?}", e);
                        }
                        let ctrl = Control::App(data);
                        let payload_bytes = match bincode::serialize(&ctrl) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };

                        let (nonce, seq) = match nonce_seq.next_nonce_and_seq() {
                            Ok(result) => result,
                            Err(e) => {
                                tracing::error!("Nonce generation failed: {:?}", e);
                                continue;
                            }
                        };
                        let clear = ClearPayload {
                            ts_ms: now_ms(),
                            seq,
                            data: payload_bytes,
                        };

                        let key_enc = {
                            let guard = cipher_state.read().await;
                            *guard.current_key()
                        };
                        let pkt = match seal_with_nonce(&key_enc, tag16, tag8, &clear, &nonce) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                        let raw_bytes = match serialize_cipher_packet(&pkt) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };

                        let len = raw_bytes.len();
                        match io.send(raw_bytes).await {
                            Ok(()) => {
                                metrics.record_packet_sent(len).await;
                                tracing::debug!("Sent {} bytes (Guaranteed)", len);
                                sent_count = sent_count.saturating_add(1);
                            }
                            Err(e) => {
                                metrics.record_connection_error().await;
                                tracing::error!("TX error: {:?}", e);
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
        }
        tracing::debug!("Sender task terminated");
    })
}

// Deprecated V1 and test tasks removed for brevity/safety - users should rely on secure task

#[cfg(test)]
mod tests {
    use super::is_valid_app_role;

    #[test]
    fn test_app_role_is_binary_choice() {
        assert!(is_valid_app_role(0x01));
        assert!(is_valid_app_role(0x02));
        assert!(!is_valid_app_role(0x00));
        assert!(!is_valid_app_role(0x03));
        assert!(!is_valid_app_role(0xff));
    }
}
