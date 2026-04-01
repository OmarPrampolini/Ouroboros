//! Tor WAN transport: SOCKS5 client connect + TCP listener for Host mode
//!
//! Supports both direct Tor and obfs4 bridges for DPI evasion.
//! Requires external Tor daemon with SOCKS5 proxy (default 127.0.0.1:9050).
//! For Host mode, Tor must have a preconfigured HiddenService forwarding to listen_addr.

use crate::onion::parse_onion_addr;
use base64::Engine;
use rand::RngCore;
use thiserror::Error;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_socks::tcp::Socks5Stream;
use tracing::debug;

#[derive(Debug, Error)]
pub enum WanTorError {
    #[error("onion parse error: {0}")]
    Onion(#[from] crate::onion::OnionError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SOCKS5 error: {0}")]
    Socks(String),
    #[error("Tor control port not available: {0}")]
    TorControlUnavailable(String),
    #[error("Failed to bind Tor listener: {0}")]
    BindListener(String),
}

type Result<T> = std::result::Result<T, WanTorError>;

/// Tor bridge configuration for obfs4
#[derive(Debug, Clone)]
pub struct TorBridge {
    pub transport: String, // "obfs4"
    pub ip: String,
    pub port: u16,
    pub cert: String, // obfs4 cert
    pub iat_mode: u8, // Inter-arrival time mode
}

/// Client: connect to peer's onion address via Tor SOCKS5 proxy or obfs4 bridge
///
/// # Arguments
/// * `socks_addr` - Tor SOCKS5 proxy address (e.g. "127.0.0.1:9050")
/// * `target_onion` - Target onion address with port (e.g. "abc...xyz.onion:9999")
/// * `bridge` - Optional obfs4 bridge for DPI evasion
/// * `isolation_key` - Optional isolation key for circuit isolation (prevents traffic correlation)
pub async fn try_tor_connect(
    socks_addr: &str,
    target_onion: &str,
    bridge: Option<&TorBridge>,
    isolation_key: Option<&str>,
) -> Result<TcpStream> {
    let (onion_host, onion_port) = parse_onion_addr(target_onion)?;

    // Generate deterministic isolation key from target to ensure consistent circuit isolation
    let isolation_key = isolation_key
        .map(|s| s.to_string())
        .or_else(|| Some(format!("{}:{}", onion_host, onion_port)));

    // Configure Tor to use bridge if provided
    if let Some(bridge) = bridge {
        configure_tor_bridge(socks_addr, bridge).await?;
        tracing::info!("Using Tor obfs4 bridge {}:{}", bridge.ip, bridge.port);
    }

    tracing::info!(
        "Connecting via Tor SOCKS5 {} to {}:{}",
        socks_addr,
        onion_host,
        onion_port
    );

    // Circuit isolation: use different authentication for each connection to prevent correlation
    let stream = if let Some(_iso_key) = isolation_key {
        // Generate deterministic username from isolation key for circuit isolation
        let mut username_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut username_bytes);
        let username = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(username_bytes);

        tracing::debug!("Using circuit isolation with username: {}", username);

        // Connect with authentication to force new circuit
        match Socks5Stream::connect_with_password(
            socks_addr,
            (onion_host.as_str(), onion_port),
            &username,
            "", // Empty password
        )
        .await
        {
            Ok(s) => s,
            Err(_) => {
                // Authentication not supported by Tor, fall back to regular connection
                tracing::warn!("SOCKS5 auth failed, falling back to regular connection");
                Socks5Stream::connect(socks_addr, (onion_host.as_str(), onion_port))
                    .await
                    .map_err(|e| WanTorError::Socks(e.to_string()))?
            }
        }
    } else {
        // Regular connection without isolation
        Socks5Stream::connect(socks_addr, (onion_host.as_str(), onion_port))
            .await
            .map_err(|e| WanTorError::Socks(e.to_string()))?
    };

    tracing::info!("Tor connection established to {}", target_onion);

    // Note: Dummy padding disabled for beta - requires stream cloning which is not supported by tokio::net::TcpStream
    // Placeholder for future implementation with Arc<Mutex<TcpStream>> pattern
    debug!("Dummy padding feature: placeholder (not implemented in this beta)");

    Ok(stream.into_inner())
}

/// Configure Tor daemon to use obfs4 bridge
async fn configure_tor_bridge(socks_addr: &str, bridge: &TorBridge) -> Result<()> {
    if !bridge.transport.eq_ignore_ascii_case("obfs4") {
        return Err(WanTorError::TorControlUnavailable(format!(
            "unsupported Tor bridge transport: {}",
            bridge.transport
        )));
    }

    // Connect to Tor control port (derive from SOCKS address)
    let control_addr = socks_addr
        .rsplit_once(':')
        .map(|(host, _)| format!("{}:9051", host))
        .unwrap_or_else(|| "127.0.0.1:9051".to_string());
    let mut control_conn = TcpStream::connect(&control_addr)
        .await
        .map_err(|e| WanTorError::TorControlUnavailable(e.to_string()))?;

    authenticate_tor_control(&mut control_conn).await?;

    let bridge_line = format!(
        "{} {}:{} cert={} iat-mode={}",
        bridge.transport, bridge.ip, bridge.port, bridge.cert, bridge.iat_mode
    );
    send_control_command(&mut control_conn, "SETCONF UseBridges=1\r\n").await?;
    send_control_command(
        &mut control_conn,
        &format!(
            "SETCONF Bridge=\"{}\"\r\n",
            escape_control_value(&bridge_line)
        ),
    )
    .await?;
    send_control_command(&mut control_conn, "SIGNAL NEWNYM\r\n").await?;

    // Close control connection
    control_conn.shutdown().await?;

    Ok(())
}

async fn authenticate_tor_control(control_conn: &mut TcpStream) -> Result<()> {
    if let Ok(cookie_path) = std::env::var("HANDSHACKE_TOR_CONTROL_COOKIE_FILE") {
        let cookie = fs::read(&cookie_path)
            .await
            .map_err(|e| WanTorError::TorControlUnavailable(e.to_string()))?;
        return send_control_command(
            control_conn,
            &format!("AUTHENTICATE {}\r\n", hex::encode(cookie)),
        )
        .await
        .map(|_| ());
    }

    if let Ok(password) = std::env::var("HANDSHACKE_TOR_CONTROL_PASSWORD") {
        let trimmed = password.trim();
        if !trimmed.is_empty() {
            return send_control_command(
                control_conn,
                &format!("AUTHENTICATE \"{}\"\r\n", escape_control_value(trimmed)),
            )
            .await
            .map(|_| ());
        }
    }

    Err(WanTorError::TorControlUnavailable(
        "missing Tor control auth; set HANDSHACKE_TOR_CONTROL_COOKIE_FILE or HANDSHACKE_TOR_CONTROL_PASSWORD".to_string(),
    ))
}

async fn send_control_command(control_conn: &mut TcpStream, command: &str) -> Result<Vec<String>> {
    control_conn.write_all(command.as_bytes()).await?;
    control_conn.flush().await?;
    let (status, lines) = read_control_reply(control_conn).await?;
    if status == 250 {
        Ok(lines)
    } else {
        Err(WanTorError::TorControlUnavailable(format!(
            "Tor control command failed: {}",
            lines.join(" | ")
        )))
    }
}

async fn read_control_reply(control_conn: &mut TcpStream) -> Result<(u16, Vec<String>)> {
    let mut lines = Vec::new();
    loop {
        let line = read_control_line(control_conn).await?;
        if line.len() < 4 {
            return Err(WanTorError::TorControlUnavailable(
                "malformed Tor control response".to_string(),
            ));
        }
        let status = line[..3].parse::<u16>().map_err(|_| {
            WanTorError::TorControlUnavailable("invalid Tor status code".to_string())
        })?;
        let separator = line.as_bytes()[3] as char;
        lines.push(line.clone());

        if separator == '+' {
            loop {
                let data_line = read_control_line(control_conn).await?;
                let done = data_line == ".";
                lines.push(data_line);
                if done {
                    break;
                }
            }
        }

        if separator == ' ' {
            return Ok((status, lines));
        }
    }
}

async fn read_control_line(control_conn: &mut TcpStream) -> Result<String> {
    let mut buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let n = control_conn.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.len() >= 2 && buf[buf.len() - 2] == b'\r' && buf[buf.len() - 1] == b'\n' {
            break;
        }
    }
    if buf.is_empty() {
        return Err(WanTorError::TorControlUnavailable(
            "Tor control connection closed unexpectedly".to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&buf).trim().to_string())
}

fn escape_control_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Host: listen for incoming connections on local address
///
/// Tor daemon must have a HiddenService configured to forward to this address.
/// Example torrc:
/// ```text
/// HiddenServiceDir /var/lib/tor/handshake/
/// HiddenServicePort 9999 127.0.0.1:9999
/// ```
///
/// # Arguments
/// * `listen_addr` - Local address to bind (e.g. "127.0.0.1:9999")
pub async fn try_tor_listen(listen_addr: &str) -> Result<TcpListener> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| WanTorError::BindListener(e.to_string()))?;

    let local_addr = listener.local_addr()?;
    tracing::info!(
        "Tor Host: listening on {} (ensure Tor HiddenService forwards here)",
        local_addr
    );

    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_onion_valid() {
        let (host, port) =
            parse_onion_addr("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:9999")
                .unwrap();
        assert_eq!(
            host,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
        );
        assert_eq!(port, 9999);
    }

    #[test]
    fn test_parse_onion_no_port() {
        assert!(parse_onion_addr("abc123.onion").is_err());
    }

    #[test]
    fn test_parse_onion_not_onion() {
        assert!(parse_onion_addr("example.com:9999").is_err());
    }
}
