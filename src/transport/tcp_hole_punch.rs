//! TCP Hole Punching implementation
//!
//! Provides TCP-based hole punching for NATs that block UDP.
//! Requires NAT with long TCP timeout and support for simultaneous open.

use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use thiserror::Error;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

#[derive(Debug, Error)]
pub enum TcpHolePunchError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("create TCP socket v6: {0}")]
    CreateSocketV6(String),
    #[error("create TCP socket v4: {0}")]
    CreateSocketV4(String),
    #[error("set SO_REUSEADDR: {0}")]
    SetReuseAddr(String),
    #[error("bind to local address: {0}")]
    BindLocal(String),
    #[error("TCP connection failed: {0}")]
    ConnectionFailed(String),
    #[error("TCP connection timeout")]
    ConnectionTimeout,
    #[error("Both sides failed: {0} and {1}")]
    BothSidesFailed(String, String),
    #[error("TCP hole punching attempts exhausted after {attempts} tries: {last_error}")]
    AttemptsExhausted { attempts: u8, last_error: String },
}

type Result<T> = std::result::Result<T, TcpHolePunchError>;

#[derive(Debug, Clone, Copy)]
pub struct TcpPunchPlan {
    pub attempts: u8,
    pub min_attempt_timeout_ms: u64,
    pub max_attempt_timeout_ms: u64,
    pub base_interval_ms: u64,
    pub max_interval_ms: u64,
    pub jitter_ms: u64,
}

impl Default for TcpPunchPlan {
    fn default() -> Self {
        // P0-safe defaults: aggressive enough for hostile WAN, bounded to avoid SYN flood-like behavior.
        Self {
            attempts: 5,
            min_attempt_timeout_ms: 1200,
            max_attempt_timeout_ms: 5000,
            base_interval_ms: 120,
            max_interval_ms: 600,
            jitter_ms: 60,
        }
    }
}

/// TCP Hole Punching implementation
pub struct TcpHolePunch;

impl TcpHolePunch {
    /// Attempt TCP hole punching between local and remote addresses with adaptive retries.
    pub async fn punch(local: SocketAddr, remote: SocketAddr) -> Result<TcpStream> {
        Self::punch_with_plan(local, remote, TcpPunchPlan::default()).await
    }

    /// Adaptive TCP hole punching strategy with deterministic jitter/backoff.
    pub async fn punch_with_plan(
        local: SocketAddr,
        remote: SocketAddr,
        plan: TcpPunchPlan,
    ) -> Result<TcpStream> {
        let attempts = plan.attempts.max(1);
        info!(
            "Attempting TCP hole punching {} -> {} (attempts={})",
            local, remote, attempts
        );

        let mut last_error = String::from("unknown");

        for attempt in 0..attempts {
            let timeout_ms = Self::attempt_timeout_ms(plan, attempt);
            match Self::punch_once(local, remote, Duration::from_millis(timeout_ms)).await {
                Ok(stream) => {
                    info!(
                        "TCP hole punching successful on attempt {}/{}",
                        attempt + 1,
                        attempts
                    );
                    return Ok(stream);
                }
                Err(e) => {
                    last_error = e.to_string();
                    let is_last = attempt + 1 >= attempts;
                    if is_last {
                        break;
                    }

                    let sleep_ms = Self::attempt_interval_ms(plan, local, remote, attempt);
                    warn!(
                        "TCP hole punch attempt {}/{} failed: {}. retrying in {}ms",
                        attempt + 1,
                        attempts,
                        last_error,
                        sleep_ms
                    );
                    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                }
            }
        }

        Err(TcpHolePunchError::AttemptsExhausted {
            attempts,
            last_error,
        })
    }

    async fn punch_once(
        local: SocketAddr,
        remote: SocketAddr,
        timeout_duration: Duration,
    ) -> Result<TcpStream> {
        // Create TCP socket with SO_REUSEADDR
        let socket = if local.is_ipv6() || remote.is_ipv6() {
            TcpSocket::new_v6().map_err(|e| TcpHolePunchError::CreateSocketV6(e.to_string()))?
        } else {
            TcpSocket::new_v4().map_err(|e| TcpHolePunchError::CreateSocketV4(e.to_string()))?
        };

        // Enable SO_REUSEADDR to allow bind to specific port
        socket
            .set_reuseaddr(true)
            .map_err(|e| TcpHolePunchError::SetReuseAddr(e.to_string()))?;

        // Try to enable TCP_FASTOPEN if available
        #[cfg(target_os = "linux")]
        Self::enable_tcp_fastopen(&socket)?;

        // Bind to specific local address (required for hole punching)
        socket
            .bind(local)
            .map_err(|e| TcpHolePunchError::BindLocal(e.to_string()))?;

        let connect_future = socket.connect(remote);
        match timeout(timeout_duration, connect_future).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(TcpHolePunchError::ConnectionFailed(e.to_string())),
            Err(_) => Err(TcpHolePunchError::ConnectionTimeout),
        }
    }

    fn attempt_timeout_ms(plan: TcpPunchPlan, attempt: u8) -> u64 {
        let exp = (attempt as u32).min(6);
        let scaled = plan
            .min_attempt_timeout_ms
            .saturating_mul(1u64 << exp)
            .max(1);
        scaled.min(plan.max_attempt_timeout_ms.max(1))
    }

    fn attempt_interval_ms(
        plan: TcpPunchPlan,
        local: SocketAddr,
        remote: SocketAddr,
        attempt: u8,
    ) -> u64 {
        let exp = (attempt as u32).min(6);
        let base = plan
            .base_interval_ms
            .saturating_mul(1u64 << exp)
            .max(1)
            .min(plan.max_interval_ms.max(1));
        let jitter = Self::deterministic_jitter_ms(local, remote, attempt, plan.jitter_ms);
        base.saturating_add(jitter)
    }

    fn deterministic_jitter_ms(
        local: SocketAddr,
        remote: SocketAddr,
        attempt: u8,
        max_jitter_ms: u64,
    ) -> u64 {
        if max_jitter_ms == 0 {
            return 0;
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tcp-hole-punch-jitter/v1");
        hasher.update(local.to_string().as_bytes());
        hasher.update(remote.to_string().as_bytes());
        hasher.update(&[attempt]);
        let bytes = hasher.finalize();
        u64::from(bytes.as_bytes()[0]) % (max_jitter_ms + 1)
    }

    /// Enable TCP_FASTOPEN on socket (Linux only)
    #[cfg(target_os = "linux")]
    fn enable_tcp_fastopen(socket: &TcpSocket) -> Result<()> {
        let fd = socket.as_raw_fd();
        let qlen: i32 = 5; // Queue length for pending TFO connections

        unsafe {
            if libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN,
                &qlen as *const i32 as *const libc::c_void,
                std::mem::size_of_val(&qlen) as libc::socklen_t,
            ) != 0
            {
                // Non-fatal, just log and continue
                tracing::debug!("TCP_FASTOPEN not available");
            }
        }
        Ok(())
    }

    /// Test if a TCP port is open (by sending RST and checking response)
    pub async fn test_port_open(addr: SocketAddr) -> Result<bool> {
        use std::io::ErrorKind;

        match timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
            Ok(Ok(_)) => Ok(true), // Port is open and accepting
            Ok(Err(e)) => {
                // If connection refused, port is closed
                // If timeout or other error, inconclusive
                match e.kind() {
                    ErrorKind::ConnectionRefused => Ok(false),
                    _ => {
                        tracing::debug!("Port test inconclusive: {}", e);
                        Ok(false)
                    }
                }
            }
            Err(_) => Ok(false), // Timeout = port likely filtered/closed
        }
    }

    /// Attempt coordinated simultaneous TCP open.
    pub async fn simultaneous_open(
        local1: SocketAddr,
        remote1: SocketAddr,
        local2: SocketAddr,
        remote2: SocketAddr,
    ) -> Result<(TcpStream, TcpStream)> {
        info!("Attempting simultaneous TCP open");

        // Small delay to improve SYN overlap.
        tokio::time::sleep(Duration::from_millis(40)).await;

        let plan = TcpPunchPlan {
            attempts: 3,
            ..TcpPunchPlan::default()
        };

        let f1 = Self::punch_with_plan(local1, remote1, plan);
        let f2 = Self::punch_with_plan(local2, remote2, plan);
        let (r1, r2) = tokio::join!(f1, f2);

        match (r1, r2) {
            (Ok(s1), Ok(s2)) => {
                info!("Simultaneous TCP open successful");
                Ok((s1, s2))
            }
            (Err(e1), Err(e2)) => Err(TcpHolePunchError::BothSidesFailed(
                e1.to_string(),
                e2.to_string(),
            )),
            (Err(e), Ok(_)) | (Ok(_), Err(e)) => Err(TcpHolePunchError::ConnectionFailed(format!(
                "one side failed: {}",
                e
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_hole_punch_creation() {
        let _puncher = TcpHolePunch;
    }

    #[test]
    fn test_attempt_timeout_monotonic_and_capped() {
        let plan = TcpPunchPlan {
            min_attempt_timeout_ms: 100,
            max_attempt_timeout_ms: 900,
            ..TcpPunchPlan::default()
        };
        let t0 = TcpHolePunch::attempt_timeout_ms(plan, 0);
        let t1 = TcpHolePunch::attempt_timeout_ms(plan, 1);
        let t2 = TcpHolePunch::attempt_timeout_ms(plan, 2);
        let t5 = TcpHolePunch::attempt_timeout_ms(plan, 5);

        assert!(t1 >= t0);
        assert!(t2 >= t1);
        assert!(t5 <= 900);
    }

    #[test]
    fn test_deterministic_jitter_is_stable() {
        let local: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let remote: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let j1 = TcpHolePunch::deterministic_jitter_ms(local, remote, 2, 60);
        let j2 = TcpHolePunch::deterministic_jitter_ms(local, remote, 2, 60);
        let j3 = TcpHolePunch::deterministic_jitter_ms(local, remote, 3, 60);

        assert_eq!(j1, j2);
        assert!(j1 <= 60);
        assert!(j3 <= 60);
    }

    #[tokio::test]
    async fn test_port_open_localhost() {
        // Test on localhost - port 1 should be closed
        let result = TcpHolePunch::test_port_open("127.0.0.1:1".parse().unwrap()).await;

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Port 1 is likely closed

        // Test on localhost - port 22 (ssh) might be open
        let result = TcpHolePunch::test_port_open("127.0.0.1:22".parse().unwrap()).await;

        // Result depends on SSH running
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[should_panic]
    async fn test_tcp_hole_punch_to_closed_port() {
        // This should fail to connect
        let _ = TcpHolePunch::punch(
            "127.0.0.1:0".parse().unwrap(),    // Random local port
            "127.0.0.1:9999".parse().unwrap(), // Likely closed
        )
        .await
        .unwrap();
    }
}
