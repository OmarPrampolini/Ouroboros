use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Error)]
pub enum ManagedTorError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to start Tor process: {0}")]
    StartTor(String),
    #[error("ADD_ONION missing ServiceID")]
    MissingServiceId,
    #[error("read control_auth_cookie: {0}")]
    ReadControlAuthCookie(String),
    #[error("Tor control auth failed")]
    ControlAuthFailed,
    #[error("Failed to write torrc: {0}")]
    WriteTorrc(String),
    #[error("Timed out waiting for Tor control port")]
    WaitControlTimeout,
    #[error("Failed to create runtime dir: {0}")]
    CreateRuntimeDir(String),
}

type Result<T> = std::result::Result<T, ManagedTorError>;

pub struct ManagedTor {
    child: Child,
    runtime_dir: PathBuf,
    control_port: u16,
    socks_port: u16,
}

impl ManagedTor {
    pub async fn start(tor_bin: Option<&str>) -> Result<Self> {
        let runtime_dir = create_runtime_dir().await?;
        let torrc_path = runtime_dir.join("torrc");

        let control_port = reserve_port()?;
        let socks_port = reserve_port()?;
        write_torrc(&torrc_path, &runtime_dir, control_port, socks_port).await?;

        let child = Command::new(tor_bin.unwrap_or("tor"))
            .arg("-f")
            .arg(&torrc_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| ManagedTorError::StartTor(e.to_string()))?;

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), control_port);
        wait_for_tcp(addr, CONTROL_TIMEOUT).await?;
        let socks_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), socks_port);
        wait_for_tcp(socks_addr, CONTROL_TIMEOUT).await?;

        Ok(Self {
            child,
            runtime_dir,
            control_port,
            socks_port,
        })
    }

    pub fn socks_addr(&self) -> String {
        format!("127.0.0.1:{}", self.socks_port)
    }

    pub async fn add_onion_with_port(&self, virt_port: u16, local_port: u16) -> Result<String> {
        let mut stream = self.control_stream().await?;
        authenticate(&mut stream, &self.runtime_dir).await?;

        let cmd = format!(
            "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port={},127.0.0.1:{}\r\n",
            virt_port, local_port
        );
        stream.write_all(cmd.as_bytes()).await?;

        let mut service_id = None;
        loop {
            let line = read_line(&mut stream).await?;
            if line.starts_with("250-ServiceID=") {
                service_id = Some(line.trim_start_matches("250-ServiceID=").trim().to_string());
            }
            if line.starts_with("250 OK") {
                break;
            }
        }

        let id = service_id.ok_or(ManagedTorError::MissingServiceId)?;
        Ok(format!("{}.onion", id))
    }

    pub async fn del_onion(&self, onion: &str) -> Result<()> {
        let mut stream = self.control_stream().await?;
        authenticate(&mut stream, &self.runtime_dir).await?;
        let id = onion.trim_end_matches(".onion");
        let cmd = format!("DEL_ONION {}\r\n", id);
        stream.write_all(cmd.as_bytes()).await?;
        loop {
            let line = read_line(&mut stream).await?;
            if line.starts_with("250 OK") {
                break;
            }
        }
        Ok(())
    }

    async fn control_stream(&self) -> Result<TcpStream> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.control_port);
        let stream = TcpStream::connect(addr).await?;
        Ok(stream)
    }

    pub fn shutdown(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.runtime_dir);
    }
}

impl Drop for ManagedTor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

async fn authenticate(stream: &mut TcpStream, runtime_dir: &Path) -> Result<()> {
    let cookie_path = runtime_dir.join("control_auth_cookie");
    let cookie = fs::read(&cookie_path)
        .await
        .map_err(|e| ManagedTorError::ReadControlAuthCookie(e.to_string()))?;
    let hex = hex::encode(cookie);
    let cmd = format!("AUTHENTICATE {}\r\n", hex);
    stream.write_all(cmd.as_bytes()).await?;
    loop {
        let line = read_line(stream).await?;
        if line.starts_with("250 OK") {
            return Ok(());
        }
        if line.starts_with("515") {
            return Err(ManagedTorError::ControlAuthFailed);
        }
    }
}

async fn read_line(stream: &mut TcpStream) -> Result<String> {
    let mut buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.len() >= 2 && buf[buf.len() - 2] == b'\r' && buf[buf.len() - 1] == b'\n' {
            break;
        }
    }
    let line = String::from_utf8_lossy(&buf).trim().to_string();
    Ok(line)
}

async fn write_torrc(
    path: &Path,
    runtime_dir: &Path,
    control_port: u16,
    socks_port: u16,
) -> Result<()> {
    let log_path = runtime_dir.join("tor.log");
    let torrc = format!(
        "DataDirectory \"{}\"\nControlPort {}\nCookieAuthentication 1\nSocksPort 127.0.0.1:{} IsolateDestAddr IsolateDestPort\nAvoidDiskWrites 1\nClientOnly 1\nSafeSocks 1\nLog notice file \"{}\"\n",
        runtime_dir.display(),
        control_port,
        socks_port,
        log_path.display()
    );
    fs::write(path, torrc)
        .await
        .map_err(|e| ManagedTorError::WriteTorrc(e.to_string()))?;
    Ok(())
}

fn reserve_port() -> Result<u16> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let listener = TcpListener::bind(addr)?;
    let port = listener.local_addr()?.port();
    Ok(port)
}

async fn wait_for_tcp(addr: SocketAddr, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Err(ManagedTorError::WaitControlTimeout);
        }
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(200)).await;
    }
}

async fn create_runtime_dir() -> Result<PathBuf> {
    let base = runtime_base_dir()?;
    let session_id = random_session_id();
    let path = base.join("runtime").join(session_id).join("tor");
    fs::create_dir_all(&path)
        .await
        .map_err(|e| ManagedTorError::CreateRuntimeDir(e.to_string()))?;
    Ok(path)
}

fn runtime_base_dir() -> Result<PathBuf> {
    if let Ok(home) = std::env::var("USERPROFILE") {
        return Ok(PathBuf::from(home).join(".handshacke"));
    }
    if let Ok(home) = std::env::var("HOME") {
        return Ok(PathBuf::from(home).join(".handshacke"));
    }
    Ok(std::env::temp_dir().join("handshacke"))
}

fn random_session_id() -> String {
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
