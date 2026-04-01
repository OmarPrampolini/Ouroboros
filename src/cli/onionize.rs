use crate::config::TOR_SOCKS_WAIT_SECS;
use crate::onion::validate_onion_addr;
use anyhow::{anyhow, Context, Result};
use clap::Args;
use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::net::TcpStream;
use tokio::time::sleep;

const DEFAULT_SOCKS_ADDR: &str = "127.0.0.1:9050";
const DEFAULT_PORT: u16 = 9999;
const HOSTNAME_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Args, Debug, Clone)]
pub struct OnionizeArgs {
    #[arg(long)]
    pub host: bool,
    #[arg(long)]
    pub client: Option<String>,
    #[arg(long, default_value_t = DEFAULT_PORT)]
    pub port: u16,
    #[arg(long)]
    pub start_tor: bool,
}

pub async fn run(args: OnionizeArgs) -> Result<()> {
    validate_mode(&args)?;

    if args.host {
        run_host_mode(&args).await
    } else {
        run_client_mode(&args).await
    }
}

fn validate_mode(args: &OnionizeArgs) -> Result<()> {
    if args.host && args.client.is_some() {
        return Err(anyhow!("Use either --host or --client, not both"));
    }
    if !args.host && args.client.is_none() {
        return Err(anyhow!("Either --host or --client is required"));
    }
    Ok(())
}

async fn run_host_mode(args: &OnionizeArgs) -> Result<()> {
    if !args.start_tor {
        return Err(anyhow!("Host mode requires --start-tor"));
    }

    ensure_port_available(args.port)?;

    let runtime_dir = create_runtime_dir().await?;
    let torrc_path = runtime_dir.join("torrc");

    write_torrc_host(&torrc_path, &runtime_dir, args.port).await?;

    let mut tor_session = TorSession::spawn_with_torrc(&runtime_dir, &torrc_path)?;

    wait_for_socks(DEFAULT_SOCKS_ADDR, Duration::from_secs(2)).await?;
    let hostname_path = runtime_dir.join("hostname");
    let onion = wait_for_hostname(&hostname_path, HOSTNAME_TIMEOUT).await?;

    println!("Onion service ready:");
    println!("{}:{}", onion.trim(), args.port);

    tokio::signal::ctrl_c().await?;
    tor_session.shutdown();
    Ok(())
}

async fn run_client_mode(args: &OnionizeArgs) -> Result<()> {
    let target = args
        .client
        .as_ref()
        .ok_or_else(|| anyhow!("--client requires onion:port"))?;
    validate_onion_target(target)?;

    if let Err(e) = wait_for_socks(DEFAULT_SOCKS_ADDR, Duration::from_secs(2)).await {
        if !args.start_tor {
            return Err(anyhow!("Tor SOCKS5 not reachable: {}", e));
        }
        let runtime_dir = create_runtime_dir().await?;
        let torrc_path = runtime_dir.join("torrc");
        write_torrc_client(&torrc_path, &runtime_dir).await?;
        let mut tor_session = TorSession::spawn_with_torrc(&runtime_dir, &torrc_path)?;
        wait_for_socks(DEFAULT_SOCKS_ADDR, Duration::from_secs(TOR_SOCKS_WAIT_SECS)).await?;

        print_client_ready(target);
        tokio::signal::ctrl_c().await?;
        tor_session.shutdown();
        return Ok(());
    }

    print_client_ready(target);
    Ok(())
}

fn print_client_ready(target: &str) {
    println!("Tor client ready.");
    println!("Config:");
    println!("  HANDSHACKE_WAN_MODE=tor");
    println!("  HANDSHACKE_TOR_ROLE=client");
    println!("  HANDSHACKE_TOR_ONION={}", target);
    println!("Run: handshacke connect");
}

fn validate_onion_target(target: &str) -> Result<()> {
    validate_onion_addr(target)?;
    Ok(())
}

async fn wait_for_socks(addr: &str, timeout: Duration) -> Result<()> {
    let addr: SocketAddr = addr.parse().context("Invalid SOCKS address")?;
    let fut = TcpStream::connect(addr);
    tokio::time::timeout(timeout, fut)
        .await
        .context("Tor SOCKS5 connection timeout")?
        .context("Tor SOCKS5 connection failed")?;
    Ok(())
}

async fn wait_for_hostname(path: &Path, timeout: Duration) -> Result<String> {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Err(anyhow!("Timed out waiting for Tor hostname file"));
        }
        match fs::read_to_string(path).await {
            Ok(s) if !s.trim().is_empty() => return Ok(s),
            _ => sleep(Duration::from_millis(200)).await,
        }
    }
}

fn ensure_port_available(port: u16) -> Result<()> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    TcpListener::bind(addr)
        .map(drop)
        .map_err(|e| anyhow!("Port {} is not available: {}", port, e))
}

async fn create_runtime_dir() -> Result<PathBuf> {
    let base = runtime_base_dir()?;
    let session_id = random_session_id();
    let path = base.join("runtime").join(session_id).join("tor");
    fs::create_dir_all(&path)
        .await
        .context("Failed to create runtime dir")?;
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

async fn write_torrc_host(torrc_path: &Path, runtime_dir: &Path, port: u16) -> Result<()> {
    let torrc = format!(
        "HiddenServiceDir \"{}\"\nHiddenServicePort {} 127.0.0.1:{}\n",
        runtime_dir.display(),
        port,
        port
    );
    fs::write(torrc_path, torrc)
        .await
        .context("Failed to write torrc")?;
    Ok(())
}

async fn write_torrc_client(torrc_path: &Path, runtime_dir: &Path) -> Result<()> {
    let torrc = format!(
        "DataDirectory \"{}\"\nSocksPort 9050\n",
        runtime_dir.display()
    );
    fs::write(torrc_path, torrc)
        .await
        .context("Failed to write torrc")?;
    Ok(())
}

struct TorSession {
    child: Child,
    runtime_dir: PathBuf,
}

impl TorSession {
    fn spawn_with_torrc(runtime_dir: &Path, torrc_path: &Path) -> Result<Self> {
        let child = Command::new("tor")
            .arg("-f")
            .arg(torrc_path)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .context("Failed to start Tor process")?;

        Ok(Self {
            child,
            runtime_dir: runtime_dir.to_path_buf(),
        })
    }

    fn shutdown(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.runtime_dir);
    }
}

impl Drop for TorSession {
    fn drop(&mut self) {
        self.shutdown();
    }
}
