use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand};
use rand::RngCore;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::Client;
use serde::{Deserialize, Serialize};

const DEFAULT_API: &str = "http://127.0.0.1:3000";

#[derive(Parser)]
#[command(name = "hs-cli", version, about = "Handshacke CLI")]
struct Args {
    #[command(subcommand)]
    command: Commands,
    #[arg(long, default_value = DEFAULT_API)]
    api: String,
    /// API bearer token (overrides env HANDSHACKE_API_TOKEN and HANDSHACKE_API_TOKEN_FILE)
    #[arg(long)]
    token: Option<String>,
    /// Read API bearer token from file (overrides env HANDSHACKE_API_TOKEN_FILE)
    #[arg(long)]
    token_file: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    Host {
        #[arg(long)]
        passphrase: Option<String>,
        #[arg(long)]
        include_tor: bool,
        #[arg(long)]
        ttl_s: Option<u64>,
    },
    Join {
        offer: String,
    },
    Doctor {
        /// Emit the doctor report as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Serialize)]
struct OfferRequest {
    passphrase: Option<String>,
    ttl_s: Option<u64>,
    role_hint: Option<String>,
    include_tor: Option<bool>,
}

#[derive(Deserialize)]
struct OfferResponse {
    offer: String,
    ver: u8,
    expires_at_ms: u64,
    endpoints: Vec<String>,
}

#[derive(Serialize)]
struct ConnectRequest {
    offer: Option<String>,
    passphrase: Option<String>,
    local_role: Option<String>,
}

#[derive(Deserialize)]
struct ConnectResponse {
    status: String,
    port: Option<u16>,
    mode: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DoctorLevel {
    Ok,
    Warn,
    Error,
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: String,
    level: DoctorLevel,
    detail: String,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    api: String,
    token_present: bool,
    checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    fn new(api: &str, token_present: bool) -> Self {
        Self {
            api: api.to_string(),
            token_present,
            checks: Vec::new(),
        }
    }

    fn push(&mut self, name: &str, level: DoctorLevel, detail: impl Into<String>) {
        self.checks.push(DoctorCheck {
            name: name.to_string(),
            level,
            detail: detail.into(),
        });
    }

    fn has_errors(&self) -> bool {
        self.checks
            .iter()
            .any(|check| matches!(check.level, DoctorLevel::Error))
    }

    fn has_warnings(&self) -> bool {
        self.checks
            .iter()
            .any(|check| matches!(check.level, DoctorLevel::Warn))
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct DoctorConnectionStatus {
    status: String,
    port: Option<u16>,
    mode: String,
    peer: Option<String>,
    privacy_profile: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct DoctorCapabilities {
    runtime_connection_mode: Option<String>,
    runtime_privacy_profile: String,
    quic: bool,
    webrtc: bool,
    pq_primitives: bool,
    orp_standard: bool,
    orp_highrisk: bool,
    keeper_replication: bool,
    bridge_bootstrap: bool,
    bootstrap_bundle_trust_posture: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct DoctorHighRiskGate {
    available: bool,
    available_effective: bool,
    observed_posture: String,
    gate_reasons: Vec<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct DoctorRoutesStatus {
    route_cache_size: usize,
    route_offers_count: usize,
    standard_private_available: bool,
    high_risk: DoctorHighRiskGate,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct DoctorEtherSyncStatus {
    running: bool,
    peer_count: usize,
    subscription_count: usize,
    spaces: Vec<String>,
    bridge_bootstrap_enabled: bool,
    bootstrap_bundle_trust_posture: String,
    high_risk_available: bool,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct DoctorKeeperStatus {
    keeper_replication_enabled: bool,
    remote_confirmation_mode: String,
    remote_storage_class: String,
    pending_remote_send_envelopes: usize,
    failed_remote_send_envelopes: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let token = resolve_api_token(&args)?;
    let mut headers = HeaderMap::new();
    if let Some(token) = &token {
        let v = HeaderValue::from_str(&format!("Bearer {}", token))
            .map_err(|_| anyhow!("Invalid token for Authorization header"))?;
        headers.insert(AUTHORIZATION, v);
    }
    let client = Client::builder().default_headers(headers).build()?;

    match args.command {
        Commands::Host {
            passphrase,
            include_tor,
            ttl_s,
        } => {
            let passphrase = passphrase.unwrap_or_else(random_passphrase);

            let connect_req = ConnectRequest {
                offer: None,
                passphrase: Some(passphrase.clone()),
                local_role: Some("host".into()),
            };
            let connect_url = format!("{}/v1/connect", args.api);
            let connect_res = client.post(connect_url).json(&connect_req).send().await?;
            if !connect_res.status().is_success() {
                return Err(anyhow!("Connect failed: {}", connect_res.status()));
            }

            let req = OfferRequest {
                passphrase: Some(passphrase),
                ttl_s,
                role_hint: Some("host".into()),
                include_tor: Some(include_tor),
            };
            let url = format!("{}/v1/offer", args.api);
            let res = client.post(url).json(&req).send().await?;

            if !res.status().is_success() {
                return Err(anyhow!("Offer generation failed: {}", res.status()));
            }
            let body: OfferResponse = res.json().await?;
            println!("Offer v{} (expires at {} ms)", body.ver, body.expires_at_ms);
            println!("Endpoints: {}", body.endpoints.join(", "));
            println!("Offer (QR-friendly):");
            println!("{}", body.offer);
        }
        Commands::Join { offer } => {
            let req = ConnectRequest {
                offer: Some(offer),
                passphrase: None,
                local_role: None,
            };
            let url = format!("{}/v1/connect", args.api);
            let res = client.post(url).json(&req).send().await?;

            let body: ConnectResponse = res.json().await?;
            println!("Status: {}", body.status);
            println!("Mode: {}", body.mode);
            if let Some(port) = body.port {
                println!("Port: {}", port);
            }
        }
        Commands::Doctor { json } => {
            let report = run_doctor(&client, &args.api, token.is_some()).await;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_doctor_report(&report);
            }
            if report.has_errors() {
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

async fn run_doctor(client: &Client, api: &str, token_present: bool) -> DoctorReport {
    let mut report = DoctorReport::new(api, token_present);

    let status_url = format!("{}/v1/status", api);
    let status = match fetch_json::<DoctorConnectionStatus>(client, &status_url).await {
        Ok(status) => {
            let peer = status.peer.clone().unwrap_or_else(|| "n/a".to_string());
            let privacy = status
                .privacy_profile
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            let port = status
                .port
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a".to_string());
            report.push(
                "api",
                DoctorLevel::Ok,
                format!(
                    "reachable; status={} mode={} privacy={} port={} peer={}",
                    empty_fallback(&status.status, "unknown"),
                    empty_fallback(&status.mode, "unknown"),
                    privacy,
                    port,
                    peer
                ),
            );
            Some(status)
        }
        Err(err) => {
            report.push("api", DoctorLevel::Error, err.to_string());
            None
        }
    };

    if status.is_none() {
        return report;
    }

    match fetch_json::<DoctorCapabilities>(client, &format!("{}/v1/capabilities", api)).await {
        Ok(cap) => {
            report.push(
                "capabilities",
                DoctorLevel::Ok,
                format!(
                    "orp-standard={} orp-highrisk={} quic={} webrtc={} pq={} keeper={} bridge-bootstrap={} trust={}",
                    bool_label(cap.orp_standard),
                    bool_label(cap.orp_highrisk),
                    bool_label(cap.quic),
                    bool_label(cap.webrtc),
                    bool_label(cap.pq_primitives),
                    bool_label(cap.keeper_replication),
                    bool_label(cap.bridge_bootstrap),
                    empty_fallback(&cap.bootstrap_bundle_trust_posture, "unknown")
                ),
            );
        }
        Err(err) => report.push("capabilities", DoctorLevel::Error, err.to_string()),
    }

    match fetch_json::<DoctorEtherSyncStatus>(client, &format!("{}/v1/ethersync/status", api)).await
    {
        Ok(status) => {
            let level = if status.running {
                DoctorLevel::Ok
            } else {
                DoctorLevel::Warn
            };
            report.push(
                "ethersync",
                level,
                format!(
                    "running={} peers={} subscriptions={} spaces={} bridge-bootstrap={} bundle-trust={}",
                    bool_label(status.running),
                    status.peer_count,
                    status.subscription_count,
                    status.spaces.len(),
                    bool_label(status.bridge_bootstrap_enabled),
                    empty_fallback(&status.bootstrap_bundle_trust_posture, "unknown")
                ),
            );
        }
        Err(err) => report.push("ethersync", DoctorLevel::Warn, err.to_string()),
    }

    match fetch_json::<DoctorRoutesStatus>(client, &format!("{}/v1/routes/status", api)).await {
        Ok(status) => {
            let level = if status.high_risk.available_effective {
                DoctorLevel::Ok
            } else {
                DoctorLevel::Warn
            };
            let reasons = if status.high_risk.gate_reasons.is_empty() {
                "none".to_string()
            } else {
                status.high_risk.gate_reasons.join("; ")
            };
            report.push(
                "orp",
                level,
                format!(
                    "standard-private={} route-cache={} route-offers={} high-risk-effective={} posture={} gate-reasons={}",
                    bool_label(status.standard_private_available),
                    status.route_cache_size,
                    status.route_offers_count,
                    bool_label(status.high_risk.available_effective),
                    empty_fallback(&status.high_risk.observed_posture, "unknown"),
                    reasons
                ),
            );
        }
        Err(err) => report.push("orp", DoctorLevel::Warn, err.to_string()),
    }

    match fetch_json::<DoctorKeeperStatus>(client, &format!("{}/v1/keepers/status", api)).await {
        Ok(status) => {
            let level = if status.failed_remote_send_envelopes > 0 {
                DoctorLevel::Warn
            } else {
                DoctorLevel::Ok
            };
            report.push(
                "keepers",
                level,
                format!(
                    "replication={} confirmation-mode={} storage-class={} pending={} failed={}",
                    bool_label(status.keeper_replication_enabled),
                    empty_fallback(&status.remote_confirmation_mode, "unknown"),
                    empty_fallback(&status.remote_storage_class, "unknown"),
                    status.pending_remote_send_envelopes,
                    status.failed_remote_send_envelopes
                ),
            );
        }
        Err(err) => report.push("keepers", DoctorLevel::Warn, err.to_string()),
    }

    report
}

async fn fetch_json<T>(client: &Client, url: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let res = client.get(url).send().await?;
    let status = res.status();
    let body = res.text().await?;
    if !status.is_success() {
        let detail = if body.trim().is_empty() {
            status.to_string()
        } else {
            format!("{} {}", status, truncate_for_display(&body, 200))
        };
        return Err(anyhow!("{} -> {}", url, detail));
    }
    Ok(serde_json::from_str(&body)?)
}

fn print_doctor_report(report: &DoctorReport) {
    println!("Doctor for {}", report.api);
    println!(
        "Token: {}",
        if report.token_present {
            "present"
        } else {
            "not set"
        }
    );
    for check in &report.checks {
        println!(
            "- {}: {} - {}",
            check.name,
            doctor_level_label(&check.level),
            check.detail
        );
    }
    let summary = if report.has_errors() {
        "errors"
    } else if report.has_warnings() {
        "warnings"
    } else {
        "ok"
    };
    println!("Doctor result: {}", summary);
}

fn doctor_level_label(level: &DoctorLevel) -> &'static str {
    match level {
        DoctorLevel::Ok => "ok",
        DoctorLevel::Warn => "warn",
        DoctorLevel::Error => "error",
    }
}

fn bool_label(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn empty_fallback(value: &str, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn truncate_for_display(value: &str, max_chars: usize) -> String {
    let trimmed = value.trim();
    if trimmed.chars().count() <= max_chars {
        return trimmed.to_string();
    }
    let mut out = trimmed.chars().take(max_chars).collect::<String>();
    out.push_str("...");
    out
}

fn random_passphrase() -> String {
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn resolve_api_token(args: &Args) -> Result<Option<String>> {
    if let Some(t) = args.token.as_ref() {
        let t = t.trim();
        if !t.is_empty() {
            return Ok(Some(t.to_string()));
        }
    }

    if let Some(path) = args
        .token_file
        .as_ref()
        .cloned()
        .or_else(|| std::env::var("HANDSHACKE_API_TOKEN_FILE").ok())
    {
        if let Ok(s) = std::fs::read_to_string(path) {
            let t = s.trim();
            if !t.is_empty() {
                return Ok(Some(t.to_string()));
            }
        }
    }

    if let Ok(t) = std::env::var("HANDSHACKE_API_TOKEN") {
        let t = t.trim().to_string();
        if !t.is_empty() {
            return Ok(Some(t));
        }
    }

    Ok(None)
}
