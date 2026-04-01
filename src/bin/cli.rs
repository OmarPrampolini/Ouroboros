use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::{Args as ClapArgs, Parser, Subcommand};
use rand::RngCore;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::{Client, Response, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

const DEFAULT_API: &str = "http://127.0.0.1:3000";

#[derive(Parser)]
#[command(name = "hs-cli", version, about = "Handshacke terminal CLI")]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
    #[arg(long, default_value = DEFAULT_API)]
    api: String,
    #[arg(long)]
    token: Option<String>,
    #[arg(long)]
    token_file: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    Interactive,
    Status {
        #[arg(long)]
        json: bool,
    },
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
    Connect {
        #[arg(long)]
        passphrase: String,
        #[arg(long, default_value = "client")]
        local_role: String,
        #[arg(long)]
        privacy_profile: Option<String>,
    },
    Disconnect,
    Doctor {
        #[arg(long)]
        json: bool,
    },
    Watch {
        #[arg(long)]
        raw: bool,
        #[arg(long)]
        show_keepalive: bool,
    },
    Ethersync {
        #[command(subcommand)]
        command: EtherSyncCommands,
    },
}

#[derive(Subcommand)]
enum EtherSyncCommands {
    Start(StartArgs),
    Stop,
    Status {
        #[arg(long)]
        json: bool,
    },
    AddPeer {
        addr: String,
    },
    Join(JoinSpaceArgs),
    Leave {
        passphrase: String,
        #[arg(long)]
        label: Option<String>,
    },
    Publish(PublishArgs),
    PublishFile(PublishFileArgs),
    Backfill {
        passphrase: String,
        #[arg(long)]
        max_messages: Option<usize>,
    },
    Policies {
        #[arg(long)]
        json: bool,
    },
    SetPolicy(SetPolicyArgs),
}

#[derive(Debug, ClapArgs)]
struct StartArgs {
    #[arg(long)]
    bind_addr: Option<String>,
    #[arg(long)]
    peer: Vec<String>,
    #[arg(long)]
    gossip_interval_secs: Option<u64>,
    #[arg(long)]
    sweep_interval_secs: Option<u64>,
    #[arg(long)]
    gossip_ttl: Option<u8>,
    #[arg(long)]
    enable_orp: bool,
    #[arg(long)]
    disable_compression: bool,
}

#[derive(Debug, ClapArgs)]
struct JoinSpaceArgs {
    passphrase: String,
    #[arg(long)]
    label: Option<String>,
    #[arg(long)]
    retention_tier: Option<String>,
    #[arg(long)]
    replication_factor: Option<usize>,
    #[arg(long)]
    route_bias: Option<String>,
}

#[derive(Debug, ClapArgs)]
struct PublishArgs {
    passphrase: String,
    #[arg(long, conflicts_with = "payload_b64")]
    message: Option<String>,
    #[arg(long, conflicts_with = "message")]
    payload_b64: Option<String>,
}

#[derive(Debug, ClapArgs)]
struct PublishFileArgs {
    passphrase: String,
    path: PathBuf,
    #[arg(long)]
    filename: Option<String>,
    #[arg(long)]
    chunk_size: Option<usize>,
}

#[derive(Debug, ClapArgs)]
struct SetPolicyArgs {
    passphrase: String,
    #[arg(long)]
    retention_tier: Option<String>,
    #[arg(long)]
    replication_factor: Option<usize>,
    #[arg(long)]
    route_bias: Option<String>,
}

#[derive(Debug, Serialize)]
struct OfferRequest {
    passphrase: Option<String>,
    ttl_s: Option<u64>,
    role_hint: Option<String>,
    include_tor: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ConnectRequest {
    offer: Option<String>,
    passphrase: Option<String>,
    local_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    privacy_profile: Option<String>,
}

#[derive(Debug, Serialize)]
struct EtherSyncStartRequest {
    bind_addr: Option<String>,
    bootstrap_peers: Option<Vec<String>>,
    gossip_interval_secs: Option<u64>,
    sweep_interval_secs: Option<u64>,
    gossip_ttl: Option<u8>,
    enable_compression: Option<bool>,
    enable_orp: Option<bool>,
}

#[derive(Debug, Serialize)]
struct EtherSyncPeerAddRequest {
    addr: String,
}

#[derive(Debug, Serialize)]
struct EtherSyncJoinRequest {
    passphrase: String,
    label: Option<String>,
    retention_tier: Option<String>,
    replication_factor: Option<usize>,
    route_bias: Option<String>,
}

#[derive(Debug, Serialize)]
struct EtherSyncLeaveRequest {
    passphrase: String,
    label: Option<String>,
}

#[derive(Debug, Serialize)]
struct EtherSyncPublishRequest {
    passphrase: String,
    payload_b64: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Serialize)]
struct EtherSyncPublishFileRequest {
    passphrase: String,
    filename: String,
    file_b64: String,
    chunk_size: Option<usize>,
}

#[derive(Debug, Serialize)]
struct KeeperBackfillRequest {
    passphrase: String,
    max_messages: Option<usize>,
}

#[derive(Debug, Serialize)]
struct KeeperPolicyUpdateRequest {
    passphrase: String,
    retention_tier: Option<String>,
    replication_factor: Option<usize>,
    route_bias: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiErrorBody {
    code: u16,
    message: String,
    details: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct OfferResponse {
    offer: String,
    ver: u8,
    expires_at_ms: u64,
    endpoints: Vec<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct ConnectionResponseView {
    status: String,
    port: Option<u16>,
    mode: String,
    peer: Option<String>,
    resume_status: Option<String>,
    privacy_profile: String,
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
    bind_addr: Option<String>,
    local_addr: Option<String>,
    peer_count: usize,
    subscription_count: usize,
    spaces: Vec<String>,
    orp_enabled: bool,
    route_cache_size: usize,
    route_offers_count: usize,
    bridge_bootstrap_enabled: bool,
    bootstrap_bundle_trust_posture: String,
    high_risk_available: bool,
    high_risk_gate_reasons: Vec<String>,
    keeper_replication_enabled: bool,
    retention_tier: String,
    pending_keeper_envelopes: usize,
    archived_keeper_envelopes: usize,
    remote_keeper_receipts: usize,
    failed_remote_send_envelopes: usize,
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

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct KeeperManifestView {
    managed: bool,
    keeper_route_intent: String,
    desired_replica_count: usize,
    available_keeper_candidates: usize,
    selected_keeper_targets: usize,
    acknowledged_keeper_targets: usize,
    candidate_shortfall: usize,
    remote_keeper_receipts: usize,
    remote_delivered_envelopes: usize,
    replication_stage: String,
    last_local_activity_ms: Option<u64>,
    last_remote_receipt_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct EtherSyncJoinResultView {
    space_id: String,
    retention_tier: String,
    replication_factor: usize,
    route_bias: String,
    keeper_manifest: KeeperManifestView,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct EtherSyncLeaveResultView {
    space_id: String,
    unsubscribed: bool,
    orp_stopped: bool,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct EtherSyncPublishResultView {
    space_id: String,
    slot_id: u64,
    payload_len: usize,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct EtherSyncFilePublishResultView {
    space_id: String,
    transfer_id: String,
    filename: String,
    total_bytes: usize,
    total_chunks: usize,
    published_chunks: usize,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct KeeperBackfillResultView {
    space_id: String,
    restored_messages: usize,
    remaining_pending: usize,
    keeper_manifest: KeeperManifestView,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct SpacePolicySnapshotView {
    space_key: String,
    retention_tier: String,
    replication_factor: usize,
    route_bias: String,
    pending_keeper_envelopes: usize,
    archived_keeper_envelopes: usize,
    remote_keeper_targets: usize,
    remote_keeper_receipts: usize,
    remote_keeper_delivered_envelopes: usize,
    keeper_manifest: KeeperManifestView,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct EtherSyncEventView {
    kind: String,
    ts_ms: u64,
    space_id: Option<String>,
    slot_id: Option<u64>,
    payload_b64: Option<String>,
    text: Option<String>,
    info: Option<String>,
    error: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(warning) = remote_http_api_warning(&args.api) {
        eprintln!("Warning: {}", warning);
    }

    let token = resolve_api_token(&args)?;
    let client = build_client(token.as_deref())?;
    let token_present = token.is_some();

    match args.command {
        Some(Commands::Interactive) | None => {
            run_interactive(&client, &args.api, token_present).await
        }
        Some(Commands::Status { json }) => run_status(&client, &args.api, json).await,
        Some(Commands::Host {
            passphrase,
            include_tor,
            ttl_s,
        }) => run_host(&client, &args.api, passphrase, include_tor, ttl_s).await,
        Some(Commands::Join { offer }) => run_join_offer(&client, &args.api, offer).await,
        Some(Commands::Connect {
            passphrase,
            local_role,
            privacy_profile,
        }) => {
            run_connect_with_passphrase(&client, &args.api, passphrase, local_role, privacy_profile)
                .await
        }
        Some(Commands::Disconnect) => run_disconnect(&client, &args.api).await,
        Some(Commands::Doctor { json }) => {
            let report = run_doctor(&client, &args.api, token_present).await;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_doctor_report(&report);
            }
            if report.has_errors() {
                std::process::exit(1);
            }
            Ok(())
        }
        Some(Commands::Watch {
            raw,
            show_keepalive,
        }) => watch_ethersync_events(&client, &args.api, raw, show_keepalive).await,
        Some(Commands::Ethersync { command }) => {
            run_ethersync_command(&client, &args.api, command).await
        }
    }
}

fn build_client(token: Option<&str>) -> Result<Client> {
    let mut headers = HeaderMap::new();
    if let Some(token) = token {
        let value = HeaderValue::from_str(&format!("Bearer {}", token))
            .map_err(|_| anyhow!("Invalid token for Authorization header"))?;
        headers.insert(AUTHORIZATION, value);
    }
    Ok(Client::builder().default_headers(headers).build()?)
}

async fn run_interactive(client: &Client, api: &str, token_present: bool) -> Result<()> {
    loop {
        println!();
        println!("hs-cli interactive");
        println!("API: {}", api);
        println!(
            "Token: {}",
            if token_present { "present" } else { "not set" }
        );
        println!("1. Status snapshot");
        println!("2. Doctor");
        println!("3. Host a session");
        println!("4. Join from offer");
        println!("5. Connect with passphrase");
        println!("6. Disconnect");
        println!("7. Start EtherSync");
        println!("8. EtherSync status");
        println!("9. EtherSync join space");
        println!("10. EtherSync leave space");
        println!("11. EtherSync publish message");
        println!("12. Watch EtherSync events");
        println!("13. Quit");

        match prompt_required("Select action")?.as_str() {
            "1" | "status" => run_status(client, api, false).await?,
            "2" | "doctor" => {
                let report = run_doctor(client, api, token_present).await;
                print_doctor_report(&report);
            }
            "3" | "host" => {
                let passphrase = prompt_optional("Passphrase (blank = generate)")?;
                let include_tor = prompt_bool("Include Tor endpoints", false)?;
                let ttl_s = prompt_optional("Offer TTL seconds (blank = default)")?
                    .and_then(|value| value.parse::<u64>().ok());
                run_host(client, api, passphrase, include_tor, ttl_s).await?;
            }
            "4" | "join" => {
                let offer = prompt_required("Offer")?;
                run_join_offer(client, api, offer).await?;
            }
            "5" | "connect" => {
                let passphrase = prompt_required("Passphrase")?;
                let local_role = prompt_with_default("Local role", "client")?;
                let privacy_profile =
                    prompt_optional("Privacy profile (blank = standard-private, or high-risk)")?;
                run_connect_with_passphrase(client, api, passphrase, local_role, privacy_profile)
                    .await?;
            }
            "6" | "disconnect" => run_disconnect(client, api).await?,
            "7" | "ethersync-start" => {
                let bind_addr = prompt_optional("Bind addr (blank = 0.0.0.0:0)")?;
                let peer_csv = prompt_optional("Bootstrap peers comma-separated (blank = none)")?;
                let enable_orp = prompt_bool("Enable ORP", true)?;
                let disable_compression = prompt_bool("Disable compression", false)?;
                let args = StartArgs {
                    bind_addr,
                    peer: split_csv(peer_csv.unwrap_or_default()),
                    gossip_interval_secs: None,
                    sweep_interval_secs: None,
                    gossip_ttl: None,
                    enable_orp,
                    disable_compression,
                };
                run_ethersync_command(client, api, EtherSyncCommands::Start(args)).await?;
            }
            "8" | "ethersync-status" => {
                run_ethersync_command(client, api, EtherSyncCommands::Status { json: false })
                    .await?
            }
            "9" | "ethersync-join" => {
                let args = JoinSpaceArgs {
                    passphrase: prompt_required("Passphrase")?,
                    label: prompt_optional("Label (blank = none)")?,
                    retention_tier: prompt_optional("Retention tier (blank = current default)")?,
                    replication_factor: prompt_optional(
                        "Replication factor (blank = current default)",
                    )?
                    .and_then(|value| value.parse::<usize>().ok()),
                    route_bias: prompt_optional("Route bias (blank = balanced)")?,
                };
                run_ethersync_command(client, api, EtherSyncCommands::Join(args)).await?;
            }
            "10" | "ethersync-leave" => {
                let passphrase = prompt_required("Passphrase")?;
                let label = prompt_optional("Label (blank = none)")?;
                run_ethersync_command(client, api, EtherSyncCommands::Leave { passphrase, label })
                    .await?;
            }
            "11" | "ethersync-publish" => {
                let args = PublishArgs {
                    passphrase: prompt_required("Passphrase")?,
                    message: Some(prompt_required("Message")?),
                    payload_b64: None,
                };
                run_ethersync_command(client, api, EtherSyncCommands::Publish(args)).await?;
            }
            "12" | "watch" => watch_ethersync_events(client, api, false, false).await?,
            "13" | "q" | "quit" | "exit" => return Ok(()),
            other => println!("Unknown action: {}", other),
        }
    }
}

async fn run_status(client: &Client, api: &str, json_output: bool) -> Result<()> {
    let connection = get_json::<ConnectionResponseView>(client, api, "/v1/status").await?;
    let capabilities = get_json::<DoctorCapabilities>(client, api, "/v1/capabilities")
        .await
        .ok();
    let ethersync = get_json::<DoctorEtherSyncStatus>(client, api, "/v1/ethersync/status")
        .await
        .ok();
    let routes = get_json::<DoctorRoutesStatus>(client, api, "/v1/routes/status")
        .await
        .ok();

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "connection": connection,
                "capabilities": capabilities,
                "ethersync": ethersync,
                "routes": routes,
            }))?
        );
        return Ok(());
    }

    println!("Status for {}", api);
    println!(
        "Connection: status={} mode={} privacy={} port={} peer={}",
        empty_fallback(&connection.status, "unknown"),
        empty_fallback(&connection.mode, "unknown"),
        empty_fallback(&connection.privacy_profile, "unknown"),
        connection
            .port
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string()),
        connection.peer.clone().unwrap_or_else(|| "n/a".to_string())
    );

    if let Some(capabilities) = capabilities {
        println!(
            "Capabilities: orp-standard={} orp-highrisk={} quic={} webrtc={} pq={} keeper={} bridge-bootstrap={} trust={}",
            bool_label(capabilities.orp_standard),
            bool_label(capabilities.orp_highrisk),
            bool_label(capabilities.quic),
            bool_label(capabilities.webrtc),
            bool_label(capabilities.pq_primitives),
            bool_label(capabilities.keeper_replication),
            bool_label(capabilities.bridge_bootstrap),
            empty_fallback(&capabilities.bootstrap_bundle_trust_posture, "unknown"),
        );
    }

    if let Some(ethersync) = ethersync {
        print_ethersync_status(&ethersync);
    }

    if let Some(routes) = routes {
        println!(
            "Routes: standard-private={} cache={} offers={} high-risk-effective={} posture={}",
            bool_label(routes.standard_private_available),
            routes.route_cache_size,
            routes.route_offers_count,
            bool_label(routes.high_risk.available_effective),
            empty_fallback(&routes.high_risk.observed_posture, "unknown"),
        );
        if !routes.high_risk.gate_reasons.is_empty() {
            println!(
                "Route gate reasons: {}",
                routes.high_risk.gate_reasons.join("; ")
            );
        }
    }

    Ok(())
}

async fn run_host(
    client: &Client,
    api: &str,
    passphrase: Option<String>,
    include_tor: bool,
    ttl_s: Option<u64>,
) -> Result<()> {
    let passphrase = passphrase.unwrap_or_else(random_passphrase);
    let connect_req = ConnectRequest {
        offer: None,
        passphrase: Some(passphrase.clone()),
        local_role: Some("host".to_string()),
        privacy_profile: None,
    };
    let _: ConnectionResponseView = post_json(client, api, "/v1/connect", &connect_req).await?;

    let offer_req = OfferRequest {
        passphrase: Some(passphrase.clone()),
        ttl_s,
        role_hint: Some("host".to_string()),
        include_tor: Some(include_tor),
    };
    let offer = post_json::<OfferResponse, _>(client, api, "/v1/offer", &offer_req).await?;

    println!("Host ready");
    println!("Passphrase: {}", passphrase);
    println!("Offer version: {}", offer.ver);
    println!("Offer expires at ms: {}", offer.expires_at_ms);
    println!(
        "Endpoints: {}",
        if offer.endpoints.is_empty() {
            "none".to_string()
        } else {
            offer.endpoints.join(", ")
        }
    );
    println!("Offer:");
    println!("{}", offer.offer);
    Ok(())
}

async fn run_join_offer(client: &Client, api: &str, offer: String) -> Result<()> {
    let request = ConnectRequest {
        offer: Some(offer),
        passphrase: None,
        local_role: None,
        privacy_profile: None,
    };
    let response =
        post_json::<ConnectionResponseView, _>(client, api, "/v1/connect", &request).await?;
    print_connection_response(&response);
    Ok(())
}

async fn run_connect_with_passphrase(
    client: &Client,
    api: &str,
    passphrase: String,
    local_role: String,
    privacy_profile: Option<String>,
) -> Result<()> {
    let request = ConnectRequest {
        offer: None,
        passphrase: Some(passphrase),
        local_role: Some(local_role),
        privacy_profile,
    };
    let response =
        post_json::<ConnectionResponseView, _>(client, api, "/v1/connect", &request).await?;
    print_connection_response(&response);
    Ok(())
}

async fn run_disconnect(client: &Client, api: &str) -> Result<()> {
    let response = post_empty::<ConnectionResponseView>(client, api, "/v1/disconnect").await?;
    print_connection_response(&response);
    Ok(())
}

async fn run_ethersync_command(
    client: &Client,
    api: &str,
    command: EtherSyncCommands,
) -> Result<()> {
    match command {
        EtherSyncCommands::Start(args) => {
            let request = EtherSyncStartRequest {
                bind_addr: args.bind_addr,
                bootstrap_peers: if args.peer.is_empty() {
                    None
                } else {
                    Some(parse_socket_addrs(&args.peer)?)
                },
                gossip_interval_secs: args.gossip_interval_secs,
                sweep_interval_secs: args.sweep_interval_secs,
                gossip_ttl: args.gossip_ttl,
                enable_compression: Some(!args.disable_compression),
                enable_orp: Some(args.enable_orp),
            };
            let status =
                post_json::<DoctorEtherSyncStatus, _>(client, api, "/v1/ethersync/start", &request)
                    .await?;
            print_ethersync_status(&status);
        }
        EtherSyncCommands::Stop => {
            let status =
                post_empty::<DoctorEtherSyncStatus>(client, api, "/v1/ethersync/stop").await?;
            print_ethersync_status(&status);
        }
        EtherSyncCommands::Status { json } => {
            let value = get_json_value(client, api, "/v1/ethersync/status").await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else {
                let status: DoctorEtherSyncStatus = serde_json::from_value(value)?;
                print_ethersync_status(&status);
            }
        }
        EtherSyncCommands::AddPeer { addr } => {
            let request = EtherSyncPeerAddRequest { addr };
            let status = post_json::<DoctorEtherSyncStatus, _>(
                client,
                api,
                "/v1/ethersync/peers/add",
                &request,
            )
            .await?;
            print_ethersync_status(&status);
        }
        EtherSyncCommands::Join(args) => {
            let request = EtherSyncJoinRequest {
                passphrase: args.passphrase,
                label: args.label,
                retention_tier: args.retention_tier,
                replication_factor: args.replication_factor,
                route_bias: args.route_bias,
            };
            let response = post_json::<EtherSyncJoinResultView, _>(
                client,
                api,
                "/v1/ethersync/spaces/join",
                &request,
            )
            .await?;
            print_join_result(&response);
        }
        EtherSyncCommands::Leave { passphrase, label } => {
            let request = EtherSyncLeaveRequest { passphrase, label };
            let response = post_json::<EtherSyncLeaveResultView, _>(
                client,
                api,
                "/v1/ethersync/spaces/leave",
                &request,
            )
            .await?;
            println!(
                "Left space {} (unsubscribed={}, orp_stopped={})",
                response.space_id,
                bool_label(response.unsubscribed),
                bool_label(response.orp_stopped)
            );
        }
        EtherSyncCommands::Publish(args) => {
            let request = EtherSyncPublishRequest {
                passphrase: args.passphrase,
                payload_b64: args.payload_b64,
                message: args.message,
            };
            let response = post_json::<EtherSyncPublishResultView, _>(
                client,
                api,
                "/v1/ethersync/spaces/publish",
                &request,
            )
            .await?;
            println!(
                "Published {} bytes to {} in slot {}",
                response.payload_len, response.space_id, response.slot_id
            );
        }
        EtherSyncCommands::PublishFile(args) => {
            let file_bytes = std::fs::read(&args.path)?;
            let filename = args.filename.unwrap_or_else(|| {
                args.path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("file.bin")
                    .to_string()
            });
            let request = EtherSyncPublishFileRequest {
                passphrase: args.passphrase,
                filename,
                file_b64: general_purpose::STANDARD.encode(file_bytes),
                chunk_size: args.chunk_size,
            };
            let response = post_json::<EtherSyncFilePublishResultView, _>(
                client,
                api,
                "/v1/ethersync/files/publish",
                &request,
            )
            .await?;
            println!(
                "Published file {} to {} (chunks={}/{}, bytes={}) transfer_id={}",
                response.filename,
                response.space_id,
                response.published_chunks,
                response.total_chunks,
                response.total_bytes,
                response.transfer_id
            );
        }
        EtherSyncCommands::Backfill {
            passphrase,
            max_messages,
        } => {
            let request = KeeperBackfillRequest {
                passphrase,
                max_messages,
            };
            let response = post_json::<KeeperBackfillResultView, _>(
                client,
                api,
                "/v1/keepers/backfill",
                &request,
            )
            .await?;
            println!(
                "Backfill for {} restored={} remaining_pending={} stage={}",
                response.space_id,
                response.restored_messages,
                response.remaining_pending,
                empty_fallback(&response.keeper_manifest.replication_stage, "unknown"),
            );
        }
        EtherSyncCommands::Policies { json } => {
            let value = get_json_value(client, api, "/v1/keepers/policies").await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else {
                let policies: Vec<SpacePolicySnapshotView> = serde_json::from_value(value)?;
                print_policies(&policies);
            }
        }
        EtherSyncCommands::SetPolicy(args) => {
            let request = KeeperPolicyUpdateRequest {
                passphrase: args.passphrase,
                retention_tier: args.retention_tier,
                replication_factor: args.replication_factor,
                route_bias: args.route_bias,
            };
            let policy = post_json::<SpacePolicySnapshotView, _>(
                client,
                api,
                "/v1/keepers/policies",
                &request,
            )
            .await?;
            print_policies(&[policy]);
        }
    }

    Ok(())
}

async fn watch_ethersync_events(
    client: &Client,
    api: &str,
    raw: bool,
    show_keepalive: bool,
) -> Result<()> {
    let url = format!("{}/v1/ethersync/events", api);
    let mut response = ensure_success(client.get(url).send().await?).await?;

    println!("Watching EtherSync events. Press Ctrl+C to stop.");
    let mut buffer = String::new();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!();
                println!("Event watch stopped.");
                break;
            }
            chunk = response.chunk() => {
                let Some(chunk) = chunk? else {
                    println!("Event stream closed.");
                    break;
                };
                let text = String::from_utf8_lossy(&chunk).replace("\r\n", "\n");
                buffer.push_str(&text);
                while let Some(frame) = take_sse_frame(&mut buffer) {
                    print_sse_frame(&frame, raw, show_keepalive)?;
                }
            }
        }
    }

    Ok(())
}

fn take_sse_frame(buffer: &mut String) -> Option<String> {
    let idx = buffer.find("\n\n")?;
    let frame = buffer[..idx].to_string();
    let rest = buffer[idx + 2..].to_string();
    *buffer = rest;
    Some(frame)
}

fn print_sse_frame(frame: &str, raw: bool, show_keepalive: bool) -> Result<()> {
    let mut event_name = "message".to_string();
    let mut data_lines = Vec::new();

    for line in frame.lines() {
        if let Some(value) = line.strip_prefix("event:") {
            event_name = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("data:") {
            data_lines.push(value.trim_start().to_string());
        }
    }

    if event_name == "keepalive" && !show_keepalive {
        return Ok(());
    }

    let data = data_lines.join("\n");
    if raw {
        println!("[{}] {}", event_name, data);
        return Ok(());
    }

    if event_name == "keepalive" {
        println!("[keepalive] {}", data);
        return Ok(());
    }

    match serde_json::from_str::<EtherSyncEventView>(&data) {
        Ok(event) => {
            let mut details = Vec::new();
            if let Some(space_id) = event.space_id.as_deref() {
                details.push(format!("space={}", space_id));
            }
            if let Some(slot_id) = event.slot_id {
                details.push(format!("slot={}", slot_id));
            }
            if let Some(info) = event.info.as_deref() {
                details.push(info.to_string());
            }
            if let Some(text) = event.text.as_deref() {
                details.push(format!("text={}", truncate_for_display(text, 120)));
            }
            if let Some(error) = event.error.as_deref() {
                details.push(format!("error={}", truncate_for_display(error, 120)));
            }
            if event.payload_b64.is_some() && event.kind == "space_file_chunk" {
                details.push("payload=file-chunk".to_string());
            }
            if details.is_empty() {
                println!("[{}] ts_ms={}", event.kind, event.ts_ms);
            } else {
                println!("[{}] {}", event.kind, details.join(" | "));
            }
        }
        Err(_) => println!("[{}] {}", event_name, data),
    }

    Ok(())
}

async fn get_json<T>(client: &Client, api: &str, path: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    let response = client.get(format!("{api}{path}")).send().await?;
    decode_response::<T>(response).await
}

async fn get_json_value(client: &Client, api: &str, path: &str) -> Result<Value> {
    get_json::<Value>(client, api, path).await
}

async fn post_json<T, B>(client: &Client, api: &str, path: &str, body: &B) -> Result<T>
where
    T: DeserializeOwned,
    B: Serialize + ?Sized,
{
    let response = client
        .post(format!("{api}{path}"))
        .json(body)
        .send()
        .await?;
    decode_response::<T>(response).await
}

async fn post_empty<T>(client: &Client, api: &str, path: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    let response = client.post(format!("{api}{path}")).send().await?;
    decode_response::<T>(response).await
}

async fn decode_response<T>(response: Response) -> Result<T>
where
    T: DeserializeOwned,
{
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        if let Ok(api_error) = serde_json::from_str::<ApiErrorBody>(&body) {
            let details = api_error
                .details
                .map(|value| format!(" details={}", truncate_for_display(&value.to_string(), 200)))
                .unwrap_or_default();
            return Err(anyhow!(
                "{} {} (code={}){}",
                status,
                api_error.message,
                api_error.code,
                details
            ));
        }
        let detail = if body.trim().is_empty() {
            status.to_string()
        } else {
            format!("{} {}", status, truncate_for_display(&body, 200))
        };
        return Err(anyhow!(detail));
    }
    Ok(serde_json::from_str(&body)?)
}

async fn ensure_success(response: Response) -> Result<Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = response.text().await?;
    if let Ok(api_error) = serde_json::from_str::<ApiErrorBody>(&body) {
        return Err(anyhow!("{} {}", status, api_error.message));
    }
    Err(anyhow!("{} {}", status, truncate_for_display(&body, 200)))
}

async fn run_doctor(client: &Client, api: &str, token_present: bool) -> DoctorReport {
    let mut report = DoctorReport::new(api, token_present);

    let status = match get_json::<ConnectionResponseView>(client, api, "/v1/status").await {
        Ok(status) => {
            let peer = status.peer.clone().unwrap_or_else(|| "n/a".to_string());
            let port = status
                .port
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string());
            report.push(
                "api",
                DoctorLevel::Ok,
                format!(
                    "reachable; status={} mode={} privacy={} port={} peer={}",
                    empty_fallback(&status.status, "unknown"),
                    empty_fallback(&status.mode, "unknown"),
                    empty_fallback(&status.privacy_profile, "unknown"),
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

    match get_json::<DoctorCapabilities>(client, api, "/v1/capabilities").await {
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
                    empty_fallback(&cap.bootstrap_bundle_trust_posture, "unknown"),
                ),
            );
        }
        Err(err) => report.push("capabilities", DoctorLevel::Error, err.to_string()),
    }

    match get_json::<DoctorEtherSyncStatus>(client, api, "/v1/ethersync/status").await {
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
                    "running={} peers={} subscriptions={} spaces={} bridge-bootstrap={} keeper={} high-risk={}",
                    bool_label(status.running),
                    status.peer_count,
                    status.subscription_count,
                    status.spaces.len(),
                    bool_label(status.bridge_bootstrap_enabled),
                    bool_label(status.keeper_replication_enabled),
                    bool_label(status.high_risk_available),
                ),
            );
        }
        Err(err) => report.push("ethersync", DoctorLevel::Warn, err.to_string()),
    }

    match get_json::<DoctorRoutesStatus>(client, api, "/v1/routes/status").await {
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

    match get_json::<DoctorKeeperStatus>(client, api, "/v1/keepers/status").await {
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

fn print_doctor_report(report: &DoctorReport) {
    println!("Doctor report for {}", report.api);
    println!(
        "Auth token: {}",
        if report.token_present {
            "present"
        } else {
            "not set"
        }
    );
    println!();

    for check in &report.checks {
        println!(
            "[{}] {:<14} {}",
            doctor_level_label(&check.level),
            check.name,
            check.detail
        );
    }

    println!();
    if report.has_errors() {
        println!("Doctor result: errors present");
    } else if report.has_warnings() {
        println!("Doctor result: warnings present");
    } else {
        println!("Doctor result: ok");
    }
}

fn print_connection_response(response: &ConnectionResponseView) {
    println!(
        "Connection: status={} mode={} privacy={} port={} peer={}",
        empty_fallback(&response.status, "unknown"),
        empty_fallback(&response.mode, "unknown"),
        empty_fallback(&response.privacy_profile, "unknown"),
        response
            .port
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string()),
        response
            .peer
            .as_deref()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    );
    if let Some(resume_status) = response.resume_status.as_deref() {
        println!("Resume status: {}", resume_status);
    }
}

fn print_ethersync_status(status: &DoctorEtherSyncStatus) {
    println!(
        "EtherSync: running={} bind={} local={} peers={} subscriptions={} spaces={}",
        bool_label(status.running),
        status.bind_addr.as_deref().unwrap_or("n/a"),
        status.local_addr.as_deref().unwrap_or("n/a"),
        status.peer_count,
        status.subscription_count,
        status.spaces.len()
    );
    println!(
        "EtherSync ORP: enabled={} route-cache={} route-offers={} high-risk={} trust={}",
        bool_label(status.orp_enabled),
        status.route_cache_size,
        status.route_offers_count,
        bool_label(status.high_risk_available),
        empty_fallback(&status.bootstrap_bundle_trust_posture, "unknown"),
    );
    if !status.high_risk_gate_reasons.is_empty() {
        println!(
            "EtherSync high-risk gate reasons: {}",
            status.high_risk_gate_reasons.join("; ")
        );
    }
    println!(
        "Keepers: enabled={} retention={} pending={} archived={} receipts={} failed={}",
        bool_label(status.keeper_replication_enabled),
        empty_fallback(&status.retention_tier, "unknown"),
        status.pending_keeper_envelopes,
        status.archived_keeper_envelopes,
        status.remote_keeper_receipts,
        status.failed_remote_send_envelopes
    );
    if !status.spaces.is_empty() {
        println!("Spaces: {}", status.spaces.join(", "));
    }
}

fn print_join_result(response: &EtherSyncJoinResultView) {
    println!(
        "Joined {} retention={} replication={} route-bias={}",
        response.space_id,
        empty_fallback(&response.retention_tier, "unknown"),
        response.replication_factor,
        empty_fallback(&response.route_bias, "balanced")
    );
    println!(
        "Keeper manifest: managed={} intent={} desired={} selected={} acked={} stage={}",
        bool_label(response.keeper_manifest.managed),
        empty_fallback(&response.keeper_manifest.keeper_route_intent, "unknown"),
        response.keeper_manifest.desired_replica_count,
        response.keeper_manifest.selected_keeper_targets,
        response.keeper_manifest.acknowledged_keeper_targets,
        empty_fallback(&response.keeper_manifest.replication_stage, "unknown")
    );
}

fn print_policies(policies: &[SpacePolicySnapshotView]) {
    if policies.is_empty() {
        println!("No EtherSync space policies configured.");
        return;
    }

    println!("EtherSync space policies:");
    for policy in policies {
        println!(
            "- {} retention={} replication={} route-bias={} pending={} archived={} keepers={}/{} delivered={}",
            policy.space_key,
            empty_fallback(&policy.retention_tier, "unknown"),
            policy.replication_factor,
            empty_fallback(&policy.route_bias, "balanced"),
            policy.pending_keeper_envelopes,
            policy.archived_keeper_envelopes,
            policy.remote_keeper_receipts,
            policy.remote_keeper_targets,
            policy.remote_keeper_delivered_envelopes
        );
        println!(
            "  manifest managed={} intent={} desired={} selected={} acked={} shortfall={} stage={}",
            bool_label(policy.keeper_manifest.managed),
            empty_fallback(&policy.keeper_manifest.keeper_route_intent, "unknown"),
            policy.keeper_manifest.desired_replica_count,
            policy.keeper_manifest.selected_keeper_targets,
            policy.keeper_manifest.acknowledged_keeper_targets,
            policy.keeper_manifest.candidate_shortfall,
            empty_fallback(&policy.keeper_manifest.replication_stage, "unknown")
        );
    }
}

fn doctor_level_label(level: &DoctorLevel) -> &'static str {
    match level {
        DoctorLevel::Ok => "OK",
        DoctorLevel::Warn => "WARN",
        DoctorLevel::Error => "ERR",
    }
}

fn bool_label(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn empty_fallback<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback
    } else {
        trimmed
    }
}

fn truncate_for_display(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{}...", truncated)
    } else {
        truncated
    }
}

fn random_passphrase() -> String {
    let mut bytes = [0u8; 18];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn remote_http_api_warning(api: &str) -> Option<String> {
    let url = Url::parse(api).ok()?;
    if url.scheme() != "http" {
        return None;
    }
    let host = url.host_str()?;
    if host.eq_ignore_ascii_case("localhost") {
        return None;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_loopback() {
            return None;
        }
    }
    Some(format!(
        "{} uses plain HTTP to a non-local API host; bearer token and commands travel without TLS",
        api
    ))
}

fn resolve_api_token(args: &Args) -> Result<Option<String>> {
    if let Some(token) = args
        .token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(Some(token.to_string()));
    }

    if let Some(path) = args
        .token_file
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        let token = std::fs::read_to_string(path)?;
        let token = token.trim().to_string();
        if !token.is_empty() {
            return Ok(Some(token));
        }
    }

    if let Ok(path) = std::env::var("HANDSHACKE_API_TOKEN_FILE") {
        let path = path.trim();
        if !path.is_empty() {
            let token = std::fs::read_to_string(path)?;
            let token = token.trim().to_string();
            if !token.is_empty() {
                return Ok(Some(token));
            }
        }
    }

    Ok(std::env::var("HANDSHACKE_API_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty()))
}

fn prompt_required(label: &str) -> Result<String> {
    match prompt_line(label)? {
        Some(value) => Ok(value),
        None => Err(anyhow!("{} is required", label)),
    }
}

fn prompt_optional(label: &str) -> Result<Option<String>> {
    prompt_line(label)
}

fn prompt_with_default(label: &str, default: &str) -> Result<String> {
    Ok(prompt_line(&format!("{} [{}]", label, default))?.unwrap_or_else(|| default.to_string()))
}

fn prompt_bool(label: &str, default: bool) -> Result<bool> {
    let default_hint = if default { "Y/n" } else { "y/N" };
    loop {
        match prompt_line(&format!("{} [{}]", label, default_hint))? {
            None => return Ok(default),
            Some(value) => match value.trim().to_ascii_lowercase().as_str() {
                "y" | "yes" | "true" | "1" => return Ok(true),
                "n" | "no" | "false" | "0" => return Ok(false),
                _ => {
                    println!("Enter yes or no.");
                }
            },
        }
    }
}

fn prompt_line(label: &str) -> Result<Option<String>> {
    print!("{}: ", label);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed))
    }
}

fn split_csv(input: String) -> Vec<String> {
    input
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .collect()
}

fn parse_socket_addrs(values: &[String]) -> Result<Vec<String>> {
    let mut addrs = Vec::with_capacity(values.len());
    for value in values {
        let parsed: SocketAddr = value
            .parse()
            .map_err(|_| anyhow!("Invalid socket address: {}", value))?;
        addrs.push(parsed.to_string());
    }
    Ok(addrs)
}
