use anyhow::Result;
use clap::{Parser, Subcommand};
use handshacke as hs;
use rand::RngCore;
use std::io::Write;

#[derive(Parser)]
#[command(
    name = "handshacke",
    version,
    about = "Deterministic P2P communication without servers"
)]
struct Args {
    #[arg(long)]
    unsafe_expose_api: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Onionize(hs::cli::onionize::OnionizeArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    if let Some(Commands::Onionize(cmd)) = args.command {
        return hs::cli::onionize::run(cmd).await;
    }

    tracing::info!("🚀 Avvio Handshacke Core...");

    // Load configuration
    let config = hs::config::Config::from_env();
    tracing::info!("📋 Configuration loaded: API bind on {}", config.api_bind);
    if config.api_bind.starts_with("0.0.0.0") && !args.unsafe_expose_api {
        anyhow::bail!("Refusing to bind API to 0.0.0.0 without --unsafe-expose-api");
    }
    // Always require auth for the API. This prevents the API from becoming
    // a "decrypt oracle" for third parties (e.g. drive-by localhost access from a browser).
    let needs_token = true;
    let api_token = if needs_token {
        let token = std::env::var("HANDSHACKE_API_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                let mut bytes = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut bytes);
                hex::encode(bytes)
            });
        tracing::info!("API auth enabled (bearer token required)");
        if let Ok(path) = std::env::var("HANDSHACKE_API_TOKEN_FILE") {
            if let Err(e) = write_token_file(&path, &token) {
                tracing::warn!("Failed to write API token file: {:?}", e);
            } else if cfg!(windows) {
                tracing::info!(
                    "Token file written (Windows: ensure directory ACLs are restricted)"
                );
            }
        }
        Some(token)
    } else {
        None
    };

    let app_state = hs::state::AppState::default();
    let (streams, _rx_out_spawn_discard) = hs::api::Streams::new();

    hs::api::create_api_server(app_state, streams, config.api_bind.clone(), api_token).await?;

    Ok(())
}

fn write_token_file(path: &str, token: &str) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    writeln!(file, "{}", token)?;
    Ok(())
}
