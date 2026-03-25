use serde::{Deserialize, Serialize};

use crate::config::Config;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BootstrapBundle {
    pub version: u8,
    pub generated_at_ms: Option<u64>,
    #[serde(default)]
    pub mirrors: Vec<String>,
    #[serde(default)]
    pub relays: Vec<BootstrapRelay>,
    #[serde(default)]
    pub bridges: Vec<BootstrapBridge>,
    #[serde(default)]
    pub keepers: Vec<BootstrapKeeper>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapRelay {
    pub id: String,
    pub addr: String,
    pub operator_id: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapBridge {
    pub id: String,
    pub endpoint: String,
    pub operator_id: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapKeeper {
    pub id: String,
    pub endpoint: String,
    pub operator_id: Option<String>,
    pub region: Option<String>,
    pub replication_factor: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BootstrapBundleSummary {
    pub loaded: bool,
    pub mirrors: usize,
    pub relays: usize,
    pub bridges: usize,
    pub keepers: usize,
}

impl BootstrapBundle {
    pub fn summary(&self) -> BootstrapBundleSummary {
        BootstrapBundleSummary {
            loaded: true,
            mirrors: self.mirrors.len(),
            relays: self.relays.len(),
            bridges: self.bridges.len(),
            keepers: self.keepers.len(),
        }
    }
}

pub fn load_bootstrap_bundle(cfg: &Config) -> Option<BootstrapBundle> {
    if let Some(inline) = cfg.bootstrap_bundle_json.as_deref() {
        match serde_json::from_str::<BootstrapBundle>(inline) {
            Ok(bundle) => return Some(bundle),
            Err(err) => {
                tracing::warn!("failed to parse HANDSHACKE_BOOTSTRAP_BUNDLE_JSON: {}", err);
            }
        }
    }

    let path = cfg.bootstrap_bundle_path.as_deref()?;
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            tracing::warn!("failed to read bootstrap bundle {}: {}", path, err);
            return None;
        }
    };

    match serde_json::from_str::<BootstrapBundle>(&content) {
        Ok(bundle) => Some(bundle),
        Err(err) => {
            tracing::warn!("failed to parse bootstrap bundle {}: {}", path, err);
            None
        }
    }
}

pub fn summarize_bootstrap_bundle(cfg: &Config) -> BootstrapBundleSummary {
    load_bootstrap_bundle(cfg)
        .map(|bundle| bundle.summary())
        .unwrap_or_default()
}
