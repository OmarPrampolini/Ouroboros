use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootstrapBundleEntryKind {
    Relay,
    Bridge,
    Keeper,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootstrapBundleValidationSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootstrapBundleValidationKind {
    EmptyBundle,
    MissingId,
    MissingEndpoint,
    DuplicateId,
    DuplicateEndpoint,
    StaleBundle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootstrapBundleStaleness {
    Unknown,
    Fresh { age_ms: u64 },
    Stale { age_ms: u64, stale_after_ms: u64 },
}

impl BootstrapBundleStaleness {
    pub fn is_stale(&self) -> bool {
        matches!(self, Self::Stale { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapBundleValidationIssue {
    pub kind: BootstrapBundleValidationKind,
    pub severity: BootstrapBundleValidationSeverity,
    pub entry_kind: Option<BootstrapBundleEntryKind>,
    pub entry_index: Option<usize>,
    pub field: Option<String>,
    pub value: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BootstrapBundleValidationIssueCounts {
    pub info: usize,
    pub warning: usize,
    pub error: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapBundleValidationReport {
    pub summary: BootstrapBundleSummary,
    pub checked_at_ms: u64,
    pub generated_at_ms: Option<u64>,
    pub stale_after_ms: u64,
    pub staleness: BootstrapBundleStaleness,
    pub is_empty: bool,
    pub is_usable: bool,
    pub is_structurally_weak: bool,
    pub issue_counts: BootstrapBundleValidationIssueCounts,
    pub issues: Vec<BootstrapBundleValidationIssue>,
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

    pub fn validation_report(&self) -> BootstrapBundleValidationReport {
        validate_bootstrap_bundle(self)
    }

    pub fn validation_report_at(
        &self,
        checked_at_ms: u64,
        stale_after_ms: u64,
    ) -> BootstrapBundleValidationReport {
        validate_bootstrap_bundle_at(self, checked_at_ms, stale_after_ms)
    }

    pub fn is_usable(&self) -> bool {
        self.validation_report().is_usable
    }

    pub fn is_structurally_weak(&self) -> bool {
        self.validation_report().is_structurally_weak
    }

    pub fn is_stale(&self) -> bool {
        self.validation_report().staleness.is_stale()
    }
}

pub const DEFAULT_BOOTSTRAP_BUNDLE_STALE_AFTER_MS: u64 = 30 * 24 * 60 * 60 * 1000;

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

pub fn validate_bootstrap_bundle(bundle: &BootstrapBundle) -> BootstrapBundleValidationReport {
    validate_bootstrap_bundle_at(
        bundle,
        current_time_ms(),
        DEFAULT_BOOTSTRAP_BUNDLE_STALE_AFTER_MS,
    )
}

pub fn validate_bootstrap_bundle_at(
    bundle: &BootstrapBundle,
    checked_at_ms: u64,
    stale_after_ms: u64,
) -> BootstrapBundleValidationReport {
    let summary = bundle.summary();
    let mut issues = Vec::new();
    let mut counts = BootstrapBundleValidationIssueCounts::default();

    if bundle.relays.is_empty()
        && bundle.bridges.is_empty()
        && bundle.keepers.is_empty()
        && bundle.mirrors.is_empty()
    {
        push_issue(
            &mut issues,
            &mut counts,
            BootstrapBundleValidationIssue {
                kind: BootstrapBundleValidationKind::EmptyBundle,
                severity: BootstrapBundleValidationSeverity::Error,
                entry_kind: None,
                entry_index: None,
                field: None,
                value: None,
                message: "bootstrap bundle has no relays, bridges, keepers, or mirrors".to_owned(),
            },
        );
    }

    validate_relays(&bundle.relays, &mut issues, &mut counts);
    validate_bridges(&bundle.bridges, &mut issues, &mut counts);
    validate_keepers(&bundle.keepers, &mut issues, &mut counts);

    let staleness = match bundle.generated_at_ms {
        Some(generated_at_ms) => {
            let age_ms = checked_at_ms.saturating_sub(generated_at_ms);
            if age_ms > stale_after_ms {
                push_issue(
                    &mut issues,
                    &mut counts,
                    BootstrapBundleValidationIssue {
                        kind: BootstrapBundleValidationKind::StaleBundle,
                        severity: BootstrapBundleValidationSeverity::Info,
                        entry_kind: None,
                        entry_index: None,
                        field: Some("generated_at_ms".to_owned()),
                        value: Some(generated_at_ms.to_string()),
                        message: format!(
                            "bootstrap bundle is older than the conservative freshness threshold (age {} ms, threshold {} ms)",
                            age_ms, stale_after_ms
                        ),
                    },
                );
                BootstrapBundleStaleness::Stale {
                    age_ms,
                    stale_after_ms,
                }
            } else {
                BootstrapBundleStaleness::Fresh { age_ms }
            }
        }
        None => BootstrapBundleStaleness::Unknown,
    };

    let is_empty =
        summary.relays == 0 && summary.bridges == 0 && summary.keepers == 0 && summary.mirrors == 0;
    let is_usable = counts.error == 0;
    let is_structurally_weak = counts.warning > 0;

    BootstrapBundleValidationReport {
        summary,
        checked_at_ms,
        generated_at_ms: bundle.generated_at_ms,
        stale_after_ms,
        staleness,
        is_empty,
        is_usable,
        is_structurally_weak,
        issue_counts: counts,
        issues,
    }
}

pub fn summarize_bootstrap_bundle(cfg: &Config) -> BootstrapBundleSummary {
    load_bootstrap_bundle(cfg)
        .map(|bundle| bundle.summary())
        .unwrap_or_default()
}

pub fn validate_loaded_bootstrap_bundle(cfg: &Config) -> Option<BootstrapBundleValidationReport> {
    load_bootstrap_bundle(cfg).map(|bundle| validate_bootstrap_bundle(&bundle))
}

pub fn bootstrap_bundle_is_usable(bundle: &BootstrapBundle) -> bool {
    bundle.validation_report().is_usable
}

pub fn bootstrap_bundle_is_stale(bundle: &BootstrapBundle) -> bool {
    bundle.validation_report().staleness.is_stale()
}

pub fn bootstrap_bundle_is_structurally_weak(bundle: &BootstrapBundle) -> bool {
    bundle.validation_report().is_structurally_weak
}

fn validate_relays(
    relays: &[BootstrapRelay],
    issues: &mut Vec<BootstrapBundleValidationIssue>,
    counts: &mut BootstrapBundleValidationIssueCounts,
) {
    let mut seen_ids = HashSet::new();
    let mut seen_addrs = HashSet::new();

    for (index, relay) in relays.iter().enumerate() {
        let id = relay.id.trim();
        if id.is_empty() {
            push_issue(
                issues,
                counts,
                BootstrapBundleValidationIssue {
                    kind: BootstrapBundleValidationKind::MissingId,
                    severity: BootstrapBundleValidationSeverity::Warning,
                    entry_kind: Some(BootstrapBundleEntryKind::Relay),
                    entry_index: Some(index),
                    field: Some("id".to_owned()),
                    value: Some(relay.id.clone()),
                    message: "relay entry is missing a usable id".to_owned(),
                },
            );
        } else if !seen_ids.insert(id.to_owned()) {
            push_issue(
                issues,
                counts,
                BootstrapBundleValidationIssue {
                    kind: BootstrapBundleValidationKind::DuplicateId,
                    severity: BootstrapBundleValidationSeverity::Warning,
                    entry_kind: Some(BootstrapBundleEntryKind::Relay),
                    entry_index: Some(index),
                    field: Some("id".to_owned()),
                    value: Some(id.to_owned()),
                    message: "duplicate relay id detected".to_owned(),
                },
            );
        }

        let addr = relay.addr.trim();
        if addr.is_empty() {
            push_issue(
                issues,
                counts,
                BootstrapBundleValidationIssue {
                    kind: BootstrapBundleValidationKind::MissingEndpoint,
                    severity: BootstrapBundleValidationSeverity::Warning,
                    entry_kind: Some(BootstrapBundleEntryKind::Relay),
                    entry_index: Some(index),
                    field: Some("addr".to_owned()),
                    value: Some(relay.addr.clone()),
                    message: "relay entry is missing a usable addr".to_owned(),
                },
            );
        } else if !seen_addrs.insert(addr.to_owned()) {
            push_issue(
                issues,
                counts,
                BootstrapBundleValidationIssue {
                    kind: BootstrapBundleValidationKind::DuplicateEndpoint,
                    severity: BootstrapBundleValidationSeverity::Warning,
                    entry_kind: Some(BootstrapBundleEntryKind::Relay),
                    entry_index: Some(index),
                    field: Some("addr".to_owned()),
                    value: Some(addr.to_owned()),
                    message: "duplicate relay addr detected".to_owned(),
                },
            );
        }
    }
}

fn validate_bridges(
    bridges: &[BootstrapBridge],
    issues: &mut Vec<BootstrapBundleValidationIssue>,
    counts: &mut BootstrapBundleValidationIssueCounts,
) {
    let mut seen_ids = HashSet::new();
    let mut seen_endpoints = HashSet::new();

    for (index, bridge) in bridges.iter().enumerate() {
        let id = bridge.id.trim();
        if id.is_empty() {
            push_issue(
                issues,
                counts,
                BootstrapBundleValidationIssue {
                    kind: BootstrapBundleValidationKind::MissingId,
                    severity: BootstrapBundleValidationSeverity::Warning,
                    entry_kind: Some(BootstrapBundleEntryKind::Bridge),
                    entry_index: Some(index),
                    field: Some("id".to_owned()),
                    value: Some(bridge.id.clone()),
                    message: "bridge entry is missing a usable id".to_owned(),
                },
            );
        } else if !seen_ids.insert(id.to_owned()) {
            push_issue(
                issues,
                counts,
                BootstrapBundleValidationIssue {
                    kind: BootstrapBundleValidationKind::DuplicateId,
                    severity: BootstrapBundleValidationSeverity::Warning,
                    entry_kind: Some(BootstrapBundleEntryKind::Bridge),
                    entry_index: Some(index),
                    field: Some("id".to_owned()),
                    value: Some(id.to_owned()),
                    message: "duplicate bridge id detected".to_owned(),
                },
            );
        }

        let endpoint = bridge.endpoint.trim();
        if endpoint.is_empty() {
            push_issue(
                issues,
                counts,
                BootstrapBundleValidationIssue {
                    kind: BootstrapBundleValidationKind::MissingEndpoint,
                    severity: BootstrapBundleValidationSeverity::Warning,
                    entry_kind: Some(BootstrapBundleEntryKind::Bridge),
                    entry_index: Some(index),
                    field: Some("endpoint".to_owned()),
                    value: Some(bridge.endpoint.clone()),
                    message: "bridge entry is missing a usable endpoint".to_owned(),
                },
            );
        } else if !seen_endpoints.insert(endpoint.to_owned()) {
            push_issue(
                issues,
                counts,
                BootstrapBundleValidationIssue {
                    kind: BootstrapBundleValidationKind::DuplicateEndpoint,
                    severity: BootstrapBundleValidationSeverity::Warning,
                    entry_kind: Some(BootstrapBundleEntryKind::Bridge),
                    entry_index: Some(index),
                    field: Some("endpoint".to_owned()),
                    value: Some(endpoint.to_owned()),
                    message: "duplicate bridge endpoint detected".to_owned(),
                },
            );
        }
    }
}

fn validate_keepers(
    keepers: &[BootstrapKeeper],
    issues: &mut Vec<BootstrapBundleValidationIssue>,
    counts: &mut BootstrapBundleValidationIssueCounts,
) {
    let mut seen_ids = HashSet::new();
    let mut seen_endpoints = HashSet::new();

    for (index, keeper) in keepers.iter().enumerate() {
        let id = keeper.id.trim();
        if id.is_empty() {
            push_issue(
                issues,
                counts,
                BootstrapBundleValidationIssue {
                    kind: BootstrapBundleValidationKind::MissingId,
                    severity: BootstrapBundleValidationSeverity::Warning,
                    entry_kind: Some(BootstrapBundleEntryKind::Keeper),
                    entry_index: Some(index),
                    field: Some("id".to_owned()),
                    value: Some(keeper.id.clone()),
                    message: "keeper entry is missing a usable id".to_owned(),
                },
            );
        } else if !seen_ids.insert(id.to_owned()) {
            push_issue(
                issues,
                counts,
                BootstrapBundleValidationIssue {
                    kind: BootstrapBundleValidationKind::DuplicateId,
                    severity: BootstrapBundleValidationSeverity::Warning,
                    entry_kind: Some(BootstrapBundleEntryKind::Keeper),
                    entry_index: Some(index),
                    field: Some("id".to_owned()),
                    value: Some(id.to_owned()),
                    message: "duplicate keeper id detected".to_owned(),
                },
            );
        }

        let endpoint = keeper.endpoint.trim();
        if endpoint.is_empty() {
            push_issue(
                issues,
                counts,
                BootstrapBundleValidationIssue {
                    kind: BootstrapBundleValidationKind::MissingEndpoint,
                    severity: BootstrapBundleValidationSeverity::Warning,
                    entry_kind: Some(BootstrapBundleEntryKind::Keeper),
                    entry_index: Some(index),
                    field: Some("endpoint".to_owned()),
                    value: Some(keeper.endpoint.clone()),
                    message: "keeper entry is missing a usable endpoint".to_owned(),
                },
            );
        } else if !seen_endpoints.insert(endpoint.to_owned()) {
            push_issue(
                issues,
                counts,
                BootstrapBundleValidationIssue {
                    kind: BootstrapBundleValidationKind::DuplicateEndpoint,
                    severity: BootstrapBundleValidationSeverity::Warning,
                    entry_kind: Some(BootstrapBundleEntryKind::Keeper),
                    entry_index: Some(index),
                    field: Some("endpoint".to_owned()),
                    value: Some(endpoint.to_owned()),
                    message: "duplicate keeper endpoint detected".to_owned(),
                },
            );
        }
    }
}

fn push_issue(
    issues: &mut Vec<BootstrapBundleValidationIssue>,
    counts: &mut BootstrapBundleValidationIssueCounts,
    issue: BootstrapBundleValidationIssue,
) {
    match issue.severity {
        BootstrapBundleValidationSeverity::Info => counts.info += 1,
        BootstrapBundleValidationSeverity::Warning => counts.warning += 1,
        BootstrapBundleValidationSeverity::Error => counts.error += 1,
    }

    issues.push(issue);
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| {
            let millis = duration.as_millis();
            u64::try_from(millis).unwrap_or(u64::MAX)
        })
        .unwrap_or(0)
}
