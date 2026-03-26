use base64::{engine::general_purpose, Engine as _};
use ring::signature::{self, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{BootstrapTrustedKey, Config};

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<BootstrapBundleSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapBundleSignature {
    pub algorithm: String,
    pub signature: String,
    #[serde(default)]
    pub key_id: Option<String>,
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
    UnsignedBundle,
    UntrustedSignature,
    InvalidSignature,
    UnsupportedSignatureAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootstrapBundleTrustPosture {
    Unsigned,
    SignedUntrusted,
    VerifiedTrusted,
    InvalidSignature,
    UnsupportedAlgorithm,
}

impl BootstrapBundleTrustPosture {
    pub fn is_verified_trusted(&self) -> bool {
        matches!(self, Self::VerifiedTrusted)
    }
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
    pub trust_posture: BootstrapBundleTrustPosture,
    pub trusted_for_high_risk: bool,
    pub trusted_keys_configured: usize,
    pub signature_present: bool,
    pub signature_algorithm: Option<String>,
    pub signature_key_id: Option<String>,
    pub trusted_key_id: Option<String>,
    pub issue_counts: BootstrapBundleValidationIssueCounts,
    pub issues: Vec<BootstrapBundleValidationIssue>,
}

impl BootstrapBundleValidationReport {
    pub fn trusted_for_runtime_high_risk(&self) -> bool {
        self.trusted_for_high_risk && !self.staleness.is_stale()
    }
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

    pub fn validation_report_with_config(&self, cfg: &Config) -> BootstrapBundleValidationReport {
        validate_bootstrap_bundle_with_config(self, cfg)
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
    validate_bootstrap_bundle_with_trusted_keys_at(
        bundle,
        &[],
        current_time_ms(),
        DEFAULT_BOOTSTRAP_BUNDLE_STALE_AFTER_MS,
    )
}

pub fn validate_bootstrap_bundle_with_config(
    bundle: &BootstrapBundle,
    cfg: &Config,
) -> BootstrapBundleValidationReport {
    validate_bootstrap_bundle_with_trusted_keys_at(
        bundle,
        &cfg.bootstrap_bundle_trusted_keys,
        current_time_ms(),
        DEFAULT_BOOTSTRAP_BUNDLE_STALE_AFTER_MS,
    )
}

pub fn validate_bootstrap_bundle_at(
    bundle: &BootstrapBundle,
    checked_at_ms: u64,
    stale_after_ms: u64,
) -> BootstrapBundleValidationReport {
    validate_bootstrap_bundle_with_trusted_keys_at(bundle, &[], checked_at_ms, stale_after_ms)
}

pub fn validate_bootstrap_bundle_with_config_at(
    bundle: &BootstrapBundle,
    cfg: &Config,
    checked_at_ms: u64,
    stale_after_ms: u64,
) -> BootstrapBundleValidationReport {
    validate_bootstrap_bundle_with_trusted_keys_at(
        bundle,
        &cfg.bootstrap_bundle_trusted_keys,
        checked_at_ms,
        stale_after_ms,
    )
}

fn validate_bootstrap_bundle_with_trusted_keys_at(
    bundle: &BootstrapBundle,
    trusted_keys: &[BootstrapTrustedKey],
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
    let trust = evaluate_bundle_trust(bundle, trusted_keys);
    match trust.posture {
        BootstrapBundleTrustPosture::Unsigned => push_issue(
            &mut issues,
            &mut counts,
            BootstrapBundleValidationIssue {
                kind: BootstrapBundleValidationKind::UnsignedBundle,
                severity: BootstrapBundleValidationSeverity::Warning,
                entry_kind: None,
                entry_index: None,
                field: Some("signature".to_owned()),
                value: None,
                message: "bootstrap bundle is unsigned; runtime may only use it as opaque ingress assist and must not treat it as trusted for high-risk routing".to_owned(),
            },
        ),
        BootstrapBundleTrustPosture::SignedUntrusted => push_issue(
            &mut issues,
            &mut counts,
            BootstrapBundleValidationIssue {
                kind: BootstrapBundleValidationKind::UntrustedSignature,
                severity: BootstrapBundleValidationSeverity::Warning,
                entry_kind: None,
                entry_index: None,
                field: Some("signature".to_owned()),
                value: trust.signature_key_id.clone(),
                message: trust.failure_reason.clone().unwrap_or_else(|| {
                    "bootstrap bundle signature did not match any configured trusted key"
                        .to_owned()
                }),
            },
        ),
        BootstrapBundleTrustPosture::InvalidSignature => push_issue(
            &mut issues,
            &mut counts,
            BootstrapBundleValidationIssue {
                kind: BootstrapBundleValidationKind::InvalidSignature,
                severity: BootstrapBundleValidationSeverity::Warning,
                entry_kind: None,
                entry_index: None,
                field: Some("signature".to_owned()),
                value: trust.signature_key_id.clone(),
                message: trust.failure_reason.clone().unwrap_or_else(|| {
                    "bootstrap bundle signature is present but invalid".to_owned()
                }),
            },
        ),
        BootstrapBundleTrustPosture::UnsupportedAlgorithm => push_issue(
            &mut issues,
            &mut counts,
            BootstrapBundleValidationIssue {
                kind: BootstrapBundleValidationKind::UnsupportedSignatureAlgorithm,
                severity: BootstrapBundleValidationSeverity::Warning,
                entry_kind: None,
                entry_index: None,
                field: Some("signature.algorithm".to_owned()),
                value: trust.signature_algorithm.clone(),
                message: trust.failure_reason.clone().unwrap_or_else(|| {
                    "bootstrap bundle signature algorithm is unsupported".to_owned()
                }),
            },
        ),
        BootstrapBundleTrustPosture::VerifiedTrusted => {}
    }
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
        trust_posture: trust.posture,
        trusted_for_high_risk: trust.posture.is_verified_trusted(),
        trusted_keys_configured: trusted_keys.len(),
        signature_present: trust.signature_present,
        signature_algorithm: trust.signature_algorithm,
        signature_key_id: trust.signature_key_id,
        trusted_key_id: trust.trusted_key_id,
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
    load_bootstrap_bundle(cfg).map(|bundle| validate_bootstrap_bundle_with_config(&bundle, cfg))
}

pub fn bootstrap_bundle_is_usable(bundle: &BootstrapBundle) -> bool {
    bundle.validation_report().is_usable
}

pub fn bootstrap_bundle_is_trusted_for_high_risk(bundle: &BootstrapBundle, cfg: &Config) -> bool {
    validate_bootstrap_bundle_with_config(bundle, cfg).trusted_for_runtime_high_risk()
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

#[derive(Debug, Clone)]
struct BundleTrustEvaluation {
    posture: BootstrapBundleTrustPosture,
    signature_present: bool,
    signature_algorithm: Option<String>,
    signature_key_id: Option<String>,
    trusted_key_id: Option<String>,
    failure_reason: Option<String>,
}

fn evaluate_bundle_trust(
    bundle: &BootstrapBundle,
    trusted_keys: &[BootstrapTrustedKey],
) -> BundleTrustEvaluation {
    let Some(signature) = bundle.signature.as_ref() else {
        return BundleTrustEvaluation {
            posture: BootstrapBundleTrustPosture::Unsigned,
            signature_present: false,
            signature_algorithm: None,
            signature_key_id: None,
            trusted_key_id: None,
            failure_reason: None,
        };
    };

    let algorithm = signature.algorithm.trim().to_ascii_lowercase();
    if algorithm != "ed25519" {
        return BundleTrustEvaluation {
            posture: BootstrapBundleTrustPosture::UnsupportedAlgorithm,
            signature_present: true,
            signature_algorithm: Some(signature.algorithm.clone()),
            signature_key_id: signature.key_id.clone(),
            trusted_key_id: None,
            failure_reason: Some(format!(
                "unsupported bootstrap bundle signature algorithm '{}'; only ed25519 is currently accepted",
                signature.algorithm
            )),
        };
    }

    let canonical_payload = match canonical_bundle_payload(bundle) {
        Ok(payload) => payload,
        Err(err) => {
            return BundleTrustEvaluation {
                posture: BootstrapBundleTrustPosture::InvalidSignature,
                signature_present: true,
                signature_algorithm: Some(signature.algorithm.clone()),
                signature_key_id: signature.key_id.clone(),
                trusted_key_id: None,
                failure_reason: Some(format!(
                    "failed to canonicalize bootstrap bundle payload before signature verification: {}",
                    err
                )),
            };
        }
    };

    let signature_bytes = match decode_material(&signature.signature) {
        Ok(bytes) => bytes,
        Err(err) => {
            return BundleTrustEvaluation {
                posture: BootstrapBundleTrustPosture::InvalidSignature,
                signature_present: true,
                signature_algorithm: Some(signature.algorithm.clone()),
                signature_key_id: signature.key_id.clone(),
                trusted_key_id: None,
                failure_reason: Some(format!(
                    "bootstrap bundle signature could not be decoded: {}",
                    err
                )),
            };
        }
    };

    if trusted_keys.is_empty() {
        return BundleTrustEvaluation {
            posture: BootstrapBundleTrustPosture::SignedUntrusted,
            signature_present: true,
            signature_algorithm: Some(signature.algorithm.clone()),
            signature_key_id: signature.key_id.clone(),
            trusted_key_id: None,
            failure_reason: Some(
                "bootstrap bundle is signed but no trusted bundle keys are configured locally"
                    .to_owned(),
            ),
        };
    }

    let mut saw_candidate_key = false;
    for trusted_key in trusted_keys.iter().filter(|trusted_key| {
        signature
            .key_id
            .as_deref()
            .map(|key_id| trusted_key.key_id.as_deref() == Some(key_id.trim()))
            .unwrap_or(true)
    }) {
        saw_candidate_key = true;
        let public_key = match decode_material(&trusted_key.public_key) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let verifier = UnparsedPublicKey::new(&signature::ED25519, public_key);
        if verifier
            .verify(&canonical_payload, &signature_bytes)
            .is_ok()
        {
            return BundleTrustEvaluation {
                posture: BootstrapBundleTrustPosture::VerifiedTrusted,
                signature_present: true,
                signature_algorithm: Some(signature.algorithm.clone()),
                signature_key_id: signature.key_id.clone(),
                trusted_key_id: trusted_key.key_id.clone(),
                failure_reason: None,
            };
        }
    }

    let posture = if saw_candidate_key && signature.key_id.is_some() {
        BootstrapBundleTrustPosture::InvalidSignature
    } else {
        BootstrapBundleTrustPosture::SignedUntrusted
    };

    BundleTrustEvaluation {
        posture,
        signature_present: true,
        signature_algorithm: Some(signature.algorithm.clone()),
        signature_key_id: signature.key_id.clone(),
        trusted_key_id: None,
        failure_reason: Some(if saw_candidate_key {
            "bootstrap bundle signature did not verify against any configured trusted key"
                .to_owned()
        } else if let Some(key_id) = signature.key_id.as_deref() {
            format!(
                "bootstrap bundle references key id '{}' but no matching trusted key is configured locally",
                key_id
            )
        } else {
            "bootstrap bundle signature did not match any configured trusted key".to_owned()
        }),
    }
}

fn canonical_bundle_payload(bundle: &BootstrapBundle) -> Result<Vec<u8>, serde_json::Error> {
    let mut unsigned = bundle.clone();
    unsigned.signature = None;
    let value = serde_json::to_value(unsigned)?;
    let canonical = canonicalize_json_value(value);
    serde_json::to_vec(&canonical)
}

fn canonicalize_json_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries = map.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut ordered = Map::new();
            for (key, value) in entries {
                ordered.insert(key, canonicalize_json_value(value));
            }
            Value::Object(ordered)
        }
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(canonicalize_json_value)
                .collect::<Vec<_>>(),
        ),
        other => other,
    }
}

fn decode_material(raw: &str) -> Result<Vec<u8>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty material".to_owned());
    }

    if trimmed.len() % 2 == 0 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return hex::decode(trimmed).map_err(|err| err.to_string());
    }

    general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|err| err.to_string())
}
