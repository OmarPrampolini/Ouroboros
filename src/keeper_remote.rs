use crate::bootstrap_bundle::BootstrapBundle;
use ouroboros_crypto::hash::blake3_hash;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ConfirmationMode {
    LocalProjection,
    RoundTrip,
}

impl Default for ConfirmationMode {
    fn default() -> Self {
        Self::LocalProjection
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct KeeperRemoteTarget {
    pub id: String,
    pub endpoint: String,
    pub operator_id: String,
    pub region: String,
    pub capacity_hint: usize,
}

#[derive(Debug, Clone)]
pub struct KeeperRemoteEnvelopeRecord {
    pub slot_id: u64,
    pub message_digest_hex: String,
    pub message_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeeperRemoteReceipt {
    pub receipt_id: String,
    pub target_id: String,
    pub target_endpoint: String,
    pub operator_id: String,
    pub region: String,
    pub latest_slot_id: Option<u64>,
    pub observed_at_ms: u64,
    pub delivery_state: String,
    pub confirmation_mode: ConfirmationMode,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct KeeperRemoteSpaceView {
    pub selected_targets: usize,
    pub acknowledged_targets: usize,
    pub receipt_count: usize,
    pub delivered_envelopes: usize,
    pub inflight_envelopes: usize,
    pub pending_remote_send_envelopes: usize,
    pub failed_remote_send_envelopes: usize,
    pub last_remote_receipt_ms: Option<u64>,
    pub last_replication_attempt_ms: Option<u64>,
    pub delivery_state: String,
    pub confirmation_mode: ConfirmationMode,
    pub targets: Vec<KeeperRemoteTarget>,
}

#[derive(Debug, Clone, Default)]
pub struct KeeperRemoteAggregateStatus {
    pub space_count: usize,
    pub acknowledged_space_count: usize,
    pub selected_targets: usize,
    pub acknowledged_targets: usize,
    pub receipt_count: usize,
    pub delivered_envelopes: usize,
    pub pending_remote_send_envelopes: usize,
    pub failed_remote_send_envelopes: usize,
    pub last_remote_receipt_ms: Option<u64>,
    pub confirmation_mode: ConfirmationMode,
}

#[derive(Debug, Clone, Default)]
pub struct KeeperRemoteReconcilePlan {
    pub selected_targets: usize,
    pub acknowledged_targets: usize,
    pub pending_sends: Vec<KeeperRemoteSendPlan>,
}

#[derive(Debug, Clone)]
pub struct KeeperRemoteSendPlan {
    pub target: KeeperRemoteTarget,
    pub envelope: KeeperRemoteEnvelopeRecord,
}

#[derive(Debug, Clone)]
pub struct KeeperRemoteSendResult {
    pub target: KeeperRemoteTarget,
    pub envelope: KeeperRemoteEnvelopeRecord,
    pub receipt_id: Option<String>,
    pub stored_at_ms: Option<u64>,
    pub confirmed_digest: Option<String>,
    pub error: Option<String>,
}

impl KeeperRemoteSendResult {
    pub fn confirmed(
        target: KeeperRemoteTarget,
        envelope: KeeperRemoteEnvelopeRecord,
        receipt_id: String,
        stored_at_ms: u64,
        confirmed_digest: String,
    ) -> Self {
        Self {
            target,
            envelope,
            receipt_id: Some(receipt_id),
            stored_at_ms: Some(stored_at_ms),
            confirmed_digest: Some(confirmed_digest),
            error: None,
        }
    }

    pub fn failed(
        target: KeeperRemoteTarget,
        envelope: KeeperRemoteEnvelopeRecord,
        error: String,
    ) -> Self {
        Self {
            target,
            envelope,
            receipt_id: None,
            stored_at_ms: None,
            confirmed_digest: None,
            error: Some(error),
        }
    }

    fn is_confirmed(&self) -> bool {
        self.error.is_none()
            && self.receipt_id.is_some()
            && self.stored_at_ms.is_some()
            && self.confirmed_digest.is_some()
    }
}

#[derive(Debug, Clone, Default)]
pub struct KeeperRemoteReconcile {
    pub selected_targets: usize,
    pub acknowledged_targets: usize,
    pub new_receipts: usize,
    pub delivered_envelopes: usize,
    pub pending_remote_send_envelopes: usize,
    pub failed_remote_send_envelopes: usize,
    pub last_remote_receipt_ms: Option<u64>,
    pub delivery_state: String,
    pub confirmation_mode: ConfirmationMode,
}

#[derive(Debug, Clone, Default)]
pub struct KeeperRemoteLedger {
    spaces: HashMap<String, KeeperRemoteSpaceState>,
}

#[derive(Debug, Clone, Default)]
struct KeeperRemoteSpaceState {
    targets: Vec<KeeperRemoteTarget>,
    confirmed_receipts: HashMap<String, KeeperRemoteReceipt>,
    failed_receipts: HashMap<String, KeeperRemoteReceipt>,
    inflight_envelopes: usize,
    pending_remote_send_envelopes: usize,
    last_replication_attempt_ms: Option<u64>,
    last_remote_receipt_ms: Option<u64>,
    delivery_state: String,
    confirmation_mode: ConfirmationMode,
}

impl KeeperRemoteLedger {
    pub fn plan_space_reconcile(
        &mut self,
        space_id: &str,
        candidates: &[KeeperRemoteTarget],
        desired_replica_count: usize,
        archived_envelopes: &[KeeperRemoteEnvelopeRecord],
        observed_at_ms: u64,
    ) -> KeeperRemoteReconcilePlan {
        let selected = select_keeper_targets(candidates, desired_replica_count);
        let selected_ids = selected
            .iter()
            .map(|target| target.id.clone())
            .collect::<HashSet<_>>();
        let state = self.spaces.entry(space_id.to_string()).or_default();
        state.targets = selected.clone();
        state.last_replication_attempt_ms = Some(observed_at_ms);
        state.confirmation_mode = if selected.is_empty() {
            ConfirmationMode::LocalProjection
        } else {
            ConfirmationMode::RoundTrip
        };

        prune_space_state(state, space_id, &selected_ids, archived_envelopes);

        let mut pending_sends = Vec::new();
        for target in &selected {
            for envelope in archived_envelopes {
                let key = envelope_target_key(space_id, &target.id, envelope);
                if !state.confirmed_receipts.contains_key(&key) {
                    pending_sends.push(KeeperRemoteSendPlan {
                        target: target.clone(),
                        envelope: envelope.clone(),
                    });
                }
            }
        }

        state.inflight_envelopes = pending_sends.len();
        state.pending_remote_send_envelopes = pending_sends.len();

        KeeperRemoteReconcilePlan {
            selected_targets: selected.len(),
            acknowledged_targets: count_acknowledged_targets(state),
            pending_sends,
        }
    }

    pub fn apply_space_results(
        &mut self,
        space_id: &str,
        desired_replica_count: usize,
        archived_envelopes: &[KeeperRemoteEnvelopeRecord],
        results: &[KeeperRemoteSendResult],
        observed_at_ms: u64,
    ) -> KeeperRemoteReconcile {
        let state = self.spaces.entry(space_id.to_string()).or_default();
        let selected_ids = state
            .targets
            .iter()
            .map(|target| target.id.clone())
            .collect::<HashSet<_>>();
        prune_space_state(state, space_id, &selected_ids, archived_envelopes);

        let mut new_receipts = 0usize;
        for result in results {
            let key = envelope_target_key(space_id, &result.target.id, &result.envelope);
            if result.is_confirmed() {
                let confirmed_digest = result.confirmed_digest.clone().unwrap_or_default();
                if confirmed_digest != result.envelope.message_digest_hex {
                    state.failed_receipts.insert(
                        key,
                        KeeperRemoteReceipt {
                            receipt_id: derive_receipt_id(
                                space_id,
                                &result.target.id,
                                &result.envelope,
                            ),
                            target_id: result.target.id.clone(),
                            target_endpoint: result.target.endpoint.clone(),
                            operator_id: result.target.operator_id.clone(),
                            region: result.target.region.clone(),
                            latest_slot_id: Some(result.envelope.slot_id),
                            observed_at_ms,
                            delivery_state: "send-failed".to_string(),
                            confirmation_mode: ConfirmationMode::RoundTrip,
                            last_error: Some(format!(
                                "keeper confirmed digest {} but local digest is {}",
                                confirmed_digest, result.envelope.message_digest_hex
                            )),
                        },
                    );
                    continue;
                }

                let receipt = KeeperRemoteReceipt {
                    receipt_id: result.receipt_id.clone().unwrap_or_else(|| {
                        derive_receipt_id(space_id, &result.target.id, &result.envelope)
                    }),
                    target_id: result.target.id.clone(),
                    target_endpoint: result.target.endpoint.clone(),
                    operator_id: result.target.operator_id.clone(),
                    region: result.target.region.clone(),
                    latest_slot_id: Some(result.envelope.slot_id),
                    observed_at_ms: result.stored_at_ms.unwrap_or(observed_at_ms),
                    delivery_state: "round-trip-accepted".to_string(),
                    confirmation_mode: ConfirmationMode::RoundTrip,
                    last_error: None,
                };
                let inserted = state
                    .confirmed_receipts
                    .insert(key.clone(), receipt)
                    .is_none();
                state.failed_receipts.remove(&key);
                let stored_at_ms = result.stored_at_ms.unwrap_or(observed_at_ms);
                state.last_remote_receipt_ms = Some(
                    state
                        .last_remote_receipt_ms
                        .map(|current| current.max(stored_at_ms))
                        .unwrap_or(stored_at_ms),
                );
                if inserted {
                    new_receipts = new_receipts.saturating_add(1);
                }
            } else {
                state.failed_receipts.insert(
                    key,
                    KeeperRemoteReceipt {
                        receipt_id: derive_receipt_id(
                            space_id,
                            &result.target.id,
                            &result.envelope,
                        ),
                        target_id: result.target.id.clone(),
                        target_endpoint: result.target.endpoint.clone(),
                        operator_id: result.target.operator_id.clone(),
                        region: result.target.region.clone(),
                        latest_slot_id: Some(result.envelope.slot_id),
                        observed_at_ms,
                        delivery_state: "send-failed".to_string(),
                        confirmation_mode: ConfirmationMode::RoundTrip,
                        last_error: result
                            .error
                            .clone()
                            .or_else(|| Some("keeper send failed".to_string())),
                    },
                );
            }
        }

        let counts = compute_space_counts(space_id, state, archived_envelopes);
        state.inflight_envelopes = 0;
        state.pending_remote_send_envelopes = counts.pending_remote_send_envelopes;

        state.delivery_state = if desired_replica_count == 0 {
            "local-only".to_string()
        } else if state.targets.is_empty() {
            "awaiting-keepers".to_string()
        } else if archived_envelopes.is_empty() {
            "targets-selected".to_string()
        } else if counts.delivered_envelopes == counts.expected_receipts
            && counts.expected_receipts > 0
        {
            "all-accepted".to_string()
        } else if counts.delivered_envelopes > 0 {
            "partially-accepted".to_string()
        } else {
            "pending-replication".to_string()
        };
        state.confirmation_mode = if state.targets.is_empty() {
            ConfirmationMode::LocalProjection
        } else {
            ConfirmationMode::RoundTrip
        };

        KeeperRemoteReconcile {
            selected_targets: state.targets.len(),
            acknowledged_targets: counts.acknowledged_targets,
            new_receipts,
            delivered_envelopes: counts.delivered_envelopes,
            pending_remote_send_envelopes: counts.pending_remote_send_envelopes,
            failed_remote_send_envelopes: counts.failed_remote_send_envelopes,
            last_remote_receipt_ms: state.last_remote_receipt_ms,
            delivery_state: state.delivery_state.clone(),
            confirmation_mode: state.confirmation_mode,
        }
    }

    pub fn view_for_space(&self, space_id: &str) -> KeeperRemoteSpaceView {
        let Some(state) = self.spaces.get(space_id) else {
            return KeeperRemoteSpaceView::default();
        };

        let delivered_envelopes = state.confirmed_receipts.len();
        let acknowledged_targets = count_acknowledged_targets(state);

        KeeperRemoteSpaceView {
            selected_targets: state.targets.len(),
            acknowledged_targets,
            receipt_count: delivered_envelopes,
            delivered_envelopes,
            inflight_envelopes: state.inflight_envelopes,
            pending_remote_send_envelopes: state.pending_remote_send_envelopes,
            failed_remote_send_envelopes: state.failed_receipts.len(),
            last_remote_receipt_ms: state.last_remote_receipt_ms,
            last_replication_attempt_ms: state.last_replication_attempt_ms,
            delivery_state: state.delivery_state.clone(),
            confirmation_mode: state.confirmation_mode,
            targets: state.targets.clone(),
        }
    }

    pub fn aggregate(&self) -> KeeperRemoteAggregateStatus {
        let mut aggregate = KeeperRemoteAggregateStatus::default();
        let mut saw_space = false;
        let mut all_round_trip = true;
        for (space_id, _) in &self.spaces {
            let view = self.view_for_space(space_id);
            if view.selected_targets == 0
                && view.receipt_count == 0
                && view.last_replication_attempt_ms.is_none()
            {
                continue;
            }
            saw_space = true;
            aggregate.space_count = aggregate.space_count.saturating_add(1);
            if view.acknowledged_targets > 0 {
                aggregate.acknowledged_space_count =
                    aggregate.acknowledged_space_count.saturating_add(1);
            }
            aggregate.selected_targets = aggregate
                .selected_targets
                .saturating_add(view.selected_targets);
            aggregate.acknowledged_targets = aggregate
                .acknowledged_targets
                .saturating_add(view.acknowledged_targets);
            aggregate.receipt_count = aggregate.receipt_count.saturating_add(view.receipt_count);
            aggregate.delivered_envelopes = aggregate
                .delivered_envelopes
                .saturating_add(view.delivered_envelopes);
            aggregate.pending_remote_send_envelopes = aggregate
                .pending_remote_send_envelopes
                .saturating_add(view.pending_remote_send_envelopes);
            aggregate.failed_remote_send_envelopes = aggregate
                .failed_remote_send_envelopes
                .saturating_add(view.failed_remote_send_envelopes);
            aggregate.last_remote_receipt_ms = match (
                aggregate.last_remote_receipt_ms,
                view.last_remote_receipt_ms,
            ) {
                (Some(left), Some(right)) => Some(left.max(right)),
                (None, Some(right)) => Some(right),
                (left, None) => left,
            };
            if view.confirmation_mode != ConfirmationMode::RoundTrip {
                all_round_trip = false;
            }
        }
        aggregate.confirmation_mode = if saw_space && all_round_trip {
            ConfirmationMode::RoundTrip
        } else {
            ConfirmationMode::LocalProjection
        };
        aggregate
    }
}

pub fn keeper_targets_from_bundle(bundle: Option<&BootstrapBundle>) -> Vec<KeeperRemoteTarget> {
    let Some(bundle) = bundle else {
        return Vec::new();
    };

    let mut seen_ids = HashSet::new();
    let mut seen_endpoints = HashSet::new();
    let mut out = Vec::new();
    for keeper in &bundle.keepers {
        let id = keeper.id.trim();
        let endpoint = keeper.endpoint.trim();
        if id.is_empty() || endpoint.is_empty() {
            continue;
        }
        if !seen_ids.insert(id.to_string()) || !seen_endpoints.insert(endpoint.to_string()) {
            continue;
        }
        out.push(KeeperRemoteTarget {
            id: id.to_string(),
            endpoint: endpoint.to_string(),
            operator_id: keeper
                .operator_id
                .as_deref()
                .unwrap_or("unknown-operator")
                .trim()
                .to_string(),
            region: keeper
                .region
                .as_deref()
                .unwrap_or("unknown-region")
                .trim()
                .to_string(),
            capacity_hint: keeper.replication_factor.unwrap_or(1).max(1),
        });
    }

    out
}

pub fn select_keeper_targets(
    candidates: &[KeeperRemoteTarget],
    desired_replica_count: usize,
) -> Vec<KeeperRemoteTarget> {
    if desired_replica_count == 0 || candidates.is_empty() {
        return Vec::new();
    }

    let mut ordered = candidates.to_vec();
    ordered.sort_by(|left, right| {
        right
            .capacity_hint
            .cmp(&left.capacity_hint)
            .then_with(|| left.operator_id.cmp(&right.operator_id))
            .then_with(|| left.region.cmp(&right.region))
            .then_with(|| left.id.cmp(&right.id))
    });

    let mut selected = Vec::new();
    let mut selected_ids = HashSet::new();
    let mut seen_operators = HashSet::new();

    for candidate in &ordered {
        if selected.len() >= desired_replica_count {
            break;
        }
        if candidate.operator_id != "unknown-operator"
            && seen_operators.insert(candidate.operator_id.clone())
            && selected_ids.insert(candidate.id.clone())
        {
            selected.push(candidate.clone());
        }
    }

    for candidate in ordered {
        if selected.len() >= desired_replica_count {
            break;
        }
        if selected_ids.insert(candidate.id.clone()) {
            selected.push(candidate);
        }
    }

    selected
}

fn prune_space_state(
    state: &mut KeeperRemoteSpaceState,
    space_id: &str,
    selected_ids: &HashSet<String>,
    archived_envelopes: &[KeeperRemoteEnvelopeRecord],
) {
    let valid_keys = selected_ids
        .iter()
        .flat_map(|target_id| {
            archived_envelopes
                .iter()
                .map(move |envelope| envelope_target_key(space_id, target_id, envelope))
        })
        .collect::<HashSet<_>>();

    state
        .targets
        .retain(|target| selected_ids.contains(&target.id));
    state.confirmed_receipts.retain(|key, receipt| {
        selected_ids.contains(&receipt.target_id) && valid_keys.contains(key)
    });
    state.failed_receipts.retain(|key, receipt| {
        selected_ids.contains(&receipt.target_id) && valid_keys.contains(key)
    });
}

fn count_acknowledged_targets(state: &KeeperRemoteSpaceState) -> usize {
    let acknowledged = state
        .confirmed_receipts
        .values()
        .map(|receipt| receipt.target_id.clone())
        .collect::<HashSet<_>>();
    state
        .targets
        .iter()
        .filter(|target| acknowledged.contains(&target.id))
        .count()
}

struct KeeperSpaceCounts {
    acknowledged_targets: usize,
    delivered_envelopes: usize,
    pending_remote_send_envelopes: usize,
    failed_remote_send_envelopes: usize,
    expected_receipts: usize,
}

fn compute_space_counts(
    space_id: &str,
    state: &KeeperRemoteSpaceState,
    archived_envelopes: &[KeeperRemoteEnvelopeRecord],
) -> KeeperSpaceCounts {
    let selected_ids = state
        .targets
        .iter()
        .map(|target| target.id.clone())
        .collect::<HashSet<_>>();
    let valid_keys = selected_ids
        .iter()
        .flat_map(|target_id| {
            archived_envelopes
                .iter()
                .map(move |envelope| envelope_target_key(space_id, target_id, envelope))
        })
        .collect::<HashSet<_>>();
    let delivered_envelopes = state
        .confirmed_receipts
        .keys()
        .filter(|key| valid_keys.contains(*key))
        .count();
    let failed_remote_send_envelopes = state
        .failed_receipts
        .keys()
        .filter(|key| valid_keys.contains(*key))
        .count();
    let expected_receipts = archived_envelopes.len().saturating_mul(state.targets.len());
    let pending_remote_send_envelopes = expected_receipts.saturating_sub(delivered_envelopes);
    let acknowledged_targets = count_acknowledged_targets(state);

    KeeperSpaceCounts {
        acknowledged_targets,
        delivered_envelopes,
        pending_remote_send_envelopes,
        failed_remote_send_envelopes,
        expected_receipts,
    }
}

fn envelope_target_key(
    space_id: &str,
    target_id: &str,
    envelope: &KeeperRemoteEnvelopeRecord,
) -> String {
    format!(
        "{}:{}:{}:{}",
        space_id, target_id, envelope.slot_id, envelope.message_digest_hex
    )
}

fn derive_receipt_id(
    space_id: &str,
    target_id: &str,
    envelope: &KeeperRemoteEnvelopeRecord,
) -> String {
    let mut seed = Vec::new();
    seed.extend_from_slice(space_id.as_bytes());
    seed.extend_from_slice(target_id.as_bytes());
    seed.extend_from_slice(&envelope.slot_id.to_le_bytes());
    seed.extend_from_slice(envelope.message_digest_hex.as_bytes());
    let hash = blake3_hash(&seed);
    hex::encode(&hash[..10])
}
