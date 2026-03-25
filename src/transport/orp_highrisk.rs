use ethersync::{EtherNode, HighRiskCircuitPlan, HighRiskGateSnapshot};
use serde::Serialize;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[derive(Debug, Clone, Serialize)]
pub struct HighRiskHopSnapshot {
    pub node_id: String,
    pub assist_tag: String,
    pub addr: String,
    pub route_class: String,
    pub operator_id_hint: String,
    pub region_hint: String,
    pub can_relay: bool,
    pub bridge_capable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct HighRiskPlanSnapshot {
    pub space_prefix: String,
    pub target_tag: String,
    pub operator_diversity: usize,
    pub region_diversity: usize,
    pub entry: HighRiskHopSnapshot,
    pub middle: HighRiskHopSnapshot,
    pub exit: HighRiskHopSnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub struct HighRiskPreparation {
    pub circuit_id: String,
    pub target_tag: String,
    pub gate: HighRiskGateSnapshot,
    pub plan: HighRiskPlanSnapshot,
    pub relay_data_plane_active: bool,
    pub control_frames_published: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HighRiskPreparationError {
    pub reason: String,
    pub gate: Option<HighRiskGateSnapshot>,
}

pub async fn prepare_high_risk_connect(
    node: &EtherNode,
    passphrase: &str,
    target_tag: [u8; 8],
) -> std::result::Result<HighRiskPreparation, HighRiskPreparationError> {
    let gate = node
        .high_risk_gate_snapshot(passphrase)
        .await
        .map_err(|err| HighRiskPreparationError {
            reason: err.to_string(),
            gate: None,
        })?;

    let plan = node
        .plan_high_risk_circuit(passphrase, target_tag)
        .await
        .map_err(|err| HighRiskPreparationError {
            reason: err.to_string(),
            gate: Some(gate.clone()),
        })?;

    let circuit_id = node
        .publish_high_risk_circuit_plan(passphrase, &plan)
        .await
        .map_err(|err| HighRiskPreparationError {
            reason: err.to_string(),
            gate: Some(gate.clone()),
        })?;

    Ok(HighRiskPreparation {
        circuit_id: hex::encode(circuit_id),
        target_tag: hex::encode(target_tag),
        gate,
        plan: snapshot_plan(plan),
        relay_data_plane_active: false,
        control_frames_published: vec![
            "CircuitOpen".to_string(),
            "CircuitExtend".to_string(),
            "CircuitExtend".to_string(),
            "Cover".to_string(),
        ],
    })
}

pub async fn cancel_prepared_high_risk_circuit(
    node: &EtherNode,
    passphrase: &str,
    circuit_id_hex: &str,
    reason_code: u16,
) -> Result<()> {
    let bytes = hex::decode(circuit_id_hex)?;
    if bytes.len() != 16 {
        return Err("invalid circuit id length".into());
    }
    let mut circuit_id = [0u8; 16];
    circuit_id.copy_from_slice(&bytes);
    node.close_high_risk_circuit(passphrase, circuit_id, reason_code)
        .await?;
    Ok(())
}

fn snapshot_plan(plan: HighRiskCircuitPlan) -> HighRiskPlanSnapshot {
    HighRiskPlanSnapshot {
        space_prefix: hex::encode(plan.space_prefix),
        target_tag: hex::encode(plan.target_tag),
        operator_diversity: plan.operator_diversity,
        region_diversity: plan.region_diversity,
        entry: snapshot_hop(plan.entry),
        middle: snapshot_hop(plan.middle),
        exit: snapshot_hop(plan.exit),
    }
}

fn snapshot_hop(hop: ethersync::HighRiskCircuitHop) -> HighRiskHopSnapshot {
    HighRiskHopSnapshot {
        node_id: hex::encode(hop.node_id),
        assist_tag: hex::encode(hop.assist_tag),
        addr: hop.addr.to_string(),
        route_class: format!("{:?}", hop.route_class).to_lowercase(),
        operator_id_hint: hop.operator_id_hint,
        region_hint: hop.region_hint,
        can_relay: hop.can_relay,
        bridge_capable: hop.bridge_capable,
    }
}
