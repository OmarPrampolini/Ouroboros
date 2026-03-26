use crate::crypto::MAX_TCP_FRAME_BYTES;
use crate::transport::io::{IoResult, TransportIo, TransportIoError};
use ethersync::{
    DeliveryOutcome, EtherNode, HighRiskCircuitPlan, HighRiskGateSnapshot, HighRiskLocalRole,
    HighRiskRouteDescriptor, HighRiskTransportSession, RouteDirection,
};
use serde::Serialize;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

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
    pub routed_data_plane_ready: bool,
    pub control_frames_staged: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HighRiskPreparationError {
    pub reason: String,
    pub gate: Option<HighRiskGateSnapshot>,
}

pub struct OrpHighRiskTransport {
    node: Arc<EtherNode>,
    passphrase: String,
    circuit_id: [u8; 16],
    direction: RouteDirection,
    receiver: Arc<Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    rate_limit_addr: std::net::SocketAddr,
}

impl OrpHighRiskTransport {
    fn from_session(
        node: Arc<EtherNode>,
        passphrase: String,
        session: HighRiskTransportSession,
    ) -> std::result::Result<Self, HighRiskPreparationError> {
        let direction = match session.local_role {
            HighRiskLocalRole::Origin => RouteDirection::OriginToTarget,
            HighRiskLocalRole::Exit => RouteDirection::TargetToOrigin,
            _ => {
                return Err(HighRiskPreparationError {
                    reason: "invalid local role for high-risk endpoint transport".to_string(),
                    gate: None,
                });
            }
        };

        let rate_limit_addr = match session.local_role {
            HighRiskLocalRole::Origin => session.descriptor.entry.addr,
            HighRiskLocalRole::Exit => {
                if session.descriptor.middle.addr.port() == 0 {
                    session.descriptor.exit.addr
                } else {
                    session.descriptor.middle.addr
                }
            }
            HighRiskLocalRole::Entry | HighRiskLocalRole::Middle => {
                std::net::SocketAddr::from(([0, 0, 0, 0], 0))
            }
        };

        Ok(Self {
            node,
            passphrase,
            circuit_id: session.circuit_id,
            direction,
            receiver: Arc::new(Mutex::new(session.receiver)),
            rate_limit_addr,
        })
    }
}

impl TransportIo for OrpHighRiskTransport {
    fn max_packet_limit(&self) -> u64 {
        MAX_TCP_FRAME_BYTES as u64
    }

    fn rate_limit_addr(&self) -> std::net::SocketAddr {
        self.rate_limit_addr
    }

    fn send<'a>(
        &'a self,
        data: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = IoResult<()>> + Send + 'a>> {
        Box::pin(async move {
            match self
                .node
                .send_high_risk_payload_reliable(
                    &self.passphrase,
                    self.circuit_id,
                    self.direction,
                    data,
                    Duration::from_secs(5),
                )
                .await
                .map_err(|err| TransportIoError::Relay(err.to_string()))?
            {
                DeliveryOutcome::Confirmed => Ok(()),
                DeliveryOutcome::Unconfirmed => Err(TransportIoError::Relay(
                    "high-risk delivery receipt timed out".to_string(),
                )),
            }
        })
    }

    fn recv<'a>(&'a self) -> Pin<Box<dyn Future<Output = IoResult<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            let mut guard = self.receiver.lock().await;
            match guard.recv().await {
                Some(payload) => Ok(payload),
                None => Err(TransportIoError::Relay(
                    "high-risk transport channel closed".to_string(),
                )),
            }
        })
    }
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
        routed_data_plane_ready: false,
        gate,
        plan: snapshot_plan(plan),
        control_frames_staged: vec![
            "CircuitOpen".to_string(),
            "CircuitExtend".to_string(),
            "CircuitExtend".to_string(),
            "Cover".to_string(),
        ],
    })
}

pub async fn establish_high_risk_outbound_transport(
    node: Arc<EtherNode>,
    passphrase: &str,
    target_tag: [u8; 8],
) -> std::result::Result<(HighRiskPreparation, Arc<dyn TransportIo>), HighRiskPreparationError> {
    let (gate, plan, session) = node
        .open_high_risk_transport(passphrase, target_tag)
        .await
        .map_err(|err| HighRiskPreparationError {
            reason: err.to_string(),
            gate: None,
        })?;
    let circuit_id = session.circuit_id;
    if let Err(err) = session.wait_ready(Duration::from_secs(5)).await {
        let _ = node
            .close_high_risk_circuit(passphrase, circuit_id, 408)
            .await;
        return Err(HighRiskPreparationError {
            reason: err.to_string(),
            gate: Some(gate.clone()),
        });
    }
    let io = OrpHighRiskTransport::from_session(node, passphrase.to_string(), session)?;
    let preparation = HighRiskPreparation {
        circuit_id: hex::encode(io.circuit_id),
        target_tag: hex::encode(target_tag),
        routed_data_plane_ready: true,
        gate,
        plan: snapshot_plan(plan),
        control_frames_staged: vec![
            "CircuitOpen".to_string(),
            "CircuitExtend".to_string(),
            "CircuitExtend".to_string(),
            "Cover".to_string(),
        ],
    };
    Ok((preparation, Arc::new(io)))
}

pub async fn accept_high_risk_inbound_transport(
    node: Arc<EtherNode>,
    passphrase: &str,
    timeout: Duration,
) -> std::result::Result<(HighRiskPreparation, Arc<dyn TransportIo>), HighRiskPreparationError> {
    let gate = node
        .high_risk_gate_snapshot(passphrase)
        .await
        .map_err(|err| HighRiskPreparationError {
            reason: err.to_string(),
            gate: None,
        })?;
    let session = node
        .accept_high_risk_transport(passphrase, timeout)
        .await
        .map_err(|err| HighRiskPreparationError {
            reason: err.to_string(),
            gate: Some(gate.clone()),
        })?;
    let target_tag = session.descriptor.target_tag;
    let plan = snapshot_descriptor(&session.descriptor);
    let io = OrpHighRiskTransport::from_session(node, passphrase.to_string(), session)?;
    let preparation = HighRiskPreparation {
        circuit_id: hex::encode(io.circuit_id),
        target_tag: hex::encode(target_tag),
        routed_data_plane_ready: true,
        gate,
        plan,
        control_frames_staged: Vec::new(),
    };
    Ok((preparation, Arc::new(io)))
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

fn snapshot_descriptor(descriptor: &HighRiskRouteDescriptor) -> HighRiskPlanSnapshot {
    let mut operators = std::collections::BTreeSet::new();
    if !descriptor.entry.operator_id_hint.trim().is_empty() {
        operators.insert(descriptor.entry.operator_id_hint.clone());
    }
    if !descriptor.middle.operator_id_hint.trim().is_empty() {
        operators.insert(descriptor.middle.operator_id_hint.clone());
    }
    if !descriptor.exit.operator_id_hint.trim().is_empty() {
        operators.insert(descriptor.exit.operator_id_hint.clone());
    }

    let mut regions = std::collections::BTreeSet::new();
    if !descriptor.entry.region_hint.trim().is_empty() {
        regions.insert(descriptor.entry.region_hint.clone());
    }
    if !descriptor.middle.region_hint.trim().is_empty() {
        regions.insert(descriptor.middle.region_hint.clone());
    }
    if !descriptor.exit.region_hint.trim().is_empty() {
        regions.insert(descriptor.exit.region_hint.clone());
    }

    HighRiskPlanSnapshot {
        space_prefix: hex::encode(descriptor.space_prefix),
        target_tag: hex::encode(descriptor.target_tag),
        operator_diversity: operators.len(),
        region_diversity: regions.len(),
        entry: snapshot_hop(descriptor.entry.clone()),
        middle: snapshot_hop(descriptor.middle.clone()),
        exit: snapshot_hop(descriptor.exit.clone()),
    }
}

fn snapshot_hop(hop: ethersync::HighRiskCircuitHop) -> HighRiskHopSnapshot {
    let sealed = hop.node_id == [0u8; 16] && hop.addr.port() == 0;
    HighRiskHopSnapshot {
        node_id: if sealed {
            "sealed".to_string()
        } else {
            hex::encode(hop.node_id)
        },
        assist_tag: if sealed {
            "sealed".to_string()
        } else {
            hex::encode(hop.assist_tag)
        },
        addr: if sealed {
            "sealed".to_string()
        } else {
            hop.addr.to_string()
        },
        route_class: if sealed {
            "sealed".to_string()
        } else {
            format!("{:?}", hop.route_class).to_lowercase()
        },
        operator_id_hint: if sealed {
            "sealed".to_string()
        } else {
            hop.operator_id_hint
        },
        region_hint: if sealed {
            "sealed".to_string()
        } else {
            hop.region_hint
        },
        can_relay: hop.can_relay,
        bridge_capable: hop.bridge_capable,
    }
}
