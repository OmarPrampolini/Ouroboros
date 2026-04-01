pub mod coordinate;
pub mod erasure_coding;
pub mod gossip;
pub mod message;
pub mod network;
pub mod node;
pub mod onion;
pub mod routing;
pub mod storage;

pub use coordinate::{derive_coordinate, EtherCoordinate};
pub use message::EtherMessage;
pub use network::{EtherUdpSocket, FrameCodec, RateLimiter};
pub use node::{
    DeliveryOutcome, EtherNode, HighRiskCircuitSnapshot, HighRiskCircuitStats, HighRiskLocalRole,
    HighRiskTransportSession, NodeConfig, SubscriptionHandle,
};
pub use onion::{HopHandshake, OnionCodec, OnionError, OnionLayer};
pub use routing::{
    decode_orp_frame, encode_orp_frame, score_announcement, CircuitClose, CircuitExtend,
    CircuitOpen, CircuitReady, CoverPacket, DeliveryReceipt, ForwardDeliveryNotice,
    HighRiskCircuitHop, HighRiskCircuitPlan, HighRiskGateSnapshot, HighRiskPlannerError,
    HighRiskRouteDescriptor, OrpFrame, RouteAnnouncement, RouteCache, RouteCapabilities,
    RouteClass, RouteDirection, RouteForward, RouteHop, RouteLookup, RouteOffer,
    SUBSPACE_CIRCUIT_CLOSE, SUBSPACE_CIRCUIT_EXTEND, SUBSPACE_CIRCUIT_OPEN, SUBSPACE_CIRCUIT_READY,
    SUBSPACE_COVER_TRAFFIC, SUBSPACE_DELIVERY_NOTICE, SUBSPACE_RELAY_BEACON,
    SUBSPACE_ROUTE_ANNOUNCE, SUBSPACE_ROUTE_FORWARD, SUBSPACE_ROUTE_LOOKUP, SUBSPACE_ROUTE_OFFER,
    SUBSPACE_USER,
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EtherSyncError {
    #[error("invalid passphrase")]
    InvalidPassphrase,
    #[error("derivation failed")]
    DerivationFailed,
    #[error("invalid slot")]
    InvalidSlot,
    #[error("storage error: {0}")]
    StorageError(String),
    #[error("network error: {0}")]
    NetworkError(String),
}
