pub mod api;
pub mod api_offer;
pub mod chunk;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod derive;
pub mod discovery;
pub mod network_telemetry;
pub mod offer;
pub mod onion;
pub mod phrase;
pub mod prelude;
pub mod protocol;
pub mod protocol_assist;
pub mod protocol_assist_v5;
pub mod resume;
pub mod security;
pub mod session_noise;
pub mod state;
pub mod tor;
pub mod transport;

// Stable public surface. Keep this list explicit to avoid leaking internal APIs.
pub use config::{Config, GuaranteedEgress, PluggableTransportMode, ProductMode, TorRole, WanMode};
pub use crypto::CryptoError;
pub use derive::{
    derive_from_passphrase_v1, derive_from_passphrase_v2, DeriveError, RendezvousParams,
};
pub use offer::{Endpoint, EndpointKind, OfferError, OfferPayload, RendezvousInfo, RoleHint};
pub use protocol_assist_v5::{verify_assist_mac_v5, AssistGoV5, AssistRequestV5, CandidatePolicy};
pub use session_noise::{run_noise_upgrade, NoiseRole, SessionNoiseError};
pub use transport::{
    connect_to, establish_connection, establish_connection_from_offer, Connection,
};
