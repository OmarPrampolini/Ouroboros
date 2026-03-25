# Feature Flags

Ouroboros uses feature flags to keep the default build practical while still allowing optional transports and post-quantum primitives.

## Default Profile

The default build enables:

- `quic`

This gives the project a strong transport option out of the box without automatically pulling in every experimental or heavyweight capability.

Build it with:

```bash
cargo build
```

## Available Features

### `quic`

Enables QUIC transport support.

- Module: `transport::quic_rfc9000`
- Dependency path: `quinn` + `rcgen`
- Status: supported

### `webrtc`

Enables WebRTC DataChannel transport support.

- Module: `transport::webrtc`
- Dependency path: `webrtc`
- Status: optional

### `pq`

Enables post-quantum hybrid primitives based on ML-KEM.

- Module: `crypto::post_quantum`
- Shared crypto crate: `ouroboros-crypto::pq`
- Status: optional

Important note:

- The `pq` feature currently enables ML-KEM-based hybrid cryptographic primitives.
- It does **not** currently wire a maintained PQ Noise backend into the live Noise transport path.
- When live session setup asks for PQ Noise parameters and none are available, the runtime falls back to classic Noise XX.

This is intentional: the project keeps PQ primitives available without depending on an unmaintained Kyber stack in the live transport backend.

### Runtime capability note

Feature flags are only part of the truth. The daemon also reports runtime capability posture through `GET /v1/capabilities`.

That surface distinguishes between:

- compiled transports such as `quic` and `webrtc`
- cryptographic capability such as `pq_primitives`
- routing tiers such as `orp_standard` and `orp_highrisk`
- managed-network scaffolding such as `keeper_replication` and `bridge_bootstrap`

### `full`

Convenience profile that enables:

- `quic`
- `webrtc`
- `pq`

Build it with:

```bash
cargo build --no-default-features --features full
```

## Suggested Builds

- Safe default: `cargo build`
- Core only: `cargo build --no-default-features`
- QUIC only: `cargo build --no-default-features --features quic`
- WebRTC only: `cargo build --no-default-features --features webrtc`
- PQ primitives only: `cargo build --no-default-features --features pq`
- Full optional stack: `cargo build --no-default-features --features full`
