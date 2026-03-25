# Project Summary - Ouroboros

## One-line summary

Ouroboros is a deterministic private communications platform that combines live sessions, encrypted shared spaces, and in-band route discovery in one architecture.

## Why it exists

The project exists to challenge the default assumption that secure communication must begin with a central directory, a mandatory account system, or a cloud backend that acts as the source of truth.

Its architectural thesis is:

> the same secret should recreate the same communication reality

That thesis powers three planes:

- Handshacke for live peer sessions
- EtherSync for encrypted shared spaces
- ORP for routing control inside those same derived spaces

## Repository structure

```text
Ouroboros/
|-- src/                  # Main daemon, REST API, transport stack
|-- ethersync/            # Shared-space substrate and ORP wire/control primitives
|-- ouroboros-crypto/     # Shared derivation and cryptographic primitives
|-- ui/                   # Tauri desktop application
|-- docs/                 # Product, architecture, threat model, ADRs
|-- tests/                # Integration tests
`-- fuzz/                 # Fuzzing targets
```

## Core crates and responsibilities

### `src/`

Main runtime and product surface:

- Axum local API
- transport orchestration
- Noise session upgrade
- phrase and Tor flows
- diagnostics and telemetry
- runtime state and connection management

### `ethersync/`

Deterministic shared-state plane:

- slot derivation
- encrypted message publication
- file chunk publication
- gossip and anti-entropy
- local storage and replay
- ORP route cache and ORP wire frames

### `ouroboros-crypto/`

Shared cryptographic building blocks:

- derivation helpers
- hashing
- AEAD wrappers
- optional PQ primitives

## Major capabilities

### Handshacke

- passphrase-based connect
- offer and hybrid QR connect
- phrase pairing over Tor
- target-driven connect
- transport fallback across LAN, WAN, assist, ORP and Tor

### EtherSync

- start and stop node runtime
- join shared spaces
- publish encrypted messages
- publish chunked files
- replay recent local backlog
- stream events to API clients

### ORP

- route announcements inside EtherSync scopes
- target-aware lookup and offer flow
- route cache for ORP-Standard
- target connect through `orp:<16-hex>`
- route classes, operator hints, and region hints in announcements
- future wire contract formalized for high-risk circuits

### Bootstrap and keeper posture

- bootstrap bundles now seed EtherSync bootstrap peers and participate in space-scoped discovery
- keeper replication posture is surfaced in runtime status with pending and archived counts
- bridge hints and operator identity hints are part of the current code model
- federated route discovery can combine ORP, bundle, and static bootstrap peers
- keeper replication can flush encrypted envelopes into a local replica archive
- keeper backfill can restore archived envelopes into local EtherSync storage

## Current truth

What is true today:

- the deterministic derivation model is real
- the stack already integrates live sessions, shared spaces, and private routing
- ORP is a meaningful routing subsystem, not a naming exercise

What is not claimed yet:

- global anonymity network
- production multi-node keeper-backed retention
- audited high-risk overlay

## Public API highlights

- `POST /v1/connect`
- `GET /v1/status`
- `GET /v1/capabilities`
- `GET /v1/routes/discover`
- `GET /v1/routes/status`
- `GET /v1/keepers/status`
- `POST /v1/keepers/backfill`
- `GET /v1/ethersync/status`
- `POST /v1/ethersync/start`
- `POST /v1/ethersync/spaces/join`
- `POST /v1/ethersync/spaces/publish`
- `POST /v1/ethersync/files/publish`
- `GET /v1/ethersync/events`

## Feature flags

Default:

- `quic`

Optional:

- `webrtc`
- `pq`
- `full`

The `pq` feature currently enables maintained ML-KEM-based primitives. It does not yet advertise a maintained PQ Noise transport path.

## Canonical docs

- [README.md](../README.md)
- [Architecture Book](./ARCHITECTURE_BOOK.md)
- [Roadmap and Gates](./roadmap_gates.md)
- [Interop and Versioning](./interop.md)
- [Operator Model](./operators.md)
- [Threat Model Book](./threat_model_book.md)

## Final positioning

Ouroboros should be understood as a product-plus-protocol effort:

- a serious application surface for users
- a defensible architecture for engineers
- a network design that can grow into managed retention and stronger anonymity tiers without lying about what exists today
