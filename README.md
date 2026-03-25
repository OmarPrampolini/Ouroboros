# Ouroboros

Private, deterministic, serverless communication.

Ouroboros is a communications platform built around a simple idea: the same secret should deterministically recreate the same communication context, without depending on a mandatory cloud backend or centralized discovery service.

It combines three layers into one product:

- **Handshacke**: live 1:1 encrypted sessions with aggressive transport fallback.
- **EtherSync**: encrypted shared spaces derived from a passphrase for messages, file chunks, and asynchronous presence.
- **ORP (Ouroboros Routing Protocol)**: deterministic route discovery inside an EtherSync space, used as a privacy-aware transport fallback before Tor.

Ouroboros is named after the snake that bites its own tail: a closed loop, self-derived, self-contained, and designed to reduce external dependency wherever possible.

Repository: [github.com/OmarPrampolini/Ouroboros](https://github.com/OmarPrampolini/Ouroboros)  
License: MIT

## Why It Exists

Most communication systems assume at least one of the following:

- a trusted server for account and peer discovery
- a managed relay or broker as the default control plane
- a cloud service to preserve state and history

Ouroboros starts from the opposite direction.

- If two peers are online at the same time, **Handshacke** optimizes for a direct live session.
- If presence is intermittent, **EtherSync** gives those peers a deterministic encrypted space that can be revisited later.
- If direct routing becomes difficult, **ORP** tries to discover a route inside that deterministic space before falling back to heavier infrastructure such as Tor.

The result is not "just another chat app." It is an attempt to build a practical private communications substrate with deterministic coordination, real transport engineering, and product-grade local UX.

## Product Model

### Handshacke

Handshacke is the live session layer.

Use it when you want:

- immediate 1:1 pairing
- encrypted live transport
- passphrase-, offer-, QR-, phrase-, or relay-assisted connection flows
- a system that actively races LAN, WAN, assist, ORP, and Tor strategies instead of assuming one network path

In code and packaging, the daemon binary is still named `handshacke`. In product terms, this is the live session side of Ouroboros.

### EtherSync

EtherSync is the shared-space layer.

A passphrase deterministically derives a logical space. Peers who know the same passphrase can publish encrypted messages, chunked files, and routing metadata into the same slot-based gossip domain.

Use it when you want:

- asynchronous encrypted collaboration
- intermittent peer presence
- passphrase-derived shared spaces
- local backlog replay on rejoin
- chunked file transfer over the same shared space

EtherSync is not a centralized database. History exists only to the extent that participating nodes saw and retained it.

### ORP

ORP is the routing control plane now integrated into the transport stack.

Today, ORP is best described as:

- a deterministic route discovery layer inside active EtherSync spaces
- a space-scoped control plane for route announcements, lookups, and offers
- a pre-Tor fallback for explicit target routing

Today, ORP is **not** claimed as a finished global anonymity network. It is a serious routing foundation that already improves the architecture, but it is still more precise to describe it as deterministic private overlay routing than as a Tor replacement.

## What Makes Ouroboros Different

- **Deterministic coordination**: the same passphrase derives the same rendezvous parameters or shared space.
- **Serverless-first architecture**: no mandatory discovery service is required for the core model.
- **Transport realism**: LAN, WAN direct, WAN assist, ORP, Tor, QUIC, WebRTC, and pluggable transports are treated as engineering tools, not marketing words.
- **Local security model**: the daemon API is bearer-protected, localhost-bound, and designed for GUI-to-daemon control without persisting secrets in plaintext.
- **Product and protocol together**: the repository contains both the Rust protocol/runtime stack and the Tauri desktop application.

## Architecture At A Glance

### Deterministic Derivation

Passphrases are canonicalized and fed into deterministic derivation pipelines.

- **Handshacke** derives rendezvous parameters, transport tags, and session inputs.
- **EtherSync** derives a shared space identity and slot-local entropy.
- **ORP** derives active routing scope from joined EtherSync spaces.

### Transport Cascade

When a live connection is needed, Ouroboros does not rely on a single path. It escalates through a transport cascade that can include:

- LAN discovery
- WAN direct traversal
- WAN assist relays
- ORP route discovery
- Tor fallback

This lets the system adapt to real network conditions instead of hard-coding one assumption about NAT, firewalls, or reachability.

### Encrypted Shared Spaces

EtherSync stores and gossips encrypted messages in slot windows. A peer joining a known space can subscribe to the stream and replay the recent local backlog that still exists on the node.

### Product Surface

The repo includes:

- the Rust daemon and protocol crates
- the Tauri desktop app
- local REST APIs
- integration tests, fuzzing targets, and protocol documentation

## Real Project Status

### Strong Today

- Deterministic passphrase derivation across the core stack
- Local authenticated API with in-memory bearer token flow
- Multiple connection flows: classic, offer, hybrid QR, phrase, guaranteed relay, and target-driven paths
- Multi-transport runtime with fallback orchestration
- EtherSync spaces with publish, subscribe, replay, and chunked file transfer
- Tauri desktop UX with daemon lifecycle management and split Handshacke / EtherSync flows
- ORP transport integration as a target-aware, space-scoped route discovery fallback

### Important Limits

- Ouroboros does not guarantee permanent distributed retention by itself.
- EtherSync history is only recoverable if at least one node observed and kept the data.
- ORP is an evolving routing layer, not a finished anonymity network.

Those limits are not bugs in the README wording. They are part of being precise about what the system is today.

## Security Posture

Ouroboros uses modern primitives and hardens the local control plane, but it does not pretend that cryptography alone solves all operational risk.

Core characteristics:

- encrypted payloads and deterministic key derivation
- replay and time-window checks
- local daemon API protected by bearer token
- no requirement to persist application secrets in plaintext
- dependency policy enforced through `Cargo.lock` and `deny.toml`

Relevant references:

- [SECURITY.md](SECURITY.md)
- [docs/threat_model_visibility.md](docs/threat_model_visibility.md)
- [docs/feature_flags.md](docs/feature_flags.md)

## Repository Structure

```text
Ouroboros/
|-- src/                  # Main daemon / library surface
|-- ethersync/            # Shared-space gossip crate
|-- ouroboros-crypto/     # Shared cryptographic primitives
|-- ui/                   # Tauri desktop application
|-- docs/                 # Technical documentation
|-- tests/                # Integration tests
`-- fuzz/                 # Fuzzing targets
```

If you want the deep technical breakdown, see [docs/PROJECT_SUMMARY.md](docs/PROJECT_SUMMARY.md).

## Quick Start

### Core Daemon

```bash
git clone https://github.com/OmarPrampolini/Ouroboros.git
cd Ouroboros
cargo build --release
cargo run --release
```

Default API bind: `127.0.0.1:8731`

### Tauri Desktop App

```bash
cargo build --release

# Windows
# copy target\release\handshacke.exe ui\src-tauri\bin\handshacke.exe

# Linux/macOS
# cp target/release/handshacke ui/src-tauri/bin/handshacke

cd ui
npm install
npm run dev
```

## Key Flows

### Handshacke

- classic passphrase connect
- offer / hybrid QR flows
- phrase mode over Tor
- relay-assisted connect
- target-driven connect

### EtherSync

- start node
- join space
- publish messages
- publish files as chunks
- consume the event stream
- replay recent local backlog on rejoin

### ORP

- join an ORP-enabled EtherSync space
- announce direct reachability into that space
- resolve explicit target assist tags through cached announcements or lookup/offer exchange
- fall back to Tor only after ORP fails

## API Surface

The daemon exposes a local `/v1/*` REST API.

Representative endpoints:

- `POST /v1/connect`
- `GET /v1/status`
- `POST /v1/disconnect`
- `POST /v1/offer`
- `POST /v1/qr/hybrid`
- `POST /v1/phrase/open`
- `POST /v1/phrase/join`
- `GET /v1/phrase/status`
- `POST /v1/ethersync/start`
- `POST /v1/ethersync/stop`
- `GET /v1/ethersync/status`
- `POST /v1/ethersync/spaces/join`
- `POST /v1/ethersync/spaces/publish`
- `POST /v1/ethersync/files/publish`
- `GET /v1/ethersync/events`
- `GET /v1/connect/fallbacks`
- `GET /v1/network/nat-metrics`

## Feature Flags

Default build:

- `quic`

Optional capabilities:

- `webrtc`
- `pq`
- `full` as a convenience profile

Current feature semantics are documented in [docs/feature_flags.md](docs/feature_flags.md).

## Who This Is For

Ouroboros is for teams, operators, researchers, and privacy-minded builders who want:

- less dependency on centralized coordination
- strong local control over runtime behavior
- a communications stack that treats networking as a first-class problem
- something that can become both a product and a protocol platform

## Positioning

If you are selling or presenting Ouroboros, the most accurate concise framing is:

> **Ouroboros is a deterministic private communications platform that combines live peer sessions, encrypted shared spaces, and in-band route discovery into one serverless-first architecture.**

That is ambitious, but it is also defensible.

## License

MIT. Commercial use is allowed.
