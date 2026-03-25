# Ouroboros, the snake that bit his tail

Private, deterministic, serverless communication.

Ouroboros is not built around accounts, central directories, or a mandatory cloud control plane. It is built around a harder and stranger idea:

> the same secret should recreate the same communication reality

That means the passphrase is not just a password. It is coordination material. It is rendezvous input. It is shared-space identity. It is routing scope.

From that idea, Ouroboros grows into three tightly connected layers:

- **Handshacke** for live encrypted peer sessions
- **EtherSync** for encrypted shared spaces and asynchronous presence
- **ORP** for in-band route discovery inside those same shared spaces

Repository: [github.com/OmarPrampolini/Ouroboros](https://github.com/OmarPrampolini/Ouroboros)  
License: MIT

## What Ouroboros Is

Ouroboros is a communications platform for people who want more than "a chat app with encryption."

It is for builders, operators, teams, and privacy-minded users who care about:

- reducing dependency on centralized discovery
- keeping transport strategy under local control
- having both live sessions and asynchronous shared spaces
- building on a protocol/runtime that treats hostile networks as a first-class problem

The name matters.

The Ouroboros is the snake that bit his tail: a closed loop, self-derived, self-contained. That is the exact spirit of the project. The system tries to coordinate from within itself instead of outsourcing its identity and routing logic to an external center.

## The Three Products In One

### Handshacke

Handshacke is the live session layer.

Use it when you want:

- immediate 1:1 encrypted connectivity
- passphrase-, offer-, QR-, phrase-, or target-based pairing
- real fallback logic across LAN, WAN direct, assist relays, ORP, and Tor
- a daemon and desktop UX that behave like a product, not just a protocol demo

In code, the binary is still named `handshacke`. In product terms, this is the synchronous communication side of Ouroboros.

### EtherSync

EtherSync is the asynchronous shared-space layer.

A passphrase deterministically derives a logical encrypted space. Peers who know the same passphrase can enter the same gossip domain, publish encrypted messages, publish chunked files, and replay recent locally retained backlog when they rejoin.

Use it when you want:

- intermittent presence
- asynchronous collaboration
- a shared encrypted space without a mandatory backend
- file transfer over the same logical substrate

EtherSync is not pretending to be a centralized database. History exists only if some node observed and retained it. That limitation is real, explicit, and foundational to understanding the system honestly.

### ORP

ORP is the most ambitious part of the architecture.

A normal system splits the world into separate layers:

- one system for messages
- one system for peer discovery
- one system for routing
- one system for fallback or anonymity

ORP challenges that split.

The core intuition is this:

> if peers can already derive the same encrypted shared space, that space can become more than storage or gossip; it can also become the control plane for reachability itself

That is why ORP matters.

ORP is not interesting because it is "yet another routing protocol." ORP is interesting because it tries to make routing emerge from the same deterministic shared context that already binds the participants together.

In practical terms, ORP does the following:

- joins the same EtherSync-derived scope as the peers
- publishes route announcements inside that scope
- resolves explicit target assist tags through lookup/offer exchange
- feeds the transport stack before Tor

The conceptual move is the important one:

- **EtherSync is no longer just a feature**
- **it becomes infrastructure**
- **it becomes the place where private asynchronous state and route discovery can coexist**

Today, the correct claim is:

- ORP is a serious deterministic private overlay routing layer
- ORP is integrated as a target-aware, space-scoped transport fallback
- ORP is not yet a finished global anonymity network

That framing is strong, accurate, and worth defending.

## Why This Is Different

Most communication products assume at least one of these:

- a trusted directory for peer discovery
- a broker or relay as the default control plane
- a cloud backend as the canonical source of history

Ouroboros starts from the opposite direction.

- If two peers are online together, **Handshacke** tries to connect them live.
- If presence is intermittent, **EtherSync** gives them a deterministic encrypted shared space.
- If direct routing is difficult, **ORP** tries to recover a route from inside that same derived space before escalating to heavier infrastructure.

This is why Ouroboros is more than a stack of features. The pieces reinforce each other.

## Architecture In One Pass

### 1. Deterministic Derivation

Passphrases are canonicalized and fed into deterministic derivation pipelines.

- **Handshacke** derives rendezvous parameters, tags, and session inputs
- **EtherSync** derives shared-space identity and slot-local entropy
- **ORP** derives routing scope from active EtherSync spaces

The same secret recreates the same logical place.

### 2. Transport Cascade

When a live connection is needed, Ouroboros does not bet on one path.

It can escalate through:

- LAN discovery
- WAN direct traversal
- WAN assist relays
- ORP route discovery
- Tor fallback

This makes the system resilient to NAT asymmetry, blocked UDP, partial reachability, and hostile edge conditions.

### 3. Shared-Space Control Plane

EtherSync stores encrypted content in slot-based gossip windows.

ORP uses those same deterministic spaces as a routing control plane.

That is the architectural twist:

- messaging and route metadata can live in the same private scope
- discovery does not have to begin with a global directory
- route hints can be emitted, observed, and resolved by participants already inside the same derived context

### 4. Product Surface

The repository includes:

- the Rust daemon and protocol crates
- the Tauri desktop application
- a local REST API surface
- integration tests and fuzzing targets
- technical documentation for security and architecture

## What Is Strong Today

- Deterministic passphrase derivation across the core stack
- Local authenticated API with in-memory bearer token flow
- Multiple live connection flows: classic, offer, hybrid QR, phrase, guaranteed relay, and target-driven connect
- Multi-transport orchestration with fallback escalation
- EtherSync spaces with message publish, file chunk publish, join replay, and event streaming
- Tauri desktop UX with robust daemon lifecycle handling
- ORP integrated as a target-aware, space-scoped route discovery fallback

## What Is Not Claimed Yet

- Ouroboros does not guarantee permanent distributed retention by itself
- EtherSync history is only recoverable if some node kept it
- ORP is not being presented as a finished Tor replacement

These are not weaknesses of the README. They are the boundaries of the current truth.

## Security Posture

Ouroboros uses modern primitives and hardened local control, but it does not pretend cryptography erases operational reality.

Key characteristics:

- encrypted payloads and deterministic derivation
- replay and time-window protection
- localhost daemon API with bearer authentication
- no requirement to persist application secrets in plaintext
- dependency policy enforced with `Cargo.lock` and `deny.toml`

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

If you want the deeper technical inventory, see [docs/PROJECT_SUMMARY.md](docs/PROJECT_SUMMARY.md).

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

## Key Runtime Flows

### Handshacke

- classic passphrase connect
- offer / hybrid QR flows
- phrase mode over Tor
- relay-assisted connect
- target-driven connect

### EtherSync

- start a node
- join a shared space
- publish encrypted messages
- publish files as chunks
- consume the event stream
- replay recent local backlog on rejoin

### ORP

- activate ORP inside an EtherSync space
- publish direct reachability into that space
- resolve an explicit target assist tag through cached announcements or lookup/offer exchange
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
- `full`

Detailed semantics are documented in [docs/feature_flags.md](docs/feature_flags.md).

## Positioning

If you are presenting or selling Ouroboros, the tightest honest line is:

> **Ouroboros is a deterministic private communications platform that combines live peer sessions, encrypted shared spaces, and in-band route discovery into one serverless-first architecture.**

That is ambitious. It is also true.

## License

MIT. Commercial use is allowed.
