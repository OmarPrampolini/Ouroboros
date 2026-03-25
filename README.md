# Ouroboros, the snake that bit his tail

Private communication, shared encrypted spaces, and in-band route discovery - built as one deterministic system.

Ouroboros is not a messenger that happens to have some crypto. It is not a protocol whitepaper detached from product reality either. It is an attempt to build a serious communications stack where the same private context can drive:

- live encrypted sessions
- asynchronous shared spaces
- route discovery and future anonymity overlays

The core thesis is simple and strange:

> the same secret should recreate the same communication reality

That means a passphrase is not just a password. In Ouroboros it becomes derivation input, rendezvous scope, shared-space identity, and routing scope.

From that idea the system grows into three planes:

- **Handshacke**: the live session plane
- **EtherSync**: the encrypted shared-state plane
- **ORP**: the Ouroboros Routing Protocol, the routing and anonymity control plane

Repository: [github.com/OmarPrampolini/Ouroboros](https://github.com/OmarPrampolini/Ouroboros)  
License: MIT

## What Ouroboros Is

Ouroboros is a deterministic private communications platform for people who want more than "encrypted chat".

It is meant for:

- builders who care about protocol clarity
- operators who care about fallback and network reality
- teams who want shared encrypted spaces without mandatory cloud identity
- privacy-minded users who do not want discovery and routing outsourced by default

The name is not decoration. The snake that bit his tail represents a loop that closes on itself. Ouroboros tries to coordinate from within its own derived context instead of depending on a permanent external center.

## The Three Planes

### Handshacke

Handshacke is the live session plane. It is the synchronous side of the product and the runtime still ships under the `handshacke` binary name for compatibility.

It covers:

- passphrase-based connect
- offer and QR-based rendezvous
- phrase and onion-based pairing
- target-driven connect
- live transport escalation across LAN, WAN direct, assist relays, ORP, and Tor

The important point is that transport is not hidden magic. Ouroboros treats real hostile-network conditions as part of the product.

### EtherSync

EtherSync is the encrypted shared-state substrate.

Peers who know the same passphrase can derive the same logical space and use it for:

- encrypted message publication
- chunked file publication
- intermittent presence
- replay of recently retained local history
- private metadata exchange

EtherSync is not pretending to be a centralized database. If nobody retained a message, that history is gone. That limitation is not hand-waved away because architectural honesty matters more than fake convenience.

### ORP

ORP is where the architecture becomes unusual.

In most systems, messaging, peer discovery, routing, and anonymity live in separate worlds. ORP challenges that split. The same derived EtherSync space that already lets peers share encrypted context can also carry reachability metadata and route intent.

That is the real ORP idea:

> the shared space is not only where peers leave encrypted state; it can also become the control plane that tells the network how to find them

This is why ORP matters. It is not "another overlay". It is an attempt to make routing emerge from the same private deterministic context that already binds participants together.

In practical terms, ORP currently does this:

- publishes route announcements inside a shared EtherSync-derived scope
- resolves explicit target assist tags through cache and lookup-offer exchange
- feeds the transport stack before Tor

In architectural terms, it does something more important:

- EtherSync stops being just a feature
- EtherSync becomes infrastructure
- routing starts living inside the same private shared world as messaging

The current truthful claim is:

- ORP is a serious deterministic private overlay routing direction
- ORP is integrated as a target-aware, space-scoped transport fallback
- ORP is not yet a finished global anonymity network

That boundary is deliberate. We do not unlock that claim until the system actually earns it.

## Privacy Tiers

Ouroboros has two permanent privacy tiers.

### Standard Private

This is the default operational tier.

It optimizes for:

- encrypted communication
- deterministic coordination
- resilient fallback
- product usability

### High-Risk

This is the adversarial tier.

It is designed to require:

- multi-hop overlay circuits
- layered encryption per hop
- cover traffic and padding
- operator diversity
- bridge ingress
- hard anonymity gating

High-Risk is intentionally blocked today. The runtime surfaces that boundary instead of silently pretending.

## Network Model

Ouroboros is a hybrid network, not a fantasy about pure decentralization and not a surrender to centralized control either.

The end-state network has four roles:

- `edge peers`
- `relay operators`
- `bridge operators`
- `keeper nodes`

This matters because global scale requires explicit operations:

- relays for forwarding and route diversity
- bridges for ingress resilience and censorship resistance
- keepers for encrypted managed retention

No central directory is structurally required, but the system is not anti-operations. It is designed to combine deterministic coordination with real network stewardship.

## Keeper Model

The keeper model is intentionally pragmatic.

- no token economy
- no speculative governance fiction
- first-party and partner-operated keepers first
- protocol openness preserved for later third-party enrollment

Free usage remains local and best-effort. Managed retention is where keeper-backed replay, replication factor, and availability SLOs enter the picture.

## Why This Is Different

Most communication products assume at least one of the following:

- a trusted global directory
- a cloud backend as the source of truth
- a relay layer that is also the mandatory control plane

Ouroboros tries to do something harder.

- If both peers are online, **Handshacke** tries to connect them live.
- If presence is intermittent, **EtherSync** gives them a deterministic encrypted shared space.
- If routing gets hard, **ORP** tries to recover a path from inside that same derived scope before escalating to heavier infrastructure.

That is why the project is more than a pile of features. The pieces explain each other.

## Current Runtime Truth

Strong today:

- deterministic derivation across the core stack
- authenticated local API
- multiple live connect flows
- transport cascade with real fallback logic
- EtherSync message and file publication with replay window
- ORP target-aware route discovery before Tor

Explicitly not claimed yet:

- global anonymity network
- production keeper-backed replicated retention
- audited high-risk multi-hop overlay

## Public API

The local control plane lives under `/v1`.

Representative endpoints:

- `POST /v1/connect`
- `GET /v1/status`
- `GET /v1/capabilities`
- `GET /v1/routes/status`
- `GET /v1/keepers/status`
- `GET /v1/ethersync/status`
- `POST /v1/ethersync/start`
- `POST /v1/ethersync/spaces/join`
- `POST /v1/ethersync/spaces/publish`
- `POST /v1/ethersync/files/publish`
- `GET /v1/ethersync/events`

The API now exposes:

- privacy profile intent
- route and ORP diagnostics
- keeper and retention scaffolding
- capability reporting for `quic`, `webrtc`, `pq`, ORP tiers, and bridge bootstrap posture

## Wire and Interop Posture

Ouroboros is moving toward a documented wire contract, not tribal knowledge.

Current anchors:

- CipherPacket V2 for session framing
- stable EtherSync subspace meanings for user data and ORP metadata
- additive ORP wire-family formalization for future high-risk circuits

The ORP family now has canonical frame names:

- `Announce`
- `Lookup`
- `Offer`
- `Forward`
- `Ack`
- `CircuitOpen`
- `CircuitExtend`
- `CircuitClose`
- `Cover`

The last four are formalized as contract and roadmap, not presented as live high-risk anonymity guarantees.

## Canonical Documentation

If you want the system-level map, start here:

- [Architecture Book](./docs/ARCHITECTURE_BOOK.md)
- [Roadmap and Gates](./docs/roadmap_gates.md)
- [Interop and Versioning](./docs/interop.md)
- [Operator Model](./docs/operators.md)
- [Threat Model Book](./docs/threat_model_book.md)
- [Feature Flags](./docs/feature_flags.md)
- [Project Summary](./docs/PROJECT_SUMMARY.md)

Architecture decisions:

- [ADR 0001 - Deterministic Scope](./docs/adr/0001-deterministic-scope.md)
- [ADR 0002 - Dual-Tier Privacy](./docs/adr/0002-dual-tier-privacy.md)
- [ADR 0003 - Hybrid Network](./docs/adr/0003-hybrid-network.md)
- [ADR 0004 - Keeper Model](./docs/adr/0004-keeper-model.md)
- [ADR 0005 - ORP Claim Boundary](./docs/adr/0005-orp-claim-boundary.md)

## Repository Layout

```text
Ouroboros/
|-- src/                  # Main daemon and API surface
|-- ethersync/            # Shared-space substrate and ORP wire/control primitives
|-- ouroboros-crypto/     # Shared cryptographic primitives
|-- ui/                   # Tauri desktop application
|-- docs/                 # Canonical product, architecture, and operator documentation
|-- tests/                # Integration tests
`-- fuzz/                 # Fuzzing targets
```

## Quick Start

### Build the daemon

```bash
git clone https://github.com/OmarPrampolini/Ouroboros.git
cd Ouroboros
cargo build --release
cargo run --release
```

Default API bind: `127.0.0.1:8731`

### Build the desktop app

```bash
cargo build --release

# Windows
# copy target\\release\\handshacke.exe ui\\src-tauri\\bin\\handshacke.exe

# Linux/macOS
# cp target/release/handshacke ui/src-tauri/bin/handshacke

cd ui
npm install
npm run dev
```

## Positioning

If you need the shortest honest line:

> **Ouroboros is a deterministic private communications platform that unifies live peer sessions, encrypted shared spaces, and in-band route discovery into one serverless-first architecture.**

If you need the stronger architectural line:

> **Ouroboros turns the same secret into rendezvous scope, shared-state identity, and routing scope, so communication can coordinate from inside its own derived context instead of depending on a permanent external center.**

That is the bet.

## License

MIT. Commercial use is allowed.
