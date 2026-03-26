# Ouroboros Architecture Book

## Purpose

This document is the canonical high-level architecture reference for Ouroboros.

Ouroboros is designed as one coherent system with three tightly coupled planes:

- Handshacke: live encrypted session plane
- EtherSync: encrypted shared-state plane
- ORP: routing and anonymity control plane

The system is intentionally serverless-first, deterministic, and privacy-aware, but it is not anti-operations. The final architecture is a hybrid network with explicit operator roles, explicit product tiers, and explicit truth boundaries.

## North Star

Ouroboros is both:

- a flagship product that users can operate without reading the source
- a protocol stack that can survive serious architectural scrutiny

The project is not trying to become "just another encrypted messenger" and it is not trying to become a vague protocol toy. It is building a communications stack where identity, shared spaces, and reachability can be derived from the same private context.

## Core Thesis

The same secret should recreate the same communication reality.

That thesis drives the whole stack:

- the passphrase is not only an authentication token
- it is derivation input
- it is rendezvous scope
- it is shared-space identity
- it is routing scope

This is why Ouroboros is named after the snake that bit his tail. The system attempts to coordinate from within its own derived context instead of depending on a permanent external directory.

## Product Surfaces

### Handshacke

Handshacke is the live session plane.

It covers:

- live peer sessions
- offer and QR-based rendezvous
- phrase and onion-based pairing
- target-driven connect
- transport cascade across LAN, WAN, assist, ORP and Tor

The binary remains `handshacke` for compatibility. Publicly, this is part of Ouroboros.

### EtherSync

EtherSync is the encrypted shared-state substrate.

It covers:

- deterministic shared spaces derived from passphrases
- slot-based message publication
- file chunk publication
- replay of recent locally retained history
- asynchronous presence and route metadata

EtherSync is the bridge between purely live communication and persistent shared context.

### ORP

ORP is the Ouroboros Routing Protocol.

It is not interesting because it is another overlay. It is interesting because it tries to make route discovery emerge from the same private shared context already used for encrypted coordination.

Today:

- ORP-Standard is the active design target
- ORP is target-aware and space-scoped
- ORP feeds the transport stack before Tor
- ORP inspection surfaces can expose ranked target candidates, route classes, operator hints, region hints, and lookup provenance
- ORP-HighRisk now has a routed session data plane in the runtime, with per-hop sealed setup capsules and rotating announcement onion keys, but it is still not presented as an audited anonymity guarantee

End-state:

- ORP-Standard provides production-grade private overlay routing
- ORP-HighRisk provides multi-hop onion circuits, padding, cover traffic, and hard anonymity gating
- untrusted bootstrap bundles may be used as opaque ingress assist, but they must not be treated as trusted routing truth

## Privacy Tiers

Ouroboros has two permanent privacy tiers.

### Standard Private

Standard Private optimizes for:

- encrypted communication
- deterministic coordination
- resilient fallback
- low operational friction

This tier is the default and is meant to be product-grade.

### High-Risk

High-Risk optimizes for:

- path privacy
- metadata minimization
- multi-hop overlay routing
- operator diversity
- bridge ingress
- anti-correlation policy

This tier must never silently downgrade. If the anonymity gate is not satisfied, the runtime must report `High-Risk unavailable`.

## Network Model

Ouroboros is a hybrid network.

The final system has four explicit roles:

- edge peers
- relay operators
- bridge operators
- keeper nodes

### Edge peers

Normal clients. They consume the product and participate in deterministic spaces.

### Relay operators

They forward traffic and participate in route discovery and high-risk path formation.

### Bridge operators

They provide ingress resilience, mirror bootstrap bundles, and help censored clients enter the network.

### Keeper nodes

They provide encrypted replicated retention for managed tiers. They are not trusted with plaintext application data.

## Keeper Model

Keeper economics are deliberately boring.

The initial model is:

- no token economy
- first-party and partner-operated keepers
- revenue from subscriptions, enterprise retention tiers, and managed network services

The protocol remains open to third-party keepers later, but operator enrollment is staged and attested.

## Control Plane and Data Plane

### Deterministic scope

Passphrases are canonicalized and fed into derivation pipelines that create:

- rendezvous parameters
- shared-space identity
- slot-local routing scope

### Shared-state plane

EtherSync carries:

- user messages
- file chunks
- replayable local history
- ORP metadata
- future retention hints

### Routing plane

ORP currently formalizes these frame families:

- `Announce`
- `Lookup`
- `Offer`
- `Forward`
- `DeliveryNotice`
- `CircuitOpen`
- `CircuitExtend`
- `CircuitClose`
- `Cover`

The full high-risk frame family now exists in the runtime and interop surface, but it must not be marketed as an audited anonymity feature until hardening and audit gates are passed.

The `/v1` namespace is mostly authenticated local control-plane surface. The deliberate exception is `POST /v1/keeper/store`, which is a bearer-protected network-facing operator ingress route and must be treated as such in docs and diagnostics.

## Transport Strategy

The transport cascade is part of the product, not a hidden implementation detail.

The system can escalate through:

- LAN
- WAN direct
- assist relays
- ORP-Standard
- Tor

High-Risk adds its own multi-hop overlay semantics on top of this world. It is not simply "ORP plus more flags". It is a separate privacy contract with hard gates.

## Retention Model

Ouroboros distinguishes between:

- local replay
- keeper-backed replay
- route metadata retention
- bootstrap metadata

Current truth:

- local replay exists
- a local keeper replica archive exists as a managed-retention scaffold
- backfill can restore archived encrypted envelopes into local replay storage
- retention and route bias can now be expressed per joined space
- ORP-Standard ranking now reacts to operator posture, bundle posture, and region diversity hints
- remote keeper selection, round-trip store receipts, and managed replication posture now exist in the runtime
- fully independent multi-operator keeper replication is still a next-stage hardening task

This distinction must remain explicit in product language and in API surfaces.

## Current Truth Boundary

Claims that are true today:

- Ouroboros is a deterministic private communications platform
- Handshacke, EtherSync, and ORP already reinforce each other
- ORP is a real private overlay routing direction, not a fake placeholder

Claims that are not yet unlocked:

- global anonymity network
- production keeper-backed retention
- operator-diverse high-risk overlay

## Canonical References

- [README.md](../README.md)
- [docs/roadmap_gates.md](./roadmap_gates.md)
- [docs/operators.md](./operators.md)
- [docs/bootstrap_bundle.md](./bootstrap_bundle.md)
- [docs/interop.md](./interop.md)
- [docs/threat_model_book.md](./threat_model_book.md)
- [docs/adr/0001-deterministic-scope.md](./adr/0001-deterministic-scope.md)
- [docs/adr/0002-dual-tier-privacy.md](./adr/0002-dual-tier-privacy.md)
- [docs/adr/0003-hybrid-network.md](./adr/0003-hybrid-network.md)
- [docs/adr/0004-keeper-model.md](./adr/0004-keeper-model.md)
- [docs/adr/0005-orp-claim-boundary.md](./adr/0005-orp-claim-boundary.md)
