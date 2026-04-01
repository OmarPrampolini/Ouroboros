# ORP MVP Specification

## Reality Check

ORP is not a greenfield protocol in this repository.
The current codebase already contains most of the primitives needed to build it:

- deterministic secret derivation in `src/derive.rs`
- temporal space derivation in `ethersync/src/coordinate.rs`
- encrypted slot-bound messaging in `ethersync/src/message.rs`
- gossip forwarding with TTL and digest exchange in `ethersync/src/gossip.rs`
- relay-assisted forwarding in `src/transport/wan_assist.rs`
- anti-correlation batching in `src/transport/dandelion.rs`

What is missing today is the unification layer.
EtherSync still assumes known peers at bootstrap time, and the transport layer does not yet expose a routing overlay between direct P2P attempts and Tor fallback.

This document defines the minimum ORP that can be implemented on top of the current code without a full rewrite.

## Goal

ORP (Ouroboros Routing Protocol) turns EtherSync slots into a deterministic routing control plane.
Peers that share a passphrase and are active in the same slot can exchange encrypted reachability hints and opportunistically relay traffic for one another.

The MVP goal is not "replace Tor".
The MVP goal is:

- remove static EtherSync bootstrap as a hard requirement
- add a deterministic route-discovery layer inside shared spaces
- reuse existing relay and dandelion components as the first ORP data plane
- expose ORP as a transport fallback between direct WAN and Tor

## Non-Goals For MVP

- global anonymous routing across arbitrary spaces
- Sybil resistance strong enough for hostile public deployment
- directory-authority replacement for the open internet
- full onion routing with layered cryptographic hop encryption
- production claims of "relay does not know" beyond best-effort metadata reduction

## MVP Architecture

ORP is split into two parts:

1. Control plane
   - implemented inside EtherSync
   - advertises ephemeral reachability inside deterministic slot spaces
   - answers route lookups and forwards route offers

2. Data plane
   - initially reuses existing assisted forwarding and dandelion batching
   - later can grow into multi-hop framed transport

In the MVP, ORP does not replace EtherSync.
It is implemented as a reserved EtherSync subspace and a route cache attached to `EtherNode`.

## Core Model

### Shared Terms

- `space_hash`: deterministic identifier of the shared logical space
- `slot`: current temporal bucket
- `subspace`: reserved logical channel inside the same passphrase
- `relay descriptor`: encrypted hint that a peer is online and reachable enough to participate
- `route offer`: encrypted response that provides a candidate next hop or forwarding path

### Reserved ORP Subspaces

The existing `EtherCoordinate` already supports `subspace`, but message derivation currently hardcodes `0`.
ORP should reserve the following values:

- `0`: user/application payloads (existing behavior)
- `1`: route announcements
- `2`: route lookups
- `3`: route offers
- `4`: relay health beacons

This allows ORP traffic to reuse the same passphrase while remaining logically separate from normal EtherSync payloads.

### New ORP Frames

The MVP introduces a dedicated routing payload enum transported inside normal `EtherMessage` ciphertexts.

```rust
pub enum OrpFrame {
    Announce(RouteAnnouncement),
    Lookup(RouteLookup),
    Offer(RouteOffer),
    Forward(RouteForward),
    Ack(RouteAck),
}
```

Recommended initial structs:

```rust
pub struct RouteAnnouncement {
    pub version: u8,
    pub slot: u64,
    pub node_id: [u8; 16],
    pub capabilities: RouteCapabilities,
    pub reachable_udp: Vec<std::net::SocketAddr>,
    pub assist_tag: [u8; 8],
    pub expires_at_slot: u64,
}

pub struct RouteLookup {
    pub version: u8,
    pub lookup_id: [u8; 16],
    pub target_tag: [u8; 8],
    pub max_hops: u8,
    pub ttl: u8,
}

pub struct RouteOffer {
    pub version: u8,
    pub lookup_id: [u8; 16],
    pub responder_id: [u8; 16],
    pub next_hop: RouteHop,
    pub score: u16,
}

pub struct RouteForward {
    pub version: u8,
    pub circuit_id: [u8; 16],
    pub hop_index: u8,
    pub remaining_hops: u8,
    pub payload: Vec<u8>,
}

pub struct RouteAck {
    pub version: u8,
    pub circuit_id: [u8; 16],
    pub delivered_hop: u8,
}
```

## How MVP ORP Works

### 1. Announcement

When an `EtherNode` joins a space, it periodically publishes a `RouteAnnouncement` into subspace `1` for the current slot and near-future slots.

That announcement is encrypted with the same passphrase-bound EtherSync key schedule, so only space members can decode it.

At minimum the announcement contains:

- ephemeral node id for the slot
- observed UDP/TCP endpoints if available
- whether WAN assist is available
- whether the peer can act as a store-and-forward relay
- expiration slot

### 2. Lookup

If direct connection fails, the caller derives the route target from current rendezvous material and publishes a `RouteLookup` into subspace `2`.

Peers that can help answer with a `RouteOffer` in subspace `3`.

The first version does not need path search across arbitrary graphs.
It only needs:

- direct target known by another peer
- a peer willing to act as a one-hop forwarding bridge
- optionally a short two-hop offer if both hops are already locally known

### 3. Offer Selection

The requesting node keeps a short-lived route cache and scores offers by:

- same-slot freshness
- direct reachability
- NAT friendliness
- relay capability
- number of hops

The chosen offer is then passed into the ORP transport path.

### 4. Forwarding

The MVP forwarding path should reuse existing WAN assist semantics instead of inventing a new transport immediately.

Initial rule:

- if a route offer includes direct peer reachability, try `connect_to` or existing direct path
- if a route offer includes relay capability, use ORP-selected relay as an assisted forwarding target
- if ORP fails, fall back to configured assist relays
- if that fails, fall back to Tor

This keeps ORP on the control plane first and only lightly extends the data plane.

## Required Code Changes

### Phase 0: Generalize EtherSync To Support Reserved Subspaces

This is the prerequisite that unlocks the rest.

Files:

- `ethersync/src/message.rs`
- `ethersync/src/node.rs`
- `ethersync/src/lib.rs`

Changes:

- add `subspace: u64` to `EtherMessageHeader`
- change `EtherMessage::new()` to accept `subspace`
- change coordinate-hash derivation to use the provided subspace instead of hardcoded `0`
- keep user payloads on subspace `0` for backward compatibility
- add helper constructors for `new_user_message()` and `new_control_message()`

Why first:

- ORP needs logical channels inside the same space
- without subspaces, routing frames would be mixed with user payloads

### Phase 1: Add ORP Module To EtherSync

Files to add:

- `ethersync/src/routing.rs`

Files to update:

- `ethersync/src/lib.rs`
- `ethersync/src/node.rs`
- `ethersync/src/gossip.rs`

Responsibilities of `routing.rs`:

- define `OrpFrame` and routing structs
- serialize and deserialize routing payloads
- keep a `RouteCache`
- track `RouteAnnouncement` freshness by `(space_hash, slot, node_id)`
- provide candidate scoring

Recommended core types:

```rust
pub struct RouteCache {
    pub announcements: std::collections::HashMap<RouteKey, CachedAnnouncement>,
    pub offers: std::collections::HashMap<[u8; 16], Vec<CachedOffer>>,
}

pub struct CachedAnnouncement {
    pub frame: RouteAnnouncement,
    pub last_seen: std::time::Instant,
    pub source_peer: std::net::SocketAddr,
}

pub struct CachedOffer {
    pub frame: RouteOffer,
    pub last_seen: std::time::Instant,
}
```

Changes in `EtherNode`:

- add route cache state
- publish route announcements on startup and periodically while subscribed
- inspect incoming control messages and feed them into the route cache
- expose `lookup_route(passphrase, target_tag)` and `best_route(passphrase, target_tag)`

Changes in `GossipEngine`:

- keep existing forwarding behavior
- do not special-case ORP at the transport framing layer
- instead, allow `EtherNode` to parse payloads after decryption and detect whether they are user payloads or ORP control frames

### Phase 2: Route Discovery Service

Files to add:

- `src/transport/orp.rs`

Files to update:

- `src/transport/mod.rs`
- `src/discovery.rs`

Responsibilities of `src/transport/orp.rs`:

- bridge EtherSync route cache into transport connection attempts
- expose `try_orp_route(...) -> Result<Connection>`
- convert selected `RouteOffer` into either:
  - direct peer dial
  - ORP relay-assisted forwarding
  - deferred retry until next slot if applicable

Changes in `src/transport/mod.rs`:

- add ORP between direct WAN and Tor fallback
- record ORP metrics in `network_telemetry`
- treat ORP as "deterministic overlay route", not as a new low-level socket primitive

Changes in `src/discovery.rs`:

- add an ORP-backed provider or helper that consumes route announcements from EtherSync
- keep existing discovery service intact
- make bootstrap peers a fallback, not the primary path, when ORP is active

### Phase 3: API Surface

Files to update:

- `src/api/ethersync.rs`
- API request/response types under `src/api/`
- state plumbing under `src/state.rs` or related state modules

Additions:

- endpoint or status field exposing ORP state
- ability to enable ORP when starting EtherSync
- diagnostics for:
  - last route announcements seen
  - number of route offers cached
  - last ORP fallback reason

Recommended shape:

- `POST /v1/ethersync/start` gains `enable_orp: bool`
- `GET /v1/ethersync/status` reports `orp_enabled`, `route_cache_size`, `last_orp_activity_ms`

### Phase 4: Hardening

Files likely involved:

- `ethersync/src/gossip.rs`
- `src/transport/dandelion.rs`
- `src/transport/wan_assist.rs`
- tests under `ethersync/tests/` and `tests/`

Hardening goals:

- cap route cache growth
- reject expired slot announcements
- rate-limit route lookups per space and sender
- prefer same-slot or plus-one-slot announcements only
- add randomized delay before responding to lookups
- use dandelion batching for forwarded route responses when enabled

## Implementation Order

The recommended implementation order is strict.
Do not skip ahead.

1. Generalize `EtherMessage` for `subspace`
2. Add ORP frame definitions and route cache
3. Teach `EtherNode` to publish announcements and consume offers
4. Add `try_orp_route()` in transport
5. Insert ORP into transport fallback chain
6. Add API diagnostics
7. Add tests and hardening

## Suggested Function Signatures

These signatures are intentionally conservative and aligned with the existing code style.

```rust
impl EtherNode {
    pub async fn publish_route_announcement(
        &self,
        passphrase: &str,
    ) -> Result<(), EtherSyncError>;

    pub async fn lookup_route(
        &self,
        passphrase: &str,
        target_tag: [u8; 8],
    ) -> Result<[u8; 16], EtherSyncError>;

    pub async fn best_route(
        &self,
        passphrase: &str,
        target_tag: [u8; 8],
    ) -> Result<Option<RouteOffer>, EtherSyncError>;
}
```

```rust
pub async fn try_orp_route(
    node: &ethersync::EtherNode,
    params: &crate::derive::RendezvousParams,
    cfg: &crate::config::Config,
) -> Result<crate::transport::Connection, Box<dyn std::error::Error + Send + Sync>>;
```

## Testing Plan

### Unit Tests

- subspace changes produce distinct coordinate hashes
- ORP frames serialize and deserialize deterministically
- expired announcements are rejected
- route scoring prefers fresher and shorter paths

### Integration Tests

- two peers in the same slot discover each other via ORP announcements
- a third peer can answer a route lookup with an offer
- transport fallback uses ORP before Tor
- ORP-disabled nodes preserve current behavior

### End-To-End Tests

- publish route announcement, drop direct path, recover via ORP-selected relay
- stale-slot lookup is ignored
- bootstrap peer list empty but ORP path still works if shared slot peers exist

## Security Notes

The MVP should be documented honestly:

- ORP reduces explicit bootstrap dependency
- ORP does not eliminate the need for online peers
- ORP in MVP is private-space deterministic overlay routing, not full anonymous onion routing
- route announcements leak some reachability metadata to members of the same passphrase space
- hostile-space membership remains an unsolved Sybil and traffic-analysis problem

Those constraints are acceptable for the first implementation.
The important win is architectural: routing becomes an emergent property of shared deterministic space membership.

## Deliverable Checklist

- [ ] EtherSync subspace support
- [ ] `ethersync/src/routing.rs`
- [ ] route announcement publication
- [ ] route lookup and offer handling
- [ ] `src/transport/orp.rs`
- [ ] ORP fallback inserted before Tor
- [ ] API and status diagnostics
- [ ] unit, integration, and e2e coverage

## Bottom Line

ORP should be implemented as a deterministic overlay inside EtherSync first, and only later expanded into a stronger multi-hop anonymity layer.

That path fits the repository as it exists today.
It reuses the strongest parts already present in the codebase, minimizes rewrite risk, and gives the project a concrete route away from static bootstrap peers.
