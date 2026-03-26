# Interop and Versioning

## Scope

This document defines the compatibility posture for Ouroboros local APIs and wire-level evolution.

## Local API

The public API namespace is `/v1`.

Core expectations:

- additive fields are allowed within `/v1`
- additive endpoints are allowed within `/v1`
- removing fields or changing meaning requires a documented migration

Boundary note:

- most `/v1` endpoints are authenticated local control-plane routes
- `POST /v1/keeper/store` is a bearer-protected network-facing operator ingress route and must not be documented as localhost-only

Key surfaces:

- `/v1/connect`
- `/v1/status`
- `/v1/capabilities`
- `/v1/interop`
- `/v1/routes/discover`
- `/v1/routes/inspect`
- `/v1/routes/status`
- `/v1/keepers/status`
- `/v1/keepers/policies`
- `/v1/keepers/backfill`
- `/v1/keeper/store`
- `/v1/ethersync/*`

Behavioral expectations:

- EtherSync startup may enrich bootstrap peers from configured discovery peers, bridge hints, and bootstrap bundles
- joining a space may seed peer knowledge from federated discovery before replay
- untrusted bootstrap bundles may still contribute opaque ingress candidates, but they must not affect trust-sensitive routing posture
- keeper status must distinguish local archive, pending remote send, failed remote send, and round-trip confirmed remote receipts
- keeper APIs may expose per-space manifests, candidate shortfall, and managed-ready posture without claiming remote keeper guarantees that do not yet exist
- joining a space may carry per-space retention and route-bias policy without changing the underlying passphrase scope
- route inspection must expose target-scoped ORP ranking inputs without inventing route semantics that the runtime does not actually use
- route status may expose high-risk circuit planning, sealed setup capsules, and live routed data-plane telemetry without advertising more anonymity than the runtime actually enforces

## CipherPacket and Session Compatibility

Current packet compatibility anchor:

- CipherPacket V2

Expectation:

- new runtime capabilities should not silently change CipherPacket framing
- transport additions should remain behind capability checks
- breaking packet-level changes require an explicit version bump and migration notes

## ORP Wire Contract

Current ORP wire family:

- `Announce`
- `Lookup`
- `Offer`
- `Forward`
- `DeliveryNotice`

Current ORP-HighRisk frame family:

- `CircuitOpen`
- `CircuitExtend`
- `CircuitClose`
- `Cover`
- `CircuitReady`

Current implementation truth:

- these frames are formalized and surfaced in interop/capability documentation
- the runtime can plan, publish, and route high-risk session traffic through the current ORP data plane
- circuit setup now ships per-hop sealed capsules instead of exposing the full route descriptor to the entire passphrase space
- the current implementation still stops short of audited anonymity guarantees and fully hardened adversarial behavior

Compatibility rule:

- ORP frame additions are additive
- unsupported frames must be ignored safely
- a runtime must not advertise `orp-highrisk` until it can interpret and enforce the high-risk contract

## EtherSync Subspaces

Formal subspace meanings:

- `0`: user payloads
- `1`: route announcements
- `2`: route lookups
- `3`: route offers
- `4`: relay beacons
- `5`: circuit open
- `6`: circuit extend
- `7`: circuit close
- `8`: cover traffic
- `9`: routed high-risk forward
- `10`: delivery notice
- `11`: circuit ready

Reserved subspaces must remain stable once published.

## Capability Reporting

Capability reporting is part of interoperability.

The runtime should expose at least:

- `quic`
- `webrtc`
- `pq_primitives`
- `orp_standard`
- `orp_highrisk`
- `keeper_replication`
- `bridge_bootstrap`

Capabilities are not marketing. They are machine-readable truth.

When the hard anonymity gate is bypassed for development, machine-readable status must distinguish strict availability from effective runtime posture instead of silently reporting `high-risk` as uniformly available.

## Deprecation Policy

The project follows this rule:

- additive minor evolution is preferred
- breaking wire changes require explicit migration notes
- high-risk claims are blocked until implementation and audit gates are passed

## Client Matrix

Current expectation:

- Rust daemon is canonical
- desktop app is first-party
- future mobile clients must consume `/v1` and the stable wire contracts without guessing hidden semantics

The repo should always remain understandable enough that a new client implementation can be built from docs plus code.
