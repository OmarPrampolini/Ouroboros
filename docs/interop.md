# Interop and Versioning

## Scope

This document defines the compatibility posture for Ouroboros local APIs and wire-level evolution.

## Local API

The public local control plane is `/v1`.

Core expectations:

- additive fields are allowed within `/v1`
- additive endpoints are allowed within `/v1`
- removing fields or changing meaning requires a documented migration

Key surfaces:

- `/v1/connect`
- `/v1/status`
- `/v1/capabilities`
- `/v1/routes/discover`
- `/v1/routes/status`
- `/v1/keepers/status`
- `/v1/keepers/backfill`
- `/v1/ethersync/*`

Behavioral expectations:

- EtherSync startup may enrich bootstrap peers from configured discovery peers, bridge hints, and bootstrap bundles
- joining a space may seed peer knowledge from federated discovery before replay
- keeper status must distinguish pending replication from archived replicated envelopes

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
- `Ack`

Reserved and formalized for ORP-HighRisk:

- `CircuitOpen`
- `CircuitExtend`
- `CircuitClose`
- `Cover`

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
