# Operator Model

## Purpose

Ouroboros is not a fantasy about a network with no operators. It is a system with explicit operator roles and explicit incentives.

## Roles

### Relay operators

Relay operators provide:

- forwarding capacity
- route diversity
- assist semantics
- future high-risk hop participation

### Bridge operators

Bridge operators provide:

- bootstrap mirrors
- ingress resilience
- censorship resistance support
- future signed bridge bundles

### Keeper operators

Keeper operators provide:

- encrypted replicated retention
- managed replay durability
- availability SLOs for paid tiers
- keeper candidate capacity that is now surfaced per space through local keeper manifests and shortfall diagnostics

Keepers do not own the application plaintext. They store encrypted envelopes and minimal availability metadata.

## Economics

The initial network model is deliberately practical.

- no token economy
- no speculative operator market
- no fake decentralization theatre

Instead:

- first-party and partner-operated infrastructure
- revenue from subscriptions
- enterprise and workspace retention tiers
- managed network services and support

## Enrollment

Initial enrollment model:

- first-party relays, bridges, and keepers
- selected partners
- public third-party operator enrollment later, after attestation and compatibility policy are stable

## Visibility and Accountability

Operators must be measurable.

Required long-term telemetry:

- reachable capacity
- software version
- operator identity
- region and deployment bucket hints
- route diversity contribution
- failure rate
- maintenance windows

Current runtime posture already surfaces:

- operator identity hints
- operator region hints
- bridge/keeper bundle posture
- per-space keeper manifest counts and candidate shortfall

High-Risk must not be enabled unless operator diversity is sufficient and measurable.

## Abuse and Safety

Operator openness does not mean operator opacity.

The project must eventually publish:

- operator requirements
- abuse handling policy
- retention handling policy
- update obligations
- incident response expectations

## Why This Matters

Ouroboros is commercially viable because it can fund real reliability without surrendering the protocol to centralized identity and routing assumptions.
