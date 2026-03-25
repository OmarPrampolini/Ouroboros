# Roadmap and Gates

## Program Shape

This is the companion roadmap for the A to Z blueprint. It is not a loose feature list. Each milestone has gates that protect architectural honesty.

## M1 - Wire Stability, Repo Gravity, Canonical Docs

Target:

- canonical docs
- stable naming
- public capability matrix
- explicit privacy tiers
- ORP wire contract formalization

Gate:

- zero fmt drift and zero warning debt on touched core surfaces
- README can explain product, architecture, and truth boundary on its own
- ADRs exist for deterministic scope, dual-tier privacy, hybrid network, keeper model, ORP claim boundary
- `/v1/capabilities`, `/v1/routes/status`, `/v1/keepers/status`, and `/v1/ethersync/status` reflect the architecture truthfully

## M2 - ORP-Standard, Keeper MVP, Managed Bootstrap

Target:

- production-grade ORP-Standard
- keeper-backed retention MVP
- first managed relay and bridge set

Gate:

- ORP scoring, route classes, diagnostics, and interop tests are production-worthy
- keeper replication is measurable and visible in API and UI
- bootstrap bundles are signed and mirrorable
- Standard Private is a serious product tier

## M3 - ORP-HighRisk, Bridges, Desktop Adversarial Mode

Target:

- multi-hop onion overlay
- circuit lifecycle
- padding and cover policy
- bridge ingress rotation
- hard anonymity gating

Gate:

- no single relay sees both ends
- circuit rotation and path expiry are measured
- diversity checks exist and are enforced
- High-Risk is unavailable when thresholds are not met

## M4 - Audit, Claim Unlock, Launch Readiness

Target:

- external audit
- benchmark publication
- operator program expansion
- public claim unlock

Gate:

- external audit complete
- simulation suite complete
- anonymity and decentralization thresholds are met
- multi-operator multi-region network verified

## Quantified Gates

### Standard Private targets

- live connect p50 <= 2.5s
- live connect p95 <= 8s on normal networks
- live connect p95 <= 15s under degraded fallback conditions
- EtherSync join-to-replay-start p95 <= 2s
- EtherSync replay-complete p95 <= 10s for standard local backlog
- ORP-Standard route resolution p50 <= 1.5s
- ORP-Standard route resolution p95 <= 6s in healthy active spaces

### High-Risk targets

- circuit establishment p50 <= 6s
- circuit establishment p95 <= 20s
- layered encryption per hop
- rotation without source-plus-target exposure to one relay

## Hard Anonymity Gate

High-Risk must be disabled unless all are true:

- at least 64 eligible relay nodes
- at least 16 distinct operator identities
- at least 6 region or ASN buckets
- no operator above 15% observed capacity
- at least one valid 3-hop path with operator and region diversity

Public anonymity-network claim unlock requires:

- at least 1,024 active anonymity participants in the target observation window
- at least 32 operator identities
- at least 8 region or ASN buckets
- audits and adversarial simulation complete

## Mobile Policy

The design must remain mobile-compatible, but High-Risk is desktop-first until resource-aware cover traffic policy exists. Mobile compatibility is not allowed to dilute the adversarial guarantees of High-Risk.
