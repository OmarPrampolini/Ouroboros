# Threat Model Book

## Scope

This document summarizes the threat classes that matter for Ouroboros.

## Threat Classes

### Consumer surveillance

Goal:

- inspect metadata
- learn who talks to whom
- correlate timing and transport choices

Relevant controls:

- encrypted payloads
- deterministic coordination without mandatory accounts
- transport cascade
- ORP-Standard before Tor

### Relay compromise

Goal:

- observe flow metadata
- bias routing
- degrade anonymity claims

Relevant controls:

- route diversity
- operator diversity
- future circuit compartmentalization
- hard block on High-Risk claims until diversity telemetry exists

### Censorship and hostile networks

Goal:

- block ingress
- fingerprint traffic
- force fallback into brittle paths

Relevant controls:

- assist relays
- Tor fallback
- future bridge operators
- pluggable transport work

### Keeper compromise

Goal:

- inspect retained content
- deanonymize replication
- reduce availability

Relevant controls:

- encrypted envelopes only
- minimal metadata retention
- replication factor
- operator attestation

### Route poisoning and Sybil pressure

Goal:

- eclipse spaces
- insert bad routes
- concentrate paths through one operator

Relevant controls:

- ORP scoring
- operator diversity checks
- future Sybil friction and path quality policy

## Current Boundary

Ouroboros today is strongest as a deterministic private communications platform.

It is not yet justified to claim:

- global anonymity network
- audited high-risk overlay
- byzantine-hardened operator ecosystem

Keeping this boundary explicit is part of the security model.
