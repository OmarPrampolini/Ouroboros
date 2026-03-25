# ADR 0003 - Hybrid Network

## Status

Accepted

## Decision

Ouroboros is a hybrid network with explicit operator roles.

## Why

Purely serverless systems struggle with availability, retention, bootstrap, and adversarial scale. Pure centralization breaks the project thesis. A hybrid network preserves deterministic coordination while allowing real operational reliability.

## Consequences

- relay, bridge, and keeper roles become first-class
- operator tooling and policy matter as much as protocol purity
- network economics are planned, not improvised
