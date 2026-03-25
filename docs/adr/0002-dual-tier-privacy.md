# ADR 0002 - Dual-Tier Privacy

## Status

Accepted

## Decision

Ouroboros has two permanent privacy tiers: `Standard Private` and `High-Risk`.

## Why

A single privacy promise would either oversell current capabilities or cripple the product for normal users. The honest design is to separate strong default privacy from adversarial high-risk privacy.

## Consequences

- `Standard Private` can be product-grade earlier
- `High-Risk` gets hard activation gates
- no silent downgrade is allowed
