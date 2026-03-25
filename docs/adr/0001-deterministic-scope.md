# ADR 0001 - Deterministic Scope

## Status

Accepted

## Decision

Passphrase-derived deterministic scope is a permanent architectural foundation.

## Why

The project differentiates itself by making the same secret recreate the same logical communication context. This applies to rendezvous, shared spaces, and routing scope.

## Consequences

- no mandatory global account system
- no mandatory central directory
- deterministic coordination remains first-class
- passphrase hygiene and canonicalization remain critical
