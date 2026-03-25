# Bootstrap Bundle

## Purpose

Bootstrap bundles are the first concrete step toward a managed-but-open network posture.

They let a node describe, ingest, and expose structured knowledge about:

- relay operators
- bridge endpoints
- keeper endpoints
- mirror sources

The goal is not to reintroduce a mandatory central directory. The goal is to make bootstrap and operator posture explicit, signed, mirrorable, and inspectable.

## Current status

The runtime can now load a bootstrap bundle from:

- `HANDSHACKE_BOOTSTRAP_BUNDLE_PATH`
- `HANDSHACKE_BOOTSTRAP_BUNDLE_JSON`

At this stage the bundle is used for:

- runtime diagnostics
- API status surfaces
- keeper and bridge posture visibility
- EtherSync bootstrap peer seeding at runtime start
- federated route discovery together with ORP and static bootstrap peers
- space-join seeding before replay and ORP activity
- ORP candidate ranking bias for known relay, bridge, and keeper posture
- operator-facing bootstrap inventory that can later be signed and mirrored

It is not yet used as a full routing authority or as a mandatory global directory.

## Validation posture

Bootstrap bundles now carry a local validation report that is intended for later runtime and API wiring.

The report is machine-friendly and separates three concerns:

- usability
- structural weakness
- freshness

The current validation rules are intentionally local and conservative:

- an empty bundle is treated as unusable
- missing relay `id` or `addr`, missing bridge `id` or `endpoint`, and missing keeper `id` or `endpoint` are flagged as structural warnings
- duplicate relay, bridge, and keeper IDs or endpoints are flagged as structural warnings
- `generated_at_ms` is checked only for advisory staleness, using a conservative age threshold
- if `generated_at_ms` is absent, freshness is unknown rather than failed

This means a bundle can still be parsed and reported even when it is weak, while clearly surfacing the reasons it should not be trusted blindly.

## JSON shape

```json
{
  "version": 1,
  "generated_at_ms": 1760000000000,
  "mirrors": [
    "https://mirror-1.example.net/ouroboros/bootstrap.json"
  ],
  "relays": [
    {
      "id": "relay-eu-1",
      "addr": "203.0.113.10:7447",
      "operator_id": "core-eu",
      "region": "eu-west"
    }
  ],
  "bridges": [
    {
      "id": "bridge-it-1",
      "endpoint": "obfs4://bridge.example.net:443",
      "operator_id": "core-it",
      "region": "eu-south"
    }
  ],
  "keepers": [
    {
      "id": "keeper-us-1",
      "endpoint": "keeper://keeper.example.net:9443",
      "operator_id": "managed-us",
      "region": "us-east",
      "replication_factor": 3
    }
  ],
  "notes": [
    "Mirrorable managed bootstrap bundle"
  ]
}
```

The bundle module exposes a validation report with the same shape for all callers, so runtime code can later attach policy without changing the bundle parser itself.

## Why this matters

This gives Ouroboros a way to scale operationally without lying about decentralization:

- bootstrap becomes inspectable
- bridge posture becomes visible
- keeper posture becomes visible
- future operator attestation has a concrete place to live

## Not implemented yet

The new validation layer is deliberately not pretending to be a trust system.

- no signature verification yet
- no remote refresh or re-fetch path yet
- no authority or policy decision based on bundle origin alone
- no automatic repair of weak or duplicate records yet

## Related surfaces

- `GET /v1/capabilities`
- `GET /v1/routes/status`
- `GET /v1/keepers/status`
- [Operator Model](./operators.md)
- [Roadmap and Gates](./roadmap_gates.md)
