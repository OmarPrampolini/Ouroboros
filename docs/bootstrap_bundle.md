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

It is not yet used as a full routing authority.

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

## Why this matters

This gives Ouroboros a way to scale operationally without lying about decentralization:

- bootstrap becomes inspectable
- bridge posture becomes visible
- keeper posture becomes visible
- future operator attestation has a concrete place to live

## Related surfaces

- `GET /v1/capabilities`
- `GET /v1/routes/status`
- `GET /v1/keepers/status`
- [Operator Model](./operators.md)
- [Roadmap and Gates](./roadmap_gates.md)
