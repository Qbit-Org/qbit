# Overlay Contract v1

The overlay augments machine-detected differences between the current manifest
and the committed v30.2 baseline.

Tracked path:

- `doc/rpc/annotations/v30.2-delta.yml`

The overlay is only for semantic deltas that cannot be derived reliably from
schema/help text changes.

The committed file should stay within the JSON subset of YAML so the site can
still be built with the Python standard library when PyYAML is unavailable.

## Top-level shape

```yaml
schema_version: "1"
baseline: "v30.2"
methods: {}
```

Required top-level fields:

- `schema_version`
- `baseline`
- `methods`

## Method entry shape

Method keys must match current RPC method names exactly.

Allowed fields:

- `status_override`
- `delta_summary`
- `delta_notes`

### `status_override`

Allowed values:

- `unchanged`
- `new_since_v30_2`
- `surface_changed_since_v30_2`
- `semantic_changed_since_v30_2`

## Validation rules

The renderer or validation step must fail if:

- a method key does not exist in the current manifest
- `status_override` is not one of the allowed values
- `schema_version` is unsupported

## Intended use

Expected semantic-only overlay cases include:

- `getblocktemplate` Cadence / AuxPoW semantics
- `getnetworkinfo` witness-pruned and archive-aware behavior
- other methods whose structure matches v30.2 but whose qbit semantics differ
