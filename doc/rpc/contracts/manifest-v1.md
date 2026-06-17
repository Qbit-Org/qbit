# Manifest Contract v1

The compiled generator must emit a deterministic JSON manifest describing the
public RPC surface derived from the same `RPCHelpMan` metadata used by runtime
help.

Primary output path:

- `build/doc/rpc/rpc-docs.json`

Auxiliary build metadata path:

- `build/doc/rpc/rpc-docs-build-meta.json`

## Determinism

The canonical manifest must be stable across repeated builds from the same
source tree.

Requirements:

- methods sorted by category, then method name
- aliases sorted consistently
- no wall-clock timestamps in `rpc-docs.json`
- pretty-printed, stable field ordering

Build-specific values such as timestamps and commit identifiers belong in
`rpc-docs-build-meta.json`.

## Top-level shape

```json
{
  "schema_version": "1",
  "project": "qbit",
  "project_version": "vX.Y.Z",
  "methods": []
}
```

Required top-level fields:

- `schema_version`
- `project`
- `project_version`
- `methods`

Optional top-level fields:

- `source_ref`
- `generator`
- `feature_matrix`

## Method shape

Required fields:

- `name`
- `category`
- `component`
- `visible`
- `summary_line`
- `description`
- `arguments`
- `results`
- `examples`
- `feature_flags`

Optional fields:

- `named_argument_map`
- `source_tags`

### `component`

Allowed values:

- `core`
- `wallet`
- `zmq`
- `signer`

### `feature_flags`

Boolean keys:

- `requires_wallet`
- `requires_zmq`
- `requires_external_signer`

## Argument and result node shape

Required fields:

- `name`
- `type`
- `description`
- `children`

Optional fields:

- `aliases`
- `required`
- `optional`
- `hidden`
- `default_kind`
- `default_value`
- `default_hint`
- `conditional`

## Visibility

Public site generation must exclude methods with:

- `visible: false`

The manifest may still include hidden methods for debugging in the future, but
the public site must not render them by default.
