# Site Model Contract v1

The renderer consumes the current manifest, the committed baseline, and the
overlay, and produces a site model used to generate MkDocs content.

The generated site model does not need to be committed, but its structure is
frozen here so the renderer and UI work can proceed independently from the
compiled generator.

Suggested generated path:

- `build/doc/rpc/site-model.json`

## Top-level shape

Required fields:

- `schema_version`
- `baseline`
- `summary`
- `change_pages`
- `categories`
- `methods`

## Summary shape

Required fields:

- `total_methods`
- `new_since_v30_2`
- `surface_changed_since_v30_2`
- `semantic_changed_since_v30_2`
- `unchanged`

## Change Page shape

Required fields:

- `change_type`
- `label`
- `page`
- `count`

## Method shape

Required fields:

- `name`
- `category`
- `component`
- `status`
- `change_types`
- `badges`
- `summary_line`
- `description`
- `arguments`
- `results`
- `examples`

Optional fields:

- `delta_summary`
- `delta_notes`

### `status`

Allowed values:

- `unchanged`
- `new_since_v30_2`
- `surface_changed_since_v30_2`
- `semantic_changed_since_v30_2`

### `change_types`

Methods may carry zero or more change types. The supported values are:

- `new_since_v30_2`
- `surface_changed_since_v30_2`
- `semantic_changed_since_v30_2`

### `badges`

Badge labels are UI-oriented and free-form, but the following labels are
reserved:

- `New since v30.2`
- `Changed params/results since v30.2`
- `Changed behavior since v30.2`
- `Wallet`
- `ZMQ`
- `Signer`

## Rendering expectations

The MkDocs site is expected to:

- render a dedicated "Changed since v30.2" page
- render dedicated pages for new endpoints, params/results changes, and behavior changes
- expose human-labeled links to each change bucket page
- allow filtering by changed state
- show badges on category listings
- show a delta summary panel on per-method pages when available
