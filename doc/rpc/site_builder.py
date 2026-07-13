# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Helpers for qbit RPC documentation site generation."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any


SCHEMA_VERSION = "1"
BASELINE_LABEL = "v30.2"
STATUS_UNCHANGED = "unchanged"
STATUS_NEW = "new_since_v30_2"
STATUS_SURFACE_CHANGED = "surface_changed_since_v30_2"
STATUS_SEMANTIC_CHANGED = "semantic_changed_since_v30_2"
LEGACY_STATUS_MODIFIED = "modified_since_v30_2"
ALLOWED_STATUSES = {
    STATUS_UNCHANGED,
    STATUS_NEW,
    STATUS_SURFACE_CHANGED,
    STATUS_SEMANTIC_CHANGED,
}
STATUS_ALIASES = {
    LEGACY_STATUS_MODIFIED: STATUS_SEMANTIC_CHANGED,
}
CHANGE_TYPE_ORDER = {
    STATUS_NEW: 0,
    STATUS_SURFACE_CHANGED: 1,
    STATUS_SEMANTIC_CHANGED: 2,
}
SUMMARY_STATUS_ORDER = (
    STATUS_NEW,
    STATUS_SURFACE_CHANGED,
    STATUS_SEMANTIC_CHANGED,
)
FEATURE_BADGES = (
    ("wallet", "requires_wallet", "Wallet"),
    ("zmq", "requires_zmq", "ZMQ"),
    ("signer", "requires_external_signer", "Signer"),
)
BADGE_VARIANTS = {
    "new_since": "new",
    "surface_changed_since": "surface",
    "semantic_changed_since": "semantic",
    "Wallet": "wallet",
    "ZMQ": "zmq",
    "Signer": "signer",
}
COMPONENT_FEATURE_KEYS = {
    "wallet": "wallet",
    "zmq": "zmq",
    "signer": "external_signer",
}
ROOT_DIR = Path(__file__).resolve().parent


class SiteBuilderError(Exception):
    """Base exception for renderer failures."""


class ManifestValidationError(SiteBuilderError):
    """Raised when the input manifest is malformed."""


class OverlayValidationError(SiteBuilderError):
    """Raised when the overlay input is malformed."""


def load_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def companion_build_meta_path(manifest_path: str | Path) -> Path:
    manifest = Path(manifest_path)
    return manifest.with_name("rpc-docs-build-meta.json")


def load_optional_build_meta_for_manifest(
    manifest_path: str | Path,
) -> dict[str, Any] | None:
    build_meta_path = companion_build_meta_path(manifest_path)
    if not build_meta_path.exists():
        return None
    return load_json(build_meta_path)


def load_manifest(path: str | Path) -> dict[str, Any]:
    manifest = load_json(path)
    validate_manifest(manifest, Path(path))
    return manifest


def validate_manifest(manifest: dict[str, Any], path: Path | None = None) -> None:
    required_keys = {"schema_version", "project", "project_version", "methods"}
    missing = sorted(required_keys.difference(manifest))
    if missing:
        location = f" in {path}" if path else ""
        raise ManifestValidationError(
            f"manifest missing required keys{location}: {', '.join(missing)}"
        )

    if manifest["schema_version"] != SCHEMA_VERSION:
        raise ManifestValidationError(
            f"unsupported manifest schema_version: {manifest['schema_version']}"
        )

    if not isinstance(manifest["methods"], list):
        raise ManifestValidationError("manifest methods must be a list")

    seen_names: set[str] = set()
    for method in manifest["methods"]:
        method_name = method.get("name")
        if not method_name:
            raise ManifestValidationError("manifest method entry missing name")
        if method_name in seen_names:
            raise ManifestValidationError(f"duplicate manifest method: {method_name}")
        seen_names.add(method_name)


def manifest_method_index(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {method["name"]: method for method in manifest["methods"]}


def canonicalize_status(status: str | None) -> str | None:
    if status is None:
        return None
    return STATUS_ALIASES.get(status, status)


def load_overlay(path: str | Path, manifest_names: set[str]) -> dict[str, Any]:
    overlay_path = Path(path)
    raw_overlay = overlay_path.read_text(encoding="utf-8")

    try:
        import yaml
    except ModuleNotFoundError:
        try:
            overlay = json.loads(raw_overlay)
        except json.JSONDecodeError as exc:
            raise OverlayValidationError(
                "PyYAML is required to load non-JSON overlay annotations"
            ) from exc
    else:
        overlay = yaml.safe_load(raw_overlay)
    validate_overlay(overlay, manifest_names, overlay_path)
    return overlay


def validate_overlay(
    overlay: dict[str, Any], manifest_names: set[str], path: Path | None = None
) -> None:
    if not isinstance(overlay, dict):
        raise OverlayValidationError("overlay must be a mapping")

    if overlay.get("schema_version") != SCHEMA_VERSION:
        raise OverlayValidationError(
            f"unsupported overlay schema_version: {overlay.get('schema_version')}"
        )

    baseline = overlay.get("baseline")
    if not isinstance(baseline, str) or not baseline:
        raise OverlayValidationError("overlay baseline must be a non-empty string")

    methods = overlay.get("methods")
    if not isinstance(methods, dict):
        raise OverlayValidationError("overlay methods must be a mapping")

    for method_name, metadata in methods.items():
        if method_name not in manifest_names:
            location = f" in {path}" if path else ""
            raise OverlayValidationError(
                f"overlay references unknown method{location}: {method_name}"
            )
        if not isinstance(metadata, dict):
            raise OverlayValidationError(
                f"overlay entry for {method_name} must be a mapping"
            )
        if "status_override" in metadata:
            status_override = metadata["status_override"]
            if not isinstance(status_override, str):
                raise OverlayValidationError(
                    f"overlay status_override for {method_name} must be one of "
                    f"{', '.join(sorted(ALLOWED_STATUSES))}"
                )
            if canonicalize_status(status_override) not in ALLOWED_STATUSES:
                raise OverlayValidationError(
                    f"overlay status_override for {method_name} must be one of "
                    f"{', '.join(sorted(ALLOWED_STATUSES))}"
                )


def feature_matrix_from_build_meta(
    build_meta: dict[str, Any] | None,
) -> dict[str, bool]:
    if not build_meta:
        return {}

    feature_matrix = build_meta.get("feature_matrix", {})
    if not isinstance(feature_matrix, dict):
        return {}

    normalized: dict[str, bool] = {}
    for key, value in feature_matrix.items():
        if isinstance(value, bool):
            normalized[key] = value
    return normalized


def component_available_in_baseline(
    component: str, baseline_feature_matrix: dict[str, bool]
) -> bool:
    feature_key = COMPONENT_FEATURE_KEYS.get(component)
    if feature_key is None:
        return True
    if feature_key not in baseline_feature_matrix:
        return True
    return baseline_feature_matrix[feature_key]


def normalize_argument_node(argument: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        key: argument[key]
        for key in ("name", "aliases", "type", "required", "hidden")
        if key in argument
    }
    normalized["children"] = [
        normalize_argument_node(child) for child in argument.get("children", [])
    ]
    return normalized


def normalize_result_node(result: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        key: result[key]
        for key in ("name", "type", "optional", "conditional")
        if key in result
    }
    normalized["children"] = [
        normalize_result_node(child) for child in result.get("children", [])
    ]
    return normalized


def method_surface_signature(method: dict[str, Any]) -> dict[str, Any]:
    return {
        "arguments": [
            normalize_argument_node(argument) for argument in method.get("arguments", [])
        ],
        "results": [
            normalize_result_node(result) for result in method.get("results", [])
        ],
    }


def method_surface_changed(
    current_method: dict[str, Any], baseline_method: dict[str, Any]
) -> bool:
    return method_surface_signature(current_method) != method_surface_signature(
        baseline_method
    )


def sort_change_types(change_types: list[str]) -> list[str]:
    unique_types = {change_type for change_type in change_types if change_type in ALLOWED_STATUSES}
    return sorted(unique_types, key=lambda change_type: CHANGE_TYPE_ORDER[change_type])


def apply_status_override(
    inferred_change_types: list[str], status_override: str | None
) -> list[str]:
    if status_override is None:
        return sort_change_types(inferred_change_types)

    override = canonicalize_status(status_override)
    if override == STATUS_UNCHANGED:
        return []
    if override == STATUS_NEW:
        return [STATUS_NEW]

    change_types = list(inferred_change_types)
    if override:
        change_types.append(override)
    return sort_change_types(change_types)


def primary_status(change_types: list[str]) -> str:
    if not change_types:
        return STATUS_UNCHANGED
    return sort_change_types(change_types)[0]


def diff_manifest_methods(
    manifest: dict[str, Any],
    baseline: dict[str, Any],
    baseline_feature_matrix: dict[str, bool] | None = None,
) -> dict[str, list[str]]:
    manifest_methods = manifest_method_index(manifest)
    baseline_methods = manifest_method_index(baseline)
    change_types: dict[str, list[str]] = {}
    baseline_feature_matrix = baseline_feature_matrix or {}

    for method_name, method in manifest_methods.items():
        baseline_method = baseline_methods.get(method_name)
        if baseline_method is None:
            if component_available_in_baseline(
                method.get("component", "core"), baseline_feature_matrix
            ):
                change_types[method_name] = [STATUS_NEW]
            else:
                change_types[method_name] = []
            continue

        inferred: list[str] = []
        if method_surface_changed(method, baseline_method):
            inferred.append(STATUS_SURFACE_CHANGED)
        change_types[method_name] = inferred

    return change_types


def build_site_model(
    manifest: dict[str, Any],
    baseline: dict[str, Any],
    overlay: dict[str, Any],
    baseline_build_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    baseline_feature_matrix = feature_matrix_from_build_meta(baseline_build_meta)
    inferred_change_types = diff_manifest_methods(
        manifest, baseline, baseline_feature_matrix
    )
    overlays = overlay["methods"]
    baseline_label = overlay["baseline"]
    methods: list[dict[str, Any]] = []

    for method in sorted(manifest["methods"], key=lambda item: (item["category"], item["name"])):
        if not method.get("visible", True):
            continue

        overlay_entry = overlays.get(method["name"], {})
        change_types = apply_status_override(
            inferred_change_types[method["name"]],
            overlay_entry.get("status_override"),
        )
        site_method = {
            "name": method["name"],
            "category": method["category"],
            "component": method["component"],
            "status": primary_status(change_types),
            "change_types": change_types,
            "changed": bool(change_types),
            "badges": build_badges(method, change_types, baseline_label),
            "summary_line": method["summary_line"],
            "description": method["description"],
            "arguments": method["arguments"],
            "results": method["results"],
            "examples": method["examples"],
        }

        for optional_key in (
            "delta_summary",
            "delta_notes",
        ):
            if optional_key in overlay_entry:
                site_method[optional_key] = overlay_entry[optional_key]

        methods.append(site_method)

    categories = build_category_entries(methods)
    summary = build_summary(methods)
    return {
        "schema_version": SCHEMA_VERSION,
        "project_version": manifest["project_version"],
        "baseline": baseline_label,
        "summary": summary,
        "change_pages": build_change_page_entries(methods, baseline_label),
        "categories": categories,
        "methods": methods,
    }


def build_badges(
    method: dict[str, Any], change_types: list[str], baseline_label: str
) -> list[str]:
    badges: list[str] = []
    for change_type in sort_change_types(change_types):
        badges.append(change_type_badge_label(change_type, baseline_label))

    feature_flags = method.get("feature_flags", {})
    for component_name, flag_name, label in FEATURE_BADGES:
        if method.get("component") == component_name or feature_flags.get(flag_name):
            badges.append(label)

    return badges


def build_summary(methods: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"total_methods": len(methods)}
    for status in SUMMARY_STATUS_ORDER:
        summary[status] = sum(1 for method in methods if status in method["change_types"])
    summary[STATUS_UNCHANGED] = sum(1 for method in methods if not method["change_types"])
    return summary


def build_category_entries(methods: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts_by_category: dict[str, dict[str, int]] = {}
    for method in methods:
        counts = counts_by_category.setdefault(
            method["category"],
            {
                "total": 0,
                STATUS_NEW: 0,
                STATUS_SURFACE_CHANGED: 0,
                STATUS_SEMANTIC_CHANGED: 0,
                STATUS_UNCHANGED: 0,
            },
        )
        counts["total"] += 1
        for change_type in method["change_types"]:
            counts[change_type] += 1
        if not method["change_types"]:
            counts[STATUS_UNCHANGED] += 1

    return [
        {"name": category, "counts": counts_by_category[category]}
        for category in sorted(counts_by_category)
    ]


def build_change_page_entries(
    methods: list[dict[str, Any]], baseline_label: str
) -> list[dict[str, Any]]:
    return [
        {
            "change_type": change_type,
            "label": change_page_label(change_type, baseline_label),
            "page": change_type_page_name(change_type, baseline_label),
            "count": sum(1 for method in methods if change_type in method["change_types"]),
        }
        for change_type in SUMMARY_STATUS_ORDER
    ]


def write_site_model(site_model: dict[str, Any], out_dir: str | Path) -> Path:
    out_path = Path(out_dir)
    site_model_dir = out_path.parent / "rpc"
    site_model_dir.mkdir(parents=True, exist_ok=True)
    site_model_path = site_model_dir / "site-model.json"
    site_model_path.write_text(
        json.dumps(site_model, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    return site_model_path


def render_markdown_site(site_model: dict[str, Any], out_dir: str | Path) -> Path:
    source_root = generated_source_root(out_dir)
    if source_root.exists():
        shutil.rmtree(source_root)

    docs_dir = source_root / "docs"
    categories_dir = docs_dir / "categories"
    methods_dir = docs_dir / "methods"
    categories_dir.mkdir(parents=True, exist_ok=True)
    methods_dir.mkdir(parents=True, exist_ok=True)

    docs_dir.joinpath("index.md").write_text(render_index_page(site_model), encoding="utf-8")
    docs_dir.joinpath(changed_page_name(site_model["baseline"])).write_text(
        render_changed_page(site_model), encoding="utf-8"
    )
    for change_page in site_model["change_pages"]:
        docs_dir.joinpath(change_page["page"]).write_text(
            render_change_type_page(site_model, change_page["change_type"]),
            encoding="utf-8",
        )

    methods_by_category = group_methods_by_category(site_model["methods"])
    for category, methods in methods_by_category.items():
        categories_dir.joinpath(f"{slugify(category)}.md").write_text(
            render_category_page(site_model, category, methods), encoding="utf-8"
        )

    for method in site_model["methods"]:
        methods_dir.joinpath(f"{slugify(method['name'])}.md").write_text(
            render_method_page(site_model, method), encoding="utf-8"
        )

    return docs_dir


def generated_source_root(out_dir: str | Path) -> Path:
    out_path = Path(out_dir)
    return out_path.parent / f"{out_path.name}-src"


def group_methods_by_category(
    methods: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for method in methods:
        grouped.setdefault(method["category"], []).append(method)
    return grouped


def render_index_page(site_model: dict[str, Any]) -> str:
    sections = [
        "# qbit RPC Reference",
        "",
        (
            "Generated from the current manifest, the committed "
            f"{site_model['baseline']} baseline, and the semantic overlay."
        ),
        "",
        "## Summary",
        "",
        render_summary_table(site_model["summary"], site_model["baseline"]),
        "",
        "Change counts are not mutually exclusive. A method may appear in more than one change bucket.",
        "",
        f"## Changed since {site_model['baseline']}",
        "",
        f"- [All changed methods]({changed_page_name(site_model['baseline'])})",
        *[
            f"- [{change_page['label']}]({change_page['page']}): {change_page['count']}"
            for change_page in site_model["change_pages"]
        ],
        "",
        "## Categories",
        "",
    ]

    for category in site_model["categories"]:
        counts = category["counts"]
        sections.append(
            f"- [{category['name'].title()}](categories/{slugify(category['name'])}.md): "
            f"{counts['total']} total, {counts[STATUS_NEW]} new, "
            f"{counts[STATUS_SURFACE_CHANGED]} params/results changed, "
            f"{counts[STATUS_SEMANTIC_CHANGED]} behavior changed, "
            f"{counts[STATUS_UNCHANGED]} unchanged"
        )

    sections.extend(
        [
            "",
            "## All Methods",
            "",
            render_method_listing(
                site_model["methods"], include_filter=True, method_prefix="methods"
            ),
        ]
    )
    return "\n".join(sections).rstrip() + "\n"


def render_changed_page(site_model: dict[str, Any]) -> str:
    changed_methods = [
        method for method in site_model["methods"] if method["change_types"]
    ]
    return "\n".join(
        [
            f"# Changed since {site_model['baseline']}",
            "",
            "Methods below are grouped into new endpoints, params/results changes, and behavior changes.",
            "",
            *[
                f"- [{change_page['label']}]({change_page['page']}): {change_page['count']}"
                for change_page in site_model["change_pages"]
            ],
            "",
            render_method_listing(
                changed_methods, include_filter=False, method_prefix="methods"
            ),
        ]
    ).rstrip() + "\n"


def render_change_type_page(site_model: dict[str, Any], change_type: str) -> str:
    methods = [
        method for method in site_model["methods"] if change_type in method["change_types"]
    ]
    return "\n".join(
        [
            f"# {change_page_label(change_type, site_model['baseline'])}",
            "",
            f"Methods listed here are classified as {change_page_description(change_type, site_model['baseline'])}.",
            "",
            render_method_listing(
                methods, include_filter=False, method_prefix="methods"
            ),
        ]
    ).rstrip() + "\n"


def render_category_page(
    site_model: dict[str, Any], category: str, methods: list[dict[str, Any]]
) -> str:
    counts = next(
        entry["counts"] for entry in site_model["categories"] if entry["name"] == category
    )
    return "\n".join(
        [
            f"# {category.title()} RPCs",
            "",
            f"{counts['total']} methods in this category, with "
            f"{counts[STATUS_NEW]} new, {counts[STATUS_SURFACE_CHANGED]} params/results changed, "
            f"{counts[STATUS_SEMANTIC_CHANGED]} behavior changed, "
            f"and {counts[STATUS_UNCHANGED]} unchanged since {site_model['baseline']}.",
            "",
            render_method_listing(
                methods, include_filter=True, method_prefix="../methods"
            ),
        ]
    ).rstrip() + "\n"


def render_method_page(site_model: dict[str, Any], method: dict[str, Any]) -> str:
    sections = [
        f"# `{method['name']}`",
        "",
        f"[Back to {method['category']}](../categories/{slugify(method['category'])}.md)",
        "",
        render_badge_block(method["badges"]),
        "",
        "## Summary",
        "",
        method["summary_line"],
        "",
        "## Description",
        "",
        method["description"],
        "",
    ]

    if "delta_summary" in method:
        sections.extend(
            [
                f"## Changed behavior since {site_model['baseline']}",
                "",
                method["delta_summary"],
                "",
            ]
        )

    if "delta_notes" in method:
        sections.append("### Notes")
        sections.append("")
        for note in method["delta_notes"]:
            sections.append(f"- {note}")
        sections.append("")

    if method["change_types"]:
        sections.extend(
            [
                "## Change Buckets",
                "",
                *[
                    f"- {change_type_badge_label(change_type, site_model['baseline'])}"
                    for change_type in method["change_types"]
                ],
                "",
            ]
        )

    sections.extend(
        [
            "## Arguments",
            "",
            render_parameter_tree(method["arguments"]) or "None.",
            "",
            "## Results",
            "",
            render_parameter_tree(method["results"]) or "None.",
            "",
            "## Examples",
            "",
            render_examples(method["examples"]),
        ]
    )
    return "\n".join(sections).rstrip() + "\n"


def render_summary_table(summary: dict[str, int], baseline_label: str) -> str:
    return "\n".join(
        [
            "| Metric | Count |",
            "| --- | ---: |",
            f"| Total methods | {summary['total_methods']} |",
            f"| New since {baseline_label} | {summary[STATUS_NEW]} |",
            f"| Changed params/results since {baseline_label} | {summary[STATUS_SURFACE_CHANGED]} |",
            f"| Changed behavior since {baseline_label} | {summary[STATUS_SEMANTIC_CHANGED]} |",
            f"| Unchanged | {summary[STATUS_UNCHANGED]} |",
        ]
    )


def render_method_listing(
    methods: list[dict[str, Any]], include_filter: bool, method_prefix: str
) -> str:
    sections: list[str] = []
    if include_filter:
        sections.extend(
            [
                '<div class="rpc-filter-controls">',
                '  <label><input type="checkbox" class="rpc-show-changed-only"> Show changed methods only</label>',
                "</div>",
                "",
            ]
        )

    sections.append('<div class="rpc-method-list">')
    for method in methods:
        sections.extend(render_method_card(method, method_prefix))
    sections.append("</div>")
    return "\n".join(sections)


def render_method_card(method: dict[str, Any], method_prefix: str) -> list[str]:
    method_name = escape_html(method["name"])
    summary_line = escape_html(method["summary_line"])
    category = escape_html(method["category"])
    component = escape_html(method["component"])
    status = escape_html(method["status"])
    change_types = escape_html(" ".join(method["change_types"]))
    changed = "true" if method["change_types"] else "false"
    lines = [
        f'<article class="rpc-method-card" data-status="{status}" data-change-types="{change_types}" data-changed="{changed}">',
        f'  <h3><a href="{method_prefix}/{slugify(method["name"])}.html">{method_name}</a></h3>',
        f'  <p class="rpc-method-summary">{summary_line}</p>',
        f'  <p class="rpc-method-meta">{category} / {component}</p>',
    ]
    if method["badges"]:
        lines.append('  <p class="rpc-badge-row">')
        for badge in method["badges"]:
            lines.append(render_badge_span(badge, indent="    "))
        lines.append("  </p>")
    if "delta_summary" in method:
        lines.append(f'  <p class="rpc-delta-summary">{escape_html(method["delta_summary"])}</p>')
    lines.append("</article>")
    return lines


def render_badge_block(badges: list[str]) -> str:
    if not badges:
        return ""
    parts = ['<p class="rpc-badge-row">']
    for badge in badges:
        parts.append(render_badge_span(badge, indent="  "))
    parts.append("</p>")
    return "\n".join(parts)


def render_parameter_tree(parameters: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for parameter in parameters:
        render_parameter_node(parameter, lines, depth=0)
    return "\n".join(lines)


def render_parameter_node(
    parameter: dict[str, Any], lines: list[str], depth: int
) -> None:
    marker = "  " * depth + "- "
    name = parameter.get("name") or "value"
    type_name = parameter.get("type", "UNKNOWN")
    qualifiers = []
    if parameter.get("required"):
        qualifiers.append("required")
    if parameter.get("optional"):
        qualifiers.append("optional")
    if parameter.get("hidden"):
        qualifiers.append("hidden")
    qualifier_text = f", {', '.join(qualifiers)}" if qualifiers else ""
    description = parameter.get("description") or "No description."
    lines.append(
        f"{marker}`{name}` (`{type_name}`{qualifier_text}): {description}"
    )
    for child in parameter.get("children", []):
        render_parameter_node(child, lines, depth + 1)


def render_examples(examples: list[str]) -> str:
    if not examples:
        return "None."
    lines: list[str] = []
    for example in examples:
        lines.extend(["```text", example, "```", ""])
    return "\n".join(lines).rstrip()


def slugify(value: str) -> str:
    return "".join(
        character if character.isalnum() or character in {"-", "_", "."} else "-"
        for character in value.lower()
    ).strip("-")


def escape_html(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_badge_span(badge: str, indent: str) -> str:
    variant = badge_variant(badge)
    return (
        f'{indent}<span class="rpc-badge rpc-badge--{variant}">{escape_html(badge)}</span>'
    )


def copy_site_assets(out_dir: str | Path) -> Path:
    source_root = generated_source_root(out_dir)
    docs_assets_dir = source_root / "docs" / "assets"
    docs_assets_dir.mkdir(parents=True, exist_ok=True)

    assets_dir = ROOT_DIR / "assets"
    for asset in assets_dir.iterdir():
        if asset.is_file():
            shutil.copy2(asset, docs_assets_dir / asset.name)

    return docs_assets_dir


def write_mkdocs_config(site_model: dict[str, Any], out_dir: str | Path) -> Path:
    out_path = Path(out_dir)
    source_root = generated_source_root(out_dir).resolve()
    config_path = source_root / "mkdocs.yml"
    base_config = (ROOT_DIR / "mkdocs.base.yml").read_text(encoding="utf-8").rstrip()

    nav_lines = [
        "nav:",
        "  - Home: index.md",
        f"  - Changed since {site_model['baseline']}: {changed_page_name(site_model['baseline'])}",
        "  - Change Buckets:",
    ]
    for change_page in site_model["change_pages"]:
        nav_lines.append(f"    - {change_page['label']}: {change_page['page']}")

    nav_lines.extend(
        [
        "  - Categories:",
        ]
    )
    for category in site_model["categories"]:
        nav_lines.append(
            f"    - {category['name'].title()}: categories/{slugify(category['name'])}.md"
        )

    nav_lines.append("  - Methods:")
    for method in site_model["methods"]:
        nav_lines.append(
            f"    - {method['name']}: methods/{slugify(method['name'])}.md"
        )

    config_text = "\n".join(
        [
            base_config,
            f"docs_dir: {json.dumps(str(source_root / 'docs'))}",
            f"site_dir: {json.dumps(str(out_path.resolve()))}",
            "extra:",
            f"  version: {json.dumps(site_model['project_version'])}",
            "strict: true",
            *nav_lines,
            "",
        ]
    )
    config_path.write_text(config_text, encoding="utf-8")
    return config_path


def build_mkdocs_site(config_path: str | Path) -> None:
    config = Path(config_path)
    command = ["mkdocs", "build", "--strict", "-f", str(config)]
    if shutil.which("mkdocs") is None:
        command = [sys.executable, "-m", "mkdocs", "build", "--strict", "-f", str(config)]

    try:
        subprocess.run(command, check=True)
    except FileNotFoundError as exc:
        raise SiteBuilderError("MkDocs is required to build the RPC docs site") from exc


def new_badge_label(baseline_label: str) -> str:
    return f"New since {baseline_label}"


def surface_changed_badge_label(baseline_label: str) -> str:
    return f"Changed params/results since {baseline_label}"


def semantic_changed_badge_label(baseline_label: str) -> str:
    return f"Changed behavior since {baseline_label}"


def change_type_badge_label(change_type: str, baseline_label: str) -> str:
    if change_type == STATUS_NEW:
        return new_badge_label(baseline_label)
    if change_type == STATUS_SURFACE_CHANGED:
        return surface_changed_badge_label(baseline_label)
    if change_type == STATUS_SEMANTIC_CHANGED:
        return semantic_changed_badge_label(baseline_label)
    raise SiteBuilderError(f"unsupported change type: {change_type}")


def changed_page_name(baseline_label: str) -> str:
    return f"changed-since-{baseline_label}.md"


def change_type_page_name(change_type: str, baseline_label: str) -> str:
    if change_type == STATUS_NEW:
        return f"new-since-{baseline_label}.md"
    if change_type == STATUS_SURFACE_CHANGED:
        return f"surface-changed-since-{baseline_label}.md"
    if change_type == STATUS_SEMANTIC_CHANGED:
        return f"semantic-changed-since-{baseline_label}.md"
    raise SiteBuilderError(f"unsupported change type: {change_type}")


def change_page_label(change_type: str, baseline_label: str) -> str:
    if change_type == STATUS_NEW:
        return f"New endpoints since {baseline_label}"
    if change_type == STATUS_SURFACE_CHANGED:
        return f"Changed params/results since {baseline_label}"
    if change_type == STATUS_SEMANTIC_CHANGED:
        return f"Changed behavior since {baseline_label}"
    raise SiteBuilderError(f"unsupported change type: {change_type}")


def change_page_description(change_type: str, baseline_label: str) -> str:
    if change_type == STATUS_NEW:
        return f"new since {baseline_label}"
    if change_type == STATUS_SURFACE_CHANGED:
        return f"having parameter or response shape changes relative to {baseline_label}"
    if change_type == STATUS_SEMANTIC_CHANGED:
        return f"having qbit-specific semantic behavior changes relative to {baseline_label}"
    raise SiteBuilderError(f"unsupported change type: {change_type}")


def badge_variant(badge: str) -> str:
    if badge.startswith("New since "):
        return BADGE_VARIANTS["new_since"]
    if badge.startswith("Changed params/results since "):
        return BADGE_VARIANTS["surface_changed_since"]
    if badge.startswith("Changed behavior since "):
        return BADGE_VARIANTS["semantic_changed_since"]
    return BADGE_VARIANTS.get(badge, "default")
