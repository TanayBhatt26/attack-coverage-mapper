"""Generate MITRE ATT&CK Navigator layer files from the coverage database.

Reads APT group technique assignments and the materialized detection coverage
(technique_coverage x datasource_types) straight from ``db/coverage.db`` and
emits Navigator layer-format v4.5 JSON files:

1. ``layers/<GROUP_ID>_ttps.json``       -- one layer per APT group (red cells),
   listing every alive technique the group is documented to use.
2. ``layers/<GROUP_ID>_gap.json``        -- the group overlaid with OUR
   detection coverage: green = detectable (best confidence >= threshold, in
   platform scope), red = gap, orange = covered only via parent/child roll-up.
3. ``layers/detection_coverage.json``    -- project-wide coverage map of all
   in-scope techniques (green = detectable, red = undetected).

Import the JSON into https://mitre-attack.github.io/attack-navigator/ via
"Open Existing Layer" -> "Upload from local".

Usage (from the project root):

    PYTHONPATH=src ./.venv/Scripts/python.exe scripts/generate_navigator_layers.py
    #   [--group G0016 ...]   limit to specific groups (default: all 191)
    #   [--outdir layers]     output directory (default: layers/)
    #   [--config config.yaml] project config (threshold, platform scope)

The script is read-only over the database and writes only into the output
directory. Detection semantics (threshold, scope, enablement) come from the
same config.yaml the Streamlit dashboard uses, so layers always agree with
the dashboard's numbers.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Make ``src``-rooted imports work when run from the project root.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from sqlalchemy import select  # noqa: E402

from analysis.coverage_analyzer import load_coverage_rows  # noqa: E402
from config_loader import load_config  # noqa: E402
from database.models import (  # noqa: E402
    AptGroup,
    AptTechnique,
    Technique,
)
from database.session import session_scope  # noqa: E402

# Navigator layer format version this script emits.
LAYER_VERSIONS = {"attack": "16.1", "navigator": "5.1.0", "layer": "4.5"}

# Platform filter mirrors config platform_scope; "all" shows every platform.
ALL_PLATFORM_FILTERS = [
    "Linux",
    "macOS",
    "Windows",
    "ESXi",
    "Containers",
    "IaaS",
    "SaaS",
    "Office 365",
    "Azure AD",
    "Identity Provider",
    "Office Suite",
    "PRE",
    "Network Devices",
]

SCOPE_TO_FILTERS = {
    "all": ALL_PLATFORM_FILTERS,
    "windows": ["Windows"],
    "linux": ["Linux"],
    "macos": ["macOS"],
    "cloud": ["IaaS", "SaaS", "Office 365", "Azure AD"],
}

# Cell colors used across layers.
COLOR_GROUP_TTP = "#ff6666"  # technique used by the group
COLOR_DETECTED = "#66ff66"  # we detect this technique
COLOR_GAP = "#ff3333"  # undetected technique
COLOR_ROLLUP = "#ffa64d"  # covered only via parent/child roll-up


def _base_layer(
    name: str,
    description: str,
    platform_filters: list[str],
    gradient_colors: list[str],
    legend: list[tuple[str, str]],
) -> dict:
    """Build the layer skeleton shared by all three layer kinds."""
    return {
        "name": name,
        "versions": dict(LAYER_VERSIONS),
        "domain": "enterprise-attack",
        "description": description,
        "filters": {"platforms": platform_filters},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": [],
        "gradient": {
            "colors": gradient_colors,
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": label, "color": color} for label, color in legend
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }


def _group_techniques(session, group_pk: str) -> list[dict]:
    """Return alive techniques used by a group.

    ``group_pk`` must be the group's *STIX id* (``apt_groups.stix_id``),
    which is the key ``apt_technique.group_stix_id`` actually stores --
    passing the short G-code finds nothing.

    Each item carries attack_id, name, tactics (list) and platforms (list),
    one entry per (technique, tactic) pair so Navigator cells light up under
    every tactic the technique serves -- same convention the skill uses.
    """
    rows = session.execute(
        select(
            Technique.attack_id,
            Technique.name,
            Technique.tactics,
            Technique.platforms,
        )
        .join(AptTechnique, AptTechnique.technique_stix_id == Technique.stix_id)
        .where(
            AptTechnique.group_stix_id == group_pk,
            Technique.revoked.is_(False),
        )
        .order_by(Technique.attack_id)
    ).all()
    return [
        {
            "attack_id": attack_id,
            "name": name,
            "tactics": [t for t in (tactics or []) if isinstance(t, str)],
            "platforms": [p for p in (platforms or []) if isinstance(p, str)],
        }
        for attack_id, name, tactics, platforms in rows
    ]


def _technique_cells(techs: list[dict], color: str, comment_prefix: str = "") -> list[dict]:
    """Flatten group techniques into one Navigator cell per (technique, tactic)."""
    cells = []
    for tech in techs:
        for tactic in tech["tactics"]:
            cells.append(
                {
                    "techniqueID": tech["attack_id"],
                    "tactic": tactic,
                    "color": color,
                    "comment": f"{comment_prefix}{tech['name']}".strip(),
                    "enabled": True,
                    "score": 100,
                }
            )
    return cells


def build_group_ttp_layer(
    group_id: str,
    group_name: str,
    aliases: list[str],
    techs: list[dict],
    platform_filters: list[str],
) -> dict:
    """Layer 1: every technique the group is documented to use."""
    layer = _base_layer(
        name=f"{group_name} ({group_id}) TTP Coverage",
        description=(
            f"Techniques attributed to {group_name} "
            f"(aliases: {', '.join(aliases) if aliases else group_name}). "
            "Generated from the ATT&CK Coverage Mapper database."
        ),
        platform_filters=platform_filters,
        gradient_colors=["#ffffff", COLOR_GROUP_TTP],
        legend=[
            (f"Used by {group_name}", COLOR_GROUP_TTP),
            ("Not observed", "#ffffff"),
        ],
    )
    layer["techniques"] = _technique_cells(
        techs, COLOR_GROUP_TTP, comment_prefix=f"{group_name}: "
    )
    return layer


def _detect_status_map(session, coverage_rows: tuple) -> dict[str, str]:
    """Classify every alive technique as 'detected' | 'rollup' | 'gap'.

    Mirrors the simulation engine's one-level parent/child roll-up
    (contract D), judged at *stix* level (where detectability actually
    lives), then folded per attack_id taking the best status -- a Navigator
    cell keys on attack_id, and any detectable/roll-up stix row under that
    id lifts the cell.
    """
    parent_of: dict[str, str] = {}  # sub stix_id -> parent attack_id
    children_of: dict[str, set[str]] = {}  # parent attack_id -> sub stix_ids
    for stix_id, is_sub, parent_attack_id in session.execute(
        select(
            Technique.stix_id,
            Technique.is_subtechnique,
            Technique.parent_attack_id,
        ).where(Technique.revoked.is_(False))
    ).all():
        if is_sub and parent_attack_id:
            parent_of[stix_id] = parent_attack_id
            children_of.setdefault(parent_attack_id, set()).add(stix_id)

    detectable_stix = {
        row.technique_stix_id
        for row in coverage_rows
        if row.scope_hit and row.is_detectable
    }

    # Status per stix row.
    stix_status: dict[str, str] = {}
    all_stix: dict[str, list[str]] = {}  # attack_id -> alive stix ids
    for stix_id, attack_id in session.execute(
        select(Technique.stix_id, Technique.attack_id).where(
            Technique.revoked.is_(False)
        )
    ).all():
        all_stix.setdefault(attack_id, []).append(stix_id)
        if stix_id in detectable_stix:
            stix_status[stix_id] = "detected"
    for stix_id, attack_id in session.execute(
        select(Technique.stix_id, Technique.attack_id).where(
            Technique.revoked.is_(False)
        )
    ).all():
        if stix_id in stix_status:
            continue
        parent_attack_id = parent_of.get(stix_id)
        if parent_attack_id:
            parent_stix = session.execute(
                select(Technique.stix_id).where(
                    Technique.attack_id == parent_attack_id,
                    Technique.revoked.is_(False),
                )
            ).scalars().first()
            if parent_stix and parent_stix in detectable_stix:
                stix_status[stix_id] = "rollup"
                continue
        if any(
            detectable_stix & children_of.get(attack_id, set())
        ):
            stix_status[stix_id] = "rollup"
            continue
        stix_status[stix_id] = "gap"

    # Fold to attack_id: best status wins (detected > rollup > gap).
    _RANK = {"detected": 2, "rollup": 1, "gap": 0}
    status: dict[str, str] = {}
    for attack_id, stix_ids in all_stix.items():
        best = "gap"
        for sid in stix_ids:
            s = stix_status.get(sid, "gap")
            if _RANK[s] > _RANK[best]:
                best = s
        status[attack_id] = best
    return status


def build_group_gap_layer(
    group_id: str,
    group_name: str,
    techs: list[dict],
    status_map: dict[str, str],
    platform_filters: list[str],
) -> dict:
    """Layer 2: the group's techniques colored by OUR detection coverage.

    ``status_map`` maps attack_id -> 'detected' | 'rollup' | 'gap'. Unknown
    ids (not in coverage at all) count as gaps -- fail-closed honesty.
    """
    layer = _base_layer(
        name=f"{group_name} ({group_id}) Detection Gap Analysis",
        description=(
            f"{group_name} techniques vs. our detection coverage. "
            "Green = detectable, red = gap, orange = covered only via "
            "parent/child roll-up. Config: platform scope + threshold from "
            "config.yaml."
        ),
        platform_filters=platform_filters,
        gradient_colors=[COLOR_GAP, COLOR_DETECTED],
        legend=[
            ("Detected", COLOR_DETECTED),
            ("Detected via parent/child roll-up", COLOR_ROLLUP),
            ("Detection gap", COLOR_GAP),
        ],
    )

    detected_count = 0
    rollup_count = 0
    gap_count = 0
    cells = []
    for tech in techs:
        status = status_map.get(tech["attack_id"], "gap")
        if status == "detected":
            detected_count += 1
            color = COLOR_DETECTED
        elif status == "rollup":
            rollup_count += 1
            color = COLOR_ROLLUP
        else:
            gap_count += 1
            color = COLOR_GAP
        for tactic in tech["tactics"]:
            cells.append(
                {
                    "techniqueID": tech["attack_id"],
                    "tactic": tactic,
                    "color": color,
                    "comment": f"{status.upper()}: {tech['name']}",
                    "enabled": True,
                    "score": 100 if status in ("detected", "rollup") else 0,
                }
            )
    layer["techniques"] = cells

    total = detected_count + rollup_count + gap_count
    if total:
        covered = detected_count + rollup_count
        layer["metadata"] = [
            {
                "name": "coverage",
                "value": (
                    f"{covered}/{total} group techniques covered "
                    f"({round(covered / total * 100, 1)}%) -- "
                    f"{detected_count} direct, {rollup_count} roll-up, "
                    f"{gap_count} gap"
                ),
            }
        ]
    return layer


def build_coverage_layer(
    coverage_rows: tuple,
    platform_filters: list[str],
) -> dict:
    """Layer 3: project-wide detection coverage of all in-scope techniques."""
    layer = _base_layer(
        name="ATT&CK Coverage Mapper - Detection Coverage",
        description=(
            "All in-scope alive techniques colored by detection coverage. "
            "Green = detectable at/above the configured threshold, "
            "red = undetected (gap)."
        ),
        platform_filters=platform_filters,
        gradient_colors=[COLOR_GAP, COLOR_DETECTED],
        legend=[
            ("Detected", COLOR_DETECTED),
            ("Detection gap", COLOR_GAP),
        ],
    )

    # One cell per (technique, tactic); skip out-of-scope techniques.
    seen: set[tuple[str, str]] = set()
    cells = []
    for row in coverage_rows:
        if not row.scope_hit:
            continue
        key = (row.attack_id, row.tactic)
        if key in seen:
            continue
        seen.add(key)
        cells.append(
            {
                "techniqueID": row.attack_id,
                "tactic": row.tactic,
                "color": COLOR_DETECTED if row.is_detectable else COLOR_GAP,
                "comment": (
                    f"{row.name} (best confidence {round(row.best_confidence, 2)})"
                ),
                "enabled": True,
                "score": 100 if row.is_detectable else 0,
            }
        )
    layer["techniques"] = cells
    return layer


def write_layer(layer: dict, outdir: Path, filename: str) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / filename
    with path.open("w", encoding="utf-8") as fh:
        json.dump(layer, fh, indent=2, ensure_ascii=False)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate ATT&CK Navigator layers from the coverage DB."
    )
    parser.add_argument(
        "--group",
        action="append",
        help="Group id to emit (repeatable, e.g. --group G0016). "
        "Default: all groups.",
    )
    parser.add_argument(
        "--outdir",
        default="layers",
        help="Output directory (default: layers/).",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Project config file (default: config.yaml).",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    scope = str(config.get("platform_scope", "all")).lower()
    platform_filters = SCOPE_TO_FILTERS.get(scope, ALL_PLATFORM_FILTERS)

    outdir = PROJECT_ROOT / args.outdir
    written: list[Path] = []

    with session_scope() as session:
        coverage_rows = load_coverage_rows(session, config)
        status_map = _detect_status_map(session, coverage_rows)

        # Layer 3: project-wide coverage.
        coverage_layer = build_coverage_layer(coverage_rows, platform_filters)
        written.append(write_layer(coverage_layer, outdir, "detection_coverage.json"))

        # Layers 1-2: one TTP layer + one gap layer per group.
        if args.group:
            wanted = [g.upper().strip() for g in args.group]
        else:
            wanted = None  # all groups

        group_rows = session.execute(
            select(
                AptGroup.group_id, AptGroup.name, AptGroup.aliases, AptGroup.stix_id
            ).order_by(AptGroup.group_id)
        ).all()
        for group_id, group_name, aliases, group_stix_id in group_rows:
            if wanted is not None and group_id not in wanted:
                continue
            techs = _group_techniques(session, group_stix_id)
            if not techs:
                continue  # zero alive techniques -> nothing to plot
            safe_name = group_name.replace(" ", "_").replace("/", "-")
            ttp_layer = build_group_ttp_layer(
                group_id,
                group_name,
                [a for a in (aliases or []) if isinstance(a, str)],
                techs,
                platform_filters,
            )
            written.append(
                write_layer(ttp_layer, outdir, f"{group_id}_{safe_name}_ttps.json")
            )
            gap_layer = build_group_gap_layer(
                group_id, group_name, techs, status_map, platform_filters
            )
            written.append(
                write_layer(gap_layer, outdir, f"{group_id}_{safe_name}_gap.json")
            )

    for path in written:
        print(f"[+] {path}")
    print(f"[+] {len(written)} layer file(s) written to {outdir}")
    print(
        "[i] Import at https://mitre-attack.github.io/attack-navigator/ "
        "-> Open Existing Layer -> Upload from local"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
