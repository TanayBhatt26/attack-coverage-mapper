"""Phase-4 fixtures -- synthetic APT-simulation dataset + golden builders.

Wave 2 (APT Simulation) test support for the two Phase-4 engine functions:

1. ``analysis.simulation.simulate_apt_attack`` -- resolve an APT group, walk
   its non-revoked techniques, classify each against the live
   ``technique_coverage`` table joined to *enabled* datasources (config is
   the single source of truth for enablement), persist a
   :class:`~database.models.SimulationResult` plus one
   :class:`~database.models.SimulationTechnique` per group technique, and
   return the result.
2. ``analysis.simulation.generate_recommendations`` -- greedy
   marginal-gain ranking over *disabled* ``DataSourceType`` formats (driven
   by :func:`analysis.coverage_analyzer.calculate_coverage_gaps`
   ``closable_by``), templated into human-readable strings.

The synthetic dataset is deliberately small (3 groups, 11 techniques) yet
exercises every branch of the simulation algorithm contract:

- **Direct detection** (``detected``): a technique whose own
  ``technique_coverage`` row is detectable on an enabled source. Pinned by
  ``SIM_DETECTED_IDS``.
- **Sub-technique roll-up** (``detected_rollup``): a live sub-technique
  whose *own* coverage is below threshold but whose *parent* technique is
  detectable. Pinned by ``SIM_ROLLUP_CHILD_IDS`` (e.g. ``T1078.003`` ->
  ``T1078``, ``T1496.001`` -> ``T1496``). This is the G0016/G0096 roll-up
  path verified in Wave 1.
- **Parent-via-children roll-up** (``detected_rollup``): a parent technique
  whose own coverage is below threshold but at least one *child* sub-
  technique is detectable. Pinned by ``SIM_ROLLUP_PARENT_IDS``.
- **Missed** (``missed``): a technique with no detectable coverage and no
  roll-up path. Pinned by ``SIM_MISSED_IDS``.
- **Revoked exclusion**: techniques flagged ``revoked=True`` are excluded
  from the group's technique set entirely (the ``WHERE revoked=False``
  filter), so they never count toward ``total_techniques`` and never
  appear as a ``SimulationTechnique`` row.
- **Cross-group overlap**: ``T1078`` is used by both G0016 and G0032, so
  the same technique_coverage row feeds two independent simulation runs
  without cross-contamination.

Invariants (asserted by :func:`assert_simulation_dataset_consistent`):

- ``detected + detected_rollup + missed == total_techniques`` for every
  group (the algorithm's core conservation invariant).
- ``coverage_pct == round(detected / total_techniques, 4)`` (0.0 when
  total is 0), never ``detected_rollup`` in the numerator.
- The summary JSON's ``counts`` mirror the top-level counters and its
  ``per_tactic`` buckets sum to the same totals.
- Recommendations only ever name *disabled* log formats and rank by
  marginal gain (number of missed techniques closable), tie-broken by
  datasource priority.

Floating-point note: golden confidences are written as *expressions*
(``base * TIER_ACTION`` etc.), never as decimal literals, so they are
bit-identical to engine arithmetic under IEEE-754 regardless of repr.

Offline and dependency-free beyond the stdlib; no pytest import so the
module doubles as a standalone self-check via ``python -m`` style runs.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, Iterable, Mapping, Sequence

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_SIM_CONFIG",
    "SIM_APT_GROUPS",
    "SIM_TECHNIQUES",
    "SIM_APT_TECHNIQUES",
    "SIM_COVERAGE_ROWS",
    "SIM_DETECTED_IDS",
    "SIM_ROLLUP_CHILD_IDS",
    "SIM_ROLLUP_PARENT_IDS",
    "SIM_MISSED_IDS",
    "SIM_GROUP_TECHNIQUE_COUNTS",
    "SIM_GROUP_EXPECTED",
    "SIM_RECOMMENDATIONS",
    "SIM_SOURCE_LABELS",
    "SIM_TECHNIQUE_STIX",
    "SIM_ATTACK_ID_TO_STIX",
    "build_simulation_result",
    "build_simulation_technique",
    "assert_simulation_dataset_consistent",
    "technique_stix",
]


# ---------------------------------------------------------------------------
# Contract D constants (mirrors fixtures_phase3 for cross-module parity)
# ---------------------------------------------------------------------------

#: Static tier multiplier for extension-evidence rules (non-empty ext_keys).
TIER_EXT = 1.0
#: Static tier multiplier for action-only rules.
TIER_ACTION = 0.85
#: Static tier multiplier for heuristic rules (match_type == "heuristic").
TIER_HEURISTIC = 0.40
#: Hard ceiling for any detection confidence score.
CONF_CAP = 0.95
#: Default detectability threshold (config.yaml detection_confidence_threshold);
#: comparison is inclusive (>=).
THRESHOLD = 0.6


# ---------------------------------------------------------------------------
# Default simulation config (mirrors config.yaml: windows scope, 0.6 bar,
# evtx/syslog/json/aws_cloudtrail/zeek enabled; cef/leef/nginx disabled).
# ---------------------------------------------------------------------------

DEFAULT_SIM_CONFIG: Mapping[str, Any] = {
    "platform_scope": "windows",
    "detection_confidence_threshold": THRESHOLD,
    "enabled_log_sources": {
        "evtx": True,
        "syslog": True,
        "cef": False,
        "leef": False,
        "json": True,
        "aws_cloudtrail": True,
        "nginx": False,
        "zeek": True,
    },
}


# ---------------------------------------------------------------------------
# Synthetic APT groups (3 groups, Wave-1 golden technique counts honoured
# where they overlap with this mini-universe).
# ---------------------------------------------------------------------------
# (stix_id, group_id, name, aliases). The three Wave-1 golden groups are
# represented so simulation runs can be pinned against the verified
# detectable set (24 techniques under default config). Here we only model
# the subset of each group's techniques that our mini-universe covers, so
# the ``technique_count`` is the *mini-universe* count, not the full
# Wave-1 count (66/82/93).

SIM_APT_GROUPS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    ("intrusion-set--g0016", "G0016", "APT29", ("APT29", "Cozy Bear", "Nobelium")),
    ("intrusion-set--g0096", "G0096", "APT33", ("APT33", "Elfin", "HOLMIUM")),
    ("intrusion-set--g0032", "G0032", "APT28", ("APT28", "Fancy Bear", "Sednit")),
)


# ---------------------------------------------------------------------------
# Synthetic techniques (11 rows). Platforms keep canonical ATT&CK casing.
# ---------------------------------------------------------------------------
# (stix_id, attack_id, name, tactics, platforms, is_subtechnique,
#  parent_attack_id, revoked). The set is engineered so every simulation
#  branch has a representative:
#
#  - T1078  Valid Accounts (parent, defense-evasion + priv-esc) -- detected
#          directly via evtx; also the roll-up target for T1078.003.
#  - T1078.003 Domain Accounts (sub, defense-evasion) -- below threshold on
#          its own, but parent T1078 is detectable -> detected_rollup.
#  - T1496 Resource Hijacking (parent, impact) -- detected directly via
#          zeek; also the roll-up target for T1496.001.
#  - T1496.001 Cryptomining (sub, impact) -- below threshold on its own,
#          but parent T1496 is detectable -> detected_rollup.
#  - T1046 Network Service Discovery (parent, discovery) -- detected via
#          zeek; also a roll-up source for its child T1046.001.
#  - T1046.001 Network Service Discovery: mDNS (sub, discovery) -- detected
#          via zeek (so parent T1046 also rolls up via this child).
#  - T1110 Brute Force (parent, credential-access) -- detected via
#          aws_cloudtrail.
#  - T1531 Account Access Removal (parent, impact) -- detected via
#          aws_cloudtrail.
#  - T1685.002 Impair Defenses: Disable Cloud Logs (sub, defense-evasion)
#          -- detected via aws_cloudtrail (the Wave-1 G0016 roll-up example
#          T1685.002 -> T1685 is mirrored here as a direct-detect case).
#  - T1059.009 Cloud API (sub, execution) -- below threshold on every
#          enabled source -> missed.
#  - T1098 Account Manipulation (parent, persistence + credential-access)
#          -- below threshold on every enabled source -> missed.
#  - T1070.001 Clear Windows Event Logs (sub, defense-evasion, REVOKED) --
#          excluded from every group's technique set by the revoked filter.

_SIM_TECHNIQUES_RAW: tuple[tuple[str, str, str, tuple[str, ...], tuple[str, ...], bool, str | None, bool], ...] = (
    ("attack-pattern--t1078", "T1078", "Valid Accounts",
     ("defense-evasion", "privilege-escalation"), ("Windows",),
     False, None, False),
    ("attack-pattern--t1078003", "T1078.003", "Valid Accounts: Domain Accounts",
     ("defense-evasion",), ("Windows",),
     True, "T1078", False),
    ("attack-pattern--t1496", "T1496", "Resource Hijacking",
     ("impact",), ("Windows", "IaaS"),
     False, None, False),
    ("attack-pattern--t1496001", "T1496.001", "Resource Hijacking: Cryptomining",
     ("impact",), ("IaaS",),
     True, "T1496", False),
    ("attack-pattern--t1046", "T1046", "Network Service Discovery",
     ("discovery",), ("Windows", "Linux"),
     False, None, False),
    ("attack-pattern--t1046001", "T1046.001", "Network Service Discovery: mDNS",
     ("discovery",), ("Windows", "Linux"),
     True, "T1046", False),
    ("attack-pattern--t1110", "T1110", "Brute Force",
     ("credential-access",), ("Windows", "IaaS"),
     False, None, False),
    ("attack-pattern--t1531", "T1531", "Account Access Removal",
     ("impact",), ("Windows", "IaaS"),
     False, None, False),
    ("attack-pattern--t1685002", "T1685.002", "Impair Defenses: Disable Cloud Logs",
     ("defense-evasion",), ("IaaS",),
     True, "T1685", False),
    ("attack-pattern--t1059009", "T1059.009", "Cloud API",
     ("execution",), ("IaaS",),
     True, "T1059", False),
    ("attack-pattern--t1098", "T1098", "Account Manipulation",
     ("persistence", "credential-access"), ("Windows", "SaaS"),
     False, None, False),
    # Revoked -- excluded from every group's technique set.
    ("attack-pattern--t1070001", "T1070.001", "Clear Windows Event Logs",
     ("defense-evasion",), ("Windows",),
     True, "T1070", True),
)

SIM_TECHNIQUES: tuple[dict[str, Any], ...] = tuple(
    {
        "stix_id": stix_id,
        "attack_id": attack_id,
        "name": name,
        "tactics": tactics,
        "platforms": platforms,
        "is_subtechnique": is_sub,
        "parent_attack_id": parent,
        "revoked": revoked,
    }
    for stix_id, attack_id, name, tactics, platforms, is_sub, parent, revoked
    in _SIM_TECHNIQUES_RAW
)

#: attack_id -> stix_id lookup (unique because each attack_id is distinct).
SIM_ATTACK_ID_TO_STIX: Mapping[str, str] = {t["attack_id"]: t["stix_id"] for t in SIM_TECHNIQUES}
SIM_TECHNIQUE_STIX: Mapping[str, dict[str, Any]] = {t["stix_id"]: t for t in SIM_TECHNIQUES}


def technique_stix(attack_id: str) -> str:
    """Return the stix_id for ``attack_id`` (simulates TechniqueCoverage join key)."""
    return SIM_ATTACK_ID_TO_STIX[attack_id]


# ---------------------------------------------------------------------------
# Group -> technique associations (apt_technique rows).
# ---------------------------------------------------------------------------
# Each group's technique set is the list of technique_stix_ids it uses.
# Revoked techniques are never associated. The three groups overlap on
# T1078 (G0016 + G0032) to prove cross-group independence.

SIM_APT_TECHNIQUES: Mapping[str, tuple[str, ...]] = {
    "G0016": (
        technique_stix("T1078"),
        technique_stix("T1078.003"),
        technique_stix("T1496"),
        technique_stix("T1496.001"),
        technique_stix("T1685.002"),
        technique_stix("T1059.009"),
    ),
    "G0096": (
        technique_stix("T1046"),
        technique_stix("T1046.001"),
        technique_stix("T1110"),
        technique_stix("T1531"),
        technique_stix("T1098"),
    ),
    "G0032": (
        technique_stix("T1078"),
        technique_stix("T1110"),
        technique_stix("T1531"),
        technique_stix("T1098"),
    ),
}


# ---------------------------------------------------------------------------
# Technique coverage rows (the detectability signal the simulation reads).
# ---------------------------------------------------------------------------
# Each entry: (technique_attack_id, datasource_format, confidence,
#              is_detectable). Confidences are written as tier-adjusted
#              expressions so they stay bit-identical to engine arithmetic.
#
#  - T1078     evtx  ext 0.85            -> 0.85 (detected)
#  - T1078.003 evtx  action 0.50        -> 0.425 (below threshold; roll-up)
#  - T1496     zeek  ext 0.80            -> 0.80 (detected)
#  - T1496.001 zeek  action 0.40        -> 0.34 (below threshold; roll-up)
#  - T1046     zeek  ext 0.75            -> 0.75 (detected)
#  - T1046.001 zeek  ext 0.70            -> 0.70 (detected; parent rolls up)
#  - T1110     aws_cloudtrail ext 0.90   -> 0.90 (detected)
#  - T1531     aws_cloudtrail ext 0.80   -> 0.80 (detected)
#  - T1685.002 aws_cloudtrail ext 0.95   -> 0.95 (detected)
#  - T1059.009 syslog heuristic 0.50    -> 0.20 (below threshold; missed)
#  - T1098     syslog action 0.45        -> 0.3825 (below threshold; missed)
#  - T1070.001 (revoked -- no coverage row; excluded from simulation)

_SIM_COVERAGE_RAW: tuple[tuple[str, str, float, bool], ...] = (
    ("T1078", "evtx", 0.85 * TIER_EXT, True),
    ("T1078.003", "evtx", 0.50 * TIER_ACTION, False),
    ("T1496", "zeek", 0.80 * TIER_EXT, True),
    ("T1496.001", "zeek", 0.40 * TIER_ACTION, False),
    ("T1046", "zeek", 0.75 * TIER_EXT, True),
    ("T1046.001", "zeek", 0.70 * TIER_EXT, True),
    ("T1110", "aws_cloudtrail", 0.90 * TIER_EXT, True),
    ("T1531", "aws_cloudtrail", 0.80 * TIER_EXT, True),
    ("T1685.002", "aws_cloudtrail", 0.95 * TIER_EXT, True),
    ("T1059.009", "syslog", 0.50 * TIER_HEURISTIC, False),
    ("T1098", "syslog", 0.45 * TIER_ACTION, False),
)

SIM_COVERAGE_ROWS: tuple[dict[str, Any], ...] = tuple(
    {
        "technique_stix_id": technique_stix(attack_id),
        "technique_attack_id": attack_id,
        "datasource_format": fmt,
        "detection_confidence": conf,
        "is_detectable": det,
    }
    for attack_id, fmt, conf, det in _SIM_COVERAGE_RAW
)


# ---------------------------------------------------------------------------
# Golden classification buckets (the engine's per-technique verdict).
# ---------------------------------------------------------------------------

#: Techniques detected directly on their own coverage row.
SIM_DETECTED_IDS: tuple[str, ...] = (
    "T1078", "T1496", "T1046", "T1046.001", "T1110", "T1531", "T1685.002",
)

#: Sub-techniques that roll up to a detectable parent (own coverage below
#: threshold, parent detectable). Mirrors the Wave-1 G0016/G0096 examples.
SIM_ROLLUP_CHILD_IDS: tuple[str, ...] = (
    "T1078.003",  # -> T1078
    "T1496.001",  # -> T1496
)

#: Parent techniques that roll up via a detectable child (own coverage
#: below threshold, at least one child detectable). T1046 is detected on
#: its own coverage here, so it is NOT in this bucket; this bucket is
#: reserved for parents that are *only* detectable via children. We keep
#: it empty-but-typed so tests can assert the bucket is empty for this
#: dataset (a meaningful negative).
SIM_ROLLUP_PARENT_IDS: tuple[str, ...] = ()

#: Techniques with no detectable coverage and no roll-up path.
SIM_MISSED_IDS: tuple[str, ...] = (
    "T1059.009",
    "T1098",
)


# ---------------------------------------------------------------------------
# Per-group expected simulation outcomes.
# ---------------------------------------------------------------------------
# Each entry: (group_id, total, detected, detected_rollup, missed,
#              coverage_pct). coverage_pct = round(detected / total, 4).

SIM_GROUP_EXPECTED: Mapping[str, Mapping[str, Any]] = {
    "G0016": {
        "total": 6,
        "detected": 3,            # T1078, T1496, T1685.002
        "detected_rollup": 2,    # T1078.003, T1496.001
        "missed": 1,             # T1059.009
        "coverage_pct": round(3 / 6, 4),  # 0.5
    },
    "G0096": {
        "total": 5,
        "detected": 4,            # T1046, T1046.001, T1110, T1531
        "detected_rollup": 0,
        "missed": 1,             # T1098
        "coverage_pct": round(4 / 5, 4),  # 0.8
    },
    "G0032": {
        "total": 4,
        "detected": 3,            # T1078, T1110, T1531
        "detected_rollup": 0,
        "missed": 1,             # T1098
        "coverage_pct": round(3 / 4, 4),  # 0.75
    },
}

#: Sanctioned technique counts per group (mirrors AptGroupOption semantics).
SIM_GROUP_TECHNIQUE_COUNTS: Mapping[str, int] = {
    gid: expected["total"] for gid, expected in SIM_GROUP_EXPECTED.items()
}


# ---------------------------------------------------------------------------
# Recommendation templates (generate_recommendations output contract).
# ---------------------------------------------------------------------------
# Source labels per the engine contract. Only disabled formats (cef, leef,
# nginx) can appear in recommendations. Under the default config the only
# missed techniques are T1059.009 and T1098, neither of which has a
# closable_by path on a disabled source in this mini-dataset, so the
# expected recommendation list is empty -- a meaningful negative that
# proves the greedy filter does not hallucinate closable paths.

SIM_SOURCE_LABELS: Mapping[str, str] = {
    "evtx": "Windows Event Log",
    "syslog": "Syslog",
    "json": "JSON/ECS",
    "aws_cloudtrail": "AWS CloudTrail",
    "zeek": "Zeek",
    "nginx": "Nginx/Apache",
    "cef": "CEF",
    "leef": "LEEF",
}

#: Expected recommendation strings for each group under DEFAULT_SIM_CONFIG.
#: Empty because no disabled source maps to the missed techniques above
#: threshold in this mini-dataset.
SIM_RECOMMENDATIONS: Mapping[str, tuple[str, ...]] = {
    "G0016": (),
    "G0096": (),
    "G0032": (),
}


# ---------------------------------------------------------------------------
# Golden builders bridging to engine dataclasses
# ---------------------------------------------------------------------------

def _field_names(cls: type) -> set[str]:
    """Return the set of attribute/column names for a dataclass or a
    SQLAlchemy mapped class.

    Supports both stdlib dataclasses (via ``dataclasses.fields``) and
    SQLAlchemy declarative models (via ``sqlalchemy.inspect``), so the
    builders work with either the engine's frozen dataclasses or the
    ``database.models`` ORM classes.
    """
    if dataclasses.is_dataclass(cls):
        return {f.name for f in dataclasses.fields(cls)}
    try:
        from sqlalchemy import inspect as sa_inspect
        mapper = sa_inspect(cls)
        if mapper is not None and mapper.columns:
            return {col.key for col in mapper.columns}
    except Exception:
        pass
    # Fallback: rely on the constructor to reject unknown kwargs.
    return set()


def build_simulation_result(cls: type, **overrides: Any) -> Any:
    """Construct a ``SimulationResult``-shaped object from ``overrides``.

    Extra keys raise ValueError (catches fixture typos early); missing
    required fields surface as the class's own TypeError.

    Args:
        cls: Target class (typically ``database.models.SimulationResult``).
        **overrides: Field-name -> value mapping. Common fields:
            ``group_stix_id``, ``group_id``, ``platform_scope``,
            ``confidence_threshold``, ``total_techniques``,
            ``detected_count``, ``missed_count``, ``coverage_pct``,
            ``summary``.

    Returns:
        The constructed instance.
    """
    known = _field_names(cls)
    extras = sorted(set(overrides) - known)
    if extras:
        raise ValueError(
            f"{cls.__name__} has no field(s) {extras}; "
            f"known fields: {sorted(known)}"
        )
    return cls(**overrides)


def build_simulation_technique(cls: type, **overrides: Any) -> Any:
    """Construct a ``SimulationTechnique``-shaped object from ``overrides``.

    Extra keys raise ValueError (catches fixture typos early); missing
    required fields surface as the class's own TypeError.

    Args:
        cls: Target class (typically
            ``database.models.SimulationTechnique``).
        **overrides: Field-name -> value mapping. Common fields:
            ``result_id``, ``technique_attack_id``, ``name``, ``tactic``,
            ``status``, ``confidence``, ``contributing_sources``.

    Returns:
        The constructed instance.
    """
    known = _field_names(cls)
    extras = sorted(set(overrides) - known)
    if extras:
        raise ValueError(
            f"{cls.__name__} has no field(s) {extras}; "
            f"known fields: {sorted(known)}"
        )
    return cls(**overrides)


# ---------------------------------------------------------------------------
# Self-consistency guard
# ---------------------------------------------------------------------------

def assert_simulation_dataset_consistent() -> None:
    """Cross-check the hand-computed simulation goldens against each other.

    Raises:
        AssertionError: On any internal inconsistency (broken invariant
            between techniques, coverage rows, classification buckets and
            per-group expectations).
    """
    alive = {t["attack_id"] for t in SIM_TECHNIQUES if not t["revoked"]}
    detectable = set(SIM_DETECTED_IDS)
    rollup_children = set(SIM_ROLLUP_CHILD_IDS)
    rollup_parents = set(SIM_ROLLUP_PARENT_IDS)
    missed = set(SIM_MISSED_IDS)

    # Classification buckets partition the alive set exactly.
    bucket_union = detectable | rollup_children | rollup_parents | missed
    assert bucket_union == alive, (
        f"classification buckets do not partition alive techniques: "
        f"extra={sorted(bucket_union - alive)}, missing={sorted(alive - bucket_union)}"
    )
    assert not (detectable & rollup_children), "a technique cannot be both detected and rollup-child"
    assert not (detectable & missed), "a technique cannot be both detected and missed"
    assert not (rollup_children & missed), "a technique cannot be both rollup-child and missed"

    # Roll-up children must be sub-techniques with a detectable parent.
    for aid in rollup_children:
        tech = next(t for t in SIM_TECHNIQUES if t["attack_id"] == aid)
        assert tech["is_subtechnique"], f"rollup-child {aid} is not a sub-technique"
        assert tech["parent_attack_id"] in detectable, (
            f"rollup-child {aid} parent {tech['parent_attack_id']} is not detectable"
        )

    # Roll-up parents must be non-sub techniques with a detectable child.
    for aid in rollup_parents:
        tech = next(t for t in SIM_TECHNIQUES if t["attack_id"] == aid)
        assert not tech["is_subtechnique"], f"rollup-parent {aid} is a sub-technique"
        assert aid not in detectable, f"rollup-parent {aid} is directly detected"
        children = [
            t for t in SIM_TECHNIQUES
            if t["parent_attack_id"] == aid and not t["revoked"]
        ]
        assert children, f"rollup-parent {aid} has no children"
        assert any(c["attack_id"] in detectable for c in children), (
            f"rollup-parent {aid} has no detectable child"
        )

    # Missed techniques must have no detectable coverage and no roll-up path.
    for aid in missed:
        assert aid not in detectable, f"missed {aid} is detectable"
        tech = next(t for t in SIM_TECHNIQUES if t["attack_id"] == aid)
        if tech["is_subtechnique"]:
            assert tech["parent_attack_id"] not in detectable, (
                f"missed sub {aid} has a detectable parent"
            )

    # Coverage rows reference alive techniques and enabled formats.
    enabled_formats = {
        fmt for fmt, en in DEFAULT_SIM_CONFIG["enabled_log_sources"].items() if en
    }
    for row in SIM_COVERAGE_ROWS:
        assert row["technique_attack_id"] in alive, (
            f"coverage row for dead technique {row['technique_attack_id']}"
        )
        assert row["datasource_format"] in enabled_formats, (
            f"coverage row on disabled format {row['datasource_format']}"
        )
        assert 0.0 <= row["detection_confidence"] <= CONF_CAP + 1e-9, (
            f"confidence cap violated for {row['technique_attack_id']}"
        )
        assert row["is_detectable"] == (row["detection_confidence"] >= THRESHOLD), (
            f"detectability mismatch for {row['technique_attack_id']}"
        )

    # Detectable-id list agrees with coverage rows.
    from_pairs = sorted({
        row["technique_attack_id"] for row in SIM_COVERAGE_ROWS if row["is_detectable"]
    })
    assert from_pairs == sorted(detectable), (
        f"detectable ids disagree with coverage rows: "
        f"from_pairs={from_pairs}, detectable={sorted(detectable)}"
    )

    # Per-group expectations honour the conservation invariant and coverage_pct.
    for gid, expected in SIM_GROUP_EXPECTED.items():
        total = expected["total"]
        detected = expected["detected"]
        rollup = expected["detected_rollup"]
        missed_count = expected["missed"]
        assert detected + rollup + missed_count == total, (
            f"{gid}: detected({detected})+rollup({rollup})+missed({missed_count}) "
            f"!= total({total})"
        )
        pct = expected["coverage_pct"]
        assert pct == round(detected / total, 4) if total else pct == 0.0, (
            f"{gid}: coverage_pct {pct} != round({detected}/{total}, 4)"
        )
        # The group's technique set (minus revoked) must match the total.
        assert len(SIM_APT_TECHNIQUES[gid]) == total, (
            f"{gid}: apt_technique count {len(SIM_APT_TECHNIQUES[gid])} != total {total}"
        )

    # Recommendations only ever name disabled formats.
    disabled_formats = {
        fmt for fmt, en in DEFAULT_SIM_CONFIG["enabled_log_sources"].items() if not en
    }
    for gid, recs in SIM_RECOMMENDATIONS.items():
        for rec in recs:
            # Every recommendation string names a source label; verify the
            # underlying format is disabled.
            assert any(fmt in rec for fmt in disabled_formats), (
                f"{gid}: recommendation {rec!r} does not name a disabled format"
            )

    logger.info(
        "simulation dataset consistent: %d groups, %d techniques, "
        "%d coverage rows, %d detectable, %d rollup-children, %d missed",
        len(SIM_APT_GROUPS), len(SIM_TECHNIQUES), len(SIM_COVERAGE_ROWS),
        len(SIM_DETECTED_IDS), len(SIM_ROLLUP_CHILD_IDS), len(SIM_MISSED_IDS),
    )


if __name__ == "__main__":  # pragma: no cover - manual self-check entry point
    logging.basicConfig(level=logging.DEBUG)
    assert_simulation_dataset_consistent()
    print("per-group expectations:")
    for gid, expected in SIM_GROUP_EXPECTED.items():
        print(f"  {gid}: {expected}")
    print("OK")
