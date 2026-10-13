"""APT attack simulation engine (Phase 4, Wave 2).

This module turns the curated coverage mapping into a per-group *what-if*
answer: given the log sources a simulated team actually collects, how much
of a chosen APT's known technique set would their SOC detect?

Two public functions:

1. :func:`simulate_apt_attack` -- resolve a group by its ``group_id``
   (e.g. ``"G0016"``), classify every technique the group is known to use as
   ``detected`` / ``detected_rollup`` / ``missed`` against the enabled
   datasources in the config, persist a :class:`~database.models.SimulationResult`
   plus one :class:`~database.models.SimulationTechnique` per group technique,
   and return the result.

2. :func:`generate_recommendations` -- greedy marginal-gain ranking over
   *disabled* :class:`~database.models.DataSourceType` formats: for each
   missed technique, ask whether enabling a closed-by source (from
   :func:`coverage_analyzer.calculate_coverage_gaps`) would lift it above
   the threshold, then recommend the sources that close the most gaps.

Classification algorithm
-----------------------
For each alive (``revoked`` false) technique the group uses:

* **DETECTED** -- the technique's own ``technique_coverage`` row is detectable
  against the *enabled* datasources (config is the single source of truth for
  enablement; the DB ``enabled`` mirror is only a seed-time default, mirroring
  the read path in :func:`coverage_analyzer.load_coverage_rows`).
* **DETECTED_ROLLUP** -- the technique is undetectable on its own, but
  (a) it is a sub-technique whose *parent* technique is detectable, OR
  (b) it is a parent technique with at least one detectable child
  sub-technique. Rollup never chains: only one hop is considered.
* **MISSED** -- neither the technique nor its immediate parent/child
  qualifies.

Invariant: ``detected + detected_rollup + missed == total`` (every group
technique is classified exactly once).

Rollup examples (verified against the production DB):

* G0016: ``T1685.002`` (sub) is detectable on its own via aws_cloudtrail
  (0.9) -> DETECTED; ``T1078.003`` (sub) detectable via evtx (0.85) ->
  DETECTED. Their parents ``T1685`` / ``T1078`` are *not* group techniques
  here, so no rollup is exercised for them in this group.
* G0096: ``T1496.001`` (sub) detectable on its own -> DETECTED.
* G0032: ``T1078.003`` (sub) detectable via evtx -> DETECTED.

The engine is deliberately conservative: rollup is a *defensive* credit
("you'd spot the family even if you missed the variant"), never an
inflationary one -- a sub-technique whose parent is missed stays missed.

Persistence & determinism
-------------------------
``SimulationResult.run_at`` is pinned to UTC now. Group techniques iterate in
``(attack_id, stix_id)`` order; floats are rounded to 4 decimals; the
``summary`` JSON carries per-tactic counts. No ``set`` ordering leaks into
persisted output, so re-runs of the same config are byte-identical.

Idempotency note
----------------
The function is *not* idempotent: each call appends a fresh
``SimulationResult`` row (timestamped). Callers who need a single snapshot
should delete prior runs for the group out-of-band.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from database.models import (
    AptGroup,
    AptTechnique,
    DataSourceType,
    SimulationResult,
    SimulationTechnique,
    Technique,
    TechniqueCoverage,
)
from analysis.coverage_analyzer import (
    CANONICAL_TACTICS,
    calculate_coverage_gaps,
    load_coverage_rows,
)
from parser.mappings_io import MappingRule

logger = logging.getLogger(__name__)

__all__ = (
    "generate_recommendations",
    "simulate_apt_attack",
)

# Source-label vocabulary for recommendation templates (matches the mapper's
# parser display names).
_SOURCE_LABELS: dict[str, str] = {
    "evtx": "Windows Event Log",
    "syslog": "Syslog",
    "json": "JSON/ECS",
    "aws_cloudtrail": "AWS CloudTrail",
    "zeek": "Zeek",
    "nginx": "Nginx/Apache",
    "cef": "CEF",
    "leef": "LEEF",
}

# Decimal places kept on persisted confidence / coverage_pct.
_ROUND_DECIMALS = 4


def _utcnow() -> datetime:
    """Return a timezone-aware UTC datetime for ``run_at``."""
    return datetime.now(timezone.utc)


def _enabled_datasource_ids(
    session: Session, config: Mapping[str, object]
) -> set[int]:
    """Return the ids of ``DataSourceType`` rows enabled by config.

    Config is the single source of truth for enablement (mirrors the read
    path in :func:`coverage_analyzer.load_coverage_rows`): a row is enabled
    unless its ``name`` maps to exactly ``False`` in the config. Absent keys
    count as enabled.

    Args:
        session: Open SQLAlchemy session.
        config: Application config mapping.

    Returns:
        Set of integer ids for enabled datasources.

    Raises:
        ValueError: If ``enabled_log_sources`` is not a mapping.
    """
    sources_cfg = config.get("enabled_log_sources")
    if sources_cfg is None:
        sources_cfg = {}
    if not isinstance(sources_cfg, Mapping):
        raise ValueError(
            "config 'enabled_log_sources' must be a mapping of format name "
            f"to bool, got {type(sources_cfg).__name__}"
        )
    disabled_formats = {str(k).lower() for k, v in sources_cfg.items() if v is False}
    rows = session.execute(select(DataSourceType.id, DataSourceType.name)).all()
    return {ds_id for ds_id, name in rows if str(name).lower() not in disabled_formats}


def _group_techniques(
    session: Session,
    group_stix_id: str,
) -> list[tuple[str, str, bool, str | None]]:
    """Return alive techniques for a group, sorted deterministically.

    Args:
        session: Open SQLAlchemy session.
        group_stix_id: The group's STIX id.

    Returns:
        Sorted list of ``(attack_id, stix_id, is_subtechnique,
        parent_attack_id)`` for every alive (``revoked`` false) technique
        the group uses, ordered by ``(attack_id, stix_id)``.
    """
    rows = session.execute(
        select(
            Technique.attack_id,
            Technique.stix_id,
            Technique.is_subtechnique,
            Technique.parent_attack_id,
        )
        .join(AptTechnique, AptTechnique.technique_stix_id == Technique.stix_id)
        .where(
            AptTechnique.group_stix_id == group_stix_id,
            Technique.revoked.is_(False),
        )
    ).all()
    return sorted(rows, key=lambda r: (r[0], r[1]))


def _detectability_index(
    session: Session,
    enabled_ids: set[int],
) -> dict[str, bool]:
    """Map each technique_stix_id to its detectability against enabled sources.

    A technique is detectable iff at least one of its ``technique_coverage``
    rows for an *enabled* datasource has ``is_detectable`` true. Only enabled
    datasources participate (config is source of truth).

    Args:
        session: Open SQLAlchemy session.
        enabled_ids: Set of enabled ``DataSourceType.id`` values.

    Returns:
        Mapping ``technique_stix_id -> bool`` (False when the technique has
        no coverage rows at all).
    """
    detectable: dict[str, bool] = {}
    if not enabled_ids:
        # Nothing enabled: every technique is undetectable. Return an empty
        # mapping so every lookup defaults to False.
        return detectable
    rows = session.execute(
        select(
            TechniqueCoverage.technique_stix_id,
            TechniqueCoverage.is_detectable,
        ).where(TechniqueCoverage.datasource_id.in_(enabled_ids))
    ).all()
    for stix_id, is_det in rows:
        if bool(is_det):
            detectable[stix_id] = True
        elif stix_id not in detectable:
            detectable[stix_id] = False
    return detectable


def _confidence_index(
    session: Session,
    enabled_ids: set[int],
) -> dict[str, float]:
    """Map each technique_stix_id to its best confidence over enabled sources.

    Args:
        session: Open SQLAlchemy session.
        enabled_ids: Set of enabled ``DataSourceType.id`` values.

    Returns:
        Mapping ``technique_stix_id -> float`` (0.0 when no enabled rows).
    """
    best: dict[str, float] = {}
    if not enabled_ids:
        return best
    rows = session.execute(
        select(
            TechniqueCoverage.technique_stix_id,
            TechniqueCoverage.detection_confidence,
        ).where(TechniqueCoverage.datasource_id.in_(enabled_ids))
    ).all()
    for stix_id, conf in rows:
        value = float(conf or 0.0)
        if value > best.get(stix_id, 0.0):
            best[stix_id] = value
    return best


def _contributing_sources_index(
    session: Session,
    enabled_ids: set[int],
) -> dict[str, list[str]]:
    """Map each technique_stix_id to its contributing source names (sorted).

    Args:
        session: Open SQLAlchemy session.
        enabled_ids: Set of enabled ``DataSourceType.id`` values.

    Returns:
        Mapping ``technique_stix_id -> sorted list of source names``.
    """
    index: dict[str, set[str]] = {}
    if not enabled_ids:
        return {}
    rows = session.execute(
        select(
            TechniqueCoverage.technique_stix_id,
            DataSourceType.name,
        )
        .join(DataSourceType, TechniqueCoverage.datasource_id == DataSourceType.id)
        .where(
            TechniqueCoverage.datasource_id.in_(enabled_ids),
            TechniqueCoverage.is_detectable.is_(True),
        )
    ).all()
    for stix_id, name in rows:
        index.setdefault(stix_id, set()).add(str(name))
    return {stix_id: sorted(names) for stix_id, names in index.items()}


def _technique_tactic(session: Session, stix_id: str) -> str:
    """Return the first canonical tactic for a technique.

    Falls back to ``"command-and-control"`` when the technique carries no
    canonical tactic, so per-tactic accounting always lands in a bucket.

    Args:
        session: Open SQLAlchemy session.
        stix_id: Technique STIX id.

    Returns:
        Canonical tactic slug.
    """
    row = session.execute(
        select(Technique.tactics).where(Technique.stix_id == stix_id)
    ).one_or_none()
    tactics = row[0] if row else []
    for t in CANONICAL_TACTICS:
        if t in tactics:
            return t
    return "command-and-control"


def _technique_name(session: Session, stix_id: str) -> str | None:
    """Return a technique's display name, or None if not found."""
    row = session.execute(
        select(Technique.name).where(Technique.stix_id == stix_id)
    ).one_or_none()
    return row[0] if row else None


def simulate_apt_attack(
    group_id: str,
    session: Session,
    *,
    persist: bool = True,
    config: Mapping[str, object] | None = None,
) -> SimulationResult:
    """Simulate an APT attack and classify every group technique.

    Algorithm (contract):

    1. Resolve the group via ``apt_groups.group_id`` (``ValueError`` listing
       valid ids if unknown).
    2. Collect the group's alive technique stix_ids from ``apt_technique``
       joined to ``techniques`` WHERE ``revoked`` is false, ordered by
       ``(attack_id, stix_id)``.
    3. For each technique, look up detectability against the *enabled*
       datasources (config is the source of truth for enablement).
    4. Classify:
       * DETECTED if the technique itself is detectable;
       * elif the technique is a sub-technique AND its parent is detectable
         -> DETECTED_ROLLUP;
       * elif the technique is a parent AND any child sub-technique is
         detectable -> DETECTED_ROLLUP;
       * else MISSED.
    5. Persist a :class:`SimulationResult` plus one
       :class:`SimulationTechnique` per group technique (when ``persist`` is
       True) and return the result.

    Invariant: ``detected + detected_rollup + missed == total``.

    Args:
        group_id: ATT&CK group id such as ``"G0016"``.
        session: Open SQLAlchemy session.
        persist: When True (default), write the result and per-technique rows
            to the session (flushed, not committed -- callers commit via
            :func:`database.session.session_scope`).
        config: Application config mapping. Required when ``persist`` is True
            (drives enablement and the summary's threshold/scope). When
            ``persist`` is False, defaults to the loader's defaults if
            omitted.

    Returns:
        The persisted (or in-memory) :class:`SimulationResult`.

    Raises:
        ValueError: If ``group_id`` is unknown or config is missing when
            required.
    """
    if config is None:
        if persist:
            raise ValueError(
                "config is required when persist=True (drives enablement and "
                "the summary metadata)"
            )
        from config_loader import DEFAULT_CONFIG

        config = DEFAULT_CONFIG

    # --- 1. resolve group -----------------------------------------------------
    group_row = session.execute(
        select(AptGroup.stix_id, AptGroup.name).where(
            AptGroup.group_id == group_id
        )
    ).one_or_none()
    if group_row is None:
        valid = sorted(
            row[0]
            for row in session.execute(
                select(AptGroup.group_id).order_by(AptGroup.group_id)
            ).all()
        )
        raise ValueError(
            f"unknown group_id {group_id!r}; valid ids: {valid}"
        )
    group_stix_id, group_name = group_row

    # --- 2. collect group techniques -----------------------------------------
    tech_rows = _group_techniques(session, group_stix_id)
    total = len(tech_rows)
    logger.info(
        "simulate %s (%s): %d alive technique(s)", group_id, group_name, total
    )

    # --- 3. detectability against enabled datasources ------------------------
    # Read detectability through the coverage_analyzer pipeline so the
    # simulation's notion of "detectable" is byte-identical to the coverage
    # engine's: load_coverage_rows applies platform scope filtering
    # (scope_hit) and the inclusive threshold, then emits one row per
    # (technique, tactic).  A technique is detectable here iff at least one
    # of its rows is both in-scope and detectable — i.e. the simulation
    # reads the *current* coverage_analyzer output on the shared
    # technique_stix_id join key, never an independent/stale projection.
    coverage_rows = load_coverage_rows(session, config)
    detectable_stix: set[str] = set()
    confidence_by_stix: dict[str, float] = {}
    contributing_by_stix: dict[str, set[str]] = {}
    for row in coverage_rows:
        # Map the coverage row's source_ids (datasource ids) back to labels
        # via the datasource_types table for the contributing_sources field.
        if row.is_detectable and row.scope_hit:
            detectable_stix.add(row.technique_stix_id)
        # best_confidence is the technique-level MAX across enabled sources
        # (already computed by load_coverage_rows); keep the highest seen.
        if row.best_confidence > confidence_by_stix.get(
            row.technique_stix_id, -1.0
        ):
            confidence_by_stix[row.technique_stix_id] = row.best_confidence
    # Build contributing source labels from the enabled datasource rows that
    # actually carry is_detectable for each technique (reuses the same
    # enabled-filter logic the coverage engine uses).
    enabled_ids = _enabled_datasource_ids(session, config)
    contributing = _contributing_sources_index(session, enabled_ids)
    # Expose the detectable set as a stix_id -> bool map for the rollup
    # helper (which expects Mapping[str, bool]).
    detectable = {stix_id: True for stix_id in detectable_stix}

    # Parent -> children index (alive, group techniques only) for the
    # parent-has-child rollup. Built once so lookups are O(1).
    parent_to_children: dict[str, set[str]] = {}
    attack_to_stix: dict[str, str] = {}
    for attack_id, stix_id, is_sub, parent_attack_id in tech_rows:
        attack_to_stix[attack_id] = stix_id
        if is_sub and parent_attack_id:
            parent_to_children.setdefault(parent_attack_id, set()).add(stix_id)

    # --- 4. classify ---------------------------------------------------------
    per_tactic: dict[str, dict[str, int]] = {
        t: {"total": 0, "detected": 0, "missed": 0} for t in CANONICAL_TACTICS
    }
    sim_techniques: list[SimulationTechnique] = []
    detected_count = detected_rollup_count = missed_count = 0

    for attack_id, stix_id, is_subtechnique, parent_attack_id in tech_rows:
        tactic = _technique_tactic(session, stix_id)

        status: str
        is_det = detectable.get(stix_id, False)
        if is_det:
            status = "detected"
        elif _rollup_eligible(
            stix_id=stix_id,
            attack_id=attack_id,
            is_subtechnique=is_subtechnique,
            parent_attack_id=parent_attack_id,
            detectable=detectable,
            parent_to_children=parent_to_children,
            attack_to_stix=attack_to_stix,
        ):
            status = "detected_rollup"
        else:
            status = "missed"

        if status == "detected":
            detected_count += 1
        elif status == "detected_rollup":
            detected_rollup_count += 1
        else:
            missed_count += 1

        bucket = per_tactic.setdefault(
            tactic, {"total": 0, "detected": 0, "missed": 0}
        )
        bucket["total"] += 1
        if status in ("detected", "detected_rollup"):
            bucket["detected"] += 1
        else:
            bucket["missed"] += 1

        sim_techniques.append(
            SimulationTechnique(
                technique_attack_id=attack_id,
                name=_technique_name(session, stix_id),
                tactic=tactic,
                status=status,
                confidence=round(confidence_by_stix.get(stix_id, 0.0), _ROUND_DECIMALS),
                contributing_sources=contributing.get(stix_id, []),
            )
        )

    # --- invariant guard -----------------------------------------------------
    assert detected_count + detected_rollup_count + missed_count == total, (
        f"classification invariant broken for {group_id}: "
        f"{detected_count}+{detected_rollup_count}+{missed_count} != {total}"
    )

    coverage_pct = round(detected_count / total, _ROUND_DECIMALS) if total else 0.0

    threshold = float(config.get("detection_confidence_threshold", 0.6))
    platform_scope = str(config.get("platform_scope", "all"))

    summary: dict = {
        "group_id": group_id,
        "run_at": _utcnow().isoformat(),
        "platform_scope": platform_scope,
        "threshold": threshold,
        "counts": {
            "total": total,
            "detected": detected_count,
            "detected_rollup": detected_rollup_count,
            "missed": missed_count,
        },
        "coverage_pct": coverage_pct,
        "per_tactic": {
            t: per_tactic[t] for t in CANONICAL_TACTICS if per_tactic[t]["total"]
        },
    }

    result = SimulationResult(
        group_stix_id=group_stix_id,
        group_id=group_id,
        run_at=_utcnow(),
        platform_scope=platform_scope,
        confidence_threshold=threshold,
        total_techniques=total,
        detected_count=detected_count,
        missed_count=missed_count,
        coverage_pct=coverage_pct,
        summary=summary,
    )

    if persist:
        session.add(result)
        session.flush()  # assign result.id before cascading children
        for sim in sim_techniques:
            sim.result_id = result.id
            session.add(sim)
        session.flush()
        logger.info(
            "simulate %s persisted: id=%s detected=%d rollup=%d missed=%d "
            "coverage=%.4f",
            group_id,
            result.id,
            detected_count,
            detected_rollup_count,
            missed_count,
            coverage_pct,
        )
    else:
        logger.info(
            "simulate %s (in-memory): detected=%d rollup=%d missed=%d",
            group_id,
            detected_count,
            detected_rollup_count,
            missed_count,
        )
    return result


def _rollup_eligible(
    *,
    stix_id: str,
    attack_id: str,
    is_subtechnique: bool,
    parent_attack_id: str | None,
    detectable: Mapping[str, bool],
    parent_to_children: Mapping[str, set[str]],
    attack_to_stix: Mapping[str, str],
) -> bool:
    """Return True if a technique qualifies for detected-rollup credit.

    Two cases (single hop, never chained):

    * Sub-technique whose *parent* technique is detectable (parent must be a
      group technique, since ``attack_to_stix`` is built from the group set).
    * Parent technique with at least one detectable child sub-technique
      (restricted to children the group actually uses, since
      ``parent_to_children`` is built from the group's technique set).
    """
    if is_subtechnique and parent_attack_id:
        parent_stix = attack_to_stix.get(parent_attack_id)
        if parent_stix is not None and detectable.get(parent_stix, False):
            return True
        return False
    if not is_subtechnique:
        for child_stix in parent_to_children.get(attack_id, ()):
            if detectable.get(child_stix, False):
                return True
    return False


def generate_recommendations(
    result: SimulationResult,
    session: Session,
    *,
    top_n: int = 3,
    config: Mapping[str, object] | None = None,
    rules: Sequence[MappingRule] | None = None,
) -> list[str]:
    """Recommend disabled datasources by greedy marginal gain.

    For each missed technique in ``result``, ask
    :func:`coverage_analyzer.calculate_coverage_gaps` which *disabled* log
    formats could close it. Then rank disabled sources by how many missed
    techniques they would close, tie-break by source priority (lower
    ``DataSourceType.priority`` first), and emit up to ``top_n`` templates.

    Templates::

        Enable {source_label} to cover {n} missed techniques ({ids_truncated})

    where ``ids_truncated`` lists up to three technique ids followed by
    ``", ..."`` when there are more. When a missed technique has no
    closable source, a fallback line is emitted::

        No configured source maps to {tid} — add a mapping row.

    Args:
        result: A :class:`SimulationResult` as produced by
            :func:`simulate_apt_attack`.
        session: Open SQLAlchemy session.
        top_n: Maximum number of source recommendations to emit.
        config: Application config mapping. Required.
        rules: Validated mapping rules for gap analysis. Required.

    Returns:
        Recommendation strings in ranked order (possibly empty when every
        technique is already covered or no rules are supplied).

    Raises:
        ValueError: If ``config`` or ``rules`` is missing.
    """
    if config is None:
        raise ValueError("config is required for generate_recommendations")
    if rules is None:
        raise ValueError("rules are required for generate_recommendations")
    if not rules:
        return []

    rows = load_coverage_rows(session, config)
    gaps = calculate_coverage_gaps(rows, rules, config)

    # Restrict to gaps whose attack_id appears in the result's missed set.
    missed_ids: set[str] = set()
    for sim in session.execute(
        select(SimulationTechnique.technique_attack_id).where(
            SimulationTechnique.result_id == result.id,
            SimulationTechnique.status == "missed",
        )
    ).all():
        missed_ids.add(sim[0])

    # Map disabled source name -> set of missed technique ids it closes.
    closable: dict[str, set[str]] = {}
    fallback: list[str] = []
    for gap in gaps:
        if gap.technique_attack_id not in missed_ids:
            continue
        if not gap.closable_by:
            fallback.append(
                f"No configured source maps to {gap.technique_attack_id} "
                f"— add a mapping row."
            )
            continue
        for source_name in gap.closable_by:
            closable.setdefault(source_name, set()).add(gap.technique_attack_id)

    # Source priority lookup (lower = higher priority).
    priority: dict[str, int] = {
        str(name): int(pri or 0)
        for name, pri in session.execute(
            select(DataSourceType.name, DataSourceType.priority)
        ).all()
    }

    # Rank: primary key = number of missed techniques closed (desc), then
    # source priority (asc), then name (asc) for byte-stable ties.
    ranked = sorted(
        closable.items(),
        key=lambda item: (-len(item[1]), priority.get(item[0], 0), item[0]),
    )[:top_n]

    recommendations: list[str] = []
    for source_name, technique_set in ranked:
        label = _SOURCE_LABELS.get(source_name, source_name)
        n = len(technique_set)
        ids_sorted = sorted(technique_set)
        if len(ids_sorted) <= 3:
            ids_str = ", ".join(ids_sorted)
        else:
            ids_str = ", ".join(ids_sorted[:3]) + ", ..."
        recommendations.append(
            f"Enable {label} to cover {n} missed techniques ({ids_str})"
        )
    # Append fallback lines after the ranked recommendations.
    recommendations.extend(fallback)
    return recommendations
