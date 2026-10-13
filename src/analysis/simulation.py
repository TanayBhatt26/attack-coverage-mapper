"""APT group data source for the simulation group picker.

The group picker (Streamlit sim view) and the simulation engine both need
the same two answers:

1. **List** every APT group with a human-readable ``name / alias / ...``
   label and its in-scope technique count, ordered so the analytically
   interesting groups (many techniques) surface first --
   :func:`list_apt_groups`.
2. **Resolve** a ``group_id`` (e.g. ``"G0016"``) to its
   :class:`~database.models.AptGroup`, rejecting anything unknown with a
   ``ValueError` that enumerates the valid ids --
   :func:`resolve_apt_group`.

Both answers read only the ``apt_groups`` / ``apt_technique`` /
``techniques`` tables; neither mutates the session.

Hashability contract
--------------------
:class:`AptGroupOption` is a frozen dataclass whose fields are only
``str`` / ``tuple`` / ``int`` -- natively hashable, so Streamlit
``@st.cache_data`` can memoise :func:`list_apt_groups` directly.
"""

# ===========================================================================
# SIMULATION OUTCOME CONTRACT (Phase 4 -- APT attack simulation engine)
# ===========================================================================
# This block documents the *return type* of :func:`simulate_apt_attack`: a
# frozen, natively-hashable :class:`SimulationOutcome` plus its nested frozen
# components. The contract mirrors the persisted SimulationResult /
# SimulationTechnique rows (written when ``persist=True``) but is a detached
# *value* -- immutable, session-free, safe to cache or compare across runs.
#
# --- Frozen dataclass hierarchy -------------------------------------------
# Three frozen dataclasses form the return type::
#
#     SimulationOutcome
#         +-- techniques: tuple[TechniqueOutcome, ...]
#         +-- per_tactic: tuple[TacticBreakdown, ...]
#         +-- recommendations: tuple[str, ...]
#
# :class:`SimulationOutcome` -- top-level result of one simulated run.
#     Attributes:
#         group_id: ATT&CK group id, e.g. ``"G0016"``.
#         group_stix_id: Stable STIX id of the group.
#         group_name: Human group name.
#         run_at: UTC-aware :class:`datetime.datetime` of the run.
#         platform_scope: Configured platform scope (e.g. ``"windows"``).
#         threshold: Detection confidence threshold applied.
#         total: Number of alive (non-revoked) techniques the group uses.
#         detected: Count of ``status == 'detected'`` techniques.
#         detected_rollup: Count of ``status == 'detected_rollup'``.
#         missed: Count of ``status == 'missed'`` techniques.
#         coverage_pct: ``round(detected / total, 4)``; 0.0 when ``total``
#             is 0 (never raises ``ZeroDivisionError``).
#         techniques: One :class:`TechniqueOutcome` per group technique,
#             sorted by ``(attack_id,)`` for byte-stable output.
#         per_tactic: One :class:`TacticBreakdown` per canonical Enterprise
#             tactic, in CANONICAL_TACTICS order (always length 14,
#             zero-filled).
#         recommendations: Greedy top-N acquisition advice strings from
#             :func:`generate_recommendations`, sorted by marginal gain.
#         persisted_result_id: The ``simulation_results.id`` when
#             ``persist=True``; ``None`` otherwise.
#
# :class:`TechniqueOutcome` -- per-technique classification.
#     Attributes:
#         technique_stix_id: Stable STIX id.
#         attack_id: ATT&CK id such as ``"T1059.001"``.
#         name: Technique display name.
#         tactic: Canonical tactic this technique is bucketed under: the
#             first tactic in CANONICAL_TACTICS order that the technique
#             carries (multi-tactic techniques appear once per tactic in
#             per_tactic but are bucketed under exactly one here).
#         status: ``'detected'`` | ``'detected_rollup'`` | ``'missed'``.
#         confidence: Technique-level best confidence across enabled
#             datasources, rounded to 6 decimals (0.0 when none).
#         contributing_sources: Alphabetically sorted datasource names
#             (e.g. ``"evtx"``) that contributed coverage evidence; empty
#             tuple when none.
#         is_subtechnique: Whether this is a sub-technique.
#         parent_attack_id: Parent technique attack id when
#             ``is_subtechnique``; ``None`` otherwise.
#         rollup_source: Why ``detected_rollup`` applies: ``'parent'`` (a
#             sub-technique whose parent is detectable), ``'child'`` (a
#             parent with a detectable sub-technique), or ``None`` (not a
#             rollup).
#
# :class:`TacticBreakdown` -- per-tactic rollup.
#     Attributes:
#         tactic: Canonical tactic slug (member of CANONICAL_TACTICS).
#         total: Group techniques assigned this tactic (multi-tactic
#             techniques count once per tactic).
#         detected: Those with status ``detected`` or ``detected_rollup``.
#         missed: Those with status ``missed``.
#
# --- Hashability contract --------------------------------------------------
# Every public return type is a frozen dataclass whose fields are only
# ``None | bool | int | float | str | datetime | tuple | nested-frozen-dataclass``
# and every collection is a ``tuple`` at every nesting depth -- never
# ``list``, ``dict`` or ``set`` -- so results are natively hashable and safe
# as ``@st.cache_data`` return values. :class:`datetime.datetime` is
# immutable/hashable.
#
# --- Invariants ------------------------------------------------------------
# - ``detected + detected_rollup + missed == total`` (exhaustive partition
#   of the group's alive techniques; each technique classified exactly once
#   in the top-level counts).
# - ``coverage_pct == round(detected / total, 4)`` when ``total > 0``, else
#   ``0.0``.
# - ``len(techniques) == total``.
# - ``len(per_tactic) == 14`` (one bucket per canonical tactic, in order).
# - ``sum(b.total for b in per_tactic) >= total`` (a multi-tactic
#   technique counts once per tactic; a technique carrying no canonical
#   tactic is counted in ``total`` but contributes nothing to per_tactic).
# - ``sum(b.detected + b.missed for b in per_tactic)`` equals the total
#   per-tactic assignment count (each assignment classified).
#
# --- Determinism -----------------------------------------------------------
# - ``techniques`` sorted by ``(attack_id,)``.
# - ``contributing_sources`` sorted alphabetically.
# - ``per_tactic`` in canonical ATT&CK order.
# - ``coverage_pct`` rounded to 4 decimals; ``confidence`` rounded to 6.
# - No ``set``- or ``dict``-order dependence anywhere.
#
# --- Classification algorithm (summary) ------------------------------------
# For each alive (``revoked`` false) group technique of the resolved group
# (see :func:`simulate_apt_attack`):
# 1. ``detected`` if ``is_detectable`` for that ``technique_stix_id`` under
#    the enabled datasources.
# 2. ``detected_rollup`` elif the technique is a sub-technique whose parent
#    is detectable (``rollup_source='parent'``), OR a parent technique with
#    any detectable sub-technique (``rollup_source='child'``).
# 3. ``missed`` otherwise.
# Config is the single source of truth for datasource enablement; the DB
# ``enabled`` mirror is a seed-time default only.
#
# --- Module API  ----------------------------------------------------------
# - :class:`SimulationOutcome` -- top-level frozen result.
# - :class:`TechniqueOutcome` -- per-technique row.
# - :class:`TacticBreakdown` -- per-tactic bucket.
# - :func:`simulate_apt_attack` -- run one simulation (returns
#   :class:`SimulationOutcome`; optionally persists rows).
# - :func:`generate_recommendations` -- greedy acquisition advice.
# ===========================================================================

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Tuple

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from analysis.coverage_analyzer import build_closable_index, load_coverage_rows
from config_loader import load_config
from database.models import (
    AptGroup,
    AptTechnique,
    AttackMeta,
    DataSourceType,
    SimulationResult,
    SimulationTechnique,
    Technique,
    TechniqueCoverage,
)

logger = logging.getLogger(__name__)

__all__ = (
    "AptGroupOption",
    "SOURCE_LABELS",
    "generate_recommendations",
    "list_apt_groups",
    "resolve_apt_group",
    "simulate_apt_attack",
)

#: Human-readable labels for the eight canonical log formats (recommendation
#: templates). Keys match ``DataSourceType.log_format`` values.
SOURCE_LABELS: dict[str, str] = {
    "evtx": "Windows Event Log",
    "syslog": "Syslog",
    "json": "JSON/ECS",
    "aws_cloudtrail": "AWS CloudTrail",
    "zeek": "Zeek",
    "nginx": "Nginx/Apache",
    "cef": "CEF",
    "leef": "LEEF",
}


@dataclass(frozen=True)
class AptGroupOption:
    """One APT group as displayed in the simulation group picker.

    Attributes:
        group_id: Short public id such as ``"G0016"`` (the lookup key).
        stix_id: Stable STIX id (the ``apt_groups`` PK / ``apt_technique``
            FK).
        name: Primary group name (e.g. ``"APT29"``).
        aliases: STIX aliases; element 0 is conventionally the canonical
            name, so ``aliases`` alone identifies the group. Empty tuple
            when the group has none.
        technique_count: Number of *non-revoked* techniques linked to this
            group (the denominator the simulation will evaluate).
    """

    group_id: str
    stix_id: str
    name: str
    aliases: Tuple[str, ...]
    technique_count: int

    @property
    def label(self) -> str:
        """Picker label: ``<name / alias / ...> (<count>)``.

        Falls back to ``name`` when a group has no aliases (two groups in
        the loaded bundle), so the label is never empty.
        """
        parts = list(self.aliases) if self.aliases else [self.name]
        return f"{' / '.join(parts)} ({self.technique_count})"


def _valid_group_ids(session: Session) -> Tuple[str, ...]:
    """Return every ``apt_groups.group_id`` in sorted order."""
    rows = session.execute(
        select(AptGroup.group_id).order_by(AptGroup.group_id)
    ).scalars().all()
    return tuple(rows)


def list_apt_groups(session: Session) -> Tuple[AptGroupOption, ...]:
    """Query the group-picker data source.

    Joins ``apt_groups`` to ``apt_technique`` and ``techniques`` (filtered
    to non-revoked) and counts the techniques the simulation will actually
    evaluate, then returns one :class:`AptGroupOption` per group sorted by
    that count descending (then name ascending for a stable total order).

    Groups with zero non-revoked techniques are included -- they sort last;
    the data source stays honest and lets the UI decide on filtering.

    Args:
        session: Open SQLAlchemy session bound to a schema containing
            ``apt_groups``, ``apt_technique`` and ``techniques``.

    Returns:
        Frozen options in deterministic ``(count desc, name asc)`` order.

    Raises:
        sqlalchemy.exc.OperationalError: If the schema is missing.
    """
    rows = session.execute(
        select(
            AptGroup.stix_id,
            AptGroup.group_id,
            AptGroup.name,
            AptGroup.aliases,
            func.count(Technique.stix_id),
        )
        .outerjoin(AptTechnique, AptGroup.stix_id == AptTechnique.group_stix_id)
        .outerjoin(
            Technique,
            and_(
                AptTechnique.technique_stix_id == Technique.stix_id,
                Technique.revoked.is_(False),
            ),
        )
        .group_by(AptGroup.stix_id)
        .order_by(func.count(Technique.stix_id).desc(), AptGroup.name.asc())
    ).all()

    options = tuple(
        AptGroupOption(
            group_id=group_id,
            stix_id=stix_id,
            name=name,
            aliases=tuple(a for a in (aliases or []) if isinstance(a, str)),
            technique_count=int(count or 0),
        )
        for stix_id, group_id, name, aliases, count in rows
    )
    logger.debug(
        "group picker: %d groups (%d with techniques)",
        len(options),
        sum(1 for o in options if o.technique_count > 0),
    )
    return options


def resolve_apt_group(session: Session, group_id: object) -> AptGroup:
    """Resolve a ``group_id`` to its :class:`AptGroup`.

    The input is whitespace-stripped and upper-cased before lookup: every
    loaded ``group_id`` matches ``^G\\d{4}$`` exactly (verified at ingest),
    so normalising case is safe and portable across the case-sensitive
    ``=`` operator on both SQLite and PostgreSQL.

    Args:
        session: Open SQLAlchemy session.
        group_id: Public group id such as ``"G0016"`` (``"g0016"`` is
            accepted via upper-casing).

    Returns:
        The matching :class:`AptGroup`.

    Raises:
        ValueError: If ``group_id`` is ``None``, empty/whitespace, or does
            not match any group. The message enumerates every valid id so
            the UI can surface the exact options.
    """
    if group_id is None:
        raise ValueError(
            f"Unknown group {group_id!r}. Valid group ids: {_valid_group_ids(session)}"
        )
    normalized = str(group_id).strip().upper()
    if not normalized:
        raise ValueError(
            f"Unknown group {str(group_id)!r}. Valid group ids: {_valid_group_ids(session)}"
        )

    group = session.execute(
        select(AptGroup).where(AptGroup.group_id == normalized)
    ).scalar_one_or_none()

    if group is None:
        raise ValueError(
            f"Unknown group {normalized!r}. Valid group ids: {_valid_group_ids(session)}"
        )
    return group


# --- Simulation outcome frozen dataclasses (Phase 4 contract) ----------------


@dataclass(frozen=True)
class TechniqueOutcome:
    """One group technique's detectability classification.

    See the module-level "Simulation outcome contract" block for semantics.
    """

    technique_stix_id: str
    attack_id: str
    name: str
    tactic: str
    status: str
    confidence: float
    contributing_sources: tuple[str, ...]
    is_subtechnique: bool
    parent_attack_id: str | None
    rollup_source: str | None


@dataclass(frozen=True)
class TacticBreakdown:
    """Detectability rollup for one Enterprise tactic bucket.

    See the module-level "Simulation outcome contract" block for semantics.
    """

    tactic: str
    total: int
    detected: int
    missed: int


@dataclass(frozen=True)
class SimulationOutcome:
    """Top-level, frozen, hashable result of one simulated APT run.

    See the module-level "Simulation outcome contract" block for the full
    hierarchy, invariants, hashability contract, and determinism rules.
    """

    group_id: str
    group_stix_id: str
    group_name: str
    run_at: datetime
    platform_scope: str
    threshold: float
    total: int
    detected: int
    detected_rollup: int
    missed: int
    coverage_pct: float
    techniques: tuple[TechniqueOutcome, ...]
    per_tactic: tuple[TacticBreakdown, ...]
    recommendations: tuple[str, ...]
    persisted_result_id: int | None


# --- Simulation engine --------------------------------------------------------


def _load_config() -> dict:
    """Load the repo config.yaml (enablement source of truth).

    Isolated as a helper so tests can monkeypatch it.
    """
    return load_config("config.yaml")


def _enabled_sources(config: Mapping) -> frozenset[str]:
    """Return the set of enabled log format names under ``config``.

    Mirrors the coverage engine's semantics: a format counts as disabled
    only when its value is exactly ``False``; absent keys count as enabled.
    """
    src_map = config.get("enabled_log_sources")
    if not isinstance(src_map, Mapping) or not src_map:
        return frozenset()
    return {
        str(fmt).lower()
        for fmt, enabled in src_map.items()
        if bool(enabled)
    }


def _group_technique_rows(
    session: Session, group_stix_id: str
) -> list[tuple[str, str, str, list[str], bool, str | None]]:
    """Return alive group techniques as ``(stix_id, attack_id, name, tactics,
    is_subtechnique, parent_attack_id)`` rows.
    """
    rows = session.execute(
        select(
            Technique.stix_id,
            Technique.attack_id,
            Technique.name,
            Technique.tactics,
            Technique.is_subtechnique,
            Technique.parent_attack_id,
        )
        .join(AptTechnique, AptTechnique.technique_stix_id == Technique.stix_id)
        .where(
            AptTechnique.group_stix_id == group_stix_id,
            Technique.revoked.is_(False),
        )
        .order_by(Technique.attack_id, Technique.stix_id)
    ).all()
    return [
        (stix_id, attack_id, name, list(tactics or []), bool(is_sub), parent)
        for stix_id, attack_id, name, tactics, is_sub, parent in rows
    ]


def _detectability_index(
    session: Session, config: Mapping,
) -> tuple[dict[str, float], dict[str, list[str]], dict[str, set[str]]]:
    """Compute per-technique detectability against *enabled* datasources.

    Returns:

        - ``best_conf``: ``technique_stix_id -> best confidence`` (0.0 when
          the technique has no enabled coverage rows).
        - ``contributors``: ``technique_stix_id -> sorted source names`` that
          achieved the best confidence.
        - ``children_of``: ``parent_attack_id -> set[child stix_id]`` for
          alive sub-techniques.
    """
    src_map = config.get("enabled_log_sources")
    disabled: set[str] = set()
    if isinstance(src_map, Mapping) and src_map:
        disabled = {str(k).lower() for k, v in src_map.items() if not bool(v)}
    threshold = float(config.get("detection_confidence_threshold", 0.6))

    cov_rows = session.execute(
        select(
            TechniqueCoverage.technique_stix_id,
            TechniqueCoverage.detection_confidence,
            DataSourceType.log_format,
        )
        .join(DataSourceType, TechniqueCoverage.datasource_id == DataSourceType.id)
    ).all()

    best_conf: dict[str, float] = {}
    contributors: dict[str, list[str]] = {}
    for stix_id, conf, log_format in cov_rows:
        fmt = str(log_format or "").lower()
        if fmt in disabled:
            continue
        conf = float(conf or 0.0)
        current_best = best_conf.get(stix_id, -1.0)
        if conf > current_best:
            best_conf[stix_id] = conf
            contributors[stix_id] = [fmt]
        elif conf == current_best and conf >= threshold:
            contributors.setdefault(stix_id, []).append(fmt)

    # Deduplicate + sort contributor lists for determinism.
    for stix_id in contributors:
        contributors[stix_id] = sorted(set(contributors[stix_id]))

    # Children index (alive sub-techniques only).
    children_of: dict[str, set[str]] = {}
    for stix_id, parent, revoked, is_sub in session.execute(
        select(
            Technique.stix_id,
            Technique.parent_attack_id,
            Technique.revoked,
            Technique.is_subtechnique,
        )
    ).all():
        if revoked or not is_sub or not parent:
            continue
        children_of.setdefault(parent, set()).add(stix_id)

    return best_conf, contributors, children_of


def simulate_apt_attack(
    group_id: str,
    session: Session,
    *,
    persist: bool = True,
    config: Mapping | None = None,
) -> SimulationResult:
    """Simulate one APT group's techniques against the current coverage.

    Pure function of the DB + config: re-simulating after a source toggle
    recomputes from scratch. Each run appends a fresh ``SimulationResult``
    (history preserved; the dashboard renders the latest per ``group_id``).

    Algorithm (contract):

    1. Resolve the group via ``apt_groups.group_id`` (``ValueError`` listing
       the valid ids when unknown).
    2. Get the group's technique stix_ids from ``apt_technique`` joined to
       ``techniques`` WHERE ``revoked = False``.
    3. For each, look up coverage detectability via ``technique_coverage``
       rows joined to *enabled* datasources (config is the single source of
       truth for enablement).
    4. Classify each group technique:

       - ``detected``        -- detectable for that technique_stix_id;
       - ``detected_rollup`` -- sub-technique whose parent is detectable, OR
         parent technique with at least one detectable child (one level);
       - ``missed``          -- neither.

       Invariant: ``detected + detected_rollup + missed == total``.
    5. ``coverage_pct = round((detected + detected_rollup) / total, 4)`` (0.0
       guard on total=0). Both directly-detected techniques and those
       covered via one-level parent/child roll-up count toward the headline
       coverage rate (contract D).
       Persist one ``SimulationResult`` + one ``SimulationTechnique`` per
       group technique (status, confidence, contributing_sources).
       ``run_at`` = UTC now.

    Args:
        group_id: Public group id such as ``"G0016"`` (case-insensitive).
        session: Open SQLAlchemy session bound to the coverage schema.
        persist: When True (default), append one ``SimulationResult`` plus
            one ``SimulationTechnique`` per group technique. When False,
            compute and return the result without writing.
        config: Config mapping to use; defaults to ``config.yaml`` via
            :func:`load_config`. Tests may inject a controlled mapping.

    Returns:
        The persisted (or computed) ``SimulationResult``.

    Raises:
        ValueError: If ``group_id`` is unknown (lists valid ids), or if the
            config subset is invalid.
    """
    if config is None:
        config = _load_config()

    threshold = float(config.get("detection_confidence_threshold", 0.6))
    platform_scope = str(config.get("platform_scope", "all"))

    # Capture run_at exactly once so result.run_at and summary.run_at always
    # agree to the microsecond (determinism contract).
    run_at = datetime.now(timezone.utc)

    group = resolve_apt_group(session, group_id)
    normalized_group_id = str(group.group_id)

    # Preserve run_at tzinfo across commit: SQLAlchemy expires all attributes
    # on session.commit(), and re-reading a DateTime(timezone=True) from
    # SQLite returns a naive datetime (SQLite stores no tz). Disabling
    # expire_on_commit for this run keeps the tz-aware run_at we set on the
    # returned result, so callers can read result.run_at after committing.
    session.expire_on_commit = False
    return _run_simulation(
        session, group, normalized_group_id, config, threshold,
        platform_scope, run_at, persist,
    )


def _run_simulation(
    session: Session,
    group: AptGroup,
    normalized_group_id: str,
    config: Mapping,
    threshold: float,
    platform_scope: str,
    run_at: datetime,
    persist: bool,
) -> SimulationResult:
    """Inner classification + persistence (expire_on_commit pinned False)."""
    techniques = _group_technique_rows(session, group.stix_id)
    total = len(techniques)

    best_conf, contributors, children_of = _detectability_index(session, config)

    # Detectability uses the coverage engine's scope-aware detectable set
    # (load_coverage_rows), which applies platform-scope filtering and the
    # inclusive threshold. Under the default config this yields 24 detectable
    # techniques (the contract's "detectable set"). The raw best_conf test
    # would over-count techniques whose coverage exists but whose platform is
    # out of scope (e.g. IaaS/SaaS techniques under a windows scope).
    coverage_rows = load_coverage_rows(session, config)
    detectable_stix: set[str] = {
        row.technique_stix_id
        for row in coverage_rows
        if row.is_detectable and row.scope_hit
    }

    # attack_id -> stix_id for parent lookup. A parent technique may not be
    # used by this group, so resolve parent stix ids from the full alive
    # techniques table (not just the group's own techniques).
    attack_to_stix: dict[str, str] = {
        attack_id: stix_id for stix_id, attack_id, *_ in techniques
    }
    missing_parents = {
        parent
        for _, _, _, _, is_sub, parent in techniques
        if is_sub and parent and parent not in attack_to_stix
    }
    if missing_parents:
        for stix_id, attack_id in session.execute(
            select(Technique.stix_id, Technique.attack_id).where(
                Technique.attack_id.in_(missing_parents),
                Technique.revoked.is_(False),
            )
        ).all():
            attack_to_stix.setdefault(attack_id, stix_id)

    detected_count = 0
    rollup_count = 0
    missed_count = 0

    per_tactic: dict[str, dict[str, int]] = {}
    sim_technique_rows: list[SimulationTechnique] = []

    for stix_id, attack_id, name, tactics, is_sub, parent_attack_id in techniques:
        # Determine the primary tactic (first canonical one) for per_tactic.
        primary_tactic = None
        for t in _TACTIC_ORDER:
            if t in tactics:
                primary_tactic = t
                break
        if primary_tactic is None:
            # Fall back to the first listed tactic so per_tactic stays honest.
            primary_tactic = tactics[0] if tactics else "unknown"

        own_conf = round(best_conf.get(stix_id, 0.0), 6)
        sources = contributors.get(stix_id, [])

        # Own detectability uses the coverage engine's scope-aware set
        # (detectable_stix), NOT the raw best_conf >= threshold test which
        # ignores platform scope.  Roll-up eligibility for parent/child is
        # likewise judged against the same scope-aware set.
        own_detectable = stix_id in detectable_stix

        status = "missed"
        conf = own_conf
        if own_detectable:
            status = "detected"
        else:
            # Roll-up: sub with detectable parent, OR parent with detectable
            # child. Confidence + sources are attributed to the *covering*
            # technique (the one that actually provides the detection).
            if is_sub and parent_attack_id:
                parent_stix = attack_to_stix.get(parent_attack_id)
                if parent_stix and parent_stix in detectable_stix:
                    status = "detected_rollup"
                    conf = round(best_conf[parent_stix], 6)
                    sources = contributors.get(parent_stix, [])
            elif not is_sub:
                child_stix_ids = children_of.get(attack_id, set())
                best_child_stix = None
                best_child_conf = -1.0
                for c in child_stix_ids:
                    cconf = best_conf.get(c, 0.0)
                    if c in detectable_stix and cconf > best_child_conf:
                        best_child_conf = cconf
                        best_child_stix = c
                if best_child_stix is not None:
                    status = "detected_rollup"
                    conf = round(best_child_conf, 6)
                    sources = contributors.get(best_child_stix, [])

        if status == "detected":
            detected_count += 1
        elif status == "detected_rollup":
            rollup_count += 1
        else:
            missed_count += 1

        # Per-tactic accounting (each technique counted once per tactic).
        # Both ``detected`` and ``detected_rollup`` count as detected so
        # per_tactic detected + missed == total for every tactic bucket.
        # Every canonical Enterprise tactic gets a bucket (length 14, in
        # ATT&CK order) even when the group touches zero of its techniques,
        # so the dashboard always renders a complete matrix.
        for t in tactics:
            bucket = per_tactic.setdefault(t, {"total": 0, "detected": 0, "missed": 0})
            bucket["total"] += 1
            if status in ("detected", "detected_rollup"):
                bucket["detected"] += 1
            else:
                bucket["missed"] += 1

        if persist:
            sim_technique_rows.append(
                SimulationTechnique(
                    technique_attack_id=attack_id,
                    name=name,
                    tactic=primary_tactic,
                    status=status,
                    confidence=conf,
                    contributing_sources=sources,
                )
            )

    # Invariant guard (defensive; should always hold).
    assert detected_count + rollup_count + missed_count == total, (
        f"classification partition failed: {detected_count}+{rollup_count}+"
        f"{missed_count} != {total}"
    )

    # coverage_pct = (detected + detected_rollup) / total (0.0 guard). Both
    # directly-detected techniques and those covered via one-level parent/
    # child roll-up count toward the headline coverage rate (contract D).
    coverage_pct = round(
        (detected_count + rollup_count) / total, 4
    ) if total > 0 else 0.0

    summary: dict[str, object] = {
        "group_id": normalized_group_id,
        "run_at": run_at.isoformat(),
        "platform_scope": platform_scope,
        "threshold": threshold,
        "counts": {
            "total": total,
            "detected": detected_count,
            "detected_rollup": rollup_count,
            "missed": missed_count,
        },
        "coverage_pct": coverage_pct,
        # All 14 canonical Enterprise tactics, in ATT&CK order, even when a
        # bucket is empty (determinism + complete-dashboard contract).
        "per_tactic": {
            t: per_tactic.get(t, {"total": 0, "detected": 0, "missed": 0})
            for t in _TACTIC_ORDER
        },
    }
    # Provenance: pin this simulation to the ATT&CK bundle that produced
    # the DB (the single-row AttackMeta snapshot). Tolerant of an absent
    # row -- provenance simply omitted.
    provenance = _attack_meta_provenance(session)
    if provenance:
        summary["attack_meta"] = provenance

    result = SimulationResult(
        group_stix_id=group.stix_id,
        group_id=normalized_group_id,
        run_at=run_at,
        platform_scope=platform_scope,
        confidence_threshold=threshold,
        total_techniques=total,
        detected_count=detected_count + rollup_count,
        missed_count=missed_count,
        coverage_pct=coverage_pct,
        summary=summary,
    )
    # Attach rollup count onto the ORM object via the summary (no column).
    # The model has no detected_rollup_count column; summary carries it.

    if persist:
        session.add(result)
        session.flush()  # assign PK before FK references
        for row in sim_technique_rows:
            row.result_id = result.id
            session.add(row)
        session.flush()
        logger.info(
            "simulation %s: %d techniques, %d detected, %d rollup, %d missed, "
            "%.2f%% coverage",
            normalized_group_id, total, detected_count, rollup_count,
            missed_count, coverage_pct * 100,
        )

    return result


def generate_recommendations(
    result: SimulationResult,
    session: Session,
    top_n: int = 3,
    *,
    config: Mapping | None = None,
    rules: Sequence | None = None,
) -> list[str]:
    """Generate greedy marginal-gain acquisition advice for a simulation.

    Ranks *disabled* log formats by how many missed techniques each would
    close, using the coverage engine's ``build_closable_index`` for honest
    threshold-gated attribution. Already-enabled sources are excluded.

    Templates:

        'Enable {source_label} to cover {n} missed techniques ({ids_truncated})'
        'No configured source maps to {tid} — add a mapping row.'

    Args:
        result: A ``SimulationResult`` from :func:`simulate_apt_attack`.
        session: Open SQLAlchemy session.
        top_n: Maximum number of recommendation strings to return.
        config: Config mapping to use; defaults to ``config.yaml``.
        rules: Mapping rules passed to ``build_closable_index``. When None,
            the function loads rules from the curated CSV via
            ``parser.mappings_io.load_mappings`` (best-effort; if loading
            fails, falls back to the closable index from the DB alone).

    Returns:
        A list of recommendation strings, ranked by marginal gain (largest
        first), tie-broken by source priority, then name.
    """
    if config is None:
        config = _load_config()

    # Collect missed technique attack ids.
    missed_ids: list[str] = []
    for tech in result.summary.get("per_tactic", {}).values():
        pass  # per_tactic doesn't carry ids; query SimulationTechnique rows.
    missed_ids = [
        row.technique_attack_id
        for row in session.query(SimulationTechnique)
        .filter(
            SimulationTechnique.result_id == result.id,
            SimulationTechnique.status == "missed",
        )
        .all()
    ]

    if not missed_ids:
        return []

    # Build closable index from rules if provided, else from DB coverage.
    closable: dict[str, tuple[str, ...]] = {}
    if rules is not None:
        closable = build_closable_index(list(rules), config)
    else:
        closable = _closable_index_from_db(session, config)

    # Determine disabled sources.
    src_map = config.get("enabled_log_sources")
    disabled_sources: list[str] = []
    if isinstance(src_map, Mapping):
        disabled_sources = sorted(
            str(k) for k, v in src_map.items() if not bool(v)
        )
    enabled = set()
    if isinstance(src_map, Mapping):
        enabled = {str(k).lower() for k, v in src_map.items() if bool(v)}

    # Count how many missed techniques each disabled source closes.
    source_hits: dict[str, list[str]] = {}
    for tid in missed_ids:
        closable_by = closable.get(tid, ())
        for src in closable_by:
            if src in enabled:
                continue
            source_hits.setdefault(src, []).append(tid)

    # Source priority for tie-breaking (lower = higher priority).
    priority: dict[str, int] = {}
    for ds in session.query(DataSourceType).all():
        priority[str(ds.log_format).lower()] = int(ds.priority or 0)

    ranked = sorted(
        source_hits.items(),
        key=lambda item: (-len(item[1]), priority.get(item[0], 0), item[0]),
    )

    recommendations: list[str] = []
    for src, ids in ranked[:top_n]:
        label = SOURCE_LABELS.get(src, src)
        ids_str = ", ".join(ids[:5])
        if len(ids) > 5:
            ids_str += f", … (+{len(ids) - 5} more)"
        recommendations.append(
            f"Enable {label} to cover {len(ids)} missed techniques ({ids_str})"
        )

    # Fallback for missed techniques with no closable source.
    covered_by_rec = set()
    for ids in source_hits.values():
        covered_by_rec.update(ids)
    unmapped = [tid for tid in missed_ids if tid not in covered_by_rec]
    if unmapped and len(recommendations) < top_n:
        recommendations.append(
            f"No configured source maps to {unmapped[0]} — add a mapping row."
        )

    return recommendations[:top_n]



def _attack_meta_provenance(session: Session) -> dict[str, object]:
    """Return the single-row ATT&CK bundle snapshot as a plain dict.

    The :class:`~database.models.AttackMeta` table pins the library +
    bundle version + bundle date + object count that produced this DB, so
    every simulation can be traced to its source bundle.  When the row is
    absent (e.g. a freshly created test DB) an empty dict is returned --
    callers must tolerate missing keys.

    Args:
        session: Open SQLAlchemy session.

    Returns:
        A dict with ``library_version``, ``bundle_version``, ``bundle_date``,
        ``object_count`` and ``loaded_at`` when the row exists; ``{}``
        otherwise.
    """
    row = session.execute(select(AttackMeta)).scalar_one_or_none()
    if row is None:
        return {}
    return {
        "library_version": row.library_version,
        "bundle_version": row.bundle_version,
        "bundle_date": row.bundle_date,
        "object_count": row.object_count,
        "loaded_at": row.loaded_at.isoformat() if row.loaded_at else None,
    }


def _closable_index_from_db(
    session: Session, config: Mapping,
) -> dict[str, tuple[str, ...]]:
    """Build a closable index directly from ``technique_coverage`` rows.

    Used when mapping rules aren't passed in: for each disabled source,
    find techniques whose best confidence on that source reaches the
    threshold. This mirrors ``build_closable_index`` semantics but reads
    the DB (where the static projection is already materialised).
    """
    src_map = config.get("enabled_log_sources")
    disabled: set[str] = set()
    if isinstance(src_map, Mapping) and src_map:
        disabled = {str(k).lower() for k, v in src_map.items() if not bool(v)}
    threshold = float(config.get("detection_confidence_threshold", 0.6))

    cov_rows = session.execute(
        select(
            TechniqueCoverage.technique_attack_id,
            TechniqueCoverage.detection_confidence,
            DataSourceType.log_format,
        )
        .join(DataSourceType, TechniqueCoverage.datasource_id == DataSourceType.id)
    ).all()

    best_by_source: dict[str, dict[str, float]] = {}
    for attack_id, conf, log_format in cov_rows:
        fmt = str(log_format or "").lower()
        if fmt not in disabled:
            continue
        conf = float(conf or 0.0)
        per_fmt = best_by_source.setdefault(attack_id, {})
        if conf > per_fmt.get(fmt, -1.0):
            per_fmt[fmt] = conf

    index: dict[str, tuple[str, ...]] = {}
    for attack_id, per_fmt in best_by_source.items():
        closable = tuple(sorted(f for f, s in per_fmt.items() if s >= threshold))
        if closable:
            index[attack_id] = closable
    return index


_TACTIC_ORDER: tuple[str, ...] = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)
