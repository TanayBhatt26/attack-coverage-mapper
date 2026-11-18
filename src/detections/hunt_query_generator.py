"""Hunt-query dispatch engine (Phase 5 Wave 2 -- the core emitter).

The hunt-query pipeline emits exactly one inert hunt query per *missed*
technique in a Phase-4 simulation run (the work-list invariant,
``docs/_phase4_handoff.md:144-146``).  Dispatch follows fixed precedence
(Wave 1, ``research/p5-wave1-full-results.md`` agent-420):

1. **hand-curated** -- the M001-M020 core mapping set
   (:func:`detections.hand_written.curated_spl`).
2. **community-sourced** -- a SigmaHQ rule converted via pySigma
   (:class:`sigma.backends.splunk.SplunkBackend` +
   :class:`sigma.pipelines.splunk.splunk_windows_pipeline`).
3. **generic** -- an ``# UNREVIEWED`` fallback template
   (:func:`detections.hand_written.generic_template`).

The public entry point is :func:`export_all_queries`, which the Streamlit
Hunt view (Phase 6) and a future JSON export consume.  Every emitted query
is persisted to ``technique_coverage.splunk_query`` +
``.query_source`` + ``attribution_json`` (the Phase-5-owned columns;
``coverage_analyzer.py:64`` never touches them).

This module is the integration layer: it owns no conversion, scoring, or
caching logic of its own -- it delegates to
:class:`detections.sigma_index.SigmaIndex`,
:class:`detections.sigma_cache.SigmaConversionCache`, and
:mod:`detections.hand_written`, and orchestrates them.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from collections.abc import Mapping
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.analysis.coverage_analyzer import (
    calculate_coverage_gaps,
    load_coverage_rows,
)
from src.config_loader import DEFAULT_CONFIG_PATH, load_config
from src.database.models import SimulationTechnique, Technique, TechniqueCoverage
from src.database.session import session_scope
from src.parser.mappings_io import DEFAULT_MAPPINGS_PATH, load_mappings

from .hand_written import (
    ATTRIBUTION_LABELS,
    curated_spl,
    generic_template,
    is_inert,
)
from .sigma_cache import SigmaConversionCache, cache_key
from .sigma_index import LogsourceMapper, SigmaIndex

logger = logging.getLogger(__name__)

__all__ = ("export_all_queries",)

# pySigma imports are deferred to the point of conversion so that the module
# imports cleanly even when pySigma is absent (the curated/generic paths do
# not need it).  Wave 1 verified the import names
# (``research/p5-wave1-full-results.md`` agent-431).
_BACKEND_NAME = "SplunkBackend"
_PIPELINE_NAME = "splunk_windows_pipeline"

# Status weights for rule scoring (Wave 1 agent-425).
_STATUS_WEIGHT: dict[str, float] = {
    "stable": 1.0,
    "experimental": 0.7,
    "test": 0.5,
    "deprecated": 0.2,
    "unsupported": 0.0,
}

# Scoring weights (Wave 1 agent-425): src + status + simple + fp + level + fresh.
_W_SRC = 0.30
_W_STATUS = 0.25
_W_SIMPLE = 0.15
_W_FP = 0.15
_W_LEVEL = 0.10
_W_FRESH = 0.05

# Level weights for the scoring tie-break.
_LEVEL_WEIGHT: dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.6,
    "low": 0.3,
    "informational": 0.1,
}

# DRL 1.1 license notice (Wave 1 agent-438).
_DRL_LICENSE = "Detection Rule License (DRL) 1.1"
_DRL_LICENSE_URL = (
    "https://github.com/SigmaHQ/Detection-Rule-License"
    "/blob/main/LICENSE.Detection.Rules.md"
)
_SIGMA_REPO_URL = "https://github.com/SigmaHQ/sigma"


def _resolve_source_format(
    closable_by: tuple[str, ...],
    contributing_sources: list[str],
    enabled_sources: tuple[str, ...],
) -> str:
    """Pick the target source format for a generic/curated query.

    Precedence (Wave 1 agent-426): ``closable_by[0]`` (alphabetically first
    disabled format that would close the gap) else ``contributing_sources[0]``
    else the alphabetically-first enabled source else ``'json'`` (the most
    generic fallback).

    Args:
        closable_by: Alphabetically-sorted disabled source formats.
        contributing_sources: Sources that already contribute to this
            technique (from the simulation row).
        enabled_sources: All enabled source formats (alphabetically sorted).

    Returns:
        A resolved source-format key such as ``'evtx'``.
    """
    if closable_by:
        return closable_by[0]
    if contributing_sources:
        return contributing_sources[0]
    if enabled_sources:
        return enabled_sources[0]
    return "json"


def _enabled_sources(config: Mapping[str, Any]) -> tuple[str, ...]:
    """Return all enabled source formats, alphabetically sorted.

    Mirrors the ``enabled_log_sources`` contract in ``config.yaml``
    (``coverage_analyzer.py:797-802``: absent key = enabled).

    Args:
        config: The loaded config mapping.

    Alphabetically-sorted enabled source-format keys.
    """
    enabled = config.get("enabled_log_sources", {})
    if isinstance(enabled, Mapping):
        return tuple(sorted(k for k, v in enabled.items() if v))
    return ()


def _validate_closable_by_invariant(
    gaps: tuple[Any, ...],
    enabled_sources: tuple[str, ...],
) -> None:
    """Validate that no enabled source appears in any gap's ``closable_by``.

    The ``closable_by`` field should only contain *disabled* sources whose
    static projection reaches the threshold. An enabled source appearing there
    indicates a logic error in :func:`build_closable_index`.

    Args:
        gaps: The gaps from :func:`calculate_coverage_gaps`.
        enabled_sources: All enabled source formats (alphabetically sorted).

    Raises:
        ValueError: If any enabled source is found in a gap's ``closable_by``.
    """
    enabled_set = frozenset(enabled_sources)
    violations = []
    for gap in gaps:
        for src in gap.closable_by:
            if src in enabled_set:
                violations.append(
                    f"closable_by invariant violated: {gap.technique_attack_id} "
                    f"has enabled source {src} in closable_by"
                )
    if violations:
        raise ValueError("; ".join(violations))


def _score_rule(
    rule: Any,
    target_source: str,
) -> float:
    """Score a candidate Sigma rule for a target source (higher = better).

    Weighted sum per Wave 1 agent-425::

        score = 0.30*src + 0.25*status + 0.15*simple + 0.15*fp
                + 0.10*level + 0.05*fresh

    Args:
        rule: A parsed :class:`sigma.rule.SigmaRule`.
        target_source: The resolved source-format key to match against.

    Returns:
        A float score in roughly ``[0, 1]``.
    """
    # --- source match (0..1) ---
    rule_logsource = getattr(rule, "logsource", None)
    if LogsourceMapper.matches(rule_logsource, target_source):
        src = 1.0
    elif LogsourceMapper.matches(rule_logsource, "json"):
        # Partial credit: json is the generic catch-all.
        src = 0.5
    else:
        src = 0.0

    # --- status (0..1) ---
    status = getattr(rule, "status", None)
    status_key = str(status).lower() if status else "test"
    status_score = _STATUS_WEIGHT.get(status_key, 0.5)

    # --- simplicity (0..1): fewer detection clauses -> higher ---
    detection = getattr(rule, "detection", None)
    clause_count = len(detection.detection_items) if detection else 1
    import math

    simple = 1.0 / (1.0 + math.log(1 + clause_count))

    # --- falsepositive burden (0..1): fewer FP notes -> higher ---
    fp_list = getattr(rule, "falsepositives", None) or []
    fp = 1.0 / (1.0 + math.log(1 + len(fp_list)))

    # --- level (0..1) ---
    level = getattr(rule, "level", None)
    level_key = str(level).lower() if level else "medium"
    level_score = _LEVEL_WEIGHT.get(level_key, 0.6)

    # --- freshness (0..1): exponential decay on modified date ---
    fresh = 0.5  # neutral when date unavailable
    modified = getattr(rule, "modified", None) or getattr(rule, "date", None)
    if modified:
        try:
            from datetime import date as _date

            if isinstance(modified, str):
                modified = _date.fromisoformat(modified)
            years = (_date.today() - modified).days / 365.25
            fresh = math.exp(-0.5 * max(years, 0.0))
        except (ValueError, TypeError):
            fresh = 0.5

    return (
        _W_SRC * src
        + _W_STATUS * status_score
        + _W_SIMPLE * simple
        + _W_FP * fp
        + _W_LEVEL * level_score
        + _W_FRESH * fresh
    )


def _sigma_rule_url(clone_dir: str | None, rule_path: str) -> str:
    """Build a GitHub permalink for a Sigma rule file.

    Args:
        clone_dir: Root of the SigmaHQ clone (used to compute the repo-relative
            path).  When ``None``, a generic repo URL is returned.
        rule_path: Absolute or relative path to the rule file.

    Returns:
        A GitHub ``blob/master/...`` permalink, or the repo root URL when the
        path cannot be made relative.
    """
    if clone_dir and rule_path:
        try:
            rel = rule_path.replace("\\", "/")
            idx = rel.rfind("rules/")
            if idx >= 0:
                rel = rel[idx:]
            else:
                from pathlib import Path

                rel = str(Path(rule_path).relative_to(Path(clone_dir))).replace(
                    "\\", "/"
                )
            return f"{_SIGMA_REPO_URL}/blob/master/{rel}"
        except (ValueError, OSError):
            pass
    return _SIGMA_REPO_URL


def _build_attribution(
    rule: Any,
    technique_id: str,
    clone_dir: str | None,
    rule_path: str,
) -> dict[str, Any]:
    """Build the DRL 1.1 attribution dict for a Sigma-derived query.

    DRL 1.1 obligations (Wave 1 agent-438): retain author, link rule set,
    state DRL 1.1 license.  ``author`` is optional in the Sigma spec, so it
    falls back to ``'unknown'`` (never skip the rule -- that would break the
    work-list invariant).

    Args:
        rule: A parsed :class:`sigma.rule.SigmaRule`.
        technique_id: The technique id this rule covers.
        clone_dir: Root of the SigmaHQ clone.
        rule_path: Path to the rule file.

    Returns:
        An attribution dict with author/rule_uuid/rule_url/license/etc.
    """
    author = getattr(rule, "author", None)
    if not author or not str(author).strip():
        author = "unknown"
    rule_uuid = str(getattr(rule, "id", ""))
    rule_url = _sigma_rule_url(clone_dir, rule_path)
    title = getattr(rule, "title", None) or "Untitled"
    return {
        "author": author,
        "rule_uuid": rule_uuid,
        "rule_url": rule_url,
        "rule_set_url": _SIGMA_REPO_URL,
        "license": _DRL_LICENSE,
        "license_url": _DRL_LICENSE_URL,
        "title": title,
        "attribution_text": (
            f"{author} | {rule_url} | Licensed under {_DRL_LICENSE}"
        ),
    }


def _convert_rule_cached(
    raw_yaml: str,
    cache: SigmaConversionCache,
    backend: Any,
) -> list[str] | None:
    """Convert a Sigma rule to SPL, memoizing the result in *cache*.

    On any pySigma failure (``SigmaError`` covers all 47 parse/conversion
    exceptions, Wave 1 agent-431) the rule is skipped (returns ``None``) so
    the caller can try the next candidate.

    Args:
        raw_yaml: The exact rule file text.
        cache: The conversion cache.
        backend: A constructed :class:`SplunkBackend` instance.

    Returns:
        The converted query strings, or ``None`` on failure.
    """
    from sigma.exceptions import SigmaError

    cached = cache.lookup(raw_yaml, _BACKEND_NAME, _PIPELINE_NAME)
    if cached is not None:
        return cached

    from sigma.rule import SigmaRule

    try:
        rule = SigmaRule.from_yaml(raw_yaml)
        queries = backend.convert_rule(rule)
    except (SigmaError, Exception) as err:
        logger.warning(
            "Sigma conversion failed for rule (%s): %s",
            getattr(err, "__class__", type(err)).__name__,
            err,
        )
        return None

    if not queries:
        return None

    cache.store(raw_yaml, _BACKEND_NAME, _PIPELINE_NAME, queries)
    return list(queries)


def _dispatch_sigma(
    technique_id: str,
    tactic: str,
    closable_by: tuple[str, ...],
    contributing_sources: list[str],
    enabled_sources: tuple[str, ...],
    sigma_index: SigmaIndex,
    cache: SigmaConversionCache,
    backend: Any,
    clone_dir: str | None,
) -> dict[str, Any] | None:
    """Try to emit a community-sourced query from the SigmaHQ index.

    Iterates candidate rules for *technique_id* (sorted paths from
    :class:`SigmaIndex`), scores each, and attempts pySigma conversion on the
    highest-scoring rule first.  Falls through to the next candidate on any
    conversion failure.  Returns ``None`` when no candidate converts.

    Args:
        technique_id: Technique id in DB form.
        tactic: Canonical tactic slug.
        closable_by: Alphabetically-sorted disabled source formats.
        contributing_sources: Sources contributing to this technique.
        enabled_sources: All enabled source formats.
        sigma_index: The SigmaHQ rule index.
        cache: The conversion cache.
        backend: A constructed :class:`SplunkBackend` instance.
        clone_dir: Root of the SigmaHQ clone (for permalinks).

    Returns:
        A normalized query dict, or ``None`` when no Sigma rule converts.
    """
    target = _resolve_source_format(
        closable_by, contributing_sources, enabled_sources
    )
    paths = sigma_index.get(technique_id)
    if not paths:
        return None

    # Parse + score every candidate, then try the best first.
    scored: list[tuple[float, str, Any]] = []
    from sigma.rule import SigmaRule

    for path in paths:
        try:
            text = open(path, "r", encoding="utf-8", errors="replace").read()
            rule = SigmaRule.from_yaml(text)
        except Exception as err:
            logger.debug("skip unparseable rule %s: %s", path, err)
            continue
        score = _score_rule(rule, target)
        scored.append((score, path, rule))

    # Sort: highest score first, then lowest FP count, then most recent
    # modified, then alphabetical title (Wave 1 agent-425 tie-breaks).
    scored.sort(
        key=lambda item: (
            -item[0],
            len(getattr(item[2], "falsepositives", None) or []),
            -(getattr(item[2], "modified", None) or getattr(item[2], "date", None) or ""),
            str(getattr(item[2], "title", "")),
        )
    )

    for score, path, rule in scored:
        try:
            raw = open(path, "r", encoding="utf-8", errors="replace").read()
        except OSError as err:
            logger.debug("skip unreadable rule %s: %s", path, err)
            continue
        queries = _convert_rule_cached(raw, cache, backend)
        if not queries:
            continue
        query = "\n".join(queries)
        if not is_inert(query):
            logger.warning(
                "Sigma rule %s produced a non-inert query; skipping", path
            )
            continue
        attribution = _build_attribution(rule, technique_id, clone_dir, path)
        return {
            "query": query,
            "query_language": "splunk",
            "attribution_label": "community-sourced",
            "source_rule_id": str(getattr(rule, "id", "")),
            "source_format": target,
            "tactic": tactic,
            "attribution": attribution,
        }

    return None


def _persist_query(
    session: Session,
    technique_attack_id: str,
    query: str,
    query_source: str,
    attribution: dict[str, Any],
    _created: set[str],
) -> None:
    """Upsert a generated query into ``technique_coverage``.

    Phase 5 owns the ``splunk_query`` / ``query_source`` / ``attribution_json``
    columns (``coverage_analyzer.py:64`` never touches them).  We match by
    ``technique_attack_id`` (the work-list invariant is one row per technique
    for the active datasource set).

    Args:
        session: Open SQLAlchemy session.
        technique_attack_id: Technique id in DB form.
        query: The inert SPL query string.
        query_source: One of ``sigmahq`` / ``curated`` / ``generic_template``.
        attribution: The attribution dict to store as JSON.
        _created: Technique ids for which we already created a new row in this
            batch (avoids creating duplicate empty-stix_id rows that would
            collide on the uq_cov_pair unique constraint).
    """
    # Match on technique_attack_id to find any existing row for this
    # technique.  Creating a brand-new row is a last resort so we never
    # collide on the uq_cov_pair unique constraint.  The SELECT runs inside a
    # no_autoflush block so the pending SimulationTechnique write does not
    # trigger a premature INSERT flush before we've resolved the existing row.
    with session.no_autoflush:
        rows = session.execute(
            select(TechniqueCoverage).where(
                TechniqueCoverage.technique_attack_id == technique_attack_id
            )
        ).scalars().all()
    row = rows[0] if rows else None
    if row is None:
        if technique_attack_id in _created:
            # Already created a row for this technique in this batch; skip the
            # duplicate write (the work-list invariant is about query *count*,
            # not coverage-row count).
            return
        # No coverage row exists for this technique -- create a minimal one so
        # the query is still persisted (the work-list invariant holds).  We
        # resolve the real stix_id from the techniques table so the
        # (technique_stix_id, datasource_id) unique constraint is satisfied.
        with session.no_autoflush:
            tech = session.execute(
                select(Technique.stix_id).where(
                    Technique.attack_id == technique_attack_id
                )
            ).scalar_one_or_none()
        row = TechniqueCoverage(
            technique_stix_id=tech or technique_attack_id,
            technique_attack_id=technique_attack_id,
            datasource_id=1,
        )
        session.add(row)
        _created.add(technique_attack_id)
    row.splunk_query = query
    row.query_source = query_source
    row.attribution_json = attribution


def export_all_queries(
    result_id: int,
    session: Session | None = None,
    config: Mapping[str, Any] | None = None,
    rules: list[Any] | None = None,
    sigma_rules_dir: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Emit one hunt query per missed technique in a simulation run.

    The public Phase-5 entry point.  Reads ``SimulationTechnique`` rows with
    ``status='missed'`` for *result_id* (ordered ``technique_attack_id ASC``),
    re-derives ``closable_by`` via :func:`calculate_coverage_gaps`, and
    dispatches one query per technique by fixed precedence:

    hand-curated (M001-M020) > SigmaHQ match (pySigma) > generic template.

    Every emitted query is persisted to ``technique_coverage`` and returned in
    an ordered dict keyed by ``technique_attack_id``.

    Args:
        result_id: The ``simulation_results.id`` to emit queries for.
        session: An open SQLAlchemy session.  When ``None``, one is opened
            from the default engine via :func:`session_scope`.
        config: The loaded config mapping.  When ``None``, loaded from
            ``config.yaml`` via :func:`load_config`.
        rules: The curated mapping rules.  When ``None``, loaded from
            ``data/attack_mappings.csv`` via :func:`load_mappings`.
        sigma_rules_dir: Root of a SigmaHQ clone.  When ``None`` (or the dir
            is absent), the SigmaHQ tier is skipped and every technique falls
            back to curated / generic.

    Returns:
        An OrderedDict keyed by ``technique_attack_id`` (ASC), each value::

            {
                "query": <inert SPL string>,
                "query_language": "splunk" | "generic",
                "attribution_label": "hand-curated" | "community-sourced"
                                     | "generic",
                "source_rule_id": <Sigma UUID / mapping_id / None>,
                "closable_by": <sorted tuple of disabled formats>,
                "confidence": <float, 6 dp>,
            }

        The dict has exactly ``SimulationResult.missed_count`` entries
        (work-list invariant).  Empty when the group has zero missed
        techniques.
    """
    # Resolve defaults.  When the caller supplies a session we reuse it;
    # otherwise we open one and own its lifecycle.
    owns_session = session is None
    if session is None:
        session_ctx = session_scope()
        session = session_ctx.__enter__()
    else:
        session_ctx = None

    try:
        if config is None:
            config = load_config(DEFAULT_CONFIG_PATH)
        if rules is None:
            rules = load_mappings(DEFAULT_MAPPINGS_PATH)

        enabled = _enabled_sources(config)

        # --- load missed techniques (work-list) ---
        missed_rows = (
            session.execute(
                select(SimulationTechnique)
                .where(
                    SimulationTechnique.result_id == result_id,
                    SimulationTechnique.status == "missed",
                )
                .order_by(SimulationTechnique.technique_attack_id.asc())
            )
            .scalars()
            .all()
        )

        # --- re-derive closable_by (Wave 1 agent-443: identical code path) ---
        coverage_rows = load_coverage_rows(session, config)
        gaps = calculate_coverage_gaps(coverage_rows, rules, config)
        closable = {
            g.technique_attack_id: g.closable_by for g in gaps
        }

        # --- invariant validation: closable_by must not contain enabled sources ---
        _validate_closable_by_invariant(gaps, enabled)

        # --- build the SigmaHQ index + conversion backend (lazy) ---
        sigma_index = SigmaIndex.from_clone(sigma_rules_dir) if sigma_rules_dir else SigmaIndex({})
        cache = SigmaConversionCache()
        backend = None  # constructed on first Sigma-path hit

        results: OrderedDict[str, dict[str, Any]] = OrderedDict()
        created_rows: set[str] = set()

        for row in missed_rows:
            tid = row.technique_attack_id
            tactic = row.tactic or ""
            closable_by = closable.get(tid, ())
            contributing = row.contributing_sources or []
            confidence = round(row.confidence, 6) if row.confidence else 0.0

            emitted: dict[str, Any] | None = None
            query_source = "generic_template"

            # Precedence 1: hand-curated core (M001-M020).
            curated = curated_spl(tid, tactic, closable_by)
            if curated is not None:
                emitted = curated
                query_source = "curated"

            # Precedence 2: SigmaHQ match (pySigma conversion).
            if emitted is None and len(sigma_index) > 0:
                if backend is None:
                    from sigma.backends.splunk import SplunkBackend
                    from sigma.pipelines.splunk import splunk_windows_pipeline

                    backend = SplunkBackend(
                        processing_pipeline=splunk_windows_pipeline()
                    )
                sigma_query = _dispatch_sigma(
                    tid,
                    tactic,
                    closable_by,
                    contributing,
                    enabled,
                    sigma_index,
                    cache,
                    backend,
                    sigma_rules_dir,
                )
                if sigma_query is not None:
                    emitted = sigma_query
                    query_source = "sigmahq"

            # Precedence 3: generic fallback.
            if emitted is None:
                target = _resolve_source_format(
                    closable_by, contributing, enabled
                )
                emitted = generic_template(tid, tactic, closable_by, target)
                query_source = "generic_template"

            # Persist to technique_coverage (Phase-5-owned columns).
            _persist_query(
                session,
                tid,
                emitted["query"],
                query_source,
                emitted.get("attribution", {}),
                created_rows,
            )

            results[tid] = {
                "query": emitted["query"],
                "query_language": emitted["query_language"],
                "attribution_label": emitted["attribution_label"],
                "source_rule_id": emitted.get("source_rule_id"),
                "closable_by": closable_by,
                "confidence": confidence,
            }

        # Commit the cache (conversions) and the session writes.
        cache.commit()
        session.commit()
        return results

    finally:
        if owns_session and session_ctx is not None:
            session_ctx.__exit__(None, None, None)
