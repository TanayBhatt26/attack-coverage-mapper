"""Phase 3 coverage engine: populate, per-tactic coverage, and gap analysis.

This module owns the analytical half of the coverage pipeline. It turns the
curated mapping rules (:mod:`parser.mappings_io`) plus the loaded ATT&CK
catalog (:mod:`database.models`) into three answers:

1. :func:`populate_technique_coverage` -- materialize one ``technique_coverage``
   row per ``(technique_stix_id, datasource_id)`` pair for every *enabled* log
   format, idempotently (safe against the surrogate-autoincrement PK +
   ``UNIQUE(technique_stix_id, datasource_id)`` layout that defeats
   ``session.merge()`` -- the Phase-1 AptGroup bug class).
2. :func:`coverage_by_tactic` -- aggregate per-(technique, tactic) rows into
   the 14 Enterprise tactic buckets, scoped to the configured platform.
3. :func:`calculate_coverage_gaps` -- list undetected in-scope techniques with
   an *honest* ``closable_by`` index of disabled log formats that would really
   lift each technique above the detection threshold.

Confidence model (static projection, DeTT&CT-informed tiers)
------------------------------------------------------------
Every mapping rule projects a fixed score independent of any event content::

    tier 1  rule declares extension keys          -> base_confidence * 1.00
    tier 2  action-pattern-only rule              -> base_confidence * 0.85
    tier 3  match_type == 'heuristic'             -> base_confidence * 0.40

capped at 0.95.  ``match_type == 'exists'`` ignores any declared value
pattern (key presence alone decides at runtime), which is irrelevant here:
the static projection never inspects pattern *content*, only rule *shape*
(``ext_keys`` presence, ``match_type``).  Inter-rule preemption (a strict
rule silencing heuristic rules for one event) is deliberately NOT modeled --
the projection is an optimistic per-datasource capability estimate.

A ``(technique, datasource)`` row stores the MAX projected score over that
datasource's rules for the technique.  Technique-level ``best_confidence``
is the MAX across enabled-datasource rows, and a technique counts as
detectable iff ``best_confidence >= threshold`` (inclusive; threshold comes
from ``config['detection_confidence_threshold']``, default 0.6).

Platform scope
--------------
A technique is in scope iff ``scope == 'all'`` OR the lowercased scope
(expanded through ``SCOPE_ALIASES`` - e.g. ``network`` -> Network Devices,
``cloud`` -> IaaS/SaaS/Office 365) intersects the technique's platform
values. Exact element-wise matching against the 12 canonical ATT&CK
platform strings; substring matching is deliberately NOT used (a naive
``office`` substring would wrongly unite 'Office Suite' + 'Office 365').

Idempotent populate algorithm (surrogate-PK safe)
-------------------------------------------------
``session.merge()`` cannot match an existing row when the PK is an
unsupplied autoincrement id, so populate never merges.  It instead:

1. seeds one :class:`~database.models.DataSourceType` row per canonical log
   format (enabled flag mirrored from ``enabled_log_sources``; a format
   absent from the mapping counts as enabled, mirroring the mapper's
   ``is False`` predicate);
2. computes the *desired* pair set from rules x enabled datasources x
   resolvable, non-revoked techniques;
3. loads existing pairs, UPDATEs in place where managed values differ,
   INSERTs missing pairs, DELETEs stale pairs (set difference).  Stale
   deletion covers revoked techniques, newly disabled sources and removed
   mapping rows.  Only ``detection_confidence``, ``is_detectable``,
   ``required_fields`` and ``sigma_rule_id`` are managed; the Phase-5 query
   columns (``splunk_query`` / ``eql_query``) are never touched.

Rules whose technique is revoked/deprecated in the DB or unresolvable are
skipped with a WARNING and surfaced in the returned
:class:`PopulateReport`; unknown source formats likewise.  The session is
mutated but *not committed* -- callers commit via
:func:`database.session.session_scope` as with the Phase-1 loader.

Hashability contract
--------------------
Every public return type is a frozen dataclass whose fields are only
``None | bool | int | float | str | tuple | nested-frozen-dataclass`` and
every collection is a ``tuple`` at every nesting depth -- never ``list``,
``dict`` or ``set`` -- so results are natively hashable and safe as Streamlit
``@st.cache_data`` return values.

Edge behaviour
--------------
The read path never raises on missing schema: with any of the three needed
tables absent, :func:`load_coverage_rows` logs a warning and returns ``()``.
An empty DB yields zero rows, which :func:`coverage_by_tactic` turns into
14 zeroed buckets and :func:`calculate_coverage_gaps` turns into ``()``.
With zero enabled sources every technique degrades to ``best_confidence``
0.0 -- fail-closed honesty: nothing collected means everything is a gap.
"""

import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from sqlalchemy import inspect, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from database.models import DataSourceType, Technique, TechniqueCoverage
from parser.mappings_io import VALID_SOURCE_FORMATS, MappingRule

logger = logging.getLogger(__name__)

__all__ = (
    "CANONICAL_TACTICS",
    "CoverageRow",
    "Gap",
    "PopulateReport",
    "TacticCoverage",
    "build_closable_index",
    "calculate_coverage_gaps",
    "coverage_by_tactic",
    "load_coverage_rows",
    "platform_in_scope",
    "populate_technique_coverage",
    "rule_tier_multiplier",
    "static_rule_score",
)

#: The 14 Enterprise tactics in canonical ATT&CK matrix order. Every
#: aggregation emits exactly these buckets, in this order, even at 0%.
CANONICAL_TACTICS: tuple[str, ...] = (
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

# Canonical order lookup (private; position of each tactic in the matrix).
_TACTIC_ORDER: dict[str, int] = {t: i for i, t in enumerate(CANONICAL_TACTICS)}

# Confidence multiplier applied per statically derived tier (mirrors the
# runtime tiers in parser.attack_mapper: ext_keys -> 1, action-only -> 0.85,
# heuristic -> 0.40).
_TIER_MULTIPLIER_EXT_KEYS = 1.0
_TIER_MULTIPLIER_ACTION_ONLY = 0.85
_TIER_MULTIPLIER_HEURISTIC = 0.40

# Upper bound for any confidence score (same cap as the runtime engine).
_MAX_CONFIDENCE = 0.95

# Decimal places kept on projected scores; strips binary-float dust from
# products such as 0.35 * 0.85 while staying far below meaningful precision.
_SCORE_DECIMALS = 6


@dataclass(frozen=True)
class TacticCoverage:
    """Detectability rollup for one Enterprise tactic bucket.

    Attributes:
        tactic: Canonical tactic slug (member of ``CANONICAL_TACTICS``).
        total: Number of in-scope, alive techniques assigned this tactic
            (multi-tactic techniques count once per tactic they carry).
        detectable: How many of ``total`` have ``best_confidence`` at or
            above the configured threshold.
        pct: ``detectable / total`` rounded to 4 decimals; 0.0 when
            ``total`` is 0 (never raises ZeroDivisionError).
    """

    tactic: str
    total: int
    detectable: int
    pct: float


@dataclass(frozen=True)
class CoverageRow:
    """One technique x tactic analysis row (multi-tactic split).

    Emitted by :func:`load_coverage_rows` for every alive (non-revoked)
    technique and every canonical tactic it carries -- including techniques
    with zero coverage rows (they surface as 0.0-confidence gaps).

    Attributes:
        technique_stix_id: Stable STIX id (the coverage-table join key).
        attack_id: Human ATT&CK id such as ``T1059.001``.
        name: Technique display name.
        tactic: Canonical tactic slug for this split row.
        scope_hit: Whether the technique matches the configured platform
            scope. Denominators and gaps only consider rows with True.
        best_confidence: MAX detection confidence across enabled-datasource
            rows; 0.0 when the technique has no enabled coverage rows.
        is_detectable: ``best_confidence >= threshold`` (inclusive).
        source_ids: Sorted ids of the enabled ``DataSourceType`` rows
            contributing coverage evidence (empty tuple when none).
        sigma_rule_id: Sigma rule id carried by the highest-scoring
            contributing row (tie broken by lowest datasource id);
            ``None`` when absent.
    """

    technique_stix_id: str
    attack_id: str
    name: str
    tactic: str
    scope_hit: bool
    best_confidence: float
    is_detectable: bool
    source_ids: tuple[int, ...]
    sigma_rule_id: str | None


@dataclass(frozen=True)
class Gap:
    """One undetected technique-tactic assignment (a coverage gap).

    Attributes:
        technique_attack_id: ATT&CK id such as ``T1190``.
        name: Technique display name.
        tactic: Canonical tactic slug of the missed assignment.
        best_confidence: Current technique-level best confidence (<
            threshold by construction).
        closable_by: Alphabetically sorted config keys of *disabled* log
            formats that hold a mapping rule for this technique whose
            statically projected score reaches the threshold. Empty tuple
            means "no acquisition path -- needs a new mapping", a distinct
            UI treatment from "toggle zeek and this closes".
    """

    technique_attack_id: str
    name: str
    tactic: str
    best_confidence: float
    closable_by: tuple[str, ...]


@dataclass(frozen=True)
class PopulateReport:
    """Audit counters emitted by :func:`populate_technique_coverage`.

    Attributes:
        rows_upserted: Total desired rows written, i.e.
            ``rows_inserted + rows_updated``.
        rows_inserted: Desired pairs absent from the table before the run.
        rows_updated: Existing pairs whose managed values differed and were
            corrected in place (PK-preserving; ids never churn).
        rows_deleted: Stale pairs removed (revoked technique, disabled
            source, or removed mapping row).
        skipped_revoked: Sorted unique technique attack-ids skipped because
            the DB marks them revoked (deprecated techniques are folded
            into this flag by the loader).
        skipped_orphan: Sorted unique technique attack-ids referenced by a
            rule but unresolvable in the techniques table.
        warnings: Number of warning events emitted (revoked skips + orphan
            skips + unknown-source-format rules).
    """

    rows_upserted: int
    rows_inserted: int
    rows_updated: int
    rows_deleted: int
    skipped_revoked: tuple[str, ...]
    skipped_orphan: tuple[str, ...]
    warnings: int


# --- configuration ----------------------------------------------------------


def _validated_settings(config: Mapping[str, object]) -> tuple[float, str]:
    """Validate the analyzer-facing config subset.

    Args:
        config: Application config mapping (as produced by
            :func:`config_loader.load_config`). Recognized keys:
            ``detection_confidence_threshold`` (number in [0, 1], default
            0.6) and ``platform_scope`` (non-empty string, default "all").
            Unknown keys are ignored.

    Returns:
        Tuple ``(threshold, platform_scope)``.

    Raises:
        ValueError: If ``config`` is not a Mapping, or either recognized
            key has a wrong type / out-of-range value.
    """
    if not isinstance(config, Mapping):
        raise ValueError(
            f"config must be a mapping, got {type(config).__name__}"
        )
    threshold_raw = config.get("detection_confidence_threshold", 0.6)
    if isinstance(threshold_raw, bool) or not isinstance(threshold_raw, (int, float)):
        raise ValueError(
            "config 'detection_confidence_threshold' must be a number, "
            f"got {threshold_raw!r}"
        )
    threshold = float(threshold_raw)
    if not 0.0 <= threshold <= 1.0:
        raise ValueError(
            "config 'detection_confidence_threshold' must be within "
            f"[0.0, 1.0], got {threshold}"
        )
    scope_raw = config.get("platform_scope", "all")
    if not isinstance(scope_raw, str) or not scope_raw.strip():
        raise ValueError(
            f"config 'platform_scope' must be a non-empty string, got {scope_raw!r}"
        )
    scope = scope_raw.strip()
    if scope.lower() not in KNOWN_SCOPES:
        raise ValueError(
            "config 'platform_scope' must be one of "
            f"{sorted(KNOWN_SCOPES)}, got {scope_raw!r}"
        )
    return threshold, scope


# Friendly scope aliases -> sets of canonical ATT&CK platform values
# (lowercased). Canonical values measured from the live bundle:
# Windows, macOS, Linux, ESXi, IaaS, Network Devices, PRE, Office Suite,
# SaaS, Identity Provider, Containers, Office 365.
SCOPE_ALIASES: dict[str, frozenset[str]] = {
    "windows": frozenset({"windows"}),
    "linux": frozenset({"linux"}),
    "macos": frozenset({"macos"}),
    "esxi": frozenset({"esxi"}),
    "iaas": frozenset({"iaas"}),
    "saas": frozenset({"saas"}),
    "pre": frozenset({"pre"}),
    "containers": frozenset({"containers"}),
    "identity provider": frozenset({"identity provider"}),
    "office suite": frozenset({"office suite"}),
    "office 365": frozenset({"office 365"}),
    "network devices": frozenset({"network devices"}),
    "network": frozenset({"network devices"}),
    "cloud": frozenset({"iaas", "saas", "office 365"}),
}
KNOWN_SCOPES = frozenset({"all"}) | set(SCOPE_ALIASES)


# --- platform scope ---------------------------------------------------------


def platform_in_scope(platforms: Iterable[object], platform_scope: str) -> bool:
    """Return whether a technique's platform list satisfies the scope rule.

    Rule (contract B): in scope iff ``platform_scope == 'all'`` OR
    ``platform_scope.lower()`` equals one of the lowercased platform
    values -- exact element-wise equality, case-insensitive, ANY-semantics
    across the list. Non-string platform entries are ignored.

    Args:
        platforms: The technique's platform values (e.g. ``["Windows"]``).
        platform_scope: Configured scope string ("all", "windows", ...).

    Returns:
        True when the technique is in scope.
    """
    if platform_scope == "all":
        return True
    lowered = {p.lower() for p in platforms if isinstance(p, str)}
    wanted = SCOPE_ALIASES.get(platform_scope.lower(), {platform_scope.lower()})
    return bool(lowered & wanted)


# --- static confidence projection -------------------------------------------


def rule_tier_multiplier(rule: MappingRule) -> float:
    """Derive the static confidence multiplier for a mapping rule.

    Tier precedence: ``heuristic`` match_type wins (0.40), then extension-key
    declaration (1.00), then action-pattern-only rules (0.85). A degenerate
    rule with neither extension keys nor an action pattern falls into the
    action-only bucket. Pattern *content* is never evaluated -- this is a
    shape-derived capability estimate, not a match.

    Args:
        rule: The mapping rule to project.

    Returns:
        One of 1.0, 0.85, 0.40.
    """
    if rule.match_type == "heuristic":
        return _TIER_MULTIPLIER_HEURISTIC
    if rule.ext_keys:
        return _TIER_MULTIPLIER_EXT_KEYS
    return _TIER_MULTIPLIER_ACTION_ONLY


def static_rule_score(rule: MappingRule) -> float:
    """Project a mapping rule's standalone confidence score.

    ``min(base_confidence * tier_multiplier, 0.95)``, rounded to 6 decimals
    to strip binary-float dust (e.g. ``0.35 * 0.85``) while keeping exact
    agreement with the golden expectations (all two-to-four decimal values).
    For ``match_type == 'exists'`` any declared value pattern is ignored by
    construction: only rule shape feeds the projection.

    Args:
        rule: The mapping rule to score.

    Returns:
        The projected confidence in ``[0.0, 0.95]``.
    """
    score = rule.base_confidence * rule_tier_multiplier(rule)
    return round(min(score, _MAX_CONFIDENCE), _SCORE_DECIMALS)


# --- populate ----------------------------------------------------------------


class _PairDraft:
    """Accumulator for one desired ``(technique_stix_id, datasource_id)`` pair.

    Internal mutable builder (never returned publicly): folds every
    contributing rule into the final row payload -- max projected score,
    union of required extension-key fields, and the winning rule's Sigma id
    (highest score; ties broken by lowest ``mapping_id``).
    """

    __slots__ = ("confidence", "required_fields", "winner_mapping_id", "sigma_rule_id")

    def __init__(self) -> None:
        self.confidence: float = -1.0
        self.required_fields: set[str] = set()
        self.winner_mapping_id: str | None = None
        self.sigma_rule_id: str | None = None

    def absorb(self, rule: MappingRule, score: float) -> None:
        """Fold one rule into the pair payload."""
        self.required_fields.update(rule.ext_keys)
        takes_lead = (
            score > self.confidence
            or (
                score == self.confidence
                and self.winner_mapping_id is not None
                and rule.mapping_id < self.winner_mapping_id
            )
        )
        if takes_lead:
            self.confidence = score
            self.winner_mapping_id = rule.mapping_id
            self.sigma_rule_id = rule.sigma_rule_id

    def finalized(self, threshold: float) -> tuple[float, bool, list[str], str | None]:
        """Return the ``(confidence, is_detectable, required_fields, sigma)`` payload."""
        confidence = max(self.confidence, 0.0)
        return (
            confidence,
            confidence >= threshold,
            sorted(self.required_fields),
            self.sigma_rule_id,
        )


def _ensure_write_schema(session: Session) -> None:
    """Raise unless the tables populate writes to exist.

    Raises:
        RuntimeError: If ``techniques`` or ``datasource_types`` is absent
            from the bound database (caller forgot ``create_all``/initdb).
    """
    inspector = inspect(session.connection())
    missing = [
        name
        for name in ("techniques", "datasource_types")
        if not inspector.has_table(name)
    ]
    if missing:
        raise RuntimeError(
            f"cannot populate technique_coverage: table(s) {missing} missing; "
            "run the Phase-1 loader (Base.metadata.create_all) first"
        )


def _seed_datasource_types(session: Session, config: Mapping[str, object]) -> dict[str, int]:
    """Ensure one ``DataSourceType`` row per canonical log format.

    Enabled flags mirror ``config['enabled_log_sources']`` with the mapper's
    semantics: a format counts as disabled only when its value is exactly
    ``False``; absent formats are enabled. Missing rows are INSERTed,
    drifted ``enabled`` flags are UPDATEd in place; pre-existing rows with
    non-canonical names are left untouched.

    Args:
        session: Open SQLAlchemy session (flushed, not committed).
        config: Application config mapping.

    Returns:
        Mapping of canonical log format name to the row's primary key.
    """
    sources_cfg = config.get("enabled_log_sources")
    if sources_cfg is None:
        sources_cfg = {}
    if not isinstance(sources_cfg, Mapping):
        raise ValueError(
            "config 'enabled_log_sources' must be a mapping of format name "
            f"to bool, got {type(sources_cfg).__name__}"
        )

    existing: dict[str, DataSourceType] = {
        ds.name: ds for ds in session.scalars(select(DataSourceType)).all()
    }
    for fmt in sorted(VALID_SOURCE_FORMATS):
        enabled_flag = sources_cfg.get(fmt) is not False
        row = existing.get(fmt)
        if row is None:
            row = DataSourceType(name=fmt, log_format=fmt, priority=0, enabled=enabled_flag)
            session.add(row)
            existing[fmt] = row
            logger.debug("seeded datasource_type %r (enabled=%s)", fmt, enabled_flag)
        elif row.enabled != enabled_flag:
            row.enabled = enabled_flag
            logger.debug("datasource_type %r enabled flag updated to %s", fmt, enabled_flag)
    session.flush()
    return {name: row.id for name, row in existing.items()}


def _technique_index(session: Session) -> dict[str, list[tuple[bool, str, str]]]:
    """Load the technique catalog indexed by attack_id.

    Returns:
        Mapping ``attack_id -> [(alive, stix_id, attack_id), ...]`` where the
        list is sorted alive-first then by stix_id so resolution is
        deterministic even if legacy data ever carries duplicate ids.
    """
    index: dict[str, list[tuple[bool, str, str]]] = {}
    for attack_id, stix_id, revoked in session.execute(
        select(Technique.attack_id, Technique.stix_id, Technique.revoked)
    ).all():
        index.setdefault(attack_id, []).append((not revoked, stix_id, attack_id))
    for candidates in index.values():
        candidates.sort(key=lambda item: (not item[0], item[1]))
    return index


def populate_technique_coverage(
    session: Session,
    rules: Sequence[MappingRule],
    config: Mapping[str, object],
) -> PopulateReport:
    """Materialize ``technique_coverage`` idempotently (surrogate-PK safe).

    Algorithm (contract C):

    1. Seed ``DataSourceType`` rows for the 8 canonical log formats with
       enabled flags mirrored from the config (see
       :func:`_seed_datasource_types`).
    2. Compute the desired pair set: mapping rules x *enabled* datasources x
       resolvable, non-revoked techniques. Each pair stores the MAX
       statically projected score over that datasource's rules for the
       technique, ``is_detectable`` against the config threshold
       (inclusive), the union of contributing rules' extension keys as
       ``required_fields``, and the winning rule's ``sigma_rule_id``.
    3. Diff against existing rows: UPDATE in place where managed values
       differ, INSERT missing, DELETE stale (set difference). Managed
       columns are ``detection_confidence``, ``is_detectable``,
       ``required_fields``, ``sigma_rule_id``; the Phase-5 query columns are
       never modified. ``session.merge()`` is never used (autoincrement PK +
       unique pair constraint make merge unable to match existing rows).

    Skips (each logged as a WARNING and reflected in the report): rules
    whose technique is revoked/deprecated in the DB, rules whose technique
    is unresolvable, and rules with an unknown source format. Rules for
    *disabled* formats are excluded silently (expected behaviour).

    The session is flushed but not committed; commit via
    :func:`database.session.session_scope`.

    Args:
        session: Open SQLAlchemy session bound to a database containing the
            Phase-1 schema.
        rules: Validated mapping rules (typically from
            :func:`parser.mappings_io.load_mappings`).
        config: Application config mapping (threshold and
            ``enabled_log_sources`` are consumed).

    Returns:
        A frozen :class:`PopulateReport` audit record.

    Raises:
        RuntimeError: If the target schema is missing.
        ValueError: If the config subset is invalid.
    """
    threshold, _scope = _validated_settings(config)
    rules_seq = tuple(rules)
    logger.info(
        "populate start: %d rules, thr %.2f", len(rules_seq), threshold
    )
    _ensure_write_schema(session)

    format_ids = _seed_datasource_types(session, config)
    sources_cfg = config.get("enabled_log_sources") or {}
    index = _technique_index(session)

    desired: dict[tuple[str, int], _PairDraft] = {}
    skipped_revoked: set[str] = set()
    skipped_orphan: set[str] = set()
    unknown_format_warnings = 0

    for rule in rules_seq:
        fmt = rule.source_format
        if fmt not in VALID_SOURCE_FORMATS:
            unknown_format_warnings += 1
            logger.warning(
                "rule %s unknown source format %r — skipped", rule.mapping_id, fmt
            )
            continue
        if isinstance(sources_cfg, Mapping) and sources_cfg.get(fmt) is False:
            logger.debug(
                "rule %s belongs to disabled format %r — excluded", rule.mapping_id, fmt
            )
            continue
        candidates = index.get(rule.technique_id)
        if not candidates:
            skipped_orphan.add(rule.technique_id)
            logger.warning(
                "rule %s references unknown technique %s — skipped",
                rule.mapping_id,
                rule.technique_id,
            )
            continue
        _alive, stix_id, attack_id = candidates[0]
        if not _alive:
            # Revoked/deprecated in the DB (deprecated techniques share the
            # revoked column per the loader contract).
            skipped_revoked.add(attack_id)
            logger.warning(
                "rule %s targets revoked technique %s — skipped",
                rule.mapping_id,
                attack_id,
            )
            continue
        key = (stix_id, format_ids[fmt])
        draft = desired.get(key)
        if draft is None:
            draft = _PairDraft()
            desired[key] = draft
        draft.absorb(rule, static_rule_score(rule))

    existing: dict[tuple[str, int], TechniqueCoverage] = {
        (row.technique_stix_id, row.datasource_id): row
        for row in session.scalars(select(TechniqueCoverage)).all()
    }

    attack_id_by_stix = {
        stix_id: attack_id
        for candidates in index.values()
        for _alive, stix_id, attack_id in candidates
    }

    inserted = updated = deleted = 0
    for key in sorted(desired):
        draft = desired[key]
        confidence, is_detectable, required_fields, sigma_rule_id = draft.finalized(
            threshold
        )
        row = existing.pop(key, None)
        if row is None:
            session.add(
                TechniqueCoverage(
                    technique_stix_id=key[0],
                    technique_attack_id=attack_id_by_stix[key[0]],
                    datasource_id=key[1],
                    is_detectable=is_detectable,
                    detection_confidence=confidence,
                    required_fields=required_fields,
                    sigma_rule_id=sigma_rule_id,
                )
            )
            inserted += 1
            continue
        changed = False
        if row.detection_confidence != confidence:
            row.detection_confidence = confidence
            changed = True
        if bool(row.is_detectable) != is_detectable:
            row.is_detectable = is_detectable
            changed = True
        stored_fields = sorted(str(f) for f in (row.required_fields or []))
        if stored_fields != required_fields:
            row.required_fields = required_fields
            changed = True
        if row.sigma_rule_id != sigma_rule_id:
            row.sigma_rule_id = sigma_rule_id
            changed = True
        if changed:
            updated += 1

    for stale_row in existing.values():
        session.delete(stale_row)
        deleted += 1
    session.flush()

    report = PopulateReport(
        rows_upserted=inserted + updated,
        rows_inserted=inserted,
        rows_updated=updated,
        rows_deleted=deleted,
        skipped_revoked=tuple(sorted(skipped_revoked)),
        skipped_orphan=tuple(sorted(skipped_orphan)),
        warnings=(
            len(skipped_revoked) + len(skipped_orphan) + unknown_format_warnings
        ),
    )
    logger.info(
        "populate complete: %d rows (%d inserted, %d updated, %d deleted), "
        "%d warnings",
        report.rows_upserted,
        report.rows_inserted,
        report.rows_updated,
        report.rows_deleted,
        report.warnings,
    )
    return report


# --- coverage reads ----------------------------------------------------------


def _has_read_schema(session: Session) -> bool:
    """Return True when all tables the read path needs exist.

    Inspects the session's own connection (not the engine) so the check
    cannot open extra connections -- mandatory for ``sqlite:///:memory:``,
    where every fresh connection is a separate empty database.
    """
    inspector = inspect(session.connection())
    return all(
        inspector.has_table(name)
        for name in ("techniques", "technique_coverage", "datasource_types")
    )


def load_coverage_rows(
    session: Session,
    config: Mapping[str, object],
) -> tuple[CoverageRow, ...]:
    """Read the DB and build per-(technique, tactic) analysis rows.

    Joins alive (``revoked`` false) techniques with enabled-datasource
    coverage rows, computes technique-level ``best_confidence`` (MAX across
    enabled rows; 0.0 without any), inclusive-threshold detectability and
    platform scope, then emits ONE row per (technique, canonical tactic)
    assignment -- multi-tactic techniques split, techniques carrying no
    canonical tactic contribute nothing (counted in a debug log).

    Never raises on pipeline state: a missing table or a failing query
    logs a warning and yields ``()`` (an empty/unpopulated DB is pipeline
    state, not a coverage fact).

    Args:
        session: Open SQLAlchemy session.
        config: Application config mapping (threshold and platform_scope
            consumed; rows must later be reduced with the same config).

    Returns:
        Frozen rows sorted by ``(attack_id, canonical tactic order)``.

    Raises:
        ValueError: If the config subset is invalid.
    """
    threshold, scope = _validated_settings(config)
    if not _has_read_schema(session):
        logger.warning(
            "coverage read: schema incomplete (missing tables); returning no rows"
        )
        return ()

    try:
        tech_rows = session.execute(
            select(
                Technique.stix_id,
                Technique.attack_id,
                Technique.name,
                Technique.tactics,
                Technique.platforms,
            ).where(Technique.revoked.is_(False))
        ).all()
        cov_rows = session.execute(
            select(
                TechniqueCoverage.technique_stix_id,
                TechniqueCoverage.detection_confidence,
                TechniqueCoverage.datasource_id,
                TechniqueCoverage.sigma_rule_id,
                DataSourceType.log_format,
            )
            .join(DataSourceType, TechniqueCoverage.datasource_id == DataSourceType.id)
        ).all()
    except OperationalError as err:
        logger.warning("coverage read failed (%s); returning no rows", err)
        return ()

    # Config is the single source of truth for enablement at READ time; the
    # DB ``enabled`` mirror is only a seed-time default. Formats explicitly
    # disabled in config are excluded even if their DB row says enabled;
    # formats absent from the config map count as enabled (populate parity).
    src_map = (config or {}).get("enabled_log_sources")
    disabled_formats = (
        {str(k).lower() for k, v in src_map.items() if not bool(v)}
        if isinstance(src_map, Mapping) and src_map
        else set()
    )

    best_confidence: dict[str, float] = {}
    source_ids: dict[str, set[int]] = {}
    sigma_winner: dict[str, tuple[float, int, str | None]] = {}
    for stix_id, confidence, datasource_id, sigma_rule_id, log_format in cov_rows:
        if str(log_format or "").lower() in disabled_formats:
            continue
        confidence = float(confidence or 0.0)
        if confidence > best_confidence.get(stix_id, 0.0):
            best_confidence[stix_id] = confidence
        source_ids.setdefault(stix_id, set()).add(datasource_id)
        current = sigma_winner.get(stix_id)
        if current is None or (-confidence, datasource_id) < (-current[0], current[1]):
            sigma_winner[stix_id] = (confidence, datasource_id, sigma_rule_id)

    rows: list[CoverageRow] = []
    no_canonic_tactic = 0
    dropped_assignments = 0
    for tech in sorted(tech_rows, key=lambda r: (r.attack_id, r.stix_id)):
        tactics = [t for t in (tech.tactics or []) if isinstance(t, str)]
        canonical = [t for t in CANONICAL_TACTICS if t in tactics]
        dropped_assignments += len(tactics) - len(canonical)
        if not canonical:
            no_canonic_tactic += 1
            continue
        scope_hit = platform_in_scope(tech.platforms or [], scope)
        best = best_confidence.get(tech.stix_id, 0.0)
        detectable = best >= threshold
        ids_tuple = tuple(sorted(source_ids.get(tech.stix_id, ())))
        sigma = sigma_winner.get(tech.stix_id)
        sigma_rule_id = sigma[2] if sigma is not None else None
        for tactic in canonical:
            rows.append(
                CoverageRow(
                    technique_stix_id=tech.stix_id,
                    attack_id=tech.attack_id,
                    name=tech.name,
                    tactic=tactic,
                    scope_hit=scope_hit,
                    best_confidence=best,
                    is_detectable=detectable,
                    source_ids=ids_tuple,
                    sigma_rule_id=sigma_rule_id,
                )
            )
    if no_canonic_tactic or dropped_assignments:
        logger.info(
            "coverage read: %d alive technique(s) carry no canonical tactic and "
            "%d non-canonical tactic assignment(s) dropped",
            no_canonic_tactic,
            dropped_assignments,
        )
    return tuple(rows)


def coverage_by_tactic(rows: Sequence[CoverageRow]) -> tuple[TacticCoverage, ...]:
    """Aggregate coverage rows into the 14 canonical tactic buckets.

    Denominator per tactic: rows with ``scope_hit`` true (in-scope, alive
    techniques assigned that tactic; multi-tactic techniques count once per
    tactic). Numerator: those additionally ``is_detectable``. All 14
    Enterprise tactics are emitted even at 0%, in canonical ATT&CK order;
    unknown tactic slugs (impossible from :func:`load_coverage_rows`) are
    skipped with a debug log.

    Args:
        rows: Rows as produced by :func:`load_coverage_rows`.

    Returns:
        Exactly 14 :class:`TacticCoverage` entries in canonical order.
    """
    totals = dict.fromkeys(CANONICAL_TACTICS, 0)
    detectables = dict.fromkeys(CANONICAL_TACTICS, 0)
    for row in rows:
        position = _TACTIC_ORDER.get(row.tactic)
        if position is None:
            logger.debug("coverage rollup: ignoring unknown tactic %r", row.tactic)
            continue
        if not row.scope_hit:
            continue
        totals[row.tactic] += 1
        if row.is_detectable:
            detectables[row.tactic] += 1
    return tuple(
        TacticCoverage(
            tactic=tactic,
            total=totals[tactic],
            detectable=detectables[tactic],
            pct=(
                round(detectables[tactic] / totals[tactic], 4)
                if totals[tactic]
                else 0.0
            ),
        )
        for tactic in CANONICAL_TACTICS
    )


def build_closable_index(
    rules: Sequence[MappingRule],
    config: Mapping[str, object],
) -> dict[str, tuple[str, ...]]:
    """Index which disabled log formats could honestly close each technique.

    For every *disabled* config format (value exactly ``False``; absent
    keys count as enabled, mirroring the mapper), track the maximum
    statically projected score of its rules per technique; keep the format
    only when that best score reaches the threshold inclusively. This is
    the honest filter: naive any-mapping logic falsely promises e.g. cef
    closing T1046/T1136 whose cef projections sit far below 0.6, while
    T1190 correctly resolves to ``('nginx',)``.

    Intermediate helper: returns a plain dict (NOT part of the frozen
    return-type contract; do not feed it back into cached functions).

    Args:
        rules: Validated mapping rules.
        config: Application config mapping (``enabled_log_sources`` and
            threshold consumed).

    Returns:
        Mapping ``technique_attack_id -> sorted tuple of closable formats``.
        Techniques with no qualifying format are absent.

    Raises:
        ValueError: If the config subset is invalid.
    """
    threshold, _scope = _validated_settings(config)
    sources_cfg = config.get("enabled_log_sources")
    if sources_cfg is None:
        sources_cfg = {}
    if not isinstance(sources_cfg, Mapping):
        raise ValueError(
            "config 'enabled_log_sources' must be a mapping of format name "
            f"to bool, got {type(sources_cfg).__name__}"
        )
    disabled = {
        fmt
        for fmt, enabled in sources_cfg.items()
        if enabled is False and fmt in VALID_SOURCE_FORMATS
    }
    best_scores: dict[str, dict[str, float]] = {}
    for rule in rules:
        if rule.source_format not in disabled:
            continue
        score = static_rule_score(rule)
        per_format = best_scores.setdefault(rule.technique_id, {})
        if score > per_format.get(rule.source_format, -1.0):
            per_format[rule.source_format] = score
    index: dict[str, tuple[str, ...]] = {}
    for technique_id, per_format in best_scores.items():
        closable = tuple(
            sorted(f for f, s in per_format.items() if s >= threshold)
        )
        if closable:
            index[technique_id] = closable
    return index


def _mapping_sources_for(
    technique_id: str,
    source_subset: frozenset[str],
    all_rules_by_source: dict[str, list],
) -> tuple[str, ...]:
    """Sources in *source_subset* that have an applicable mapping for *technique_id*.

    Uses the same eligibility criteria as the mapper: platform scope match,
    positive tier multiplier, and rule exists for the technique.

    Args:
        technique_id: ATT&CK technique ID (e.g. ``T1059.001``).
        source_subset: Sources to check (enabled sources or all sources).
        all_rules_by_source: Mapping rules keyed by source format.

    Returns:
        Sorted tuple of source format names that have at least one
        eligible mapping rule for the technique.
    """
    applicable = []
    for src in source_subset:
        rules = all_rules_by_source.get(src, [])
        for rule in rules:
            if rule.technique_id == technique_id:
                if rule_tier_multiplier(rule) > 0:
                    applicable.append(src)
                    break
    return tuple(sorted(set(applicable)))


def calculate_coverage_gaps(
    rows: Sequence[CoverageRow],
    rules: Sequence[MappingRule],
    config: Mapping[str, object],
) -> tuple[Gap, ...]:
    """List coverage gaps with an honest ``closable_by`` attribution.

    A gap is one CoverageRow with ``scope_hit`` true and ``is_detectable``
    false (i.e. best confidence strictly below the threshold). Multi-tactic
    techniques yield one gap per missed tactic assignment. Gaps sort by
    canonical tactic order, then ``best_confidence`` ascending (near-misses
    surface first within each tactic group), then attack id ascending for a
    byte-stable total order.

    ``closable_by`` comes from :func:`build_closable_index`: only disabled
    formats holding a rule for the technique whose static projection
    reaches the threshold qualify. Pass the same config used to load
    ``rows`` so threshold semantics agree.

    Args:
        rows: Rows as produced by :func:`load_coverage_rows`.
        rules: Validated mapping rules.
        config: Application config mapping.

    Returns:
        Frozen :class:`Gap` tuple in the deterministic sort order above.

    Raises:
        ValueError: If the config subset is invalid.
    """
    _threshold = _validated_settings(config)[0]  # validates; index revalidates
    closable = build_closable_index(rules, config)
    gaps = [
        Gap(
            technique_attack_id=row.attack_id,
            name=row.name,
            tactic=row.tactic,
            best_confidence=row.best_confidence,
            closable_by=closable.get(row.attack_id, ()),
        )
        for row in rows
        if row.scope_hit and not row.is_detectable and row.tactic in _TACTIC_ORDER
    ]
    gaps.sort(
        key=lambda gap: (
            _TACTIC_ORDER[gap.tactic],
            gap.best_confidence,
            gap.technique_attack_id,
        )
    )
    logger.info(
        "gap analysis: %d gap(s) across %d tactic bucket(s)",
        len(gaps),
        len({gap.tactic for gap in gaps}),
    )
    return tuple(gaps)
