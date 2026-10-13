"""Tests for Phase-3 coverage population and the analysis engine.

Scope of this module (Wave-2 deliverable ``test_coverage_populate.py``):

* **Populate idempotency** on the surrogate-PK ``technique_coverage`` table
  (contract C): desired-pair diffing with PK-preserving UPDATE / INSERT /
  DELETE-stale, revoked+orphan+unknown-format skip paths, and the
  ``PopulateReport`` frozen-dataclass shape.
* **Coverage semantics** (contract D): static tier projection
  (``ext_keys -> x1.0``, action-only ``-> x0.85``, heuristic ``-> x0.40``,
  capped at ``0.95``), per-(technique, datasource) MAX aggregation,
  inclusive detectability threshold, platform-scope element-wise matching
  (contract B), all-14-tactic canonical emission and denominators that
  count every in-scope alive technique per tactic.
* **Gap semantics** (contract E): canonical-tactic-then-confidence ordering
  and the *honest* ``closable_by`` filter -- a disabled format only counts
  when its statically projected score would actually clear the threshold
  (the measured T1190/nginx lesson).
* **Hashability contract** (contract A): every analyzer return value is a
  frozen dataclass whose fields are only ``None|bool|int|float|str|tuple``
  or nested frozen dataclasses; collections are tuples at every depth.
* **Golden smoke** (contract I): a guarded run against a *copy* of the real
  ``db/coverage.db`` asserting Wave-1 CORE-ROW findings (execution tactic
  with T1059.001/T1059.003/T1047/T1569.002 detectable; M016's revoked
  target T1562.008 landing on the ``skipped_revoked`` path; T1190's
  ``('nginx',)`` closable beacon).

Synthetic tests build their own tiny databases (in-memory SQLite via
``StaticPool``) and construct :class:`~parser.mappings_io.MappingRule`
objects programmatically -- including deliberately invalid ones (unknown
source format) that the strict CSV loader would reject, so the populate
skip paths are reachable. Nothing touches shared repo state; the single
real-database smoke test operates on a ``tmp_path`` copy. All offline.

Expected values are computed here from an *independent* re-implementation
of the static projection (:func:`project_rule_confidence`), never by
calling the analyzer under test -- the tests are oracles, not mirrors.
"""

from __future__ import annotations

import copy
import dataclasses
import logging
import re
import shutil
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from analysis.coverage_analyzer import (
    Gap,
    PopulateReport,
    TacticCoverage,
    calculate_coverage_gaps,
    coverage_by_tactic,
    load_coverage_rows,
    platform_in_scope,
    populate_technique_coverage,
)
from config_loader import DEFAULT_CONFIG
from database.models import Base, DataSourceType, Technique, TechniqueCoverage
from parser.mappings_io import MappingRule

logger = logging.getLogger(__name__)

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_MAPPINGS_CSV = REPO_ROOT / "data" / "attack_mappings.csv"
REAL_COVERAGE_DB = REPO_ROOT / "db" / "coverage.db"

#: Canonical ATT&CK Enterprise tactic order (contract D) -- coverage_by_tactic
#: must emit exactly these, in exactly this order, even at zero percent.
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

#: Static tier multipliers (contract D; mirrors parser.attack_mapper).
TIER_MULT_EXT_KEYS = 1.0
TIER_MULT_ACTION_ONLY = 0.85
TIER_MULT_HEURISTIC = 0.40
CONFIDENCE_CAP = 0.95


# ---------------------------------------------------------------------------
# Independent oracle + factories.
# ---------------------------------------------------------------------------

def project_rule_confidence(
    *,
    base_confidence: float,
    ext_keys: Iterable[str] = (),
    event_action_pattern: str | None = None,
    match_type: str = "regex",
) -> float:
    """Statically project one mapping rule's confidence (contract D).

    Tier derivation is purely structural, mirroring the documented engine
    behaviour: a heuristic rule always rides tier 3; otherwise declared
    extension keys mean tier 1 and an action-only rule means tier 2. For
    ``match_type == 'exists'`` any value pattern is documentation only
    (the CSV loader drops it), so it never influences the projection.
    """
    if match_type == "heuristic":
        multiplier = TIER_MULT_HEURISTIC
    elif tuple(ext_keys):
        multiplier = TIER_MULT_EXT_KEYS
    elif event_action_pattern:
        multiplier = TIER_MULT_ACTION_ONLY
    else:
        # Neither keys nor an action constraint: can never fire at event time.
        return 0.0
    return min(round(base_confidence * multiplier, 10), CONFIDENCE_CAP)


_rule_counter = iter(range(1, 10_000))
_stix_counter = iter(range(1, 10_000))


def make_rule(
    technique_id: str,
    *,
    source_format: str = "evtx",
    base_confidence: float = 0.7,
    event_action_pattern: str | None = None,
    ext_keys: Sequence[str] = (),
    match_type: str = "regex",
    tactic: str = "execution",
    sigma_rule_id: str | None = None,
    mapping_id: str | None = None,
) -> MappingRule:
    """Build one synthetic :class:`MappingRule` with validated-shape defaults."""
    return MappingRule(
        mapping_id=mapping_id or f"SYN-{next(_rule_counter):04d}",
        source_format=source_format,
        event_action_re=(
            re.compile(event_action_pattern) if event_action_pattern else None
        ),
        ext_keys=tuple(key.lower() for key in ext_keys),
        ext_value_re=None,
        match_type=match_type,
        is_core=True,
        technique_id=technique_id,
        tactic=tactic,
        base_confidence=float(base_confidence),
        visibility_hint=3,
        evidence_ref=f"https://attack.mitre.org/techniques/{technique_id}/",
        sigma_rule_id=sigma_rule_id,
        notes="synthetic wave-2 fixture rule",
    )


def add_technique(
    session: Session,
    attack_id: str,
    *,
    name: str | None = None,
    tactics: Sequence[str] = ("execution",),
    platforms: Sequence[str] = ("Windows",),
    revoked: bool = False,
) -> Technique:
    """Insert one alive-or-revoked technique; returns the ORM instance.

    Note (contract G): the loader folds ``x_mitre_deprecated`` into the same
    boolean ``revoked`` column, so ``revoked=True`` models both revoked and
    deprecated techniques for populate-skip purposes.
    """
    technique = Technique(
        stix_id=f"attack-pattern--synthetic-{next(_stix_counter):05d}",
        attack_id=attack_id,
        name=name or f"Synthetic technique {attack_id}",
        description="Synthetic technique used by test_coverage_populate.",
        tactics=list(tactics),
        platforms=list(platforms),
        detection_strategy_refs=[],
        is_subtechnique="." in attack_id,
        parent_attack_id=attack_id.split(".")[0] if "." in attack_id else None,
        revoked=revoked,
    )
    session.add(technique)
    return technique


def make_cfg(
    *,
    platform_scope: str = "windows",
    threshold: float = 0.6,
    enabled_log_sources: Mapping[str, bool] | None = None,
) -> dict[str, object]:
    """A normalized cfg dict shaped like :func:`config_loader.load_config` output."""
    sources: dict[str, bool] = {
        fmt: True
        for fmt in (
            "evtx", "syslog", "cef", "leef", "json", "aws_cloudtrail", "nginx", "zeek",
        )
    }
    if enabled_log_sources is not None:
        sources.update(enabled_log_sources)
    return {
        "platform_scope": platform_scope,
        "detection_confidence_threshold": threshold,
        "enabled_log_sources": sources,
    }


@pytest.fixture
def session_factory():
    """Fresh in-memory SQLite engine + session factory sharing one connection."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, expire_on_commit=False)
    engine.dispose()


def datasource_id_of(session: Session, log_format: str) -> int:
    """Primary key of the seeded :class:`DataSourceType` row for ``log_format``."""
    row = (
        session.execute(
            select(DataSourceType).where(DataSourceType.log_format == log_format)
        )
        .scalars()
        .one_or_none()
    )
    assert row is not None, f"no DataSourceType row seeded for {log_format!r}"
    return row.id


def coverage_pairs(session: Session) -> list[tuple[str, int]]:
    """All ``(technique_attack_id, datasource_id)`` pairs currently stored."""
    rows = session.execute(
        select(TechniqueCoverage.technique_attack_id, TechniqueCoverage.datasource_id)
    ).all()
    return sorted(rows)


def coverage_row_of(
    session: Session, attack_id: str, datasource_id: int
) -> TechniqueCoverage | None:
    """Fetch the unique coverage row for one ``(technique, datasource)`` pair."""
    return (
        session.execute(
            select(TechniqueCoverage)
            .where(TechniqueCoverage.technique_attack_id == attack_id)
            .where(TechniqueCoverage.datasource_id == datasource_id)
        )
        .scalars()
        .one_or_none()
    )


# ---------------------------------------------------------------------------
# Contract A -- hashability / frozen-shape of everything analyzers return.
# ---------------------------------------------------------------------------

_ALLOWED_SCALARS = (type(None), bool, int, float, str)


def assert_hashable_shape(obj: Any, trail: str = "root") -> None:
    """Recursively enforce the frozen/hashable value contract (A).

    Every node must be ``None|bool|int|float|str``, a ``tuple`` (collections
    are tuples at every nesting depth -- lists/dicts/sets/frozensets banned),
    or a frozen dataclass whose fields obey the same rule. Also proves
    ``hash()`` works and mutation is rejected at every dataclass level.
    """
    if obj is None or isinstance(obj, _ALLOWED_SCALARS):
        return
    if isinstance(obj, tuple):
        for index, item in enumerate(obj):
            assert_hashable_shape(item, f"{trail}[{index}]")
        return
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        try:
            hash(obj)
        except TypeError as err:
            raise AssertionError(
                f"{trail}: {type(obj).__name__} is not hashable: {err}"
            ) from err
        try:
            setattr(obj, "_hash_probe", True)
        except (dataclasses.FrozenInstanceError, AttributeError):
            pass
        else:
            raise AssertionError(
                f"{trail}: {type(obj).__name__} is not frozen (setattr succeeded)"
            )
        for field in dataclasses.fields(obj):
            assert_hashable_shape(getattr(obj, field.name), f"{trail}.{field.name}")
        return
    raise AssertionError(
        f"{trail}: forbidden value type {type(obj).__name__!r} "
        "(allowed: None|bool|int|float|str|tuple|frozen-dataclass)"
    )


class TestReturnValueContract:
    """Contract A: frozen, hashable, tuple-only analyzer outputs."""

    @staticmethod
    def _seed_one_technique_world(session: Session) -> None:
        add_technique(session, "T1001", tactics=("execution", "persistence"))
        session.commit()

    @staticmethod
    def _one_rule() -> list[MappingRule]:
        return [
            make_rule("T1001", base_confidence=0.7, ext_keys=("newprocessname",)),
        ]

    def test_report_is_frozen_and_hashable(self, session_factory, tmp_path):
        """PopulateReport is a frozen dataclass of scalars and tuples only."""
        del tmp_path  # symmetry with the other worlds; no filesystem needed
        session = session_factory()
        self._seed_one_technique_world(session)
        report = populate_technique_coverage(session, self._one_rule(), make_cfg())
        assert isinstance(report, PopulateReport)
        assert_hashable_shape(report)
        hash(report)

    def test_rows_tactics_and_gaps_are_frozen_hashable(self, session_factory):
        """Every load/aggregation/gap output obeys the frozen tuple-only shape."""
        session = session_factory()
        self._seed_one_technique_world(session)
        rules = self._one_rule()
        populate_technique_coverage(session, rules, make_cfg())
        rows = load_coverage_rows(session, make_cfg())
        assert rows, "world must produce at least one split row"
        for row in rows:
            assert_hashable_shape(row)
        for entry in coverage_by_tactic(rows):
            assert isinstance(entry, TacticCoverage)
            assert_hashable_shape(entry)
        for gap in calculate_coverage_gaps(rows, rules, make_cfg()):
            assert isinstance(gap, Gap)
            assert_hashable_shape(gap)

    def test_rows_equal_and_hash_stable_across_calls(self, session_factory):
        """Purity/cache contract: repeated loads give equal, equally-hashed values."""
        session = session_factory()
        self._seed_one_technique_world(session)
        rules = self._one_rule()
        populate_technique_coverage(session, rules, make_cfg())
        first = load_coverage_rows(session, make_cfg())
        second = load_coverage_rows(session, make_cfg())
        assert first == second
        assert [hash(row) for row in first] == [hash(row) for row in second]
        assert coverage_by_tactic(first) == coverage_by_tactic(second)


# ---------------------------------------------------------------------------
# Contract C -- populate idempotency on the surrogate-PK table.
# ---------------------------------------------------------------------------

class TestPopulateIdempotency:
    """Desired-pair diff algorithm: UPDATE-in-place / INSERT / DELETE-stale."""

    def test_fresh_run_inserts_only_enabled_pairs(self, session_factory):
        session = session_factory()
        add_technique(session, "T1001")
        session.commit()
        rules = [
            make_rule("T1001", source_format="evtx", base_confidence=0.70,
                      ext_keys=("newprocessname",)),
            make_rule("T1001", source_format="json", base_confidence=0.90,
                      match_type="heuristic"),
        ]
        cfg = make_cfg(enabled_log_sources={"json": False})
        report = populate_technique_coverage(session, rules, cfg)

        assert report.rows_inserted == 1, "disabled json datasource must be skipped"
        assert report.rows_updated == 0
        assert report.rows_deleted == 0
        assert report.rows_upserted == report.rows_inserted + report.rows_updated
        assert report.skipped_revoked == ()
        assert report.skipped_orphan == ()
        assert report.warnings == 0

        evtx_id = datasource_id_of(session, "evtx")
        stored = coverage_row_of(session, "T1001", evtx_id)
        assert stored is not None
        assert stored.detection_confidence == pytest.approx(0.70)
        assert stored.is_detectable is True
        assert coverage_pairs(session) == [("T1001", evtx_id)]

    def test_rerun_is_a_noop_despite_surrogate_pk(self, session_factory):
        """merge() cannot match surrogate-PK rows; the diff must keep them stable."""
        session = session_factory()
        add_technique(session, "T1001")
        session.commit()
        rules = [
            make_rule("T1001", base_confidence=0.70, ext_keys=("newprocessname",)),
        ]
        cfg = make_cfg()
        populate_technique_coverage(session, rules, cfg)
        before_ids = [
            row.id for row in session.execute(select(TechniqueCoverage)).scalars()
        ]

        report2 = populate_technique_coverage(session, rules, cfg)

        after_ids = [
            row.id for row in session.execute(select(TechniqueCoverage)).scalars()
        ]
        assert report2.rows_inserted == 0
        assert report2.rows_updated == 0
        assert report2.rows_deleted == 0
        assert before_ids == after_ids, "idempotent rerun must not churn surrogate PKs"
        assert coverage_pairs(session) == [("T1001", datasource_id_of(session, "evtx"))]

    def test_changed_values_update_in_place_preserving_pk(self, session_factory):
        """Value diffs UPDATE the existing row; the confidence flip crosses 0.6."""
        session = session_factory()
        add_technique(session, "T1001")
        session.commit()

        def rules_with(base: float) -> list[MappingRule]:
            return [make_rule("T1001", base_confidence=base,
                              ext_keys=("newprocessname",))]

        populate_technique_coverage(session, rules_with(0.55), make_cfg())
        evtx_id = datasource_id_of(session, "evtx")
        stale = coverage_row_of(session, "T1001", evtx_id)
        assert stale is not None and stale.is_detectable is False

        report = populate_technique_coverage(session, rules_with(0.65), make_cfg())

        assert report.rows_inserted == 0
        assert report.rows_updated == 1
        assert report.rows_deleted == 0
        refreshed = coverage_row_of(session, "T1001", evtx_id)
        assert refreshed is not None
        assert refreshed.id == stale.id, "value update must happen in place (same PK)"
        assert refreshed.detection_confidence == pytest.approx(0.65)
        assert refreshed.is_detectable is True

    def test_removed_mapping_deletes_stale_pair(self, session_factory):
        session = session_factory()
        add_technique(session, "T1001")
        session.commit()
        v1 = [
            make_rule("T1001", source_format="evtx", ext_keys=("a",)),
            make_rule("T1001", source_format="json", ext_keys=("b",)),
        ]
        populate_technique_coverage(session, v1, make_cfg())
        evtx_id = datasource_id_of(session, "evtx")
        json_id = datasource_id_of(session, "json")
        assert coverage_pairs(session) == [("T1001", evtx_id), ("T1001", json_id)]

        report = populate_technique_coverage(session, v1[:1], make_cfg())

        assert report.rows_deleted == 1
        assert report.rows_inserted == 0 and report.rows_updated == 0
        assert coverage_pairs(session) == [("T1001", evtx_id)]

    def test_disabling_a_source_deletes_its_rows_on_next_run(self, session_factory):
        """Config-driven toggles: rerun with json off removes the json pairs."""
        session = session_factory()
        add_technique(session, "T1001")
        session.commit()
        rules = [
            make_rule("T1001", source_format="evtx", ext_keys=("a",)),
            make_rule("T1001", source_format="json", ext_keys=("b",)),
        ]
        populate_technique_coverage(session, rules, make_cfg())

        report = populate_technique_coverage(
            session, rules, make_cfg(enabled_log_sources={"json": False})
        )

        assert report.rows_deleted == 1
        assert coverage_pairs(session) == [("T1001", datasource_id_of(session, "evtx"))]

    def test_empty_rule_set_on_virgin_database_is_harmless(self, session_factory):
        session = session_factory()
        add_technique(session, "T1001")
        session.commit()
        report = populate_technique_coverage(session, [], make_cfg())
        assert report.rows_inserted == 0
        assert report.rows_deleted == 0
        assert coverage_pairs(session) == []

    def test_out_of_range_threshold_rejected(self, session_factory):
        """Config validation guards every entry point (threshold outside [0, 1])."""
        session = session_factory()
        add_technique(session, "T1001")
        session.commit()
        rules = [make_rule("T1001")]
        with pytest.raises(ValueError):
            populate_technique_coverage(session, rules, make_cfg(threshold=1.5))
        with pytest.raises(ValueError):
            load_coverage_rows(session, make_cfg(threshold=-0.1))


# ---------------------------------------------------------------------------
# Contract C -- skip paths: revoked/deprecated, orphan, unknown format.
# ---------------------------------------------------------------------------

class TestPopulateSkipPaths:
    """Revoked/deprecated techniques, unresolvable ids, unknown source formats."""

    def test_revoked_and_orphan_rules_skipped_with_warnings(self, session_factory):
        session = session_factory()
        add_technique(session, "T1001")
        add_technique(session, "T2002", revoked=True)  # deprecated shares this flag
        session.commit()
        rules = [
            make_rule("T1001", ext_keys=("a",)),
            make_rule("T2002", tactic="defense-evasion", ext_keys=("b",)),
            make_rule("T9999", tactic="impact", ext_keys=("c",)),
        ]
        report = populate_technique_coverage(session, rules, make_cfg())

        assert isinstance(report.skipped_revoked, tuple)
        assert isinstance(report.skipped_orphan, tuple)
        assert set(report.skipped_revoked) == {"T2002"}
        assert set(report.skipped_orphan) == {"T9999"}
        assert report.warnings == 2, "each skip must WARN exactly once here"
        assert len(coverage_pairs(session)) == 1, "only the healthy pair survives"

    def test_unknown_source_format_skips_without_crashing(self, session_factory):
        """Contract C: unknown formats skip+WARN at rule level (bypasses the
        strict CSV loader by constructing the rule object directly)."""
        session = session_factory()
        add_technique(session, "T1001")
        session.commit()
        rules = [
            make_rule("T1001", ext_keys=("a",)),
            make_rule("T1001", source_format="novell_audit", ext_keys=("a",)),
        ]
        report = populate_technique_coverage(session, rules, make_cfg())

        assert len(coverage_pairs(session)) == 1, "healthy rule must still populate"
        assert report.warnings >= 1, "unknown source format must count as a warning"

    def test_empty_techniques_table_reports_orphans_without_crashing(
        self, session_factory
    ):
        """An unloaded catalog is pipeline state, not a crash: every rule lands
        on the orphan path and nothing is written."""
        session = session_factory()
        rules = [make_rule("T1001"), make_rule("T1002")]
        report = populate_technique_coverage(session, rules, make_cfg())

        assert report.rows_inserted == 0
        assert set(report.skipped_orphan) == {"T1001", "T1002"}
        assert report.warnings == 2
        assert coverage_pairs(session) == []


# ---------------------------------------------------------------------------
# Contract D -- static tier projection, caps, boundary threshold.
# ---------------------------------------------------------------------------

class TestConfidenceSemantics:
    """confidence = max(base * tier_mult) over a datasource's rules, cap 0.95."""

    def test_max_over_rules_with_static_tiers_and_cap(self, session_factory):
        session = session_factory()
        add_technique(session, "T1001")
        session.commit()
        scenarios = (
            # (base, ext_keys, action, match_type) -- independent oracle inputs.
            (1.0, (), "^process_created$", "regex"),   # action-only: 0.85
            (1.0, ("newprocessname",), None, "regex"),  # tier 1 hitting the cap
            (0.90, ("whatever",), None, "heuristic"),   # heuristic wins over keys
            (0.70, ("commandline",), None, "regex"),    # ordinary tier-1 loser
        )
        rules = [
            make_rule(
                "T1001",
                base_confidence=base,
                ext_keys=keys,
                event_action_pattern=action,
                match_type=match_type,
                mapping_id=f"ORD-{i:02d}",
            )
            for i, (base, keys, action, match_type) in enumerate(scenarios, start=1)
        ]
        populate_technique_coverage(session, rules, make_cfg())
        stored = coverage_row_of(session, "T1001", datasource_id_of(session, "evtx"))
        assert stored is not None
        expected = max(
            project_rule_confidence(
                base_confidence=base,
                ext_keys=keys,
                event_action_pattern=action,
                match_type=match_type,
            )
            for base, keys, action, match_type in scenarios
        )
        assert expected == pytest.approx(CONFIDENCE_CAP)
        assert stored.detection_confidence == pytest.approx(expected)
        assert stored.detection_confidence <= CONFIDENCE_CAP
        assert stored.is_detectable is True

    def test_exists_rule_value_pattern_is_irrelevant_tier_one(self, session_factory):
        """'exists' scores on key presence alone; boundary 0.60 is inclusive."""
        session = session_factory()
        add_technique(session, "T1001")
        session.commit()
        rules = [
            make_rule("T1001", tactic="credential-access", base_confidence=0.60,
                      ext_keys=("logontype",), match_type="exists"),
        ]
        populate_technique_coverage(session, rules, make_cfg())
        stored = coverage_row_of(session, "T1001", datasource_id_of(session, "evtx"))
        assert stored is not None
        assert stored.detection_confidence == pytest.approx(0.60)
        assert stored.is_detectable is True, "threshold comparison is inclusive"

    def test_below_threshold_not_detectable(self, session_factory):
        session = session_factory()
        add_technique(session, "T1001")
        session.commit()
        rules = [make_rule("T1001", base_confidence=0.59,
                           ext_keys=("newprocessname",))]
        populate_technique_coverage(session, rules, make_cfg())
        stored = coverage_row_of(session, "T1001", datasource_id_of(session, "evtx"))
        assert stored is not None
        assert stored.detection_confidence == pytest.approx(0.59)
        assert stored.is_detectable is False

    def test_technique_level_best_is_max_across_enabled_datasources(
        self, session_factory
    ):
        session = session_factory()
        add_technique(session, "T1001")
        session.commit()
        rules = [
            make_rule("T1001", source_format="evtx", base_confidence=0.50,
                      ext_keys=("a",)),
            make_rule("T1001", source_format="zeek", base_confidence=0.90,
                      ext_keys=("b",)),
        ]
        populate_technique_coverage(session, rules, make_cfg())
        rows = load_coverage_rows(session, make_cfg())
        targets = [row for row in rows if row.attack_id == "T1001"]
        assert targets, "mapped in-scope technique must produce coverage rows"
        assert all(row.best_confidence == pytest.approx(0.90) for row in targets)
        assert all(row.is_detectable for row in targets)

        evtx_stored = coverage_row_of(session, "T1001", datasource_id_of(session, "evtx"))
        zeek_stored = coverage_row_of(session, "T1001", datasource_id_of(session, "zeek"))
        assert evtx_stored is not None and zeek_stored is not None
        assert evtx_stored.detection_confidence == pytest.approx(0.50)
        assert zeek_stored.detection_confidence == pytest.approx(0.90)

    def test_multi_tactic_split_rows_share_the_technique_verdict(
        self, session_factory
    ):
        session = session_factory()
        add_technique(session, "T1001", tactics=("discovery", "collection"))
        session.commit()
        rules = [make_rule("T1001", base_confidence=0.75, ext_keys=("k",))]
        populate_technique_coverage(session, rules, make_cfg())
        rows = [row for row in load_coverage_rows(session, make_cfg())
                if row.attack_id == "T1001"]
        assert len(rows) == 2, "multi-tactic technique splits one row per tactic"
        assert {row.tactic for row in rows} == {"discovery", "collection"}
        assert len({row.best_confidence for row in rows}) == 1
        assert len({row.is_detectable for row in rows}) == 1


# ---------------------------------------------------------------------------
# Contracts B + D -- platform scope, tactic aggregation, canonical order.
# ---------------------------------------------------------------------------

class TestPlatformScope:
    """Element-wise case-insensitive scope matching (contract B)."""

    def test_platform_in_scope_elementwise_semantics(self):
        """Direct probe of the pure predicate: exact membership, case-folded."""
        platforms = ("Windows", "Linux")
        assert platform_in_scope(platforms, "windows") is True
        assert platform_in_scope(platforms, "Windows") is True
        assert platform_in_scope(platforms, "linux") is True
        assert platform_in_scope(platforms, "macos") is False
        assert platform_in_scope(platforms, "window") is False, (
            "substring matches are banned -- element-wise equality only"
        )
        assert platform_in_scope(platforms, "all") is True
        assert platform_in_scope(("IaaS",), "all") is True
        assert platform_in_scope((), "windows") is False
        assert platform_in_scope(("Containers",), "all") is True

    def test_scope_flag_flows_through_loaded_rows(self, session_factory):
        session = session_factory()
        add_technique(session, "T1001")                       # Windows
        add_technique(session, "T1002", platforms=("Linux",))
        add_technique(session, "T1003", platforms=("macOS",), revoked=True)
        session.commit()
        rules = [make_rule("T1001", ext_keys=("a",)),
                 make_rule("T1002", ext_keys=("b",))]
        populate_technique_coverage(session, rules, make_cfg(platform_scope="linux"))

        linux_rows = load_coverage_rows(session, make_cfg(platform_scope="linux"))
        by_id = {row.attack_id: row.scope_hit for row in linux_rows}
        assert by_id["T1002"] is True
        assert by_id["T1001"] is False
        assert "T1003" not in by_id, "revoked techniques are not loaded at all"


class TestTacticAggregation:
    """All-14 canonical emission with full in-scope-alive denominators."""

    @staticmethod
    def _seed_world(session: Session) -> None:
        add_technique(session, "T1001", tactics=("execution",))  # detected 0.95
        add_technique(session, "T1002", tactics=("execution",))  # miss 0.55
        add_technique(session, "T1003", tactics=("credential-access",))  # 0.60 hit
        add_technique(
            session, "T1004", tactics=("discovery", "collection"),
            platforms=("Linux",),
        )  # mapped but out of windows scope; multi-tactic
        add_technique(
            session, "T1005", tactics=("execution",), platforms=("macOS",)
        )  # out of scope entirely
        add_technique(session, "T1006", tactics=("execution",), revoked=True)
        session.commit()

    @staticmethod
    def _rules() -> list[MappingRule]:
        return [
            make_rule("T1001", base_confidence=0.95, ext_keys=("a",)),
            make_rule("T1002", base_confidence=0.55, ext_keys=("a",)),
            make_rule("T1003", tactic="credential-access", base_confidence=0.60,
                      ext_keys=("a",)),
            make_rule("T1004", tactic="discovery", base_confidence=0.30,
                      ext_keys=("a",)),
            make_rule("T1005", base_confidence=0.90, ext_keys=("a",)),
        ]

    def test_all_fourteen_tactics_canonical_order_full_denominators(
        self, session_factory
    ):
        session = session_factory()
        self._seed_world(session)
        populate_technique_coverage(session, self._rules(), make_cfg())

        rows = load_coverage_rows(session, make_cfg(platform_scope="windows"))
        entries = coverage_by_tactic(rows)

        assert [entry.tactic for entry in entries] == list(CANONICAL_TACTICS)
        assert len(entries) == 14
        by_name = {entry.tactic: entry for entry in entries}
        # execution: T1001 + T1002; T1005 (macOS) and T1006 (revoked) excluded.
        assert (by_name["execution"].total, by_name["execution"].detectable) == (2, 1)
        assert by_name["execution"].pct == pytest.approx(round(1 / 2, 4))
        # credential-access: T1003 sits exactly on the inclusive 0.6 bar.
        cred = by_name["credential-access"]
        assert (cred.total, cred.detectable, cred.pct) == (1, 1, 1.0)
        # multi-tactic technique counts once PER tactic -- but only when scoped.
        assert (by_name["discovery"].total, by_name["discovery"].detectable) == (0, 0)
        assert (by_name["collection"].total, by_name["collection"].detectable) == (0, 0)
        # untouched tactics still emitted at zero.
        exfil = by_name["exfiltration"]
        assert (exfil.total, exfil.detectable, exfil.pct) == (0, 0, 0.0)
        # split-sum sanity under windows scope: execution 2 + credential 1.
        assert sum(entry.total for entry in entries) == 3

    def test_linux_scope_counts_the_multi_tactic_technique_once_per_tactic(
        self, session_factory
    ):
        session = session_factory()
        self._seed_world(session)
        populate_technique_coverage(session, self._rules(), make_cfg())

        rows = load_coverage_rows(session, make_cfg(platform_scope="linux"))
        entries = coverage_by_tactic(rows)
        by_name = {entry.tactic: entry for entry in entries}
        assert (by_name["discovery"].total, by_name["discovery"].detectable) == (1, 0)
        assert (by_name["collection"].total, by_name["collection"].detectable) == (1, 0)
        assert by_name["execution"].total == 0, "Windows techniques leave linux scope"
        assert sum(entry.total for entry in entries) == 2  # T1004 counted twice

    def test_unmapped_in_scope_techniques_still_feed_denominators(
        self, session_factory
    ):
        """Denominator = ALL in-scope alive techniques assigned the tactic,
        including those with no coverage row at all (best_confidence 0.0)."""
        session = session_factory()
        add_technique(session, "T1001", tactics=("impact",))  # mapped
        add_technique(session, "T1002", tactics=("impact",))  # unmapped on purpose
        session.commit()
        rules = [make_rule("T1001", tactic="impact", base_confidence=0.80,
                           ext_keys=("a",))]
        populate_technique_coverage(session, rules, make_cfg())

        rows = load_coverage_rows(session, make_cfg())
        unmapped = [row for row in rows if row.attack_id == "T1002"]
        assert unmapped, "unmapped in-scope techniques must still be returned"
        assert all(row.best_confidence == 0.0 and row.is_detectable is False
                   for row in unmapped)
        impact = next(entry for entry in coverage_by_tactic(rows)
                      if entry.tactic == "impact")
        assert (impact.total, impact.detectable, impact.pct) == (2, 1, 0.5)

    def test_zero_enabled_sources_yield_zero_pcts_and_full_gap_list(
        self, session_factory
    ):
        session = session_factory()
        self._seed_world(session)
        rules = self._rules()
        everything_off = {
            fmt: False
            for fmt in (
                "evtx", "syslog", "cef", "leef", "json",
                "aws_cloudtrail", "nginx", "zeek",
            )
        }
        cfg = make_cfg(enabled_log_sources=everything_off)

        report = populate_technique_coverage(session, rules, cfg)
        assert report.rows_inserted == 0
        assert report.rows_deleted == 0

        rows = load_coverage_rows(session, cfg)
        entries = coverage_by_tactic(rows)
        assert [entry.tactic for entry in entries] == list(CANONICAL_TACTICS)
        assert all(entry.detectable == 0 and entry.pct == 0.0 for entry in entries)
        gaps = calculate_coverage_gaps(rows, rules, cfg)
        scoped_ids = {row.attack_id for row in rows if row.scope_hit}
        assert scoped_ids >= {"T1001", "T1002", "T1003"}
        assert {gap.technique_attack_id for gap in gaps} == scoped_ids


# ---------------------------------------------------------------------------
# Contract E -- gaps: filter, sort, honest closable_by.
# ---------------------------------------------------------------------------

class TestCoverageGaps:
    """scope_hit AND not detectable, ordered canonically then by confidence."""

    @staticmethod
    def _seed_gap_world(session: Session) -> None:
        add_technique(session, "T1101", tactics=("execution",))       # near miss 0.45
        add_technique(session, "T1102", tactics=("execution",))       # near miss 0.55
        add_technique(session, "T1103", tactics=("initial-access",))  # miss 0.40
        add_technique(session, "T1104", tactics=("execution",))       # detected 0.95
        add_technique(
            session, "T1105", tactics=("impact",), platforms=("macOS",)
        )  # out-of-scope miss
        session.commit()

    @staticmethod
    def _rules() -> list[MappingRule]:
        return [
            make_rule("T1101", base_confidence=0.45, ext_keys=("k",)),
            make_rule("T1102", base_confidence=0.55, ext_keys=("k",)),
            make_rule("T1103", tactic="initial-access", base_confidence=0.40,
                      ext_keys=("k",)),
            make_rule("T1104", base_confidence=0.95, ext_keys=("k",)),
            make_rule("T1105", tactic="impact", base_confidence=0.90,
                      ext_keys=("k",)),
        ]

    def test_gap_filter_order_and_exclusions(self, session_factory):
        session = session_factory()
        self._seed_gap_world(session)
        rules = self._rules()
        cfg = make_cfg()
        populate_technique_coverage(session, rules, cfg)
        gaps = calculate_coverage_gaps(load_coverage_rows(session, cfg), rules, cfg)

        ids_in_order = [gap.technique_attack_id for gap in gaps]
        # initial-access precedes execution canonically; within execution the
        # lower confidence surfaces first (near-miss-first demo beat).
        assert ids_in_order == ["T1103", "T1101", "T1102"], (
            f"unexpected gap order: {ids_in_order}"
        )
        assert "T1104" not in ids_in_order, "detected techniques are not gaps"
        assert "T1105" not in ids_in_order, "out-of-scope techniques are not gaps"

        confidences = [gap.best_confidence for gap in gaps]
        assert confidences == sorted(confidences), "ascending confidence within order"

    def test_gap_partition_identity_and_field_hygiene(self, session_factory):
        session = session_factory()
        self._seed_gap_world(session)
        rules = self._rules()
        cfg = make_cfg()
        populate_technique_coverage(session, rules, cfg)
        rows = load_coverage_rows(session, cfg)
        gaps = calculate_coverage_gaps(rows, rules, cfg)

        missing = {row.attack_id for row in rows if row.scope_hit
                   and not row.is_detectable}
        detected = {row.attack_id for row in rows if row.scope_hit
                    and row.is_detectable}
        scoped = {row.attack_id for row in rows if row.scope_hit}
        assert {gap.technique_attack_id for gap in gaps} == missing
        assert detected | missing == scoped, "gaps partition the scoped universe"

        for gap in gaps:
            assert isinstance(gap.closable_by, tuple)
            assert list(gap.closable_by) == sorted(gap.closable_by)
            assert gap.name, "gap carries the technique display name"
            assert gap.tactic in CANONICAL_TACTICS
            assert 0.0 <= gap.best_confidence < float(cfg["detection_confidence_threshold"])

    def test_closable_by_is_honest_about_static_projection(self, session_factory):
        """Disabled formats count ONLY if their projected best clears the bar.

        Mirrors the measured lesson (contract E): naive any-mapping logic
        falsely promises nginx/cef closes things whose projections sit below
        the threshold; only genuinely qualifying formats may appear.
        """
        session = session_factory()
        add_technique(session, "T2201", tactics=("execution",))
        session.commit()
        rules = [
            # enabled evtx evidence too weak to detect -> keeps T2201 a gap
            make_rule("T2201", source_format="evtx", base_confidence=0.55,
                      ext_keys=("k",)),
            # zeek disabled BUT tier-1 projects to 0.90 >= 0.6 -> closable
            make_rule("T2201", source_format="zeek", base_confidence=0.90,
                      ext_keys=("k",)),
            # nginx disabled and action-only 0.65*0.85=0.5525 < 0.6 -> NOT closable
            make_rule("T2201", source_format="nginx", base_confidence=0.65,
                      event_action_pattern="^get 401$"),
        ]
        populate_technique_coverage(session, rules, make_cfg())
        cfg = make_cfg(enabled_log_sources={"zeek": False, "nginx": False})
        rows = load_coverage_rows(session, cfg)
        gaps = calculate_coverage_gaps(rows, rules, cfg)

        target = [gap for gap in gaps if gap.technique_attack_id == "T2201"]
        assert len(target) == 1, "weak evtx evidence leaves T2201 a gap"
        assert target[0].closable_by == ("zeek",), (
            "only the honestly-projecting disabled format may promise closure; "
            f"got {target[0].closable_by}"
        )

    def test_enabling_the_closable_source_closes_the_gap(self, session_factory):
        """Toggle demo beat: flipping zeek on moves the technique out of gaps."""
        session = session_factory()
        add_technique(session, "T2201", tactics=("execution",))
        session.commit()
        rules = [
            make_rule("T2201", source_format="evtx", base_confidence=0.55,
                      ext_keys=("k",)),
            make_rule("T2201", source_format="zeek", base_confidence=0.90,
                      ext_keys=("k",)),
        ]
        off_cfg = make_cfg(enabled_log_sources={"zeek": False})
        populate_technique_coverage(session, rules, off_cfg)
        gaps_off = calculate_coverage_gaps(
            load_coverage_rows(session, off_cfg), rules, off_cfg
        )
        assert any(gap.technique_attack_id == "T2201" for gap in gaps_off)

        report = populate_technique_coverage(
            session, rules, make_cfg(enabled_log_sources={"zeek": True})
        )
        assert report.rows_inserted >= 1, "enabling zeek materializes its pair"
        on_cfg = make_cfg(enabled_log_sources={"zeek": True})
        gaps_on = calculate_coverage_gaps(
            load_coverage_rows(session, on_cfg), rules, on_cfg
        )
        assert not any(gap.technique_attack_id == "T2201" for gap in gaps_on)

    def test_build_closable_index_treats_absent_keys_as_enabled(
        self, session_factory
    ):
        """Mapper semantics: a format absent from the config map counts enabled,
        so it can never appear in closable_by."""
        session = session_factory()
        add_technique(session, "T2201", tactics=("execution",))
        session.commit()
        rules = [
            make_rule("T2201", source_format="zeek", base_confidence=0.90,
                      ext_keys=("k",)),
        ]
        populate_technique_coverage(
            session, rules, make_cfg(enabled_log_sources={"zeek": False})
        )
        sparse_cfg: dict[str, object] = {
            "platform_scope": "windows",
            "detection_confidence_threshold": 0.6,
            "enabled_log_sources": {"evtx": True},  # 'zeek' key absent
        }
        rows = load_coverage_rows(session, sparse_cfg)
        gaps = calculate_coverage_gaps(rows, rules, sparse_cfg)
        target = [gap for gap in gaps if gap.technique_attack_id == "T2201"]
        assert target, "absent-config-key zeek behaves as enabled -> weak evidence"
        assert target[0].closable_by == ()


# ---------------------------------------------------------------------------
# Contract I -- guarded golden smoke against the real database snapshot.
# ---------------------------------------------------------------------------

def _shipped_cfg() -> dict[str, object]:
    """Config mirroring the repo's shipped ``config.yaml`` (offline literal)."""
    return make_cfg(
        platform_scope="windows",
        threshold=0.6,
        enabled_log_sources={
            "evtx": True, "syslog": True, "cef": False, "leef": False,
            "json": True, "aws_cloudtrail": True, "nginx": False, "zeek": True,
        },
    )


class TestGoldenRealDatabase:
    """Wave-1 CORE-ROW expectations, run on a throwaway copy of db/coverage.db."""

    def test_execution_golden_revoked_skips_and_t1190_beacon(self, tmp_path):
        if not REAL_COVERAGE_DB.is_file():
            pytest.skip(f"real coverage database not present: {REAL_COVERAGE_DB}")
        if not REAL_MAPPINGS_CSV.is_file():
            pytest.skip(f"real mappings csv not present: {REAL_MAPPINGS_CSV}")

        from parser.mappings_io import load_mappings

        db_copy = tmp_path / "coverage-copy.db"
        shutil.copy2(REAL_COVERAGE_DB, db_copy)
        engine = create_engine(f"sqlite:///{db_copy}")
        Base.metadata.create_all(engine)  # idempotent; adds any missing tables
        session = sessionmaker(bind=engine, expire_on_commit=False)()
        try:
            if not session.execute(
                select(func.count()).select_from(Technique)
            ).scalar_one():
                pytest.skip("real database has no techniques loaded yet")

            rules = load_mappings(str(REAL_MAPPINGS_CSV))
            cfg = _shipped_cfg()
            enabled_map = dict(cfg["enabled_log_sources"])  # type: ignore[arg-type]
            report = populate_technique_coverage(session, rules, cfg)

            targeted = {rule.technique_id for rule in rules}

            # (I) revoked-skip: every CSV-targeted technique the DB flags as
            # revoked/deprecated must land on skipped_revoked (currently
            # includes M016's T1562.008 pending its retarget to T1685.002).
            revoked_ids = {
                attack_id
                for (attack_id,) in session.execute(
                    select(Technique.attack_id).where(Technique.revoked.is_(True))
                ).all()
            }
            expected_revoked = targeted & revoked_ids
            assert expected_revoked <= set(report.skipped_revoked), (
                f"targeted-but-revoked techniques missed by the skip report: "
                f"{expected_revoked - set(report.skipped_revoked)}"
            )
            known_ids = {
                attack_id
                for (attack_id,) in session.execute(select(Technique.attack_id)).all()
            }
            assert targeted - known_ids <= set(report.skipped_orphan)

            rows = load_coverage_rows(session, cfg)
            entries = coverage_by_tactic(rows)
            assert [entry.tactic for entry in entries] == list(CANONICAL_TACTICS)

            execution = next(entry for entry in entries if entry.tactic == "execution")
            # Sanity range (loader fixes may shift the exact denominator a bit;
            # Wave-1 measured 46 windows-alive execution techniques).
            assert 40 <= execution.total <= 60, (
                f"execution denominator drifted hard: {execution.total}"
            )
            assert execution.pct == pytest.approx(
                round(execution.detectable / execution.total, 4)
            )

            detected_execution = {
                row.attack_id for row in rows
                if row.tactic == "execution" and row.is_detectable and row.scope_hit
            }
            scoped_execution = {
                row.attack_id for row in rows
                if row.tactic == "execution" and row.scope_hit
            }
            # The four golden detectables, filtered by what the CURRENT inputs
            # still support (survives the pending M016 retarget gracefully).
            core_candidates = {"T1059.001", "T1059.003", "T1047", "T1569.002"}
            expected_present = {
                tid for tid in core_candidates
                if any(rule.technique_id == tid and rule.source_format == "evtx"
                       for rule in rules)
                and tid in known_ids
                and tid not in revoked_ids
                and tid in scoped_execution
            }
            assert expected_present, (
                "golden core execution rules vanished from the live inputs"
            )
            missing = expected_present - detected_execution
            assert not missing, (
                f"golden detectables absent from the execution set: {missing}"
            )

            # Honest-filter beacon: while nginx is disabled and holds the only
            # qualifying mapping for T1190, the gap must advertise nginx.
            t1190_rules = [rule for rule in rules if rule.technique_id == "T1190"]
            has_enabled_evidence = any(
                enabled_map.get(rule.source_format, False) for rule in t1190_rules
            )
            nginx_projection_ok = any(
                rule.source_format == "nginx"
                and project_rule_confidence(
                    base_confidence=rule.base_confidence,
                    ext_keys=rule.ext_keys,
                    event_action_pattern=(
                        rule.event_action_re.pattern if rule.event_action_re else None
                    ),
                    match_type=rule.match_type,
                )
                >= float(cfg["detection_confidence_threshold"])
                for rule in t1190_rules
            )
            if t1190_rules and not has_enabled_evidence and nginx_projection_ok:
                t1190_gaps = [
                    gap for gap in calculate_coverage_gaps(rows, rules, cfg)
                    if gap.technique_attack_id == "T1190"
                ]
                assert t1190_gaps, "T1190 should surface as a closable gap"
                assert "nginx" in t1190_gaps[0].closable_by
            else:
                logger.info(
                    "T1190 golden precondition changed (retarget/enabled "
                    "evidence); skipping the nginx closable assertion"
                )
        finally:
            session.close()
            engine.dispose()


# ---------------------------------------------------------------------------
# Guard rails on this module itself (cheap meta-checks).
# ---------------------------------------------------------------------------

def test_module_avoids_forbidden_constructs():
    """Static hygiene: engine sources use no eval/exec/subprocess anywhere.

    Scans the shipped ``src/`` tree (not this file - a literal list of
    forbidden tokens would trip any self-scan by construction).
    """
    src_root = Path(__file__).resolve().parents[1] / "src"
    offenders = []
    for path in sorted(src_root.rglob("*.py")):
        module_source = path.read_text(encoding="utf-8")
        for forbidden in ("eval(", "exec(", "subprocess", "os.system", "pickle."):
            if forbidden in module_source:
                offenders.append(f"{path.name}:{forbidden}")
    assert not offenders, f"forbidden constructs present: {offenders}"


def test_default_config_contract_untouched():
    """Sanity: DEFAULT_CONFIG still drives our cfg builder (no drift)."""
    snapshot = copy.deepcopy(DEFAULT_CONFIG)
    assert isinstance(snapshot, dict)
    assert set(snapshot) >= {
        "platform_scope",
        "detection_confidence_threshold",
        "enabled_log_sources",
    }
