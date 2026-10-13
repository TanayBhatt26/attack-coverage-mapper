"""tests/test_coverage_by_tactic.py -- Coverage-by-tactic semantics (Phase 3, Wave 2).

Owns the aggregation-layer contract for ``src/analysis/coverage_analyzer.py``
as pinned by ``PLAN.md:114`` with the Wave-2 hard contracts applied:

* **(D) semantics** -- per-tactic denominators count *every* in-scope,
  non-revoked technique assigned that tactic (multi-tactic techniques count
  once per tactic); numerators count techniques whose technique-level
  ``best_confidence`` (MAX across enabled-datasource coverage rows) is >=
  the config threshold, inclusively. All 14 Enterprise tactics are always
  emitted, in canonical ATT&CK order, even at 0%.
* **(B) platform scope** -- a technique is in scope iff
  ``cfg['platform_scope'] == 'all'`` OR the lowered scope equals one of the
  technique's lowered platform strings. Element-wise equality, never a
  substring test.
* **(A) hashability** -- ``TacticCoverage`` is a frozen dataclass whose
  fields are only ``str | int | float``, so returned tuples are natively
  hashable (Streamlit ``st.cache_data`` contract).
* **(I) golden snapshot** -- the Wave-1 CORE-ROW AGGREGATE execution slice
  (4 detectable of 46 windows-execution techniques: T1059.001, T1059.003,
  T1047, T1569.002 at 0.70-0.75) is encoded by driving the *real*
  ``populate_technique_coverage`` with faithful replicas of the nine
  execution-targeting mapping rules, then aggregating.

Implementation notes vs. the older swarm-2 design sketch: the landed engine
returns :class:`analysis.coverage_analyzer.CoverageRow` (keyed by
``attack_id``, scoped via ``scope_hit``, evidence via ``source_ids`` --
datasource primary keys) and ``coverage_by_tactic(rows)`` consumes the
already-scoped rows with no config argument. The read path selects
coverage evidence through ``DataSourceType.enabled``; that flag is the
populate-mirrored image of ``config['enabled_log_sources']``, so the
toggle tests flip both, reproducing genuine post-populate state.

Scope discipline: populate-side audit counters (insert/update/delete,
skipped lists) belong to the populate owner's suite; the golden test here
uses populate purely as the upstream producer of tier-projected rows.

The full-bundle test loads the offline STIX cache into a throwaway SQLite
database and checks structural invariants computed independently from the
bundle; it deliberately avoids pinning absolute tactic totals, because the
loader fix folding ``x_mitre_deprecated`` onto ``revoked`` legitimately
shifts denominators versus the Wave-1 measurements.

The module-level skip-guard arms gracefully if the analyzer module is ever
absent again (parallel-build window); once present, internal defects surface
loudly -- nothing is blanket-swallowed.
"""

import copy
import dataclasses
import importlib.util
import inspect
import logging
from typing import Any, Mapping, Optional, Sequence

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from config_loader import DEFAULT_CONFIG
from database.models import (
    Base,
    DataSourceType,
    Technique,
    TechniqueCoverage,
)
from tests.conftest import build_mapping_rule

logger = logging.getLogger(__name__)

# --- parallel-build guard ----------------------------------------------------

_ANALYZER_SPEC = importlib.util.find_spec("analysis.coverage_analyzer")
if _ANALYZER_SPEC is not None:
    import analysis.coverage_analyzer as coverage_analyzer
else:  # pragma: no cover -- only true during the parallel build window
    coverage_analyzer = None  # type: ignore[assignment]

pytestmark = pytest.mark.skipif(
    coverage_analyzer is None,
    reason=(
        "src/analysis/coverage_analyzer.py not implemented yet "
        "(parallel Wave-2 build); tests arm automatically once it lands"
    ),
)

# --- contract constants -------------------------------------------------------

#: Canonical ATT&CK Enterprise tactic order (hard contract D). Asserted as a
#: literal so accidental re-orderings upstream fail loudly here.
CANONICAL_TACTIC_ORDER: tuple[str, ...] = (
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

#: Every parser format, seeded as datasource_types rows in fixtures.
ALL_FORMATS: tuple[str, ...] = (
    "evtx",
    "syslog",
    "cef",
    "leef",
    "json",
    "aws_cloudtrail",
    "nginx",
    "zeek",
)


# ---------------------------------------------------------------------------
# Synthetic DB builders
# ---------------------------------------------------------------------------

def make_session(tmp_path) -> Session:
    """Create a fresh file-backed SQLite DB with the full schema.

    A file (not ``:memory:``) keeps each test fully isolated through
    ``tmp_path`` while remaining fast; the engine is disposed by the
    caller-facing fixture.
    """
    engine = create_engine(f"sqlite:///{tmp_path / 'coverage_test.db'}")
    Base.metadata.create_all(engine)
    return Session(engine)


def close_session(session: Session) -> None:
    """Commit pending writes, close the session and dispose its engine."""
    session.commit()
    session.close()
    engine = session.get_bind()
    engine.dispose()


def add_technique(
    session: Session,
    attack_id: str,
    *,
    tactics: Sequence[str] = ("execution",),
    platforms: Sequence[str] = ("Windows",),
    revoked: bool = False,
    name: Optional[str] = None,
    stix_id: Optional[str] = None,
) -> str:
    """Insert one synthetic technique row and return its stix_id.

    ``stix_id`` is derived deterministically from ``attack_id`` so lookups
    stay stable across tests without a registry.
    """
    sid = stix_id or f"attack-pattern--test-{attack_id.lower().replace('.', '-')}"
    session.merge(
        Technique(
            stix_id=sid,
            attack_id=attack_id,
            name=name or f"Technique {attack_id}",
            description=None,
            tactics=list(tactics),
            platforms=list(platforms),
            detection_strategy_refs=[],
            is_subtechnique="." in attack_id,
            parent_attack_id=attack_id.rsplit(".", 1)[0] if "." in attack_id else None,
            revoked=revoked,
        )
    )
    return sid


def add_datasource(
    session: Session, log_format: str, *, enabled: bool = True
) -> DataSourceType:
    """Insert (or fetch) one datasource_types row for ``log_format``.

    Named after the format itself, mirroring how populate seeds the table.
    """
    existing = session.scalar(
        select(DataSourceType).where(DataSourceType.log_format == log_format)
    )
    if existing is not None:
        return existing
    row = DataSourceType(
        name=log_format, log_format=log_format, priority=0, enabled=enabled
    )
    session.add(row)
    session.flush()
    return row


def set_formats_enabled(
    session: Session, formats: Sequence[str], *, enabled: bool
) -> None:
    """Flip the ``enabled`` flag of the given formats' datasource rows.

    The coverage read path filters evidence through this DB flag (the
    populate-mirrored image of ``config['enabled_log_sources']``); toggling
    both keeps fixtures faithful to real post-populate state.
    """
    for fmt in formats:
        ds = add_datasource(session, fmt)
        ds.enabled = enabled
    session.flush()


def seed_datasources(session: Session, formats: Sequence[str] = ALL_FORMATS) -> None:
    """Seed one enabled datasource row per requested format."""
    for fmt in formats:
        add_datasource(session, fmt)


def add_coverage_row(
    session: Session,
    technique_stix_id: str,
    log_format: str,
    confidence: float,
    *,
    attack_id: Optional[str] = None,
    threshold: float = DEFAULT_CONFIG["detection_confidence_threshold"],
) -> None:
    """Insert one technique_coverage row as populate would have produced it.

    ``confidence`` is the *post-populate* per-(technique, datasource) value
    (max of ``base * static_tier_mult`` capped at 0.95, per contract D);
    computing it from raw mapping rules belongs to the populate suite.
    """
    if attack_id is None:
        tech = session.get(Technique, technique_stix_id)
        if tech is None:
            raise LookupError(f"no technique {technique_stix_id!r} seeded")
        attack_id = tech.attack_id
    ds = add_datasource(session, log_format)
    session.merge(
        TechniqueCoverage(
            technique_stix_id=technique_stix_id,
            technique_attack_id=attack_id,
            datasource_id=ds.id,
            is_detectable=bool(confidence >= float(threshold)),
            detection_confidence=float(confidence),
            required_fields=[],
            sigma_rule_id=None,
            splunk_query=None,
            eql_query=None,
        )
    )


def base_cfg(**overrides: Any) -> dict[str, Any]:
    """Fresh normalized-style config dict with selective overrides.

    ``platform_scope`` defaults to ``"windows"`` -- mirroring the repo's
    real ``config.yaml`` -- because ``config_loader.DEFAULT_CONFIG`` ships
    the permissive ``"all"``, which would silently neutralise every
    scope-scoped assertion here.
    """
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["platform_scope"] = str(overrides.pop("platform_scope", "windows"))
    cfg.update(overrides)
    return cfg


# ---------------------------------------------------------------------------
# Public-API adapters (tolerate both pinned call forms)
# ---------------------------------------------------------------------------

def load_rows(session: Session, cfg: Mapping[str, Any]) -> tuple:
    """Call ``coverage_analyzer.load_coverage_rows(session, cfg)``."""
    return coverage_analyzer.load_coverage_rows(session, cfg)  # type: ignore[misc]


def compute_tactics(
    session: Session, cfg: Mapping[str, Any]
) -> tuple[tuple, tuple]:
    """Run the public pipeline and return ``(tactic_tuple, rows_tuple)``.

    The landed engine exposes ``coverage_by_tactic(rows)`` -- scope,
    threshold and enabled-source state are already baked into the rows by
    ``load_coverage_rows(session, config)``. The adapter still tolerates the
    older ``(rows, cfg)`` sketch shape so a refactor cannot silently strand
    these tests; rows are always produced via ``load_coverage_rows`` either
    way.
    """
    fn = coverage_analyzer.coverage_by_tactic  # type: ignore[attr-defined]
    signature_params = list(inspect.signature(fn).parameters)
    rows = load_rows(session, cfg)
    if len(signature_params) >= 2:
        result = fn(rows, dict(cfg))
    else:
        result = fn(rows)
    return result, rows


def by_tactic(result: Sequence) -> dict[str, Any]:
    """Index a TacticCoverage tuple by tactic slug."""
    return {entry.tactic: entry for entry in result}


def find_row(rows: Sequence, attack_id: str) -> Optional[Any]:
    """Return the CoverageRow for ``attack_id`` if one was emitted.

    Multi-tactic techniques split into one row per tactic; the first match
    wins (identical per-technique fields across splits). Out-of-scope and
    unmapped techniques ARE emitted explicitly by the landed loader, so a
    ``None`` here means revoked or tactic-less.
    """
    for row in rows:
        if row.attack_id == attack_id:
            return row
    return None


# ---------------------------------------------------------------------------
# Unit: TacticCoverage dataclass contract (A)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestTacticCoverageDataclassContract:
    """Frozen, primitive-typed, hashable return shape (hard contract A)."""

    def test_fields_are_exactly_the_pinned_four(self):
        names = [f.name for f in dataclasses.fields(coverage_analyzer.TacticCoverage)]
        assert names == ["tactic", "total", "detectable", "pct"]

    def test_frozen_instance_rejects_mutation(self):
        entry = coverage_analyzer.TacticCoverage(
            tactic="execution", total=1, detectable=0, pct=0.0
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            entry.total = 5  # type: ignore[misc]

    def test_fields_hold_only_primitives(self):
        entry = coverage_analyzer.TacticCoverage(
            tactic="discovery", total=3, detectable=2, pct=0.6667
        )
        assert type(entry.tactic) is str
        assert type(entry.total) is int and not isinstance(entry.total, bool)
        assert type(entry.detectable) is int and not isinstance(entry.detectable, bool)
        assert type(entry.pct) is float

    def test_equal_instances_share_hash_and_tuple_is_hashable(self):
        a = coverage_analyzer.TacticCoverage("impact", total=10, detectable=1, pct=0.1)
        b = coverage_analyzer.TacticCoverage("impact", total=10, detectable=1, pct=0.1)
        assert a == b
        assert hash(a) == hash(b)
        pair = (a, b)
        assert hash(pair) == hash(pair)  # no TypeError => st.cache_data-safe


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def session(tmp_path):
    """Isolated schema-complete SQLite session, cleaned up after the test."""
    s = make_session(tmp_path)
    yield s
    close_session(s)


@pytest.fixture
def sparse_session(session):
    """Minimal populated DB: one detected execution technique, one revoked."""
    seed_datasources(session)
    sid = add_technique(session, "T1059.001", tactics=("execution",))
    add_coverage_row(session, sid, "evtx", 0.75)
    dead = add_technique(
        session, "T1505.001", tactics=("persistence",), revoked=True
    )
    add_coverage_row(session, dead, "evtx", 0.90)
    session.commit()
    return session


# ---------------------------------------------------------------------------
# Integration: canonical shape and empty states
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCanonicalShape:
    def test_emits_all_14_tactics_in_canonical_order(self, sparse_session):
        result, _ = compute_tactics(sparse_session, base_cfg())
        assert isinstance(result, tuple)
        assert [entry.tactic for entry in result] == list(CANONICAL_TACTIC_ORDER)

    def test_pcts_are_floats_within_unit_interval(self, sparse_session):
        result, _ = compute_tactics(sparse_session, base_cfg())
        for entry in result:
            assert type(entry.pct) is float
            assert 0.0 <= entry.pct <= 1.0


@pytest.mark.integration
class TestEmptyStates:
    def test_empty_database_raises_with_hint_or_returns_all_zeros(self, tmp_path):
        """Unpinned corner: loader may raise-with-hint or emit zero tactics.

        The swarm-2 design documents "empty techniques table => raise with a
        hint to run the Phase-1 loader"; a graceful all-zeros tuple is the
        equally contract-compatible alternative. Accept exactly one of the
        two, never a crash of another kind.
        """
        s = make_session(tmp_path)
        try:
            try:
                result, _ = compute_tactics(s, base_cfg())
            except (ValueError, RuntimeError) as exc:
                logger.debug("empty-DB raise branch taken: %s", exc)
                assert "technique" in str(exc).lower() or "load" in str(exc).lower()
                return
            assert [e.tactic for e in result] == list(CANONICAL_TACTIC_ORDER)
            for entry in result:
                assert (entry.total, entry.detectable, entry.pct) == (0, 0, 0.0)
        finally:
            close_session(s)

    def test_zero_enabled_sources_yield_all_zero_percentages(self, sparse_session):
        cfg = base_cfg()
        cfg["enabled_log_sources"] = {fmt: False for fmt in ALL_FORMATS}
        set_formats_enabled(sparse_session, ALL_FORMATS, enabled=False)
        result, _ = compute_tactics(sparse_session, cfg)
        assert len(result) == len(CANONICAL_TACTIC_ORDER)
        for entry in result:
            assert entry.detectable == 0
            assert entry.pct == 0.0


# ---------------------------------------------------------------------------
# Integration: denominators, revocation, multi-tactic (D)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDenominators:
    def test_unmapped_alive_inscope_techniques_still_count(self, session):
        seed_datasources(session)
        hit = add_technique(session, "T1003.001")  # mapped + detectable
        add_coverage_row(session, hit, "evtx", 0.80)
        add_technique(session, "T9001")  # alive, in scope, never mapped
        add_technique(
            session, "T9002", platforms=("IaaS",)
        )  # alive but out of scope
        session.commit()

        result, rows = compute_tactics(session, base_cfg())
        entry = by_tactic(result)["execution"]
        assert entry.total == 2  # T1003.001 + T9001; IaaS technique excluded
        assert entry.detectable == 1
        assert find_row(rows, "T9001") is not None  # unmapped row visible at 0.0
        unmapped = find_row(rows, "T9001")
        assert unmapped.best_confidence == 0.0
        assert unmapped.is_detectable is False

    def test_multi_tactic_technique_counts_once_per_tactic(self, session):
        seed_datasources(session)
        dual = add_technique(
            session,
            "T1112",
            tactics=("defense-evasion", "persistence"),
        )
        add_coverage_row(session, dual, "evtx", 0.85)
        add_technique(session, "T9003", tactics=("defense-evasion",))
        session.commit()

        result, _ = compute_tactics(session, base_cfg())
        index = by_tactic(result)
        assert index["defense-evasion"].total == 2
        assert index["defense-evasion"].detectable == 1
        assert index["persistence"].total == 1
        assert index["persistence"].detectable == 1

    def test_revoked_techniques_excluded_from_totals_and_detectables(
        self, session
    ):
        seed_datasources(session)
        alive = add_technique(session, "T1059.001")
        add_coverage_row(session, alive, "evtx", 0.75)
        dead = add_technique(session, "T1562.008", revoked=True)
        add_coverage_row(session, dead, "evtx", 0.90)
        session.commit()

        result, rows = compute_tactics(session, base_cfg())
        entry = by_tactic(result)["execution"]
        assert entry.total == 1
        assert entry.detectable == 1
        dead_row = find_row(rows, "T1562.008")
        # Either the loader omits revoked rows entirely or emits them as
        # non-detectable regardless of their stored confidence.
        assert dead_row is None or dead_row.is_detectable is False


# ---------------------------------------------------------------------------
# Integration: platform scoping (B)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPlatformScope:
    @pytest.mark.parametrize(
        ("platforms", "scope", "expected_total"),
        [
            (("Windows",), "windows", 1),          # exact element, case-insensitive
            (("Windows",), "WINDOWS", 1),           # scope lowering
            (("windows",), "Windows", 1),           # platform lowering
            (("Linux", "Windows"), "linux", 1),     # membership across elements
            (("IaaS", "SaaS"), "windows", 0),       # disjoint platforms
            (("Windows Server 2019",), "windows", 0),  # exactness, NOT substring
            (("Windows",), "all", 1),               # 'all' admits everything
            (("IaaS",), "all", 1),
        ],
    )
    def test_scope_rule_elementwise_case_insensitive(
        self, session, platforms, scope, expected_total
    ):
        seed_datasources(session)
        add_technique(session, "T1018", tactics=("discovery",), platforms=platforms)
        session.commit()
        result, rows = compute_tactics(session, base_cfg(platform_scope=scope))
        assert by_tactic(result)["discovery"].total == expected_total
        row = find_row(rows, "T1018")
        if row is not None:
            assert row.scope_hit is bool(expected_total)


# ---------------------------------------------------------------------------
# Integration: threshold semantics (D, inclusive)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestThresholdSemantics:
    @pytest.fixture
    def graded_session(self, session):
        """Four credential-access techniques straddling the 0.6 bar."""
        seed_datasources(session)
        for attack_id, confidence in (
            ("T1110.001", 0.45),
            ("T1110.003", 0.51),
            ("T1555", 0.60),
            ("T1558.001", 0.75),
        ):
            sid = add_technique(
                session, attack_id, tactics=("credential-access",)
            )
            add_coverage_row(session, sid, "evtx", confidence)
        session.commit()
        return session

    def test_boundary_confidence_equals_threshold_is_detectable(
        self, graded_session
    ):
        _, rows = compute_tactics(graded_session, base_cfg())
        at_bar = find_row(rows, "T1555")
        just_below = find_row(rows, "T1110.003")
        assert at_bar.is_detectable is True      # 0.60 >= 0.60 inclusive
        assert just_below.is_detectable is False

    @pytest.mark.parametrize(
        ("threshold", "expected_ids"),
        [
            (0.30, {"T1110.001", "T1110.003", "T1555", "T1558.001"}),
            (0.50, {"T1110.003", "T1555", "T1558.001"}),   # 0.45 drops
            (0.60, {"T1555", "T1558.001"}),                 # inclusive bar
            (0.61, {"T1558.001"}),                          # 0.60 drops
            (0.90, set()),                                  # everything gaps
        ],
    )
    def test_threshold_override_recomputes_detection_set(
        self, graded_session, threshold, expected_ids
    ):
        _, rows = compute_tactics(
            graded_session,
            base_cfg(detection_confidence_threshold=threshold),
        )
        detected = {
            row.attack_id for row in rows if row.is_detectable
        }
        assert detected == expected_ids


# ---------------------------------------------------------------------------
# Integration: best-confidence MAX across enabled datasources (D)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestBestConfidenceAggregation:
    @pytest.fixture
    def triple_source_session(self, session):
        """Real T1110.001 populate outcome: evtx 0.51 / json 0.45 / zeek 0.90."""
        seed_datasources(session)
        sid = add_technique(
            session, "T1110.001", tactics=("credential-access",)
        )
        add_coverage_row(session, sid, "evtx", 0.51)   # action-only M001 projection
        add_coverage_row(session, sid, "json", 0.45)   # heuristic M080 projection
        add_coverage_row(session, sid, "zeek", 0.90)   # notice M020 projection
        session.commit()
        return session

    def test_best_confidence_is_max_over_enabled_sources(
        self, triple_source_session
    ):
        _, rows = compute_tactics(triple_source_session, base_cfg())
        row = find_row(rows, "T1110.001")
        assert row.best_confidence == pytest.approx(0.90)
        assert row.is_detectable is True
        expected_ids = tuple(
            sorted(
                add_datasource(triple_source_session, fmt).id
                for fmt in ("evtx", "json", "zeek")
            )
        )
        assert row.source_ids == expected_ids

    @pytest.mark.parametrize(
        ("disabled", "expected_best"),
        [(("zeek",), 0.51), (("zeek", "evtx"), 0.45)],
    )
    def test_disabling_a_source_lowers_the_best_score(
        self, triple_source_session, disabled, expected_best
    ):
        cfg = base_cfg()
        for fmt in disabled:
            cfg["enabled_log_sources"][fmt] = False
        # Mirror the config toggle into the DB flag the read path consumes.
        set_formats_enabled(triple_source_session, disabled, enabled=False)
        _, rows = compute_tactics(triple_source_session, cfg)
        row = find_row(rows, "T1110.001")
        assert row.best_confidence == pytest.approx(expected_best)
        assert row.is_detectable is (expected_best >= 0.6)


# ---------------------------------------------------------------------------
# Integration: percentage rounding (D)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPercentageRounding:
    @pytest.mark.parametrize(
        ("detectable_count", "expected_pct"),
        [(1, 0.3333), (2, 0.6667)],
    )
    def test_pct_rounded_to_four_decimals(
        self, session, detectable_count, expected_pct
    ):
        seed_datasources(session)
        for i in range(3):
            sid = add_technique(session, f"T900{i}", tactics=("discovery",))
            if i < detectable_count:
                add_coverage_row(session, sid, "evtx", 0.80)
        session.commit()
        result, _ = compute_tactics(session, base_cfg())
        entry = by_tactic(result)["discovery"]
        assert (entry.total, entry.detectable) == (3, detectable_count)
        assert entry.pct == pytest.approx(expected_pct)


# ---------------------------------------------------------------------------
# Integration: golden snapshot -- execution slice of the Wave-1 aggregate (I)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExecutionGoldenSnapshot:
    """Wave-1 CORE-ROW AGGREGATE execution slice, reproduced end to end.

    Drives the real ``populate_technique_coverage`` with faithful replicas
    of the nine execution-targeting mapping rules so the statically
    projected confidences are produced, not asserted-in: ext-key rules
    project x1.0 (T1059.001 wins max(M002 .70, M004 .75, M035 .75, M034
    .65) = 0.75 on evtx), action-only x0.85 (M075 -> 0.3825) and heuristic
    x0.40 (M056 -> 0.20), capped at 0.95. T1059.003 / T1047 / T1569.002
    land at 0.70. Forty-two filler windows-execution techniques complete
    the measured denominator of 46 (= 42 unmapped + 4 mapped); T1059.009
    (IaaS) and T1053.003 (non-windows platforms) sit outside that
    denominator, matching the Wave-1 finding that all four detectables
    are windows-scoped.
    """

    GOLDEN_DETECTABLE: dict[str, float] = {
        "T1059.001": 0.75,
        "T1059.003": 0.70,
        "T1047": 0.70,
        "T1569.002": 0.70,
    }
    GOLDEN_SUB_THRESHOLD: dict[str, float] = {
        "T1059.009": 0.20,      # heuristic cloudtrail rule, IaaS platform
        "T1053.003": 0.3825,    # syslog cron rule, non-windows platforms
    }

    @staticmethod
    def _execution_rules() -> tuple:
        """The nine data/attack_mappings.csv rows targeting ``execution``."""
        cradle = r"(?i)(?=.*(\.downloadstring\(|\.downloadfile\(|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b))(?=.*(\biex\b|invoke-expression))"
        return (
            build_mapping_rule(
                mapping_id="M002", source_format="evtx",
                event_action_re=r"^process_created$",
                ext_keys="newprocessname",
                ext_value_re=r'(?i)\\(powershell|pwsh|powershell_ise)\.exe"?$',
                match_type="regex", is_core=True,
                technique_id="T1059.001", tactic="execution",
                base_confidence=0.70,
            ),
            build_mapping_rule(
                mapping_id="M004", source_format="evtx",
                event_action_re=r"^process_created$",
                ext_keys="commandline", ext_value_re=cradle,
                match_type="regex", is_core=True,
                technique_id="T1059.001", tactic="execution",
                base_confidence=0.75,
            ),
            build_mapping_rule(
                mapping_id="M034", source_format="evtx",
                event_action_re=r"^process_created$",
                ext_keys="commandline",
                ext_value_re=r"(?i)(?=.*powershell).*(-version 2 )",
                match_type="regex", is_core=False,
                technique_id="T1059.001", tactic="execution",
                base_confidence=0.65,
            ),
            build_mapping_rule(
                mapping_id="M035", source_format="evtx",
                event_action_re=r"^process_created$",
                ext_keys="commandline",
                ext_value_re=(
                    r"(?i).*(::FromBase64String"
                    r"|OgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcA).*"
                ),
                match_type="regex", is_core=False,
                technique_id="T1059.001", tactic="execution",
                base_confidence=0.75,
            ),
            build_mapping_rule(
                mapping_id="M003", source_format="evtx",
                event_action_re=r"^process_created$",
                ext_keys="newprocessname", ext_value_re=r'(?i)\\cmd\.exe"?$',
                match_type="regex", is_core=True,
                technique_id="T1059.003", tactic="execution",
                base_confidence=0.70,
            ),
            build_mapping_rule(
                mapping_id="M030", source_format="evtx",
                event_action_re=r"^process_created$",
                ext_keys="newprocessname", ext_value_re=r'(?i)\\wmic\.exe"?$',
                match_type="regex", is_core=False,
                technique_id="T1047", tactic="execution",
                base_confidence=0.70,
            ),
            build_mapping_rule(
                mapping_id="M046", source_format="evtx",
                event_action_re=r"^new_service_installed$",
                ext_keys="imagepath",
                ext_value_re=(
                    r"(?i).*(powershell|%comspec%|cmd\.exe|-enc "
                    r"|-encodedcommand|rundll32|mshta).*"
                ),
                match_type="regex", is_core=False,
                technique_id="T1569.002", tactic="execution",
                base_confidence=0.70,
            ),
            build_mapping_rule(
                mapping_id="M056", source_format="aws_cloudtrail",
                event_action_re=r"^RunInstances$",
                ext_keys="request_params", ext_value_re=r"(?is).*userdata.*",
                match_type="heuristic", is_core=False,
                technique_id="T1059.009", tactic="execution",
                base_confidence=0.50,
            ),
            build_mapping_rule(
                mapping_id="M075", source_format="syslog",
                event_action_re=r"^cron(d)?(\[\d+\])?$",
                ext_keys=(), match_type="regex", is_core=False,
                technique_id="T1053.003", tactic="execution",
                base_confidence=0.45,
            ),
        )

    @pytest.fixture
    def golden_session(self, session):
        platforms_by_id = {
            "T1059.001": ("Windows",),
            "T1059.003": ("Windows",),
            "T1047": ("Windows",),
            "T1569.002": ("Windows",),
            "T1059.009": ("IaaS",),
            "T1053.003": ("Linux", "macOS"),
        }
        for attack_id, platforms in platforms_by_id.items():
            add_technique(
                session,
                attack_id,
                tactics=("execution",),
                platforms=platforms,
            )
        for i in range(42):  # unmapped alive windows-execution fillers
            add_technique(session, f"T9{i:03d}", tactics=("execution",))
        # Populate seeds its own canonical datasource_types rows.
        report = coverage_analyzer.populate_technique_coverage(
            session, self._execution_rules(), base_cfg()
        )
        # Fixture-wiring sanity only; counters are the populate suite's job.
        assert report.rows_inserted == 6
        assert report.skipped_revoked == ()
        assert report.skipped_orphan == ()
        session.commit()
        return session

    def test_execution_entry_matches_golden_snapshot(self, golden_session):
        result, _ = compute_tactics(golden_session, base_cfg())
        entry = by_tactic(result)["execution"]
        assert entry.total == 46
        assert entry.detectable == 4
        assert entry.pct == pytest.approx(round(4 / 46, 4))

    def test_golden_detectable_ids_and_scores(self, golden_session):
        _, rows = compute_tactics(golden_session, base_cfg())
        detected = {r.attack_id: r.best_confidence for r in rows if r.is_detectable}
        assert set(detected) == set(self.GOLDEN_DETECTABLE)
        for attack_id, expected in self.GOLDEN_DETECTABLE.items():
            assert detected[attack_id] == pytest.approx(expected)
        for attack_id, expected in self.GOLDEN_SUB_THRESHOLD.items():
            row = find_row(rows, attack_id)
            assert row is not None
            assert row.best_confidence == pytest.approx(expected)
            assert row.is_detectable is False

    def test_other_tactics_remain_at_zero_in_snapshot(self, golden_session):
        result, _ = compute_tactics(golden_session, base_cfg())
        recon = by_tactic(result)["resource-development"]
        assert (recon.total, recon.detectable, recon.pct) == (0, 0, 0.0)


# ---------------------------------------------------------------------------
# Integration: determinism + partition invariant (A/D)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDeterminismAndPartitions:
    @pytest.fixture
    def mixed_session(self, session):
        """Several tactics with mapped, unmapped, revoked and off-scope rows."""
        seed_datasources(session)
        spec = (
            ("T1059.001", ("execution",), ("Windows",), False, (("evtx", 0.75),)),
            ("T1003.001", ("credential-access",), ("Windows",), False, (("evtx", 0.85), ("json", 0.60))),
            ("T1078", ("defense-evasion", "persistence"), ("Windows",), False, ()),
            ("T1112", ("defense-evasion",), ("Windows",), False, (("zeek", 0.55),)),
            ("T1650", ("reconnaissance",), ("Windows",), True, (("evtx", 0.99),)),
            ("T1557", ("collection", "credential-access"), ("Linux",), False, (("syslog", 0.65),)),
        )
        for attack_id, tactics, platforms, revoked, cov_rows in spec:
            sid = add_technique(
                session,
                attack_id,
                tactics=tactics,
                platforms=platforms,
                revoked=revoked,
            )
            for fmt, confidence in cov_rows:
                add_coverage_row(session, sid, fmt, confidence)
        session.commit()
        return session

    def test_repeated_calls_are_identical_and_hashable(self, mixed_session):
        first, rows_first = compute_tactics(mixed_session, base_cfg())
        second, rows_second = compute_tactics(mixed_session, base_cfg())
        assert first == second
        assert hash(first) == hash(second)  # native hashability, contract A
        assert hash(rows_first) == hash(rows_second)
        assert rows_first == rows_second

    def test_every_tactic_entry_matches_independent_recomputation(
        self, mixed_session
    ):
        """Oracle: recompute contract-D aggregates straight from the DB."""
        result, _ = compute_tactics(mixed_session, base_cfg())
        techniques = mixed_session.scalars(select(Technique)).all()
        coverage_by_pair: dict[tuple[str, str], float] = {}
        ds_format_by_id = {
            ds.id: ds.log_format
            for ds in mixed_session.scalars(select(DataSourceType))
        }
        for cov in mixed_session.scalars(select(TechniqueCoverage)):
            fmt = ds_format_by_id[cov.datasource_id]
            if not mixed_session.get(Technique, cov.technique_stix_id):
                continue
            key = (cov.technique_stix_id, fmt)
            coverage_by_pair[key] = max(
                coverage_by_pair.get(key, 0.0), cov.detection_confidence
            )

        expected: dict[str, tuple[int, int]] = {
            tactic: [0, 0] for tactic in CANONICAL_TACTIC_ORDER
        }
        cfg = base_cfg()
        threshold = float(cfg["detection_confidence_threshold"])
        scope = str(cfg["platform_scope"]).lower()
        for tech in techniques:
            if tech.revoked:
                continue
            platforms = {str(p).lower() for p in (tech.platforms or [])}
            if scope != "all" and scope not in platforms:
                continue
            best = max(
                (
                    conf
                    for (sid, fmt), conf in coverage_by_pair.items()
                    if sid == tech.stix_id
                    and cfg["enabled_log_sources"].get(fmt, True) is not False
                ),
                default=0.0,
            )
            for tactic in tech.tactics or []:
                bucket = expected[tactic]
                bucket[0] += 1
                bucket[1] += int(best >= threshold)

        for entry in result:
            total, detectable = expected[entry.tactic]
            assert (entry.total, entry.detectable) == (total, detectable)
            pct = round(detectable / total, 4) if total else 0.0
            assert entry.pct == pytest.approx(pct)


# ---------------------------------------------------------------------------
# Integration: full real bundle, structural invariants only
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRealBundleEndToEnd:
    """Offline full-stack run: cached bundle -> fresh DB -> tactic coverage.

    Absolute tactic totals are intentionally NOT pinned: the loader's
    deprecation fold (contract G) legitimately moves techniques out of the
    alive pool relative to Wave-1 measurements. Instead each entry is
    checked against an independent recomputation, and the canonical shape
    and ordering are asserted exactly.
    """

    @pytest.fixture(scope="class")
    def bundle_session(self, tmp_path_factory):
        from attack_data.client import DEFAULT_CACHE
        from attack_data.loader import load_all

        if not DEFAULT_CACHE.is_file():
            pytest.skip("offline ATT&CK STIX cache missing; refusing network")
        engine = create_engine(
            f"sqlite:///{tmp_path_factory.mktemp('bundle') / 'cov.db'}"
        )
        Base.metadata.create_all(engine)
        session = Session(engine)
        report = load_all(session)
        session.commit()
        logger.info(
            "bundle load for coverage test: %s (warnings=%d)",
            report.counts,
            report.warnings,
        )
        yield session
        session.close()
        engine.dispose()

    def test_real_bundle_tactic_coverage_matches_oracle(self, bundle_session):
        result, _ = compute_tactics(bundle_session, base_cfg())
        assert [entry.tactic for entry in result] == list(CANONICAL_TACTIC_ORDER)

        techniques = bundle_session.scalars(select(Technique)).all()
        cfg = base_cfg()
        threshold = float(cfg["detection_confidence_threshold"])
        scope = str(cfg["platform_scope"]).lower()
        # Nothing is populated yet, so every technique is a gap: numerators 0.
        for entry in result:
            assert entry.detectable == 0
            assert entry.pct == 0.0
            expected_total = sum(
                1
                for tech in techniques
                if not tech.revoked
                and tactic_in(tech, entry.tactic)
                and scope_in(tech.platforms, scope)
            )
            assert entry.total == expected_total
        assert sum(entry.total for entry in result) > 0
        # v19 phase-alias smoke: defense-evasion must be non-empty post-fix.
        assert by_tactic(result)["defense-evasion"].total > 0


def tactic_in(tech: Technique, tactic: str) -> bool:
    """Whether a loaded technique carries ``tactic`` in its JSON list."""
    return tactic in (tech.tactics or [])


def scope_in(platforms: Any, scope: str) -> bool:
    """Contract-B predicate: 'all' or lowered element-wise membership."""
    if scope == "all":
        return True
    return scope in {str(p).lower() for p in (platforms or [])}
