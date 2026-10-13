"""test_coverage_gaps.py -- Phase-3 coverage-engine semantics and gap contracts.

Exercises ``src/analysis/coverage_analyzer.py`` end-to-end over a synthetic
SQLite database (built here; the real ``db/coverage.db`` is never touched) and
pins the Wave-2 hard contracts:

- **(A) Hashability**: every analyzer return object is a frozen dataclass
  whose fields are only ``None|bool|int|float|str|tuple`` or nested frozen
  dataclasses -- collections are tuples at every nesting depth, so the
  results are natively hashable (Streamlit ``st.cache_data`` contract).
- **(B) Platform scope**: a technique's ``scope_hit`` is true iff
  ``platform_scope == 'all'`` or ``scope.lower()`` equals one of the
  technique's lowered platform strings (element-wise, case-insensitive).
- **(D) Coverage semantics**: ``best_confidence`` = MAX across enabled
  datasource rows (disabled-source rows ignored even if present);
  ``is_detectable`` is inclusive at the threshold; tactic denominators count
  ALL in-scope, non-revoked per-(technique, tactic) rows (multi-tactic
  techniques count once per tactic); all 14 Enterprise tactics are emitted
  even at 0%, ordered canonically.
- **(E) Gaps**: ``calculate_coverage_gaps`` returns in-scope, non-detectable
  rows sorted by ``(canonical tactic, best_confidence asc, attack_id)`` with
  the honest ``closable_by`` filter: a disabled format qualifies only when
  some mapping rule belongs to it AND its statically-projected best score
  (``base * tier_mult``, tiers 1.0 / 0.85 / 0.40, cap 0.95) reaches the
  threshold. Measured golden case from Wave 1: naive any-mapping logic would
  promise ``cef`` closes things it cannot (projections 0.25-0.38), while
  ``T1190`` genuinely closes via disabled ``nginx`` (rules at 0.75 / 0.60).

Golden expectations mirror ``research/p3-wave1-full-results.md`` (CORE-ROW
AGGREGATE agent-225 and per-tactic ground truth agent-165): the four
detectable execution techniques are exactly ``T1059.001 / T1059.003 / T1047 /
T1569.002`` at 0.70-0.75, with tier-3 ``T1059.009`` (0.50 x 0.40 = 0.20) and
tier-2 ``T1053.003`` (0.45 x 0.85 = 0.3825) left undetected. Absolute tactic
totals differ from the live 591-platform DB (this suite uses a small
synthetic denominator) but every ratio/borderline semantic is identical.

The revoked-skip behaviour demanded by contract (C)/(I) for ``M016 ->
T1562.008`` is asserted on the analyzer side: whatever wrote a stale
coverage row pointing at a revoked technique, the analyzer must exclude it
from every total, percentage and gap.

Everything is offline; no network, no real ATT&CK bundle, no hunt queries.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
from pathlib import Path
from typing import Any, Mapping, Sequence

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from analysis import coverage_analyzer as ca
from database.models import (
    Base,
    DataSourceType,
    Technique,
    TechniqueCoverage,
)
from tests.conftest import build_mapping_rule

logger = logging.getLogger(__name__)

pytestmark = pytest.mark.integration

#: Canonical ATT&CK Enterprise tactic order (contract D); the analyzer must
#: emit exactly this sequence, including zero-total tactics. Mirrors
#: ``coverage_analyzer.CANONICAL_TACTICS`` -- duplicated here so a drift in
#: either constant fails loudly instead of silently agreeing.
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

#: Formats switched OFF, mirroring the shipped ``config.yaml`` posture.
DISABLED_FORMATS: frozenset[str] = frozenset({"cef", "leef", "nginx"})
ENABLED_FORMATS: tuple[str, ...] = (
    "evtx",
    "syslog",
    "json",
    "aws_cloudtrail",
    "zeek",
)

_THRESHOLD = 0.6


# ---------------------------------------------------------------------------
# Config / DB builders
# ---------------------------------------------------------------------------

def _make_cfg(**overrides: Any) -> dict[str, Any]:
    """Fresh config dict equivalent to the shipped ``config.yaml``.

    Keyword overrides replace top-level keys wholesale (e.g.
    ``platform_scope="all"``, ``detection_confidence_threshold=0.71``).
    """
    cfg: dict[str, Any] = {
        "platform_scope": "windows",
        "detection_confidence_threshold": _THRESHOLD,
        "enabled_log_sources": {
            **{fmt: True for fmt in ENABLED_FORMATS},
            **{fmt: False for fmt in DISABLED_FORMATS},
        },
    }
    cfg.update(overrides)
    return cfg


def _add_technique(
    session: Session,
    attack_id: str,
    *,
    tactics: Sequence[str] = (),
    platforms: Sequence[str] = ("Windows",),
    revoked: bool = False,
    name: str | None = None,
) -> Technique:
    """Insert one synthetic technique; STIX id derived from the ATTACK id."""
    row = Technique(
        stix_id=f"attack-pattern--synthetic-{attack_id.lower()}",
        attack_id=attack_id,
        name=name or f"Technique {attack_id}",
        description=f"Synthetic fixture technique {attack_id}",
        tactics=list(tactics),
        platforms=list(platforms),
        detection_strategy_refs=[],
        is_subtechnique="." in attack_id,
        parent_attack_id=attack_id.split(".")[0] if "." in attack_id else None,
        revoked=revoked,
    )
    session.add(row)
    return row


def _add_datasource(
    session: Session, log_format: str, *, enabled: bool = True
) -> DataSourceType:
    """Insert one ``DataSourceType`` for ``log_format``."""
    row = DataSourceType(
        name=log_format, log_format=log_format, priority=0, enabled=enabled
    )
    session.add(row)
    session.flush()  # assign PK before coverage rows reference it
    return row


def _add_cov(
    session: Session,
    attack_id: str,
    datasource: DataSourceType,
    confidence: float,
) -> TechniqueCoverage:
    """Insert one stored coverage pair as populate would have written it."""
    row = TechniqueCoverage(
        technique_stix_id=f"attack-pattern--synthetic-{attack_id.lower()}",
        technique_attack_id=attack_id,
        datasource_id=datasource.id,
        is_detectable=confidence >= _THRESHOLD,
        detection_confidence=confidence,
        required_fields=[],
    )
    session.add(row)
    return row


def _seed_standard_db(session: Session) -> None:
    """Populate the full synthetic universe used by most tests.

    Layout (all Windows-scoped unless noted; ``windows`` scope, thr 0.6):

    ==========  ========================  =========================  ========
    technique   tactic(s)                 coverage (format: conf)    result
    ==========  ========================  =========================  ========
    T1595       reconnaissance            --                         gap
    T1583       resource-development      --                         gap
    T1190       initial-access            --                         gap nginx
    T1059.001   execution                 evtx:0.75                  detected
    T1059.003   execution                 evtx:0.70                  detected
    T1047       execution                 evtx:0.70                  detected
    T1569.002   execution                 evtx:0.70                  detected
    T1059.009   execution Win+Linux       aws_cloudtrail:0.20        gap
    T1106       execution                 --                         gap
    T1204       execution                 --                         gap
    T1053.003   execution Linux-only      syslog:0.3825              out-of-
                                                                     scope
    T1505.003   persistence               --                         gap
    T1078       defense-evasion +         evtx:0.65                  detected
                privilege-escalation                                 in both
    T1036       defense-evasion           --                         gap ()
    T1562.008   defense-evasion           evtx:0.90 (stale pair)     REVOKED
    T1110       credential-access         cloud:0.70, evtx:0.50,     detected
                                          leef:0.90 (row on a        @0.70
                                          DISABLED source)
    T1110.001   credential-access         evtx:0.60                  detected
                                                                     (>= bar)
    T1558       credential-access         --                         gap
    T9999       discovery macOS-only      --                         out-of-
                                                                     scope
    ==========  ========================  =========================  ========

    The T1562.008 row encodes the M016-revoked-target situation from
    ``research/p3-wave1-full-results.md``: the analyzer must exclude revoked
    techniques from every aggregate regardless of stored rows.
    """
    # Datasources: enabled flags mirror the config posture so the DB join
    # and the config keys can never disagree silently.
    ds = {
        fmt: _add_datasource(session, fmt, enabled=(fmt not in DISABLED_FORMATS))
        for fmt in (*ENABLED_FORMATS, *DISABLED_FORMATS)
    }

    _add_technique(session, "T1595", tactics=["reconnaissance"])
    _add_technique(session, "T1583", tactics=["resource-development"])
    _add_technique(session, "T1190", tactics=["initial-access"])
    for attack_id in ("T1059.001", "T1059.003", "T1047", "T1569.002"):
        _add_technique(session, attack_id, tactics=["execution"])
    _add_technique(
        session, "T1059.009", tactics=["execution"], platforms=["Windows", "Linux"]
    )
    _add_technique(session, "T1106", tactics=["execution"])
    _add_technique(session, "T1204", tactics=["execution"])
    _add_technique(session, "T1053.003", tactics=["execution"], platforms=["Linux"])
    _add_technique(session, "T1505.003", tactics=["persistence"])
    _add_technique(
        session, "T1078", tactics=["defense-evasion", "privilege-escalation"]
    )
    _add_technique(session, "T1036", tactics=["defense-evasion"])
    _add_technique(session, "T1562.008", tactics=["defense-evasion"], revoked=True)
    _add_technique(session, "T1110", tactics=["credential-access"])
    _add_technique(session, "T1110.001", tactics=["credential-access"])
    _add_technique(session, "T1558", tactics=["credential-access"])
    _add_technique(session, "T9999", tactics=["discovery"], platforms=["macOS"])

    _add_cov(session, "T1059.001", ds["evtx"], 0.75)
    _add_cov(session, "T1059.003", ds["evtx"], 0.70)
    _add_cov(session, "T1047", ds["evtx"], 0.70)
    _add_cov(session, "T1569.002", ds["evtx"], 0.70)
    _add_cov(session, "T1059.009", ds["aws_cloudtrail"], 0.20)
    _add_cov(session, "T1053.003", ds["syslog"], 0.3825)
    _add_cov(session, "T1078", ds["evtx"], 0.65)
    # Stale row against a revoked technique (populate deletes such pairs;
    # kept here to prove the read path filters independently).
    _add_cov(session, "T1562.008", ds["evtx"], 0.90)
    # Max-across-enabled-sources case; the leef row sits on a DISABLED
    # datasource and must never win (nor leak into best_confidence).
    _add_cov(session, "T1110", ds["aws_cloudtrail"], 0.70)
    _add_cov(session, "T1110", ds["evtx"], 0.50)
    _add_cov(session, "T1110", ds["leef"], 0.90)
    _add_cov(session, "T1110.001", ds["evtx"], 0.60)

    session.commit()


# ---------------------------------------------------------------------------
# Mapping rules for the closable_by scenarios
# ---------------------------------------------------------------------------

def _closability_rules() -> tuple:
    """Mapping rules reproducing the Wave-1 measured ``closable_by`` cases.

    - Two ``nginx`` rules for T1190 (disabled format): an extension-key rule
      at 0.75 (static tier 1, x1.0) and a boundary rule at exactly 0.60 --
      the honest filter closes inclusively, so ``closable_by=('nginx',)``.
    - One ``cef`` action-only rule for T1036 (disabled format): static tier 2
      projects 0.45 x 0.85 = 0.3825 < 0.6, so the mapping exists yet must
      NOT be promised -- ``closable_by=()`` (the anti-"false hope" case).
    """
    return (
        build_mapping_rule(
            mapping_id="SYNTH-M082",
            source_format="nginx",
            event_action_re=r"^POST 403$",
            ext_keys=("request",),
            ext_value_re=r"wp-admin",
            technique_id="T1190",
            tactic="initial-access",
            base_confidence=0.75,
        ),
        build_mapping_rule(
            mapping_id="SYNTH-M083",
            source_format="nginx",
            event_action_re=r"^GET 404$",
            ext_keys=("request",),
            technique_id="T1190",
            tactic="initial-access",
            base_confidence=0.60,
        ),
        build_mapping_rule(
            mapping_id="SYNTH-MCEF",
            source_format="cef",
            event_action_re=r"deny",
            ext_keys=(),
            technique_id="T1036",
            tactic="defense-evasion",
            base_confidence=0.45,
        ),
    )


# ---------------------------------------------------------------------------
# Thin wrappers around the analyzer entry points (single place that knows
# the argument order; every test reads declaratively).
# ---------------------------------------------------------------------------

def _load_rows(session: Session, cfg: Mapping[str, Any]):
    """Call ``load_coverage_rows(session, config)``."""
    return ca.load_coverage_rows(session, cfg)


def _tactics(rows):
    """Call ``coverage_by_tactic(rows)``."""
    return ca.coverage_by_tactic(rows)


def _gaps(rows, cfg: Mapping[str, Any], rules: tuple = ()):
    """Call ``calculate_coverage_gaps(rows, rules, config)``."""
    return ca.calculate_coverage_gaps(rows, rules, cfg)


def _gap_map(gaps) -> dict[str, Any]:
    """Index gaps by ATTACK id (unique unless a multi-tactic technique is
    undetected in more than one tactic -- only ever read for single-tactic
    techniques or membership/order checks below)."""
    return {gap.technique_attack_id: gap for gap in gaps}


def _tc_map(tactics) -> dict[str, Any]:
    return {entry.tactic: entry for entry in tactics}


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def seeded_session(tmp_path: Path):
    """File-backed SQLite session pre-seeded with :func:`_seed_standard_db`.

    A temp file (rather than ``sqlite://``) sidesteps in-memory pooling
    pitfalls: the analyzer may open its own connection to the same URL.
    """
    engine = create_engine(f"sqlite:///{tmp_path / 'coverage_fixture.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    _seed_standard_db(session)
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def standard_cfg() -> dict[str, Any]:
    """Shipped-posture config (windows scope, thr 0.6, 5 sources enabled)."""
    return _make_cfg()


@pytest.fixture
def standard_rows(seeded_session, standard_cfg):
    """Rows loaded once from the standard fixture DB."""
    return _load_rows(seeded_session, standard_cfg)


@pytest.fixture
def standard_tactics(standard_rows):
    """Tactic rollup computed once from :data:`standard_rows`."""
    return _tactics(standard_rows)


# ---------------------------------------------------------------------------
# Contract B -- platform scoping
# ---------------------------------------------------------------------------

def test_platform_scope_element_wise_case_insensitive(seeded_session):
    """Scope matching is element-wise and case-insensitive (contract B)."""
    rows = _load_rows(seeded_session, _make_cfg(platform_scope="WiNdOwS"))
    hit = {row.attack_id for row in rows if row.scope_hit}
    # Windows-flagged techniques in; the Linux-only T1053.003 and the
    # macOS-only T9999 stay out.
    assert "T1059.001" in hit
    assert "T1053.003" not in hit
    assert "T9999" not in hit


def test_platform_scope_all_includes_every_platform(seeded_session):
    """scope='all' puts every platform's alive techniques in scope."""
    rows = _load_rows(seeded_session, _make_cfg(platform_scope="all"))
    hit = {row.attack_id for row in rows if row.scope_hit}
    assert {"T1053.003", "T9999"} <= hit


def test_platform_scope_mismatch_excludes_technique(seeded_session):
    """Only macOS-flagged rows carry scope_hit under a macOS scope."""
    rows = _load_rows(seeded_session, _make_cfg(platform_scope="macOS"))
    hit = {row.attack_id for row in rows if row.scope_hit}
    assert hit == {"T9999"}


# ---------------------------------------------------------------------------
# Contract D -- per-technique semantics
# ---------------------------------------------------------------------------

def test_best_confidence_is_max_over_enabled_sources_only(standard_rows):
    """best_confidence = MAX across enabled rows; disabled rows ignored."""
    by_id = {row.attack_id: row for row in standard_rows}
    assert by_id["T1110"].best_confidence == pytest.approx(0.70)
    assert by_id["T1110"].is_detectable is True


def test_threshold_boundary_is_inclusive(standard_rows):
    """0.60 exactly meets the 0.6 bar ('at or above', inclusive)."""
    by_id = {row.attack_id: row for row in standard_rows}
    assert by_id["T1110.001"].best_confidence == pytest.approx(0.60)
    assert by_id["T1110.001"].is_detectable is True


def test_raised_threshold_flips_borderline_to_gap(seeded_session):
    """Raising the bar to 0.71 demotes every <=0.70 technique to a gap."""
    cfg = _make_cfg(detection_confidence_threshold=0.71)
    rows = _load_rows(seeded_session, cfg)
    by_id = {row.attack_id: row for row in rows}
    assert by_id["T1059.001"].is_detectable is True  # 0.75 survives
    assert by_id["T1110"].is_detectable is False  # 0.70 drops
    assert by_id["T1110.001"].is_detectable is False  # 0.60 drops
    gap_ids = {gap.technique_attack_id for gap in _gaps(rows, cfg)}
    assert {"T1110", "T1110.001"} <= gap_ids


# ---------------------------------------------------------------------------
# Contract D -- tactic aggregates
# ---------------------------------------------------------------------------

def test_canonical_constants_agree_with_implementation():
    """The suite's canonical order must equal the analyzer's constant."""
    assert CANONICAL_TACTICS == tuple(ca.CANONICAL_TACTICS)


def test_all_fourteen_tactics_emitted_in_canonical_order(standard_tactics):
    """Every Enterprise tactic appears exactly once, canonically ordered."""
    assert isinstance(standard_tactics, tuple)
    assert tuple(entry.tactic for entry in standard_tactics) == CANONICAL_TACTICS


def test_zero_total_tactics_still_reported(standard_tactics):
    """Unmapped tactics (discovery..impact) emit 0/0/0.0, never dropped."""
    tc = _tc_map(standard_tactics)
    for tactic in (
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    ):
        entry = tc[tactic]
        assert (entry.total, entry.detectable, entry.pct) == (0, 0, 0.0)


def test_execution_matches_wave1_golden_shape(standard_rows, standard_tactics):
    """Execution: exactly the four Wave-1 detectable ids over the full
    in-scope-alive denominator (golden: 4 detectable; here denominator 7 --
    T1053.003 is Linux-out-of-scope and T1562.008 is not an execution row).

    Absolute totals differ from the live 46-technique DB by construction of
    the fixture; the pinned semantic is the denominator rule itself: ALL
    in-scope alive techniques tagged execution count, mapped or not.
    """
    scoped_alive_execution = {
        "T1059.001",
        "T1059.003",
        "T1047",
        "T1569.002",
        "T1059.009",
        "T1106",
        "T1204",
    }
    execution_gap_ids = {
        gap.technique_attack_id
        for gap in _gaps(standard_rows, _make_cfg())
        if gap.tactic == "execution"
    }
    detectable_ids = scoped_alive_execution - execution_gap_ids
    assert detectable_ids == {"T1059.001", "T1059.003", "T1047", "T1569.002"}

    entry = _tc_map(standard_tactics)["execution"]
    assert entry.total == 7  # 4 detectable + T1059.009 + T1106 + T1204
    assert entry.detectable == 4
    assert entry.pct == pytest.approx(4 / 7, rel=1e-3)


def test_multi_tactic_technique_counts_once_per_tactic(standard_tactics):
    """T1078 (defense-evasion + privilege-escalation) feeds both buckets."""
    tc = _tc_map(standard_tactics)
    assert tc["defense-evasion"].total == 2  # T1078 + T1036
    assert tc["defense-evasion"].detectable == 1  # T1078 only
    assert tc["privilege-escalation"].total == 1
    assert tc["privilege-escalation"].detectable == 1


def test_revoked_technique_excluded_everywhere(standard_rows, standard_tactics):
    """Revoked T1562.008 leaks into no total, pct, or gap (M016 contract)."""
    gap_ids = {gap.technique_attack_id for gap in _gaps(standard_rows, _make_cfg())}
    assert "T1562.008" not in gap_ids
    tc = _tc_map(standard_tactics)
    # Without the revoked row, defense-evasion is T1078 (det) + T1036 (gap).
    assert tc["defense-evasion"].total == 2
    assert tc["defense-evasion"].detectable == 1


def test_out_of_scope_excluded_from_denominator_and_gaps(
    standard_rows, standard_tactics
):
    """Linux/macOS techniques vanish from windows aggregates entirely."""
    tc = _tc_map(standard_tactics)
    assert tc["execution"].total == 7  # T1053.003 (Linux) not counted
    assert tc["discovery"].total == 0  # T9999 (macOS) not counted
    gap_ids = {gap.technique_attack_id for gap in _gaps(standard_rows, _make_cfg())}
    assert "T1053.003" not in gap_ids
    assert "T9999" not in gap_ids


def test_pcts_are_fractions_of_alive_in_scope_totals(standard_tactics):
    """credential-access: 2 detectable / 3 in-scope alive = 0.6667."""
    entry = _tc_map(standard_tactics)["credential-access"]
    assert entry.total == 3
    assert entry.detectable == 2
    assert entry.pct == pytest.approx(2 / 3, rel=1e-3)


# ---------------------------------------------------------------------------
# Contract E -- gaps
# ---------------------------------------------------------------------------

def test_gap_set_is_exactly_the_scoped_misses(standard_rows):
    """gaps = in-scope, alive, not detectable -- nothing more, nothing less."""
    gap_ids = {gap.technique_attack_id for gap in _gaps(standard_rows, _make_cfg())}
    assert gap_ids == {
        "T1595",
        "T1583",
        "T1190",
        "T1059.009",
        "T1106",
        "T1204",
        "T1505.003",
        "T1036",
        "T1558",
    }


def test_gaps_sorted_total_order(standard_rows):
    """Canonical tactic blocks, confidence asc within, id asc on ties."""
    gaps = _gaps(standard_rows, _make_cfg())
    rank = {name: idx for idx, name in enumerate(CANONICAL_TACTICS)}
    tactic_ranks = [rank[gap.tactic] for gap in gaps]
    assert tactic_ranks == sorted(tactic_ranks)
    keys = [
        (rank[gap.tactic], gap.best_confidence, gap.technique_attack_id)
        for gap in gaps
    ]
    assert keys == sorted(keys)
    # And the concrete golden sequence for this fixture universe.
    assert [gap.technique_attack_id for gap in gaps] == [
        "T1595",        # reconnaissance, 0.0
        "T1583",        # resource-development, 0.0
        "T1190",        # initial-access, 0.0
        "T1106",        # execution, 0.0 (id tie-break before T1204)
        "T1204",        # execution, 0.0
        "T1059.009",    # execution, 0.20 near-miss trails the block
        "T1505.003",    # persistence, 0.0
        "T1036",        # defense-evasion, 0.0
        "T1558",        # credential-access, 0.0
    ]


def test_unmapped_technique_is_zero_confidence_gap(standard_rows):
    """An in-scope technique with no coverage row at all is a 0.0 gap."""
    gap = _gap_map(_gaps(standard_rows, _make_cfg()))["T1190"]
    assert gap.best_confidence == pytest.approx(0.0)
    assert gap.name == "Technique T1190"
    assert gap.tactic == "initial-access"


def test_closable_by_honest_filter(standard_rows):
    """Disabled formats close a gap only when statically projected >= bar.

    Golden measured cases (Wave 1, agent-195): T1190 closes via nginx
    (0.75 and boundary 0.60 rules); T1036's existing cef mapping projects
    0.45 x 0.85 = 0.3825 < 0.6 so closable_by stays empty despite the
    mapping existing.
    """
    gaps = _gap_map(_gaps(standard_rows, _make_cfg(), _closability_rules()))
    assert gaps["T1190"].closable_by == ("nginx",)
    assert gaps["T1036"].closable_by == ()


def test_closable_by_empty_rules_has_no_false_promises(standard_rows):
    """Without rule context every closable_by is an empty sorted subset."""
    gaps = _gaps(standard_rows, _make_cfg())
    for gap in gaps:
        assert gap.closable_by == ()
        assert isinstance(gap.closable_by, tuple)


# ---------------------------------------------------------------------------
# Fail-closed edges
# ---------------------------------------------------------------------------

def test_zero_enabled_sources_fail_closed(seeded_session):
    """All sources disabled: everything in scope becomes a gap, pcts 0.0.

    Mirrors the production pipeline where populate mirrors the config into
    ``DataSourceType.enabled``: the test flips those flags exactly as
    populate would before reading.
    """
    for ds in seeded_session.query(DataSourceType).all():
        ds.enabled = False
    seeded_session.commit()

    cfg = _make_cfg(enabled_log_sources={fmt: False for fmt in (*ENABLED_FORMATS,
                                                                 *DISABLED_FORMATS)})
    rows = _load_rows(seeded_session, cfg)
    tactics = _tactics(rows)
    assert all(entry.pct == 0.0 and entry.detectable == 0 for entry in tactics)
    gaps = _gaps(rows, cfg)
    # Every alive in-scope technique must surface as a gap (id-level check:
    # robust whether multi-tactic techniques yield one record or several).
    assert {gap.technique_attack_id for gap in gaps} == {
        "T1595", "T1583", "T1190",
        "T1059.001", "T1059.003", "T1047", "T1569.002", "T1059.009",
        "T1106", "T1204",
        "T1505.003", "T1078", "T1036",
        "T1110", "T1110.001", "T1558",
    }


def test_empty_database_yields_zero_state(tmp_path: Path):
    """Schema without data: all-zero tactics, empty gap tuple, no raise."""
    engine = create_engine(f"sqlite:///{tmp_path / 'empty.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        cfg = _make_cfg()
        rows = _load_rows(session, cfg)
        assert rows == ()
        tactics = _tactics(rows)
        assert tuple(entry.tactic for entry in tactics) == CANONICAL_TACTICS
        assert all(entry.total == 0 and entry.pct == 0.0 for entry in tactics)
        assert _gaps(rows, cfg) == ()
    finally:
        session.close()
        engine.dispose()


def test_missing_schema_returns_no_rows(tmp_path: Path):
    """A database without the Phase-1 tables degrades to () instead of raising."""
    engine = create_engine(f"sqlite:///{tmp_path / 'schemaless.db'}")
    session = sessionmaker(bind=engine)()
    try:
        assert _load_rows(session, _make_cfg()) == ()
    finally:
        session.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# Contract A -- hashability / cache stability
# ---------------------------------------------------------------------------

_ALLOWED_LEAVES = (type(None), bool, int, float, str)


def _assert_contract_a(value: Any, trail: str = "root") -> None:
    """Recursively enforce contract (A) on an analyzer return value.

    Leaves must be None/bool/int/float/str; collections must be tuples at
    every depth; nested dataclasses must be frozen and recursed into.
    """
    if isinstance(value, _ALLOWED_LEAVES):
        return
    if isinstance(value, tuple):
        for idx, item in enumerate(value):
            _assert_contract_a(item, f"{trail}[{idx}]")
        return
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        params = getattr(value, "__dataclass_params__", None)
        assert params is not None and params.frozen, f"{trail} not frozen"
        for field in dataclasses.fields(value):
            _assert_contract_a(getattr(value, field.name), f"{trail}.{field.name}")
        return
    pytest.fail(
        f"contract A violated at {trail}: disallowed type "
        f"{type(value).__name__} (list/dict/set are forbidden)"
    )


def test_gap_and_tactic_records_hashable(standard_rows, standard_tactics):
    """Both public results satisfy contract A and hash natively."""
    rules = _closability_rules()
    cfg = _make_cfg()
    tactics = standard_tactics
    gaps = _gaps(standard_rows, cfg, rules)
    _assert_contract_a(tactics, "tactics")
    _assert_contract_a(gaps, "gaps")
    # Native hash must succeed for cache_data keying; exercise it for real.
    assert isinstance(hash(tactics), int)
    assert isinstance(hash(gaps), int)
    digest = hashlib.sha256(repr((tactics, gaps)).encode("utf-8")).hexdigest()
    logger.debug("fixture result fingerprint: %s", digest)


def test_repeated_calls_are_deterministic(seeded_session, standard_cfg):
    """Identical inputs give byte-identical results across calls."""
    rows = _load_rows(seeded_session, standard_cfg)
    first = (_tactics(rows), _gaps(rows, standard_cfg, _closability_rules()))
    second = (_tactics(rows), _gaps(rows, standard_cfg, _closability_rules()))
    assert repr(first) == repr(second)
    assert first[0] == second[0]
    assert first[1] == second[1]


def test_gap_records_survive_dict_keying(standard_rows):
    """Frozen gap records work as dictionary keys (downstream cache pattern)."""
    gaps = _gaps(standard_rows, _make_cfg())
    keyed = {gap: idx for idx, gap in enumerate(gaps)}
    assert len(keyed) == len(gaps)
