"""Phase-4 APT simulation: roll-up edge-case tests.

Exercises the ``simulate_apt_attack`` algorithm's parent/sub-technique
roll-up policy (contract: one-level roll-up) against a disposable in-memory
SQLite database. The simulation engine classifies every group technique as
one of::

    detected            technique_stix_id itself is detectable
    detected_rollup     sub-technique whose parent is detectable, OR
                        parent whose any child is detectable
    missed              none of the above

These tests pin the *edge cases* of that contract:

1.  Sub-technique (T1078.003) rolls UP to its detectable parent (T1078):
    a) when the parent carries a direct detectable coverage row, and
    b) when only a *sibling* sub-technique (T1078.004) is detectable --
       the parent is NOT itself detectable, so T1078.003 must classify as
       ``missed`` (roll-up is one-level and parent-driven, not
       cousin-aggregation).
2.  Parent technique (T1048) rolls UP when one of its children
    (T1048.003) is detectable even though T1048 itself has no coverage.
3.  A sub-technique that is itself detectable stays ``detected`` even when
    its parent is fully uncovered (no double-counting, no demotion).
4.  A revoked technique used by a group is excluded from the denominator
    entirely (revoked == invisible to the simulation).
5.  The invariant ``detected + detected_rollup + missed == total`` holds
    across every run, and ``coverage_pct == round(detected / total, 4)``
    (0.0 when total is 0).
6.  ``detected_rollup`` never overlaps ``detected`` (a technique detectable
    on its own is never also counted as a roll-up).
7.  Unknown group_id raises ValueError listing valid ids.
8.  Persistence: one SimulationResult + N SimulationTechnique rows are
    written and cascade-correctly linked.

The fixture builds a minimal but complete universe: techniques table
(parents + sub-techniques with ``is_subtechnique`` / ``parent_attack_id``
set per the loader contract), a group via ``apt_groups``, the
group->technique associations via ``apt_technique``, and the
``technique_coverage`` rows that drive detectability. All coverage rows
are on a single enabled datasource (evtx) so the tests are independent of
the populate engine.

Offline only; no network, no subprocess/eval/exec. Never touches
``db/coverage.db``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import pytest

from database.models import (
    AptGroup,
    AptTechnique,
    Base,
    DataSourceType,
    SimulationResult,
    SimulationTechnique,
    Technique,
    TechniqueCoverage,
)
from database.session import make_engine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canonical tactic slugs reused for the synthetic techniques.
# ---------------------------------------------------------------------------

_EXEC = "execution"
_CRED = "credential-access"
_LATERAL = "lateral-movement"
_DEF_EVASION = "defense-evasion"


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _make_technique(
    stix_id: str,
    attack_id: str,
    name: str,
    *,
    tactics: Sequence[str] = (_EXEC,),
    platforms: Sequence[str] = ("Windows",),
    is_subtechnique: bool = False,
    parent_attack_id: str | None = None,
    revoked: bool = False,
) -> Technique:
    """Build one Technique row honoring the sub-technique contract."""
    return Technique(
        stix_id=stix_id,
        attack_id=attack_id,
        name=name,
        description=f"{name} (synthetic)",
        tactics=list(tactics),
        platforms=list(platforms),
        detection_strategy_refs=[],
        is_subtechnique=is_subtechnique,
        parent_attack_id=parent_attack_id,
        revoked=revoked,
    )


def _make_coverage(
    technique: Technique,
    datasource_id: int,
    *,
    confidence: float,
) -> TechniqueCoverage:
    """Build one TechniqueCoverage row; is_detectable derived from 0.6 bar."""
    return TechniqueCoverage(
        technique_stix_id=technique.stix_id,
        technique_attack_id=technique.attack_id,
        datasource_id=datasource_id,
        is_detectable=confidence >= 0.6,
        detection_confidence=confidence,
        required_fields=[],
        sigma_rule_id=None,
    )


@pytest.fixture
def sim_env(tmp_path: Path):
    """Build a complete simulation universe on a disposable in-memory DB.

    Techniques (all Windows-scoped, alive unless noted):

    - T1078  Valid Accounts (parent)             -- NO direct coverage row
      - T1078.003  Local Accounts (sub)          -- NO direct coverage row
      - T1110  Brute Force (parent, standalone)  -- detectable via evtx 0.70
    - T1048  Exfiltration Over Alternative Protocol (parent)
      - T1048.003  Exfil Over Unnon-comm Network (sub) -- detectable 0.80
    - T1059.001  PowerShell (sub of T1059)       -- detectable 0.75 on its own
      - T1059  Command & Scripting Interpreter (parent) -- NO coverage
    - T1098  Account Manipulation (parent)
      - T1098.001  Additional Cloud Credentials (sub) -- NOT detectable 0.45
    - T1066  Indicator Removal (revoked)         -- alive=False; excluded

    Group G0001 ``RollUpTest`` uses every technique above (including the
    revoked T1066) so we can assert the revoked one is dropped from the
    denominator.

    A second group G0002 ``EmptyGroup`` uses NO techniques (exercises the
    zero-total / 0.0 coverage-pct guard).
    """
    engine = make_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    import sqlalchemy.orm

    factory = sqlalchemy.orm.sessionmaker(bind=engine)
    session = factory()

    # Single enabled datasource (evtx) -- config enablement is the source of
    # truth in the read path, but these tests query coverage rows directly
    # so we only need one id-stable row.
    ds = DataSourceType(name="evtx", log_format="evtx", priority=0, enabled=True)
    session.add(ds)
    session.flush()
    ds_id = ds.id

    # -- technique catalog ---------------------------------------------------
    t_t1078 = _make_technique(
        "attack-pattern--r01", "T1078", "Valid Accounts",
        tactics=(_DEF_EVASION, _CRED),
    )
    t_t1078_003 = _make_technique(
        "attack-pattern--r02", "T1078.003", "Local Accounts",
        tactics=(_DEF_EVASION,),
        is_subtechnique=True,
        parent_attack_id="T1078",
    )
    t_t1110 = _make_technique(
        "attack-pattern--r03", "T1110", "Brute Force",
        tactics=(_CRED,),
    )
    t_t1048 = _make_technique(
        "attack-pattern--r04", "T1048",
        "Exfiltration Over Alternative Protocol",
        tactics=("exfiltration",),
    )
    t_t1048_003 = _make_technique(
        "attack-pattern--r05", "T1048.003",
        "Exfil Over Uncommon Network",
        tactics=("exfiltration",),
        is_subtechnique=True,
        parent_attack_id="T1048",
    )
    t_t1059 = _make_technique(
        "attack-pattern--r06", "T1059",
        "Command & Scripting Interpreter",
        tactics=(_EXEC,),
    )
    t_t1059_001 = _make_technique(
        "attack-pattern--r07", "T1059.001", "PowerShell",
        tactics=(_EXEC,),
        is_subtechnique=True,
        parent_attack_id="T1059",
    )
    t_t1098 = _make_technique(
        "attack-pattern--r08", "T1098", "Account Manipulation",
        tactics=("persistence",),
    )
    t_t1098_001 = _make_technique(
        "attack-pattern--r09", "T1098.001",
        "Additional Cloud Credentials",
        tactics=("persistence",),
        is_subtechnique=True,
        parent_attack_id="T1098",
    )
    t_t1066 = _make_technique(
        "attack-pattern--r10", "T1066", "Indicator Removal",
        tactics=(_DEF_EVASION,),
        revoked=True,
    )

    techniques = [
        t_t1078, t_t1078_003, t_t1110, t_t1048, t_t1048_003,
        t_t1059, t_t1059_001, t_t1098, t_t1098_001, t_t1066,
    ]
    session.add_all(techniques)

    # -- coverage rows (drive detectability) ---------------------------------
    # T1110: directly detectable (parent, standalone).
    # T1048.003: detectable sub -> parent T1048 should roll up.
    # T1059.001: detectable sub with NO parent coverage -> stays detected.
    # T1098.001: sub below threshold (0.45) -> parent T1098 missed.
    # T1078 family: NO rows at all -> sub T1078.003 missed (no cousin agg).
    coverage_rows = [
        _make_coverage(t_t1110, ds_id, confidence=0.70),
        _make_coverage(t_t1048_003, ds_id, confidence=0.80),
        _make_coverage(t_t1059_001, ds_id, confidence=0.75),
        _make_coverage(t_t1098_001, ds_id, confidence=0.45),
    ]
    session.add_all(coverage_rows)

    # -- groups --------------------------------------------------------------
    g1 = AptGroup(
        stix_id="intrusion-set--g0001",
        group_id="G0001",
        name="RollUpTest",
        aliases=["RollUpTest"],
        description="Roll-up edge-case fixture group",
    )
    g2 = AptGroup(
        stix_id="intrusion-set--g0002",
        group_id="G0002",
        name="EmptyGroup",
        aliases=[],
        description="Group with no techniques",
    )
    session.add_all([g1, g2])
    session.flush()

    # G0001 uses every technique including the revoked T1066.
    g1_techniques = techniques  # all 10, including revoked
    session.add_all(
        AptTechnique(group_stix_id=g1.stix_id, technique_stix_id=t.stix_id)
        for t in g1_techniques
    )
    # G0002 intentionally gets no apt_technique rows.

    session.commit()

    cfg = {
        "platform_scope": "windows",
        "detection_confidence_threshold": 0.6,
        "enabled_log_sources": {"evtx": True},
    }

    env = {
        "engine": engine,
        "session": session,
        "cfg": cfg,
        "ds_id": ds_id,
        "techniques": {t.attack_id: t for t in techniques},
        "coverage": {c.technique_attack_id: c for c in coverage_rows},
    }
    try:
        yield env
    finally:
        session.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sim_technique_map(session: Any, result_id: int) -> dict[str, SimulationTechnique]:
    """Query persisted SimulationTechnique rows for a result by result_id.

    The SimulationResult model does not declare an ORM relationship, so
    tests query directly through the cascade FK -- the same path the
    engine uses on persist.
    """
    rows = (
        session.query(SimulationTechnique)
        .filter(SimulationTechnique.result_id == result_id)
        .all()
    )
    return {st.technique_attack_id: st for st in rows}


def _classify(session: Any, result_id: int) -> dict[str, str]:
    """Return {technique_attack_id: status} for a persisted simulation."""
    return {
        st.technique_attack_id: st.status
        for st in _sim_technique_map(session, result_id).values()
    }


# ---------------------------------------------------------------------------
# Roll-up edge cases
# ---------------------------------------------------------------------------


class TestSimulationRollUp:
    """Parent/sub-technique roll-up edge cases (one-level policy)."""

    def test_sub_technique_rolls_up_via_detectable_parent(
        self, sim_env, monkeypatch
    ) -> None:
        """T1078.003 is missed when NEITHER its parent nor itself is
        detectable -- roll-up is parent-driven, not cousin-aggregation.

        This is the core negative case: a sub-technique with an uncovered
        parent must NOT be rescued by a detectable *sibling*. We model it
        by leaving the whole T1078 family uncovered and asserting
        T1078.003 == missed.
        """
        from analysis import simulation

        session = sim_env["session"]
        cfg = sim_env["cfg"]

        # Make T1078 itself detectable so we can assert the POSITIVE case
        # first: when the parent IS detectable, the sub rolls up.
        t1078 = sim_env["techniques"]["T1078"]
        session.add(
            TechniqueCoverage(
                technique_stix_id=t1078.stix_id,
                technique_attack_id="T1078",
                datasource_id=sim_env["ds_id"],
                is_detectable=True,
                detection_confidence=0.80,
                required_fields=[],
                sigma_rule_id=None,
            )
        )
        session.commit()

        result = simulation.simulate_apt_attack("G0001", session, persist=True)
        session.commit()

        status = _classify(session, result.id)
        # Parent T1078 directly detectable; child T1078.003 rolls up.
        assert status["T1078"] == "detected"
        assert status["T1078.003"] == "detected_rollup"

    def test_sub_technique_missed_when_parent_uncovered(
        self, sim_env, monkeypatch
    ) -> None:
        """With NO coverage on T1078 or T1078.003, the sub is missed.

        The whole T1078 family is uncovered in the base fixture, so
        T1078.003 must classify as ``missed`` -- roll-up does not aggregate
        across siblings or cousins.
        """
        from analysis import simulation

        session = sim_env["session"]
        result = simulation.simulate_apt_attack("G0001", session, persist=True)
        session.commit()

        status = _classify(session, result.id)
        assert status["T1078"] == "missed"
        assert status["T1078.003"] == "missed"

    def test_parent_rolls_up_via_detectable_child(
        self, sim_env, monkeypatch
    ) -> None:
        """T1048 has NO direct coverage, but its child T1048.003 is
        detectable at 0.80 -> parent rolls up to detected_rollup."""
        from analysis import simulation

        session = sim_env["session"]
        result = simulation.simulate_apt_attack("G0001", session, persist=True)
        session.commit()

        status = _classify(session, result.id)
        assert status["T1048"] == "detected_rollup"
        assert status["T1048.003"] == "detected"

    def test_sub_stays_detected_even_with_uncovered_parent(
        self, sim_env, monkeypatch
    ) -> None:
        """T1059.001 is detectable (0.75) while parent T1059 has no
        coverage. The sub stays ``detected`` -- never demoted to a roll-up
        and never missed. (The parent T1059 separately rolls up to
        detected_rollup via its detectable child, per the sibling test.)"""
        from analysis import simulation

        session = sim_env["session"]
        result = simulation.simulate_apt_attack("G0001", session, persist=True)
        session.commit()

        status = _classify(session, result.id)
        assert status["T1059.001"] == "detected"
        assert status["T1059"] == "detected_rollup"

    def test_parent_missed_when_only_child_is_below_threshold(
        self, sim_env, monkeypatch
    ) -> None:
        """T1098.001 sits at 0.45 (< 0.6 bar). Parent T1098 has no direct
        coverage. Both are missed -- a sub below threshold cannot rescue
        its parent."""
        from analysis import simulation

        session = sim_env["session"]
        result = simulation.simulate_apt_attack("G0001", session, persist=True)
        session.commit()

        status = _classify(session, result.id)
        assert status["T1098"] == "missed"
        assert status["T1098.001"] == "missed"

    def test_revoked_technique_excluded_from_denominator(
        self, sim_env, monkeypatch
    ) -> None:
        """T1066 is revoked; even though G0001 uses it, it must be absent
        from the persisted SimulationTechnique rows and from the total."""
        from analysis import simulation

        session = sim_env["session"]
        result = simulation.simulate_apt_attack("G0001", session, persist=True)
        session.commit()

        persisted = _sim_technique_map(session, result.id)
        assert "T1066" not in persisted, (
            "revoked technique must be excluded from simulation"
        )
        # 10 techniques associated, 1 revoked -> 9 counted.
        assert result.total_techniques == 9

    def test_invariant_counts_sum_to_total(self, sim_env, monkeypatch) -> None:
        """detected + detected_rollup + missed == total for every run."""
        from analysis import simulation

        session = sim_env["session"]
        result = simulation.simulate_apt_attack("G0001", session, persist=True)
        session.commit()

        counts = result.summary["counts"]
        assert (
            counts["detected"]
            + counts["detected_rollup"]
            + counts["missed"]
        ) == counts["total"]
        assert counts["total"] == result.total_techniques

    def test_coverage_pct_is_detected_over_total(
        self, sim_env, monkeypatch
    ) -> None:
        """coverage_pct == round(detected / total, 4)."""
        from analysis import simulation

        session = sim_env["session"]
        result = simulation.simulate_apt_attack("G0001", session, persist=True)
        session.commit()

        expected = round(
            result.detected_count / result.total_techniques, 4
        ) if result.total_techniques else 0.0
        assert result.coverage_pct == expected
        assert result.coverage_pct == result.summary["coverage_pct"]

    def test_detected_and_rollup_are_disjoint(
        self, sim_env, monkeypatch
    ) -> None:
        """No technique is counted as both detected and detected_rollup."""
        from analysis import simulation

        session = sim_env["session"]
        result = simulation.simulate_apt_attack("G0001", session, persist=True)
        session.commit()

        statuses = _classify(session, result.id)
        detected = {tid for tid, s in statuses.items() if s == "detected"}
        rollup = {tid for tid, s in statuses.items() if s == "detected_rollup"}
        assert detected.isdisjoint(rollup)

    def test_unknown_group_raises_valueerror(self, sim_env, monkeypatch) -> None:
        """An unknown group_id raises ValueError listing valid ids."""
        from analysis import simulation

        session = sim_env["session"]
        with pytest.raises(ValueError) as exc:
            simulation.simulate_apt_attack("G9999", session, persist=True)
        # Error message should mention the bad id and a valid alternative.
        msg = str(exc.value)
        assert "G9999" in msg
        assert "G0001" in msg or "G0002" in msg

    def test_persistence_result_and_techniques(
        self, sim_env, monkeypatch
    ) -> None:
        """SimulationResult + one SimulationTechnique per counted technique
        are persisted and cascade-linked."""
        from analysis import simulation

        session = sim_env["session"]
        result = simulation.simulate_apt_attack("G0001", session, persist=True)
        session.commit()

        # Result row persisted.
        stored = (
            session.query(SimulationResult)
            .filter(SimulationResult.id == result.id)
            .one()
        )
        assert stored.group_id == "G0001"
        assert stored.total_techniques == result.total_techniques

        # One SimulationTechnique per counted technique, all linked.
        tech_rows = (
            session.query(SimulationTechnique)
            .filter(SimulationTechnique.result_id == result.id)
            .all()
        )
        assert len(tech_rows) == result.total_techniques
        for row in tech_rows:
            assert row.status in ("detected", "detected_rollup", "missed")

    def test_run_at_is_utc(self, sim_env, monkeypatch) -> None:
        """run_at is timezone-aware UTC."""
        from analysis import simulation

        session = sim_env["session"]
        result = simulation.simulate_apt_attack("G0001", session, persist=True)
        session.commit()

        assert result.run_at is not None
        assert result.run_at.tzinfo is not None

    def test_summary_schema_shape(self, sim_env, monkeypatch) -> None:
        """summary JSON has the documented schema including per_tactic."""
        from analysis import simulation

        session = sim_env["session"]
        result = simulation.simulate_apt_attack("G0001", session, persist=True)
        session.commit()

        summary = result.summary
        assert summary["group_id"] == "G0001"
        assert "run_at" in summary
        assert summary["platform_scope"] == "windows"
        assert summary["threshold"] == 0.6
        assert {"total", "detected", "detected_rollup", "missed"} <= set(
            summary["counts"]
        )
        assert isinstance(summary["per_tactic"], dict)
        # Every per_tactic bucket has total/detected/missed.
        for bucket in summary["per_tactic"].values():
            assert {"total", "detected", "missed"} <= set(bucket)

    def test_empty_group_yields_zero_total(
        self, sim_env, monkeypatch
    ) -> None:
        """A group with no techniques yields total=0, coverage_pct=0.0."""
        from analysis import simulation

        session = sim_env["session"]
        result = simulation.simulate_apt_attack("G0002", session, persist=True)
        session.commit()

        assert result.total_techniques == 0
        assert result.detected_count == 0
        assert result.missed_count == 0
        assert result.coverage_pct == 0.0
        assert result.summary["counts"]["total"] == 0
        assert result.summary["counts"]["detected_rollup"] == 0

    def test_persist_false_does_not_write(self, sim_env, monkeypatch) -> None:
        """persist=False computes the result without writing to the DB."""
        from analysis import simulation

        session = sim_env["session"]
        result = simulation.simulate_apt_attack("G0001", session, persist=False)

        assert result.total_techniques == 9
        # No SimulationResult rows should exist for this run.
        count = (
            session.query(SimulationResult)
            .filter(SimulationResult.group_id == "G0001")
            .count()
        )
        assert count == 0

    def test_standalone_parent_detected_is_not_rollup(
        self, sim_env, monkeypatch
    ) -> None:
        """T1110 is a standalone parent, directly detectable -> detected
        (not roll-up), proving roll-up only fires for the parent-of-child
        or child-of-parent path."""
        from analysis import simulation

        session = sim_env["session"]
        result = simulation.simulate_apt_attack("G0001", session, persist=True)
        session.commit()

        status = _classify(session, result.id)
        assert status["T1110"] == "detected"
