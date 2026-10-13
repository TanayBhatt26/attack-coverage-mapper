"""Core unit tests for the Phase-4 APT simulation engine.

The engine under test lives in :mod:`analysis.simulation`:

* :func:`~analysis.simulation.simulate_apt_attack` -- classify every
  non-revoked technique of an APT group against the current coverage
  (direct detectability + one-level parent/sub roll-up), persist one
  :class:`~database.models.SimulationResult` plus one
  :class:`~database.models.SimulationTechnique` per group technique, and
  return the ORM result.
* :func:`~analysis.simulation.generate_recommendations` -- greedy
  marginal-gain acquisition advice over *disabled* log formats, ranked by
  how many missed techniques each would close.

These are **core unit tests**: every test builds its own in-memory SQLite
database (``StaticPool``) and injects a controlled ``config`` mapping, so
nothing touches ``db/coverage.db`` or ``config.yaml``. Expected values are
re-derived by hand from the documented contract
(``swarm2-planning-designs.md:502-547``, ``p4-wave1-full-results.md``),
never by calling the engine as an oracle.

Key contract points the tests pin:

* ``detected`` coverage is *direct* detectability only; ``detected_rollup``
  (sub-with-covered-parent OR parent-with-covered-child) is tracked
  separately and excluded from ``coverage_pct``'s numerator.
* Invariant: ``detected_count + detected_rollup_count + missed_count ==
  total_techniques`` (the rollup count lives in ``summary['counts']``).
* ``coverage_pct = round(detected_count / total, 4)``, 0.0 when ``total=0``.
* Unknown ``group_id`` raises ``ValueError`` enumerating every valid id;
  lookup is case-insensitive and whitespace-tolerant.
* Two runs against an unchanged DB+config yield byte-identical deterministic
  cores (all fields except ``id`` + ``run_at``).
* ``persist=False`` returns a result with ``id=None`` and writes nothing.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Sequence

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from analysis.simulation import generate_recommendations, simulate_apt_attack
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

logger = logging.getLogger(__name__)

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Canonical constants.
# ---------------------------------------------------------------------------

ALL_LOG_FORMATS: tuple[str, ...] = (
    "evtx",
    "syslog",
    "cef",
    "leef",
    "json",
    "aws_cloudtrail",
    "nginx",
    "zeek",
)

DEFAULT_THRESHOLD = 0.6

# Source display labels (contract from p4-wave1-full-results.md:861-867).
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


# ---------------------------------------------------------------------------
# Factories.
# ---------------------------------------------------------------------------

def _make_cfg(
    *,
    platform_scope: str = "windows",
    threshold: float = DEFAULT_THRESHOLD,
    enabled_log_sources: dict[str, bool] | None = None,
) -> dict[str, object]:
    """A normalized config dict shaped like ``config_loader.load_config`` output."""
    sources: dict[str, bool] = {fmt: True for fmt in ALL_LOG_FORMATS}
    if enabled_log_sources is not None:
        sources.update(enabled_log_sources)
    return {
        "platform_scope": platform_scope,
        "detection_confidence_threshold": threshold,
        "enabled_log_sources": sources,
    }


def _make_rule(
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
) -> Any:
    """Build one synthetic ``MappingRule`` with validated-shape defaults."""
    from parser.mappings_io import MappingRule

    return MappingRule(
        mapping_id=mapping_id or f"SYN-{technique_id}-{source_format}",
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
        notes="synthetic simulation fixture rule",
    )


def _add_technique(
    session: Session,
    attack_id: str,
    *,
    name: str | None = None,
    tactics: Sequence[str] = ("execution",),
    platforms: Sequence[str] = ("Windows",),
    is_subtechnique: bool | None = None,
    parent_attack_id: str | None = None,
    revoked: bool = False,
) -> Technique:
    """Insert one technique; returns the ORM instance."""
    sub = (
        is_subtechnique
        if is_subtechnique is not None
        else ("." in attack_id)
    )
    parent = parent_attack_id
    if parent is None and "." in attack_id:
        parent = attack_id.split(".")[0]
    technique = Technique(
        stix_id=f"attack-pattern--{attack_id.lower()}",
        attack_id=attack_id,
        name=name or f"Synthetic technique {attack_id}",
        description="Synthetic technique for simulation tests.",
        tactics=list(tactics),
        platforms=list(platforms),
        detection_strategy_refs=[],
        is_subtechnique=sub,
        parent_attack_id=parent,
        revoked=revoked,
    )
    session.add(technique)
    return technique


def _add_group(
    session: Session,
    *,
    stix_id: str = "intrusion-set--synthetic-g0016",
    group_id: str = "G0016",
    name: str = "APT29",
    aliases: Sequence[str] = ("APT29", "Cozy Bear"),
) -> AptGroup:
    group = AptGroup(
        stix_id=stix_id,
        group_id=group_id,
        name=name,
        aliases=list(aliases),
        description="Synthetic APT group for simulation tests.",
    )
    session.add(group)
    return group


def _link_group_technique(session: Session, group_stix_id: str, technique_attack_id: str) -> None:
    tech = session.execute(
        select(Technique).where(Technique.attack_id == technique_attack_id)
    ).scalar_one()
    session.add(
        AptTechnique(
            group_stix_id=group_stix_id,
            technique_stix_id=tech.stix_id,
        )
    )


def _add_coverage(
    session: Session,
    *,
    technique_attack_id: str,
    datasource_name: str,
    confidence: float,
    is_detectable: bool,
) -> TechniqueCoverage:
    tech = session.execute(
        select(Technique).where(Technique.attack_id == technique_attack_id)
    ).scalar_one()
    ds = session.execute(
        select(DataSourceType).where(DataSourceType.name == datasource_name)
    ).scalar_one()
    row = TechniqueCoverage(
        technique_stix_id=tech.stix_id,
        technique_attack_id=technique_attack_id,
        datasource_id=ds.id,
        is_detectable=is_detectable,
        detection_confidence=confidence,
        required_fields=[],
        sigma_rule_id=None,
    )
    session.add(row)
    return row


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


# ---------------------------------------------------------------------------
# Contract: group resolution.
# ---------------------------------------------------------------------------


class TestGroupResolution:
    """Unknown / malformed ``group_id`` must raise ``ValueError`` enumerating valid ids."""

    def _seed_groups(self, session: Session) -> None:
        _add_group(session, group_id="G0016", name="APT29")
        _add_group(
            session,
            group_id="G0096",
            name="APT41",
            stix_id="intrusion-set--synthetic-g0096",
        )
        session.commit()

    def test_unknown_group_raises_value_error_with_valid_ids(self, session_factory):
        session = session_factory()
        self._seed_groups(session)

        with pytest.raises(ValueError) as exc_info:
            simulate_apt_attack("G9999", session, config=_make_cfg())
        message = str(exc_info.value)
        assert "G9999" in message
        assert "G0016" in message
        assert "G0096" in message

    def test_case_insensitive_lookup(self, session_factory):
        session = session_factory()
        self._seed_groups(session)

        result = simulate_apt_attack("g0016", session, config=_make_cfg())
        assert result.group_id == "G0016"

    def test_whitespace_tolerant_lookup(self, session_factory):
        session = session_factory()
        self._seed_groups(session)

        result = simulate_apt_attack("  G0016  ", session, config=_make_cfg())
        assert result.group_id == "G0016"

    def test_none_group_raises_value_error(self, session_factory):
        session = session_factory()
        self._seed_groups(session)

        with pytest.raises(ValueError):
            simulate_apt_attack(None, session, config=_make_cfg())

    def test_empty_group_raises_value_error(self, session_factory):
        session = session_factory()
        self._seed_groups(session)

        with pytest.raises(ValueError):
            simulate_apt_attack("   ", session, config=_make_cfg())


# ---------------------------------------------------------------------------
# Contract: classification + invariant.
# ---------------------------------------------------------------------------


class TestClassificationAndInvariant:
    """Per-technique status and the detected+rollup+missed == total invariant."""

    def _seed_world(self, session: Session) -> None:
        """Seed a deterministic world:

        - T1059 (parent, execution) -- covered by evtx (detected directly).
        - T1059.001 (sub of T1059, execution) -- NOT covered itself; parent
          covered -> detected_rollup.
        - T1110 (parent, credential-access) -- NOT covered.
        - T1110.003 (sub of T1110, credential-access) -- covered by zeek;
          parent used + child covered -> detected_rollup for T1110.
        - T1046 (parent, discovery) -- NOT covered at all -> missed.
        """
        _add_group(session, group_id="G0016", name="APT29")
        _add_technique(session, "T1059", tactics=("execution",), platforms=("Windows",))
        _add_technique(session, "T1059.001", tactics=("execution",), platforms=("Windows",))
        _add_technique(session, "T1110", tactics=("credential-access",), platforms=("Windows",))
        _add_technique(session, "T1110.003", tactics=("credential-access",), platforms=("Windows",))
        _add_technique(session, "T1046", tactics=("discovery",), platforms=("Windows",))
        session.flush()

        group = session.execute(
            select(AptGroup).where(AptGroup.group_id == "G0016")
        ).scalar_one()
        for aid in ("T1059", "T1059.001", "T1110", "T1110.003", "T1046"):
            _link_group_technique(session, group.stix_id, aid)

        for fmt in ("evtx", "zeek"):
            session.add(DataSourceType(name=fmt, log_format=fmt, priority=0, enabled=True))
        session.flush()

        _add_coverage(
            session,
            technique_attack_id="T1059",
            datasource_name="evtx",
            confidence=0.75,
            is_detectable=True,
        )
        _add_coverage(
            session,
            technique_attack_id="T1110.003",
            datasource_name="zeek",
            confidence=0.80,
            is_detectable=True,
        )
        session.commit()

    def test_detected_directly(self, session_factory):
        session = session_factory()
        self._seed_world(session)

        result = simulate_apt_attack("G0016", session, config=_make_cfg())
        children = (
            session.execute(
                select(SimulationTechnique)
                .where(SimulationTechnique.result_id == result.id)
                .order_by(SimulationTechnique.technique_attack_id)
            )
            .scalars()
            .all()
        )
        by_id = {t.technique_attack_id: t for t in children}
        assert by_id["T1059"].status == "detected"

    def test_sub_used_parent_covered_is_rollup(self, session_factory):
        """Group uses T1059.001 (sub); only T1059 (parent) covered -> rollup."""
        session = session_factory()
        self._seed_world(session)

        result = simulate_apt_attack("G0016", session, config=_make_cfg())
        children = (
            session.execute(
                select(SimulationTechnique)
                .where(SimulationTechnique.result_id == result.id)
                .order_by(SimulationTechnique.technique_attack_id)
            )
            .scalars()
            .all()
        )
        by_id = {t.technique_attack_id: t for t in children}
        assert by_id["T1059.001"].status == "detected_rollup"

    def test_parent_used_child_covered_is_rollup(self, session_factory):
        """Group uses T1110 (parent); only T1110.003 (child) covered -> rollup."""
        session = session_factory()
        self._seed_world(session)

        result = simulate_apt_attack("G0016", session, config=_make_cfg())
        children = (
            session.execute(
                select(SimulationTechnique)
                .where(SimulationTechnique.result_id == result.id)
                .order_by(SimulationTechnique.technique_attack_id)
            )
            .scalars()
            .all()
        )
        by_id = {t.technique_attack_id: t for t in children}
        assert by_id["T1110"].status == "detected_rollup"

    def test_missed_when_nothing_covered(self, session_factory):
        session = session_factory()
        self._seed_world(session)

        result = simulate_apt_attack("G0016", session, config=_make_cfg())
        children = (
            session.execute(
                select(SimulationTechnique)
                .where(SimulationTechnique.result_id == result.id)
                .order_by(SimulationTechnique.technique_attack_id)
            )
            .scalars()
            .all()
        )
        by_id = {t.technique_attack_id: t for t in children}
        assert by_id["T1046"].status == "missed"

    def test_invariant_detected_plus_rollup_plus_missed_equals_total(self, session_factory):
        """The three statuses partition the group's techniques exhaustively.

        The authoritative per-status counts come from the child
        ``SimulationTechnique`` rows; the summary['counts'] must agree with
        them exactly. ``detected_count + missed_count`` may or may not
        include rollups depending on the counting convention, but the
        three-way partition is invariant.
        """
        session = session_factory()
        self._seed_world(session)

        result = simulate_apt_attack("G0016", session, config=_make_cfg())
        children = (
            session.execute(
                select(SimulationTechnique)
                .where(SimulationTechnique.result_id == result.id)
            )
            .scalars()
            .all()
        )
        detected = sum(1 for t in children if t.status == "detected")
        rollup = sum(1 for t in children if t.status == "detected_rollup")
        missed = sum(1 for t in children if t.status == "missed")
        # Exhaustive partition invariant.
        assert detected + rollup + missed == result.total_techniques
        # Summary counts agree with the child rows (authoritative).
        assert result.summary["counts"]["detected"] == detected
        assert result.summary["counts"]["detected_rollup"] == rollup
        assert result.summary["counts"]["missed"] == missed
        # missed_count matches the missed child rows.
        assert result.missed_count == missed
        assert result.total_techniques == 5

    def test_statuses_are_exhaustive(self, session_factory):
        """Every SimulationTechnique status is one of the three allowed values."""
        session = session_factory()
        self._seed_world(session)

        result = simulate_apt_attack("G0016", session, config=_make_cfg())
        children = (
            session.execute(
                select(SimulationTechnique)
                .where(SimulationTechnique.result_id == result.id)
            )
            .scalars()
            .all()
        )
        allowed = {"detected", "detected_rollup", "missed"}
        for t in children:
            assert t.status in allowed


# ---------------------------------------------------------------------------
# Contract: coverage math.
# ---------------------------------------------------------------------------


class TestCoverageMath:
    """coverage_pct = round(detected / total, 4) with 0.0 guard; rollup excluded from numerator."""

    def _seed_simple(self, session: Session) -> None:
        _add_group(session, group_id="G0016", name="APT29")
        _add_technique(session, "T1059", tactics=("execution",), platforms=("Windows",))
        _add_technique(session, "T1110", tactics=("credential-access",), platforms=("Windows",))
        session.flush()
        group = session.execute(
            select(AptGroup).where(AptGroup.group_id == "G0016")
        ).scalar_one()
        for aid in ("T1059", "T1110"):
            _link_group_technique(session, group.stix_id, aid)
        session.add(DataSourceType(name="evtx", log_format="evtx", priority=0, enabled=True))
        session.flush()
        _add_coverage(
            session,
            technique_attack_id="T1059",
            datasource_name="evtx",
            confidence=0.75,
            is_detectable=True,
        )
        # T1110 left uncovered -> missed.
        session.commit()

    def test_coverage_pct_is_direct_detected_only(self, session_factory):
        session = session_factory()
        self._seed_simple(session)

        result = simulate_apt_attack("G0016", session, config=_make_cfg())
        # 1 direct detected of 2 total -> 0.5 exactly.
        assert result.coverage_pct == 0.5
        assert result.total_techniques == 2
        assert result.detected_count == 1
        assert result.missed_count == 1

    def test_coverage_pct_rounds_fraction(self, session_factory):
        session = session_factory()
        _add_group(session, group_id="G0016", name="APT29")
        for aid in ("T1059", "T1110", "T1046"):
            _add_technique(session, aid, tactics=("execution",), platforms=("Windows",))
        session.flush()
        group = session.execute(
            select(AptGroup).where(AptGroup.group_id == "G0016")
        ).scalar_one()
        for aid in ("T1059", "T1110", "T1046"):
            _link_group_technique(session, group.stix_id, aid)
        session.add(DataSourceType(name="evtx", log_format="evtx", priority=0, enabled=True))
        session.flush()
        _add_coverage(
            session,
            technique_attack_id="T1059",
            datasource_name="evtx",
            confidence=0.75,
            is_detectable=True,
        )
        session.commit()

        result = simulate_apt_attack("G0016", session, config=_make_cfg())
        # 1 of 3 -> 0.3333 rounded to 4 decimals.
        assert result.coverage_pct == round(1 / 3, 4)

    def test_zero_technique_group_guards_division(self, session_factory):
        """A group with zero non-revoked techniques must not ZeroDivide."""
        session = session_factory()
        _add_group(session, group_id="G0016", name="APT29")
        session.commit()

        result = simulate_apt_attack("G0016", session, config=_make_cfg())
        assert result.total_techniques == 0
        assert result.coverage_pct == 0.0
        assert result.detected_count == 0
        assert result.missed_count == 0


# ---------------------------------------------------------------------------
# Contract: persistence.
# ---------------------------------------------------------------------------


class TestPersistence:
    """Each run appends one SimulationResult + one SimulationTechnique per technique."""

    def _seed_simple(self, session: Session) -> None:
        _add_group(session, group_id="G0016", name="APT29")
        _add_technique(session, "T1059", tactics=("execution",), platforms=("Windows",))
        session.flush()
        group = session.execute(
            select(AptGroup).where(AptGroup.group_id == "G0016")
        ).scalar_one()
        _link_group_technique(session, group.stix_id, "T1059")
        session.add(DataSourceType(name="evtx", log_format="evtx", priority=0, enabled=True))
        session.flush()
        _add_coverage(
            session,
            technique_attack_id="T1059",
            datasource_name="evtx",
            confidence=0.75,
            is_detectable=True,
        )
        session.commit()

    def test_persist_true_writes_result_and_children(self, session_factory):
        session = session_factory()
        self._seed_simple(session)

        result = simulate_apt_attack("G0016", session, config=_make_cfg(), persist=True)
        assert isinstance(result, SimulationResult)
        assert result.id is not None
        children = (
            session.execute(
                select(SimulationTechnique)
                .where(SimulationTechnique.result_id == result.id)
            )
            .scalars()
            .all()
        )
        assert len(children) == 1
        assert children[0].technique_attack_id == "T1059"

    def test_persist_false_writes_nothing(self, session_factory):
        session = session_factory()
        self._seed_simple(session)

        result = simulate_apt_attack("G0016", session, config=_make_cfg(), persist=False)
        assert result.id is None
        count = session.execute(
            select(func.count()).select_from(SimulationResult)
        ).scalar_one()
        child_count = session.execute(
            select(func.count()).select_from(SimulationTechnique)
        ).scalar_one()
        assert count == 0
        assert child_count == 0

    def test_two_runs_append_two_results(self, session_factory):
        session = session_factory()
        self._seed_simple(session)

        simulate_apt_attack("G0016", session, config=_make_cfg(), persist=True)
        session.commit()
        simulate_apt_attack("G0016", session, config=_make_cfg(), persist=True)
        session.commit()

        results = (
            session.execute(
                select(SimulationResult).order_by(SimulationResult.id)
            )
            .scalars()
            .all()
        )
        assert len(results) == 2
        assert results[0].id != results[1].id

    def test_run_at_is_utc_aware(self, session_factory):
        session = session_factory()
        self._seed_simple(session)

        result = simulate_apt_attack("G0016", session, config=_make_cfg(), persist=True)
        assert result.run_at is not None
        assert result.run_at.tzinfo is not None


# ---------------------------------------------------------------------------
# Contract: determinism.
# ---------------------------------------------------------------------------


class TestDeterminism:
    """Two runs against unchanged DB+config yield byte-identical deterministic cores."""

    def _seed_world(self, session: Session) -> None:
        _add_group(session, group_id="G0016", name="APT29")
        _add_technique(session, "T1059", tactics=("execution",), platforms=("Windows",))
        _add_technique(session, "T1059.001", tactics=("execution",), platforms=("Windows",))
        _add_technique(session, "T1110", tactics=("credential-access",), platforms=("Windows",))
        session.flush()
        group = session.execute(
            select(AptGroup).where(AptGroup.group_id == "G0016")
        ).scalar_one()
        for aid in ("T1059", "T1059.001", "T1110"):
            _link_group_technique(session, group.stix_id, aid)
        session.add(DataSourceType(name="evtx", log_format="evtx", priority=0, enabled=True))
        session.flush()
        _add_coverage(
            session,
            technique_attack_id="T1059",
            datasource_name="evtx",
            confidence=0.75,
            is_detectable=True,
        )
        session.commit()

    @staticmethod
    def _deterministic_view(result: SimulationResult) -> dict[str, Any]:
        """All deterministic SimulationResult fields.

        Excludes ``id`` + ``run_at`` (wall-clock) and ``summary`` (which
        embeds a ``run_at`` timestamp, making it non-deterministic).
        """
        return {
            "group_stix_id": result.group_stix_id,
            "group_id": result.group_id,
            "platform_scope": result.platform_scope,
            "confidence_threshold": result.confidence_threshold,
            "total_techniques": result.total_techniques,
            "detected_count": result.detected_count,
            "missed_count": result.missed_count,
            "coverage_pct": result.coverage_pct,
        }

    @staticmethod
    def _children_view(session: Session, result_id: int) -> tuple[dict[str, Any], ...]:
        rows = (
            session.execute(
                select(SimulationTechnique)
                .where(SimulationTechnique.result_id == result_id)
                .order_by(SimulationTechnique.technique_attack_id)
            )
            .scalars()
            .all()
        )
        return tuple(
            {
                "technique_attack_id": t.technique_attack_id,
                "name": t.name,
                "tactic": t.tactic,
                "status": t.status,
                "confidence": t.confidence,
                "contributing_sources": t.contributing_sources,
            }
            for t in rows
        )

    def test_two_runs_byte_identical_deterministic_core(self, session_factory):
        session = session_factory()
        self._seed_world(session)
        cfg = _make_cfg()

        r1 = simulate_apt_attack("G0016", session, config=cfg, persist=True)
        session.commit()
        r2 = simulate_apt_attack("G0016", session, config=cfg, persist=True)
        session.commit()

        assert r1.id != r2.id
        assert self._deterministic_view(r1) == self._deterministic_view(r2)
        assert self._children_view(session, r1.id) == self._children_view(session, r2.id)

    def test_run_at_is_monotonic(self, session_factory):
        session = session_factory()
        self._seed_world(session)
        cfg = _make_cfg()

        r1 = simulate_apt_attack("G0016", session, config=cfg, persist=True)
        session.commit()
        r2 = simulate_apt_attack("G0016", session, config=cfg, persist=True)
        session.commit()

        assert r1.run_at is not None and r2.run_at is not None
        assert r1.run_at <= r2.run_at


# ---------------------------------------------------------------------------
# Contract: summary JSON schema.
# ---------------------------------------------------------------------------


class TestSummarySchema:
    """summary JSON matches the documented shape."""

    def _seed_world(self, session: Session) -> None:
        _add_group(session, group_id="G0016", name="APT29")
        _add_technique(session, "T1059", tactics=("execution",), platforms=("Windows",))
        _add_technique(session, "T1110", tactics=("credential-access",), platforms=("Windows",))
        session.flush()
        group = session.execute(
            select(AptGroup).where(AptGroup.group_id == "G0016")
        ).scalar_one()
        for aid in ("T1059", "T1110"):
            _link_group_technique(session, group.stix_id, aid)
        session.add(DataSourceType(name="evtx", log_format="evtx", priority=0, enabled=True))
        session.flush()
        _add_coverage(
            session,
            technique_attack_id="T1059",
            datasource_name="evtx",
            confidence=0.75,
            is_detectable=True,
        )
        session.commit()

    def test_summary_shape(self, session_factory):
        session = session_factory()
        self._seed_world(session)

        result = simulate_apt_attack("G0016", session, config=_make_cfg(), persist=True)
        summary = result.summary
        assert isinstance(summary, dict)
        assert summary["group_id"] == "G0016"
        assert "run_at" in summary
        assert summary["platform_scope"] == "windows"
        assert summary["threshold"] == pytest.approx(0.6)
        counts = summary["counts"]
        assert counts["total"] == 2
        assert counts["detected"] + counts["detected_rollup"] + counts["missed"] == 2
        assert summary["coverage_pct"] == result.coverage_pct
        per_tactic = summary["per_tactic"]
        assert "execution" in per_tactic
        assert "credential-access" in per_tactic
        for _tactic, bucket in per_tactic.items():
            assert "total" in bucket
            assert "detected" in bucket
            assert "missed" in bucket


# ---------------------------------------------------------------------------
# Contract: recommendations.
# ---------------------------------------------------------------------------


class TestRecommendations:
    """Greedy marginal-gain recommendations over disabled sources."""

    def _seed_world(
        self,
        session: Session,
        *,
        disabled: Sequence[str] = ("zeek",),
    ) -> None:
        _add_group(session, group_id="G0016", name="APT29")
        _add_technique(session, "T1059", tactics=("execution",), platforms=("Windows",))
        _add_technique(session, "T1110", tactics=("credential-access",), platforms=("Windows",))
        session.flush()
        group = session.execute(
            select(AptGroup).where(AptGroup.group_id == "G0016")
        ).scalar_one()
        for aid in ("T1059", "T1110"):
            _link_group_technique(session, group.stix_id, aid)
        for fmt in ("evtx", "zeek"):
            session.add(DataSourceType(name=fmt, log_format=fmt, priority=0, enabled=True))
        session.flush()
        # T1059 covered by evtx (detected).
        _add_coverage(
            session,
            technique_attack_id="T1059",
            datasource_name="evtx",
            confidence=0.75,
            is_detectable=True,
        )
        # T1110 covered only by zeek (disabled) -> missed, closable by zeek.
        _add_coverage(
            session,
            technique_attack_id="T1110",
            datasource_name="zeek",
            confidence=0.80,
            is_detectable=True,
        )
        session.commit()

    def test_recommendation_mentions_disabled_source(self, session_factory):
        """A missed technique closable by a disabled source yields a recommendation."""
        session = session_factory()
        self._seed_world(session)
        cfg = _make_cfg(enabled_log_sources={"evtx": True, "zeek": False})

        result = simulate_apt_attack("G0016", session, config=cfg, persist=True)
        recs = generate_recommendations(result, session, top_n=3, config=cfg)
        assert isinstance(recs, list)
        assert len(recs) >= 1
        joined = " ".join(recs)
        # The disabled source label appears in the recommendation.
        assert "Zeek" in joined
        # The closable missed technique id is named.
        assert "T1110" in joined

    def test_recommendation_template_form(self, session_factory):
        """Recommendation follows the 'Enable {source} to cover {n} missed techniques ({ids})' template."""
        session = session_factory()
        self._seed_world(session)
        cfg = _make_cfg(enabled_log_sources={"evtx": True, "zeek": False})

        result = simulate_apt_attack("G0016", session, config=cfg, persist=True)
        recs = generate_recommendations(result, session, top_n=3, config=cfg)
        assert recs, "expected at least one recommendation"
        # First rec matches the documented template.
        assert recs[0].startswith("Enable ")
        assert "to cover" in recs[0]
        assert "missed technique" in recs[0]

    def test_no_missed_means_no_recommendations(self, session_factory):
        session = session_factory()
        _add_group(session, group_id="G0016", name="APT29")
        _add_technique(session, "T1059", tactics=("execution",), platforms=("Windows",))
        session.flush()
        group = session.execute(
            select(AptGroup).where(AptGroup.group_id == "G0016")
        ).scalar_one()
        _link_group_technique(session, group.stix_id, "T1059")
        session.add(DataSourceType(name="evtx", log_format="evtx", priority=0, enabled=True))
        session.flush()
        _add_coverage(
            session,
            technique_attack_id="T1059",
            datasource_name="evtx",
            confidence=0.75,
            is_detectable=True,
        )
        session.commit()

        result = simulate_apt_attack("G0016", session, config=_make_cfg(), persist=True)
        recs = generate_recommendations(result, session, top_n=3, config=_make_cfg())
        assert recs == []

    def test_recommendation_top_n_caps_results(self, session_factory):
        session = session_factory()
        self._seed_world(session)
        cfg = _make_cfg(enabled_log_sources={"evtx": True, "zeek": False})

        result = simulate_apt_attack("G0016", session, config=cfg, persist=True)
        recs = generate_recommendations(result, session, top_n=1, config=cfg)
        assert len(recs) <= 1


# ---------------------------------------------------------------------------
# Contract: revoked techniques excluded from group evaluation.
# ---------------------------------------------------------------------------


class TestRevokedExcluded:
    """Revoked/deprecated techniques must not count toward the group total."""

    def test_revoked_technique_excluded(self, session_factory):
        session = session_factory()
        _add_group(session, group_id="G0016", name="APT29")
        _add_technique(session, "T1059", tactics=("execution",), platforms=("Windows",))
        _add_technique(
            session,
            "T1070.001",
            tactics=("defense-evasion",),
            platforms=("Windows",),
            revoked=True,
        )
        session.flush()
        group = session.execute(
            select(AptGroup).where(AptGroup.group_id == "G0016")
        ).scalar_one()
        _link_group_technique(session, group.stix_id, "T1059")
        _link_group_technique(session, group.stix_id, "T1070.001")
        session.add(DataSourceType(name="evtx", log_format="evtx", priority=0, enabled=True))
        session.flush()
        _add_coverage(
            session,
            technique_attack_id="T1059",
            datasource_name="evtx",
            confidence=0.75,
            is_detectable=True,
        )
        session.commit()

        result = simulate_apt_attack("G0016", session, config=_make_cfg())
        # Only the non-revoked T1059 counts.
        assert result.total_techniques == 1
        children = (
            session.execute(
                select(SimulationTechnique)
                .where(SimulationTechnique.result_id == result.id)
            )
            .scalars()
            .all()
        )
        assert len(children) == 1
        assert children[0].technique_attack_id == "T1059"


# ---------------------------------------------------------------------------
# Import guard: the module must expose the documented public API.
# ---------------------------------------------------------------------------


def test_simulation_module_imports():
    """The simulation module must expose the documented public API."""
    from analysis import simulation

    assert hasattr(simulation, "simulate_apt_attack")
    assert hasattr(simulation, "generate_recommendations")
    assert callable(simulation.simulate_apt_attack)
    assert callable(simulation.generate_recommendations)
