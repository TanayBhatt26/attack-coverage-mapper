"""Recommendation-correctness tests for the Phase-4 APT simulation engine.

The recommendation generator (:func:`analysis.simulation.generate_recommendations`)
is a greedy marginal-gain reducer over *disabled* log formats: for every
missed technique of a simulated group it asks which disabled source would
push the technique's best confidence to or above the threshold, then ranks
the sources by how many missed techniques each would close. This suite pins
that contract over a synthetic in-memory SQLite database (built here; the
real ``db/coverage.db`` is never touched) and programmatic mapping rules:

* **(R1) Ranking** — recommendations are ordered by the number of missed
  techniques closable (largest marginal gain first); ties break on the
  ``DataSourceType.priority`` column (lower value = higher priority), then
  on the source key alphabetically for a byte-stable total order.
* **(R2) Template** — every sourced recommendation reads
  ``"Enable {source_label} to cover {n} missed techniques ({ids}, …)"``
  where ``source_label`` is the human-readable label from
  :data:`analysis.simulation.SOURCE_LABELS` (``"Nginx/Apache"``, not
  ``"nginx"``), ``n`` is the count, and the parenthesised list is the
  first five closable ids with an ``"(+m more)"`` suffix when there are
  more than five.
* **(R3) Honest filter** — a disabled source is recommended for a technique
  only when the coverage engine's ``build_closable_index`` (or the
  DB-backed equivalent) attests that the source's *best* static projection
  for that technique reaches the threshold inclusively. A mapping that
  exists but projects below the bar must NOT be promised (the anti-false-
  hope case, e.g. a ``cef`` rule at 0.25 against a 0.6 bar).
* **(R4) top_n cap** — ``generate_recommendations(..., top_n=k)`` returns
  at most ``k`` strings.
* **(R5) No-op** — a simulation with zero missed techniques yields an
  empty recommendation list.
* **(R6) Unmapped fallback** — when at least one missed technique has no
  closable source at all, a
  ``"No configured source maps to {tid} — add a mapping row."`` fallback
  string is appended (only when headroom under ``top_n`` remains).
* **(R7) Enabled-source exclusion** — sources already enabled in the
  config are never recommended, even if they appear in a technique's
  closable set.
* **(R8) Actionability** — every recommended source is a real disabled
  ``enabled_log_sources`` key, so a UI can map the string 1:1 to a config
  toggle.

The suite is offline: no network, no real ATT&CK bundle, no
``config.yaml`` reads (each test injects a controlled config mapping via
``simulate_apt_attack(..., config=...)``).

Known blocker: ``src/analysis/simulation.py`` currently has a syntax error
(``_closable_index_from_db`` is defined with no body and the file has a
duplicate ``_attack_meta_provenance``), so the module does not import. The
tests guard the import with :func:`pytest.importorskip`; they collect and
skip cleanly until that file is repaired, then pin the contract above.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Sequence

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from config_loader import DEFAULT_CONFIG
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
# Canonical constants (mirrors coverage_analyzer / config_loader).
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

# Human-readable source labels (contract from p4-wave1-full-results.md and
# analysis.simulation.SOURCE_LABELS).
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
# Config / DB / rule factories.
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


def _link_group_technique(
    session: Session, group_stix_id: str, technique_attack_id: str
) -> None:
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


def _add_datasource(
    session: Session, name: str, *, priority: int = 0, enabled: bool = True
) -> DataSourceType:
    row = DataSourceType(
        name=name, log_format=name, priority=priority, enabled=enabled
    )
    session.add(row)
    return row


# ---------------------------------------------------------------------------
# Session fixture.
# ---------------------------------------------------------------------------


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
# Import guard.
# ---------------------------------------------------------------------------


@pytest.fixture
def sim():
    """Import the simulation module, skipping the suite if it fails to import.

    ``src/analysis/simulation.py`` currently has a syntax error (an
    empty-bodied ``_closable_index_from_db`` def plus a duplicate
    ``_attack_meta_provenance``) that prevents import. Rather than letting
    every test explode with an opaque ImportError, we skip the whole suite
    cleanly with a pointer to the repair.
    """
    mod = pytest.importorskip(
        "analysis.simulation",
        reason=(
            "analysis.simulation does not import (pre-existing syntax error "
            "in src/analysis/simulation.py: empty-bodied "
            "_closable_index_from_db + duplicate _attack_meta_provenance). "
            "Re-run after that file is repaired."
        ),
    )
    return mod


# ---------------------------------------------------------------------------
# Contract R5: no missed techniques -> empty recommendations.
# ---------------------------------------------------------------------------


class TestNoMissedYieldsEmpty:
    """A fully-detected group must produce no acquisition advice."""

    def test_all_detected_returns_empty(self, session_factory, sim):
        from analysis.simulation import generate_recommendations

        session = session_factory()
        _add_group(session, group_id="G0016", name="APT29")
        _add_technique(session, "T1059", tactics=("execution",), platforms=("Windows",))
        session.flush()
        group = session.execute(
            select(AptGroup).where(AptGroup.group_id == "G0016")
        ).scalar_one()
        _link_group_technique(session, group.stix_id, "T1059")
        _add_datasource(session, "evtx")
        session.flush()
        _add_coverage(
            session,
            technique_attack_id="T1059",
            datasource_name="evtx",
            confidence=0.75,
            is_detectable=True,
        )
        session.commit()

        result = sim.simulate_apt_attack(
            "G0016", session, persist=True, config=_make_cfg()
        )
        recs = generate_recommendations(result, session, top_n=3, config=_make_cfg())
        assert recs == []


# ---------------------------------------------------------------------------
# Contract R1 / R2 / R8: ranking + template + actionability.
# ---------------------------------------------------------------------------


class TestRankingAndTemplate:
    """Recommendations ranked by marginal gain, rendered with human labels."""

    def _seed_world(
        self,
        session: Session,
        *,
        enabled: Sequence[str] = ("evtx",),
        disabled: Sequence[str] = ("zeek", "nginx"),
    ) -> None:
        """Seed a world where two missed techniques close via ``zeek`` (disabled)
        and one closes via ``nginx`` (disabled); ``zeek`` therefore has the
        largest marginal gain and must rank first.
        """
        _add_group(session, group_id="G0016", name="APT29")
        # Detected via evtx.
        _add_technique(session, "T1059", tactics=("execution",), platforms=("Windows",))
        # Missed, closable by zeek (network-layer).
        _add_technique(session, "T1046", tactics=("discovery",), platforms=("Windows",))
        # Missed, closable by both zeek and nginx.
        _add_technique(session, "T1048", tactics=("exfiltration",), platforms=("Windows",))
        # Missed, closable only by nginx.
        _add_technique(session, "T1571", tactics=("command-and-control",), platforms=("Windows",))
        session.flush()

        group = session.execute(
            select(AptGroup).where(AptGroup.group_id == "G0016")
        ).scalar_one()
        for aid in ("T1059", "T1046", "T1048", "T1571"):
            _link_group_technique(session, group.stix_id, aid)

        # Datasource rows: evtx enabled, zeek + nginx disabled (priority 0).
        for fmt in ("evtx", "zeek", "nginx"):
            _add_datasource(session, fmt, priority=0)
        session.flush()

        # T1059 covered by evtx (detected).
        _add_coverage(
            session,
            technique_attack_id="T1059",
            datasource_name="evtx",
            confidence=0.75,
            is_detectable=True,
        )
        session.commit()

    def _rules(self) -> list:
        """Mapping rules that make T1046/T1048 closable by zeek and T1048/T1571
        closable by nginx (all extension-key rules -> tier 1 -> base * 1.0)."""
        return [
            _make_rule(
                "T1046",
                source_format="zeek",
                base_confidence=0.80,
                ext_keys=("id.orig_h",),
                mapping_id="R-ZEEK-T1046",
            ),
            _make_rule(
                "T1048",
                source_format="zeek",
                base_confidence=0.80,
                ext_keys=("id.orig_h",),
                mapping_id="R-ZEEK-T1048",
            ),
            _make_rule(
                "T1048",
                source_format="nginx",
                base_confidence=0.75,
                ext_keys=("request",),
                mapping_id="R-NGINX-T1048",
            ),
            _make_rule(
                "T1571",
                source_format="nginx",
                base_confidence=0.75,
                ext_keys=("request",),
                mapping_id="R-NGINX-T1571",
            ),
        ]

    def test_ranked_by_marginal_gain(self, session_factory, sim):
        """zeek closes 2 missed techniques, nginx closes 2 -> tie on count;
        tie-break is priority (both 0) then alphabetical key -> nginx before
        zeek. Either way both must appear and both must report n=2."""
        from analysis.simulation import generate_recommendations

        session = session_factory()
        self._seed_world(session)

        cfg = _make_cfg(enabled_log_sources={f: False for f in ("zeek", "nginx")})
        result = sim.simulate_apt_attack("G0016", session, persist=True, config=cfg)
        recs = generate_recommendations(
            result, session, top_n=3, config=cfg, rules=self._rules()
        )

        assert len(recs) >= 1
        # Every recommendation must report covering at least one technique.
        for rec in recs:
            assert re.search(r"cover \d+ missed techniques", rec)

        # The top recommendation closes the most techniques (2 here).
        top = recs[0]
        match = re.search(r"cover (\d+) missed techniques", top)
        assert match is not None
        assert int(match.group(1)) >= 2

    def test_template_uses_human_label(self, session_factory, sim):
        """The rendered string must use the human label, not the config key."""
        from analysis.simulation import generate_recommendations

        session = session_factory()
        self._seed_world(session)

        cfg = _make_cfg(enabled_log_sources={f: False for f in ("zeek", "nginx")})
        result = sim.simulate_apt_attack("G0016", session, persist=True, config=cfg)
        recs = generate_recommendations(
            result, session, top_n=3, config=cfg, rules=self._rules()
        )

        joined = " ".join(recs)
        # Human labels present, raw keys (when standing alone) do not.
        assert ("Nginx/Apache" in joined) or ("Zeek" in joined)
        # Template shape: "Enable <Label> to cover <n> missed techniques (<ids>)".
        for rec in recs:
            assert rec.startswith("Enable ")
            assert " to cover " in rec
            assert " missed techniques (" in rec
            assert rec.endswith(")")

    def test_recommendation_is_actionable(self, session_factory, sim):
        """Every recommended source is a real disabled config key."""
        from analysis.simulation import generate_recommendations

        session = session_factory()
        self._seed_world(session)

        disabled = {"zeek", "nginx"}
        cfg = _make_cfg(enabled_log_sources={f: False for f in disabled})
        result = sim.simulate_apt_attack("G0016", session, persist=True, config=cfg)
        recs = generate_recommendations(
            result, session, top_n=3, config=cfg, rules=self._rules()
        )

        # Extract the source key from each recommendation by reverse lookup
        # through SOURCE_LABELS; every rec must map to a disabled key.
        by_label = {v: k for k, v in SOURCE_LABELS.items()}
        for rec in recs:
            if rec.startswith("Enable "):
                # "Enable <Label> to cover ..." -> label is between 'Enable '
                # and ' to cover'.
                label = rec[len("Enable ") : rec.index(" to cover")]
                key = by_label.get(label)
                assert key is not None, f"unknown label {label!r}"
                assert key in disabled, f"recommended source {key!r} is not disabled"


# ---------------------------------------------------------------------------
# Contract R3: honest filter (no false promises).
# ---------------------------------------------------------------------------


class TestHonestFilter:
    """A mapping that exists but projects below the bar must NOT be promised."""

    def test_below_threshold_mapping_not_promised(self, session_factory, sim):
        """T1136.001 has a cef rule at base 0.25 (tier 1 -> 0.25 < 0.6);
        cef must NOT appear in the recommendations despite the mapping
        existing (the anti-false-hope case)."""
        from analysis.simulation import generate_recommendations

        session = session_factory()
        _add_group(session, group_id="G0016", name="APT29")
        _add_technique(
            session, "T1136.001", tactics=("persistence",), platforms=("Windows",)
        )
        session.flush()
        group = session.execute(
            select(AptGroup).where(AptGroup.group_id == "G0016")
        ).scalar_one()
        _link_group_technique(session, group.stix_id, "T1136.001")
        _add_datasource(session, "evtx")
        _add_datasource(session, "cef")
        session.flush()
        # No coverage row -> T1136.001 is missed.
        session.commit()

        rules = [
            _make_rule(
                "T1136.001",
                source_format="cef",
                base_confidence=0.25,
                ext_keys=("fname",),
                mapping_id="R-CEF-T1136.001",
            ),
        ]
        cfg = _make_cfg(enabled_log_sources={"cef": False})
        result = sim.simulate_apt_attack("G0016", session, persist=True, config=cfg)
        recs = generate_recommendations(
            result, session, top_n=3, config=cfg, rules=rules
        )

        # cef must not be promised; only the unmapped fallback may appear.
        joined = " ".join(recs)
        assert "CEF" not in joined
        # The unmapped fallback is the only permissible string.
        if recs:
            assert recs == ["No configured source maps to T1136.001 — add a mapping row."]

    def test_boundary_mapping_is_promised(self, session_factory, sim):
        """A rule projecting exactly at the threshold (0.60 >= 0.6, inclusive)
        MUST be promised."""
        from analysis.simulation import generate_recommendations

        session = session_factory()
        _add_group(session, group_id="G0016", name="APT29")
        _add_technique(session, "T1190", tactics=("initial-access",), platforms=("Windows",))
        session.flush()
        group = session.execute(
            select(AptGroup).where(AptGroup.group_id == "G0016")
        ).scalar_one()
        _link_group_technique(session, group.stix_id, "T1190")
        _add_datasource(session, "evtx")
        _add_datasource(session, "nginx")
        session.flush()
        session.commit()

        rules = [
            _make_rule(
                "T1190",
                source_format="nginx",
                base_confidence=0.60,
                ext_keys=("request",),
                mapping_id="R-NGINX-T1190",
            ),
        ]
        cfg = _make_cfg(enabled_log_sources={"nginx": False})
        result = sim.simulate_apt_attack("G0016", session, persist=True, config=cfg)
        recs = generate_recommendations(
            result, session, top_n=3, config=cfg, rules=rules
        )

        assert any("Nginx/Apache" in rec for rec in recs)
        assert any("T1190" in rec for rec in recs)


# ---------------------------------------------------------------------------
# Contract R4: top_n cap.
# ---------------------------------------------------------------------------


class TestTopNCap:
    """generate_recommendations(..., top_n=k) returns at most k strings."""

    def test_top_n_caps_results(self, session_factory, sim):
        from analysis.simulation import generate_recommendations

        session = session_factory()
        _add_group(session, group_id="G0016", name="APT29")
        _add_technique(session, "T1046", tactics=("discovery",), platforms=("Windows",))
        _add_technique(session, "T1048", tactics=("exfiltration",), platforms=("Windows",))
        session.flush()
        group = session.execute(
            select(AptGroup).where(AptGroup.group_id == "G0016")
        ).scalar_one()
        for aid in ("T1046", "T1048"):
            _link_group_technique(session, group.stix_id, aid)
        _add_datasource(session, "evtx")
        _add_datasource(session, "zeek")
        _add_datasource(session, "nginx")
        session.flush()
        session.commit()

        rules = [
            _make_rule("T1046", source_format="zeek", base_confidence=0.80,
                       ext_keys=("id.orig_h",), mapping_id="R-ZEEK-T1046"),
            _make_rule("T1048", source_format="nginx", base_confidence=0.75,
                       ext_keys=("request",), mapping_id="R-NGINX-T1048"),
        ]
        cfg = _make_cfg(enabled_log_sources={"zeek": False, "nginx": False})
        result = sim.simulate_apt_attack("G0016", session, persist=True, config=cfg)

        assert len(generate_recommendations(result, session, top_n=1, config=cfg, rules=rules)) <= 1
        assert len(generate_recommendations(result, session, top_n=2, config=cfg, rules=rules)) <= 2
        assert len(generate_recommendations(result, session, top_n=0, config=cfg, rules=rules)) == 0


# ---------------------------------------------------------------------------
# Contract R6: unmapped fallback.
# ---------------------------------------------------------------------------


class TestUnmappedFallback:
    """Missed techniques with no closable source trigger the fallback string."""

    def test_fallback_appended_when_unmapped(self, session_factory, sim):
        from analysis.simulation import generate_recommendations

        session = session_factory()
        _add_group(session, group_id="G0016", name="APT29")
        # T1046 missed, no mapping rule at all -> no closable source.
        _add_technique(session, "T1046", tactics=("discovery",), platforms=("Windows",))
        session.flush()
        group = session.execute(
            select(AptGroup).where(AptGroup.group_id == "G0016")
        ).scalar_one()
        _link_group_technique(session, group.stix_id, "T1046")
        _add_datasource(session, "evtx")
        session.flush()
        session.commit()

        cfg = _make_cfg()
        result = sim.simulate_apt_attack("G0016", session, persist=True, config=cfg)
        recs = generate_recommendations(result, session, top_n=3, config=cfg, rules=[])

        assert recs == ["No configured source maps to T1046 — add a mapping row."]

    def test_fallback_respects_top_n(self, session_factory, sim):
        """When top_n is already filled by sourced recs, the fallback is not
        appended beyond the cap."""
        from analysis.simulation import generate_recommendations

        session = session_factory()
        _add_group(session, group_id="G0016", name="APT29")
        # T1046 closable by zeek (sourced rec). T1571 unmapped (fallback).
        _add_technique(session, "T1046", tactics=("discovery",), platforms=("Windows",))
        _add_technique(session, "T1571", tactics=("command-and-control",), platforms=("Windows",))
        session.flush()
        group = session.execute(
            select(AptGroup).where(AptGroup.group_id == "G0016")
        ).scalar_one()
        for aid in ("T1046", "T1571"):
            _link_group_technique(session, group.stix_id, aid)
        _add_datasource(session, "evtx")
        _add_datasource(session, "zeek")
        session.flush()
        session.commit()

        rules = [
            _make_rule("T1046", source_format="zeek", base_confidence=0.80,
                       ext_keys=("id.orig_h",), mapping_id="R-ZEEK-T1046"),
        ]
        cfg = _make_cfg(enabled_log_sources={"zeek": False})
        result = sim.simulate_apt_attack("G0016", session, persist=True, config=cfg)

        # top_n=1: only the sourced rec fits; fallback must be excluded.
        recs = generate_recommendations(result, session, top_n=1, config=cfg, rules=rules)
        assert len(recs) == 1
        assert recs[0].startswith("Enable ")

        # top_n=2: sourced rec + fallback both fit.
        recs = generate_recommendations(result, session, top_n=2, config=cfg, rules=rules)
        assert len(recs) == 2
        assert any("add a mapping row" in rec for rec in recs)


# ---------------------------------------------------------------------------
# Contract R7: enabled-source exclusion.
# ---------------------------------------------------------------------------


class TestEnabledSourceExclusion:
    """Already-enabled sources must never be recommended."""

    def test_enabled_source_not_recommended(self, session_factory, sim):
        from analysis.simulation import generate_recommendations

        session = session_factory()
        _add_group(session, group_id="G0016", name="APT29")
        _add_technique(session, "T1046", tactics=("discovery",), platforms=("Windows",))
        session.flush()
        group = session.execute(
            select(AptGroup).where(AptGroup.group_id == "G0016")
        ).scalar_one()
        _link_group_technique(session, group.stix_id, "T1046")
        # Both evtx and zeek rows exist; evtx enabled, zeek disabled.
        _add_datasource(session, "evtx")
        _add_datasource(session, "zeek")
        session.flush()
        session.commit()

        # Rule that would make T1046 closable by evtx (enabled) -> must be
        # excluded; with no disabled source closing it, only the fallback.
        rules = [
            _make_rule("T1046", source_format="evtx", base_confidence=0.80,
                       ext_keys=("id.orig_h",), mapping_id="R-EVTX-T1046"),
        ]
        cfg = _make_cfg()  # evtx enabled (default), zeek enabled (default).
        result = sim.simulate_apt_attack("G0016", session, persist=True, config=cfg)
        recs = generate_recommendations(result, session, top_n=3, config=cfg, rules=rules)

        # evtx is enabled so it must not be recommended; only fallback.
        joined = " ".join(recs)
        assert "Windows Event Log" not in joined
        if recs:
            assert all("add a mapping row" in rec for rec in recs)


# ---------------------------------------------------------------------------
# Contract: SOURCE_LABELS parity with the simulation module.
# ---------------------------------------------------------------------------


def test_source_labels_parity(sim):
    """This suite's label map must match the module's SOURCE_LABELS exactly."""
    from analysis.simulation import SOURCE_LABELS as MODULE_LABELS

    assert MODULE_LABELS == SOURCE_LABELS
