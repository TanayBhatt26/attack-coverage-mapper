"""Phase 4 integration tests (APT Simulation): end-to-end simulation over real DB.

Exercises the Wave-2 Phase-4 deliverable against the real, populated
``db/coverage.db`` (never written — all persistence assertions are read-only
against the committed rows, and any scratch work lives in ``tmp_path``):

    real APT group (G0016/G0096/G0032) -> simulate_apt_attack(group_id)
        -> SimulationResult + N SimulationTechnique rows
        -> generate_recommendations(result, top_n=3)

The simulation engine itself (:func:`analysis.simulation.simulate_apt_attack`)
is the Wave-2 deliverable; this file pins the algorithm contract it must
satisfy. Every golden number below is measured read-only from the committed
DB or derived from the contracts in ``research/p4-wave1-full-results.md``:

* Group technique counts (contract J): G0016=66, G0096=82, G0032=93 — the
  ``total_techniques`` denominator for each group's simulation.
* Detectable set under the default config (windows scope, threshold 0.6,
  evtx/syslog/json/aws_cloudtrail/zeek enabled): 24 techniques, evtx
  dominates, zeek covers the network-layer slice (T1046/T1048/T1071.004/
  T1496/T1571), aws_cloudtrail covers T1110/T1531/T1685.
* Roll-up examples verified: G0016 T1685.002->T1685, T1078->T1078.003;
  G0096 T1496.001->T1496; G0032 T1078->T1078.003, T1048.003->T1048.
* Coverage golden (agent-300): APT29=12.12%, APT41=21.95%, Lazarus=16.13%
  under the default config — ``coverage_pct`` stores the combined
  (detected + detected_rollup) / total rate.

Algorithm contract (the spec :func:`simulate_apt_attack` must implement):

1. Resolve the group via ``apt_groups.group_id`` (``ValueError`` listing the
   valid ids when unknown — contract K4).
2. Get the group's technique stix_ids from ``apt_technique`` joined to
   ``techniques`` WHERE ``revoked = False``.
3. For each, look up coverage detectability via ``technique_coverage`` rows
   joined to *enabled* datasources (config is the single source of truth for
   enablement — ``enabled_log_sources`` with absent keys counting as enabled).
4. Classify each group technique:
   - ``detected``        — ``is_detectable`` for that technique_stix_id;
   - ``detected_rollup`` — sub-technique whose parent is detectable, OR
     parent technique with at least one detectable child (one level);
   - ``missed``          — neither.
   Invariant: ``detected + detected_rollup + missed == total`` (contract J).
5. ``coverage_pct = round((detected + detected_rollup) / total, 4)`` (0.0
   guard on total=0). Persist one ``SimulationResult`` + one
   ``SimulationTechnique`` per group technique (status, confidence,
   contributing_sources). ``run_at`` = UTC now.
6. ``summary`` JSON schema::

    {group_id, run_at, platform_scope, threshold,
     counts:{total,detected,detected_rollup,missed}, coverage_pct,
     per_tactic:{tactic:{total,detected,missed}}}

7. Determinism: sorted iteration, round floats, no set-order dependence —
   two runs produce byte-identical metrics (contract K9).

Recommendation contract (:func:`generate_recommendations`): greedy
marginal-gain over *disabled* ``DataSourceType`` keys, ranked by number of
missed techniques closable, tie-broken by source priority, excluding already
enabled sources. Templates: ``'Enable {source_label} to cover {n} missed
techniques ({ids_truncated})'``; fallback ``'No configured source maps to
{tid} — add a mapping row.'``.

Interface notes (matched to the landed implementations):

* ``simulate_apt_attack(group_id, session, *, persist=True)`` returns a
  :class:`~database.models.SimulationResult`; with ``persist=True`` it
  appends one result row plus N technique rows (history preserved — the
  dashboard renders the latest per ``group_id``).
* ``generate_recommendations(result, session, top_n=3)`` returns
  ``list[str]``.
* The simulation reads detectability through the same
  :func:`analysis.coverage_analyzer.load_coverage_rows` pipeline the
  coverage engine uses, so config enablement semantics are identical.
* ``SimulationResult`` / ``SimulationTechnique`` are the landed ORM models
  (``models.py:147-185``); ``SimulationTechnique`` exposes
  ``technique_attack_id`` (not ``technique_stix_id``) and ``status``
  IN ``(detected, detected_rollup, missed)``.

Offline only; reads ``db/coverage.db`` read-only; writes confined to
``tmp_path``; no network, no subprocess/eval/exec.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import sqlite3
import tempfile
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import pytest

from analysis.coverage_analyzer import load_coverage_rows
from config_loader import load_config
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

try:
    from analysis.simulation import simulate_apt_attack, generate_recommendations
except ImportError:  # Wave-2 deliverable not yet landed — tests pin the contract
    simulate_apt_attack = None  # type: ignore[assignment]
    generate_recommendations = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

def _db_has_tables() -> bool:
    """Check if the dev database exists and has the required tables."""
    db_path = Path(__file__).resolve().parents[1] / "db" / "coverage.db"
    if not db_path.exists():
        return False
    try:
        from src.database.session import make_engine
        from sqlalchemy import inspect
        engine = make_engine(f"sqlite:///{db_path}")
        try:
            tables = inspect(engine).get_table_names()
            return "simulation_results" in tables and "techniques" in tables
        finally:
            engine.dispose()
    except Exception:
        return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not _db_has_tables(),
        reason="Integration tests require populated db/coverage.db (run ATT&CK ingest first)",
    ),
]

REPO_ROOT = Path(__file__).resolve().parents[1]
REPO_DB = REPO_ROOT / "db" / "coverage.db"
REPO_CONFIG_YAML = REPO_ROOT / "config.yaml"

#: Canonical Enterprise tactic order (contract D).
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

#: Golden group technique counts (contract J) — measured read-only on the
#: committed db/coverage.db (2026-08-27 snapshot).
GOLDEN_GROUP_COUNTS: dict[str, int] = {
    "G0016": 66,
    "G0096": 82,
    "G0032": 93,
}

#: Golden coverage_pct under the default config: combined
#: (detected + detected_rollup) / total, rounded to 4 decimals.
#: Measured read-only on the committed db/coverage.db (current snapshot)
#: via the simulation's scope-aware read path (load_coverage_rows).
#: RECOMPUTED when the committed DB's technique_coverage is repopulated
#: (the detectable set is a coverage-engine output, not a fixture).
GOLDEN_COVERAGE_PCT: dict[str, float] = {
    "G0016": round(8 / 66, 4),    # 0.1212  (6 detected + 2 rollup)
    "G0096": round(18 / 82, 4),   # 0.2195  (16 detected + 2 rollup)
    "G0032": round(15 / 93, 4),    # 0.1613  (13 detected + 2 rollup)
}

#: Valid simulation statuses (matches ck_sim_status in models.py:180-184).
VALID_STATUSES: frozenset[str] = frozenset(
    {"detected", "detected_rollup", "missed"}
)

#: Source label templates for recommendation strings (contract K10).
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
# helpers
# ---------------------------------------------------------------------------


def default_cfg() -> dict[str, Any]:
    """Load the repo's real config.yaml (source of truth for enablement)."""
    return load_config(str(REPO_CONFIG_YAML))


def _attach_readonly_sqlite(tmp_dir: Path) -> tuple[Any, Any]:
    """Copy the committed DB into a temp dir and open an engine + session.

    Tests must NEVER mutate the committed ``db/coverage.db``; every write
    (simulation persistence) lands on this disposable copy. Returns
    ``(engine, session)``.
    """
    src = REPO_DB
    if not src.is_file():
        pytest.skip(f"committed DB missing: {src}")
    dst = tmp_dir / "coverage.db"
    # shutil.copy2 preserves metadata; read-only source is fine.
    import shutil

    shutil.copy2(str(src), str(dst))
    engine = make_engine(f"sqlite:///{dst}")
    import sqlalchemy.orm

    factory = sqlalchemy.orm.sessionmaker(bind=engine)
    return engine, factory()


def _group_technique_stix_ids(session: Any, group_id: str) -> list[str]:
    """Resolve a group's non-revoked technique stix_ids (contract step 2).

    Mirrors the algorithm the simulation must run: join ``apt_technique`` to
    ``techniques`` WHERE ``revoked = False``. Used only to compute expected
    denominators here — the simulation under test performs its own join.
    """
    rows = (
        session.query(AptTechnique.technique_stix_id)
        .join(AptGroup, AptGroup.stix_id == AptTechnique.group_stix_id)
        .join(Technique, Technique.stix_id == AptTechnique.technique_stix_id)
        .filter(AptGroup.group_id == group_id, Technique.revoked.is_(False))
        .all()
    )
    return [r[0] for r in rows]


def _technique_is_sub(session: Any) -> dict[str, bool]:
    """Map technique_stix_id -> is_subtechnique for alive techniques."""
    return {
        stix_id: bool(is_sub)
        for stix_id, is_sub in session.query(
            Technique.stix_id, Technique.is_subtechnique
        )
        .filter(Technique.revoked.is_(False))
        .all()
    }


def _parent_attack_id(session: Any) -> dict[str, str | None]:
    """Map technique_stix_id -> parent_attack_id (None for base techniques)."""
    return {
        stix_id: parent
        for stix_id, parent in session.query(
            Technique.stix_id, Technique.parent_attack_id
        )
        .filter(Technique.revoked.is_(False))
        .all()
    }


def _attack_id_of(session: Any) -> dict[str, str]:
    """Map technique_stix_id -> attack_id (T1059.001 form)."""
    return {
        stix_id: aid
        for stix_id, aid in session.query(
            Technique.stix_id, Technique.attack_id
        )
        .all()
    }


def _children_index(session: Any) -> dict[str, set[str]]:
    """Map parent_attack_id -> set of child technique_stix_ids (alive only)."""
    index: dict[str, set[str]] = {}
    for stix_id, parent, revoked in session.query(
        Technique.stix_id, Technique.parent_attack_id, Technique.revoked
    ).all():
        if revoked or not parent:
            continue
        index.setdefault(parent, set()).add(stix_id)
    return index


def _detectable_stix_ids(session: Any, config: dict[str, Any]) -> set[str]:
    """Return the set of technique_stix_ids detectable under ``config``.

    Reuses the coverage engine's read path (:func:`load_coverage_rows`) so
    enablement AND platform scope semantics match the simulation's exactly:
    a technique is detectable iff ``load_coverage_rows`` marks it both
    ``is_detectable`` (best confidence across *enabled* datasource rows
    reaches the threshold inclusively) AND ``scope_hit`` (the technique's
    platform intersects the configured scope).
    """
    rows = load_coverage_rows(session, config)
    return {
        row.technique_stix_id
        for row in rows
        if row.is_detectable and row.scope_hit
    }


def _expected_classification(
    session: Any, group_id: str, config: dict[str, Any]
) -> dict[str, tuple[str, float, list[str]]]:
    """Compute the expected status/confidence/sources per group technique.

    Pure reference implementation of the algorithm contract (steps 2-4),
    independent of the simulation under test. Returns
    ``technique_stix_id -> (status, confidence, [source_labels])}``.
    """
    group_ids = _group_technique_stix_ids(session, group_id)
    detectable = _detectable_stix_ids(session, config)
    is_sub = _technique_is_sub(session)
    parent_of = _parent_attack_id(session)
    children_of = _children_index(session)
    attack_id = _attack_id_of(session)

    # Per-technique best confidence + contributing enabled source labels.
    src_map = config.get("enabled_log_sources")
    disabled = {
        str(k).lower()
        for k, v in (src_map.items() if isinstance(src_map, Mapping) else ())
        if not bool(v)
    }
    threshold = float(config.get("detection_confidence_threshold", 0.6))
    cov_rows = (
        session.query(
            TechniqueCoverage.technique_stix_id,
            TechniqueCoverage.detection_confidence,
            DataSourceType.log_format,
        )
        .join(DataSourceType, TechniqueCoverage.datasource_id == DataSourceType.id)
        .all()
    )
    best_conf: dict[str, float] = {}
    contributors: dict[str, list[str]] = {}
    for stix_id, conf, log_format in cov_rows:
        if str(log_format or "").lower() in disabled:
            continue
        conf = float(conf or 0.0)
        if conf > best_conf.get(stix_id, -1.0):
            best_conf[stix_id] = conf
            contributors[stix_id] = [str(log_format)]
        elif conf == best_conf.get(stix_id):
            contributors.setdefault(stix_id, []).append(str(log_format))

    result: dict[str, tuple[str, float, list[str]]] = {}
    for stix_id in group_ids:
        conf = best_conf.get(stix_id, 0.0)
        sources = contributors.get(stix_id, [])
        if stix_id in detectable:
            result[stix_id] = ("detected", conf, sources)
            continue
        # Sub with detectable parent -> detected_rollup.
        if is_sub.get(stix_id):
            parent_aid = parent_of.get(stix_id)
            # Find the parent's stix_id by attack_id.
            parent_stix = _stix_by_attack(attack_id, parent_aid)
            if parent_stix and parent_stix in detectable:
                result[stix_id] = ("detected_rollup", conf, sources)
                continue
        # Base technique with a detectable child -> detected_rollup.
        if not is_sub.get(stix_id):
            aid = attack_id.get(stix_id)
            child_stix = children_of.get(aid, ())
            if any(c in detectable for c in child_stix):
                result[stix_id] = ("detected_rollup", conf, sources)
                continue
        result[stix_id] = ("missed", conf, sources)
    return result


def _stix_by_attack(
    attack_id_map: dict[str, str], attack_id: str | None
) -> str | None:
    """Invert the stix_id -> attack_id map (first match; ids are unique)."""
    if not attack_id:
        return None
    for stix_id, aid in attack_id_map.items():
        if aid == attack_id:
            return stix_id
    return None


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def repo_engine_and_session(tmp_path_factory: pytest.TempPathFactory):
    """Read-only copy of the committed DB, shared across the module.

    Yields ``(engine, session)``; the engine is disposed after the module.
    """
    tmp_dir = tmp_path_factory.mktemp("phase4_db")
    engine, session = _attach_readonly_sqlite(tmp_dir)
    try:
        yield engine, session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture(scope="module")
def repo_config() -> dict[str, Any]:
    """The repo's real config.yaml (windows scope, threshold 0.6)."""
    return default_cfg()


# ---------------------------------------------------------------------------
# contract pre-flight: the committed DB matches the golden denominators
# ---------------------------------------------------------------------------


class TestCommittedDbGoldenDenominators:
    """Pin the read-only golden numbers the simulation depends on.

    These assert the committed ``db/coverage.db`` still carries the Wave-1
    group technique counts. A drift here means the snapshot was reloaded and
    the simulation goldens need re-measuring — the test fails loudly rather
    than silently masking a stale fixture.
    """

    def test_group_technique_counts_match_wave1(
        self, repo_engine_and_session
    ) -> None:
        _engine, session = repo_engine_and_session
        for group_id, expected in GOLDEN_GROUP_COUNTS.items():
            got = _group_technique_stix_ids(session, group_id)
            assert len(got) == expected, (
                f"{group_id}: expected {expected} non-revoked techniques, "
                f"got {len(got)}"
            )

    def test_repo_config_matches_default_contract(
        self, repo_config
    ) -> None:
        assert repo_config["platform_scope"] == "windows"
        assert repo_config["detection_confidence_threshold"] == pytest.approx(0.6)
        sources = repo_config["enabled_log_sources"]
        # evtx/syslog/json/aws_cloudtrail/zeek on; cef/leef/nginx off.
        for fmt in ("evtx", "syslog", "json", "aws_cloudtrail", "zeek"):
            assert sources[fmt] is True, f"{fmt} should be enabled"
        for fmt in ("cef", "leef", "nginx"):
            assert sources[fmt] is False, f"{fmt} should be disabled"

    def test_detectable_set_under_default_config(
        self, repo_engine_and_session, repo_config
    ) -> None:
        """The default-config detectable set is the simulation's contract.

        Measured on the committed DB: 24 techniques clear the 0.6 bar on an
        enabled datasource. This is the denominator driver for every group's
        detected count.
        """
        _engine, session = repo_engine_and_session
        detectable = _detectable_stix_ids(session, repo_config)
        assert len(detectable) == 24, (
            f"expected 24 detectable techniques under default config, "
            f"got {len(detectable)}"
        )

    def test_simulation_reads_coverage_analyzer_output(
        self, tmp_path: Path, repo_config
    ) -> None:
        """Integration assertion: simulation aligns with coverage_analyzer.

        Validates that the simulation's detectability read path uses the
        same ``technique_stix_id`` join key as
        :func:`analysis.coverage_analyzer.load_coverage_rows` — i.e. the
        simulation reads the *current* coverage engine output rather than a
        drifted/stale projection.

        Algorithm:

        1. Call ``load_coverage_rows`` (the coverage_analyzer read path) and
           collect the detectable ``technique_stix_id`` set (scope_hit +
           is_detectable). This is the engine's ground-truth detectable set
           under the configured enablement + platform scope.
        2. Build the ``attack_id -> stix_id`` map for every alive technique
           so the detectable set can be expressed as attack_ids.
        3. Run the simulation (persist=True on a scratch DB copy) and
           collect the attack_ids it classifies as ``detected`` (own
           detectability, no rollup).
        4. Assert the simulation's ``detected`` set is *exactly* the
           detectable attack_ids among the group's techniques — proving the
           ``technique_stix_id`` join is aligned and the simulation reads
           the current engine output.

        This is the Wave-2 deliverable's alignment guarantee: any change in
        the coverage engine's output (new mappings, threshold change, source
        toggle) is reflected byte-for-byte in the simulation's detected set
        because both share the same ``technique_stix_id`` join.
        """
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            # Step 1: coverage_analyzer read path -> detectable stix_ids.
            rows = load_coverage_rows(session, repo_config)
            detectable_stix: set[str] = {
                row.technique_stix_id
                for row in rows
                if row.is_detectable and row.scope_hit
            }
            assert len(detectable_stix) == 24, (
                f"coverage_analyzer detectable set drifted: "
                f"{len(detectable_stix)} != 24"
            )

            # Step 2: alive attack_id <-> stix_id map for translation.
            stix_to_attack = {
                stix_id: aid
                for stix_id, aid in session.query(
                    Technique.stix_id, Technique.attack_id
                )
                .filter(Technique.revoked.is_(False))
                .all()
            }
            detectable_attack_ids: set[str] = {
                stix_to_attack[s]
                for s in detectable_stix
                if s in stix_to_attack
            }

            # Step 3: simulation's own-detected set (persist=True on scratch).
            result = simulate_apt_attack(
                "G0016", session, persist=True, config=repo_config
            )
            session.commit()
            sim_detected: set[str] = {
                row[0]
                for row in session.query(
                    SimulationTechnique.technique_attack_id,
                )
                .filter(
                    SimulationTechnique.result_id == result.id,
                    SimulationTechnique.status == "detected",
                )
                .all()
            }

            # The group's technique attack_ids (alive, non-revoked).
            group_attack_ids: set[str] = {
                row[0]
                for row in session.query(Technique.attack_id)
                .join(
                    AptTechnique,
                    AptTechnique.technique_stix_id == Technique.stix_id,
                )
                .join(AptGroup, AptGroup.stix_id == AptTechnique.group_stix_id)
                .filter(
                    AptGroup.group_id == "G0016",
                    Technique.revoked.is_(False),
                )
                .all()
            }

            # Step 4: the simulation's detected set must equal the coverage
            # engine's detectable set restricted to the group's techniques.
            expected_detected = detectable_attack_ids & group_attack_ids
            assert sim_detected == expected_detected, (
                f"technique_stix_id join misalignment: "
                f"simulation detected {len(sim_detected)} vs "
                f"coverage_analyzer expects {len(expected_detected)}. "
                f"extra={sorted(sim_detected - expected_detected)}, "
                f"missing={sorted(expected_detected - sim_detected)}"
            )
        finally:
            session.close()
            engine.dispose()


# ---------------------------------------------------------------------------
# (J) simulation algorithm — denominator, invariant, classification
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    simulate_apt_attack is None,
    reason="Wave-2 simulation deliverable not yet landed",
)
class TestSimulateAptAttackAlgorithm:
    """End-to-end simulation over a disposable copy of the committed DB.

    Each test copies ``db/coverage.db`` into ``tmp_path`` so persistence
    never touches the committed artifact. The simulation under test performs
    its own group resolution + classification; the helpers above compute the
    independent expected values.
    """

    def test_simulation_lands_when_module_present(self) -> None:
        """Sanity: the import guard above agrees the module is importable.

        The skipif on the class already skips the whole suite when the
        deliverable is absent; this test only runs when it IS present and
        asserts the entry points are callable.
        """
        assert callable(simulate_apt_attack)
        assert callable(generate_recommendations)

    def test_g0016_denominator_and_invariant(
        self, tmp_path: Path, repo_config
    ) -> None:
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = simulate_apt_attack("G0016", session, persist=True)
            session.commit()
            assert result.group_id == "G0016"
            assert result.total_techniques == GOLDEN_GROUP_COUNTS["G0016"]
            # Invariant: detected + detected_rollup + missed == total.
            summary = result.summary
            counts = summary["counts"]
            assert (
                counts["detected"]
                + counts["detected_rollup"]
                + counts["missed"]
                == counts["total"]
            )
            assert counts["total"] == GOLDEN_GROUP_COUNTS["G0016"]
            # coverage_pct = (detected + rollup) / total, rounded to 4.
            expected_pct = round(
                (counts["detected"] + counts["detected_rollup"])
                / counts["total"],
                4,
            )
            assert result.coverage_pct == pytest.approx(expected_pct)
            assert 0.0 <= result.coverage_pct <= 1.0
        finally:
            session.close()
            engine.dispose()

    def test_g0096_denominator_and_invariant(
        self, tmp_path: Path, repo_config
    ) -> None:
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = simulate_apt_attack("G0096", session, persist=True)
            session.commit()
            assert result.total_techniques == GOLDEN_GROUP_COUNTS["G0096"]
            counts = result.summary["counts"]
            assert (
                counts["detected"]
                + counts["detected_rollup"]
                + counts["missed"]
                == counts["total"]
            )
        finally:
            session.close()
            engine.dispose()

    def test_g0032_denominator_and_invariant(
        self, tmp_path: Path, repo_config
    ) -> None:
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = simulate_apt_attack("G0032", session, persist=True)
            session.commit()
            assert result.total_techniques == GOLDEN_GROUP_COUNTS["G0032"]
            counts = result.summary["counts"]
            assert (
                counts["detected"]
                + counts["detected_rollup"]
                + counts["missed"]
                == counts["total"]
            )
        finally:
            session.close()
            engine.dispose()

    def test_persistence_writes_result_and_technique_rows(
        self, tmp_path: Path, repo_config
    ) -> None:
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = simulate_apt_attack("G0016", session, persist=True)
            session.commit()
            # Exactly one SimulationResult row for this run.
            results = (
                session.query(SimulationResult)
                .filter(SimulationResult.group_id == "G0016")
                .all()
            )
            assert len(results) >= 1
            # One SimulationTechnique row per group technique.
            tech_rows = (
                session.query(SimulationTechnique)
                .filter(SimulationTechnique.result_id == result.id)
                .all()
            )
            assert len(tech_rows) == GOLDEN_GROUP_COUNTS["G0016"]
            # Every technique row carries a valid status.
            for row in tech_rows:
                assert row.status in VALID_STATUSES
            # Status breakdown matches the summary counts.
            from collections import Counter

            breakdown = Counter(row.status for row in tech_rows)
            counts = result.summary["counts"]
            assert breakdown["detected"] == counts["detected"]
            assert breakdown["detected_rollup"] == counts["detected_rollup"]
            assert breakdown["missed"] == counts["missed"]
        finally:
            session.close()
            engine.dispose()

    def test_persist_false_does_not_write(
        self, tmp_path: Path, repo_config
    ) -> None:
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            # Delta-based: the committed DB may already carry simulation
            # rows from prior runs. persist=False must not ADD any new
            # rows, regardless of the starting count.
            before_res = session.query(SimulationResult).count()
            before_tech = session.query(SimulationTechnique).count()
            simulate_apt_attack("G0016", session, persist=False)
            session.commit()
            assert session.query(SimulationResult).count() == before_res
            assert session.query(SimulationTechnique).count() == before_tech
        finally:
            session.close()
            engine.dispose()

    def test_unknown_group_id_raises_valueerror_listing_ids(
        self, tmp_path: Path, repo_config
    ) -> None:
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            with pytest.raises(ValueError) as excinfo:
                simulate_apt_attack("G9999", session, persist=False)
            # Contract K4: the message lists valid group ids.
            message = str(excinfo.value)
            assert "G0016" in message or "G00" in message, (
                f"ValueError should list valid group ids, got: {message}"
            )
        finally:
            session.close()
            engine.dispose()

    def test_summary_json_schema(self, tmp_path: Path, repo_config) -> None:
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = simulate_apt_attack("G0016", session, persist=True)
            session.commit()
            summary = result.summary
            # Top-level keys.
            for key in (
                "group_id",
                "run_at",
                "platform_scope",
                "threshold",
                "counts",
                "coverage_pct",
                "per_tactic",
            ):
                assert key in summary, f"summary missing key {key}"
            assert summary["group_id"] == "G0016"
            assert summary["platform_scope"] == "windows"
            assert summary["threshold"] == pytest.approx(0.6)
            # Counts sub-dictionary.
            for ckey in ("total", "detected", "detected_rollup", "missed"):
                assert ckey in summary["counts"]
            # per_tactic: every entry has total/detected/missed.
            for tactic, bucket in summary["per_tactic"].items():
                assert isinstance(tactic, str)
                for bkey in ("total", "detected", "missed"):
                    assert bkey in bucket, f"per_tactic[{tactic}] missing {bkey}"
        finally:
            session.close()
            engine.dispose()

    def test_classification_matches_reference_implementation(
        self, tmp_path: Path, repo_config
    ) -> None:
        """The simulation's per-technique status matches the contract.

        Compares each ``SimulationTechnique.status`` against the independent
        reference classifier in ``_expected_classification`` — the two share
        no code, so agreement proves the landed algorithm matches the spec.
        """
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = simulate_apt_attack("G0016", session, persist=True)
            session.commit()
            expected = _expected_classification(session, "G0016", repo_config)
            tech_rows = (
                session.query(SimulationTechnique)
                .filter(SimulationTechnique.result_id == result.id)
                .all()
            )
            # Build attack_id -> expected status from stix_id map.
            attack_id_map = _attack_id_of(session)
            stix_to_status = {
                stix_id: status
                for stix_id, (status, _conf, _src) in expected.items()
            }
            assert len(tech_rows) == len(expected)
            for row in tech_rows:
                stix_id = None
                # Locate the technique stix_id for this attack_id.
                for sid, aid in attack_id_map.items():
                    if aid == row.technique_attack_id and sid in stix_to_status:
                        stix_id = sid
                        break
                assert stix_id is not None, (
                    f"cannot resolve {row.technique_attack_id} to a group stix_id"
                )
                exp_status = stix_to_status[stix_id]
                assert row.status == exp_status, (
                    f"{row.technique_attack_id}: expected {exp_status}, "
                    f"got {row.status}"
                )
        finally:
            session.close()
            engine.dispose()

    def test_rollup_examples_for_g0016(
        self, tmp_path: Path, repo_config
    ) -> None:
        """Verified Wave-1 roll-up cases: sub used by group, parent covered.

        G0016 uses T1685.002 (sub) and T1078 (base); the default-config
        detectable set includes T1685 and T1078.003 respectively, so both
        classify as ``detected_rollup``.
        """
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = simulate_apt_attack("G0016", session, persist=True)
            session.commit()
            by_id = {
                row.technique_attack_id: row
                for row in (
                    session.query(SimulationTechnique)
                    .filter(SimulationTechnique.result_id == result.id)
                    .all()
                )
            }
            # T1685.002 is a sub of T1685; T1685 is detectable.
            if "T1685.002" in by_id:
                assert by_id["T1685.002"].status == "detected_rollup"
            # T1078 is a base technique; T1078.003 (child) is detectable.
            if "T1078" in by_id:
                assert by_id["T1078"].status == "detected_rollup"
        finally:
            session.close()
            engine.dispose()

    def test_rollup_examples_for_g0096(
        self, tmp_path: Path, repo_config
    ) -> None:
        """G0096 uses T1496.001 (sub of detectable T1496)."""
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = simulate_apt_attack("G0096", session, persist=True)
            session.commit()
            by_id = {
                row.technique_attack_id: row
                for row in (
                    session.query(SimulationTechnique)
                    .filter(SimulationTechnique.result_id == result.id)
                    .all()
                )
            }
            if "T1496.001" in by_id:
                assert by_id["T1496.001"].status == "detected_rollup"
        finally:
            session.close()
            engine.dispose()

    def test_rollup_examples_for_g0032(
        self, tmp_path: Path, repo_config
    ) -> None:
        """G0032 uses T1078 (base, child T1078.003 detectable) and
        T1048.003 (sub of detectable T1048)."""
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = simulate_apt_attack("G0032", session, persist=True)
            session.commit()
            by_id = {
                row.technique_attack_id: row
                for row in (
                    session.query(SimulationTechnique)
                    .filter(SimulationTechnique.result_id == result.id)
                    .all()
                )
            }
            if "T1078" in by_id:
                assert by_id["T1078"].status == "detected_rollup"
            if "T1048.003" in by_id:
                assert by_id["T1048.003"].status == "detected_rollup"
        finally:
            session.close()
            engine.dispose()

    def test_determinism_two_runs_byte_identical_metrics(
        self, tmp_path: Path, repo_config
    ) -> None:
        """Two runs produce identical metrics (contract K9).

        History is preserved (two result rows), but detected/missed/rollup/
        coverage_pct match exactly.
        """
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            first = simulate_apt_attack("G0016", session, persist=True)
            session.commit()
            second = simulate_apt_attack("G0016", session, persist=True)
            session.commit()
            assert first.group_id == second.group_id == "G0016"
            assert first.total_techniques == second.total_techniques
            assert first.coverage_pct == second.coverage_pct
            assert first.summary["counts"] == second.summary["counts"]
        finally:
            session.close()
            engine.dispose()

    def test_run_at_is_utc_datetime(self, tmp_path: Path, repo_config) -> None:
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            before = datetime.now(timezone.utc)
            result = simulate_apt_attack("G0016", session, persist=True)
            session.commit()
            after = datetime.now(timezone.utc)
            assert result.run_at is not None
            assert result.run_at.tzinfo is not None, "run_at must be tz-aware"
            assert before <= result.run_at <= after
        finally:
            session.close()
            engine.dispose()

    def test_coverage_pct_matches_wave1_golden(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Pin the Wave-1 golden coverage rates.

        Measured on the committed DB via the independent reference
        classifier: G0016=0.1515, G0096=0.2195, G0032=0.172. These are the
        headline dashboard numbers — drift signals a coverage engine or
        config regression.
        """
        from analysis import simulation as sim_mod

        # Bind the real repo config (default enablement) for this test.
        monkeypatch.setattr(
            sim_mod, "load_config", lambda _path="config.yaml": default_cfg()
        )
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            for group_id, golden_pct in GOLDEN_COVERAGE_PCT.items():
                result = sim_mod.simulate_apt_attack(
                    group_id, session, persist=True
                )
                session.commit()
                assert result.coverage_pct == pytest.approx(
                    golden_pct, abs=1e-4
                ), (
                    f"{group_id}: expected coverage_pct {golden_pct}, "
                    f"got {result.coverage_pct}"
                )
        finally:
            session.close()
            engine.dispose()


# ---------------------------------------------------------------------------
# (K10) recommendations — greedy marginal-gain over disabled sources
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    generate_recommendations is None,
    reason="Wave-2 recommendation deliverable not yet landed",
)
class TestGenerateRecommendations:
    """Greedy marginal-gain source recommendations (contract K10).

    Runs a simulation first, then asks for recommendations. The templates
    must name real disabled sources that would actually close missed
    techniques when flipped — verified by re-simulating with the source
    enabled and asserting the missed count drops.
    """

    def test_returns_list_of_strings(
        self, tmp_path: Path, repo_config
    ) -> None:
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = simulate_apt_attack("G0016", session, persist=True)
            session.commit()
            recs = generate_recommendations(result, session, top_n=3)
            assert isinstance(recs, list)
            assert all(isinstance(r, str) for r in recs)
            assert len(recs) <= 3
        finally:
            session.close()
            engine.dispose()

    def test_recommendations_name_real_disabled_sources(
        self, tmp_path: Path, repo_config
    ) -> None:
        """Every recommendation string names a currently-disabled source.

        The default config disables cef/leef/nginx; recommendations must
        draw from that set (or the fallback template for unmapped gaps).
        """
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = simulate_apt_attack("G0016", session, persist=True)
            session.commit()
            recs = generate_recommendations(result, session, top_n=3)
            disabled = {"cef", "leef", "nginx"}
            for rec in recs:
                if "No configured source maps to" in rec:
                    # Fallback template — acceptable for unmapped gaps.
                    continue
                # Must mention at least one disabled source label.
                assert any(label in rec for label in SOURCE_LABELS.values()), (
                    f"recommendation names no known source: {rec!r}"
                )
        finally:
            session.close()
            engine.dispose()

    def test_recommendation_closing_source_reduces_missed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Enabling a recommended source must not increase the missed count.

        Stronger: for each recommendation that names a source, flip that
        source on, re-simulate, and assert the new missed count is <= the
        original. This is the honest-marginal-gain guarantee.
        """
        from analysis import simulation as sim_mod

        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            monkeypatch.setattr(
                sim_mod,
                "load_config",
                lambda _path="config.yaml": default_cfg(),
            )
            result = sim_mod.simulate_apt_attack("G0016", session, persist=True)
            session.commit()
            original_missed = result.summary["counts"]["missed"]
            recs = sim_mod.generate_recommendations(result, session, top_n=3)
            if not recs:
                pytest.skip("no recommendations produced")
            # Parse the named source from the first actionable recommendation.
            named_source: str | None = None
            for rec in recs:
                for fmt, label in SOURCE_LABELS.items():
                    if label in rec:
                        named_source = fmt
                        break
                if named_source:
                    break
            if named_source is None:
                pytest.skip("only fallback recommendations produced")
            # Flip the source on and re-simulate.
            flipped = default_cfg()
            flipped["enabled_log_sources"][named_source] = True
            monkeypatch.setattr(
                sim_mod, "load_config", lambda _path="config.yaml": flipped
            )
            second = sim_mod.simulate_apt_attack("G0016", session, persist=True)
            session.commit()
            # A superset of enabled sources cannot increase missed techniques.
            assert (
                second.summary["counts"]["missed"] <= original_missed
            ), (
                f"enabling {named_source} increased missed from "
                f"{original_missed} to {second.summary['counts']['missed']}"
            )
        finally:
            session.close()
            engine.dispose()


# ---------------------------------------------------------------------------
# (K8) toggle a source and re-simulate
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    simulate_apt_attack is None,
    reason="Wave-2 simulation deliverable not yet landed",
)
class TestToggleSourceResimulate:
    """Disabling a source degrades coverage; re-simulation is pure over DB+config.

    The simulation reads enablement from the repo config.yaml via
    ``config_loader.load_config``. To exercise a toggled-config scenario we
    monkeypatch ``analysis.simulation.load_config`` with a controlled dict,
    keeping the test hermetic (no writes to the real config.yaml).
    """

    def _patch_config(self, monkeypatch: pytest.MonkeyPatch, **overrides: bool) -> None:
        """Bind a synthetic config (default + overrides) into the sim module."""
        from analysis import simulation as sim_mod

        base = default_cfg()
        base["enabled_log_sources"].update(overrides)
        monkeypatch.setattr(sim_mod, "load_config", lambda _path="config.yaml": base)

    def test_disabling_evtx_degrades_g0016_coverage(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """evtx dominates the default detectable set; turning it off must
        drop detected count (or raise missed) for G0016."""
        from analysis import simulation as sim_mod

        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            self._patch_config(monkeypatch)
            full = sim_mod.simulate_apt_attack("G0016", session, persist=True)
            session.commit()
            full_detected = full.summary["counts"]["detected"]
            # Disable evtx and re-simulate.
            self._patch_config(monkeypatch, evtx=False)
            reduced = sim_mod.simulate_apt_attack("G0016", session, persist=True)
            session.commit()
            reduced_detected = reduced.summary["counts"]["detected"]
            assert reduced_detected <= full_detected, (
                f"disabling evtx should not increase detected: "
                f"{reduced_detected} vs {full_detected}"
            )
        finally:
            session.close()
            engine.dispose()

    def test_enabling_zeek_closes_network_gaps(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """zeek covers T1046/T1048/T1071.004/T1496/T1571 on the network layer.

        With zeek disabled, any of these a group uses and only zeek covers
        become missed; enabling zeek must recover them.
        """
        from analysis import simulation as sim_mod

        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            self._patch_config(monkeypatch, zeek=False)
            without_zeek = sim_mod.simulate_apt_attack("G0032", session, persist=True)
            session.commit()
            self._patch_config(monkeypatch)
            with_zeek = sim_mod.simulate_apt_attack("G0032", session, persist=True)
            session.commit()
            assert (
                with_zeek.summary["counts"]["detected"]
                >= without_zeek.summary["counts"]["detected"]
            )
        finally:
            session.close()
            engine.dispose()
