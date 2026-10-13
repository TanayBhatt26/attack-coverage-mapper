"""Core contract tests for the Phase 5 hunt-query dispatch engine.

Verifies the work-list invariant and frozen output shape of
:func:`detections.hunt_query_generator.export_all_queries` — the strongest
guarantees the Phase-6 Streamlit Hunt view depends on.  These tests run
offline against the committed ``db/coverage.db`` via the read-only fixture
(:func:`tests.test_integration_phase4._attach_readonly_sqlite`) and roll back
all Phase-5 persistence so they are idempotent.

TheSigmaHQ *match* tier is exercised in ``test_sigma_index.py`` (which builds
a controlled clone); here we verify dispatch structure, which is clone-
independent.
"""

from __future__ import annotations

from collections import OrderedDict
from pathlib import Path

import pytest
from sqlalchemy import select

from src.database.models import SimulationResult, SimulationTechnique
from src.detections.hand_written import ATTRIBUTION_LABELS
from src.detections.hunt_query_generator import export_all_queries

# Reuse the read-only SQLite fixture from the Phase-4 integration tests so
# we never mutate the committed db/coverage.db.  Import here (not at module
# top) to avoid a hard dependency on the phase4 test module layout.
from tests.test_integration_phase4 import _attach_readonly_sqlite  # noqa: E402

# Skip all hunt query generator tests if the dev database doesn't have the required tables.
def _db_has_tables() -> bool:
    db_path = Path(__file__).resolve().parents[2] / "db" / "coverage.db"
    if not db_path.exists():
        return False
    try:
        from src.database.session import make_engine
        from sqlalchemy import inspect
        engine = make_engine(f"sqlite:///{db_path}")
        try:
            tables = inspect(engine).get_table_names()
            return "simulation_results" in tables
        finally:
            engine.dispose()
    except Exception:
        return False

pytestmark = pytest.mark.skipif(
    not _db_has_tables(),
    reason="Hunt query generator tests require populated db/coverage.db (run ATT&CK ingest first)",
)

# The exact frozen field set every emitted query dict must carry
# (docs/_phase4_handoff.md:2.1).
REQUIRED_FIELDS = frozenset(
    {
        "query",
        "query_language",
        "attribution_label",
        "source_rule_id",
        "closable_by",
        "confidence",
    }
)


@pytest.fixture(scope="module")
def repo_config() -> dict:
    from src.config_loader import load_config

    return load_config("config.yaml")


class TestWorkListInvariant:
    """The work-list invariant: one query per missed technique."""

    def test_g0016_emits_one_query_per_missed(
        self, tmp_path: Path, repo_config: dict
    ) -> None:
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = (
                session.execute(select(SimulationResult))
                .scalars()
                .first()
            )
            assert result is not None, "no simulation result in committed DB"
            queries = export_all_queries(
                result.id, session=session, config=repo_config
            )
            session.rollback()  # demo must be re-runnable
            assert isinstance(queries, OrderedDict)
            assert len(queries) == result.missed_count
        finally:
            session.close()
            engine.dispose()

    def test_ordered_by_technique_id_asc(
        self, tmp_path: Path, repo_config: dict
    ) -> None:
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = (
                session.execute(select(SimulationResult))
                .scalars()
                .first()
            )
            queries = export_all_queries(
                result.id, session=session, config=repo_config
            )
            session.rollback()
            assert list(queries.keys()) == sorted(queries.keys())
        finally:
            session.close()
            engine.dispose()

    def test_frozen_field_set(self, tmp_path: Path, repo_config: dict) -> None:
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = (
                session.execute(select(SimulationResult))
                .scalars()
                .first()
            )
            queries = export_all_queries(
                result.id, session=session, config=repo_config
            )
            session.rollback()
            for tid, q in queries.items():
                assert frozenset(q.keys()) == REQUIRED_FIELDS, (
                    f"{tid}: bad fields {frozenset(q.keys())}"
                )
        finally:
            session.close()
            engine.dispose()

    def test_attribution_labels_valid(
        self, tmp_path: Path, repo_config: dict
    ) -> None:
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = (
                session.execute(select(SimulationResult))
                .scalars()
                .first()
            )
            queries = export_all_queries(
                result.id, session=session, config=repo_config
            )
            session.rollback()
            for tid, q in queries.items():
                assert q["attribution_label"] in ATTRIBUTION_LABELS, (
                    f"{tid}: bad label {q['attribution_label']}"
                )
        finally:
            session.close()
            engine.dispose()

    def test_queries_are_inert(self, tmp_path: Path, repo_config: dict) -> None:
        from src.detections.hand_written import is_inert

        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = (
                session.execute(select(SimulationResult))
                .scalars()
                .first()
            )
            queries = export_all_queries(
                result.id, session=session, config=repo_config
            )
            session.rollback()
            for tid, q in queries.items():
                assert is_inert(q["query"]), f"{tid}: query not inert"
                # Belt-and-suspenders: no forbidden tokens anywhere.
                for token in ("eval(", "exec(", "subprocess", "os.system"):
                    assert token not in q["query"], (
                        f"{tid}: forbidden token {token}"
                    )
        finally:
            session.close()
            engine.dispose()

    def test_closable_by_is_tuple(
        self, tmp_path: Path, repo_config: dict
    ) -> None:
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = (
                session.execute(select(SimulationResult))
                .scalars()
                .first()
            )
            queries = export_all_queries(
                result.id, session=session, config=repo_config
            )
            session.rollback()
            for tid, q in queries.items():
                assert isinstance(q["closable_by"], tuple), (
                    f"{tid}: closable_by not a tuple"
                )
        finally:
            session.close()
            engine.dispose()
