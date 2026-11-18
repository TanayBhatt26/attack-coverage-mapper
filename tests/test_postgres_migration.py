"""SQLite -> PostgreSQL migration and the production database contract.

Two layers:

* **Unit tests** (always run) for :mod:`database.session`'s deployment guard and
  the migration script's pure helpers -- URL resolution, ``APP_ENV`` handling,
  table ordering, datetime normalisation, and the refusal semantics.
* **Integration tests** (``TEST_POSTGRES_URL`` set) that perform a real
  migration into a throwaway PostgreSQL database and prove ids, sequences,
  refusal-on-duplicate and ``--verify-only`` behaviour end to end. They are
  skipped otherwise so the default suite never needs a live server.

Run the integration layer against the docker-compose service::

    docker compose up -d postgres
    TEST_POSTGRES_URL=postgresql+psycopg://attack_mapper:attack_mapper@localhost:5432/attack_coverage \\
        PYTHONPATH=src ./.venv/Scripts/python.exe -m pytest tests/test_postgres_migration.py -q
"""
from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import func, inspect, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from database.models import (  # noqa: E402
    AptGroup,
    AptTechnique,
    Base,
    DataSourceType,
    SimulationResult,
    SimulationTechnique,
    Technique,
)
from database.session import (  # noqa: E402
    DEVELOPMENT,
    PRODUCTION,
    app_env,
    database_url,
    make_engine,
    session_scope,
    verify_schema,
)

PG_URL = os.environ.get("TEST_POSTGRES_URL")
POSTGRES_AVAILABLE = bool(PG_URL)

requires_postgres = pytest.mark.skipif(
    not POSTGRES_AVAILABLE,
    reason="set TEST_POSTGRES_URL to a PostgreSQL database to run these tests",
)


# ---------------------------------------------------------------------------
# database.session -- deployment contract
# ---------------------------------------------------------------------------

class TestAppEnv:
    """``APP_ENV`` parsing."""

    def test_defaults_to_development(self, monkeypatch):
        monkeypatch.delenv("APP_ENV", raising=False)
        assert app_env() == DEVELOPMENT

    def test_reads_production(self, monkeypatch):
        monkeypatch.setenv("APP_ENV", "Production")
        assert app_env() == PRODUCTION

    def test_rejects_unknown_marker(self, monkeypatch):
        monkeypatch.setenv("APP_ENV", "staging")
        with pytest.raises(ValueError, match="invalid APP_ENV"):
            app_env()


class TestDatabaseUrl:
    """``database_url`` under both environments."""

    def test_development_defaults_to_sqlite(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.delenv("APP_ENV", raising=False)
        assert database_url().startswith("sqlite:///")

    def test_development_honours_explicit_url(self, monkeypatch):
        monkeypatch.setenv(
            "DATABASE_URL",
            "postgresql+psycopg://u:p@localhost:5432/coverage",
        )
        assert database_url() == "postgresql+psycopg://u:p@localhost:5432/coverage"

    def test_production_requires_an_explicit_url(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("APP_ENV", "production")
        with pytest.raises(RuntimeError, match="requires DATABASE_URL"):
            database_url()

    def test_production_refuses_sqlite(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "sqlite:///db/coverage.db")
        monkeypatch.setenv("APP_ENV", "production")
        with pytest.raises(RuntimeError, match="refusing to fall back to SQLite"):
            database_url()

    def test_production_accepts_postgres(self, monkeypatch):
        url = "postgresql+psycopg://u:p@host:5432/coverage"
        monkeypatch.setenv("DATABASE_URL", url)
        monkeypatch.setenv("APP_ENV", "production")
        assert database_url() == url

    def test_rejects_unsupported_driver(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "mysql+pymysql://u:p@host/db")
        with pytest.raises(ValueError, match="unsupported database driver"):
            database_url()

    def test_bare_postgresql_alias_selects_psycopg(self, monkeypatch):
        """Neon hands you `postgresql://`; accept it instead of failing later."""
        monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@host:5432/coverage")
        assert database_url() == "postgresql+psycopg://u:p@host:5432/coverage"

    def test_production_accepts_the_bare_postgresql_alias(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@host:5432/coverage")
        monkeypatch.setenv("APP_ENV", "production")
        assert database_url() == "postgresql+psycopg://u:p@host:5432/coverage"

    def test_postgres_scheme_alias_is_accepted(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgres://u:p@host:5432/coverage")
        assert database_url() == "postgresql+psycopg://u:p@host:5432/coverage"

    def test_sqlite_urls_are_not_rewritten(self, monkeypatch):
        """The SQLite default and its directory helper rely on `sqlite://`."""
        monkeypatch.setenv("DATABASE_URL", "sqlite:///db/coverage.db")
        assert database_url() == "sqlite:///db/coverage.db"


class TestVerifySchema:
    """The empty/wrong-database guard."""

    def test_missing_tables_are_named(self, tmp_path):
        engine = make_engine(f"sqlite:///{tmp_path / 'empty.db'}")
        with pytest.raises(RuntimeError, match="missing application tables"):
            verify_schema(engine)
        engine.dispose()

    def test_schema_without_data_is_rejected(self, tmp_path):
        engine = make_engine(f"sqlite:///{tmp_path / 'schema_only.db'}")
        Base.metadata.create_all(engine)
        with pytest.raises(RuntimeError, match="techniques.*empty"):
            verify_schema(engine)
        engine.dispose()

    def test_require_data_false_accepts_empty_schema(self, tmp_path):
        engine = make_engine(f"sqlite:///{tmp_path / 'schema_only.db'}")
        Base.metadata.create_all(engine)
        verify_schema(engine, require_data=False)
        engine.dispose()

    def test_populated_database_passes(self):
        db_path = REPO_ROOT / "db" / "coverage.db"
        if not db_path.is_file():
            pytest.skip("db/coverage.db not present")
        engine = make_engine(f"sqlite:///{db_path}")
        try:
            verify_schema(engine)
        finally:
            engine.dispose()


# ---------------------------------------------------------------------------
# Migration script -- pure helpers
# ---------------------------------------------------------------------------

class TestMigrationHelpers:
    """Ordering, path resolution and datetime normalisation."""

    def test_table_order_matches_orm_metadata(self):
        from scripts.migrate_sqlite_to_postgres import TABLE_ORDER

        assert set(TABLE_ORDER) == set(Base.metadata.tables)
        assert len(TABLE_ORDER) == len(set(TABLE_ORDER))

    def test_table_order_is_foreign_key_safe(self):
        from scripts.migrate_sqlite_to_postgres import TABLE_ORDER

        position = {name: index for index, name in enumerate(TABLE_ORDER)}
        for table in Base.metadata.sorted_tables:
            for foreign_key in table.foreign_keys:
                parent = foreign_key.column.table.name
                if parent == table.name:
                    continue
                assert position[parent] < position[table.name], (
                    f"{parent} must be copied before {table.name}"
                )

    def test_sqlite_file_path_resolution(self):
        from scripts.migrate_sqlite_to_postgres import _sqlite_file_path

        assert _sqlite_file_path("sqlite:///:memory:") is None
        assert _sqlite_file_path("sqlite:///db/coverage.db") == (
            REPO_ROOT / "db" / "coverage.db"
        )
        absolute = Path("C:/tmp/x.db") if os.name == "nt" else Path("/tmp/x.db")
        assert _sqlite_file_path(f"sqlite:///{absolute}") == absolute

    def test_naive_datetime_is_treated_as_utc(self):
        from scripts.migrate_sqlite_to_postgres import _normalise_datetime

        naive = datetime(2026, 11, 16, 12, 0, 0)
        assert _normalise_datetime(naive).tzinfo is timezone.utc
        aware = datetime(2026, 11, 16, 12, 0, 0, tzinfo=timezone.utc)
        assert _normalise_datetime(aware) is aware
        assert _normalise_datetime(None) is None

    def test_usage_errors_exit_one_not_two_or_three(self, capsys):
        from scripts.migrate_sqlite_to_postgres import (
            EXIT_OPERATIONAL,
            EXIT_VERIFY_FAILED,
            parse_args,
        )

        with pytest.raises(SystemExit) as excinfo:
            parse_args(["--dry-run", "--verify-only"])
        assert excinfo.value.code == EXIT_OPERATIONAL != EXIT_VERIFY_FAILED

    def test_exit_codes_are_distinct(self):
        from scripts import migrate_sqlite_to_postgres as mig

        codes = {
            mig.EXIT_OK,
            mig.EXIT_OPERATIONAL,
            mig.EXIT_VERIFY_FAILED,
            mig.EXIT_REFUSED,
        }
        assert len(codes) == 4


class TestSessionScopeContract:
    """The transactional contract :mod:`app` relies on for its writes."""

    def test_staged_write_is_committed(self, tmp_path):
        engine = make_engine(f"sqlite:///{tmp_path / 'commit.db'}")
        Base.metadata.create_all(engine)
        try:
            with session_scope(engine) as session:
                session.add(DataSourceType(name="evtx", log_format="evtx"))
            with engine.connect() as conn:
                names = conn.execute(
                    text("SELECT name FROM datasource_types")
                ).scalars().all()
            assert names == ["evtx"]
        finally:
            engine.dispose()

    def test_exception_rolls_back(self, tmp_path):
        engine = make_engine(f"sqlite:///{tmp_path / 'rollback.db'}")
        Base.metadata.create_all(engine)
        try:
            with pytest.raises(RuntimeError, match="boom"):
                with session_scope(engine) as session:
                    session.add(DataSourceType(name="evtx", log_format="evtx"))
                    raise RuntimeError("boom")
            with engine.connect() as conn:
                assert conn.execute(
                    text("SELECT COUNT(*) FROM datasource_types")
                ).scalar() == 0
        finally:
            engine.dispose()


# ---------------------------------------------------------------------------
# Migration script -- live PostgreSQL round trip
# ---------------------------------------------------------------------------

def _seed_sqlite(path: Path) -> None:
    """Create a small but referentially valid coverage database at ``path``."""
    engine = make_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        technique = Technique(
            stix_id="attack-pattern--test-0001",
            attack_id="T9999",
            name="Test Technique",
            tactics=["execution"],
            platforms=["Windows"],
        )
        group = AptGroup(
            stix_id="intrusion-set--test-0001",
            group_id="G9999",
            name="Test Group",
        )
        session.add_all([technique, group])
        session.flush()
        session.add(
            AptTechnique(
                group_stix_id=group.stix_id,
                technique_stix_id=technique.stix_id,
            )
        )
        source = DataSourceType(
            id=1, name="evtx", log_format="evtx", priority=0, enabled=True
        )
        session.add(source)
        session.flush()
        session.add(
            SimulationResult(
                id=7,
                group_stix_id=group.stix_id,
                group_id="G9999",
                run_at=datetime(2026, 11, 16, 12, 0, 0, tzinfo=timezone.utc),
                platform_scope="windows",
                confidence_threshold=0.6,
                total_techniques=1,
                detected_count=0,
                missed_count=1,
                coverage_pct=0.0,
                summary={"counts": {"total": 1}},
            )
        )
        session.flush()
        session.add(
            SimulationTechnique(
                id=11,
                result_id=7,
                technique_attack_id="T9999",
                name="Test Technique",
                tactic="execution",
                status="missed",
                confidence=None,
                contributing_sources=[],
            )
        )
        session.commit()
    finally:
        session.close()
        engine.dispose()


def _admin_engine(pg_url: str):
    """Engine against the maintenance database, for CREATE/DROP DATABASE."""
    admin_url = make_url(pg_url).set(database="postgres")
    # hide_password=False: this string is handed to create_engine, not printed.
    return make_engine(admin_url.render_as_string(hide_password=False))


def _create_database(admin, name: str) -> None:
    with admin.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))


def _drop_database(admin, name: str) -> None:
    with admin.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(
            text(f'SELECT pg_terminate_backend(pid) FROM pg_stat_activity '
                 f"WHERE datname = '{name}'")
        )
        conn.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))


@requires_postgres
class TestPostgresMigration:
    """End-to-end migration into a disposable database."""

    @pytest.fixture
    def target(self, tmp_path):
        name = f"migration_test_{uuid.uuid4().hex[:12]}"
        admin = _admin_engine(PG_URL or "")
        _create_database(admin, name)
        base = make_url(PG_URL or "")
        url = base.set(database=name).render_as_string(hide_password=False)
        source = tmp_path / "source.db"
        _seed_sqlite(source)
        yield url, f"sqlite:///{source}"
        _drop_database(admin, name)
        admin.dispose()

    def test_migration_copies_rows_and_advances_sequences(self, target):
        from scripts.migrate_sqlite_to_postgres import main

        url, sqlite_url = target
        assert main(["--sqlite-url", sqlite_url, "--postgres-url", url,
                     "--deep-verify"]) == 0

        engine = make_engine(url)
        try:
            session = sessionmaker(bind=engine)()
            try:
                result = session.get(SimulationResult, 7)
                assert result is not None, "surrogate id 7 was not preserved"
                assert result.coverage_pct == 0.0
                assert session.get(SimulationTechnique, 11) is not None
                assert result.run_at.tzinfo is not None, (
                    "timestamps must come back timezone-aware from PostgreSQL"
                )
            finally:
                session.close()

            # The sequence must continue past imported ids, not restart at 1.
            session = sessionmaker(bind=engine)()
            try:
                new = SimulationResult(
                    group_stix_id="intrusion-set--test-0001",
                    group_id="G9999",
                    platform_scope="windows",
                    confidence_threshold=0.6,
                    total_techniques=1,
                    detected_count=0,
                    missed_count=1,
                    coverage_pct=0.0,
                )
                session.add(new)
                session.commit()
                assert new.id == 8, f"sequence not synchronised (got id {new.id})"
            finally:
                session.close()
        finally:
            engine.dispose()

    def test_second_run_is_refused(self, target):
        from scripts.migrate_sqlite_to_postgres import (
            EXIT_REFUSED,
            main,
        )

        url, sqlite_url = target
        assert main(["--sqlite-url", sqlite_url, "--postgres-url", url]) == 0
        assert main(["--sqlite-url", sqlite_url, "--postgres-url", url]) == (
            EXIT_REFUSED
        )

    def test_verify_only_detects_drift(self, target):
        from scripts.migrate_sqlite_to_postgres import (
            EXIT_OK,
            EXIT_VERIFY_FAILED,
            main,
        )

        url, sqlite_url = target
        assert main(["--sqlite-url", sqlite_url, "--postgres-url", url]) == EXIT_OK
        assert main(["--verify-only", "--sqlite-url", sqlite_url,
                     "--postgres-url", url]) == EXIT_OK

        engine = make_engine(url)
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM simulation_techniques WHERE id = 11"))
        engine.dispose()

        assert main(["--verify-only", "--sqlite-url", sqlite_url,
                     "--postgres-url", url]) == EXIT_VERIFY_FAILED

    def test_dry_run_writes_nothing(self, target):
        from scripts.migrate_sqlite_to_postgres import main

        url, sqlite_url = target
        assert main(["--dry-run", "--sqlite-url", sqlite_url,
                     "--postgres-url", url]) == 0
        engine = make_engine(url)
        try:
            assert inspect(engine).get_table_names() == []
        finally:
            engine.dispose()

    def test_simulation_persists_through_a_committing_session(self, target):
        """The dashboard write path: simulate -> commit -> readable anew.

        Regression guard for the bug where ``app._bound_session`` closed without
        committing, so every "Run simulation" click was silently discarded.
        """
        from analysis.simulation import simulate_apt_attack
        from config_loader import load_config
        from scripts.migrate_sqlite_to_postgres import main

        url, sqlite_url = target
        assert main(["--sqlite-url", sqlite_url, "--postgres-url", url]) == 0

        engine = make_engine(url)
        config = load_config(str(REPO_ROOT / "config.yaml"))
        try:
            with session_scope(engine) as session:
                outcome = simulate_apt_attack(
                    "G9999", session, config=config, persist=True
                )
            new_id = int(outcome.id)

            with session_scope(engine) as session:
                reread = session.get(SimulationResult, new_id)
                assert reread is not None, "simulation run was not committed"
                rows = session.execute(
                    select(func.count())
                    .select_from(SimulationTechnique)
                    .where(SimulationTechnique.result_id == new_id)
                ).scalar()
            assert int(rows) == 1
        finally:
            engine.dispose()
