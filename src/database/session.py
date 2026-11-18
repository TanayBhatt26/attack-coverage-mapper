"""Database engine and session helpers.

Reads DATABASE_URL from the environment (via .env if present).
SQLite file URLs are default; PostgreSQL via docker-compose at checkpoints.

Deployment contract
-------------------
``APP_ENV`` selects how strict the URL resolution is:

``development`` (default)
    ``DATABASE_URL`` when set, otherwise the local ``db/coverage.db``.

``production``
    ``DATABASE_URL`` is mandatory and must be a PostgreSQL URL. The app refuses
    to start rather than silently opening SQLite -- Streamlit Community Cloud
    mounts the repository read-only, so a SQLite fallback would either fail on
    every write (``attempt to write a readonly database``) or, worse, quietly
    create a fresh empty database and render a blank dashboard.

:func:`verify_schema` covers that second failure mode: ``SELECT 1`` succeeds
against any live server, so table presence and content are checked explicitly.
"""
import os
from contextlib import contextmanager
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

# Lazy-load .env: call load_dotenv() explicitly when needed, not at module import
_dotenv_loaded = False


def _ensure_dotenv_loaded() -> None:
    """Load .env file once, lazily."""
    global _dotenv_loaded
    if not _dotenv_loaded:
        load_dotenv()
        _dotenv_loaded = True


DEFAULT_URL = "sqlite:///db/coverage.db"

#: Drivers the application accepts, mapped to the driver actually loaded.
#:
#: Neon and most hosted Postgres consoles hand you a bare ``postgresql://``
#: URL. SQLAlchemy resolves that to psycopg2, which this project does not
#: install (requirements pin ``psycopg[binary]``, i.e. psycopg 3). Accept the
#: alias and select psycopg explicitly rather than making the operator edit the
#: URL by hand -- a step that is easy to miss and fails only at connect time.
DRIVER_ALIASES = {
    "postgresql": "postgresql+psycopg",
    "postgres": "postgresql+psycopg",
    "postgresql+psycopg": "postgresql+psycopg",
    # Identity entries: accepted, but never rewritten (the SQLite default URL
    # and its directory bootstrap depend on the `sqlite://` prefix).
    "sqlite": "sqlite",
    "sqlite+pysqlite": "sqlite+pysqlite",
}

#: Backwards-compatible alias for callers that used the old name.
SUPPORTED_DRIVERS = tuple(DRIVER_ALIASES)

#: Deployment environment markers (see module docstring).
DEVELOPMENT = "development"
PRODUCTION = "production"

#: Tables the dashboard needs, in foreign-key dependency order.
REQUIRED_TABLES = (
    "techniques",
    "detection_strategies",
    "analytics",
    "apt_groups",
    "apt_technique",
    "datasource_types",
    "technique_coverage",
    "simulation_results",
    "simulation_techniques",
    "attack_meta",
)


def app_env() -> str:
    """Return the validated deployment environment (default ``development``)."""
    env = os.getenv("APP_ENV", DEVELOPMENT).strip().lower()
    if env not in (DEVELOPMENT, PRODUCTION):
        raise ValueError(
            f"invalid APP_ENV={env!r}; expected {DEVELOPMENT!r} or {PRODUCTION!r}"
        )
    return env


def database_url() -> str:
    """Resolve the active ``DATABASE_URL`` under the deployment contract.

    Raises:
        RuntimeError: In production, when ``DATABASE_URL`` is unset or is not
            PostgreSQL. Failing here is deliberate -- a silent SQLite fallback
            on a read-only host produces a deploy that looks healthy until the
            first write.
        ValueError: When the URL is malformed, uses an unsupported driver, or
            ``APP_ENV`` is not a known marker.
    """
    _ensure_dotenv_loaded()
    env = app_env()
    explicit = os.getenv("DATABASE_URL")

    if env == PRODUCTION and not explicit:
        raise RuntimeError(
            "APP_ENV=production requires DATABASE_URL to be set to a "
            "postgresql+psycopg:// URL (on Streamlit Cloud: add it under "
            "Secrets)."
        )
    url = explicit or DEFAULT_URL

    # Validate URL scheme to prevent path traversal via .env
    from sqlalchemy.engine import make_url

    try:
        parsed = make_url(url)
    except Exception as exc:
        raise ValueError(f"invalid DATABASE_URL: {exc}") from exc
    canonical = DRIVER_ALIASES.get(parsed.drivername)
    if canonical is None:
        raise ValueError(f"unsupported database driver: {parsed.drivername}")
    if canonical != parsed.drivername:
        # Re-render with the driver SQLAlchemy should actually load. The
        # password is preserved (hide_password=False) -- this string is handed
        # back to create_engine, never displayed.
        url = parsed.set(drivername=canonical).render_as_string(hide_password=False)
        parsed = make_url(url)

    if env == PRODUCTION and parsed.drivername != "postgresql+psycopg":
        raise RuntimeError(
            f"APP_ENV=production requires a PostgreSQL DATABASE_URL, got "
            f"{parsed.drivername!r}; refusing to fall back to SQLite."
        )
    return url


def _ensure_sqlite_dir(url: str) -> None:
    """Create the parent directory for a file-based SQLite URL so first connect works."""
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        return
    path = url[len(prefix):]
    if path in ("", ":memory:"):
        return
    parent = Path(path).parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)


def make_engine(url: str | None = None):
    url = url or database_url()
    _ensure_sqlite_dir(url)
    kwargs = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(url, **kwargs)


def verify_schema(engine, *, require_data: bool = True) -> None:
    """Raise unless ``engine`` points at a populated coverage database.

    Args:
        engine: A live SQLAlchemy engine.
        require_data: Also require the ``techniques`` table to be non-empty.
            Disable only when deliberately working with a freshly created
            schema (for example the Phase 0 hello-world gate).

    Raises:
        RuntimeError: Naming the missing tables, or reporting an empty schema.
            Both messages point at the ingest or the SQLite-to-PostgreSQL
            migration.
    """
    present = set(inspect(engine).get_table_names())
    missing = [name for name in REQUIRED_TABLES if name not in present]
    if missing:
        raise RuntimeError(
            "the connected database is missing application tables: "
            + ", ".join(missing)
            + "\nPoint DATABASE_URL at a populated database, or run "
            "scripts/migrate_sqlite_to_postgres.py."
        )
    if require_data:
        with engine.connect() as conn:
            rows = conn.execute(text('SELECT COUNT(*) FROM "techniques"')).scalar()
        if not rows:
            raise RuntimeError(
                'the connected database has the application schema but the '
                '"techniques" table is empty; run the ATT&CK ingest or the '
                "SQLite-to-PostgreSQL migration before starting the dashboard."
            )


@contextmanager
def session_scope(engine=None):
    """Transactional scope: commit on success, rollback on error."""
    engine = engine or make_engine()
    factory = sessionmaker(bind=engine)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
