"""Database engine and session helpers.

Reads DATABASE_URL from the environment (via .env if present).
SQLite file URLs are default; PostgreSQL via docker-compose at checkpoints.
"""
import os
from contextlib import contextmanager
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine
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


def database_url() -> str:
    _ensure_dotenv_loaded()
    url = os.getenv("DATABASE_URL", DEFAULT_URL)
    # Validate URL scheme to prevent path traversal via .env
    from sqlalchemy.engine import make_url
    try:
        parsed = make_url(url)
        if parsed.drivername not in ("sqlite", "postgresql+psycopg", "sqlite+pysqlite"):
            raise ValueError(f"unsupported database driver: {parsed.drivername}")
    except Exception as exc:
        raise ValueError(f"invalid DATABASE_URL: {exc}") from exc
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
