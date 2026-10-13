"""Phase 5 schema migration: add hunt-query provenance to technique_coverage.

Adds two columns to ``technique_coverage`` (created by the Phase-1 loader via
``Base.metadata.create_all``):

- ``query_source`` (VARCHAR(16), nullable) -- one of ``sigmahq`` /
  ``curated`` / ``generic_template`` / NULL.  NULL means no hunt query has
  been generated yet (pre-Phase-5 rows).
- ``attribution_json`` (JSON, default empty dict) -- DRL 1.1 attribution blob
  populated only when ``query_source == 'sigmahq'``.

Alembic is intentionally NOT used (the project has no Alembic setup through
Phase 4); this is a raw-SQL ALTER guarded by ``PRAGMA table_info`` so it is
safe to re-run: columns already present are skipped idempotently.

Run from the repository root:

    ./.venv/Scripts/python.exe scripts/migrate_phase5.py

Exit code 0 on success (including a no-op re-run), non-zero on failure.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

_SRC_DIR = REPO_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from database.session import make_engine  # noqa: E402
from sqlalchemy import text  # noqa: E402

logger = logging.getLogger(__name__)

TABLE = "technique_coverage"

# Columns to add: (name, sqlite_type, nullable, default_expr_or_None).
# default_expr is the SQL literal for DEFAULT (without the DEFAULT keyword);
# None means no default (column is nullable, existing rows stay NULL).
COLUMNS: tuple[tuple[str, str, bool, str | None], ...] = (
    ("query_source", "VARCHAR(16)", True, None),
    # JSON columns are TEXT in SQLite; the default must be a quoted string
    # literal ('{}'), not a bare {} (SQLite rejects the unrecognized '{').
    ("attribution_json", "JSON", False, "'{}'"),
)


def _validate_identifier(value: str) -> None:
    """Validate that an identifier contains only safe characters.

    Args:
        value: The identifier to validate.

    Raises:
        ValueError: If the identifier contains unsafe characters.
    """
    import re
    if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', value):
        raise ValueError(f"invalid SQL identifier: {value!r}")


def _existing_columns(engine) -> set[str]:
    """Return the set of column names currently in ``technique_coverage``."""
    _validate_identifier(TABLE)
    with engine.connect() as conn:
        rows = conn.execute(text(f"PRAGMA table_info({TABLE})")).all()
    return {row.name for row in rows}


def migrate(engine, *, dry_run: bool = False) -> bool:
    """Apply the Phase 5 migration idempotently.

    Args:
        engine: A SQLAlchemy engine bound to the target database.
        dry_run: If True, report what would change without executing DDL.

    Returns:
        True if a change was (or would be) made, False if already current.
    """
    existing = _existing_columns(engine)
    added_any = False
    for name, sql_type, nullable, default_expr in COLUMNS:
        if name in existing:
            logger.info("column %s.%s already present — skipped", TABLE, name)
            continue
        added_any = True
        # Validate identifiers to prevent SQL injection in DDL
        _validate_identifier(TABLE)
        _validate_identifier(name)
        nullable_sql = "" if nullable else " NOT NULL"
        default_sql = f" DEFAULT {default_expr}" if default_expr is not None else ""
        ddl = (
            f"ALTER TABLE {TABLE} "
            f"ADD COLUMN {name} {sql_type}{nullable_sql}{default_sql}"
        )
        if dry_run:
            logger.info("dry-run: %s", ddl)
            continue
        with engine.begin() as conn:
            conn.execute(text(ddl))
        logger.info("added column %s.%s", TABLE, name)
    return added_any


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url",
        default=None,
        help=(
            "SQLAlchemy database URL. Defaults to DATABASE_URL env var or "
            "sqlite:///db/coverage.db (see database.session)."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the DDL that would run without executing it.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable INFO-level logging.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    engine = make_engine(args.database_url)
    try:
        changed = migrate(engine, dry_run=args.dry_run)
    except Exception:
        logger.exception("Phase 5 migration failed")
        return 1
    if args.dry_run:
        logger.info("dry-run complete (no changes made)")
        return 0
    if changed:
        logger.info("Phase 5 migration applied successfully")
    else:
        logger.info("schema already current — nothing to do")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
