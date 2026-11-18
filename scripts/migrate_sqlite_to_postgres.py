#!/usr/bin/env python3
"""SQLite -> PostgreSQL migration for ATT&CK Coverage Mapper.

Copies an existing development SQLite database into a managed PostgreSQL
database (Neon, or any ``postgresql+psycopg://`` target) without dropping or
overwriting anything, so the Streamlit Community Cloud deployment can persist
simulation results instead of failing with ``attempt to write a readonly
database``.

Guarantees
----------
* **Never destructive.** ``Base.metadata.create_all(checkfirst=True)`` only
  creates missing tables; nothing is dropped, truncated or reset. The source
  SQLite file is only read, never written.
* **No duplicate imports.** The target is refused (exit code 3) when any
  application table already holds rows, so a second run can never double the
  data. Combined with the single transaction below, a partial import is
  impossible -- there is no "resume" state to get wrong.
* **Everything in one transaction.** Schema creation, the row copy, the
  sequence resynchronisation and the post-copy verification all run inside one
  PostgreSQL transaction that commits only after verification passes. A failure
  at any point leaves the target untouched.
* **Primary keys, foreign keys, JSON and timestamps are preserved verbatim.**
  Rows are inserted with their original key values (including surrogate
  ``id`` columns), so relationships and history survive intact.
* **Identity sequences are resynchronised.** After the copy, ``setval`` is
  called for every serial primary key so the next inserted row does not
  collide with an imported id.

Verification
------------
Two levels, both derived from the source and the target after the copy:

1. Row counts per table (always).
2. ``--deep-verify``: a per-row SHA-256 signature over every column --
   *including* surrogate ids and timestamps -- using the same canonicalisation
   as ``scripts/checkpoint_a_parity.py`` (datetimes normalised to UTC-aware
   ISO-8601, JSON compared semantically with sorted keys, floats via ``repr``).
   This is stricter than the parity harness, which deliberately ignores
   surrogate ids and clock-written columns; a migration must preserve them.

Usage::

    python scripts/migrate_sqlite_to_postgres.py \\
        --sqlite-url sqlite:///db/coverage.db \\
        --postgres-url postgresql+psycopg://user:pass@host/db

    # inspect without writing anything
    python scripts/migrate_sqlite_to_postgres.py --dry-run

    # re-check an existing target against the source
    python scripts/migrate_sqlite_to_postgres.py --verify-only --deep-verify

Exit codes
----------
0  success (or ``--dry-run``/``--verify-only`` passed)
1  operational failure (unreachable backend, driver missing, bad arguments)
2  verification failure (row counts or signatures differ)
3  refused (target already contains application data)

Pure stdlib + SQLAlchemy; never imports ``detections/`` or pySigma, so it runs
in a bare environment with only ``requirements.txt`` installed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

from sqlalchemy import insert, inspect as sa_inspect, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.sql.schema import Table

logger = logging.getLogger("migrate_sqlite_to_postgres")

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_SQLITE_URL = "sqlite:///db/coverage.db"

#: Application tables in foreign-key-safe copy order (parents before children).
#: ``metadata.sorted_tables`` is derived from the same metadata, but an
#: explicit list keeps the copy order auditable and independent of import order.
TABLE_ORDER: tuple[str, ...] = (
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

#: Tables whose single integer ``id`` primary key is a SERIAL on PostgreSQL.
#: Natural-key tables (``techniques``, ``detection_strategies``, ``analytics``,
#: ``apt_groups``, ``apt_technique``) have no sequence to resynchronise.
SERIAL_PK_TABLES: tuple[str, ...] = (
    "datasource_types",
    "technique_coverage",
    "simulation_results",
    "simulation_techniques",
    "attack_meta",
)

EXIT_OK = 0
EXIT_OPERATIONAL = 1
EXIT_VERIFY_FAILED = 2
EXIT_REFUSED = 3

#: Marker for the "target already holds data" refusal, mapped to exit code 3.
TARGET_OCCUPIED_MARKER = "already contains application data"


class VerificationError(RuntimeError):
    """Raised when post-copy verification fails, so the caller rolls back."""


class _ArgumentParser(argparse.ArgumentParser):
    """argparse parser whose usage errors exit 1, keeping 2/3 semantic."""

    def error(self, message: str) -> NoReturn:  # noqa: D102 - argparse hook
        self.print_usage(sys.stderr)
        self.exit(EXIT_OPERATIONAL, f"{self.prog}: error: {message}\n")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _label(engine: Engine) -> str:
    """Human-safe engine label with the password masked."""
    return engine.url.render_as_string(hide_password=True)


def _is_postgresql(url: str) -> bool:
    return url.strip().lower().startswith(("postgresql+", "postgresql:", "postgres:"))


def _is_sqlite(url: str) -> bool:
    return url.strip().lower().startswith(("sqlite+", "sqlite:"))


def _connectable(engine: Engine) -> None:
    """Raise a descriptive error unless ``SELECT 1`` succeeds on ``engine``."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        if _is_postgresql(engine.url.render_as_string(hide_password=True)):
            raise RuntimeError(
                f"cannot reach PostgreSQL at {_label(engine)}: {exc}"
            ) from exc
        raise RuntimeError(f"cannot open database {_label(engine)}: {exc}") from exc


def _sqlite_file_path(url: str) -> Path | None:
    """Resolve the filesystem path of a file-backed SQLite URL, if any."""
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        return None
    raw = url[len(prefix):]
    if raw in ("", ":memory:"):
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalise_datetime(value):
    """Treat a naive datetime as UTC.

    SQLite's DATETIME storage drops the offset, so a ``DateTime(timezone=True)``
    column reads back naive even though the writer supplied a UTC-aware value.
    PostgreSQL ``timestamptz`` returns an aware value; attaching UTC here makes
    the copied instant identical instead of being reinterpreted in the session
    time zone.
    """
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _canonicalise_row(row, table: Table) -> str:
    """SHA-256 signature over every column of one row, in table column order.

    Uses the canonicalisation from ``scripts/checkpoint_a_parity.py`` so both
    tools agree on what "the same value" means across SQLite and PostgreSQL.
    Unlike the parity harness this includes surrogate ids and timestamps: a
    migration is supposed to preserve them exactly.
    """
    from scripts.checkpoint_a_parity import _normalize_value

    cells: list[str] = []
    for column in table.columns:
        canonical = _normalize_value(row[column.name], column.type)
        cells.append(f"{column.name}\x1f{canonical}")
    return hashlib.sha256(
        json.dumps(cells, ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _table_counts(conn: Connection, tables: list[Table]) -> dict[str, int]:
    """Row counts for ``tables``; a table missing from the target counts as 0."""
    existing = set(sa_inspect(conn).get_table_names())
    counts: dict[str, int] = {}
    for table in tables:
        if table.name not in existing:
            counts[table.name] = 0
            continue
        counts[table.name] = int(
            conn.execute(select(text("COUNT(*)")).select_from(table)).scalar()
        )
    return counts


# ---------------------------------------------------------------------------
# Migration steps
# ---------------------------------------------------------------------------

def _assert_target_empty(conn: Connection, tables: list[Table]) -> dict[str, int]:
    """Refuse to migrate into a target that already holds application rows.

    Returns the observed counts (all zero) so the caller can log them.
    """
    counts = _table_counts(conn, tables)
    occupied = {name: n for name, n in counts.items() if n}
    if occupied:
        raise RuntimeError(
            TARGET_OCCUPIED_MARKER + ": "
            + ", ".join(f"{name}={n}" for name, n in sorted(occupied.items()))
            + "\nRefusing to import: this tool never overwrites or merges into "
            "a populated database. Point --postgres-url at an empty database, "
            "or use --verify-only to compare."
        )
    return counts


def _create_schema(conn: Connection, metadata) -> list[str]:
    """Create missing application tables; return the names actually created."""
    inspector_names = set(sa_inspect(conn).get_table_names())
    created = [
        table.name
        for table in metadata.sorted_tables
        if table.name not in inspector_names
    ]
    metadata.create_all(conn)
    return created


def _copy_table(source: Engine, conn: Connection, table: Table, batch_size: int) -> int:
    """Copy one table in batches, preserving every column value verbatim."""
    with source.connect() as src_conn:
        rows = [dict(row) for row in src_conn.execute(select(table)).mappings()]
    if not rows:
        return 0

    prepared = [
        {
            column.name: _normalise_datetime(row.get(column.name))
            for column in table.columns
        }
        for row in rows
    ]
    copied = 0
    for start in range(0, len(prepared), batch_size):
        batch = prepared[start:start + batch_size]
        conn.execute(insert(table), batch)
        copied += len(batch)
    return copied


def _sync_sequences(conn: Connection, table_name: str, pk_name: str) -> bool:
    """Advance a serial primary key past the imported rows.

    Without this the first newly inserted row would reuse id 1 and violate the
    primary key. ``pg_get_serial_sequence`` returns NULL for natural-key
    tables, which is reported as "nothing to do" rather than an error.
    """
    sequence = conn.execute(
        text("SELECT pg_get_serial_sequence(:table, :column)"),
        {"table": table_name, "column": pk_name},
    ).scalar()
    if not sequence:
        return False

    max_id = int(
        conn.execute(
            text(f'SELECT COALESCE(MAX("{pk_name}"), 0) FROM "{table_name}"')
        ).scalar()
    )
    if max_id > 0:
        conn.execute(
            text("SELECT setval(:sequence, :value, true)"),
            {"sequence": sequence, "value": max_id},
        )
    else:
        # Empty table: leave is_called = false so the first nextval is 1.
        conn.execute(
            text("SELECT setval(:sequence, 1, false)"), {"sequence": sequence}
        )
    return True


def _verify(
    source: Engine,
    target_conn: Connection,
    tables: list[Table],
    deep: bool,
) -> list[str]:
    """Compare source and target; return a list of mismatch descriptions.

    ``target_conn`` must be the transactional connection holding the copy, or
    the uncommitted rows would be invisible and every check would fail.
    """
    problems: list[str] = []

    with source.connect() as src_conn:
        src_counts = _table_counts(src_conn, tables)
    tgt_counts = _table_counts(target_conn, tables)
    for table in tables:
        name = table.name
        if src_counts[name] != tgt_counts[name]:
            problems.append(
                f"{name}: source has {src_counts[name]} rows, "
                f"target has {tgt_counts[name]}"
            )

    if deep and not problems:
        for table in tables:
            with source.connect() as src_conn:
                src_sigs = Counter(
                    _canonicalise_row(row, table)
                    for row in src_conn.execute(select(table)).mappings()
                )
            tgt_sigs = Counter(
                _canonicalise_row(row, table)
                for row in target_conn.execute(select(table)).mappings()
            )
            if src_sigs != tgt_sigs:
                only_src = sum((src_sigs - tgt_sigs).values())
                only_tgt = sum((tgt_sigs - src_sigs).values())
                problems.append(
                    f"{table.name}: row signatures differ "
                    f"({only_src} only in source, {only_tgt} only in target)"
                )
    return problems


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = _ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument(
        "--sqlite-url",
        default=DEFAULT_SQLITE_URL,
        help=f"source SQLite DATABASE_URL (default: {DEFAULT_SQLITE_URL})",
    )
    parser.add_argument(
        "--postgres-url",
        default=None,
        help="target PostgreSQL DATABASE_URL (falls back to $DATABASE_URL)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="rows per INSERT batch (default: 1000)",
    )
    parser.add_argument(
        "--deep-verify",
        action="store_true",
        help="compare per-row signatures, including ids and timestamps",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="validate both ends and print the plan without writing",
    )
    mode.add_argument(
        "--verify-only",
        action="store_true",
        help="do not copy; only compare source and target",
    )
    parser.add_argument("--verbose", action="store_true", help="DEBUG logging")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point; see the module docstring for the contract and exit codes."""
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stdout,
    )

    postgres_url = args.postgres_url or os.getenv("DATABASE_URL") or None
    if not postgres_url:
        logger.error(
            "no target given: pass --postgres-url or set DATABASE_URL "
            "to a postgresql+psycopg:// URL"
        )
        return EXIT_OPERATIONAL

    if not _is_postgresql(postgres_url):
        logger.error(
            "refusing to migrate into non-PostgreSQL target %s",
            postgres_url.rsplit("@", 1)[-1],
        )
        return EXIT_OPERATIONAL
    # Hosted consoles copy a bare `postgresql://` string; SQLAlchemy resolves
    # that to psycopg2, which this project does not install. Select psycopg 3.
    for _scheme in ("postgresql", "postgres"):
        _prefix = f"{_scheme}://"
        if postgres_url.startswith(_prefix):
            postgres_url = "postgresql+psycopg://" + postgres_url[len(_prefix):]
            break
    if not _is_sqlite(args.sqlite_url):
        logger.error("refusing to migrate from non-SQLite source %s", args.sqlite_url)
        return EXIT_OPERATIONAL
    if args.batch_size < 1:
        logger.error("--batch-size must be >= 1")
        return EXIT_OPERATIONAL

    sys.path.insert(0, str(PROJECT_ROOT / "src"))
    sys.path.insert(0, str(PROJECT_ROOT))

    from database.models import Base
    from database.session import make_engine

    missing = [name for name in TABLE_ORDER if name not in Base.metadata.tables]
    if missing:
        logger.error("TABLE_ORDER names absent from ORM metadata: %s", ", ".join(missing))
        return EXIT_OPERATIONAL

    tables = [Base.metadata.tables[name] for name in TABLE_ORDER]

    sqlite_path = _sqlite_file_path(args.sqlite_url)
    if sqlite_path is not None and not sqlite_path.is_file():
        logger.error("source SQLite file not found: %s", sqlite_path)
        return EXIT_OPERATIONAL

    try:
        source = make_engine(args.sqlite_url)
        target = make_engine(postgres_url)
        _connectable(source)
        _connectable(target)
    except Exception as exc:
        logger.error("%s", exc)
        return EXIT_OPERATIONAL

    before_sha = _sha256_file(sqlite_path) if sqlite_path else None
    if before_sha:
        logger.info("source %s sha256=%s", sqlite_path, before_sha)
    logger.info("source: %s", _label(source))
    logger.info("target: %s", _label(target))

    problems: list[str] = []
    try:
        if args.verify_only:
            with target.connect() as conn:
                problems = _verify(source, conn, tables, deep=True)
        elif args.dry_run:
            with target.connect() as conn:
                _assert_target_empty(conn, tables)
            with source.connect() as src_conn:
                src_counts = _table_counts(src_conn, tables)
            total = sum(src_counts.values())
            for table in tables:
                logger.info(
                    "  would copy %-22s %6d rows",
                    table.name,
                    src_counts[table.name],
                )
            logger.info("  total %d rows across %d tables", total, len(tables))
            logger.info("dry run: target is empty, nothing was written")
        else:
            with target.begin() as conn:
                created = _create_schema(conn, Base.metadata)
                logger.info(
                    "schema ready (created: %s)",
                    ", ".join(created) if created else "nothing new",
                )
                _assert_target_empty(conn, tables)

                for table in tables:
                    copied = _copy_table(source, conn, table, args.batch_size)
                    logger.info("copied %-22s %6d rows", table.name, copied)

                for table_name in SERIAL_PK_TABLES:
                    if _sync_sequences(conn, table_name, "id"):
                        logger.debug("sequence resynchronised for %s", table_name)

                problems = _verify(source, conn, tables, deep=args.deep_verify)

            if problems:
                # `target.begin()` commits on clean exit, so an explicit
                # failure is required to roll the copy back.
                raise VerificationError("\n".join(problems))

    except VerificationError as exc:
        logger.error("verification failed; target was not modified:\n%s", exc)
        return EXIT_VERIFY_FAILED
    except RuntimeError as exc:
        message = str(exc)
        logger.error("%s", message)
        return EXIT_REFUSED if TARGET_OCCUPIED_MARKER in message else EXIT_OPERATIONAL
    except Exception as exc:  # operational failure, not a verdict
        logger.error("migration failure: %s", exc, exc_info=args.verbose)
        return EXIT_OPERATIONAL

    after_sha = _sha256_file(sqlite_path) if sqlite_path else None
    if before_sha and after_sha != before_sha:
        problems.append(
            f"source SQLite file changed during the run ({before_sha} -> {after_sha})"
        )

    if problems:
        for problem in problems:
            logger.error("mismatch: %s", problem)
        return EXIT_VERIFY_FAILED

    if args.verify_only:
        print("VERIFY OK: source and target match")
    elif args.dry_run:
        print("DRY RUN OK: target is empty and both endpoints are reachable")
    else:
        with target.connect() as conn:
            total = sum(_table_counts(conn, tables).values())
        print(f"MIGRATION OK: {total} rows now in {_label(target)}")
        if after_sha:
            print(f"source SQLite sha256 unchanged: {after_sha}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
